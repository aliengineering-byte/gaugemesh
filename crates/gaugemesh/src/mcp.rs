use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{auth::AuthenticatedIdentity, outbound::UpstreamRuntime, task_proxy::TaskProxy};
use anyhow::{Context, Result};
use gaugemesh_core::{
    capability::CapabilityId,
    config::CapabilityMode,
    context::{
        CapabilityScope, MoneyBudgetMicros, PrincipalId, RetryBudget, SideEffectClass, TenantId,
        TokenBudget,
    },
    digest::Sha256Digest,
    federation::{CompositeCursor, FederatedTool, Federation, open_cursor, seal_cursor},
    lease::{CapabilityLease, LeaseError},
    storage::{LeaseStorage, MemoryStorage, TaskRouteStorage},
};
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    model::*,
    service::{RequestContext, SubscriptionContext},
};
use serde_json::{Map, Value, json};

#[derive(Clone)]
pub struct MeshMcpServer {
    state: Arc<MeshMcpState>,
}

struct MeshMcpState {
    federation: Federation,
    leases: Arc<dyn LeaseStorage>,
    upstreams: Option<Arc<UpstreamRuntime>>,
    capability_mode: CapabilityMode,
    cursor_key: [u8; 32],
    conformance_fixture: bool,
    task_proxy: Option<TaskProxy>,
}

impl MeshMcpServer {
    pub fn demo() -> Self {
        Self {
            state: Arc::new(MeshMcpState {
                federation: Federation::demo(),
                leases: Arc::new(MemoryStorage::default()),
                upstreams: None,
                capability_mode: CapabilityMode::Transparent,
                cursor_key: *Sha256Digest::of_bytes(uuid::Uuid::new_v4().as_bytes()).as_bytes(),
                conformance_fixture: std::env::var_os("GAUGEMESH_CONFORMANCE_FIXTURE").is_some(),
                task_proxy: None,
            }),
        }
    }

    pub fn configured(
        federation: Federation,
        upstreams: Option<Arc<UpstreamRuntime>>,
        leases: Arc<dyn LeaseStorage>,
        task_routes: Option<Arc<dyn TaskRouteStorage>>,
        capability_mode: CapabilityMode,
    ) -> Self {
        let task_proxy = task_routes.and_then(|store| {
            upstreams
                .as_ref()
                .filter(|runtime| runtime.has_task_capable_source())
                .map(|runtime| TaskProxy::new(store, runtime.clone()))
        });
        Self {
            state: Arc::new(MeshMcpState {
                federation,
                leases,
                upstreams,
                capability_mode,
                cursor_key: *Sha256Digest::of_bytes(uuid::Uuid::new_v4().as_bytes()).as_bytes(),
                conformance_fixture: std::env::var_os("GAUGEMESH_CONFORMANCE_FIXTURE").is_some(),
                task_proxy,
            }),
        }
    }

    pub fn federation(&self) -> &Federation {
        &self.state.federation
    }

    fn tool_result(tool: &FederatedTool, arguments: Option<&Map<String, Value>>) -> CallToolResult {
        let query = arguments
            .and_then(|arguments| arguments.get("query"))
            .and_then(Value::as_str)
            .unwrap_or("");
        CallToolResult::structured(json!({
            "capabilityId": tool.identity.digest().to_string(),
            "source": tool.identity.source.0,
            "query": query,
            "value": tool.fixture_result,
        }))
    }

    fn discovery_meta(&self) -> Option<MetaObject> {
        let incomplete = self
            .state
            .upstreams
            .as_ref()
            .map(|upstreams| upstreams.incomplete_sources())
            .unwrap_or_default();
        if incomplete.is_empty() {
            None
        } else {
            Some(MetaObject(
                serde_json::from_value(json!({
                    "dev.gaugemesh/discovery": {
                        "complete": false,
                        "unavailableSources": incomplete,
                    }
                }))
                .expect("discovery metadata is an object"),
            ))
        }
    }

    fn page<T: Clone + serde::Serialize>(
        &self,
        kind: &str,
        items: Vec<T>,
        request: Option<PaginatedRequestParams>,
    ) -> Result<(Vec<T>, Option<String>), McpError> {
        const PAGE_SIZE: usize = 128;
        let snapshot_digest = Sha256Digest::of_json(
            &serde_json::to_value(&items)
                .map_err(|_| McpError::internal_error("GM_CURSOR_SNAPSHOT", None))?,
        );
        let start = if let Some(cursor) = request.and_then(|request| request.cursor) {
            let cursor = open_cursor(&cursor, &self.state.cursor_key)
                .map_err(|error| McpError::invalid_params(error.to_string(), None))?;
            if cursor.snapshot_digest != snapshot_digest || cursor.source_positions.len() != 1 {
                return Err(McpError::invalid_params("GM_CURSOR_STALE", None));
            }
            cursor
                .source_positions
                .get(kind)
                .and_then(|position| position.parse::<usize>().ok())
                .filter(|position| *position <= items.len())
                .ok_or_else(|| McpError::invalid_params("GM_CURSOR_INVALID", None))?
        } else {
            0
        };
        let end = start.saturating_add(PAGE_SIZE).min(items.len());
        let page = items[start..end].to_vec();
        let next = if end < items.len() {
            Some(
                seal_cursor(
                    &CompositeCursor {
                        source_positions: BTreeMap::from([(kind.into(), end.to_string())]),
                        snapshot_digest,
                    },
                    &self.state.cursor_key,
                )
                .map_err(|error| McpError::internal_error(error.to_string(), None))?,
            )
        } else {
            None
        };
        Ok((page, next))
    }

    async fn invoke_tool(
        &self,
        tool: &FederatedTool,
        arguments: Option<Map<String, Value>>,
    ) -> Result<CallToolResponse, McpError> {
        let Some(upstreams) = &self.state.upstreams else {
            return Ok(Self::tool_result(tool, arguments.as_ref()).into());
        };
        if !upstreams.contains_source(&tool.identity.source) {
            return Err(McpError::internal_error(
                "GM_MCP_UPSTREAM_SOURCE_UNAVAILABLE",
                None,
            ));
        }
        let mut request = CallToolRequestParams::new(tool.native_name.clone());
        request.arguments = arguments;
        let mut response = upstreams
            .call_tool(&tool.identity.source, request)
            .await
            .map_err(|error| {
                McpError::internal_error(format!("GM_MCP_UPSTREAM_CALL:{error}"), None)
            })?;
        if let CallToolResponse::Complete(result) = &mut response {
            bind_result_meta(
                &mut result.meta,
                &tool.identity,
                result.result_type.as_ref(),
                None,
                None,
            );
        }
        Ok(response)
    }

    fn meta_tools() -> Vec<Tool> {
        [
            (
                "gaugemesh_search",
                "Deterministically search reviewed capabilities",
                json!({"type":"object","properties":{"query":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":32}},"required":["query"],"additionalProperties":false}),
            ),
            (
                "gaugemesh_describe",
                "Describe one exact capability",
                json!({"type":"object","properties":{"alias":{"type":"string"}},"required":["alias"],"additionalProperties":false}),
            ),
            (
                "gaugemesh_lease",
                "Issue a bounded capability lease with explicit side-effect authority",
                json!({"type":"object","properties":{"aliases":{"type":"array","items":{"type":"string"},"maxItems":32},"ttlMs":{"type":"integer","minimum":1,"maximum":600000},"sideEffects":{"type":"array","items":{"enum":["read_only","idempotent_write","non_idempotent_write"]},"minItems":1,"maxItems":3,"uniqueItems":true}},"required":["aliases"],"additionalProperties":false}),
            ),
            (
                "gaugemesh_invoke",
                "Invoke a capability inside an exact lease",
                json!({"type":"object","properties":{"leaseId":{"type":"string"},"alias":{"type":"string"},"arguments":{"type":"object"}},"required":["leaseId","alias"],"additionalProperties":false}),
            ),
            (
                "gaugemesh_submit",
                "Submit one versioned, caller-idempotent capability request through a durable MCP task route",
                json!({
                    "type":"object",
                    "properties":{
                        "leaseId":{"type":"string"},
                        "alias":{"type":"string"},
                        "arguments":{"type":"object"},
                        "task":{
                            "type":"object",
                            "properties":{
                                "schemaVersion":{"const":"gaugemesh.task-submission/1"},
                                "logicalTaskId":{"type":"string","minLength":1,"maxLength":128},
                                "attemptId":{"type":"string","minLength":1,"maxLength":128},
                                "correlationId":{"type":"string","minLength":1,"maxLength":128},
                                "idempotencyKey":{"type":"string","minLength":1,"maxLength":128},
                                "inputSha256":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
                                "acceptancePolicySha256":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
                                "artifactScopeSha256":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
                                "providerInterfaceVersion":{"type":"string","minLength":1,"maxLength":128},
                                "deadlineUnixMs":{"type":"integer","minimum":1},
                                "retentionMs":{"type":"integer","minimum":1,"maximum":3600000},
                                "limits":{
                                    "type":"object",
                                    "properties":{
                                        "maxRuntimeMs":{"type":"integer","minimum":1,"maximum":30000},
                                        "maxOutputBytes":{"type":"integer","minimum":1,"maximum":65536},
                                        "maxArtifactBytes":{"type":"integer","minimum":1,"maximum":8388608},
                                        "maxAttempts":{"const":1}
                                    },
                                    "required":["maxRuntimeMs","maxOutputBytes","maxArtifactBytes","maxAttempts"],
                                    "additionalProperties":false
                                },
                                "permittedEffect":{"const":"non_idempotent_write"},
                                "cleanupRequired":{"const":true}
                            },
                            "required":["schemaVersion","logicalTaskId","attemptId","correlationId","idempotencyKey","inputSha256","acceptancePolicySha256","artifactScopeSha256","providerInterfaceVersion","deadlineUnixMs","retentionMs","limits","permittedEffect","cleanupRequired"],
                            "additionalProperties":false
                        }
                    },
                    "required":["leaseId","alias","arguments","task"],
                    "additionalProperties":false
                }),
            ),
            (
                "gaugemesh_release",
                "Release a capability lease",
                json!({"type":"object","properties":{"leaseId":{"type":"string"}},"required":["leaseId"],"additionalProperties":false}),
            ),
        ]
        .into_iter()
        .map(|(name, description, schema)| {
            let (read_only, destructive, idempotent, open_world) = match name {
                "gaugemesh_invoke" | "gaugemesh_submit" => {
                    (Some(false), Some(true), Some(false), Some(true))
                }
                "gaugemesh_lease" => (Some(false), Some(false), Some(false), Some(false)),
                "gaugemesh_release" => (Some(false), Some(false), Some(true), Some(false)),
                _ => (Some(true), Some(false), Some(true), Some(false)),
            };
            Tool::new(
                name,
                description,
                Arc::new(schema.as_object().cloned().expect("schema object")),
            )
            .with_annotations(ToolAnnotations::from_raw(
                None,
                read_only,
                destructive,
                idempotent,
                open_world,
            ))
        })
        .collect()
    }

    fn conformance_tools() -> Vec<Tool> {
        [
            "test_simple_text",
            "test_image_content",
            "test_multiple_content_types",
            "test_tool_with_logging",
            "test_error_handling",
            "test_tool_with_progress",
            "test_sampling",
            "test_elicitation",
            "test_elicitation_sep1034_defaults",
            "test_elicitation_sep1330_enums",
            "test_audio_content",
            "test_embedded_resource",
            "test_missing_capability",
            "test_streaming_elicitation",
            "test_logging_tool",
            "test_input_required_result_elicitation",
            "test_input_required_result_sampling",
            "test_input_required_result_list_roots",
            "test_input_required_result_request_state",
            "test_input_required_result_multiple_inputs",
            "test_input_required_result_multi_round",
            "test_input_required_result_tampered_state",
            "test_input_required_result_capabilities",
        ]
        .into_iter()
        .map(|name| {
            Tool::new(
                name,
                "Synthetic MCP conformance fixture",
                Arc::new(
                    json!({"type":"object","additionalProperties":false})
                        .as_object()
                        .cloned()
                        .expect("object schema"),
                ),
            )
        })
        .collect()
    }

    fn conformance_tool_result(name: &str) -> Option<CallToolResult> {
        const PNG_1X1: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9Zl1sAAAAASUVORK5CYII=";
        const WAV_HEADER: &str = "UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA=";
        let result = match name {
            "test_simple_text" => {
                CallToolResult::success(vec![ContentBlock::text("This is a simple text response.")])
            }
            "test_image_content" => {
                CallToolResult::success(vec![ContentBlock::image(PNG_1X1, "image/png")])
            }
            "test_audio_content" => {
                CallToolResult::success(vec![ContentBlock::audio(WAV_HEADER, "audio/wav")])
            }
            "test_embedded_resource" => {
                CallToolResult::success(vec![ContentBlock::resource(ResourceContents::text(
                    "This is an embedded resource content.",
                    "test://embedded-resource",
                ))])
            }
            "test_multiple_content_types" => CallToolResult::success(vec![
                ContentBlock::text("Multiple content types test:"),
                ContentBlock::image(PNG_1X1, "image/png"),
                ContentBlock::resource(
                    ResourceContents::text(
                        r#"{"test":"data","value":123}"#,
                        "test://mixed-content-resource",
                    )
                    .with_mime_type("application/json"),
                ),
            ]),
            "test_error_handling" => {
                CallToolResult::error(vec![ContentBlock::text("Intentional test error")])
            }
            "test_tool_with_progress" => {
                CallToolResult::success(vec![ContentBlock::text("Progress complete")])
            }
            _ => return None,
        };
        Some(result)
    }

    fn conformance_resources() -> Vec<Resource> {
        vec![
            Resource::new("test://static-text", "Static text fixture")
                .with_description("Synthetic text resource for MCP conformance")
                .with_mime_type("text/plain"),
            Resource::new("test://static-binary", "Static binary fixture")
                .with_description("Synthetic binary resource for MCP conformance")
                .with_mime_type("image/png"),
        ]
    }

    fn conformance_prompts() -> Vec<Prompt> {
        vec![
            Prompt::new(
                "test_simple_prompt",
                Some("Synthetic simple prompt for MCP conformance"),
                None,
            ),
            Prompt::new(
                "test_prompt_with_arguments",
                Some("Synthetic argument prompt for MCP conformance"),
                Some(vec![
                    PromptArgument::new("arg1").with_required(true),
                    PromptArgument::new("arg2").with_required(true),
                ]),
            ),
            Prompt::new(
                "test_prompt_with_embedded_resource",
                Some("Synthetic resource prompt for MCP conformance"),
                Some(vec![PromptArgument::new("resourceUri").with_required(true)]),
            ),
            Prompt::new(
                "test_prompt_with_image",
                Some("Synthetic image prompt for MCP conformance"),
                None,
            ),
            Prompt::new(
                "test_input_required_result_prompt",
                Some("Synthetic MRTR prompt for MCP conformance"),
                None,
            ),
        ]
    }

    fn conformance_input_request(value: Value) -> InputRequest {
        serde_json::from_value(value).expect("static conformance input request is valid")
    }

    fn conformance_elicitation_input(message: &str, field: &str) -> InputRequest {
        Self::conformance_input_request(json!({
            "method": "elicitation/create",
            "params": {
                "message": message,
                "requestedSchema": {
                    "type": "object",
                    "properties": {field: {"type": "string"}},
                    "required": [field]
                }
            }
        }))
    }

    fn conformance_confirmation_input(message: &str) -> InputRequest {
        Self::conformance_input_request(json!({
            "method": "elicitation/create",
            "params": {
                "message": message,
                "requestedSchema": {
                    "type": "object",
                    "properties": {"ok": {"type": "boolean"}},
                    "required": ["ok"]
                }
            }
        }))
    }

    fn conformance_sampling_input(prompt: &str, max_tokens: u64) -> InputRequest {
        Self::conformance_input_request(json!({
            "method": "sampling/createMessage",
            "params": {
                "messages": [{
                    "role": "user",
                    "content": {"type": "text", "text": prompt}
                }],
                "maxTokens": max_tokens
            }
        }))
    }

    fn conformance_roots_input() -> InputRequest {
        Self::conformance_input_request(json!({
            "method": "roots/list",
            "params": {}
        }))
    }

    fn conformance_state(&self, round: &str) -> Result<String, McpError> {
        seal_cursor(
            &CompositeCursor {
                source_positions: BTreeMap::from([("round".into(), round.into())]),
                snapshot_digest: Sha256Digest::of_bytes("gaugemesh-conformance-mrtr"),
            },
            &self.state.cursor_key,
        )
        .map_err(|_| McpError::internal_error("GM_CONFORMANCE_STATE_SEAL", None))
    }

    fn validate_conformance_state(&self, state: Option<&str>, round: &str) -> Result<(), McpError> {
        let state = state
            .ok_or_else(|| McpError::invalid_params("GM_MRTR_REQUEST_STATE_REQUIRED", None))?;
        let decoded = open_cursor(state, &self.state.cursor_key)
            .map_err(|_| McpError::invalid_params("GM_MRTR_REQUEST_STATE_INVALID", None))?;
        if decoded.snapshot_digest != Sha256Digest::of_bytes("gaugemesh-conformance-mrtr")
            || decoded.source_positions.get("round").map(String::as_str) != Some(round)
        {
            return Err(McpError::invalid_params(
                "GM_MRTR_REQUEST_STATE_INVALID",
                None,
            ));
        }
        Ok(())
    }

    fn accepted_input_response(request: &CallToolRequestParams, key: &str) -> bool {
        request
            .input_responses
            .as_ref()
            .and_then(|responses| responses.get(key))
            .is_some_and(Value::is_object)
    }

    fn mrtr(input_requests: InputRequests, request_state: Option<String>) -> CallToolResponse {
        InputRequiredResult::new(Some(input_requests), request_state).into()
    }

    #[allow(deprecated)]
    fn conformance_mrtr_tool(
        &self,
        request: &CallToolRequestParams,
        context: &RequestContext<RoleServer>,
    ) -> Result<Option<CallToolResponse>, McpError> {
        let response = match request.name.as_ref() {
            "test_missing_capability" => {
                if context
                    .client_capabilities()
                    .is_none_or(|capabilities| capabilities.sampling.is_none())
                {
                    return Err(McpError::missing_required_client_capability(
                        ClientCapabilities::builder().enable_sampling().build(),
                    ));
                }
                CallToolResult::success(vec![ContentBlock::text("sampling capability present")])
                    .into()
            }
            "test_logging_tool" => CallToolResult::success(vec![ContentBlock::text(
                "logging remains silent without an authorized log level",
            )])
            .into(),
            "test_streaming_elicitation" => Self::mrtr(
                BTreeMap::from([(
                    "confirm".into(),
                    Self::conformance_confirmation_input("Please confirm"),
                )]),
                None,
            ),
            "test_input_required_result_elicitation" => {
                if Self::accepted_input_response(request, "user_name") {
                    CallToolResult::success(vec![ContentBlock::text("Hello, Alice!")]).into()
                } else {
                    Self::mrtr(
                        BTreeMap::from([(
                            "user_name".into(),
                            Self::conformance_elicitation_input("What is your name?", "name"),
                        )]),
                        None,
                    )
                }
            }
            "test_input_required_result_sampling" => {
                if Self::accepted_input_response(request, "capital_question") {
                    CallToolResult::success(vec![ContentBlock::text(
                        "The sampling response was received.",
                    )])
                    .into()
                } else {
                    Self::mrtr(
                        BTreeMap::from([(
                            "capital_question".into(),
                            Self::conformance_sampling_input("What is the capital of France?", 100),
                        )]),
                        None,
                    )
                }
            }
            "test_input_required_result_list_roots" => {
                if Self::accepted_input_response(request, "client_roots") {
                    CallToolResult::success(vec![ContentBlock::text("Client roots received")])
                        .into()
                } else {
                    Self::mrtr(
                        BTreeMap::from([("client_roots".into(), Self::conformance_roots_input())]),
                        None,
                    )
                }
            }
            "test_input_required_result_request_state" => {
                if Self::accepted_input_response(request, "confirm") {
                    self.validate_conformance_state(request.request_state.as_deref(), "state")?;
                    CallToolResult::success(vec![ContentBlock::text("state-ok")]).into()
                } else {
                    Self::mrtr(
                        BTreeMap::from([(
                            "confirm".into(),
                            Self::conformance_confirmation_input("Please confirm"),
                        )]),
                        Some(self.conformance_state("state")?),
                    )
                }
            }
            "test_input_required_result_multiple_inputs" => {
                let complete = ["user_name", "greeting", "client_roots"]
                    .into_iter()
                    .all(|key| Self::accepted_input_response(request, key));
                if complete {
                    self.validate_conformance_state(request.request_state.as_deref(), "multiple")?;
                    CallToolResult::success(vec![ContentBlock::text(
                        "All requested inputs were received",
                    )])
                    .into()
                } else {
                    Self::mrtr(
                        BTreeMap::from([
                            (
                                "user_name".into(),
                                Self::conformance_elicitation_input("What is your name?", "name"),
                            ),
                            (
                                "greeting".into(),
                                Self::conformance_sampling_input("Generate a greeting", 50),
                            ),
                            ("client_roots".into(), Self::conformance_roots_input()),
                        ]),
                        Some(self.conformance_state("multiple")?),
                    )
                }
            }
            "test_input_required_result_multi_round" => match request.request_state.as_deref() {
                None => Self::mrtr(
                    BTreeMap::from([(
                        "step1".into(),
                        Self::conformance_elicitation_input("Step 1: What is your name?", "name"),
                    )]),
                    Some(self.conformance_state("multi-1")?),
                ),
                Some(state) => {
                    if self
                        .validate_conformance_state(Some(state), "multi-1")
                        .is_ok()
                    {
                        if !Self::accepted_input_response(request, "step1") {
                            return Err(McpError::invalid_params(
                                "GM_MRTR_INPUT_RESPONSE_REQUIRED",
                                None,
                            ));
                        }
                        Self::mrtr(
                            BTreeMap::from([(
                                "step2".into(),
                                Self::conformance_elicitation_input(
                                    "Step 2: What is your favorite color?",
                                    "color",
                                ),
                            )]),
                            Some(self.conformance_state("multi-2")?),
                        )
                    } else {
                        self.validate_conformance_state(Some(state), "multi-2")?;
                        if !Self::accepted_input_response(request, "step2") {
                            return Err(McpError::invalid_params(
                                "GM_MRTR_INPUT_RESPONSE_REQUIRED",
                                None,
                            ));
                        }
                        CallToolResult::success(vec![ContentBlock::text(
                            "Multi-round input complete",
                        )])
                        .into()
                    }
                }
            },
            "test_input_required_result_tampered_state" => {
                if Self::accepted_input_response(request, "confirm") {
                    self.validate_conformance_state(request.request_state.as_deref(), "tamper")?;
                    CallToolResult::success(vec![ContentBlock::text("state accepted")]).into()
                } else {
                    Self::mrtr(
                        BTreeMap::from([(
                            "confirm".into(),
                            Self::conformance_confirmation_input("Please confirm"),
                        )]),
                        Some(self.conformance_state("tamper")?),
                    )
                }
            }
            "test_input_required_result_capabilities" => {
                let capabilities = context.client_capabilities().unwrap_or_default();
                let mut requests = InputRequests::new();
                if capabilities.sampling.is_some() {
                    requests.insert(
                        "sampling".into(),
                        Self::conformance_sampling_input("Generate a bounded response", 50),
                    );
                }
                if capabilities.elicitation.is_some() {
                    requests.insert(
                        "elicitation".into(),
                        Self::conformance_elicitation_input(
                            "Provide a bounded response",
                            "response",
                        ),
                    );
                }
                if capabilities.roots.is_some() {
                    requests.insert("roots".into(), Self::conformance_roots_input());
                }
                if requests.is_empty() {
                    return Err(McpError::missing_required_client_capability(
                        ClientCapabilities::builder().enable_sampling().build(),
                    ));
                }
                Self::mrtr(requests, None)
            }
            _ => return Ok(None),
        };
        Ok(Some(response))
    }

    fn conformance_elicitation_schema(name: &str) -> Result<ElicitationSchema, McpError> {
        let schema = match name {
            "test_elicitation" => json!({
                "type": "object",
                "properties": {
                    "username": {"type": "string", "description": "User's response"},
                    "email": {"type": "string", "description": "User's email address"}
                },
                "required": ["username", "email"]
            }),
            "test_elicitation_sep1034_defaults" => json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string", "default": "John Doe"},
                    "age": {"type": "integer", "default": 30},
                    "score": {"type": "number", "default": 95.5},
                    "status": {"type": "string", "enum": ["active", "inactive", "pending"], "default": "active"},
                    "verified": {"type": "boolean", "default": true}
                }
            }),
            "test_elicitation_sep1330_enums" => json!({
                "type": "object",
                "properties": {
                    "untitledSingle": {"type": "string", "enum": ["option1", "option2", "option3"]},
                    "titledSingle": {"type": "string", "oneOf": [
                        {"const": "value1", "title": "First Option"},
                        {"const": "value2", "title": "Second Option"}
                    ]},
                    "legacyEnum": {"type": "string", "enum": ["opt1", "opt2", "opt3"], "enumNames": ["Option One", "Option Two", "Option Three"]},
                    "untitledMulti": {"type": "array", "items": {"type": "string", "enum": ["option1", "option2", "option3"]}},
                    "titledMulti": {"type": "array", "items": {"anyOf": [
                        {"const": "value1", "title": "First Choice"},
                        {"const": "value2", "title": "Second Choice"}
                    ]}}
                }
            }),
            _ => {
                return Err(McpError::invalid_params(
                    "unknown elicitation fixture",
                    None,
                ));
            }
        };
        ElicitationSchema::from_json_schema(
            schema
                .as_object()
                .cloned()
                .expect("elicitation fixture is an object"),
        )
        .map_err(|error| McpError::invalid_params(error.to_string(), None))
    }

    async fn call_meta_tool(
        &self,
        name: &str,
        arguments: Option<Map<String, Value>>,
        identity: &AuthenticatedIdentity,
        client_supports_tasks: bool,
    ) -> Result<CallToolResponse, McpError> {
        let arguments = arguments.unwrap_or_default();
        match name {
            "gaugemesh_search" => {
                let query = arguments.get("query").and_then(Value::as_str).unwrap_or("");
                let limit = arguments.get("limit").and_then(Value::as_u64).unwrap_or(8) as usize;
                let results = self
                    .state
                    .federation
                    .search(query, limit)
                    .into_iter()
                    .map(|tool| json!({"alias":tool.alias,"capabilityId":tool.identity.digest().to_string(),"source":tool.identity.source.0,"description":tool.description}))
                    .collect::<Vec<_>>();
                Ok(CallToolResult::structured(json!({"results": results})).into())
            }
            "gaugemesh_describe" => {
                let alias = arguments.get("alias").and_then(Value::as_str).unwrap_or("");
                match self.state.federation.tool(alias) {
                    Ok(tool) => Ok(CallToolResult::structured(json!({
                        "alias": tool.alias,
                        "capabilityId": tool.identity.digest().to_string(),
                        "schemaDigest": tool.identity.schema_digest.to_string(),
                        "source": tool.identity.source.0,
                        "sideEffect": tool.side_effect,
                        "inputSchema": tool.input_schema,
                    }))
                    .into()),
                    Err(error) => Ok(tool_error(error.to_string()).into()),
                }
            }
            "gaugemesh_lease" => {
                let Some(aliases) = arguments.get("aliases").and_then(Value::as_array) else {
                    return Ok(tool_error("GM_LEASE_CAPABILITY_OUTSIDE_CONE").into());
                };
                if aliases.is_empty() || aliases.len() > 32 {
                    return Ok(tool_error("GM_LEASE_LIMIT_INVALID").into());
                }
                let tools = aliases
                    .iter()
                    .filter_map(Value::as_str)
                    .filter_map(|alias| self.state.federation.tool(alias).ok())
                    .collect::<Vec<_>>();
                if tools.len() != aliases.len() || tools.is_empty() {
                    return Ok(tool_error("GM_LEASE_CAPABILITY_OUTSIDE_CONE").into());
                }
                let side_effects = match explicit_side_effects(arguments.get("sideEffects")) {
                    Ok(side_effects) => side_effects,
                    Err(code) => return Ok(tool_error(code).into()),
                };
                if side_effects
                    .iter()
                    .any(|effect| !identity_authorizes_effect(identity, *effect))
                {
                    return Ok(tool_error("GM_LEASE_SIDE_EFFECT_SCOPE_REQUIRED").into());
                }
                if tools
                    .iter()
                    .any(|tool| !side_effects.contains(&tool.side_effect))
                {
                    return Ok(tool_error("GM_LEASE_SIDE_EFFECT_OUTSIDE_CONE").into());
                }
                let capabilities = tools
                    .iter()
                    .map(|tool| tool.identity.clone())
                    .collect::<Vec<_>>();
                let ttl_ms = match arguments.get("ttlMs") {
                    None => 60_000,
                    Some(value) => match value.as_u64() {
                        Some(value @ 1..=600_000) => value,
                        _ => return Ok(tool_error("GM_LEASE_LIMIT_INVALID").into()),
                    },
                };
                let now = unix_time_ms()?;
                let lease = CapabilityLease::issue_with_side_effects(
                    identity.principal.clone(),
                    identity.tenant.clone(),
                    "mcp-request".into(),
                    capabilities,
                    CapabilityScope::default(),
                    now.saturating_add(ttl_ms),
                    MoneyBudgetMicros(0),
                    TokenBudget(4_096),
                    RetryBudget(1),
                    side_effects,
                );
                if self.state.leases.put(&lease).is_err() {
                    return Ok(tool_error("GM_STORAGE_WRITE").into());
                }
                Ok(CallToolResult::structured(json!({
                    "leaseId": lease.id.0,
                    "manifestDigest": lease.manifest_digest.to_string(),
                    "expiresInMs": ttl_ms,
                    "capabilities": lease.capabilities.iter().map(CapabilityId::digest).map(|digest| digest.to_string()).collect::<Vec<_>>(),
                })).into())
            }
            "gaugemesh_invoke" => {
                let lease_id = arguments
                    .get("leaseId")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let alias = arguments.get("alias").and_then(Value::as_str).unwrap_or("");
                let tool_arguments = arguments.get("arguments").and_then(Value::as_object);
                let tool = match self.state.federation.tool(alias) {
                    Ok(tool) => tool,
                    Err(error) => return Ok(tool_error(error.to_string()).into()),
                };
                let Some(lease) = self
                    .state
                    .leases
                    .get(lease_id)
                    .map_err(|_| McpError::internal_error("GM_STORAGE_READ", None))?
                else {
                    return Ok(tool_error("GM_LEASE_CAPABILITY_OUTSIDE_CONE").into());
                };
                let now = unix_time_ms()?;
                let authorization = lease.authorize_invocation(
                    &identity.principal,
                    &identity.tenant,
                    &tool.identity,
                    tool.side_effect,
                    now,
                );
                match authorization {
                    Ok(()) => self.invoke_tool(tool, tool_arguments.cloned()).await,
                    Err(error) => Ok(tool_error(lease_error_code(error)).into()),
                }
            }
            "gaugemesh_submit" => {
                if !client_supports_tasks {
                    return Ok(tool_error("GM_TASK_CLIENT_CAPABILITY_REQUIRED").into());
                }
                let Some(task_proxy) = &self.state.task_proxy else {
                    return Ok(tool_error("GM_TASK_DURABLE_ROUTE_UNAVAILABLE").into());
                };
                let lease_id = arguments
                    .get("leaseId")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let alias = arguments.get("alias").and_then(Value::as_str).unwrap_or("");
                let Some(tool_arguments) = arguments.get("arguments").and_then(Value::as_object)
                else {
                    return Ok(tool_error("GM_TASK_ARGUMENTS_REQUIRED").into());
                };
                let Some(task) = arguments.get("task") else {
                    return Ok(tool_error("GM_TASK_SUBMISSION_REQUIRED").into());
                };
                let tool = match self.state.federation.tool(alias) {
                    Ok(tool) => tool,
                    Err(error) => return Ok(tool_error(error.to_string()).into()),
                };
                if !task_proxy.source_supported(&tool.identity.source) {
                    return Ok(tool_error("GM_TASK_UPSTREAM_UNSUPPORTED").into());
                }
                let Some(lease) = self
                    .state
                    .leases
                    .get(lease_id)
                    .map_err(|_| McpError::internal_error("GM_STORAGE_READ", None))?
                else {
                    return Ok(tool_error("GM_LEASE_CAPABILITY_OUTSIDE_CONE").into());
                };
                let now = unix_time_ms()?;
                if let Err(error) = lease.authorize_invocation(
                    &identity.principal,
                    &identity.tenant,
                    &tool.identity,
                    SideEffectClass::NonIdempotentWrite,
                    now,
                ) {
                    return Ok(tool_error(lease_error_code(error)).into());
                }
                task_proxy
                    .submit(tool, tool_arguments.clone(), task, identity)
                    .await
            }
            "gaugemesh_release" => {
                let lease_id = arguments
                    .get("leaseId")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let lease = self
                    .state
                    .leases
                    .get(lease_id)
                    .map_err(|_| McpError::internal_error("GM_STORAGE_READ", None))?;
                let released = lease.as_ref().is_some_and(|lease| {
                    lease.principal == identity.principal && lease.tenant == identity.tenant
                });
                if lease.is_some() && !released {
                    return Ok(tool_error("GM_LEASE_PRINCIPAL_MISMATCH").into());
                }
                self.state
                    .leases
                    .remove(lease_id)
                    .map_err(|_| McpError::internal_error("GM_STORAGE_WRITE", None))?;
                Ok(CallToolResult::structured(json!({"released": released})).into())
            }
            _ => Ok(tool_error("GM_CAPABILITY_NOT_FOUND").into()),
        }
    }
}

impl ServerHandler for MeshMcpServer {
    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        context.peer.set_peer_info(request.clone());
        let mut info = self.get_info();
        if self
            .supported_protocol_versions()
            .contains(&request.protocol_version)
        {
            info.protocol_version = request.protocol_version;
        }
        if info.protocol_version != ProtocolVersion::V_2026_07_28 {
            let extensions_empty =
                info.capabilities
                    .extensions
                    .as_mut()
                    .is_some_and(|extensions| {
                        extensions.remove(TASKS_EXTENSION_ID);
                        extensions.is_empty()
                    });
            if extensions_empty {
                info.capabilities.extensions = None;
            }
        }
        Ok(info)
    }

    #[allow(deprecated)]
    fn get_info(&self) -> ServerInfo {
        let capabilities = if self.state.conformance_fixture {
            ServerCapabilities::builder()
                .enable_logging()
                .enable_tools()
                .enable_resources()
                .enable_resources_subscribe()
                .enable_prompts()
                .build()
        } else {
            let builder = ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_prompts();
            if self.state.task_proxy.is_some() {
                builder.enable_tasks().build()
            } else {
                builder.build()
            }
        };
        ServerInfo::new(capabilities)
            .with_server_info(Implementation::new("gaugemesh", env!("CARGO_PKG_VERSION")))
            .with_protocol_version(ProtocolVersion::V_2026_07_28)
            .with_instructions("Reviewed capabilities with stable identities and bounded leases.")
    }

    #[allow(deprecated)]
    async fn set_level(
        &self,
        _request: SetLevelRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        if self.state.conformance_fixture {
            Ok(())
        } else {
            Err(McpError::method_not_found::<SetLevelRequestMethod>())
        }
    }

    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        self.state
            .conformance_fixture
            .then(|| requested.supported_by(&self.get_info().capabilities))
    }

    async fn listen(&self, context: SubscriptionContext) -> Result<(), McpError> {
        context.cancelled().await;
        Ok(())
    }

    #[allow(deprecated)]
    async fn subscribe(
        &self,
        _request: SubscribeRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        if self.state.conformance_fixture {
            Ok(())
        } else {
            Err(McpError::method_not_found::<SubscribeRequestMethod>())
        }
    }

    #[allow(deprecated)]
    async fn unsubscribe(
        &self,
        _request: UnsubscribeRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        if self.state.conformance_fixture {
            Ok(())
        } else {
            Err(McpError::method_not_found::<UnsubscribeRequestMethod>())
        }
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let mut tools = if self.state.capability_mode == CapabilityMode::Transparent {
            self.state.federation.rmcp_tools()
        } else {
            Vec::new()
        };
        let expose_task_submission =
            self.state.task_proxy.is_some() && context_supports_tasks(&context);
        tools.extend(
            Self::meta_tools()
                .into_iter()
                .filter(|tool| expose_task_submission || tool.name != "gaugemesh_submit"),
        );
        if self.state.conformance_fixture {
            tools.extend(Self::conformance_tools());
        }
        let (tools, next_cursor) = self.page("tools", tools, request)?;
        let mut result = ListToolsResult::with_all_items(tools)
            .with_ttl_ms(5_000)
            .with_cache_scope(CacheScope::Private);
        result.meta = self.discovery_meta();
        result.next_cursor = next_cursor;
        Ok(result)
    }

    #[allow(deprecated)]
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let identity = identity_from_context(&context);
        let client_supports_tasks = context_supports_tasks(&context);
        if self.state.conformance_fixture {
            if let Some(response) = self.conformance_mrtr_tool(&request, &context)? {
                return Ok(response);
            }
            if request.name == "test_tool_with_logging" {
                for message in [
                    "Tool execution started",
                    "Tool processing data",
                    "Tool execution completed",
                ] {
                    let _ = context
                        .peer
                        .notify_logging_message(LoggingMessageNotificationParam::new(
                            LoggingLevel::Info,
                            json!({"message": message}),
                        ))
                        .await;
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                }
                return Ok(
                    CallToolResult::success(vec![ContentBlock::text("Logging complete")]).into(),
                );
            }
            if request.name == "test_sampling" {
                let prompt = request
                    .arguments
                    .as_ref()
                    .and_then(|values| values.get("prompt"))
                    .and_then(Value::as_str)
                    .unwrap_or("Test prompt for sampling");
                let outcome = context
                    .peer
                    .create_message(CreateMessageRequestParams::new(
                        vec![SamplingMessage::user_text(prompt)],
                        100,
                    ))
                    .await;
                return Ok(match outcome {
                    Ok(response) => CallToolResult::success(vec![ContentBlock::text(format!(
                        "LLM response: {:?}",
                        response.message.content
                    ))]),
                    Err(error) => tool_error(format!("sampling failed: {error}")),
                }
                .into());
            }
            if matches!(
                request.name.as_ref(),
                "test_elicitation"
                    | "test_elicitation_sep1034_defaults"
                    | "test_elicitation_sep1330_enums"
            ) {
                let schema = Self::conformance_elicitation_schema(&request.name)?;
                let message = request
                    .arguments
                    .as_ref()
                    .and_then(|values| values.get("message"))
                    .and_then(Value::as_str)
                    .unwrap_or("Please provide the requested test values");
                let outcome = context
                    .peer
                    .create_elicitation(ElicitRequestParams::FormElicitationParams {
                        meta: None,
                        message: message.into(),
                        requested_schema: schema,
                    })
                    .await;
                return Ok(match outcome {
                    Ok(response) => CallToolResult::success(vec![ContentBlock::text(format!(
                        "Elicitation completed: action={:?}, content={:?}",
                        response.action, response.content
                    ))]),
                    Err(error) => tool_error(format!("elicitation failed: {error}")),
                }
                .into());
            }
            if request.name == "test_tool_with_progress" {
                if let Some(token) = context.meta.get_progress_token() {
                    for progress in [0.0, 50.0, 100.0] {
                        let _ = context
                            .peer
                            .notify_progress(
                                ProgressNotificationParam::new(token.clone(), progress)
                                    .with_total(100.0),
                            )
                            .await;
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                }
            }
            if let Some(result) = Self::conformance_tool_result(&request.name) {
                return Ok(result.into());
            }
        }
        if request.name.starts_with("gaugemesh_") {
            return self
                .call_meta_tool(
                    &request.name,
                    request.arguments,
                    &identity,
                    client_supports_tasks,
                )
                .await;
        }
        if self.state.capability_mode == CapabilityMode::Lease {
            return Err(McpError::invalid_request(
                "GM_CAPABILITY_LEASE_REQUIRED",
                None,
            ));
        }
        let tool = self
            .state
            .federation
            .tool(&request.name)
            .map_err(|error| McpError::invalid_params(error.to_string(), None))?
            .clone();
        if let Some(upstreams) = &self.state.upstreams {
            if upstreams.contains_source(&tool.identity.source) {
                let mut upstream_request = request;
                upstream_request.name = tool.native_name.clone().into();
                let mut response = upstreams
                    .call_tool(&tool.identity.source, upstream_request)
                    .await
                    .map_err(|error| {
                        McpError::internal_error(format!("GM_MCP_UPSTREAM_CALL:{error}"), None)
                    })?;
                if let CallToolResponse::Complete(result) = &mut response {
                    bind_result_meta(
                        &mut result.meta,
                        &tool.identity,
                        result.result_type.as_ref(),
                        None,
                        None,
                    );
                }
                return Ok(response);
            }
        }
        Ok(Self::tool_result(&tool, request.arguments.as_ref()).into())
    }

    async fn get_task(
        &self,
        request: GetTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetTaskResult, McpError> {
        if !context_supports_tasks(&context) {
            return Err(McpError::method_not_found::<GetTaskMethod>());
        }
        let task_proxy = self
            .state
            .task_proxy
            .as_ref()
            .ok_or_else(McpError::method_not_found::<GetTaskMethod>)?;
        task_proxy
            .get_task(request, &identity_from_context(&context))
            .await
    }

    async fn update_task(
        &self,
        request: UpdateTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        if !context_supports_tasks(&context) {
            return Err(McpError::method_not_found::<UpdateTaskMethod>());
        }
        let task_proxy = self
            .state
            .task_proxy
            .as_ref()
            .ok_or_else(McpError::method_not_found::<UpdateTaskMethod>)?;
        task_proxy
            .update_task(request, &identity_from_context(&context))
            .await
    }

    async fn cancel_task(
        &self,
        request: CancelTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        if !context_supports_tasks(&context) {
            return Err(McpError::method_not_found::<CancelTaskMethod>());
        }
        let task_proxy = self
            .state
            .task_proxy
            .as_ref()
            .ok_or_else(McpError::method_not_found::<CancelTaskMethod>)?;
        task_proxy
            .cancel_task(request, &identity_from_context(&context))
            .await
    }

    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        let mut resources = self.state.federation.rmcp_resources();
        if self.state.conformance_fixture {
            resources.extend(Self::conformance_resources());
        }
        let (resources, next_cursor) = self.page("resources", resources, request)?;
        let mut result = ListResourcesResult::with_all_items(resources)
            .with_ttl_ms(5_000)
            .with_cache_scope(CacheScope::Private);
        result.meta = self.discovery_meta();
        result.next_cursor = next_cursor;
        Ok(result)
    }

    async fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        let mut templates = self.state.federation.rmcp_templates();
        if self.state.conformance_fixture {
            templates.push(ResourceTemplate::new(
                "test://template/{id}/data",
                "Synthetic template fixture",
            ));
        }
        let (templates, next_cursor) = self.page("resource_templates", templates, request)?;
        let mut result = ListResourceTemplatesResult::with_all_items(templates)
            .with_ttl_ms(5_000)
            .with_cache_scope(CacheScope::Private);
        result.meta = self.discovery_meta();
        result.next_cursor = next_cursor;
        Ok(result)
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, McpError> {
        if self.state.conformance_fixture {
            let contents = match request.uri.as_str() {
                "test://static-text" => Some(ResourceContents::text(
                    "This is the content of the static text resource.",
                    &request.uri,
                )),
                "test://static-binary" => Some(
                    ResourceContents::blob(
                        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9Zl1sAAAAASUVORK5CYII=",
                        &request.uri,
                    )
                    .with_mime_type("image/png"),
                ),
                "test://template/123/data" => Some(
                    ResourceContents::text(
                        r#"{"id":"123","templateTest":true,"data":"Data for ID: 123"}"#,
                        &request.uri,
                    )
                    .with_mime_type("application/json"),
                ),
                _ => None,
            };
            if let Some(contents) = contents {
                return Ok(ReadResourceResult::new(vec![contents])
                    .with_ttl_ms(5_000)
                    .with_cache_scope(CacheScope::Private)
                    .into());
            }
        }
        if let Some(upstreams) = &self.state.upstreams {
            if let Ok(resource) = self.state.federation.resource(&request.uri) {
                let resource = resource.clone();
                let virtual_uri = request.uri.clone();
                let mut upstream_request = request;
                upstream_request.uri = resource.native_uri.clone();
                let mut response = upstreams
                    .read_resource(&resource.identity.source, upstream_request)
                    .await
                    .map_err(|error| {
                        McpError::internal_error(format!("GM_MCP_UPSTREAM_READ:{error}"), None)
                    })?;
                virtualize_resource_response(&mut response, &virtual_uri, &resource.identity);
                return Ok(response);
            }
            if let Some((template, native_uri)) =
                self.state.federation.resolve_template(&request.uri)
            {
                let template = template.clone();
                let virtual_uri = request.uri.clone();
                let mut upstream_request = request;
                upstream_request.uri = native_uri;
                let mut response = upstreams
                    .read_resource(&template.identity.source, upstream_request)
                    .await
                    .map_err(|error| {
                        McpError::internal_error(format!("GM_MCP_UPSTREAM_READ:{error}"), None)
                    })?;
                virtualize_resource_response(&mut response, &virtual_uri, &template.identity);
                return Ok(response);
            }
        }
        let resource = self
            .state
            .federation
            .resource(&request.uri)
            .map_err(|_| McpError::resource_not_found("GM_RESOURCE_NOT_FOUND", None))?;
        Ok(ReadResourceResult::new(vec![ResourceContents::text(
            &resource.contents,
            &resource.virtual_uri,
        )])
        .with_ttl_ms(5_000)
        .with_cache_scope(CacheScope::Private)
        .into())
    }

    async fn list_prompts(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, McpError> {
        let mut prompts = self.state.federation.rmcp_prompts();
        if self.state.conformance_fixture {
            prompts.extend(Self::conformance_prompts());
        }
        let (prompts, next_cursor) = self.page("prompts", prompts, request)?;
        let mut result = ListPromptsResult::with_all_items(prompts)
            .with_ttl_ms(5_000)
            .with_cache_scope(CacheScope::Private);
        result.meta = self.discovery_meta();
        result.next_cursor = next_cursor;
        Ok(result)
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, McpError> {
        if self.state.conformance_fixture {
            if request.name == "test_input_required_result_prompt" {
                if request
                    .input_responses
                    .as_ref()
                    .and_then(|responses| responses.get("user_context"))
                    .is_some_and(Value::is_object)
                {
                    return Ok(GetPromptResult::new(vec![PromptMessage::new_text(
                        Role::User,
                        "Prompt with supplied user context",
                    )])
                    .with_description("Synthetic MCP conformance fixture")
                    .into());
                }
                return Ok(InputRequiredResult::from_input_requests(BTreeMap::from([(
                    "user_context".into(),
                    Self::conformance_elicitation_input(
                        "What context should the prompt use?",
                        "context",
                    ),
                )]))
                .into());
            }
            const PNG_1X1: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9Zl1sAAAAASUVORK5CYII=";
            let messages = match request.name.as_ref() {
                "test_simple_prompt" => Some(vec![PromptMessage::new_text(
                    Role::User,
                    "This is a simple prompt for testing.",
                )]),
                "test_prompt_with_arguments" => {
                    let arguments = request.arguments.as_ref();
                    let arg1 = arguments
                        .and_then(|values| values.get("arg1"))
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let arg2 = arguments
                        .and_then(|values| values.get("arg2"))
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    Some(vec![PromptMessage::new_text(
                        Role::User,
                        format!("Prompt with arguments: arg1='{arg1}', arg2='{arg2}'"),
                    )])
                }
                "test_prompt_with_embedded_resource" => {
                    let uri = request
                        .arguments
                        .as_ref()
                        .and_then(|values| values.get("resourceUri"))
                        .and_then(Value::as_str)
                        .unwrap_or("test://example-resource");
                    Some(vec![
                        PromptMessage::new(
                            Role::User,
                            ContentBlock::resource(ResourceContents::text(
                                "Embedded resource content for testing.",
                                uri,
                            )),
                        ),
                        PromptMessage::new_text(
                            Role::User,
                            "Please process the embedded resource above.",
                        ),
                    ])
                }
                "test_prompt_with_image" => Some(vec![
                    PromptMessage::new(Role::User, ContentBlock::image(PNG_1X1, "image/png")),
                    PromptMessage::new_text(Role::User, "Please analyze the image above."),
                ]),
                _ => None,
            };
            if let Some(messages) = messages {
                return Ok(GetPromptResult::new(messages)
                    .with_description("Synthetic MCP conformance fixture")
                    .into());
            }
        }
        let prompt = self
            .state
            .federation
            .prompt(&request.name)
            .map_err(|_| McpError::invalid_params("GM_PROMPT_NOT_FOUND", None))?
            .clone();
        if let Some(upstreams) = &self.state.upstreams {
            if upstreams.contains_source(&prompt.identity.source) {
                let mut upstream_request = request;
                upstream_request.name = prompt.native_name.clone();
                let mut response = upstreams
                    .get_prompt(&prompt.identity.source, upstream_request)
                    .await
                    .map_err(|error| {
                        McpError::internal_error(format!("GM_MCP_UPSTREAM_PROMPT:{error}"), None)
                    })?;
                if let GetPromptResponse::Complete(result) = &mut response {
                    bind_result_meta(
                        &mut result.meta,
                        &prompt.identity,
                        result.result_type.as_ref(),
                        None,
                        None,
                    );
                }
                return Ok(response);
            }
        }
        let mut rendered = prompt.template.clone();
        for argument in &prompt.arguments {
            let value = request
                .arguments
                .as_ref()
                .and_then(|arguments| arguments.get(argument))
                .and_then(Value::as_str)
                .ok_or_else(|| McpError::invalid_params("GM_PROMPT_ARGUMENT_REQUIRED", None))?;
            rendered = rendered.replace(&format!("{{{{{argument}}}}}"), value);
        }
        Ok(
            GetPromptResult::new(vec![PromptMessage::new_text(Role::User, rendered)])
                .with_description(&prompt.description)
                .into(),
        )
    }
}

fn bind_result_meta(
    meta: &mut Option<MetaObject>,
    identity: &CapabilityId,
    result_type: Option<&ResultType>,
    ttl_ms: Option<u64>,
    cache_scope: Option<&CacheScope>,
) {
    let map = &mut meta.get_or_insert_with(|| MetaObject(Map::new())).0;
    map.insert(
        "dev.gaugemesh/conservation".into(),
        json!({
            "capabilityId": identity.digest().to_string(),
            "source": identity.source.0,
            "schemaDigest": identity.schema_digest.to_string(),
            "resultTypePreserved": result_type.is_some(),
            "ttlMsPreserved": ttl_ms.is_some(),
            "cacheScopePreserved": cache_scope.is_some(),
            "requiredSemanticLosses": [],
        }),
    );
}

fn virtualize_resource_response(
    response: &mut ReadResourceResponse,
    virtual_uri: &str,
    identity: &CapabilityId,
) {
    if let ReadResourceResponse::Complete(result) = response {
        for contents in &mut result.contents {
            match contents {
                ResourceContents::TextResourceContents { uri, .. }
                | ResourceContents::BlobResourceContents { uri, .. } => {
                    *uri = virtual_uri.to_owned();
                }
                _ => {}
            }
        }
        let result_type = result.result_type.clone();
        let cache_scope = result.cache_scope;
        bind_result_meta(
            &mut result.meta,
            identity,
            result_type.as_ref(),
            result.ttl_ms,
            cache_scope.as_ref(),
        );
    }
}

fn local_principal() -> PrincipalId {
    PrincipalId("local-demo".into())
}

fn local_tenant() -> TenantId {
    TenantId("local".into())
}

fn identity_from_context(context: &RequestContext<RoleServer>) -> AuthenticatedIdentity {
    context
        .extensions
        .get::<axum::http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<AuthenticatedIdentity>())
        .cloned()
        .unwrap_or_else(|| AuthenticatedIdentity {
            principal: local_principal(),
            tenant: local_tenant(),
            scopes: Vec::new(),
        })
}

fn context_supports_tasks(context: &RequestContext<RoleServer>) -> bool {
    context
        .client_capabilities()
        .is_some_and(|capabilities| capabilities.supports_tasks())
        && context.protocol_version() == Some(ProtocolVersion::V_2026_07_28)
}

fn tool_error(message: impl Into<String>) -> CallToolResult {
    CallToolResult::structured_error(json!({"code": message.into()}))
}

fn unix_time_ms() -> Result<u64, McpError> {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| McpError::internal_error("GM_CLOCK_INVALID", None))?
        .as_millis();
    u64::try_from(milliseconds).map_err(|_| McpError::internal_error("GM_CLOCK_INVALID", None))
}

fn explicit_side_effects(value: Option<&Value>) -> Result<BTreeSet<SideEffectClass>, &'static str> {
    let Some(value) = value else {
        return Ok(BTreeSet::from([SideEffectClass::ReadOnly]));
    };
    let values = value.as_array().ok_or("GM_LEASE_SIDE_EFFECT_INVALID")?;
    if values.is_empty() || values.len() > 3 {
        return Err("GM_LEASE_SIDE_EFFECT_INVALID");
    }
    let mut effects = BTreeSet::new();
    for value in values {
        let effect = match value.as_str() {
            Some("read_only") => SideEffectClass::ReadOnly,
            Some("idempotent_write") => SideEffectClass::IdempotentWrite,
            Some("non_idempotent_write") => SideEffectClass::NonIdempotentWrite,
            _ => return Err("GM_LEASE_SIDE_EFFECT_INVALID"),
        };
        if !effects.insert(effect) {
            return Err("GM_LEASE_SIDE_EFFECT_INVALID");
        }
    }
    Ok(effects)
}

fn identity_authorizes_effect(identity: &AuthenticatedIdentity, effect: SideEffectClass) -> bool {
    if identity.principal == local_principal() && identity.tenant == local_tenant() {
        return true;
    }
    let required_scope = match effect {
        SideEffectClass::ReadOnly => return true,
        SideEffectClass::IdempotentWrite => "gaugemesh:effect:idempotent-write",
        SideEffectClass::NonIdempotentWrite => "gaugemesh:effect:non-idempotent-write",
    };
    identity.scopes.iter().any(|scope| scope == required_scope)
}

fn lease_error_code(error: LeaseError) -> &'static str {
    match error {
        LeaseError::Expired => "GM_LEASE_EXPIRED",
        LeaseError::Principal => "GM_LEASE_PRINCIPAL_MISMATCH",
        LeaseError::Tenant => "GM_LEASE_TENANT_MISMATCH",
        LeaseError::Capability => "GM_LEASE_CAPABILITY_OUTSIDE_CONE",
        LeaseError::StaleSchema => "GM_LEASE_STALE_SCHEMA",
        LeaseError::Manifest => "GM_LEASE_MANIFEST_TAMPERED",
    }
}

pub async fn serve_stdio_server(server: MeshMcpServer) -> Result<()> {
    use rmcp::ServiceExt as _;
    let service = server
        .serve(rmcp::transport::stdio())
        .await
        .context("failed to start MCP stdio transport")?;
    service
        .waiting()
        .await
        .context("MCP stdio transport failed")?;
    Ok(())
}

pub fn router(
    server: MeshMcpServer,
    cancellation_token: tokio_util::sync::CancellationToken,
) -> axum::Router {
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    };

    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_cancellation_token(cancellation_token),
    );
    axum::Router::new()
        .nest_service("/mcp", service)
        .layer(tower_http::limit::RequestBodyLimitLayer::new(1024 * 1024))
}

#[cfg(test)]
mod tests {
    use rmcp::{ClientHandler, ServiceExt};

    use super::*;

    #[derive(Clone, Default)]
    struct TestClient;

    impl ClientHandler for TestClient {}

    #[test]
    fn conservation_metadata_records_revision_sensitive_result_fields() {
        let federation = Federation::demo();
        let identity = &federation
            .tools()
            .next()
            .expect("demo federation has a tool")
            .identity;
        let mut meta = None;

        bind_result_meta(
            &mut meta,
            identity,
            Some(&ResultType::COMPLETE),
            Some(5_000),
            Some(&CacheScope::Private),
        );

        let conservation = meta
            .as_ref()
            .and_then(|meta| meta.0.get("dev.gaugemesh/conservation"))
            .expect("conservation metadata is present");
        assert_eq!(conservation["capabilityId"], identity.digest().to_string());
        assert_eq!(
            conservation["schemaDigest"],
            identity.schema_digest.to_string()
        );
        assert_eq!(conservation["resultTypePreserved"], true);
        assert_eq!(conservation["ttlMsPreserved"], true);
        assert_eq!(conservation["cacheScopePreserved"], true);
    }

    #[tokio::test]
    async fn rmcp_client_sees_collision_safe_tools_resources_and_prompts() {
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            MeshMcpServer::demo()
                .serve(server_side)
                .await
                .unwrap()
                .waiting()
                .await
                .unwrap();
        });
        let client = TestClient.serve(client_side).await.unwrap();
        let tools = client.list_all_tools().await.unwrap();
        assert!(tools.iter().any(|tool| tool.name == "docs-a__search"));
        assert!(tools.iter().any(|tool| tool.name == "docs-b__search"));
        assert!(!tools.iter().any(|tool| tool.name == "gaugemesh_submit"));
        assert_eq!(client.list_all_resources().await.unwrap().len(), 2);
        assert_eq!(client.list_all_prompts().await.unwrap().len(), 2);
        client.cancel().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn compressed_mode_requires_and_enforces_a_capability_lease() {
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            MeshMcpServer::configured(
                Federation::demo(),
                None,
                Arc::new(MemoryStorage::default()),
                None,
                CapabilityMode::Lease,
            )
            .serve(server_side)
            .await
            .unwrap()
            .waiting()
            .await
            .unwrap();
        });
        let client = TestClient.serve(client_side).await.unwrap();
        let tools = client.list_all_tools().await.unwrap();
        assert!(tools.iter().any(|tool| tool.name == "gaugemesh_lease"));
        assert!(!tools.iter().any(|tool| tool.name == "gaugemesh_submit"));
        assert!(!tools.iter().any(|tool| tool.name == "docs-a__search"));
        let direct = client
            .call_tool_once(CallToolRequestParams::new("docs-a__search"))
            .await;
        assert!(
            direct
                .unwrap_err()
                .to_string()
                .contains("GM_CAPABILITY_LEASE_REQUIRED")
        );

        for invalid_arguments in [
            json!({"aliases": vec!["docs-a__search"; 33]}),
            json!({"aliases":["docs-a__search"],"ttlMs":0}),
            json!({"aliases":["docs-a__search"],"ttlMs":-1}),
            json!({"aliases":["docs-a__search"],"ttlMs":1.5}),
        ] {
            let response = client
                .call_tool_once(
                    CallToolRequestParams::new("gaugemesh_lease")
                        .with_arguments(invalid_arguments.as_object().unwrap().clone()),
                )
                .await
                .unwrap();
            let code = match response {
                CallToolResponse::Complete(result) => result
                    .structured_content
                    .and_then(|value| value.get("code").and_then(Value::as_str).map(str::to_owned))
                    .unwrap(),
                other => panic!("expected bounded lease refusal, got {other:?}"),
            };
            assert_eq!(code, "GM_LEASE_LIMIT_INVALID");
        }

        let lease_response = client
            .call_tool_once(
                CallToolRequestParams::new("gaugemesh_lease").with_arguments(
                    json!({"aliases":["docs-a__search"]})
                        .as_object()
                        .unwrap()
                        .clone(),
                ),
            )
            .await
            .unwrap();
        let mut lease_id = None;
        if let CallToolResponse::Complete(result) = lease_response {
            lease_id = result
                .structured_content
                .as_ref()
                .and_then(|value| value.get("leaseId"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
        }
        let lease_id = lease_id.expect("lease response contains an id");
        let invocation = client
            .call_tool_once(
                CallToolRequestParams::new("gaugemesh_invoke").with_arguments(
                    json!({"leaseId":lease_id,"alias":"docs-a__search","arguments":{"query":"bounded"}})
                        .as_object()
                        .unwrap()
                        .clone(),
                ),
            )
            .await
            .unwrap();
        assert!(matches!(invocation, CallToolResponse::Complete(_)));
        client.cancel().await.unwrap();
        server.await.unwrap();
    }

    #[test]
    fn remote_write_effects_require_explicit_scopes() {
        let mut identity = AuthenticatedIdentity {
            principal: PrincipalId("remote-caller".into()),
            tenant: TenantId("tenant-a".into()),
            scopes: vec![],
        };
        assert!(identity_authorizes_effect(
            &identity,
            SideEffectClass::ReadOnly
        ));
        assert!(!identity_authorizes_effect(
            &identity,
            SideEffectClass::IdempotentWrite
        ));
        assert!(!identity_authorizes_effect(
            &identity,
            SideEffectClass::NonIdempotentWrite
        ));
        identity
            .scopes
            .push("gaugemesh:effect:idempotent-write".into());
        assert!(identity_authorizes_effect(
            &identity,
            SideEffectClass::IdempotentWrite
        ));
        assert!(!identity_authorizes_effect(
            &identity,
            SideEffectClass::NonIdempotentWrite
        ));
    }
}
