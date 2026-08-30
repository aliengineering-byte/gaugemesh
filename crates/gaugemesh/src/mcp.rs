use std::{collections::BTreeMap, sync::Arc};

use crate::outbound::UpstreamRuntime;
use anyhow::{Context, Result};
use gaugemesh_core::{
    capability::CapabilityId,
    config::CapabilityMode,
    context::{
        CapabilityScope, MoneyBudgetMicros, PrincipalId, RetryBudget, TenantId, TokenBudget,
    },
    digest::Sha256Digest,
    federation::{CompositeCursor, FederatedTool, Federation, open_cursor, seal_cursor},
    lease::{CapabilityLease, LeaseError},
    storage::{LeaseStorage, MemoryStorage},
};
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler, model::*, service::RequestContext};
use serde_json::{Map, Value, json};

#[derive(Clone)]
pub struct MeshMcpServer {
    state: Arc<MeshMcpState>,
}

struct MeshMcpState {
    federation: Federation,
    leases: Arc<dyn LeaseStorage>,
    started: std::time::Instant,
    upstreams: Option<Arc<UpstreamRuntime>>,
    capability_mode: CapabilityMode,
    cursor_key: [u8; 32],
}

impl MeshMcpServer {
    pub fn demo() -> Self {
        Self {
            state: Arc::new(MeshMcpState {
                federation: Federation::demo(),
                leases: Arc::new(MemoryStorage::default()),
                started: std::time::Instant::now(),
                upstreams: None,
                capability_mode: CapabilityMode::Transparent,
                cursor_key: *Sha256Digest::of_bytes(uuid::Uuid::new_v4().as_bytes()).as_bytes(),
            }),
        }
    }

    pub fn configured(
        federation: Federation,
        upstreams: Option<Arc<UpstreamRuntime>>,
        leases: Arc<dyn LeaseStorage>,
        capability_mode: CapabilityMode,
    ) -> Self {
        Self {
            state: Arc::new(MeshMcpState {
                federation,
                leases,
                started: std::time::Instant::now(),
                upstreams,
                capability_mode,
                cursor_key: *Sha256Digest::of_bytes(uuid::Uuid::new_v4().as_bytes()).as_bytes(),
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
                "Issue a bounded local capability lease",
                json!({"type":"object","properties":{"aliases":{"type":"array","items":{"type":"string"},"maxItems":32},"ttlMs":{"type":"integer","minimum":1,"maximum":600000}},"required":["aliases"],"additionalProperties":false}),
            ),
            (
                "gaugemesh_invoke",
                "Invoke a capability inside an exact lease",
                json!({"type":"object","properties":{"leaseId":{"type":"string"},"alias":{"type":"string"},"arguments":{"type":"object"}},"required":["leaseId","alias"],"additionalProperties":false}),
            ),
            (
                "gaugemesh_release",
                "Release a capability lease",
                json!({"type":"object","properties":{"leaseId":{"type":"string"}},"required":["leaseId"],"additionalProperties":false}),
            ),
        ]
        .into_iter()
        .map(|(name, description, schema)| {
            Tool::new(
                name,
                description,
                Arc::new(schema.as_object().cloned().expect("schema object")),
            )
            .with_annotations(ToolAnnotations::from_raw(
                None,
                Some(name != "gaugemesh_invoke"),
                Some(false),
                Some(true),
                Some(false),
            ))
        })
        .collect()
    }

    async fn call_meta_tool(
        &self,
        name: &str,
        arguments: Option<Map<String, Value>>,
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
                let aliases = arguments
                    .get("aliases")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let capabilities = aliases
                    .iter()
                    .filter_map(Value::as_str)
                    .filter_map(|alias| self.state.federation.tool(alias).ok())
                    .map(|tool| tool.identity.clone())
                    .collect::<Vec<_>>();
                if capabilities.len() != aliases.len() || capabilities.is_empty() {
                    return Ok(tool_error("GM_LEASE_CAPABILITY_OUTSIDE_CONE").into());
                }
                let ttl_ms = arguments
                    .get("ttlMs")
                    .and_then(Value::as_u64)
                    .unwrap_or(60_000)
                    .min(600_000);
                let lease = CapabilityLease::issue(
                    local_principal(),
                    local_tenant(),
                    "mcp-request".into(),
                    capabilities,
                    CapabilityScope::default(),
                    self.state.started.elapsed().as_millis() as u64 + ttl_ms,
                    MoneyBudgetMicros(0),
                    TokenBudget(4_096),
                    RetryBudget(1),
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
                let now = self.state.started.elapsed().as_millis() as u64;
                let authorization = lease.authorize_invocation(
                    &local_principal(),
                    &local_tenant(),
                    &tool.identity,
                    tool.side_effect,
                    now,
                );
                match authorization {
                    Ok(()) => self.invoke_tool(tool, tool_arguments.cloned()).await,
                    Err(error) => Ok(tool_error(lease_error_code(error)).into()),
                }
            }
            "gaugemesh_release" => {
                let lease_id = arguments
                    .get("leaseId")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let released = self
                    .state
                    .leases
                    .get(lease_id)
                    .map_err(|_| McpError::internal_error("GM_STORAGE_READ", None))?
                    .is_some();
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
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_prompts()
                .build(),
        )
        .with_server_info(Implementation::new("gaugemesh", env!("CARGO_PKG_VERSION")))
        .with_protocol_version(ProtocolVersion::V_2026_07_28)
        .with_instructions("Reviewed capabilities with stable identities and bounded leases.")
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let mut tools = if self.state.capability_mode == CapabilityMode::Transparent {
            self.state.federation.rmcp_tools()
        } else {
            Vec::new()
        };
        tools.extend(Self::meta_tools());
        let (tools, next_cursor) = self.page("tools", tools, request)?;
        let mut result = ListToolsResult::with_all_items(tools)
            .with_ttl_ms(5_000)
            .with_cache_scope(CacheScope::Private);
        result.meta = self.discovery_meta();
        result.next_cursor = next_cursor;
        Ok(result)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        if request.name.starts_with("gaugemesh_") {
            return self.call_meta_tool(&request.name, request.arguments).await;
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

    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        let (resources, next_cursor) =
            self.page("resources", self.state.federation.rmcp_resources(), request)?;
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
        let (templates, next_cursor) = self.page(
            "resource_templates",
            self.state.federation.rmcp_templates(),
            request,
        )?;
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
        let (prompts, next_cursor) =
            self.page("prompts", self.state.federation.rmcp_prompts(), request)?;
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

fn tool_error(message: impl Into<String>) -> CallToolResult {
    CallToolResult::structured_error(json!({"code": message.into()}))
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
    axum::Router::new().nest_service("/mcp", service)
}

#[cfg(test)]
mod tests {
    use rmcp::{ClientHandler, ServiceExt};

    use super::*;

    #[derive(Clone, Default)]
    struct TestClient;

    impl ClientHandler for TestClient {}

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
}
