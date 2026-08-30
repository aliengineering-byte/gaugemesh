use std::{collections::BTreeMap, sync::Arc};

use anyhow::{Context, Result};
use gaugemesh_core::{
    capability::CapabilityId,
    context::{
        CapabilityScope, MoneyBudgetMicros, PrincipalId, RetryBudget, TenantId, TokenBudget,
    },
    federation::{FederatedTool, Federation},
    lease::{CapabilityLease, LeaseError},
};
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler, model::*, service::RequestContext};
use serde_json::{Map, Value, json};
use tokio::sync::Mutex;

#[derive(Clone, Debug)]
pub struct MeshMcpServer {
    state: Arc<MeshMcpState>,
}

#[derive(Debug)]
struct MeshMcpState {
    federation: Federation,
    leases: Mutex<BTreeMap<String, CapabilityLease>>,
    started: std::time::Instant,
}

impl MeshMcpServer {
    pub fn demo() -> Self {
        Self {
            state: Arc::new(MeshMcpState {
                federation: Federation::demo(),
                leases: Mutex::new(BTreeMap::new()),
                started: std::time::Instant::now(),
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
    ) -> CallToolResult {
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
                CallToolResult::structured(json!({"results": results}))
            }
            "gaugemesh_describe" => {
                let alias = arguments.get("alias").and_then(Value::as_str).unwrap_or("");
                match self.state.federation.tool(alias) {
                    Ok(tool) => CallToolResult::structured(json!({
                        "alias": tool.alias,
                        "capabilityId": tool.identity.digest().to_string(),
                        "schemaDigest": tool.identity.schema_digest.to_string(),
                        "source": tool.identity.source.0,
                        "sideEffect": tool.side_effect,
                        "inputSchema": tool.input_schema,
                    })),
                    Err(error) => tool_error(error.to_string()),
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
                    return tool_error("GM_LEASE_CAPABILITY_OUTSIDE_CONE");
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
                self.state
                    .leases
                    .lock()
                    .await
                    .insert(lease.id.0.clone(), lease.clone());
                CallToolResult::structured(json!({
                    "leaseId": lease.id.0,
                    "manifestDigest": lease.manifest_digest.to_string(),
                    "expiresInMs": ttl_ms,
                    "capabilities": lease.capabilities.iter().map(CapabilityId::digest).map(|digest| digest.to_string()).collect::<Vec<_>>(),
                }))
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
                    Err(error) => return tool_error(error.to_string()),
                };
                let leases = self.state.leases.lock().await;
                let Some(lease) = leases.get(lease_id) else {
                    return tool_error("GM_LEASE_CAPABILITY_OUTSIDE_CONE");
                };
                let now = self.state.started.elapsed().as_millis() as u64;
                match lease.authorize(&local_principal(), &local_tenant(), &tool.identity, now) {
                    Ok(()) => Self::tool_result(tool, tool_arguments),
                    Err(error) => tool_error(lease_error_code(error)),
                }
            }
            "gaugemesh_release" => {
                let lease_id = arguments
                    .get("leaseId")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let released = self.state.leases.lock().await.remove(lease_id).is_some();
                CallToolResult::structured(json!({"released": released}))
            }
            _ => tool_error("GM_CAPABILITY_NOT_FOUND"),
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
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let mut tools = self.state.federation.rmcp_tools();
        tools.extend(Self::meta_tools());
        Ok(ListToolsResult::with_all_items(tools)
            .with_ttl_ms(5_000)
            .with_cache_scope(CacheScope::Private))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        if request.name.starts_with("gaugemesh_") {
            return Ok(self
                .call_meta_tool(&request.name, request.arguments)
                .await
                .into());
        }
        Ok(match self.state.federation.tool(&request.name) {
            Ok(tool) => Self::tool_result(tool, request.arguments.as_ref()),
            Err(error) => tool_error(error.to_string()),
        }
        .into())
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        Ok(
            ListResourcesResult::with_all_items(self.state.federation.rmcp_resources())
                .with_ttl_ms(5_000)
                .with_cache_scope(CacheScope::Private),
        )
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        Ok(
            ListResourceTemplatesResult::with_all_items(self.state.federation.rmcp_templates())
                .with_ttl_ms(5_000)
                .with_cache_scope(CacheScope::Private),
        )
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, McpError> {
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
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, McpError> {
        Ok(
            ListPromptsResult::with_all_items(self.state.federation.rmcp_prompts())
                .with_ttl_ms(5_000)
                .with_cache_scope(CacheScope::Private),
        )
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
            .map_err(|_| McpError::invalid_params("GM_PROMPT_NOT_FOUND", None))?;
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

pub async fn serve_stdio() -> Result<()> {
    use rmcp::ServiceExt as _;
    let service = MeshMcpServer::demo()
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
}
