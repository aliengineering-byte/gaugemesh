use std::{collections::BTreeMap, path::Path, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use gaugemesh_core::{
    capability::{CapabilityId, CapabilityKind, CapabilityRevision, SourceId},
    config::{DiscoveryMode, McpSourceConfig, McpTransportConfig},
    context::SideEffectClass,
    digest::Sha256Digest,
    federation::{
        FederatedPrompt, FederatedResource, FederatedResourceTemplate, FederatedTool, Federation,
    },
    protocol::McpRevision,
};
use rmcp::{
    ClientHandler, ClientLifecycleMode, ClientServiceExt, ErrorData as McpError, Peer, RoleClient,
    ServiceExt,
    model::{
        CallToolRequestParams, CallToolResponse, ClientCapabilities, ClientInfo,
        GetPromptRequestParams, GetPromptResponse, Implementation, ProtocolVersion,
        ReadResourceRequestParams, ReadResourceResponse,
    },
    service::RequestContext as McpRequestContext,
    service::RunningService,
    transport::{StreamableHttpClientTransport, TokioChildProcess},
};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::Mutex;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamSnapshot {
    pub protocol_revision: String,
    pub server_name: String,
    pub tools: Vec<String>,
    pub resources: Vec<String>,
    pub resource_templates: Vec<String>,
    pub prompts: Vec<String>,
}

async fn snapshot(peer: &Peer<RoleClient>) -> Result<UpstreamSnapshot> {
    let info = peer
        .peer_info()
        .context("GM_MCP_UPSTREAM_MISSING_SERVER_IDENTITY")?;
    let tools = if info.capabilities.tools.is_some() {
        peer.list_all_tools()
            .await
            .context("GM_MCP_UPSTREAM_TOOLS_LIST")?
            .into_iter()
            .map(|item| item.name.into_owned())
            .collect()
    } else {
        Vec::new()
    };
    let resources = if info.capabilities.resources.is_some() {
        peer.list_all_resources()
            .await
            .context("GM_MCP_UPSTREAM_RESOURCES_LIST")?
            .into_iter()
            .map(|item| item.uri)
            .collect()
    } else {
        Vec::new()
    };
    let resource_templates = if info.capabilities.resources.is_some() {
        peer.list_all_resource_templates()
            .await
            .context("GM_MCP_UPSTREAM_RESOURCE_TEMPLATES_LIST")?
            .into_iter()
            .map(|item| item.uri_template)
            .collect()
    } else {
        Vec::new()
    };
    let prompts = if info.capabilities.prompts.is_some() {
        peer.list_all_prompts()
            .await
            .context("GM_MCP_UPSTREAM_PROMPTS_LIST")?
            .into_iter()
            .map(|item| item.name)
            .collect()
    } else {
        Vec::new()
    };
    let server_name = info
        .server_info
        .as_ref()
        .context("GM_MCP_UPSTREAM_MISSING_IMPLEMENTATION")?
        .name
        .clone();
    Ok(UpstreamSnapshot {
        protocol_revision: info.protocol_version.to_string(),
        server_name,
        tools,
        resources,
        resource_templates,
        prompts,
    })
}

pub async fn discover_http_revision(
    uri: &str,
    revision: McpRevision,
    timeout: Duration,
) -> Result<UpstreamSnapshot> {
    let parsed = url::Url::parse(uri).context("GM_MCP_UPSTREAM_URL_INVALID")?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        bail!("GM_MCP_UPSTREAM_SCHEME_DENIED");
    }
    let transport = StreamableHttpClientTransport::from_uri(uri.to_owned());
    let client = tokio::time::timeout(timeout, async move {
        match revision {
            McpRevision::V2025_11_25 => client_info(revision).serve(transport).await,
            McpRevision::V2026_07_28 => {
                client_info(revision)
                    .serve_with_lifecycle(
                        transport,
                        ClientLifecycleMode::Discover {
                            preferred_versions: vec![ProtocolVersion::V_2026_07_28],
                        },
                    )
                    .await
            }
        }
    })
    .await
    .context("GM_MCP_UPSTREAM_STARTUP_TIMEOUT")??;
    let result = tokio::time::timeout(timeout, snapshot(client.peer()))
        .await
        .context("GM_MCP_UPSTREAM_DISCOVERY_TIMEOUT")?;
    client.cancel().await.context("GM_MCP_UPSTREAM_CLEANUP")?;
    result
}

pub async fn discover_stdio(
    executable: &Path,
    args: &[String],
    allowlist: &[std::path::PathBuf],
    revision: McpRevision,
    timeout: Duration,
) -> Result<UpstreamSnapshot> {
    if !executable.is_absolute() || !allowlist.iter().any(|allowed| allowed == executable) {
        bail!("GM_MCP_EXECUTABLE_NOT_ALLOWLISTED");
    }
    let mut command = tokio::process::Command::new(executable);
    command.args(args).kill_on_drop(true);
    let transport = TokioChildProcess::new(command).context("GM_MCP_UPSTREAM_SPAWN")?;
    let client = tokio::time::timeout(timeout, async move {
        match revision {
            McpRevision::V2025_11_25 => client_info(revision).serve(transport).await,
            McpRevision::V2026_07_28 => {
                client_info(revision)
                    .serve_with_lifecycle(
                        transport,
                        ClientLifecycleMode::Discover {
                            preferred_versions: vec![ProtocolVersion::V_2026_07_28],
                        },
                    )
                    .await
            }
        }
    })
    .await
    .context("GM_MCP_UPSTREAM_STARTUP_TIMEOUT")??;
    let result = tokio::time::timeout(timeout, snapshot(client.peer()))
        .await
        .context("GM_MCP_UPSTREAM_DISCOVERY_TIMEOUT")?;
    client.cancel().await.context("GM_MCP_UPSTREAM_CLEANUP")?;
    result
}

#[derive(Clone)]
pub(crate) struct GatewayClient {
    info: ClientInfo,
}

impl ClientHandler for GatewayClient {
    fn get_info(&self) -> ClientInfo {
        self.info.clone()
    }

    #[allow(deprecated)]
    async fn create_message(
        &self,
        _params: rmcp::model::CreateMessageRequestParams,
        _context: McpRequestContext<RoleClient>,
    ) -> Result<rmcp::model::CreateMessageResult, McpError> {
        Err(sampling_unavailable())
    }

    async fn create_elicitation(
        &self,
        _request: rmcp::model::ElicitRequestParams,
        _context: McpRequestContext<RoleClient>,
    ) -> Result<rmcp::model::ElicitResult, McpError> {
        Ok(rmcp::model::ElicitResult::new(
            rmcp::model::ElicitationAction::Decline,
        ))
    }
}

fn sampling_unavailable() -> McpError {
    McpError::invalid_request("GM_SAMPLING_COMPAT_DISABLED", None)
}

fn client_info(revision: McpRevision) -> GatewayClient {
    let protocol = match revision {
        McpRevision::V2025_11_25 => ProtocolVersion::V_2025_11_25,
        McpRevision::V2026_07_28 => ProtocolVersion::V_2026_07_28,
    };
    GatewayClient {
        info: ClientInfo::new(
            ClientCapabilities::default(),
            Implementation::new("gaugemesh", env!("CARGO_PKG_VERSION")),
        )
        .with_protocol_version(protocol),
    }
}

type ActiveClient = RunningService<RoleClient, GatewayClient>;

pub struct UpstreamRuntime {
    peers: BTreeMap<String, Peer<RoleClient>>,
    services: Mutex<Vec<ActiveClient>>,
    incomplete_sources: Vec<String>,
}

impl UpstreamRuntime {
    pub fn incomplete_sources(&self) -> &[String] {
        &self.incomplete_sources
    }

    pub fn contains_source(&self, source: &SourceId) -> bool {
        self.peers.contains_key(&source.0)
    }

    pub async fn call_tool(
        &self,
        source: &SourceId,
        request: CallToolRequestParams,
    ) -> Result<CallToolResponse> {
        let peer = self
            .peers
            .get(&source.0)
            .context("GM_MCP_UPSTREAM_SOURCE_UNAVAILABLE")?;
        tokio::time::timeout(Duration::from_secs(30), peer.call_tool_once(request))
            .await
            .context("GM_MCP_UPSTREAM_CALL_TIMEOUT")?
            .context("GM_MCP_UPSTREAM_CALL")
    }

    pub async fn read_resource(
        &self,
        source: &SourceId,
        request: ReadResourceRequestParams,
    ) -> Result<ReadResourceResponse> {
        let peer = self
            .peers
            .get(&source.0)
            .context("GM_MCP_UPSTREAM_SOURCE_UNAVAILABLE")?;
        tokio::time::timeout(Duration::from_secs(30), peer.read_resource_once(request))
            .await
            .context("GM_MCP_UPSTREAM_READ_TIMEOUT")?
            .context("GM_MCP_UPSTREAM_READ")
    }

    pub async fn get_prompt(
        &self,
        source: &SourceId,
        request: GetPromptRequestParams,
    ) -> Result<GetPromptResponse> {
        let peer = self
            .peers
            .get(&source.0)
            .context("GM_MCP_UPSTREAM_SOURCE_UNAVAILABLE")?;
        tokio::time::timeout(Duration::from_secs(30), peer.get_prompt_once(request))
            .await
            .context("GM_MCP_UPSTREAM_PROMPT_TIMEOUT")?
            .context("GM_MCP_UPSTREAM_PROMPT")
    }

    pub async fn shutdown(&self) -> Result<()> {
        let mut services = self.services.lock().await;
        for service in services.iter_mut() {
            if service
                .close_with_timeout(Duration::from_secs(5))
                .await
                .context("GM_MCP_UPSTREAM_CLEANUP")?
                .is_none()
            {
                bail!("GM_MCP_UPSTREAM_CLEANUP_TIMEOUT");
            }
        }
        services.clear();
        Ok(())
    }
}

pub async fn connect_configured_sources(
    sources: &[McpSourceConfig],
    mode: DiscoveryMode,
    timeout: Duration,
) -> Result<(Federation, Arc<UpstreamRuntime>)> {
    let mut federation = Federation::default();
    let mut peers = BTreeMap::new();
    let mut services = Vec::new();
    let mut incomplete_sources = Vec::new();

    for source in sources {
        match connect_source(source, timeout).await {
            Ok(service) => {
                if let Err(error) =
                    add_source_capabilities(&mut federation, source, service.peer()).await
                {
                    let _ = service.cancel().await;
                    if mode == DiscoveryMode::Strict {
                        return Err(error);
                    }
                    incomplete_sources.push(source.id.clone());
                    continue;
                }
                peers.insert(source.id.clone(), service.peer().clone());
                services.push(service);
            }
            Err(error) if mode == DiscoveryMode::Degraded => {
                tracing::warn!(source = %source.id, error = %error, "MCP source unavailable in degraded mode");
                incomplete_sources.push(source.id.clone());
            }
            Err(error) => return Err(error),
        }
    }

    incomplete_sources.sort();
    Ok((
        federation,
        Arc::new(UpstreamRuntime {
            peers,
            services: Mutex::new(services),
            incomplete_sources,
        }),
    ))
}

async fn connect_source(source: &McpSourceConfig, timeout: Duration) -> Result<ActiveClient> {
    let revision =
        McpRevision::parse(&source.protocol_revision).map_err(|error| anyhow::anyhow!(error))?;
    let start = async {
        match &source.transport {
            McpTransportConfig::StreamableHttp { url } => {
                let transport = StreamableHttpClientTransport::from_uri(url.to_string());
                serve_client(revision, transport).await
            }
            McpTransportConfig::Stdio { command, args } => {
                if !command.is_absolute() || !command.is_file() {
                    bail!("GM_MCP_EXECUTABLE_NOT_ALLOWLISTED");
                }
                let mut process = tokio::process::Command::new(command);
                process.args(args).kill_on_drop(true);
                let transport = TokioChildProcess::new(process).context("GM_MCP_UPSTREAM_SPAWN")?;
                serve_client(revision, transport).await
            }
        }
    };
    tokio::time::timeout(timeout, start)
        .await
        .context("GM_MCP_UPSTREAM_STARTUP_TIMEOUT")?
}

async fn serve_client<T, E, A>(revision: McpRevision, transport: T) -> Result<ActiveClient>
where
    T: rmcp::transport::IntoTransport<RoleClient, E, A>,
    E: std::error::Error + Send + Sync + 'static,
{
    let service = match revision {
        McpRevision::V2025_11_25 => client_info(revision).serve(transport).await?,
        McpRevision::V2026_07_28 => {
            client_info(revision)
                .serve_with_lifecycle(
                    transport,
                    ClientLifecycleMode::Discover {
                        preferred_versions: vec![ProtocolVersion::V_2026_07_28],
                    },
                )
                .await?
        }
    };
    Ok(service)
}

async fn add_source_capabilities(
    federation: &mut Federation,
    source: &McpSourceConfig,
    peer: &Peer<RoleClient>,
) -> Result<()> {
    let info = peer
        .peer_info()
        .context("GM_MCP_UPSTREAM_MISSING_SERVER_IDENTITY")?;
    let source_id = SourceId(source.id.clone());
    let revision = CapabilityRevision(info.protocol_version.to_string());
    let configuration_digest = Sha256Digest::of_json(&serde_json::to_value(source)?);

    if info.capabilities.tools.is_some() {
        for tool in peer
            .list_all_tools()
            .await
            .context("GM_MCP_UPSTREAM_TOOLS_LIST")?
        {
            let schema = Value::Object((*tool.input_schema).clone());
            reject_oversized_metadata(&schema)?;
            let identity = CapabilityId::new(
                source_id.clone(),
                CapabilityKind::Tool,
                &tool.name,
                Sha256Digest::of_json(&serde_json::to_value(&tool)?),
                revision.clone(),
                configuration_digest,
            );
            let side_effect = match tool.annotations.as_ref() {
                Some(annotations) if annotations.read_only_hint == Some(true) => {
                    SideEffectClass::ReadOnly
                }
                Some(annotations) if annotations.idempotent_hint == Some(true) => {
                    SideEffectClass::IdempotentWrite
                }
                _ => SideEffectClass::NonIdempotentWrite,
            };
            federation.insert_tool(FederatedTool {
                alias: identity.readable_alias(&tool.name),
                identity,
                native_name: tool.name.into_owned(),
                description: bounded_text(tool.description.as_deref().unwrap_or(""), 4_096),
                input_schema: schema,
                side_effect,
                fixture_result: Value::Null,
            })?;
        }
    }

    if info.capabilities.resources.is_some() {
        for resource in peer
            .list_all_resources()
            .await
            .context("GM_MCP_UPSTREAM_RESOURCES_LIST")?
        {
            let identity = CapabilityId::new(
                source_id.clone(),
                CapabilityKind::Resource,
                &resource.uri,
                Sha256Digest::of_json(&serde_json::to_value(&resource)?),
                revision.clone(),
                configuration_digest,
            );
            federation.insert_resource(FederatedResource {
                virtual_uri: format!(
                    "gaugemesh://resource/{}/{}",
                    source.id,
                    &identity.native_identity_digest.to_string()[7..31]
                ),
                identity,
                native_uri: resource.uri,
                name: bounded_text(&resource.name, 1_024),
                mime_type: resource
                    .mime_type
                    .unwrap_or_else(|| "application/octet-stream".into()),
                contents: String::new(),
            })?;
        }

        for template in peer
            .list_all_resource_templates()
            .await
            .context("GM_MCP_UPSTREAM_RESOURCE_TEMPLATES_LIST")?
        {
            let Some(variables) = simple_template_variables(&template.uri_template) else {
                tracing::warn!(source = %source.id, template = %template.uri_template, "unsupported RFC 6570 expression omitted");
                continue;
            };
            let identity = CapabilityId::new(
                source_id.clone(),
                CapabilityKind::ResourceTemplate,
                &template.uri_template,
                Sha256Digest::of_json(&serde_json::to_value(&template)?),
                revision.clone(),
                configuration_digest,
            );
            let prefix = format!(
                "gaugemesh://template/{}/{}/",
                source.id,
                &identity.native_identity_digest.to_string()[7..31]
            );
            let suffix = variables
                .iter()
                .map(|variable| format!("{{{variable}}}"))
                .collect::<Vec<_>>()
                .join("/");
            federation.insert_template(FederatedResourceTemplate {
                identity,
                virtual_uri_template: format!("{prefix}{suffix}"),
                virtual_prefix: prefix,
                native_uri_template: template.uri_template,
                name: bounded_text(&template.name, 1_024),
                description: bounded_text(template.description.as_deref().unwrap_or(""), 4_096),
                mime_type: template.mime_type,
                variables,
            })?;
        }
    }

    if info.capabilities.prompts.is_some() {
        for prompt in peer
            .list_all_prompts()
            .await
            .context("GM_MCP_UPSTREAM_PROMPTS_LIST")?
        {
            let identity = CapabilityId::new(
                source_id.clone(),
                CapabilityKind::Prompt,
                &prompt.name,
                Sha256Digest::of_json(&serde_json::to_value(&prompt)?),
                revision.clone(),
                configuration_digest,
            );
            federation.insert_prompt(FederatedPrompt {
                alias: identity.readable_alias(&prompt.name),
                identity,
                native_name: prompt.name,
                description: bounded_text(prompt.description.as_deref().unwrap_or(""), 4_096),
                arguments: prompt
                    .arguments
                    .unwrap_or_default()
                    .into_iter()
                    .map(|argument| argument.name)
                    .collect(),
                template: String::new(),
            })?;
        }
    }
    Ok(())
}

fn reject_oversized_metadata(value: &Value) -> Result<()> {
    if serde_json::to_vec(value)?.len() > 256 * 1024 {
        bail!("GM_MCP_UPSTREAM_METADATA_TOO_LARGE");
    }
    Ok(())
}

fn bounded_text(value: &str, max_bytes: usize) -> String {
    let mut boundary = value.len().min(max_bytes);
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value[..boundary].to_owned()
}

fn simple_template_variables(template: &str) -> Option<Vec<String>> {
    let mut variables = Vec::new();
    let mut remaining = template;
    while let Some(open) = remaining.find('{') {
        let after_open = &remaining[open + 1..];
        let close = after_open.find('}')?;
        let variable = &after_open[..close];
        if variable.is_empty()
            || variable.len() > 64
            || !variable.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
            })
        {
            return None;
        }
        variables.push(variable.to_owned());
        remaining = &after_open[close + 1..];
    }
    if remaining.contains('}') || variables.is_empty() || variables.len() > 8 {
        None
    } else {
        Some(variables)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::{MeshMcpServer, router};

    #[tokio::test]
    async fn http_client_discovers_tools_resources_and_prompts() {
        let cancellation = tokio_util::sync::CancellationToken::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(
            axum::serve(
                listener,
                router(MeshMcpServer::demo(), cancellation.clone()),
            )
            .with_graceful_shutdown({
                let cancellation = cancellation.clone();
                async move { cancellation.cancelled().await }
            })
            .into_future(),
        );
        for revision in [McpRevision::V2025_11_25, McpRevision::V2026_07_28] {
            let snapshot = discover_http_revision(
                &format!("http://{address}/mcp"),
                revision,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
            assert_eq!(snapshot.protocol_revision, revision.as_str());
            assert!(snapshot.tools.contains(&"docs-a__search".into()));
            assert_eq!(snapshot.resources.len(), 2);
            assert_eq!(snapshot.prompts.len(), 2);
        }
        cancellation.cancel();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn configured_runtime_forwards_tools_resources_and_prompts() {
        let upstream_cancellation = tokio_util::sync::CancellationToken::new();
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream_listener.local_addr().unwrap();
        let upstream_server = tokio::spawn(
            axum::serve(
                upstream_listener,
                router(MeshMcpServer::demo(), upstream_cancellation.clone()),
            )
            .with_graceful_shutdown({
                let cancellation = upstream_cancellation.clone();
                async move { cancellation.cancelled().await }
            })
            .into_future(),
        );

        let source = McpSourceConfig {
            id: "reviewed-upstream".into(),
            transport: McpTransportConfig::StreamableHttp {
                url: url::Url::parse(&format!("http://{upstream_address}/mcp")).unwrap(),
            },
            protocol_revision: "2025-11-25".into(),
            sharing: gaugemesh_core::config::SharingClass::NonShareable,
            reviewed: true,
        };
        let (federation, upstreams) =
            connect_configured_sources(&[source], DiscoveryMode::Strict, Duration::from_secs(5))
                .await
                .unwrap();
        assert!(upstreams.incomplete_sources().is_empty());

        let downstream_cancellation = tokio_util::sync::CancellationToken::new();
        let downstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let downstream_address = downstream_listener.local_addr().unwrap();
        let downstream_server = tokio::spawn(
            axum::serve(
                downstream_listener,
                router(
                    MeshMcpServer::configured(
                        federation,
                        Some(upstreams.clone()),
                        std::sync::Arc::new(gaugemesh_core::storage::MemoryStorage::default()),
                        gaugemesh_core::config::CapabilityMode::Transparent,
                    ),
                    downstream_cancellation.clone(),
                ),
            )
            .with_graceful_shutdown({
                let cancellation = downstream_cancellation.clone();
                async move { cancellation.cancelled().await }
            })
            .into_future(),
        );

        let transport =
            StreamableHttpClientTransport::from_uri(format!("http://{downstream_address}/mcp"));
        let client = client_info(McpRevision::V2026_07_28)
            .serve_with_lifecycle(
                transport,
                ClientLifecycleMode::Discover {
                    preferred_versions: vec![ProtocolVersion::V_2026_07_28],
                },
            )
            .await
            .unwrap();
        let tools = client.list_all_tools().await.unwrap();
        let alias = tools
            .iter()
            .map(|tool| tool.name.as_ref())
            .find(|name| name.ends_with("docs-a__search"))
            .unwrap()
            .to_owned();
        let tool_response = client
            .call_tool_once(
                CallToolRequestParams::new(alias).with_arguments(
                    serde_json::json!({"query":"identity"})
                        .as_object()
                        .unwrap()
                        .clone(),
                ),
            )
            .await
            .unwrap();
        assert!(matches!(tool_response, CallToolResponse::Complete(_)));

        let resource = client.list_all_resources().await.unwrap().remove(0);
        let resource_response = client
            .read_resource_once(ReadResourceRequestParams::new(resource.uri.clone()))
            .await
            .unwrap();
        assert!(matches!(
            &resource_response,
            ReadResourceResponse::Complete(_)
        ));
        if let ReadResourceResponse::Complete(resource_result) = resource_response {
            assert!(
                resource_result
                    .contents
                    .iter()
                    .all(|contents| match contents {
                        rmcp::model::ResourceContents::TextResourceContents { uri, .. }
                        | rmcp::model::ResourceContents::BlobResourceContents { uri, .. } => {
                            uri == &resource.uri
                        }
                        _ => false,
                    })
            );
        }

        let prompt = client.list_all_prompts().await.unwrap().remove(0);
        let prompt_response = client
            .get_prompt_once(
                GetPromptRequestParams::new(prompt.name).with_arguments(
                    serde_json::json!({"topic":"leases"})
                        .as_object()
                        .unwrap()
                        .clone(),
                ),
            )
            .await
            .unwrap();
        assert!(matches!(prompt_response, GetPromptResponse::Complete(_)));

        client.cancel().await.unwrap();
        downstream_cancellation.cancel();
        downstream_server.await.unwrap().unwrap();
        upstreams.shutdown().await.unwrap();
        upstream_cancellation.cancel();
        upstream_server.await.unwrap().unwrap();
    }

    #[test]
    fn deprecated_sampling_is_never_silently_dropped() {
        assert_eq!(
            sampling_unavailable().message,
            "GM_SAMPLING_COMPAT_DISABLED"
        );
        assert!(
            client_info(McpRevision::V2026_07_28)
                .get_info()
                .capabilities
                .sampling
                .is_none()
        );
    }
}
