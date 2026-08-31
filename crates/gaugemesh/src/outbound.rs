use std::{
    collections::BTreeMap,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail};
use gaugemesh_core::{
    capability::{CapabilityId, CapabilityKind, CapabilityRevision, SourceId},
    config::{ApprovalConfig, DiscoveryMode, McpSourceConfig, McpTransportConfig},
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
    transport::{
        StreamableHttpClientTransport, TokioChildProcess,
        streamable_http_client::StreamableHttpClientTransportConfig,
    },
};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::{Mutex, RwLock};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamSnapshot {
    pub protocol_revision: String,
    pub server_name: String,
    pub capability_manifest_digest: Sha256Digest,
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
    } else {
        Vec::new()
    };
    let resources = if info.capabilities.resources.is_some() {
        peer.list_all_resources()
            .await
            .context("GM_MCP_UPSTREAM_RESOURCES_LIST")?
    } else {
        Vec::new()
    };
    let resource_templates = if info.capabilities.resources.is_some() {
        peer.list_all_resource_templates()
            .await
            .context("GM_MCP_UPSTREAM_RESOURCE_TEMPLATES_LIST")?
    } else {
        Vec::new()
    };
    let prompts = if info.capabilities.prompts.is_some() {
        peer.list_all_prompts()
            .await
            .context("GM_MCP_UPSTREAM_PROMPTS_LIST")?
    } else {
        Vec::new()
    };
    let server_name = info
        .server_info
        .as_ref()
        .context("GM_MCP_UPSTREAM_MISSING_IMPLEMENTATION")?
        .name
        .clone();
    let capability_manifest_digest = Sha256Digest::of_json(&serde_json::json!({
        "protocolRevision": info.protocol_version,
        "serverInfo": info.server_info,
        "capabilities": info.capabilities,
        "tools": tools,
        "resources": resources,
        "resourceTemplates": resource_templates,
        "prompts": prompts,
    }));
    Ok(UpstreamSnapshot {
        protocol_revision: info.protocol_version.to_string(),
        server_name,
        capability_manifest_digest,
        tools: tools
            .into_iter()
            .map(|item| item.name.into_owned())
            .collect(),
        resources: resources.into_iter().map(|item| item.uri).collect(),
        resource_templates: resource_templates
            .into_iter()
            .map(|item| item.uri_template)
            .collect(),
        prompts: prompts.into_iter().map(|item| item.name).collect(),
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
    let transport = safe_http_transport(&parsed).await?;
    let client = tokio::time::timeout(timeout, async move {
        match revision {
            McpRevision::V2025_11_25 => {
                client_info(revision, ApprovalConfig::Deny)
                    .serve(transport)
                    .await
            }
            McpRevision::V2026_07_28 => {
                client_info(revision, ApprovalConfig::Deny)
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
    let resolved = executable
        .canonicalize()
        .context("GM_MCP_EXECUTABLE_NOT_ALLOWLISTED")?;
    let allowed = allowlist.iter().any(|allowed| {
        allowed
            .canonicalize()
            .is_ok_and(|allowed| allowed == resolved)
    });
    if !executable.is_absolute() || !resolved.is_file() || !allowed {
        bail!("GM_MCP_EXECUTABLE_NOT_ALLOWLISTED");
    }
    let command = reviewed_command(&resolved, args)?;
    let transport = TokioChildProcess::new(command).context("GM_MCP_UPSTREAM_SPAWN")?;
    let client = tokio::time::timeout(timeout, async move {
        match revision {
            McpRevision::V2025_11_25 => {
                client_info(revision, ApprovalConfig::Deny)
                    .serve(transport)
                    .await
            }
            McpRevision::V2026_07_28 => {
                client_info(revision, ApprovalConfig::Deny)
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
    approval: ApprovalConfig,
    cli_lock: Arc<Mutex<()>>,
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
        request: rmcp::model::ElicitRequestParams,
        _context: McpRequestContext<RoleClient>,
    ) -> Result<rmcp::model::ElicitResult, McpError> {
        crate::approval::handle(&self.approval, &request, &self.cli_lock).await
    }
}

fn sampling_unavailable() -> McpError {
    McpError::invalid_request("GM_SAMPLING_COMPAT_DISABLED", None)
}

fn client_info(revision: McpRevision, approval: ApprovalConfig) -> GatewayClient {
    let protocol = match revision {
        McpRevision::V2025_11_25 => ProtocolVersion::V_2025_11_25,
        McpRevision::V2026_07_28 => ProtocolVersion::V_2026_07_28,
    };
    GatewayClient {
        info: ClientInfo::new(
            ClientCapabilities::builder()
                .enable_elicitation()
                .enable_elicitation_schema_validation()
                .build(),
            Implementation::new("gaugemesh", env!("CARGO_PKG_VERSION")),
        )
        .with_protocol_version(protocol),
        approval,
        cli_lock: Arc::new(Mutex::new(())),
    }
}

type ActiveClient = RunningService<RoleClient, GatewayClient>;

pub struct UpstreamRuntime {
    sources: BTreeMap<String, Arc<ManagedSource>>,
    incomplete_sources: Vec<String>,
    shutting_down: AtomicBool,
}

struct ManagedSource {
    config: McpSourceConfig,
    peer: RwLock<Peer<RoleClient>>,
    service: Mutex<Option<ActiveClient>>,
    expected_snapshot: Sha256Digest,
    generation: AtomicU64,
    restarts: AtomicU8,
    restart_lock: Mutex<()>,
    serialize_requests: bool,
    request_lock: Mutex<()>,
}

impl UpstreamRuntime {
    pub fn incomplete_sources(&self) -> &[String] {
        &self.incomplete_sources
    }

    pub fn contains_source(&self, source: &SourceId) -> bool {
        self.sources.contains_key(&source.0)
    }

    async fn peer(&self, source: &SourceId) -> Result<(Arc<ManagedSource>, Peer<RoleClient>, u64)> {
        let source = self
            .sources
            .get(&source.0)
            .context("GM_MCP_UPSTREAM_SOURCE_UNAVAILABLE")?
            .clone();
        Ok((
            source.clone(),
            source.peer.read().await.clone(),
            source.generation.load(Ordering::Acquire),
        ))
    }

    async fn restart_after_failure(&self, source_id: &SourceId, observed: u64) -> Result<()> {
        if self.shutting_down.load(Ordering::Acquire) {
            bail!("GM_MCP_UPSTREAM_SHUTTING_DOWN");
        }
        let source = self
            .sources
            .get(&source_id.0)
            .context("GM_MCP_UPSTREAM_SOURCE_UNAVAILABLE")?;
        let _restart = source.restart_lock.lock().await;
        if source.generation.load(Ordering::Acquire) != observed {
            return Ok(());
        }
        source
            .restarts
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |restarts| {
                (restarts < 2).then_some(restarts + 1)
            })
            .map_err(|_| anyhow::anyhow!("GM_MCP_UPSTREAM_RESTART_BUDGET_EXHAUSTED"))?;
        let service = connect_source(&source.config, Duration::from_secs(10)).await?;
        let new_snapshot = tokio::time::timeout(Duration::from_secs(10), snapshot(service.peer()))
            .await
            .context("GM_MCP_UPSTREAM_RESTART_DISCOVERY_TIMEOUT")??;
        if Sha256Digest::of_json(&serde_json::to_value(&new_snapshot)?) != source.expected_snapshot
        {
            let _ = service.cancel().await;
            bail!("GM_MCP_UPSTREAM_IDENTITY_CHANGED");
        }
        let new_peer = service.peer().clone();
        let old = source.service.lock().await.replace(service);
        *source.peer.write().await = new_peer;
        source.generation.fetch_add(1, Ordering::Release);
        if let Some(mut old) = old {
            let _ = old.close_with_timeout(Duration::from_secs(5)).await;
        }
        Ok(())
    }

    pub async fn call_tool(
        &self,
        source: &SourceId,
        request: CallToolRequestParams,
    ) -> Result<CallToolResponse> {
        let (managed, peer, generation) = self.peer(source).await?;
        let _serialization = if managed.serialize_requests {
            Some(managed.request_lock.lock().await)
        } else {
            None
        };
        let result =
            match tokio::time::timeout(Duration::from_secs(30), peer.call_tool_once(request)).await
            {
                Ok(result) => result.context("GM_MCP_UPSTREAM_CALL"),
                Err(_) => Err(anyhow::anyhow!("GM_MCP_UPSTREAM_CALL_TIMEOUT")),
            };
        if result.is_err() {
            let _ = self.restart_after_failure(source, generation).await;
        }
        if let Ok(response) = &result {
            reject_oversized_call_response(response)?;
        }
        result
    }

    pub async fn read_resource(
        &self,
        source: &SourceId,
        request: ReadResourceRequestParams,
    ) -> Result<ReadResourceResponse> {
        let (managed, peer, generation) = self.peer(source).await?;
        let _serialization = if managed.serialize_requests {
            Some(managed.request_lock.lock().await)
        } else {
            None
        };
        let result =
            match tokio::time::timeout(Duration::from_secs(30), peer.read_resource_once(request))
                .await
            {
                Ok(result) => result.context("GM_MCP_UPSTREAM_READ"),
                Err(_) => Err(anyhow::anyhow!("GM_MCP_UPSTREAM_READ_TIMEOUT")),
            };
        if result.is_err() {
            let _ = self.restart_after_failure(source, generation).await;
        }
        if let Ok(response) = &result {
            reject_oversized_read_response(response)?;
        }
        result
    }

    pub async fn get_prompt(
        &self,
        source: &SourceId,
        request: GetPromptRequestParams,
    ) -> Result<GetPromptResponse> {
        let (managed, peer, generation) = self.peer(source).await?;
        let _serialization = if managed.serialize_requests {
            Some(managed.request_lock.lock().await)
        } else {
            None
        };
        let result = match tokio::time::timeout(
            Duration::from_secs(30),
            peer.get_prompt_once(request),
        )
        .await
        {
            Ok(result) => result.context("GM_MCP_UPSTREAM_PROMPT"),
            Err(_) => Err(anyhow::anyhow!("GM_MCP_UPSTREAM_PROMPT_TIMEOUT")),
        };
        if result.is_err() {
            let _ = self.restart_after_failure(source, generation).await;
        }
        if let Ok(response) = &result {
            reject_oversized_prompt_response(response)?;
        }
        result
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.shutting_down.store(true, Ordering::Release);
        for source in self.sources.values() {
            let _restart = source.restart_lock.lock().await;
            let Some(mut service) = source.service.lock().await.take() else {
                continue;
            };
            if service
                .close_with_timeout(Duration::from_secs(5))
                .await
                .context("GM_MCP_UPSTREAM_CLEANUP")?
                .is_none()
            {
                bail!("GM_MCP_UPSTREAM_CLEANUP_TIMEOUT");
            }
        }
        Ok(())
    }
}

pub async fn connect_configured_sources(
    sources: &[McpSourceConfig],
    mode: DiscoveryMode,
    timeout: Duration,
) -> Result<(Federation, Arc<UpstreamRuntime>)> {
    let mut federation = Federation::default();
    let mut active_sources = BTreeMap::new();
    let mut incomplete_sources = Vec::new();

    for source in sources {
        match connect_source(source, timeout).await {
            Ok(service) => {
                let mut source_federation = Federation::default();
                let discovered = tokio::time::timeout(timeout, async {
                    add_source_capabilities(&mut source_federation, source, service.peer()).await?;
                    snapshot(service.peer()).await
                })
                .await
                .context("GM_MCP_UPSTREAM_DISCOVERY_TIMEOUT")
                .and_then(|result| result);
                let source_snapshot = match discovered {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        let _ = service.cancel().await;
                        if mode == DiscoveryMode::Strict {
                            return Err(error);
                        }
                        incomplete_sources.push(source.id.clone());
                        continue;
                    }
                };
                if source
                    .capability_snapshot_digest
                    .is_some_and(|expected| expected != source_snapshot.capability_manifest_digest)
                {
                    let _ = service.cancel().await;
                    let error = anyhow::anyhow!("GM_MCP_UPSTREAM_IDENTITY_CHANGED");
                    if mode == DiscoveryMode::Strict {
                        return Err(error);
                    }
                    incomplete_sources.push(source.id.clone());
                    continue;
                }
                if let Err(error) = federation.merge(source_federation) {
                    let _ = service.cancel().await;
                    if mode == DiscoveryMode::Strict {
                        return Err(error.into());
                    }
                    incomplete_sources.push(source.id.clone());
                    continue;
                }
                let expected_snapshot =
                    Sha256Digest::of_json(&serde_json::to_value(&source_snapshot)?);
                active_sources.insert(
                    source.id.clone(),
                    Arc::new(ManagedSource {
                        config: source.clone(),
                        peer: RwLock::new(service.peer().clone()),
                        service: Mutex::new(Some(service)),
                        expected_snapshot,
                        generation: AtomicU64::new(1),
                        restarts: AtomicU8::new(0),
                        restart_lock: Mutex::new(()),
                        serialize_requests: source.sharing
                            == gaugemesh_core::config::SharingClass::ShareableWithSerialization,
                        request_lock: Mutex::new(()),
                    }),
                );
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
            sources: active_sources,
            incomplete_sources,
            shutting_down: AtomicBool::new(false),
        }),
    ))
}

async fn connect_source(source: &McpSourceConfig, timeout: Duration) -> Result<ActiveClient> {
    let revision =
        McpRevision::parse(&source.protocol_revision).map_err(|error| anyhow::anyhow!(error))?;
    let start = async {
        match &source.transport {
            McpTransportConfig::StreamableHttp { url } => {
                let transport = safe_http_transport(url).await?;
                serve_client(revision, source.approval.clone(), transport).await
            }
            McpTransportConfig::Stdio { command, args } => {
                let resolved = command
                    .canonicalize()
                    .context("GM_MCP_EXECUTABLE_NOT_ALLOWLISTED")?;
                if !command.is_absolute() || !resolved.is_file() {
                    bail!("GM_MCP_EXECUTABLE_NOT_ALLOWLISTED");
                }
                let process = reviewed_command(&resolved, args)?;
                let transport = TokioChildProcess::new(process).context("GM_MCP_UPSTREAM_SPAWN")?;
                serve_client(revision, source.approval.clone(), transport).await
            }
        }
    };
    tokio::time::timeout(timeout, start)
        .await
        .context("GM_MCP_UPSTREAM_STARTUP_TIMEOUT")?
}

fn reviewed_command(executable: &Path, args: &[String]) -> Result<tokio::process::Command> {
    let mut command = tokio::process::Command::new(executable);
    command
        .args(args)
        .current_dir(executable.parent().context("GM_MCP_EXECUTABLE_DIRECTORY")?)
        .env_clear()
        .kill_on_drop(true);
    for name in [
        "PATH",
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "TMP",
        "TMPDIR",
        "LANG",
        "LC_ALL",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    Ok(command)
}

async fn safe_http_transport(
    url: &url::Url,
) -> Result<StreamableHttpClientTransport<reqwest::Client>> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5));
    let host = url.host_str().context("GM_MCP_UPSTREAM_URL_INVALID")?;
    let local = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if !matches!(url.scheme(), "http" | "https") || (url.scheme() == "http" && !local) {
        bail!("GM_MCP_UPSTREAM_SCHEME_DENIED");
    }
    if !local {
        let origin = gaugemesh_core::security::ResolvedOrigin::resolve(url, false)
            .await
            .context("GM_MCP_UPSTREAM_ORIGIN")?;
        let addresses = origin
            .addresses
            .iter()
            .map(|address| std::net::SocketAddr::new(*address, origin.port))
            .collect::<Vec<_>>();
        builder = builder.resolve_to_addrs(&origin.host, &addresses);
    }
    let client = builder.build().context("GM_MCP_UPSTREAM_HTTP_CLIENT")?;
    let config = StreamableHttpClientTransportConfig::with_uri(url.to_string())
        .max_sse_event_size(1024 * 1024)
        .reinit_on_expired_session(false);
    Ok(StreamableHttpClientTransport::with_client(client, config))
}

async fn serve_client<T, E, A>(
    revision: McpRevision,
    approval: ApprovalConfig,
    transport: T,
) -> Result<ActiveClient>
where
    T: rmcp::transport::IntoTransport<RoleClient, E, A>,
    E: std::error::Error + Send + Sync + 'static,
{
    let service = match revision {
        McpRevision::V2025_11_25 => client_info(revision, approval).serve(transport).await?,
        McpRevision::V2026_07_28 => {
            client_info(revision, approval)
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

fn reject_oversized_response(value: &impl Serialize) -> Result<()> {
    if serde_json::to_vec(value)?.len() > 1024 * 1024 {
        bail!("GM_MCP_UPSTREAM_RESPONSE_TOO_LARGE");
    }
    Ok(())
}

fn reject_oversized_call_response(value: &CallToolResponse) -> Result<()> {
    match value {
        CallToolResponse::Complete(result) => reject_oversized_response(result),
        CallToolResponse::InputRequired(result) => reject_oversized_response(result),
        CallToolResponse::Task(result) => reject_oversized_response(result),
        _ => bail!("GM_MCP_UPSTREAM_RESPONSE_UNSUPPORTED"),
    }
}

fn reject_oversized_read_response(value: &ReadResourceResponse) -> Result<()> {
    match value {
        ReadResourceResponse::Complete(result) => reject_oversized_response(result),
        ReadResourceResponse::InputRequired(result) => reject_oversized_response(result),
        _ => bail!("GM_MCP_UPSTREAM_RESPONSE_UNSUPPORTED"),
    }
}

fn reject_oversized_prompt_response(value: &GetPromptResponse) -> Result<()> {
    match value {
        GetPromptResponse::Complete(result) => reject_oversized_response(result),
        GetPromptResponse::InputRequired(result) => reject_oversized_response(result),
        _ => bail!("GM_MCP_UPSTREAM_RESPONSE_UNSUPPORTED"),
    }
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
            capability_snapshot_digest: None,
            sharing: gaugemesh_core::config::SharingClass::NonShareable,
            reviewed: true,
            approval: gaugemesh_core::config::ApprovalConfig::Deny,
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
        let client = client_info(McpRevision::V2026_07_28, ApprovalConfig::Deny)
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

    #[tokio::test]
    async fn transport_crashes_restart_for_future_requests_only_and_exhaust_the_budget() {
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
        let source = McpSourceConfig {
            id: "restart-source".into(),
            transport: McpTransportConfig::StreamableHttp {
                url: url::Url::parse(&format!("http://{address}/mcp")).unwrap(),
            },
            protocol_revision: "2025-11-25".into(),
            capability_snapshot_digest: None,
            sharing: gaugemesh_core::config::SharingClass::ShareableStateless,
            reviewed: true,
            approval: ApprovalConfig::Deny,
        };
        let (_, upstreams) =
            connect_configured_sources(&[source], DiscoveryMode::Strict, Duration::from_secs(5))
                .await
                .unwrap();
        let source_id = SourceId("restart-source".into());
        let managed = upstreams.sources.get(&source_id.0).unwrap();
        for expected_restarts in 1..=2 {
            managed
                .service
                .lock()
                .await
                .take()
                .unwrap()
                .cancel()
                .await
                .unwrap();
            assert!(
                upstreams
                    .call_tool(&source_id, CallToolRequestParams::new("docs-a__search"))
                    .await
                    .is_err()
            );
            assert_eq!(managed.restarts.load(Ordering::Acquire), expected_restarts);
            assert_eq!(
                managed.generation.load(Ordering::Acquire),
                u64::from(expected_restarts) + 1
            );
        }

        managed
            .service
            .lock()
            .await
            .take()
            .unwrap()
            .cancel()
            .await
            .unwrap();
        assert!(
            upstreams
                .call_tool(&source_id, CallToolRequestParams::new("docs-a__search"))
                .await
                .is_err()
        );
        assert_eq!(managed.restarts.load(Ordering::Acquire), 2);
        upstreams.shutdown().await.unwrap();
        cancellation.cancel();
        server.await.unwrap().unwrap();
    }

    #[test]
    fn deprecated_sampling_is_never_silently_dropped() {
        assert_eq!(
            sampling_unavailable().message,
            "GM_SAMPLING_COMPAT_DISABLED"
        );
        assert!(
            client_info(McpRevision::V2026_07_28, ApprovalConfig::Deny)
                .get_info()
                .capabilities
                .sampling
                .is_none()
        );
    }

    #[test]
    fn shell_like_arguments_remain_literal_process_arguments() {
        let executable = std::env::current_exe().unwrap();
        let arguments = vec!["; echo injected".into(), "$(touch should-not-exist)".into()];
        let command = reviewed_command(&executable, &arguments).unwrap();
        assert_eq!(
            command
                .as_std()
                .get_args()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            arguments
        );
    }
}
