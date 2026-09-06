use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
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
        CallToolRequest, CallToolRequestParams, CallToolResponse, CancelTaskParams,
        ClientCapabilities, ClientInfo, ClientRequest, GetPromptRequestParams, GetPromptResponse,
        GetTaskParams, GetTaskResult, Implementation, PaginatedRequestParams, Prompt,
        ProtocolVersion, ReadResourceRequestParams, ReadResourceResponse, RequestMetaObject,
        Resource, ResourceTemplate, ServerResult, Tool,
    },
    service::{PeerRequestOptions, RequestContext as McpRequestContext, RunningService},
    transport::{
        StreamableHttpClientTransport, TokioChildProcess,
        streamable_http_client::StreamableHttpClientTransportConfig,
    },
};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::{Mutex, RwLock};

#[cfg(test)]
use rmcp::model::UpdateTaskParams;

pub(crate) const TASK_EXECUTION_META_KEY: &str = "dev.gaugemesh/taskExecution";

const MAX_DISCOVERY_PAGES_PER_KIND: usize = 128;
const MAX_DISCOVERY_ITEMS: usize = 4_096;
const MAX_DISCOVERY_AGGREGATE_BYTES: usize = 8 * 1024 * 1024;
const MAX_DISCOVERY_CURSOR_BYTES: usize = 4 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamSnapshot {
    pub protocol_revision: String,
    pub server_name: String,
    pub supports_tasks: bool,
    pub capability_manifest_digest: Sha256Digest,
    pub tools: Vec<String>,
    pub resources: Vec<String>,
    pub resource_templates: Vec<String>,
    pub prompts: Vec<String>,
}

#[derive(Debug)]
struct CapturedDiscovery {
    snapshot: UpstreamSnapshot,
    tools: Vec<Tool>,
    resources: Vec<Resource>,
    resource_templates: Vec<ResourceTemplate>,
    prompts: Vec<Prompt>,
}

#[derive(Default)]
struct DiscoveryBudget {
    items: usize,
    bytes: usize,
}

impl DiscoveryBudget {
    fn charge_page(&mut self, page: &impl Serialize, item_count: usize) -> Result<()> {
        let items = self
            .items
            .checked_add(item_count)
            .context("GM_MCP_UPSTREAM_DISCOVERY_ITEM_LIMIT")?;
        if items > MAX_DISCOVERY_ITEMS {
            bail!("GM_MCP_UPSTREAM_DISCOVERY_ITEM_LIMIT");
        }
        let page_bytes = serde_json::to_vec(page)?.len();
        let bytes = self
            .bytes
            .checked_add(page_bytes)
            .context("GM_MCP_UPSTREAM_DISCOVERY_BYTE_LIMIT")?;
        if bytes > MAX_DISCOVERY_AGGREGATE_BYTES {
            bail!("GM_MCP_UPSTREAM_DISCOVERY_BYTE_LIMIT");
        }
        self.items = items;
        self.bytes = bytes;
        Ok(())
    }
}

#[derive(Default)]
struct DiscoveryPager {
    pages: usize,
    cursor: Option<String>,
    seen_cursors: BTreeSet<String>,
}

impl DiscoveryPager {
    fn request_params(&self) -> Result<Option<PaginatedRequestParams>> {
        if self.pages >= MAX_DISCOVERY_PAGES_PER_KIND {
            bail!("GM_MCP_UPSTREAM_DISCOVERY_PAGE_LIMIT");
        }
        Ok(self
            .cursor
            .clone()
            .map(|cursor| PaginatedRequestParams::default().with_cursor(Some(cursor))))
    }

    /// Returns true when another page is required.
    fn accept_page(&mut self, item_count: usize, next_cursor: Option<String>) -> Result<bool> {
        self.pages = self
            .pages
            .checked_add(1)
            .context("GM_MCP_UPSTREAM_DISCOVERY_PAGE_LIMIT")?;
        let Some(next_cursor) = next_cursor else {
            self.cursor = None;
            return Ok(false);
        };
        if item_count == 0 {
            bail!("GM_MCP_UPSTREAM_DISCOVERY_EMPTY_PAGE");
        }
        if next_cursor.len() > MAX_DISCOVERY_CURSOR_BYTES {
            bail!("GM_MCP_UPSTREAM_DISCOVERY_CURSOR_TOO_LARGE");
        }
        if !self.seen_cursors.insert(next_cursor.clone()) {
            bail!("GM_MCP_UPSTREAM_DISCOVERY_CURSOR_REPEATED");
        }
        self.cursor = Some(next_cursor);
        Ok(true)
    }
}

fn classify_upstream_result<T>(
    result: std::result::Result<T, rmcp::ServiceError>,
    context: &'static str,
) -> (Result<T>, bool) {
    match result {
        Ok(value) => (Ok(value), false),
        Err(error) => {
            // JSON-RPC/MCP application errors and local protocol validation
            // failures do not imply a broken connection. Rotating the peer for
            // those responses would burn restart budget and invalidate durable
            // task session bindings while the provider is still healthy.
            let restart = matches!(
                &error,
                rmcp::ServiceError::TransportSend(_)
                    | rmcp::ServiceError::TransportClosed
                    | rmcp::ServiceError::Timeout { .. }
            );
            (Err(anyhow::Error::new(error).context(context)), restart)
        }
    }
}

fn source_supports_durable_tasks(source: &McpSourceConfig, snapshot: &UpstreamSnapshot) -> bool {
    snapshot.supports_tasks
        && source.capability_snapshot_digest == Some(snapshot.capability_manifest_digest)
}

async fn capture_discovery(peer: &Peer<RoleClient>) -> Result<CapturedDiscovery> {
    let info = peer
        .peer_info()
        .context("GM_MCP_UPSTREAM_MISSING_SERVER_IDENTITY")?;
    let mut budget = DiscoveryBudget::default();
    budget.charge_page(&info, 0)?;
    let tools = if info.capabilities.tools.is_some() {
        list_tools_bounded(peer, &mut budget).await?
    } else {
        Vec::new()
    };
    let resources = if info.capabilities.resources.is_some() {
        list_resources_bounded(peer, &mut budget).await?
    } else {
        Vec::new()
    };
    let resource_templates = if info.capabilities.resources.is_some() {
        list_resource_templates_bounded(peer, &mut budget).await?
    } else {
        Vec::new()
    };
    let prompts = if info.capabilities.prompts.is_some() {
        list_prompts_bounded(peer, &mut budget).await?
    } else {
        Vec::new()
    };
    let server_name = info
        .server_info
        .as_ref()
        .context("GM_MCP_UPSTREAM_MISSING_IMPLEMENTATION")?
        .name
        .clone();
    let supports_tasks = info.protocol_version == ProtocolVersion::V_2026_07_28
        && info.capabilities.supports_tasks();
    let capability_manifest_digest = Sha256Digest::of_json(&serde_json::json!({
        "protocolRevision": info.protocol_version,
        "serverInfo": info.server_info,
        "capabilities": info.capabilities,
        "tools": tools,
        "resources": resources,
        "resourceTemplates": resource_templates,
        "prompts": prompts,
    }));
    let snapshot = UpstreamSnapshot {
        protocol_revision: info.protocol_version.to_string(),
        server_name,
        supports_tasks,
        capability_manifest_digest,
        tools: tools
            .iter()
            .map(|item| item.name.clone().into_owned())
            .collect(),
        resources: resources.iter().map(|item| item.uri.clone()).collect(),
        resource_templates: resource_templates
            .iter()
            .map(|item| item.uri_template.clone())
            .collect(),
        prompts: prompts.iter().map(|item| item.name.clone()).collect(),
    };
    Ok(CapturedDiscovery {
        snapshot,
        tools,
        resources,
        resource_templates,
        prompts,
    })
}

async fn list_tools_bounded(
    peer: &Peer<RoleClient>,
    budget: &mut DiscoveryBudget,
) -> Result<Vec<Tool>> {
    let mut pager = DiscoveryPager::default();
    let mut items = Vec::new();
    loop {
        let page = peer
            .list_tools(pager.request_params()?)
            .await
            .context("GM_MCP_UPSTREAM_TOOLS_LIST")?;
        let item_count = page.tools.len();
        budget.charge_page(&page, item_count)?;
        let next_cursor = page.next_cursor.clone();
        items.extend(page.tools);
        if !pager.accept_page(item_count, next_cursor)? {
            return Ok(items);
        }
    }
}

async fn list_resources_bounded(
    peer: &Peer<RoleClient>,
    budget: &mut DiscoveryBudget,
) -> Result<Vec<Resource>> {
    let mut pager = DiscoveryPager::default();
    let mut items = Vec::new();
    loop {
        let page = peer
            .list_resources(pager.request_params()?)
            .await
            .context("GM_MCP_UPSTREAM_RESOURCES_LIST")?;
        let item_count = page.resources.len();
        budget.charge_page(&page, item_count)?;
        let next_cursor = page.next_cursor.clone();
        items.extend(page.resources);
        if !pager.accept_page(item_count, next_cursor)? {
            return Ok(items);
        }
    }
}

async fn list_resource_templates_bounded(
    peer: &Peer<RoleClient>,
    budget: &mut DiscoveryBudget,
) -> Result<Vec<ResourceTemplate>> {
    let mut pager = DiscoveryPager::default();
    let mut items = Vec::new();
    loop {
        let page = peer
            .list_resource_templates(pager.request_params()?)
            .await
            .context("GM_MCP_UPSTREAM_RESOURCE_TEMPLATES_LIST")?;
        let item_count = page.resource_templates.len();
        budget.charge_page(&page, item_count)?;
        let next_cursor = page.next_cursor.clone();
        items.extend(page.resource_templates);
        if !pager.accept_page(item_count, next_cursor)? {
            return Ok(items);
        }
    }
}

async fn list_prompts_bounded(
    peer: &Peer<RoleClient>,
    budget: &mut DiscoveryBudget,
) -> Result<Vec<Prompt>> {
    let mut pager = DiscoveryPager::default();
    let mut items = Vec::new();
    loop {
        let page = peer
            .list_prompts(pager.request_params()?)
            .await
            .context("GM_MCP_UPSTREAM_PROMPTS_LIST")?;
        let item_count = page.prompts.len();
        budget.charge_page(&page, item_count)?;
        let next_cursor = page.next_cursor.clone();
        items.extend(page.prompts);
        if !pager.accept_page(item_count, next_cursor)? {
            return Ok(items);
        }
    }
}

async fn snapshot(peer: &Peer<RoleClient>) -> Result<UpstreamSnapshot> {
    Ok(capture_discovery(peer).await?.snapshot)
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
    let capabilities = gateway_capabilities(revision == McpRevision::V2026_07_28);
    GatewayClient {
        info: ClientInfo::new(
            capabilities,
            Implementation::new("gaugemesh", env!("CARGO_PKG_VERSION")),
        )
        .with_protocol_version(protocol),
        approval,
        cli_lock: Arc::new(Mutex::new(())),
    }
}

fn gateway_capabilities(include_tasks: bool) -> ClientCapabilities {
    let mut capabilities = ClientCapabilities::builder()
        .enable_elicitation()
        .enable_elicitation_schema_validation();
    if include_tasks {
        capabilities = capabilities.enable_tasks();
    }
    capabilities.build()
}

type ActiveClient = RunningService<RoleClient, GatewayClient>;

pub struct UpstreamRuntime {
    sources: BTreeMap<String, Arc<ManagedSource>>,
    incomplete_sources: Vec<String>,
    shutting_down: AtomicBool,
}

struct ManagedSource {
    config: McpSourceConfig,
    peer: RwLock<ManagedPeer>,
    service: Mutex<Option<ActiveClient>>,
    expected_snapshot: Sha256Digest,
    supports_tasks: bool,
    restarts: AtomicU8,
    restart_lock: Mutex<()>,
    serialize_requests: bool,
    request_lock: Mutex<()>,
}

struct ManagedPeer {
    peer: Peer<RoleClient>,
    generation: u64,
    session_id: String,
}

impl ManagedPeer {
    fn new(peer: Peer<RoleClient>, generation: u64) -> Self {
        Self {
            peer,
            generation,
            session_id: format!("gmus_{}", uuid::Uuid::new_v4()),
        }
    }
}

impl UpstreamRuntime {
    pub fn incomplete_sources(&self) -> &[String] {
        &self.incomplete_sources
    }

    pub fn contains_source(&self, source: &SourceId) -> bool {
        self.sources.contains_key(&source.0)
    }

    pub fn has_task_capable_source(&self) -> bool {
        self.sources.values().any(|source| source.supports_tasks)
    }

    pub fn source_supports_tasks(&self, source: &SourceId) -> bool {
        self.sources
            .get(&source.0)
            .is_some_and(|source| source.supports_tasks)
    }

    pub fn source_snapshot_digest(&self, source: &SourceId) -> Option<Sha256Digest> {
        self.sources
            .get(&source.0)
            .map(|source| source.expected_snapshot)
    }

    pub fn source_configuration_digest(&self, source: &SourceId) -> Option<Sha256Digest> {
        self.sources.get(&source.0).map(|source| {
            Sha256Digest::of_json(
                &serde_json::to_value(&source.config).expect("source configuration serializes"),
            )
        })
    }

    pub async fn source_session_id(&self, source: &SourceId) -> Option<String> {
        self.peer(source)
            .await
            .ok()
            .map(|(_, _, _, session_id)| session_id)
    }

    async fn peer(
        &self,
        source: &SourceId,
    ) -> Result<(Arc<ManagedSource>, Peer<RoleClient>, u64, String)> {
        let source = self
            .sources
            .get(&source.0)
            .context("GM_MCP_UPSTREAM_SOURCE_UNAVAILABLE")?
            .clone();
        // Pair selection with restart serialization so generation/session and
        // the cloned peer always describe the same upstream connection.
        let _restart = source.restart_lock.lock().await;
        let managed_peer = source.peer.read().await;
        Ok((
            source.clone(),
            managed_peer.peer.clone(),
            managed_peer.generation,
            managed_peer.session_id.clone(),
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
        if source.peer.read().await.generation != observed {
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
        *source.peer.write().await = ManagedPeer::new(new_peer, observed.saturating_add(1));
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
        self.call_tool_inner(source, request, false, None).await
    }

    /// Forward a tool call with only the downstream Tasks capability preserved.
    ///
    /// RMCP supplies GaugeMesh's client context automatically. The explicit
    /// per-request metadata override is limited to the capability which affects
    /// the response shape, preventing unrelated downstream capabilities from
    /// crossing the trust boundary.
    #[cfg(test)]
    pub async fn call_tool_with_task_capability(
        &self,
        source: &SourceId,
        request: CallToolRequestParams,
        client_supports_tasks: bool,
    ) -> Result<CallToolResponse> {
        self.call_tool_inner(source, request, client_supports_tasks, None)
            .await
    }

    pub async fn call_tool_with_task_capability_for_session(
        &self,
        source: &SourceId,
        request: CallToolRequestParams,
        client_supports_tasks: bool,
        expected_session_id: &str,
    ) -> Result<CallToolResponse> {
        self.call_tool_inner(
            source,
            request,
            client_supports_tasks,
            Some(expected_session_id),
        )
        .await
    }

    async fn call_tool_inner(
        &self,
        source: &SourceId,
        request: CallToolRequestParams,
        client_supports_tasks: bool,
        expected_session_id: Option<&str>,
    ) -> Result<CallToolResponse> {
        let (managed, peer, generation, session_id) = self.peer(source).await?;
        if expected_session_id.is_some_and(|expected| expected != session_id) {
            bail!("GM_MCP_UPSTREAM_SESSION_CHANGED");
        }
        let task_response_allowed = client_supports_tasks
            && managed.supports_tasks
            && managed.config.protocol_revision == McpRevision::V2026_07_28.as_str();
        let _serialization = if managed.serialize_requests {
            Some(managed.request_lock.lock().await)
        } else {
            None
        };
        let request = async {
            if managed.config.protocol_revision == McpRevision::V2026_07_28.as_str() {
                call_tool_once_with_task_capability(
                    &peer,
                    request,
                    client_supports_tasks && managed.supports_tasks,
                )
                .await
            } else {
                // Preserve the pre-extension request shape for legacy peers.
                peer.call_tool_once(request).await
            }
        };
        let (result, restart) = match tokio::time::timeout(Duration::from_secs(30), request).await {
            Ok(result) => classify_upstream_result(result, "GM_MCP_UPSTREAM_CALL"),
            Err(_) => (Err(anyhow::anyhow!("GM_MCP_UPSTREAM_CALL_TIMEOUT")), true),
        };
        if restart {
            let _ = self.restart_after_failure(source, generation).await;
        }
        if !task_response_allowed {
            if let Ok(CallToolResponse::Task(created)) = &result {
                let task_id = created.task.task_id.clone();
                if managed.supports_tasks {
                    let _ = tokio::time::timeout(
                        Duration::from_secs(5),
                        peer.cancel_task(CancelTaskParams::new(task_id)),
                    )
                    .await;
                }
                bail!("GM_MCP_UNEXPECTED_TASK_RESPONSE");
            }
        }
        if let Ok(response) = &result {
            reject_oversized_call_response(response)?;
        }
        result
    }

    #[cfg(test)]
    pub async fn get_task(
        &self,
        source: &SourceId,
        request: GetTaskParams,
    ) -> Result<GetTaskResult> {
        self.get_task_inner(source, request, None).await
    }

    pub async fn get_task_for_session(
        &self,
        source: &SourceId,
        request: GetTaskParams,
        expected_session_id: &str,
    ) -> Result<GetTaskResult> {
        self.get_task_inner(source, request, Some(expected_session_id))
            .await
    }

    async fn get_task_inner(
        &self,
        source: &SourceId,
        request: GetTaskParams,
        expected_session_id: Option<&str>,
    ) -> Result<GetTaskResult> {
        let (managed, peer, generation, session_id) = self.peer(source).await?;
        if expected_session_id.is_some_and(|expected| expected != session_id) {
            bail!("GM_MCP_UPSTREAM_SESSION_CHANGED");
        }
        require_tasks_capability(&managed)?;
        let _serialization = if managed.serialize_requests {
            Some(managed.request_lock.lock().await)
        } else {
            None
        };
        let (result, restart) =
            match tokio::time::timeout(Duration::from_secs(30), peer.get_task(request)).await {
                Ok(result) => classify_upstream_result(result, "GM_MCP_UPSTREAM_TASK_GET"),
                Err(_) => (
                    Err(anyhow::anyhow!("GM_MCP_UPSTREAM_TASK_GET_TIMEOUT")),
                    true,
                ),
            };
        if restart {
            // The failed request is never replayed; a successful restart can
            // only prepare this source for a later caller request.
            let _ = self.restart_after_failure(source, generation).await;
        }
        if let Ok(response) = &result {
            reject_oversized_task_response(response)?;
        }
        result
    }

    #[cfg(test)]
    pub async fn update_task(&self, source: &SourceId, request: UpdateTaskParams) -> Result<()> {
        reject_oversized_task_update(&request)?;
        let (managed, peer, generation, _) = self.peer(source).await?;
        require_tasks_capability(&managed)?;
        let _serialization = if managed.serialize_requests {
            Some(managed.request_lock.lock().await)
        } else {
            None
        };
        let (result, restart) =
            match tokio::time::timeout(Duration::from_secs(30), peer.update_task(request)).await {
                Ok(result) => classify_upstream_result(result, "GM_MCP_UPSTREAM_TASK_UPDATE"),
                Err(_) => (
                    Err(anyhow::anyhow!("GM_MCP_UPSTREAM_TASK_UPDATE_TIMEOUT")),
                    true,
                ),
            };
        if restart {
            let _ = self.restart_after_failure(source, generation).await;
        }
        result
    }

    #[cfg(test)]
    pub async fn cancel_task(&self, source: &SourceId, request: CancelTaskParams) -> Result<()> {
        self.cancel_task_inner(source, request, None).await
    }

    pub async fn cancel_task_for_session(
        &self,
        source: &SourceId,
        request: CancelTaskParams,
        expected_session_id: &str,
    ) -> Result<()> {
        self.cancel_task_inner(source, request, Some(expected_session_id))
            .await
    }

    async fn cancel_task_inner(
        &self,
        source: &SourceId,
        request: CancelTaskParams,
        expected_session_id: Option<&str>,
    ) -> Result<()> {
        let (managed, peer, generation, session_id) = self.peer(source).await?;
        if expected_session_id.is_some_and(|expected| expected != session_id) {
            bail!("GM_MCP_UPSTREAM_SESSION_CHANGED");
        }
        require_tasks_capability(&managed)?;
        let _serialization = if managed.serialize_requests {
            Some(managed.request_lock.lock().await)
        } else {
            None
        };
        let (result, restart) =
            match tokio::time::timeout(Duration::from_secs(30), peer.cancel_task(request)).await {
                Ok(result) => classify_upstream_result(result, "GM_MCP_UPSTREAM_TASK_CANCEL"),
                Err(_) => (
                    Err(anyhow::anyhow!("GM_MCP_UPSTREAM_TASK_CANCEL_TIMEOUT")),
                    true,
                ),
            };
        if restart {
            let _ = self.restart_after_failure(source, generation).await;
        }
        result
    }

    pub async fn read_resource(
        &self,
        source: &SourceId,
        request: ReadResourceRequestParams,
    ) -> Result<ReadResourceResponse> {
        let (managed, peer, generation, _) = self.peer(source).await?;
        let _serialization = if managed.serialize_requests {
            Some(managed.request_lock.lock().await)
        } else {
            None
        };
        let (result, restart) =
            match tokio::time::timeout(Duration::from_secs(30), peer.read_resource_once(request))
                .await
            {
                Ok(result) => classify_upstream_result(result, "GM_MCP_UPSTREAM_READ"),
                Err(_) => (Err(anyhow::anyhow!("GM_MCP_UPSTREAM_READ_TIMEOUT")), true),
            };
        if restart {
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
        let (managed, peer, generation, _) = self.peer(source).await?;
        let _serialization = if managed.serialize_requests {
            Some(managed.request_lock.lock().await)
        } else {
            None
        };
        let (result, restart) = match tokio::time::timeout(
            Duration::from_secs(30),
            peer.get_prompt_once(request),
        )
        .await
        {
            Ok(result) => classify_upstream_result(result, "GM_MCP_UPSTREAM_PROMPT"),
            Err(_) => (Err(anyhow::anyhow!("GM_MCP_UPSTREAM_PROMPT_TIMEOUT")), true),
        };
        if restart {
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
                    let discovered = capture_discovery(service.peer()).await?;
                    add_source_capabilities(&mut source_federation, source, &discovered)?;
                    Ok::<_, anyhow::Error>(discovered)
                })
                .await
                .context("GM_MCP_UPSTREAM_DISCOVERY_TIMEOUT")
                .and_then(|result| result);
                let source_snapshot = match discovered {
                    Ok(discovered) => discovered.snapshot,
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
                // Preserve compatibility for existing hand-authored sources
                // without a persisted pin, but do not grant the new durable
                // task path until first-start capabilities are owner-pinned.
                let supports_tasks = source_supports_durable_tasks(source, &source_snapshot);
                let expected_snapshot =
                    Sha256Digest::of_json(&serde_json::to_value(&source_snapshot)?);
                active_sources.insert(
                    source.id.clone(),
                    Arc::new(ManagedSource {
                        config: source.clone(),
                        peer: RwLock::new(ManagedPeer::new(service.peer().clone(), 1)),
                        service: Mutex::new(Some(service)),
                        expected_snapshot,
                        supports_tasks,
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

fn add_source_capabilities(
    federation: &mut Federation,
    source: &McpSourceConfig,
    discovered: &CapturedDiscovery,
) -> Result<()> {
    let source_id = SourceId(source.id.clone());
    let revision = CapabilityRevision(discovered.snapshot.protocol_revision.clone());
    let configuration_digest = Sha256Digest::of_json(&serde_json::to_value(source)?);

    for tool in &discovered.tools {
        let schema = Value::Object((*tool.input_schema).clone());
        reject_oversized_metadata(&schema)?;
        let identity = CapabilityId::new(
            source_id.clone(),
            CapabilityKind::Tool,
            &tool.name,
            Sha256Digest::of_json(&serde_json::to_value(tool)?),
            revision.clone(),
            configuration_digest,
        );
        // Preserve the existing descriptive classification for ordinary
        // calls. Durable task admission applies its own conservative
        // non-idempotent-write authority independently of these hints.
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
            native_name: tool.name.clone().into_owned(),
            description: bounded_text(tool.description.as_deref().unwrap_or(""), 4_096),
            input_schema: schema,
            side_effect,
            fixture_result: Value::Null,
        })?;
    }

    for resource in &discovered.resources {
        let identity = CapabilityId::new(
            source_id.clone(),
            CapabilityKind::Resource,
            &resource.uri,
            Sha256Digest::of_json(&serde_json::to_value(resource)?),
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
            native_uri: resource.uri.clone(),
            name: bounded_text(&resource.name, 1_024),
            mime_type: resource
                .mime_type
                .clone()
                .unwrap_or_else(|| "application/octet-stream".into()),
            contents: String::new(),
        })?;
    }

    for template in &discovered.resource_templates {
        let Some(variables) = simple_template_variables(&template.uri_template) else {
            tracing::warn!(source = %source.id, template = %template.uri_template, "unsupported RFC 6570 expression omitted");
            continue;
        };
        let identity = CapabilityId::new(
            source_id.clone(),
            CapabilityKind::ResourceTemplate,
            &template.uri_template,
            Sha256Digest::of_json(&serde_json::to_value(template)?),
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
            native_uri_template: template.uri_template.clone(),
            name: bounded_text(&template.name, 1_024),
            description: bounded_text(template.description.as_deref().unwrap_or(""), 4_096),
            mime_type: template.mime_type.clone(),
            variables,
        })?;
    }

    for prompt in &discovered.prompts {
        let identity = CapabilityId::new(
            source_id.clone(),
            CapabilityKind::Prompt,
            &prompt.name,
            Sha256Digest::of_json(&serde_json::to_value(prompt)?),
            revision.clone(),
            configuration_digest,
        );
        federation.insert_prompt(FederatedPrompt {
            alias: identity.readable_alias(&prompt.name),
            identity,
            native_name: prompt.name.clone(),
            description: bounded_text(prompt.description.as_deref().unwrap_or(""), 4_096),
            arguments: prompt
                .arguments
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|argument| argument.name.clone())
                .collect(),
            template: String::new(),
        })?;
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

fn reject_oversized_task_response(value: &GetTaskResult) -> Result<()> {
    reject_oversized_response(value)
}

#[cfg(test)]
fn reject_oversized_task_update(value: &UpdateTaskParams) -> Result<()> {
    if serde_json::to_vec(value)?.len() > 1024 * 1024 {
        bail!("GM_MCP_UPSTREAM_TASK_UPDATE_TOO_LARGE");
    }
    Ok(())
}

fn require_tasks_capability(source: &ManagedSource) -> Result<()> {
    if !source.supports_tasks {
        bail!("GM_MCP_UPSTREAM_TASKS_UNAVAILABLE");
    }
    Ok(())
}

async fn call_tool_once_with_task_capability(
    peer: &Peer<RoleClient>,
    mut request: CallToolRequestParams,
    client_supports_tasks: bool,
) -> std::result::Result<CallToolResponse, rmcp::ServiceError> {
    let capabilities = gateway_capabilities(client_supports_tasks);
    let mut meta = RequestMetaObject::new();
    if let Some(execution) = request
        .meta
        .take()
        .and_then(|mut request_meta| request_meta.remove(TASK_EXECUTION_META_KEY))
    {
        meta.insert(TASK_EXECUTION_META_KEY.into(), execution);
    }
    meta.set_client_capabilities(capabilities);
    let response = peer
        .send_request_with_option(
            ClientRequest::CallToolRequest(CallToolRequest::new(request)),
            PeerRequestOptions::no_options().with_meta(meta),
        )
        .await?
        .await_response()
        .await?;
    match response {
        ServerResult::CallToolResult(result) => Ok(CallToolResponse::Complete(result)),
        ServerResult::InputRequiredResult(result) => Ok(CallToolResponse::InputRequired(result)),
        ServerResult::CreateTaskResult(result) => Ok(CallToolResponse::Task(result)),
        _ => Err(rmcp::ServiceError::UnexpectedResponse),
    }
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
    use gaugemesh_core::{
        context::{PrincipalId, TenantId},
        digest::canonical_json,
        storage::{LeaseStorage, SqliteStorage, TaskRouteStorage},
        task::{
            PublicTaskId, TaskRouteCaller, TaskRouteIdempotencyKey, TaskRoutePhase,
            TaskRouteRecord, TaskRouteUpdate,
        },
    };
    use rmcp::{
        ServerHandler,
        model::{
            CallToolResult, ContentBlock, CreateTaskResult, DetailedTask, Implementation,
            JsonObject, ListToolsResult, MetaObject, ServerCapabilities, ServerInfo, Task,
            TaskPayload, TaskStatus, Tool, ToolAnnotations,
        },
        service::{RequestContext, RoleServer},
        task_manager::{TaskExit, TaskManager, TaskOptions},
    };
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use std::{
        fs,
        io::Write as _,
        path::{Component, PathBuf},
        sync::atomic::{AtomicU64, AtomicUsize, Ordering as AtomicOrdering},
        time::SystemTime,
    };
    use tempfile::TempDir;

    const NEUTRAL_WORKER_ENV: &str = "GAUGEMESH_NEUTRAL_WORKER_ENTRY";
    const NEUTRAL_WORKER_ROOT_ENV: &str = "GAUGEMESH_NEUTRAL_WORKER_ROOT";
    const NEUTRAL_WORKER_ARGUMENTS_ENV: &str = "GAUGEMESH_NEUTRAL_WORKER_ARGUMENTS";
    const NEUTRAL_WORKER_INVALID_ENV: &str = "GAUGEMESH_NEUTRAL_WORKER_INVALID";
    const NEUTRAL_TOOL_NAME: &str = "normalize_json";
    const NEUTRAL_TOOL_ALIAS: &str = "neutral-worker__normalize_json";
    const NEUTRAL_RESULT_SCHEMA: &str = "gaugemesh.neutral-result/1";
    const NEUTRAL_MANIFEST_SCHEMA: &str = "gaugemesh.neutral-manifest/1";
    const MAX_NEUTRAL_INPUT_BYTES: usize = 4 * 1024;
    const MAX_NEUTRAL_ARTIFACT_BYTES: usize = 64 * 1024;

    #[test]
    fn application_errors_do_not_request_peer_restart() {
        let (_, restart) = classify_upstream_result::<()>(
            Err(rmcp::ServiceError::McpError(McpError::invalid_request(
                "fixture application rejection",
                None,
            ))),
            "fixture",
        );
        assert!(!restart);

        let (_, restart) =
            classify_upstream_result::<()>(Err(rmcp::ServiceError::UnexpectedResponse), "fixture");
        assert!(!restart);
    }

    #[test]
    fn connection_errors_request_peer_restart() {
        let (_, restart) =
            classify_upstream_result::<()>(Err(rmcp::ServiceError::TransportClosed), "fixture");
        assert!(restart);
    }

    #[test]
    fn discovery_pager_rejects_repeated_cursor_and_page_overflow() {
        let mut pager = DiscoveryPager::default();
        assert!(pager.accept_page(1, Some("again".into())).unwrap());
        let repeated = pager.accept_page(1, Some("again".into())).unwrap_err();
        assert!(
            repeated
                .to_string()
                .contains("GM_MCP_UPSTREAM_DISCOVERY_CURSOR_REPEATED")
        );

        let pager = DiscoveryPager {
            pages: MAX_DISCOVERY_PAGES_PER_KIND,
            ..DiscoveryPager::default()
        };
        assert!(
            pager
                .request_params()
                .unwrap_err()
                .to_string()
                .contains("GM_MCP_UPSTREAM_DISCOVERY_PAGE_LIMIT")
        );
    }

    #[test]
    fn discovery_budget_rejects_aggregate_item_and_byte_overflow() {
        let mut item_budget = DiscoveryBudget {
            items: MAX_DISCOVERY_ITEMS,
            bytes: 0,
        };
        assert!(
            item_budget
                .charge_page(&serde_json::json!({}), 1)
                .unwrap_err()
                .to_string()
                .contains("GM_MCP_UPSTREAM_DISCOVERY_ITEM_LIMIT")
        );

        let mut byte_budget = DiscoveryBudget {
            items: 0,
            bytes: MAX_DISCOVERY_AGGREGATE_BYTES,
        };
        assert!(
            byte_budget
                .charge_page(&serde_json::json!(null), 0)
                .unwrap_err()
                .to_string()
                .contains("GM_MCP_UPSTREAM_DISCOVERY_BYTE_LIMIT")
        );
    }

    fn neutral_acceptance_policy_sha256() -> Sha256Digest {
        Sha256Digest::of_json(&json!({
            "schemaVersion": "gaugemesh.neutral-acceptance/1",
            "requireManifest": true,
            "requireExactIdentity": true
        }))
    }

    fn neutral_artifact_scope_sha256() -> Sha256Digest {
        Sha256Digest::of_json(&json!({
            "schemaVersion": "gaugemesh.artifact-scope/1",
            "rootClass": "temporary-permitted-output",
            "artifacts": ["result.json", "manifest.json"]
        }))
    }

    fn neutral_tool() -> Tool {
        let schema = json!({
            "type": "object",
            "properties": {
                "input": {"type": "object"},
                "outputDirectory": {"type": "string"},
                "identities": {"type": "object"}
            },
            "required": ["input", "outputDirectory", "identities"],
            "additionalProperties": false
        });
        Tool::new(
            NEUTRAL_TOOL_NAME,
            "Test-only bounded JSON normalization worker",
            Arc::new(schema.as_object().unwrap().clone()),
        )
        .with_annotations(ToolAnnotations::from_raw(
            None,
            Some(false),
            Some(false),
            Some(true),
            Some(false),
        ))
    }

    fn neutral_provider_interface_version() -> String {
        Sha256Digest::of_json(&serde_json::to_value(neutral_tool()).unwrap()).to_string()
    }

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct NeutralIdentities {
        logical_task_id: String,
        attempt_id: String,
        correlation_id: String,
        acceptance_policy_sha256: Sha256Digest,
        artifact_scope_sha256: Sha256Digest,
        provider_interface_version: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct NeutralWorkerArguments {
        input: Value,
        output_directory: String,
        identities: NeutralIdentities,
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct NeutralResult {
        schema_version: String,
        input_sha256: Sha256Digest,
        identities: NeutralIdentities,
        normalized: Value,
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct NeutralManifest {
        schema_version: String,
        input_sha256: Sha256Digest,
        identities: NeutralIdentities,
        result_sha256: Sha256Digest,
        artifacts: Vec<String>,
    }

    #[derive(Clone)]
    struct NeutralTaskFixture {
        tasks: TaskManager,
        permitted_root: Arc<PathBuf>,
        submissions: Arc<AtomicUsize>,
        acknowledgement_delay_ms: Arc<AtomicU64>,
        complete_response: Arc<AtomicBool>,
        task_metadata: Arc<Mutex<BTreeMap<String, MetaObject>>>,
    }

    impl NeutralTaskFixture {
        fn new(permitted_root: PathBuf) -> Self {
            Self {
                tasks: TaskManager::new(),
                permitted_root: Arc::new(permitted_root),
                submissions: Arc::new(AtomicUsize::new(0)),
                acknowledgement_delay_ms: Arc::new(AtomicU64::new(0)),
                complete_response: Arc::new(AtomicBool::new(false)),
                task_metadata: Arc::new(Mutex::new(BTreeMap::new())),
            }
        }
    }

    impl ServerHandler for NeutralTaskFixture {
        async fn list_tools(
            &self,
            _request: Option<rmcp::model::PaginatedRequestParams>,
            _context: RequestContext<RoleServer>,
        ) -> std::result::Result<ListToolsResult, McpError> {
            Ok(ListToolsResult::with_all_items(vec![neutral_tool()]))
        }

        async fn call_tool(
            &self,
            request: CallToolRequestParams,
            context: RequestContext<RoleServer>,
        ) -> std::result::Result<CallToolResponse, McpError> {
            if request.name != NEUTRAL_TOOL_NAME {
                return Err(McpError::invalid_params("UNKNOWN_NEUTRAL_TOOL", None));
            }
            if !context
                .client_capabilities()
                .is_some_and(|capabilities| capabilities.supports_tasks())
            {
                return Err(McpError::invalid_request(
                    "NEUTRAL_FIXTURE_REQUIRES_TASKS",
                    None,
                ));
            }
            let arguments = Value::Object(request.arguments.unwrap_or_default());
            if serde_json::to_vec(&arguments)
                .map_err(|_| McpError::invalid_params("NEUTRAL_ARGUMENTS_INVALID", None))?
                .len()
                > MAX_NEUTRAL_INPUT_BYTES
            {
                return Err(McpError::invalid_params(
                    "NEUTRAL_ARGUMENTS_TOO_LARGE",
                    None,
                ));
            }
            let worker_arguments =
                serde_json::from_value::<NeutralWorkerArguments>(arguments.clone())
                    .map_err(|_| McpError::invalid_params("NEUTRAL_ARGUMENTS_INVALID", None))?;
            let execution_metadata = context
                .meta
                .get(TASK_EXECUTION_META_KEY)
                .cloned()
                .ok_or_else(|| {
                    McpError::invalid_params("NEUTRAL_EXECUTION_METADATA_REQUIRED", None)
                })?;
            if execution_metadata
                .get("schemaVersion")
                .and_then(Value::as_str)
                != Some("gaugemesh.task-execution/1")
            {
                return Err(McpError::invalid_params(
                    "NEUTRAL_EXECUTION_METADATA_INVALID",
                    None,
                ));
            }
            let submission_task = execution_metadata
                .get("submission")
                .and_then(|value| value.get("task"));
            for field in ["publicTaskId", "requestSha256", "upstreamSessionId"] {
                if execution_metadata
                    .get(field)
                    .and_then(Value::as_str)
                    .is_none()
                {
                    return Err(McpError::invalid_params(
                        "NEUTRAL_EXECUTION_METADATA_INVALID",
                        None,
                    ));
                }
            }
            let Some(submission_task) = submission_task else {
                return Err(McpError::invalid_params(
                    "NEUTRAL_EXECUTION_METADATA_INVALID",
                    None,
                ));
            };
            let expected_identity = [
                (
                    "logicalTaskId",
                    json!(worker_arguments.identities.logical_task_id),
                ),
                ("attemptId", json!(worker_arguments.identities.attempt_id)),
                (
                    "correlationId",
                    json!(worker_arguments.identities.correlation_id),
                ),
                (
                    "acceptancePolicySha256",
                    json!(worker_arguments.identities.acceptance_policy_sha256),
                ),
                (
                    "artifactScopeSha256",
                    json!(worker_arguments.identities.artifact_scope_sha256),
                ),
                (
                    "providerInterfaceVersion",
                    json!(worker_arguments.identities.provider_interface_version),
                ),
            ];
            let expected_input_sha256 = json!(Sha256Digest::of_json(&arguments));
            if worker_arguments.identities.provider_interface_version
                != neutral_provider_interface_version()
                || worker_arguments.identities.acceptance_policy_sha256
                    != neutral_acceptance_policy_sha256()
                || worker_arguments.identities.artifact_scope_sha256
                    != neutral_artifact_scope_sha256()
                || submission_task.get("inputSha256") != Some(&expected_input_sha256)
                || expected_identity
                    .iter()
                    .any(|(field, expected)| submission_task.get(*field) != Some(expected))
            {
                return Err(McpError::invalid_params(
                    "NEUTRAL_EXECUTION_IDENTITY_MISMATCH",
                    None,
                ));
            }
            self.submissions.fetch_add(1, AtomicOrdering::SeqCst);
            let mut metadata = JsonObject::new();
            metadata.insert(TASK_EXECUTION_META_KEY.into(), execution_metadata);
            let metadata = MetaObject(metadata);
            let terminal_metadata = metadata.clone();
            let permitted_root = self.permitted_root.as_ref().clone();
            if self.complete_response.load(AtomicOrdering::Acquire) {
                let worker = run_neutral_worker_process(&permitted_root, &arguments, false)
                    .await
                    .map_err(|error| McpError::internal_error(error.to_string(), None))?;
                if !worker.success() {
                    return Err(McpError::internal_error(
                        "NEUTRAL_WORKER_PROCESS_FAILED",
                        None,
                    ));
                }
                let acknowledgement_delay_ms =
                    self.acknowledgement_delay_ms.load(AtomicOrdering::Acquire);
                if acknowledgement_delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(acknowledgement_delay_ms)).await;
                }
                return Ok(CallToolResponse::Complete(
                    CallToolResult::structured(json!({
                        "worker": "test-process",
                        "status": "artifacts-written"
                    }))
                    .with_meta(Some(metadata)),
                ));
            }
            let task = self.tasks.spawn(
                TaskOptions::new()
                    .with_ttl_ms(30_000)
                    .with_poll_interval_ms(10)
                    .with_status_message("test-only neutral worker process"),
                move |context| {
                    Box::pin(async move {
                        let worker = run_neutral_worker_process(&permitted_root, &arguments, false);
                        tokio::select! {
                            _ = context.cancelled() => Err(TaskExit::Cancelled),
                            outcome = worker => {
                                let output = outcome.map_err(|error| {
                                    TaskExit::Error(McpError::internal_error(error.to_string(), None))
                                })?;
                                if !output.success() {
                                    return Err(TaskExit::Error(McpError::internal_error(
                                        "NEUTRAL_WORKER_PROCESS_FAILED",
                                        None,
                                    )));
                                }
                                Ok(CallToolResult::structured(json!({
                                    "worker": "test-process",
                                    "status": "artifacts-written"
                                })).with_meta(Some(terminal_metadata)))
                            }
                        }
                    })
                },
            );
            self.task_metadata
                .lock()
                .await
                .insert(task.task_id.clone(), metadata.clone());
            let acknowledgement_delay_ms =
                self.acknowledgement_delay_ms.load(AtomicOrdering::Acquire);
            if acknowledgement_delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(acknowledgement_delay_ms)).await;
            }
            Ok(CallToolResponse::Task(
                CreateTaskResult::new(task).with_meta(metadata),
            ))
        }

        async fn get_task(
            &self,
            request: GetTaskParams,
            _context: RequestContext<RoleServer>,
        ) -> std::result::Result<GetTaskResult, McpError> {
            let mut result = GetTaskResult::new(self.tasks.get_task(&request.task_id)?);
            result.meta = self
                .task_metadata
                .lock()
                .await
                .get(&request.task_id)
                .cloned();
            Ok(result)
        }

        async fn update_task(
            &self,
            request: UpdateTaskParams,
            _context: RequestContext<RoleServer>,
        ) -> std::result::Result<(), McpError> {
            self.tasks
                .update_task(&request.task_id, request.input_responses)
        }

        async fn cancel_task(
            &self,
            request: CancelTaskParams,
            _context: RequestContext<RoleServer>,
        ) -> std::result::Result<(), McpError> {
            self.tasks.cancel_task(&request.task_id)
        }

        fn get_info(&self) -> ServerInfo {
            ServerInfo::new(
                ServerCapabilities::builder()
                    .enable_tools()
                    .enable_tasks()
                    .build(),
            )
            .with_server_info(Implementation::new("neutral-worker-fixture", "1"))
        }
    }

    fn neutral_task_client_info() -> rmcp::model::ClientInfo {
        rmcp::model::ClientInfo::new(
            ClientCapabilities::builder().enable_tasks().build(),
            Implementation::new("neutral-qualification-caller", "1"),
        )
        .with_protocol_version(ProtocolVersion::V_2026_07_28)
    }

    fn checked_relative_components(value: &str) -> anyhow::Result<Vec<std::ffi::OsString>> {
        let path = Path::new(value);
        if path.as_os_str().is_empty() || path.is_absolute() {
            anyhow::bail!("NEUTRAL_OUTPUT_PATH_DENIED");
        }
        let mut components = Vec::new();
        for component in path.components() {
            match component {
                Component::Normal(value) => components.push(value.to_os_string()),
                _ => anyhow::bail!("NEUTRAL_OUTPUT_PATH_DENIED"),
            }
        }
        if components.is_empty() || components.len() > 8 {
            anyhow::bail!("NEUTRAL_OUTPUT_PATH_DENIED");
        }
        Ok(components)
    }

    fn prepare_output_directory(root: &Path, relative: &str) -> anyhow::Result<PathBuf> {
        let root = root.canonicalize().context("NEUTRAL_OUTPUT_ROOT_INVALID")?;
        let mut current = root.clone();
        for component in checked_relative_components(relative)? {
            current.push(component);
            match fs::symlink_metadata(&current) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() || !metadata.is_dir() {
                        anyhow::bail!("NEUTRAL_OUTPUT_SYMLINK_OR_TYPE_DENIED");
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    fs::create_dir(&current).context("NEUTRAL_OUTPUT_CREATE_FAILED")?;
                }
                Err(error) => return Err(error).context("NEUTRAL_OUTPUT_INSPECTION_FAILED"),
            }
        }
        let canonical = current
            .canonicalize()
            .context("NEUTRAL_OUTPUT_CANONICALIZE_FAILED")?;
        if !canonical.starts_with(&root) {
            anyhow::bail!("NEUTRAL_OUTPUT_CONTAINMENT_FAILED");
        }
        Ok(canonical)
    }

    fn checked_existing_artifact(
        root: &Path,
        output_directory: &str,
        file_name: &str,
    ) -> anyhow::Result<PathBuf> {
        let root = root.canonicalize().context("NEUTRAL_VERIFY_ROOT_INVALID")?;
        let mut current = root.clone();
        let mut components = checked_relative_components(output_directory)?;
        components.push(file_name.into());
        for component in components {
            current.push(component);
            let metadata =
                fs::symlink_metadata(&current).context("NEUTRAL_VERIFY_ARTIFACT_MISSING")?;
            if metadata.file_type().is_symlink() {
                anyhow::bail!("NEUTRAL_VERIFY_SYMLINK_DENIED");
            }
        }
        let canonical = current
            .canonicalize()
            .context("NEUTRAL_VERIFY_CANONICALIZE_FAILED")?;
        if !canonical.starts_with(&root) || !canonical.is_file() {
            anyhow::bail!("NEUTRAL_VERIFY_CONTAINMENT_FAILED");
        }
        Ok(canonical)
    }

    fn write_new(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .context("NEUTRAL_ARTIFACT_ALREADY_EXISTS")?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }

    fn write_neutral_worker_artifacts(
        root: &Path,
        arguments: &Value,
        invalid_output: bool,
    ) -> anyhow::Result<()> {
        let encoded_arguments = serde_json::to_vec(arguments)?;
        if encoded_arguments.len() > MAX_NEUTRAL_INPUT_BYTES {
            anyhow::bail!("NEUTRAL_ARGUMENTS_TOO_LARGE");
        }
        let arguments: NeutralWorkerArguments = serde_json::from_value(arguments.clone())?;
        if !arguments.input.is_object() {
            anyhow::bail!("NEUTRAL_INPUT_MUST_BE_OBJECT");
        }
        let output = prepare_output_directory(root, &arguments.output_directory)?;
        let effects = prepare_output_directory(root, "worker-effects")?;
        write_new(
            &effects.join(format!("effect-{}", std::process::id())),
            b"neutral-worker-effect-v1\n",
        )?;

        let input_sha256 = Sha256Digest::of_json(&serde_json::to_value(&arguments)?);
        let mut identities = arguments.identities.clone();
        if invalid_output {
            identities.provider_interface_version = "invalid-provider-interface".into();
        }
        let result = NeutralResult {
            schema_version: NEUTRAL_RESULT_SCHEMA.into(),
            input_sha256,
            identities,
            normalized: canonical_json(&arguments.input),
        };
        let result_value = canonical_json(&serde_json::to_value(&result)?);
        let result_bytes = serde_json::to_vec(&result_value)?;
        let manifest = NeutralManifest {
            schema_version: NEUTRAL_MANIFEST_SCHEMA.into(),
            input_sha256,
            identities: arguments.identities,
            result_sha256: Sha256Digest::of_bytes(&result_bytes),
            artifacts: vec!["result.json".into()],
        };
        let manifest_bytes = serde_json::to_vec(&canonical_json(&serde_json::to_value(manifest)?))?;
        if result_bytes.len().saturating_add(manifest_bytes.len()) > MAX_NEUTRAL_ARTIFACT_BYTES {
            anyhow::bail!("NEUTRAL_ARTIFACT_LIMIT_EXCEEDED");
        }
        write_new(&output.join("result.json"), &result_bytes)?;
        write_new(&output.join("manifest.json"), &manifest_bytes)?;
        Ok(())
    }

    async fn run_neutral_worker_process(
        root: &Path,
        arguments: &Value,
        invalid_output: bool,
    ) -> anyhow::Result<std::process::ExitStatus> {
        let executable = std::env::current_exe().context("NEUTRAL_WORKER_EXE_UNAVAILABLE")?;
        let mut command = tokio::process::Command::new(executable);
        command
            .arg("--ignored")
            .arg("--exact")
            .arg("outbound::tests::neutral_worker_process_entry")
            .arg("--nocapture")
            .env(NEUTRAL_WORKER_ENV, "1")
            .env(NEUTRAL_WORKER_ROOT_ENV, root.as_os_str())
            .env(
                NEUTRAL_WORKER_ARGUMENTS_ENV,
                serde_json::to_string(arguments)?,
            )
            .env(
                NEUTRAL_WORKER_INVALID_ENV,
                if invalid_output { "1" } else { "0" },
            )
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        tokio::time::timeout(Duration::from_secs(5), command.status())
            .await
            .context("NEUTRAL_WORKER_TIMEOUT")?
            .context("NEUTRAL_WORKER_SPAWN_FAILED")
    }

    fn verify_neutral_artifacts(root: &Path, arguments: &Value) -> anyhow::Result<()> {
        let expected: NeutralWorkerArguments = serde_json::from_value(arguments.clone())?;
        let manifest_path =
            checked_existing_artifact(root, &expected.output_directory, "manifest.json")?;
        let result_path =
            checked_existing_artifact(root, &expected.output_directory, "result.json")?;
        let manifest_bytes = fs::read(manifest_path)?;
        let result_bytes = fs::read(result_path)?;
        if manifest_bytes.len().saturating_add(result_bytes.len()) > MAX_NEUTRAL_ARTIFACT_BYTES {
            anyhow::bail!("NEUTRAL_VERIFY_ARTIFACT_LIMIT_EXCEEDED");
        }
        let manifest: NeutralManifest = serde_json::from_slice(&manifest_bytes)?;
        let result: NeutralResult = serde_json::from_slice(&result_bytes)?;
        let expected_input_sha256 = Sha256Digest::of_json(arguments);
        if manifest.schema_version != NEUTRAL_MANIFEST_SCHEMA
            || result.schema_version != NEUTRAL_RESULT_SCHEMA
            || manifest.input_sha256 != expected_input_sha256
            || result.input_sha256 != expected_input_sha256
            || expected.identities.acceptance_policy_sha256 != neutral_acceptance_policy_sha256()
            || expected.identities.artifact_scope_sha256 != neutral_artifact_scope_sha256()
            || expected.identities.provider_interface_version
                != neutral_provider_interface_version()
            || manifest.identities != expected.identities
            || result.identities != expected.identities
            || manifest.result_sha256 != Sha256Digest::of_bytes(&result_bytes)
            || manifest.artifacts != vec!["result.json".to_owned()]
            || result.normalized != canonical_json(&expected.input)
        {
            anyhow::bail!("NEUTRAL_VERIFY_IDENTITY_OR_CONTENT_MISMATCH");
        }
        Ok(())
    }

    fn neutral_arguments(
        output_directory: &str,
        identities: &NeutralIdentities,
        input: Value,
    ) -> Value {
        serde_json::to_value(NeutralWorkerArguments {
            input,
            output_directory: output_directory.into(),
            identities: identities.clone(),
        })
        .unwrap()
    }

    fn task_submission(
        arguments: &Value,
        identities: &NeutralIdentities,
        idempotency_key: &str,
        deadline_unix_ms: u64,
    ) -> Value {
        json!({
            "schemaVersion": "gaugemesh.task-submission/1",
            "logicalTaskId": identities.logical_task_id,
            "attemptId": identities.attempt_id,
            "correlationId": identities.correlation_id,
            "idempotencyKey": idempotency_key,
            "inputSha256": Sha256Digest::of_json(arguments),
            "acceptancePolicySha256": identities.acceptance_policy_sha256,
            "artifactScopeSha256": identities.artifact_scope_sha256,
            "providerInterfaceVersion": identities.provider_interface_version,
            "deadlineUnixMs": deadline_unix_ms,
            "retentionMs": 30_000,
            "limits": {
                "maxRuntimeMs": 5_000,
                "maxOutputBytes": 32_768,
                "maxArtifactBytes": 65_536,
                "maxAttempts": 1
            },
            "permittedEffect": "non_idempotent_write",
            "cleanupRequired": true
        })
    }

    fn submit_arguments(lease_id: &str, tool_arguments: &Value, task: Value) -> JsonObject {
        json!({
            "leaseId": lease_id,
            "alias": NEUTRAL_TOOL_ALIAS,
            "arguments": tool_arguments,
            "task": task
        })
        .as_object()
        .unwrap()
        .clone()
    }

    fn task_id(response: CallToolResponse) -> String {
        match response {
            CallToolResponse::Task(created) => created.task.task_id,
            other => panic!("expected task response, got {other:?}"),
        }
    }

    fn structured_error_code(response: CallToolResponse) -> Option<String> {
        match response {
            CallToolResponse::Complete(result) => result
                .structured_content
                .and_then(|value| value.get("code").and_then(Value::as_str).map(str::to_owned)),
            _ => None,
        }
    }

    #[test]
    #[ignore = "helper process entry; invoked by the neutral qualification test"]
    fn neutral_worker_process_entry() {
        if std::env::var_os(NEUTRAL_WORKER_ENV).as_deref() != Some(std::ffi::OsStr::new("1")) {
            return;
        }
        let root = PathBuf::from(
            std::env::var_os(NEUTRAL_WORKER_ROOT_ENV)
                .expect("worker root must be supplied by the harness"),
        );
        let arguments: Value = serde_json::from_str(
            &std::env::var(NEUTRAL_WORKER_ARGUMENTS_ENV)
                .expect("worker arguments must be supplied by the harness"),
        )
        .expect("worker arguments must be JSON");
        let invalid_output = std::env::var(NEUTRAL_WORKER_INVALID_ENV).as_deref() == Ok("1");
        write_neutral_worker_artifacts(&root, &arguments, invalid_output)
            .expect("bounded neutral worker must succeed");
    }

    #[test]
    fn neutral_verifier_rejects_missing_truncated_and_swapped_artifacts() {
        let workspace = TempDir::new().unwrap();
        let root = workspace.path().join("permitted");
        fs::create_dir(&root).unwrap();
        let identities = NeutralIdentities {
            logical_task_id: "artifact-negative".into(),
            attempt_id: "attempt-a".into(),
            correlation_id: "artifact-negative".into(),
            acceptance_policy_sha256: neutral_acceptance_policy_sha256(),
            artifact_scope_sha256: neutral_artifact_scope_sha256(),
            provider_interface_version: neutral_provider_interface_version(),
        };

        let missing = neutral_arguments("missing", &identities, json!({"case": "missing"}));
        write_neutral_worker_artifacts(&root, &missing, false).unwrap();
        fs::remove_file(root.join("missing/manifest.json")).unwrap();
        assert!(
            verify_neutral_artifacts(&root, &missing)
                .unwrap_err()
                .to_string()
                .contains("NEUTRAL_VERIFY_ARTIFACT_MISSING")
        );
        fs::remove_dir_all(root.join("worker-effects")).unwrap();

        let truncated = neutral_arguments(
            "truncated",
            &NeutralIdentities {
                attempt_id: "attempt-truncated".into(),
                ..identities.clone()
            },
            json!({"case": "truncated"}),
        );
        write_neutral_worker_artifacts(&root, &truncated, false).unwrap();
        fs::write(root.join("truncated/result.json"), b"{").unwrap();
        assert!(verify_neutral_artifacts(&root, &truncated).is_err());
        fs::remove_dir_all(root.join("worker-effects")).unwrap();

        let first = neutral_arguments(
            "swap-a",
            &NeutralIdentities {
                attempt_id: "attempt-swap-a".into(),
                ..identities.clone()
            },
            json!({"case": "swap-a"}),
        );
        let second = neutral_arguments(
            "swap-b",
            &NeutralIdentities {
                attempt_id: "attempt-swap-b".into(),
                ..identities
            },
            json!({"case": "swap-b"}),
        );
        write_neutral_worker_artifacts(&root, &first, false).unwrap();
        fs::remove_dir_all(root.join("worker-effects")).unwrap();
        write_neutral_worker_artifacts(&root, &second, false).unwrap();
        fs::copy(
            root.join("swap-a/result.json"),
            root.join("swap-b/result.json"),
        )
        .unwrap();
        assert!(
            verify_neutral_artifacts(&root, &second)
                .unwrap_err()
                .to_string()
                .contains("NEUTRAL_VERIFY_IDENTITY_OR_CONTENT_MISMATCH")
        );
    }

    #[derive(Clone, Default)]
    struct TaskFixture {
        call_capabilities: Arc<Mutex<Vec<(bool, bool)>>>,
        updates: Arc<Mutex<Vec<String>>>,
        cancellations: Arc<Mutex<Vec<String>>>,
        force_task_response: Arc<AtomicBool>,
    }

    impl ServerHandler for TaskFixture {
        async fn call_tool(
            &self,
            _request: CallToolRequestParams,
            context: RequestContext<RoleServer>,
        ) -> std::result::Result<CallToolResponse, McpError> {
            let capabilities = context.client_capabilities().unwrap_or_default();
            let client_supports_tasks = capabilities.supports_tasks();
            self.call_capabilities
                .lock()
                .await
                .push((client_supports_tasks, capabilities.elicitation.is_some()));
            if client_supports_tasks || self.force_task_response.load(Ordering::Acquire) {
                Ok(CallToolResponse::Task(CreateTaskResult::new(Task::new(
                    "upstream-task",
                    TaskStatus::Working,
                    "2026-09-05T00:00:00Z",
                    "2026-09-05T00:00:00Z",
                ))))
            } else {
                Ok(CallToolResponse::Complete(CallToolResult::success(vec![
                    ContentBlock::text("complete"),
                ])))
            }
        }

        async fn get_task(
            &self,
            request: GetTaskParams,
            _context: RequestContext<RoleServer>,
        ) -> std::result::Result<GetTaskResult, McpError> {
            Ok(GetTaskResult::new(DetailedTask::new(
                Task::new(
                    request.task_id,
                    TaskStatus::Working,
                    "2026-09-05T00:00:00Z",
                    "2026-09-05T00:00:01Z",
                ),
                TaskPayload::Working,
            )))
        }

        async fn update_task(
            &self,
            request: UpdateTaskParams,
            _context: RequestContext<RoleServer>,
        ) -> std::result::Result<(), McpError> {
            self.updates.lock().await.push(request.task_id);
            Ok(())
        }

        async fn cancel_task(
            &self,
            request: CancelTaskParams,
            _context: RequestContext<RoleServer>,
        ) -> std::result::Result<(), McpError> {
            self.cancellations.lock().await.push(request.task_id);
            Ok(())
        }

        fn get_info(&self) -> ServerInfo {
            ServerInfo::new(
                ServerCapabilities::builder()
                    .enable_tools()
                    .enable_tasks()
                    .build(),
            )
        }
    }

    #[test]
    fn gateway_advertises_tasks_only_for_the_extension_revision() {
        let legacy = client_info(McpRevision::V2025_11_25, ApprovalConfig::Deny).get_info();
        let current = client_info(McpRevision::V2026_07_28, ApprovalConfig::Deny).get_info();

        assert!(!legacy.capabilities.supports_tasks());
        assert!(current.capabilities.supports_tasks());
        assert!(legacy.capabilities.elicitation.is_some());
        assert!(current.capabilities.elicitation.is_some());
    }

    #[tokio::test]
    async fn task_capability_and_lifecycle_are_forwarded_without_broker_state() {
        let fixture = TaskFixture::default();
        let (server_transport, client_transport) = tokio::io::duplex(4096);
        let fixture_server = fixture.clone();
        let server = tokio::spawn(async move {
            let service = fixture_server.serve(server_transport).await?;
            service.waiting().await?;
            anyhow::Ok(())
        });
        let service = serve_client(
            McpRevision::V2026_07_28,
            ApprovalConfig::Deny,
            client_transport,
        )
        .await
        .unwrap();
        let source_snapshot = snapshot(service.peer()).await.unwrap();
        assert!(source_snapshot.supports_tasks);
        let source_id = SourceId("task-fixture".into());
        let config = McpSourceConfig {
            id: source_id.0.clone(),
            transport: McpTransportConfig::StreamableHttp {
                url: url::Url::parse("http://127.0.0.1/unused").unwrap(),
            },
            protocol_revision: McpRevision::V2026_07_28.as_str().into(),
            capability_snapshot_digest: None,
            sharing: gaugemesh_core::config::SharingClass::NonShareable,
            reviewed: true,
            approval: ApprovalConfig::Deny,
        };
        let mut sources = BTreeMap::new();
        sources.insert(
            source_id.0.clone(),
            Arc::new(ManagedSource {
                config,
                peer: RwLock::new(ManagedPeer::new(service.peer().clone(), 1)),
                service: Mutex::new(Some(service)),
                expected_snapshot: Sha256Digest::of_json(
                    &serde_json::to_value(&source_snapshot).unwrap(),
                ),
                supports_tasks: source_snapshot.supports_tasks,
                restarts: AtomicU8::new(0),
                restart_lock: Mutex::new(()),
                serialize_requests: false,
                request_lock: Mutex::new(()),
            }),
        );
        let runtime = UpstreamRuntime {
            sources,
            incomplete_sources: Vec::new(),
            shutting_down: AtomicBool::new(false),
        };

        assert!(runtime.has_task_capable_source());
        assert!(runtime.source_supports_tasks(&source_id));
        assert!(matches!(
            runtime
                .call_tool(&source_id, CallToolRequestParams::new("operation"))
                .await
                .unwrap(),
            CallToolResponse::Complete(_)
        ));
        fixture.force_task_response.store(true, Ordering::Release);
        let error = runtime
            .call_tool(&source_id, CallToolRequestParams::new("operation"))
            .await
            .unwrap_err();
        let error_chain = format!("{error:#}");
        let response_reached_gaugemesh = error_chain.contains("GM_MCP_UNEXPECTED_TASK_RESPONSE");
        assert!(
            error_chain.contains("GM_MCP_UNEXPECTED_TASK_RESPONSE")
                || error_chain.contains("GM_MCP_UPSTREAM_CALL"),
            "unexpected refusal: {error_chain}"
        );
        assert!(!error_chain.contains("upstream-task"));
        fixture.force_task_response.store(false, Ordering::Release);
        let task_id = match runtime
            .call_tool_with_task_capability(
                &source_id,
                CallToolRequestParams::new("operation"),
                true,
            )
            .await
            .unwrap()
        {
            CallToolResponse::Task(result) => result.task.task_id,
            other => panic!("expected upstream task, got {other:?}"),
        };
        assert_eq!(task_id, "upstream-task");
        let task = runtime
            .get_task(&source_id, GetTaskParams::new(task_id.clone()))
            .await
            .unwrap();
        assert_eq!(task.task.task.task_id, task_id);

        let mut input_responses = BTreeMap::new();
        input_responses.insert("answer".into(), serde_json::json!(42));
        runtime
            .update_task(
                &source_id,
                UpdateTaskParams::new(task_id.clone(), input_responses),
            )
            .await
            .unwrap();
        runtime
            .cancel_task(&source_id, CancelTaskParams::new(task_id.clone()))
            .await
            .unwrap();

        assert_eq!(
            fixture.call_capabilities.lock().await.as_slice(),
            &[(false, true), (false, true), (true, true)]
        );
        assert_eq!(fixture.updates.lock().await.as_slice(), &[task_id.clone()]);
        let cancellations = fixture.cancellations.lock().await;
        assert_eq!(
            cancellations.len(),
            if response_reached_gaugemesh { 2 } else { 1 }
        );
        assert!(cancellations.iter().all(|cancelled| cancelled == &task_id));

        runtime.shutdown().await.unwrap();
        server.abort();
    }

    #[test]
    fn task_payload_bounds_are_enforced() {
        let oversized_task = GetTaskResult::new(DetailedTask::new(
            Task::new(
                "task",
                TaskStatus::Working,
                "2026-09-05T00:00:00Z",
                "2026-09-05T00:00:00Z",
            )
            .with_status_message("x".repeat(1024 * 1024)),
            TaskPayload::Working,
        ));
        assert!(
            reject_oversized_task_response(&oversized_task)
                .unwrap_err()
                .to_string()
                .contains("GM_MCP_UPSTREAM_RESPONSE_TOO_LARGE")
        );

        let mut input_responses = BTreeMap::new();
        input_responses.insert("answer".into(), Value::String("x".repeat(1024 * 1024)));
        let oversized_update = UpdateTaskParams::new("task", input_responses);
        assert!(
            reject_oversized_task_update(&oversized_update)
                .unwrap_err()
                .to_string()
                .contains("GM_MCP_UPSTREAM_TASK_UPDATE_TOO_LARGE")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn neutral_process_task_survives_lost_ack_and_router_restart_without_duplicate_effects() {
        let workspace = TempDir::new().unwrap();
        let permitted_root = workspace.path().join("permitted-output");
        fs::create_dir(&permitted_root).unwrap();
        let fixture = NeutralTaskFixture::new(permitted_root.clone());

        let (upstream_server_side, upstream_client_side) = tokio::io::duplex(64 * 1024);
        let upstream_fixture = fixture.clone();
        let upstream_server = tokio::spawn(async move {
            let service = upstream_fixture.serve(upstream_server_side).await?;
            service.waiting().await?;
            anyhow::Ok(())
        });
        let upstream_service = serve_client(
            McpRevision::V2026_07_28,
            ApprovalConfig::Deny,
            upstream_client_side,
        )
        .await
        .unwrap();
        let discovered = capture_discovery(upstream_service.peer()).await.unwrap();
        let source_snapshot = discovered.snapshot.clone();
        assert!(source_snapshot.supports_tasks);
        assert_eq!(source_snapshot.tools, vec![NEUTRAL_TOOL_NAME.to_owned()]);

        let source_id = SourceId("neutral-worker".into());
        let source_config = McpSourceConfig {
            id: source_id.0.clone(),
            transport: McpTransportConfig::StreamableHttp {
                url: url::Url::parse("http://127.0.0.1/test-only-neutral-worker").unwrap(),
            },
            protocol_revision: McpRevision::V2026_07_28.as_str().into(),
            capability_snapshot_digest: Some(source_snapshot.capability_manifest_digest),
            sharing: gaugemesh_core::config::SharingClass::NonShareable,
            reviewed: true,
            approval: ApprovalConfig::Deny,
        };
        assert!(source_supports_durable_tasks(
            &source_config,
            &source_snapshot
        ));
        let mut unpinned_source = source_config.clone();
        unpinned_source.capability_snapshot_digest = None;
        assert!(!source_supports_durable_tasks(
            &unpinned_source,
            &source_snapshot
        ));
        let mut federation = Federation::default();
        add_source_capabilities(&mut federation, &source_config, &discovered).unwrap();
        let tool = federation.tool(NEUTRAL_TOOL_ALIAS).unwrap();
        assert_eq!(
            tool.side_effect,
            SideEffectClass::IdempotentWrite,
            "ordinary-call classification remains compatible with the pinned provider hint"
        );
        assert_eq!(
            tool.identity.schema_digest.to_string(),
            neutral_provider_interface_version()
        );
        let identities = NeutralIdentities {
            logical_task_id: "neutral-task-1".into(),
            attempt_id: "attempt-1".into(),
            correlation_id: "qualification-1".into(),
            acceptance_policy_sha256: neutral_acceptance_policy_sha256(),
            artifact_scope_sha256: neutral_artifact_scope_sha256(),
            provider_interface_version: neutral_provider_interface_version(),
        };
        let source_snapshot_digest =
            Sha256Digest::of_json(&serde_json::to_value(&source_snapshot).unwrap());
        let mut sources = BTreeMap::new();
        sources.insert(
            source_id.0.clone(),
            Arc::new(ManagedSource {
                config: source_config,
                peer: RwLock::new(ManagedPeer::new(upstream_service.peer().clone(), 1)),
                service: Mutex::new(Some(upstream_service)),
                expected_snapshot: source_snapshot_digest,
                supports_tasks: true,
                restarts: AtomicU8::new(0),
                restart_lock: Mutex::new(()),
                serialize_requests: false,
                request_lock: Mutex::new(()),
            }),
        );
        let upstreams = Arc::new(UpstreamRuntime {
            sources,
            incomplete_sources: Vec::new(),
            shutting_down: AtomicBool::new(false),
        });

        let database = workspace.path().join("task-routes.sqlite3");
        let first_storage = Arc::new(SqliteStorage::open(&database).unwrap());
        let first_leases: Arc<dyn LeaseStorage> = first_storage.clone();
        let first_routes: Arc<dyn TaskRouteStorage> = first_storage.clone();
        let first_mesh = MeshMcpServer::configured(
            federation.clone(),
            Some(upstreams.clone()),
            first_leases,
            Some(first_routes),
            gaugemesh_core::config::CapabilityMode::Lease,
        );
        let (first_server_side, first_client_side) = tokio::io::duplex(64 * 1024);
        let first_server = tokio::spawn(async move {
            let service = first_mesh.serve(first_server_side).await?;
            service.waiting().await?;
            anyhow::Ok(())
        });
        let first_client = neutral_task_client_info()
            .serve(first_client_side)
            .await
            .unwrap();
        assert!(
            first_client
                .peer_info()
                .unwrap()
                .capabilities
                .supports_tasks()
        );
        assert!(
            first_client
                .list_all_tools()
                .await
                .unwrap()
                .iter()
                .any(|tool| tool.name == "gaugemesh_submit")
        );
        let lease_response = first_client
            .call_tool_once(
                CallToolRequestParams::new("gaugemesh_lease").with_arguments(
                    json!({
                        "aliases": [NEUTRAL_TOOL_ALIAS],
                        "ttlMs": 60_000,
                        "sideEffects": ["idempotent_write", "non_idempotent_write"]
                    })
                    .as_object()
                    .unwrap()
                    .clone(),
                ),
            )
            .await
            .unwrap();
        let lease_id = match lease_response {
            CallToolResponse::Complete(result) => result
                .structured_content
                .and_then(|value| {
                    value
                        .get("leaseId")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .expect("lease response contains its durable identifier"),
            other => panic!("expected complete lease response, got {other:?}"),
        };
        let arguments = neutral_arguments(
            "valid-run",
            &identities,
            json!({"z": 3, "a": {"second": 2, "first": 1}}),
        );
        let deadline_unix_ms = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 20_000;
        let submission = task_submission(
            &arguments,
            &identities,
            "caller-a-neutral-idempotency-1",
            deadline_unix_ms,
        );
        let first_response =
            first_client
                .call_tool_once(
                    CallToolRequestParams::new("gaugemesh_submit").with_arguments(
                        submit_arguments(&lease_id, &arguments, submission.clone()),
                    ),
                )
                .await
                .unwrap();
        // The harness records the id for comparison; the simulated caller loses
        // the entire acknowledgement and only retains its idempotency key.
        let observer_task_id = task_id(first_response);
        assert_eq!(fixture.submissions.load(AtomicOrdering::SeqCst), 1);

        // Simulated crash fixture: persist the exact state that exists after a
        // dispatch claim but before any upstream acknowledgement or task ID.
        // Reopening SQLite under a new TaskProxy instance must make this route
        // explicitly unknown and must not dispatch it again.
        let crash_identities = NeutralIdentities {
            logical_task_id: "neutral-task-crash-before-ack".into(),
            attempt_id: "attempt-crash-before-ack".into(),
            correlation_id: "qualification-crash-before-ack".into(),
            ..identities.clone()
        };
        let crash_arguments = neutral_arguments(
            "crash-before-ack",
            &crash_identities,
            json!({"fault": "simulated-coordinator-crash-before-ack"}),
        );
        let crash_submission = task_submission(
            &crash_arguments,
            &crash_identities,
            "caller-a-crash-before-ack",
            deadline_unix_ms,
        );
        let parsed_crash_submission = crate::task_proxy::TaskSubmission::parse(
            &crash_submission,
            crash_arguments.as_object().unwrap(),
            &neutral_provider_interface_version(),
            SideEffectClass::NonIdempotentWrite,
            deadline_unix_ms - 20_000,
        )
        .unwrap();
        let crash_binding = json!({
            "schemaVersion": "gaugemesh.task-route/1",
            "capabilityId": tool.identity.digest(),
            "capabilitySource": tool.identity.source,
            "capabilitySchemaSha256": tool.identity.schema_digest,
            "sourceConfigurationSha256": tool.identity.source_configuration_digest,
            "sourceSnapshotSha256": source_snapshot_digest,
            "task": parsed_crash_submission,
        });
        let crash_record = TaskRouteRecord::prepare_with_id(
            PublicTaskId::new("gmt_crash_before_ack").unwrap(),
            TaskRouteCaller::new(PrincipalId("local-demo".into()), TenantId("local".into()))
                .unwrap(),
            Some(TaskRouteIdempotencyKey::new("caller-a-crash-before-ack").unwrap()),
            Sha256Digest::of_json(&crash_binding),
            crash_binding,
            tool.identity.clone(),
            upstreams.source_session_id(&source_id).await.unwrap(),
            deadline_unix_ms - 20_000,
            30_000,
        )
        .unwrap();
        first_storage.begin_or_existing(&crash_record).unwrap();
        let crash_record = first_storage
            .compare_and_set_task_route(
                &crash_record.caller,
                &crash_record.public_task_id,
                0,
                TaskRouteUpdate::dispatching(
                    "gmci_simulated_crashed_instance".into(),
                    deadline_unix_ms - 19_999,
                ),
            )
            .unwrap()
            .unwrap();
        assert_eq!(crash_record.phase, TaskRoutePhase::Dispatching);
        first_client.cancel().await.unwrap();
        first_server.await.unwrap().unwrap();
        drop(first_storage);

        let second_storage = Arc::new(SqliteStorage::open(&database).unwrap());
        let second_leases: Arc<dyn LeaseStorage> = second_storage.clone();
        let second_routes: Arc<dyn TaskRouteStorage> = second_storage;
        let second_mesh = MeshMcpServer::configured(
            federation,
            Some(upstreams.clone()),
            second_leases,
            Some(second_routes),
            gaugemesh_core::config::CapabilityMode::Lease,
        );
        let (second_server_side, second_client_side) = tokio::io::duplex(64 * 1024);
        let second_server = tokio::spawn(async move {
            let service = second_mesh.serve(second_server_side).await?;
            service.waiting().await?;
            anyhow::Ok(())
        });
        let second_client = neutral_task_client_info()
            .serve(second_client_side)
            .await
            .unwrap();
        let recovered_task_id = task_id(
            second_client
                .call_tool_once(
                    CallToolRequestParams::new("gaugemesh_submit").with_arguments(
                        submit_arguments(&lease_id, &arguments, submission.clone()),
                    ),
                )
                .await
                .unwrap(),
        );
        assert_eq!(recovered_task_id, observer_task_id);
        assert_eq!(fixture.submissions.load(AtomicOrdering::SeqCst), 1);

        let mut unsupported_input = BTreeMap::new();
        unsupported_input.insert("answer".into(), json!(42));
        let update_error = second_client
            .peer()
            .update_task(UpdateTaskParams::new(
                recovered_task_id.clone(),
                unsupported_input,
            ))
            .await
            .unwrap_err();
        assert!(
            update_error
                .to_string()
                .contains("GM_TASK_UPDATE_UNSUPPORTED_DURABLE")
        );

        let crash_recovered_task_id = task_id(
            second_client
                .call_tool_once(
                    CallToolRequestParams::new("gaugemesh_submit").with_arguments(
                        submit_arguments(&lease_id, &crash_arguments, crash_submission),
                    ),
                )
                .await
                .unwrap(),
        );
        assert_eq!(crash_recovered_task_id, "gmt_crash_before_ack");
        assert_eq!(fixture.submissions.load(AtomicOrdering::SeqCst), 1);
        let crash_state = second_client
            .peer()
            .get_task(GetTaskParams::new(crash_recovered_task_id))
            .await
            .unwrap();
        assert_eq!(crash_state.task.status(), TaskStatus::Working);
        assert_eq!(
            crash_state
                .meta
                .as_ref()
                .and_then(|meta| meta.get("dev.gaugemesh/taskRoute"))
                .and_then(|route| route.get("routePhase"))
                .and_then(Value::as_str),
            Some("reconciliation_required")
        );
        assert!(!permitted_root.join("crash-before-ack").exists());

        let changed_arguments =
            neutral_arguments("must-not-run", &identities, json!({"a": "changed input"}));
        let changed_submission = task_submission(
            &changed_arguments,
            &identities,
            "caller-a-neutral-idempotency-1",
            deadline_unix_ms,
        );
        let conflict =
            second_client
                .call_tool_once(
                    CallToolRequestParams::new("gaugemesh_submit").with_arguments(
                        submit_arguments(&lease_id, &changed_arguments, changed_submission),
                    ),
                )
                .await
                .unwrap_err();
        assert!(
            conflict
                .to_string()
                .contains("GM_TASK_IDEMPOTENCY_CONFLICT")
        );
        assert_eq!(fixture.submissions.load(AtomicOrdering::SeqCst), 1);

        let mut bad_schema = task_submission(
            &arguments,
            &identities,
            "caller-a-bad-schema",
            deadline_unix_ms,
        );
        bad_schema["schemaVersion"] = json!("gaugemesh.task-submission/999");
        let schema_error = second_client
            .call_tool_once(
                CallToolRequestParams::new("gaugemesh_submit")
                    .with_arguments(submit_arguments(&lease_id, &arguments, bad_schema)),
            )
            .await
            .unwrap_err();
        assert!(
            schema_error
                .to_string()
                .contains("GM_TASK_SCHEMA_UNSUPPORTED")
        );

        let mut unsupported_provider = task_submission(
            &arguments,
            &identities,
            "caller-a-unsupported-provider-version",
            deadline_unix_ms,
        );
        unsupported_provider["providerInterfaceVersion"] = json!("neutral-json/999");
        let provider_error =
            second_client
                .call_tool_once(
                    CallToolRequestParams::new("gaugemesh_submit").with_arguments(
                        submit_arguments(&lease_id, &arguments, unsupported_provider),
                    ),
                )
                .await
                .unwrap_err();
        assert!(
            provider_error
                .to_string()
                .contains("GM_TASK_PROVIDER_VERSION_UNSUPPORTED")
        );
        assert_eq!(fixture.submissions.load(AtomicOrdering::SeqCst), 1);

        let mut wrong_capability = submit_arguments(
            &lease_id,
            &arguments,
            task_submission(
                &arguments,
                &identities,
                "caller-a-wrong-capability",
                deadline_unix_ms,
            ),
        );
        wrong_capability.insert("alias".into(), json!("missing-worker__normalize_json"));
        let wrong_capability = second_client
            .call_tool_once(
                CallToolRequestParams::new("gaugemesh_submit").with_arguments(wrong_capability),
            )
            .await
            .unwrap();
        assert_eq!(
            structured_error_code(wrong_capability).as_deref(),
            Some("GM_CAPABILITY_NOT_FOUND")
        );

        let unauthorized_effect_lease = second_client
            .call_tool_once(
                CallToolRequestParams::new("gaugemesh_lease").with_arguments(
                    json!({
                        "aliases": [NEUTRAL_TOOL_ALIAS],
                        "ttlMs": 60_000,
                        "sideEffects": ["read_only"]
                    })
                    .as_object()
                    .unwrap()
                    .clone(),
                ),
            )
            .await
            .unwrap();
        assert_eq!(
            structured_error_code(unauthorized_effect_lease).as_deref(),
            Some("GM_LEASE_SIDE_EFFECT_OUTSIDE_CONE")
        );

        let unauthorized = second_client
            .call_tool_once(
                CallToolRequestParams::new("gaugemesh_submit").with_arguments(submit_arguments(
                    "not-a-lease",
                    &arguments,
                    task_submission(
                        &arguments,
                        &identities,
                        "caller-a-unauthorized",
                        deadline_unix_ms,
                    ),
                )),
            )
            .await
            .unwrap();
        assert_eq!(
            structured_error_code(unauthorized).as_deref(),
            Some("GM_LEASE_CAPABILITY_OUTSIDE_CONE")
        );

        let mut effect_mismatch = task_submission(
            &arguments,
            &identities,
            "caller-a-effect-mismatch",
            deadline_unix_ms,
        );
        effect_mismatch["permittedEffect"] = json!("idempotent_write");
        let effect_error =
            second_client
                .call_tool_once(
                    CallToolRequestParams::new("gaugemesh_submit")
                        .with_arguments(submit_arguments(&lease_id, &arguments, effect_mismatch)),
                )
                .await
                .unwrap_err();
        assert!(effect_error.to_string().contains("GM_TASK_EFFECT_MISMATCH"));

        let terminal = {
            let mut observed = None;
            for _ in 0..200 {
                let state = second_client
                    .peer()
                    .get_task(GetTaskParams::new(recovered_task_id.clone()))
                    .await
                    .unwrap();
                if state.task.status().is_terminal() {
                    observed = Some(state.task);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            observed.expect("neutral worker task must settle within the bounded fixture window")
        };
        assert_eq!(terminal.status(), TaskStatus::Completed);
        assert_eq!(terminal.task.task_id, recovered_task_id);
        assert_eq!(terminal.task.ttl_ms, Some(30_000));
        assert_eq!(terminal.task.poll_interval_ms, Some(100));
        verify_neutral_artifacts(&permitted_root, &arguments).unwrap();
        assert_eq!(
            fs::read_dir(permitted_root.join("worker-effects"))
                .unwrap()
                .count(),
            1,
            "lost acknowledgement and restart must not duplicate the worker process effect"
        );

        // Exercise cancellation racing an in-flight upstream acknowledgement.
        // The duplicate submission exposes the already-durable public ID while
        // the original request is still awaiting the provider response.
        fixture
            .acknowledgement_delay_ms
            .store(150, AtomicOrdering::Release);
        let race_identities = NeutralIdentities {
            logical_task_id: "neutral-task-cancel-race".into(),
            attempt_id: "attempt-cancel-race".into(),
            correlation_id: "qualification-cancel-race".into(),
            ..identities.clone()
        };
        let race_arguments = neutral_arguments(
            "cancel-race",
            &race_identities,
            json!({"race": "cancellation-before-ack"}),
        );
        let race_submission = task_submission(
            &race_arguments,
            &race_identities,
            "caller-a-cancel-race",
            deadline_unix_ms,
        );
        let original_peer = second_client.peer().clone();
        let original_request = CallToolRequestParams::new("gaugemesh_submit").with_arguments(
            submit_arguments(&lease_id, &race_arguments, race_submission.clone()),
        );
        let original =
            tokio::spawn(async move { original_peer.call_tool_once(original_request).await });
        for _ in 0..100 {
            if fixture.submissions.load(AtomicOrdering::SeqCst) == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(fixture.submissions.load(AtomicOrdering::SeqCst), 2);
        let race_task_id = task_id(
            second_client
                .call_tool_once(
                    CallToolRequestParams::new("gaugemesh_submit").with_arguments(
                        submit_arguments(&lease_id, &race_arguments, race_submission),
                    ),
                )
                .await
                .unwrap(),
        );
        second_client
            .peer()
            .cancel_task(CancelTaskParams::new(race_task_id.clone()))
            .await
            .unwrap();
        let original_task_id = task_id(original.await.unwrap().unwrap());
        assert_eq!(original_task_id, race_task_id);
        fixture
            .acknowledgement_delay_ms
            .store(0, AtomicOrdering::Release);
        let mut race_terminal = None;
        for _ in 0..200 {
            let state = second_client
                .peer()
                .get_task(GetTaskParams::new(race_task_id.clone()))
                .await
                .unwrap();
            if state.task.status().is_terminal() {
                race_terminal = Some(state.task);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            race_terminal.is_some(),
            "a cancellation/acknowledgement race must retain the upstream ID for reconciliation"
        );
        assert_eq!(fixture.submissions.load(AtomicOrdering::SeqCst), 2);

        // A synchronous provider completion can race the same pre-ack
        // cancellation. The public response must not become terminal until
        // the complete payload is durably cached.
        fixture
            .complete_response
            .store(true, AtomicOrdering::Release);
        fixture
            .acknowledgement_delay_ms
            .store(150, AtomicOrdering::Release);
        let complete_identities = NeutralIdentities {
            logical_task_id: "neutral-task-complete-cancel-race".into(),
            attempt_id: "attempt-complete-cancel-race".into(),
            correlation_id: "qualification-complete-cancel-race".into(),
            ..identities.clone()
        };
        let complete_arguments = neutral_arguments(
            "complete-cancel-race",
            &complete_identities,
            json!({"race": "synchronous-completion-before-ack"}),
        );
        let complete_submission = task_submission(
            &complete_arguments,
            &complete_identities,
            "caller-a-complete-cancel-race",
            deadline_unix_ms,
        );
        let complete_peer = second_client.peer().clone();
        let complete_request = CallToolRequestParams::new("gaugemesh_submit").with_arguments(
            submit_arguments(&lease_id, &complete_arguments, complete_submission.clone()),
        );
        let complete =
            tokio::spawn(async move { complete_peer.call_tool_once(complete_request).await });
        for _ in 0..100 {
            if fixture.submissions.load(AtomicOrdering::SeqCst) == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(fixture.submissions.load(AtomicOrdering::SeqCst), 3);
        let complete_task_id = task_id(
            second_client
                .call_tool_once(
                    CallToolRequestParams::new("gaugemesh_submit").with_arguments(
                        submit_arguments(&lease_id, &complete_arguments, complete_submission),
                    ),
                )
                .await
                .unwrap(),
        );
        second_client
            .peer()
            .cancel_task(CancelTaskParams::new(complete_task_id.clone()))
            .await
            .unwrap();
        let complete_response = complete.await.unwrap().unwrap();
        assert_eq!(task_id(complete_response), complete_task_id);
        let complete_terminal = second_client
            .peer()
            .get_task(GetTaskParams::new(complete_task_id))
            .await
            .unwrap();
        assert_eq!(complete_terminal.task.status(), TaskStatus::Completed);
        verify_neutral_artifacts(&permitted_root, &complete_arguments).unwrap();
        fixture
            .complete_response
            .store(false, AtomicOrdering::Release);
        fixture
            .acknowledgement_delay_ms
            .store(0, AtomicOrdering::Release);

        let invalid_arguments = neutral_arguments(
            "invalid-worker-output",
            &NeutralIdentities {
                attempt_id: "attempt-invalid".into(),
                ..identities.clone()
            },
            json!({"neutral": true}),
        );
        let invalid_worker = run_neutral_worker_process(&permitted_root, &invalid_arguments, true)
            .await
            .unwrap();
        assert!(invalid_worker.success());
        assert!(
            verify_neutral_artifacts(&permitted_root, &invalid_arguments)
                .unwrap_err()
                .to_string()
                .contains("NEUTRAL_VERIFY_IDENTITY_OR_CONTENT_MISMATCH")
        );

        let traversal_arguments = neutral_arguments(
            "../outside-permitted-root",
            &identities,
            json!({"neutral": true}),
        );
        let traversal = run_neutral_worker_process(&permitted_root, &traversal_arguments, false)
            .await
            .unwrap();
        assert!(!traversal.success());
        assert!(!workspace.path().join("outside-permitted-root").exists());

        #[cfg(unix)]
        {
            let outside = TempDir::new().unwrap();
            std::os::unix::fs::symlink(outside.path(), permitted_root.join("linked-output"))
                .unwrap();
            let symlink_arguments =
                neutral_arguments("linked-output/job", &identities, json!({"neutral": true}));
            let symlink = run_neutral_worker_process(&permitted_root, &symlink_arguments, false)
                .await
                .unwrap();
            assert!(!symlink.success());
            assert!(!outside.path().join("job").exists());
        }

        second_client.cancel().await.unwrap();
        second_server.await.unwrap().unwrap();
        upstreams.shutdown().await.unwrap();
        upstream_server.abort();
    }

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
                        None,
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
        let initial_session = upstreams.source_session_id(&source_id).await.unwrap();
        let mut prior_session = initial_session.clone();
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
            let managed_peer = managed.peer.read().await;
            assert_eq!(managed_peer.generation, u64::from(expected_restarts) + 1);
            assert_ne!(managed_peer.session_id, prior_session);
            prior_session = managed_peer.session_id.clone();
            drop(managed_peer);
            let stale_session_error = upstreams
                .call_tool_with_task_capability_for_session(
                    &source_id,
                    CallToolRequestParams::new("docs-a__search"),
                    true,
                    &initial_session,
                )
                .await
                .unwrap_err();
            assert!(format!("{stale_session_error:#}").contains("GM_MCP_UPSTREAM_SESSION_CHANGED"));
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
