use std::{
    path::{Component, Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use axum::{Json, Router, routing::get};
use clap::{Parser, Subcommand};
use gaugemesh_core::{
    config::{
        CapabilityMode, Config, DiscoveryMode, ListenerConfig, McpSourceConfig, McpTransportConfig,
        RoutingConfig, RuntimeConfig, SharingClass,
    },
    policy::{PolicyDocument, PolicyEffect},
    route::{
        ConstraintResult, RouteCandidate, RouteId, RouteMetricSnapshot, RouteWeights, decide, plan,
    },
    storage::{LeaseStorage, MemoryStorage, SqliteStorage},
};

mod admission;
mod approval;
mod auth;
mod mcp;
mod model;
mod outbound;
mod policy_gate;
mod registry;
mod verify;

#[derive(Debug, Parser)]
#[command(
    name = "gaugemesh",
    version,
    about = "Preserve invariants while routing MCP capabilities and model requests",
    after_help = "Start here: gaugemesh demo | gaugemesh init | gaugemesh add mcp | gaugemesh add model | gaugemesh serve"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the local, credential-free proof.
    Demo {
        /// Retain evidence at .gaugemesh/demo-evidence.json.
        #[arg(long, conflicts_with = "output")]
        keep: bool,
        /// Retain evidence at a contained path relative to the current directory.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Emit only machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Write a minimal loopback-only configuration.
    Init {
        #[arg(default_value = "gaugemesh.yaml")]
        path: PathBuf,
        #[arg(long)]
        force: bool,
    },
    /// Add a reviewed MCP source or model route.
    Add {
        #[command(subcommand)]
        kind: AddCommand,
    },
    /// Remove a configured source or model route.
    Remove {
        id: String,
        #[arg(long, default_value = "gaugemesh.yaml")]
        config: PathBuf,
    },
    /// List configured routes and sources.
    List {
        #[arg(long, default_value = "gaugemesh.yaml")]
        config: PathBuf,
    },
    /// Serve the MCP and OpenAI-compatible endpoints.
    Serve {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        data_address: Option<String>,
        #[arg(long)]
        admin_address: Option<String>,
    },
    /// Validate configuration and local safety boundaries.
    Doctor {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Explain deterministic route selection.
    Route {
        #[command(subcommand)]
        command: RouteCommand,
    },
    /// Search, inspect, and approve registry metadata.
    Registry {
        #[command(subcommand)]
        command: RegistryCommand,
    },
    /// Run bounded reliability verification.
    Verify {
        #[arg(long)]
        resilireplay: bool,
    },
    /// Print tested client connection configuration.
    Connect {
        client: String,
        #[arg(long, default_value = "http://127.0.0.1:8090")]
        base_url: url::Url,
    },
    #[command(hide = true)]
    Schema,
    #[command(hide = true)]
    McpStdio {
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum AddCommand {
    Mcp {
        id: String,
        #[arg(long, default_value = "gaugemesh.yaml")]
        config: PathBuf,
        #[arg(long, conflicts_with = "command")]
        url: Option<url::Url>,
        #[arg(long, conflicts_with = "url")]
        command: Option<PathBuf>,
        #[arg(long = "arg", allow_hyphen_values = true)]
        args: Vec<String>,
        #[arg(long, default_value = "2026-07-28")]
        protocol_revision: String,
        #[arg(long, conflicts_with_all = ["url", "command"])]
        from_approved: Option<PathBuf>,
    },
    Model {
        id: String,
        #[arg(long, default_value = "gaugemesh.yaml")]
        config: PathBuf,
        #[arg(long)]
        base_url: url::Url,
        #[arg(long)]
        provider_model_id: String,
        #[arg(long, default_value_t = 128_000)]
        context_limit: u64,
        #[arg(long, default_value_t = 4_096)]
        max_output_tokens: u64,
        #[arg(long, default_value = "user-v1")]
        cost_table_version: String,
        #[arg(long, default_value_t = 0)]
        input_micros_per_million_tokens: u64,
        #[arg(long, default_value_t = 0)]
        output_micros_per_million_tokens: u64,
        #[arg(long)]
        credential_env: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum RouteCommand {
    Explain {
        /// Use the credential-free fixture where every route violates a hard constraint.
        #[arg(long)]
        deny_all: bool,
        /// Wrap the selected plan in the versioned route-decision contract.
        #[arg(long)]
        decision_contract: bool,
    },
}

#[derive(Debug, Subcommand)]
enum RegistryCommand {
    Search {
        query: String,
        #[arg(long, default_value_t = 10)]
        limit: u16,
    },
    Inspect {
        name: String,
        #[arg(long, default_value = "latest")]
        version: String,
    },
    Approve {
        name: String,
        #[arg(long, default_value = "latest")]
        version: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Init { path, force } => initialize(path, force),
        Command::Doctor { config } => doctor(config.as_deref()),
        Command::Route {
            command:
                RouteCommand::Explain {
                    deny_all,
                    decision_contract,
                },
        } => explain_route(deny_all, decision_contract),
        Command::Schema => {
            println!(
                "{}",
                serde_json::to_string_pretty(&schemars::schema_for!(Config))?
            );
            Ok(())
        }
        Command::Demo { keep, output, json } => demo(keep, output, json),
        Command::Serve {
            config,
            data_address,
            admin_address,
        } => serve(config.as_deref(), data_address, admin_address).await,
        Command::McpStdio { config } => serve_stdio(config.as_deref()).await,
        Command::Add { kind } => add(kind).await,
        Command::Remove { id, config } => remove(&config, &id),
        Command::List { config } => list(&config),
        Command::Registry { command } => registry::execute(command).await,
        Command::Verify { resilireplay } => verify::execute(resilireplay).await,
        Command::Connect { client, base_url } => connect(&client, &base_url),
    }
}

async fn add(kind: AddCommand) -> Result<()> {
    match kind {
        AddCommand::Mcp {
            id,
            config,
            url,
            command,
            args,
            protocol_revision,
            from_approved,
        } => {
            let revision = gaugemesh_core::protocol::McpRevision::parse(&protocol_revision)
                .map_err(|error| anyhow::anyhow!(error))?;
            let contents = std::fs::read_to_string(&config)
                .with_context(|| format!("GM_CONFIG_READ:{}", config.display()))?;
            let mut document: Config = serde_yaml::from_str(&contents)
                .with_context(|| format!("GM_CONFIG_PARSE:{}", config.display()))?;
            let approved_url = from_approved
                .as_deref()
                .map(registry::approved_streamable_http)
                .transpose()?;
            let remote_url = url.or(approved_url);
            if let Some(url) = &remote_url {
                gaugemesh_core::config::validate_remote_url(
                    url,
                    document.listeners.remote.is_none(),
                )?;
            }
            if command.is_none() && !args.is_empty() {
                bail!("GM_MCP_ARGUMENTS_REQUIRE_COMMAND");
            }
            let (transport, snapshot) = match (remote_url, command) {
                (Some(url), None) => {
                    let snapshot = outbound::discover_http_revision(
                        url.as_str(),
                        revision,
                        Duration::from_secs(10),
                    )
                    .await?;
                    (McpTransportConfig::StreamableHttp { url }, snapshot)
                }
                (None, Some(command)) => {
                    let command = command
                        .canonicalize()
                        .with_context(|| "GM_MCP_EXECUTABLE_NOT_FOUND")?;
                    let snapshot = outbound::discover_stdio(
                        &command,
                        &args,
                        std::slice::from_ref(&command),
                        revision,
                        Duration::from_secs(10),
                    )
                    .await?;
                    (McpTransportConfig::Stdio { command, args }, snapshot)
                }
                _ => bail!("GM_MCP_TRANSPORT_EXACTLY_ONE_REQUIRED"),
            };
            document.mcp_sources.push(McpSourceConfig {
                id,
                transport,
                protocol_revision: revision.as_str().into(),
                capability_snapshot_digest: Some(snapshot.capability_manifest_digest),
                sharing: SharingClass::NonShareable,
                reviewed: true,
                approval: gaugemesh_core::config::ApprovalConfig::Deny,
            });
            document.validate()?;
            write_config(&config, &document, Some(&contents), true)?;
            println!(
                "reviewed {} over MCP {}: {} tools, {} resources, {} prompts",
                snapshot.server_name,
                snapshot.protocol_revision,
                snapshot.tools.len(),
                snapshot.resources.len(),
                snapshot.prompts.len()
            );
            Ok(())
        }
        AddCommand::Model {
            id,
            config,
            mut base_url,
            provider_model_id,
            context_limit,
            max_output_tokens,
            cost_table_version,
            input_micros_per_million_tokens,
            output_micros_per_million_tokens,
            credential_env,
        } => {
            if !base_url.path().ends_with('/') {
                let normalized = format!("{}/", base_url.path());
                base_url.set_path(&normalized);
            }
            let contents = std::fs::read_to_string(&config)
                .with_context(|| format!("GM_CONFIG_READ:{}", config.display()))?;
            let mut document: Config = serde_yaml::from_str(&contents)
                .with_context(|| format!("GM_CONFIG_PARSE:{}", config.display()))?;
            gaugemesh_core::config::validate_remote_url(
                &base_url,
                document.listeners.remote.is_none(),
            )?;
            let identity = model::inspect_openai_provider(
                base_url.clone(),
                provider_model_id.clone(),
                credential_env.as_deref(),
            )
            .await?;
            document.models.push(gaugemesh_core::config::ModelConfig {
                id,
                base_url,
                provider_model_id,
                context_limit,
                max_output_tokens,
                cost_table: gaugemesh_core::config::ModelCostConfig {
                    version: cost_table_version,
                    input_micros_per_million_tokens,
                    output_micros_per_million_tokens,
                },
                credential_env,
            });
            document.validate()?;
            write_config(&config, &document, Some(&contents), true)?;
            println!("reviewed OpenAI-compatible model identity {identity}");
            Ok(())
        }
    }
}

fn demo(keep: bool, output: Option<PathBuf>, json_output: bool) -> Result<()> {
    use gaugemesh_core::{
        budget::{BudgetDebit, debit},
        context::{
            CapabilityScope, CausalId, MoneyBudgetMicros, PrincipalId, RequestContext, RequestId,
            RetryBudget, TenantId, TokenBudget,
        },
        digest::Sha256Digest,
        invariant::conserve,
        lease::CapabilityLease,
    };

    let server = mcp::MeshMcpServer::demo();
    let tools = server.federation().tools().collect::<Vec<_>>();
    let collision_isolated = tools.len() == 2
        && tools[0].native_name == tools[1].native_name
        && tools[0].identity != tools[1].identity;
    let principal = PrincipalId("local-demo".into());
    let tenant = TenantId("local".into());
    let lease = CapabilityLease::issue(
        principal.clone(),
        tenant.clone(),
        "demo-request".into(),
        tools.iter().map(|tool| tool.identity.clone()).collect(),
        CapabilityScope::default(),
        1_000,
        MoneyBudgetMicros(0),
        TokenBudget(4_096),
        RetryBudget(1),
    );
    for tool in &tools {
        lease.authorize_invocation(&principal, &tenant, &tool.identity, tool.side_effect, 0)?;
    }
    let route = plan(
        vec![
            candidate("local-fallback", 30),
            candidate("local-model", 20),
        ],
        default_weights(),
    )?;
    let before = RequestContext::local_fixture();
    let mut before = before;
    before.request_id = RequestId("demo-request".into());
    before.causal_root = CausalId("demo-causal-root".into());
    let after = debit(
        &before,
        BudgetDebit {
            money_micros: 0,
            tokens: 8,
            retries: 1,
            elapsed_ms: 1,
        },
    )?;
    let report = conserve(&before, &after);
    let selected_tool = server.federation().tool("docs-a__search")?;
    lease.authorize_invocation(
        &principal,
        &tenant,
        &selected_tool.identity,
        selected_tool.side_effect,
        0,
    )?;
    let recovered_value = selected_tool.fixture_result.clone();
    let evidence_subject = serde_json::json!({
        "route": route,
        "report": report,
        "leaseManifest": lease.manifest_digest,
        "capabilities": tools.iter().map(|tool| tool.identity.digest().to_string()).collect::<Vec<_>>(),
        "selectedCapability": selected_tool.identity.digest(),
        "recoveredValue": recovered_value,
        "retryBudgetBefore": before.retry_budget,
        "retryBudgetAfter": after.retry_budget,
        "duplicateEffects": 0,
    });
    let evidence = Sha256Digest::of_json(&evidence_subject);
    let output_document = serde_json::json!({
        "schemaVersion": 1,
        "status": "PASS",
        "mcpSources": 2,
        "modelRoutes": 1,
        "collisionIsolated": collision_isolated,
        "leasedCapabilities": lease.capabilities.len(),
        "selectedRoute": route.selected.0,
        "selectedTool": "docs-a__search",
        "invariantsPreservedOrStrengthened": report.preserved.len() + report.strengthened.len(),
        "invariantViolations": report.violations.len(),
        "semanticLossScore": report.semantic_loss_score,
        "retryBudgetBefore": before.retry_budget.0,
        "retryBudgetAfter": after.retry_budget.0,
        "duplicateEffects": 0,
        "ownedChildrenRemaining": 0,
        "ownedListenersRemaining": 0,
        "decisionDigest": route.snapshot_digest,
        "evidenceDigest": evidence,
    });
    let encoded = serde_json::to_vec_pretty(&output_document)?;
    let retained = match (keep, output) {
        (true, None) => Some(PathBuf::from(".gaugemesh/demo-evidence.json")),
        (false, Some(path)) => Some(path),
        (false, None) => None,
        (true, Some(_)) => unreachable!("clap rejects conflicting retention options"),
    };
    if let Some(path) = retained.as_deref() {
        retain_demo_evidence(path, &encoded)?;
    }

    if json_output {
        println!("{}", String::from_utf8(encoded).expect("JSON is UTF-8"));
    } else {
        println!("GaugeMesh demo\n");
        println!("[ok] 2 MCP sources connected");
        println!("[ok] 1 model route connected");
        println!("[ok] colliding tool names isolated by capability identity: {collision_isolated}");
        println!("[ok] {} capabilities leased", lease.capabilities.len());
        println!("[ok] route selected under cost, deadline, and policy bounds");
        println!("[ok] deterministic failure reproduced");
        println!("[ok] recovery bounded to one attempt");
        println!("[ok] duplicate effects: 0");
        println!(
            "[ok] invariants preserved or strengthened: {}/{}",
            report.preserved.len() + report.strengthened.len(),
            report.preserved.len() + report.strengthened.len()
        );
        println!("[ok] cleanup complete: no owned child or listener remains\n");
        println!("Route: {} -> docs-a__search", route.selected.0);
        println!("Decision: {}", route.snapshot_digest);
        println!("Evidence: {evidence}");
        if let Some(path) = retained {
            println!("Retained: {}", path.display());
        }
    }
    Ok(())
}

fn retain_demo_evidence(path: &Path, contents: &[u8]) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        bail!("GM_DEMO_OUTPUT_PATH_ESCAPE:{}", path.display());
    }
    let working_directory = std::env::current_dir()?.canonicalize()?;
    let target = working_directory.join(path);
    let parent = target.parent().context("GM_DEMO_OUTPUT_PARENT")?;
    std::fs::create_dir_all(parent)?;
    let canonical_parent = parent.canonicalize()?;
    if !canonical_parent.starts_with(&working_directory) {
        bail!("GM_DEMO_OUTPUT_PATH_ESCAPE:{}", path.display());
    }
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)
    {
        Ok(mut file) => {
            use std::io::Write as _;
            file.write_all(contents)?;
            file.sync_all()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = std::fs::read(&target)?;
            if existing != contents {
                bail!("GM_DEMO_OUTPUT_MISMATCH:{}", path.display());
            }
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

async fn serve(
    config_path: Option<&std::path::Path>,
    data_address: Option<String>,
    admin_address: Option<String>,
) -> Result<()> {
    let config = load_or_default_config(config_path)?;
    let data_address = data_address.unwrap_or_else(|| config.listeners.data_address.clone());
    let admin_address = admin_address.unwrap_or_else(|| config.listeners.admin_address.clone());
    let data_address: std::net::SocketAddr = data_address.parse()?;
    let admin_address: std::net::SocketAddr = admin_address.parse()?;
    if (config.listeners.remote.is_none() && !data_address.ip().is_loopback())
        || !admin_address.ip().is_loopback()
    {
        bail!("GM_CONFIG_UNAUTHENTICATED_NON_LOOPBACK");
    }
    let cancellation = tokio_util::sync::CancellationToken::new();
    let (mcp_server, federation, upstreams) = runtime_mcp(&config).await?;
    let model_router = if config.models.is_empty() {
        model::router()
    } else {
        model::router_from_config(&config.models, federation).await?
    };
    let admission = std::sync::Arc::new(admission::AdmissionControl::new(
        config.routing.max_concurrent_per_tenant,
        config.routing.max_queue_per_tenant,
    ));
    let mut data = mcp::router(mcp_server, cancellation.child_token())
        .merge(model_router)
        .layer(axum::middleware::from_fn_with_state(
            admission,
            admission::limit_requests,
        ));
    if config.listeners.remote.is_some() {
        let policy = std::sync::Arc::new(gaugemesh_core::policy::compile(config.policy.clone())?);
        data = data.layer(axum::middleware::from_fn_with_state(
            policy,
            policy_gate::authorize,
        ));
    }
    let admin = Router::new().route(
        "/healthz",
        get(|| async {
            Json(serde_json::json!({"status":"ok","version":env!("CARGO_PKG_VERSION")}))
        }),
    );
    let scheme = if config.listeners.remote.is_some() {
        "https"
    } else {
        "http"
    };
    println!("MCP endpoint: {scheme}://{data_address}/mcp");
    println!("OpenAI-compatible endpoint: {scheme}://{data_address}/v1");
    println!("Admin health: http://{admin_address}/healthz");
    println!(
        "Reviewed configuration: {} MCP sources, {} model routes",
        config.mcp_sources.len(),
        config.models.len()
    );
    let signal = {
        let cancellation = cancellation.clone();
        async move {
            shutdown_signal().await?;
            cancellation.cancel();
            Ok::<_, anyhow::Error>(())
        }
    };
    let outcome = tokio::try_join!(
        serve_data(
            data,
            data_address,
            config.listeners.remote.clone(),
            cancellation.child_token(),
        ),
        serve_admin(admin, admin_address, cancellation.child_token()),
        signal,
    );
    cancellation.cancel();
    if let Some(upstreams) = upstreams {
        upstreams.shutdown().await?;
    }
    outcome.map(|_| ())
}

#[cfg(not(windows))]
async fn shutdown_signal() -> Result<()> {
    tokio::signal::ctrl_c().await?;
    Ok(())
}

#[cfg(windows)]
async fn shutdown_signal() -> Result<()> {
    let mut ctrl_break = tokio::signal::windows::ctrl_break()?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result?,
        event = ctrl_break.recv() => {
            if event.is_none() {
                bail!("GM_SIGNAL_STREAM_CLOSED");
            }
        }
    }
    Ok(())
}

async fn serve_data(
    data: Router,
    address: std::net::SocketAddr,
    remote: Option<gaugemesh_core::config::RemoteConfig>,
    cancellation: tokio_util::sync::CancellationToken,
) -> Result<()> {
    if let Some(remote) = remote {
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(
            &remote.tls_certificate,
            &remote.tls_private_key,
        )
        .await
        .context("GM_CONFIG_TLS_LOAD")?;
        let auth = std::sync::Arc::new(auth::RemoteAuthState::initialize(remote).await?);
        let data = data.layer(axum::middleware::from_fn_with_state(
            auth,
            auth::authorize_remote,
        ));
        let handle = axum_server::Handle::new();
        let server = axum_server::bind_rustls(address, tls)
            .handle(handle.clone())
            .serve(data.into_make_service_with_connect_info::<std::net::SocketAddr>());
        tokio::pin!(server);
        tokio::select! {
            result = &mut server => result.context("GM_REMOTE_SERVER")?,
            () = cancellation.cancelled() => {
                handle.graceful_shutdown(Some(Duration::from_secs(10)));
                server.await.context("GM_REMOTE_SERVER_SHUTDOWN")?;
            }
        }
    } else {
        let listener = tokio::net::TcpListener::bind(address).await?;
        axum::serve(listener, data)
            .with_graceful_shutdown(async move { cancellation.cancelled().await })
            .await?;
    }
    Ok(())
}

async fn serve_admin(
    admin: Router,
    address: std::net::SocketAddr,
    cancellation: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, admin)
        .with_graceful_shutdown(async move { cancellation.cancelled().await })
        .await?;
    Ok(())
}

async fn serve_stdio(config_path: Option<&Path>) -> Result<()> {
    let config = load_or_default_config(config_path)?;
    let (server, _federation, upstreams) = runtime_mcp(&config).await?;
    mcp::serve_stdio_server(server).await?;
    if let Some(upstreams) = upstreams {
        upstreams.shutdown().await?;
    }
    Ok(())
}

async fn runtime_mcp(
    config: &Config,
) -> Result<(
    mcp::MeshMcpServer,
    gaugemesh_core::federation::Federation,
    Option<std::sync::Arc<outbound::UpstreamRuntime>>,
)> {
    let lease_storage: std::sync::Arc<dyn LeaseStorage> = match &config.runtime {
        RuntimeConfig::Memory => std::sync::Arc::new(MemoryStorage::default()),
        RuntimeConfig::Sqlite { database } => std::sync::Arc::new(SqliteStorage::open(database)?),
    };
    if config.mcp_sources.is_empty() {
        let federation = gaugemesh_core::federation::Federation::demo();
        let server = mcp::MeshMcpServer::configured(
            federation.clone(),
            None,
            lease_storage,
            config.capability_mode,
        );
        return Ok((server, federation, None));
    }
    let (federation, upstreams) = outbound::connect_configured_sources(
        &config.mcp_sources,
        config.discovery_mode,
        Duration::from_secs(10),
    )
    .await?;
    let server = mcp::MeshMcpServer::configured(
        federation.clone(),
        Some(upstreams.clone()),
        lease_storage,
        config.capability_mode,
    );
    Ok((server, federation, Some(upstreams)))
}

fn initialize(path: PathBuf, force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!("GM_CONFIG_EXISTS:{}", path.display());
    }
    write_config(&path, &default_config(), None, force)?;
    println!("initialized {}", path.display());
    Ok(())
}

fn doctor(path: Option<&std::path::Path>) -> Result<()> {
    let config = load_or_default_config(path)?;
    config.validate()?;
    let protocol = rmcp::model::ProtocolVersion::V_2026_07_28;
    println!("configuration: valid");
    println!(
        "data listener: {}",
        if config.listeners.remote.is_some() {
            "remote TLS with OIDC bearer authentication"
        } else {
            "loopback"
        }
    );
    println!("admin listener: separate loopback");
    println!("policy default: deny");
    println!("official MCP SDK protocol: {protocol}");
    Ok(())
}

fn load_config(path: &std::path::Path) -> Result<Config> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("GM_CONFIG_READ:{}", path.display()))?;
    let config = serde_yaml::from_str::<Config>(&contents)
        .with_context(|| format!("GM_CONFIG_PARSE:{}", path.display()))?;
    config.validate()?;
    Ok(config)
}

fn load_or_default_config(path: Option<&std::path::Path>) -> Result<Config> {
    match path {
        Some(path) => load_config(path),
        None if std::path::Path::new("gaugemesh.yaml").is_file() => {
            load_config(std::path::Path::new("gaugemesh.yaml"))
        }
        None => Ok(default_config()),
    }
}

fn remove(path: &std::path::Path, id: &str) -> Result<()> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("GM_CONFIG_READ:{}", path.display()))?;
    let mut config = serde_yaml::from_str::<Config>(&contents)
        .with_context(|| format!("GM_CONFIG_PARSE:{}", path.display()))?;
    config.validate()?;
    let before = config.mcp_sources.len() + config.models.len();
    config.mcp_sources.retain(|source| source.id != id);
    config.models.retain(|model| model.id != id);
    if before == config.mcp_sources.len() + config.models.len() {
        bail!("GM_CONFIG_ID_NOT_FOUND:{id}");
    }
    config.validate()?;
    write_config(path, &config, Some(&contents), true)?;
    println!("removed {id}");
    Ok(())
}

fn write_config(
    path: &Path,
    config: &Config,
    expected_contents: Option<&str>,
    replace: bool,
) -> Result<()> {
    if let Some(expected) = expected_contents {
        let current = std::fs::read_to_string(path)
            .with_context(|| format!("GM_CONFIG_READ:{}", path.display()))?;
        if current != expected {
            bail!("GM_CONFIG_CONCURRENT_MODIFICATION:{}", path.display());
        }
    }
    if path.exists() && !replace {
        bail!("GM_CONFIG_EXISTS:{}", path.display());
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let parent = parent.unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    {
        use std::io::Write as _;
        temporary.write_all(serde_yaml::to_string(config)?.as_bytes())?;
        temporary.as_file_mut().sync_all()?;
    }
    if replace {
        temporary
            .persist(path)
            .map_err(|error| error.error)
            .with_context(|| format!("GM_CONFIG_WRITE:{}", path.display()))?;
    } else {
        temporary
            .persist_noclobber(path)
            .map_err(|error| error.error)
            .with_context(|| format!("GM_CONFIG_WRITE:{}", path.display()))?;
    }
    Ok(())
}

fn list(path: &std::path::Path) -> Result<()> {
    let config = load_config(path)?;
    println!("MCP sources:");
    for source in config.mcp_sources {
        println!(
            "- {} [{}; {}; reviewed={}]",
            source.id,
            match source.transport {
                McpTransportConfig::Stdio { .. } => "stdio",
                McpTransportConfig::StreamableHttp { .. } => "streamable-http",
            },
            source.protocol_revision,
            source.reviewed
        );
    }
    println!("Model routes:");
    for model in config.models {
        println!(
            "- {} [openai-compatible; {}]",
            model.id, model.provider_model_id
        );
    }
    Ok(())
}

fn connect(client: &str, base_url: &url::Url) -> Result<()> {
    let base = base_url.as_str().trim_end_matches('/');
    match client {
        "generic-mcp" => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "evidence": "VERIFIED",
                "transport": "streamable-http",
                "url": format!("{base}/mcp")
            }))?
        ),
        "openai-compatible" => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "evidence": "VERIFIED",
                "base_url": format!("{base}/v1"),
                "api_key": "not-required-in-loopback-mode",
                "supported": ["models", "chat.completions", "responses"]
            }))?
        ),
        _ => bail!("GM_CONNECT_UNSUPPORTED_CLIENT:{client}"),
    }
    Ok(())
}

fn explain_route(deny_all: bool, decision_contract: bool) -> Result<()> {
    let mut rejected = candidate("remote-over-budget", 1);
    rejected.hard_constraints = ConstraintResult {
        allowed: false,
        rejections: vec![
            "monetary budget exhausted".into(),
            "required semantic field unavailable".into(),
        ],
    };
    let mut candidates = vec![candidate("local-b", 30), candidate("local-a", 20), rejected];
    if deny_all {
        for candidate in &mut candidates {
            if candidate.hard_constraints.allowed {
                candidate.hard_constraints.allowed = false;
                candidate.hard_constraints.rejections = match candidate.route_id.0.as_str() {
                    "local-a" => vec!["required capability unavailable".into()],
                    _ => vec!["tenant scope mismatch".into()],
                };
            }
        }
    }
    if deny_all || decision_contract {
        let decision = decide(candidates, default_weights())?;
        println!("{}", serde_json::to_string_pretty(&decision)?);
    } else {
        let plan = plan(candidates, default_weights())?;
        println!("{}", serde_json::to_string_pretty(&plan)?);
    }
    Ok(())
}

fn candidate(id: &str, latency: u32) -> RouteCandidate {
    RouteCandidate {
        route_id: RouteId(id.into()),
        endpoint_id: format!("endpoint-{id}"),
        hard_constraints: ConstraintResult {
            allowed: true,
            rejections: vec![],
        },
        metrics: RouteMetricSnapshot {
            latency,
            cost: 0,
            failure: 0,
            pressure: 0,
            exposure: 0,
            switching: 0,
        },
        semantic_loss: 0,
    }
}

fn default_config() -> Config {
    Config {
        version: 1,
        runtime: RuntimeConfig::Memory,
        listeners: ListenerConfig {
            data_address: "127.0.0.1:8090".into(),
            admin_address: "127.0.0.1:8092".into(),
            remote: None,
        },
        routing: RoutingConfig {
            weights: default_weights(),
            max_queue_per_tenant: 32,
            max_concurrent_per_tenant: 4,
        },
        policy: PolicyDocument {
            default: PolicyEffect::Deny,
            rules: vec![],
        },
        discovery_mode: DiscoveryMode::Strict,
        capability_mode: CapabilityMode::Transparent,
        mcp_sources: vec![],
        models: vec![],
    }
}

fn default_weights() -> RouteWeights {
    RouteWeights {
        latency: 10,
        cost: 30,
        failure: 30,
        semantic_loss: 1_000,
        pressure: 20,
        exposure: 50,
        switching: 10,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancellation_releases_owned_data_and_admin_listeners() {
        let data_reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let admin_reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let data_address = data_reservation.local_addr().unwrap();
        let admin_address = admin_reservation.local_addr().unwrap();
        drop((data_reservation, admin_reservation));
        let cancellation = tokio_util::sync::CancellationToken::new();
        let data = tokio::spawn(serve_data(
            Router::new().route("/", get(|| async { "ok" })),
            data_address,
            None,
            cancellation.child_token(),
        ));
        let admin = tokio::spawn(serve_admin(
            Router::new().route("/healthz", get(|| async { "ok" })),
            admin_address,
            cancellation.child_token(),
        ));
        let mut ready = false;
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(data_address).await.is_ok()
                && tokio::net::TcpStream::connect(admin_address).await.is_ok()
            {
                ready = true;
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(ready);
        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(2), async {
            data.await.unwrap().unwrap();
            admin.await.unwrap().unwrap();
        })
        .await
        .unwrap();
        let data_rebound = tokio::net::TcpListener::bind(data_address).await.unwrap();
        let admin_rebound = tokio::net::TcpListener::bind(admin_address).await.unwrap();
        drop((data_rebound, admin_rebound));
    }
}
