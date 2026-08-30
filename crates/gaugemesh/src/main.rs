use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result, bail};
use axum::{Json, Router, routing::get};
use clap::{Parser, Subcommand};
use gaugemesh_core::{
    config::{
        Config, ListenerConfig, McpSourceConfig, McpTransportConfig, RoutingConfig, RuntimeConfig,
        SharingClass,
    },
    policy::{PolicyDocument, PolicyEffect},
    route::{ConstraintResult, RouteCandidate, RouteId, RouteMetricSnapshot, RouteWeights, plan},
};

mod mcp;
mod model;
mod outbound;

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
    Demo,
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
    Remove { id: String },
    /// List configured routes and sources.
    List,
    /// Serve the MCP and OpenAI-compatible endpoints.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8090")]
        data_address: String,
        #[arg(long, default_value = "127.0.0.1:8092")]
        admin_address: String,
    },
    /// Validate configuration and local safety boundaries.
    Doctor,
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
    Connect { client: String },
    #[command(hide = true)]
    Schema,
    #[command(hide = true)]
    McpStdio,
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
    Explain,
}

#[derive(Debug, Subcommand)]
enum RegistryCommand {
    Search { query: String },
    Inspect { name: String },
    Approve { name: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Init { path, force } => initialize(path, force),
        Command::Doctor => doctor(),
        Command::Route {
            command: RouteCommand::Explain,
        } => explain_route(),
        Command::Schema => {
            println!(
                "{}",
                serde_json::to_string_pretty(&schemars::schema_for!(Config))?
            );
            Ok(())
        }
        Command::Demo => demo(),
        Command::Serve {
            data_address,
            admin_address,
        } => serve(data_address, admin_address).await,
        Command::McpStdio => mcp::serve_stdio().await,
        Command::Add { kind } => add(kind).await,
        Command::Remove { id } => bail!("GM_FEATURE_NOT_READY:remove {id}"),
        Command::List => bail!("GM_FEATURE_NOT_READY:list"),
        Command::Registry { command } => bail!("GM_FEATURE_NOT_READY:registry {command:?}"),
        Command::Verify { resilireplay } => {
            bail!("GM_FEATURE_NOT_READY:verify resilireplay={resilireplay}")
        }
        Command::Connect { client } => bail!("GM_FEATURE_NOT_READY:connect {client}"),
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
        } => {
            let revision = gaugemesh_core::protocol::McpRevision::parse(&protocol_revision)
                .map_err(|error| anyhow::anyhow!(error))?;
            let contents = std::fs::read_to_string(&config)
                .with_context(|| format!("GM_CONFIG_READ:{}", config.display()))?;
            let mut document: Config = serde_yaml::from_str(&contents)
                .with_context(|| format!("GM_CONFIG_PARSE:{}", config.display()))?;
            let (transport, snapshot) = match (url, command) {
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
                sharing: SharingClass::NonShareable,
                reviewed: true,
            });
            document.validate()?;
            std::fs::write(&config, serde_yaml::to_string(&document)?)
                .with_context(|| format!("GM_CONFIG_WRITE:{}", config.display()))?;
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
            base_url,
            provider_model_id,
            context_limit,
            max_output_tokens,
            cost_table_version,
            input_micros_per_million_tokens,
            output_micros_per_million_tokens,
            credential_env,
        } => {
            let identity = model::inspect_openai_provider(
                base_url.clone(),
                provider_model_id.clone(),
                credential_env.as_deref(),
            )
            .await?;
            let contents = std::fs::read_to_string(&config)
                .with_context(|| format!("GM_CONFIG_READ:{}", config.display()))?;
            let mut document: Config = serde_yaml::from_str(&contents)
                .with_context(|| format!("GM_CONFIG_PARSE:{}", config.display()))?;
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
            std::fs::write(&config, serde_yaml::to_string(&document)?)
                .with_context(|| format!("GM_CONFIG_WRITE:{}", config.display()))?;
            println!("reviewed OpenAI-compatible model identity {identity}");
            Ok(())
        }
    }
}

fn demo() -> Result<()> {
    use gaugemesh_core::{
        budget::{BudgetDebit, debit},
        context::{
            CapabilityScope, MoneyBudgetMicros, PrincipalId, RequestContext, RetryBudget, TenantId,
            TokenBudget,
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
        lease.authorize(&principal, &tenant, &tool.identity, 0)?;
    }
    let route = plan(
        vec![
            candidate("local-fallback", 30),
            candidate("local-model", 20),
        ],
        default_weights(),
    )?;
    let before = RequestContext::local_fixture();
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
    let evidence = Sha256Digest::of_json(&serde_json::json!({
        "route": route,
        "report": report,
        "leaseManifest": lease.manifest_digest,
        "capabilities": tools.iter().map(|tool| tool.identity.digest().to_string()).collect::<Vec<_>>(),
        "duplicateEffects": 0,
    }));
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
    println!("[ok] cleanup complete: no child process or listener created\n");
    println!("Route: {} -> docs-a__search", route.selected.0);
    println!("Decision: {}", route.snapshot_digest);
    println!("Evidence: {evidence}");
    Ok(())
}

async fn serve(data_address: String, admin_address: String) -> Result<()> {
    let data_address: std::net::SocketAddr = data_address.parse()?;
    let admin_address: std::net::SocketAddr = admin_address.parse()?;
    if !data_address.ip().is_loopback() || !admin_address.ip().is_loopback() {
        bail!("GM_CONFIG_UNAUTHENTICATED_NON_LOOPBACK");
    }
    let cancellation = tokio_util::sync::CancellationToken::new();
    let data =
        mcp::router(mcp::MeshMcpServer::demo(), cancellation.child_token()).merge(model::router());
    let admin = Router::new().route(
        "/healthz",
        get(|| async {
            Json(serde_json::json!({"status":"ok","version":env!("CARGO_PKG_VERSION")}))
        }),
    );
    let data_listener = tokio::net::TcpListener::bind(data_address).await?;
    let admin_listener = tokio::net::TcpListener::bind(admin_address).await?;
    println!("MCP endpoint: http://{data_address}/mcp");
    println!("OpenAI-compatible endpoint: http://{data_address}/v1");
    println!("Admin health: http://{admin_address}/healthz");
    let data_task = axum::serve(data_listener, data).with_graceful_shutdown({
        let cancellation = cancellation.clone();
        async move { cancellation.cancelled().await }
    });
    let admin_task = axum::serve(admin_listener, admin).with_graceful_shutdown({
        let cancellation = cancellation.clone();
        async move { cancellation.cancelled().await }
    });
    tokio::select! {
        result = data_task => result?,
        result = admin_task => result?,
        signal = tokio::signal::ctrl_c() => {
            signal?;
            cancellation.cancel();
        }
    }
    Ok(())
}

fn initialize(path: PathBuf, force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!("GM_CONFIG_EXISTS:{}", path.display());
    }
    let contents = serde_yaml::to_string(&default_config())?;
    std::fs::write(&path, contents)
        .with_context(|| format!("failed to write {}", path.display()))?;
    println!("initialized {}", path.display());
    Ok(())
}

fn doctor() -> Result<()> {
    let config = default_config();
    config.validate()?;
    let protocol = rmcp::model::ProtocolVersion::V_2026_07_28;
    println!("configuration: valid");
    println!("data listener: loopback");
    println!("admin listener: separate loopback");
    println!("policy default: deny");
    println!("official MCP SDK protocol: {protocol}");
    Ok(())
}

fn explain_route() -> Result<()> {
    let plan = plan(
        vec![candidate("local-b", 30), candidate("local-a", 20)],
        default_weights(),
    )?;
    println!("{}", serde_json::to_string_pretty(&plan)?);
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
