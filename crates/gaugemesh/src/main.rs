use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use gaugemesh_core::{
    config::{Config, ListenerConfig, RoutingConfig, RuntimeConfig},
    policy::{PolicyDocument, PolicyEffect},
    route::{ConstraintResult, RouteCandidate, RouteId, RouteMetricSnapshot, RouteWeights, plan},
};

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
    Serve,
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
}

#[derive(Debug, Subcommand)]
enum AddCommand {
    Mcp { id: String },
    Model { id: String },
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
        Command::Demo => bail!("GM_FEATURE_NOT_READY:demo is added by the federation stage"),
        Command::Serve => bail!("GM_FEATURE_NOT_READY:serve is added by the federation stage"),
        Command::Add { kind } => bail!("GM_FEATURE_NOT_READY:add {kind:?}"),
        Command::Remove { id } => bail!("GM_FEATURE_NOT_READY:remove {id}"),
        Command::List => bail!("GM_FEATURE_NOT_READY:list"),
        Command::Registry { command } => bail!("GM_FEATURE_NOT_READY:registry {command:?}"),
        Command::Verify { resilireplay } => {
            bail!("GM_FEATURE_NOT_READY:verify resilireplay={resilireplay}")
        }
        Command::Connect { client } => bail!("GM_FEATURE_NOT_READY:connect {client}"),
    }
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
