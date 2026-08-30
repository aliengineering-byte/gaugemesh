use std::{path::Path, time::Duration};

use anyhow::{Context, Result, bail};
use gaugemesh_core::protocol::McpRevision;
use rmcp::{
    ClientLifecycleMode, ClientServiceExt, Peer, RoleClient, ServiceExt,
    model::{ClientCapabilities, ClientInfo, Implementation, ProtocolVersion},
    transport::{StreamableHttpClientTransport, TokioChildProcess},
};
use serde::Serialize;

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
    let tools = peer
        .list_all_tools()
        .await
        .context("GM_MCP_UPSTREAM_TOOLS_LIST")?
        .into_iter()
        .map(|item| item.name.into_owned())
        .collect();
    let resources = peer
        .list_all_resources()
        .await
        .context("GM_MCP_UPSTREAM_RESOURCES_LIST")?
        .into_iter()
        .map(|item| item.uri)
        .collect();
    let resource_templates = peer
        .list_all_resource_templates()
        .await
        .context("GM_MCP_UPSTREAM_RESOURCE_TEMPLATES_LIST")?
        .into_iter()
        .map(|item| item.uri_template)
        .collect();
    let prompts = peer
        .list_all_prompts()
        .await
        .context("GM_MCP_UPSTREAM_PROMPTS_LIST")?
        .into_iter()
        .map(|item| item.name)
        .collect();
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

fn client_info(revision: McpRevision) -> ClientInfo {
    let protocol = match revision {
        McpRevision::V2025_11_25 => ProtocolVersion::V_2025_11_25,
        McpRevision::V2026_07_28 => ProtocolVersion::V_2026_07_28,
    };
    ClientInfo::new(
        ClientCapabilities::default(),
        Implementation::new("gaugemesh", env!("CARGO_PKG_VERSION")),
    )
    .with_protocol_version(protocol)
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
}
