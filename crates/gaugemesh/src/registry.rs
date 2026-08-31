use std::{
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use gaugemesh_core::{digest::Sha256Digest, security::ResolvedOrigin};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

use crate::RegistryCommand;

const OFFICIAL_REGISTRY: &str = "https://registry.modelcontextprotocol.io";
const API_VERSION: &str = "v0.1";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ApprovalRecord {
    version: u16,
    registry: String,
    registry_api: String,
    server_name: String,
    server_version: String,
    record_digest: Sha256Digest,
    transport: ApprovedTransport,
    approval_digest: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum ApprovedTransport {
    StreamableHttp { url: Url },
}

pub async fn execute(command: RegistryCommand) -> Result<()> {
    match command {
        RegistryCommand::Search { query, limit } => {
            let limit = limit.clamp(1, 100);
            let client = registry_client().await?;
            let mut url = Url::parse(&format!("{OFFICIAL_REGISTRY}/{API_VERSION}/servers"))?;
            url.query_pairs_mut()
                .append_pair("search", &query)
                .append_pair("version", "latest")
                .append_pair("limit", &limit.to_string());
            let value = get_json(&client, url).await?;
            println!("{}", serde_json::to_string_pretty(&value)?);
            Ok(())
        }
        RegistryCommand::Inspect { name, version } => {
            let value = inspect(&name, &version).await?;
            println!("{}", serde_json::to_string_pretty(&value)?);
            Ok(())
        }
        RegistryCommand::Approve {
            name,
            version,
            output,
        } => {
            let value = inspect(&name, &version).await?;
            let server = value.get("server").context("GM_REGISTRY_RECORD_SHAPE")?;
            let actual_name = server
                .get("name")
                .and_then(Value::as_str)
                .context("GM_REGISTRY_NAME_MISSING")?;
            let actual_version = server
                .get("version")
                .and_then(Value::as_str)
                .context("GM_REGISTRY_VERSION_MISSING")?;
            if actual_name != name {
                bail!("GM_REGISTRY_NAME_MISMATCH");
            }
            let remote = server
                .get("remotes")
                .and_then(Value::as_array)
                .and_then(|remotes| {
                    remotes.iter().find(|remote| {
                        remote.get("type").and_then(Value::as_str) == Some("streamable-http")
                    })
                })
                .context("GM_REGISTRY_NO_STREAMABLE_HTTP_REMOTE")?;
            let remote_url = Url::parse(
                remote
                    .get("url")
                    .and_then(Value::as_str)
                    .context("GM_REGISTRY_REMOTE_URL_MISSING")?,
            )?;
            if remote_url.scheme() != "https" {
                bail!("GM_REGISTRY_REMOTE_REQUIRES_HTTPS");
            }
            let record_digest = Sha256Digest::of_json(&value);
            let base = json!({
                "version": 1,
                "registry": OFFICIAL_REGISTRY,
                "registryApi": API_VERSION,
                "serverName": actual_name,
                "serverVersion": actual_version,
                "recordDigest": record_digest,
                "transport": {"type":"streamable-http","url":remote_url},
            });
            let approval = ApprovalRecord {
                version: 1,
                registry: OFFICIAL_REGISTRY.into(),
                registry_api: API_VERSION.into(),
                server_name: actual_name.into(),
                server_version: actual_version.into(),
                record_digest,
                transport: ApprovedTransport::StreamableHttp { url: remote_url },
                approval_digest: Sha256Digest::of_json(&base),
            };
            let output =
                output.unwrap_or_else(|| default_approval_path(actual_name, actual_version));
            if let Some(parent) = output.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)
                .with_context(|| format!("GM_REGISTRY_APPROVAL_CREATE:{}", output.display()))?;
            file.write_all(&serde_json::to_vec_pretty(&approval)?)?;
            file.sync_all()?;
            println!(
                "approved {} {} -> {}",
                actual_name,
                actual_version,
                output.display()
            );
            println!("approval digest: {}", approval.approval_digest);
            Ok(())
        }
    }
}

async fn inspect(name: &str, version: &str) -> Result<Value> {
    let client = registry_client().await?;
    let mut url = Url::parse(&format!("{OFFICIAL_REGISTRY}/{API_VERSION}/"))?;
    url.path_segments_mut()
        .map_err(|_| anyhow::anyhow!("GM_REGISTRY_URL"))?
        .extend(["servers", name, "versions", version]);
    get_json(&client, url).await
}

async fn registry_client() -> Result<reqwest::Client> {
    let url = Url::parse(OFFICIAL_REGISTRY)?;
    let origin = ResolvedOrigin::resolve(&url, false)
        .await
        .context("GM_REGISTRY_ORIGIN_RESOLUTION")?;
    let addresses = origin
        .addresses
        .iter()
        .map(|address| std::net::SocketAddr::new(*address, origin.port))
        .collect::<Vec<_>>();
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .resolve_to_addrs(&origin.host, &addresses)
        .user_agent(concat!("gaugemesh/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

async fn get_json(client: &reqwest::Client, url: Url) -> Result<Value> {
    if url.scheme() != "https" || url.host_str() != Some("registry.modelcontextprotocol.io") {
        bail!("GM_REGISTRY_ORIGIN_DENIED");
    }
    let response = client
        .get(url)
        .send()
        .await
        .context("GM_REGISTRY_REQUEST")?;
    if !response.status().is_success() {
        bail!("GM_REGISTRY_STATUS:{}", response.status().as_u16());
    }
    if response
        .content_length()
        .is_some_and(|length| length > 2 * 1024 * 1024)
    {
        bail!("GM_REGISTRY_RESPONSE_TOO_LARGE");
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("GM_REGISTRY_BODY")?;
        if bytes.len().saturating_add(chunk.len()) > 2 * 1024 * 1024 {
            bail!("GM_REGISTRY_RESPONSE_TOO_LARGE");
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).context("GM_REGISTRY_JSON")
}

fn default_approval_path(name: &str, version: &str) -> PathBuf {
    let safe = format!("{name}-{version}")
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    PathBuf::from(".gaugemesh")
        .join("approvals")
        .join(format!("{safe}.json"))
}

pub fn approved_streamable_http(path: &Path) -> Result<Url> {
    let contents = std::fs::read(path)
        .with_context(|| format!("GM_REGISTRY_APPROVAL_READ:{}", path.display()))?;
    let approval: ApprovalRecord = serde_json::from_slice(&contents)
        .with_context(|| format!("GM_REGISTRY_APPROVAL_PARSE:{}", path.display()))?;
    let base = json!({
        "version": approval.version,
        "registry": approval.registry,
        "registryApi": approval.registry_api,
        "serverName": approval.server_name,
        "serverVersion": approval.server_version,
        "recordDigest": approval.record_digest,
        "transport": approval.transport,
    });
    if Sha256Digest::of_json(&base) != approval.approval_digest {
        bail!("GM_REGISTRY_APPROVAL_TAMPERED");
    }
    match approval.transport {
        ApprovedTransport::StreamableHttp { url } if url.scheme() == "https" => Ok(url),
        _ => bail!("GM_REGISTRY_APPROVED_TRANSPORT_DENIED"),
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn approval_tampering_is_rejected() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("approval.json");
        let record = ApprovalRecord {
            version: 1,
            registry: OFFICIAL_REGISTRY.into(),
            registry_api: API_VERSION.into(),
            server_name: "example/server".into(),
            server_version: "1.0.0".into(),
            record_digest: Sha256Digest::of_bytes("record"),
            transport: ApprovedTransport::StreamableHttp {
                url: Url::parse("https://example.com/mcp").unwrap(),
            },
            approval_digest: Sha256Digest::of_bytes("wrong"),
        };
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(
            approved_streamable_http(&path)
                .unwrap_err()
                .to_string()
                .contains("GM_REGISTRY_APPROVAL_TAMPERED")
        );
    }

    #[test]
    fn approval_paths_cannot_escape_the_approval_directory() {
        let path = default_approval_path("../../server", "1/2");
        assert_eq!(path.parent().unwrap(), Path::new(".gaugemesh/approvals"));
    }
}
