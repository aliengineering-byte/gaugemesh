use std::{net::IpAddr, path::PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::{policy, route::RouteWeights};

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u16,
    pub runtime: RuntimeConfig,
    pub listeners: ListenerConfig,
    pub routing: RoutingConfig,
    pub policy: policy::PolicyDocument,
    #[serde(default)]
    pub mcp_sources: Vec<McpSourceConfig>,
    #[serde(default)]
    pub models: Vec<ModelConfig>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeConfig {
    Memory,
    Sqlite { database: PathBuf },
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    pub data_address: String,
    pub admin_address: String,
    #[serde(default)]
    pub remote: Option<RemoteConfig>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteConfig {
    pub tls_certificate: PathBuf,
    pub tls_private_key: PathBuf,
    pub public_origin: Url,
    pub issuer: Url,
    pub audience: String,
    #[serde(default)]
    pub trusted_proxies: Vec<IpAddr>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingConfig {
    pub weights: RouteWeights,
    pub max_queue_per_tenant: u16,
    pub max_concurrent_per_tenant: u16,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpSourceConfig {
    pub id: String,
    pub transport: McpTransportConfig,
    pub protocol_revision: String,
    pub sharing: SharingClass,
    pub reviewed: bool,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum McpTransportConfig {
    Stdio { command: PathBuf, args: Vec<String> },
    StreamableHttp { url: Url },
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SharingClass {
    ShareableStateless,
    ShareableWithSerialization,
    PrincipalIsolated,
    TenantIsolated,
    NonShareable,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelConfig {
    pub id: String,
    pub base_url: Url,
    pub provider_model_id: String,
    pub context_limit: u64,
    pub max_output_tokens: u64,
    pub cost_table: ModelCostConfig,
    #[serde(default)]
    pub credential_env: Option<String>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCostConfig {
    pub version: String,
    pub input_micros_per_million_tokens: u64,
    pub output_micros_per_million_tokens: u64,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConfigError {
    #[error("GM_CONFIG_VERSION_UNSUPPORTED")]
    Version,
    #[error("GM_CONFIG_UNAUTHENTICATED_NON_LOOPBACK")]
    UnauthenticatedNonLoopback,
    #[error("GM_CONFIG_REMOTE_REQUIRES_DEFAULT_DENY")]
    RemoteDefaultAllow,
    #[error("GM_CONFIG_DUPLICATE_ID:{0}")]
    DuplicateId(String),
    #[error("GM_CONFIG_UNREVIEWED_SOURCE:{0}")]
    UnreviewedSource(String),
    #[error("GM_CONFIG_UNSAFE_URL:{0}")]
    UnsafeUrl(String),
    #[error(transparent)]
    Policy(#[from] policy::PolicyCompileError),
}

impl Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version != 1 {
            return Err(ConfigError::Version);
        }
        let data_ip = address_ip(&self.listeners.data_address)?;
        let admin_ip = address_ip(&self.listeners.admin_address)?;
        if self.listeners.remote.is_none() && (!data_ip.is_loopback() || !admin_ip.is_loopback()) {
            return Err(ConfigError::UnauthenticatedNonLoopback);
        }
        if self.listeners.remote.is_some() && self.policy.default != policy::PolicyEffect::Deny {
            return Err(ConfigError::RemoteDefaultAllow);
        }
        policy::compile(self.policy.clone())?;
        let mut ids = std::collections::BTreeSet::new();
        for source in &self.mcp_sources {
            if !ids.insert(source.id.clone()) {
                return Err(ConfigError::DuplicateId(source.id.clone()));
            }
            if !source.reviewed {
                return Err(ConfigError::UnreviewedSource(source.id.clone()));
            }
            crate::protocol::McpRevision::parse(&source.protocol_revision)
                .map_err(|_| ConfigError::Version)?;
            if let McpTransportConfig::StreamableHttp { url } = &source.transport {
                validate_remote_url(url, self.listeners.remote.is_none())?;
            }
        }
        for model in &self.models {
            if !ids.insert(model.id.clone()) {
                return Err(ConfigError::DuplicateId(model.id.clone()));
            }
            validate_remote_url(&model.base_url, self.listeners.remote.is_none())?;
        }
        Ok(())
    }
}

fn address_ip(address: &str) -> Result<IpAddr, ConfigError> {
    address
        .parse::<std::net::SocketAddr>()
        .map(|address| address.ip())
        .map_err(|_| ConfigError::UnsafeUrl(address.into()))
}

pub fn validate_remote_url(url: &Url, allow_loopback: bool) -> Result<(), ConfigError> {
    if url.scheme() != "https" && !(allow_loopback && url.scheme() == "http") {
        return Err(ConfigError::UnsafeUrl(url.to_string()));
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(ConfigError::UnsafeUrl(url.to_string()));
    }
    let host = url
        .host_str()
        .ok_or_else(|| ConfigError::UnsafeUrl(url.to_string()))?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        let forbidden = ip.is_unspecified()
            || ip.is_multicast()
            || (!allow_loopback && ip.is_loopback())
            || is_link_local(ip)
            || (!allow_loopback && is_private(ip));
        if forbidden {
            return Err(ConfigError::UnsafeUrl(url.to_string()));
        }
    }
    if host.eq_ignore_ascii_case("metadata.google.internal")
        || host.eq_ignore_ascii_case("instance-data.ec2.internal")
    {
        return Err(ConfigError::UnsafeUrl(url.to_string()));
    }
    Ok(())
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.octets() == [169, 254, 169, 254],
        IpAddr::V6(ip) => (ip.segments()[0] & 0xfe00) == 0xfc00,
    }
}

fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_link_local(),
        IpAddr::V6(ip) => (ip.segments()[0] & 0xffc0) == 0xfe80,
    }
}
