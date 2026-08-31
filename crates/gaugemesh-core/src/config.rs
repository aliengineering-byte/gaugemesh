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
    pub discovery_mode: DiscoveryMode,
    #[serde(default)]
    pub capability_mode: CapabilityMode,
    #[serde(default)]
    pub mcp_sources: Vec<McpSourceConfig>,
    #[serde(default)]
    pub models: Vec<ModelConfig>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityMode {
    #[default]
    Transparent,
    Lease,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryMode {
    #[default]
    Strict,
    Degraded,
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
    pub resource: String,
    pub jwks_url: Url,
    pub required_scopes: Vec<String>,
    #[serde(default = "default_jwks_cache_ttl_seconds")]
    pub jwks_cache_ttl_seconds: u64,
    #[serde(default = "default_clock_skew_seconds")]
    pub clock_skew_seconds: u64,
    #[serde(default)]
    pub trusted_proxies: Vec<IpAddr>,
}

fn default_jwks_cache_ttl_seconds() -> u64 {
    300
}

fn default_clock_skew_seconds() -> u64 {
    30
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
    #[serde(default)]
    pub capability_snapshot_digest: Option<crate::digest::Sha256Digest>,
    pub sharing: SharingClass,
    pub reviewed: bool,
    #[serde(default)]
    pub approval: ApprovalConfig,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApprovalConfig {
    #[default]
    Deny,
    StaticPolicy {
        response: serde_json::Value,
    },
    LocalCli,
    SignedWebhook {
        url: Url,
        secret_env: String,
        #[serde(default = "default_approval_timeout_ms")]
        timeout_ms: u64,
    },
}

fn default_approval_timeout_ms() -> u64 {
    5_000
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
    #[error("GM_CONFIG_INVALID_ID:{0}")]
    InvalidId(String),
    #[error("GM_CONFIG_INVALID_LIMIT:{0}")]
    InvalidLimit(String),
    #[error("GM_CONFIG_LISTENER_COLLISION")]
    ListenerCollision,
    #[error("GM_CONFIG_REMOTE_INVALID:{0}")]
    InvalidRemote(String),
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
        if self.listeners.data_address == self.listeners.admin_address {
            return Err(ConfigError::ListenerCollision);
        }
        if self.listeners.remote.is_none() && (!data_ip.is_loopback() || !admin_ip.is_loopback()) {
            return Err(ConfigError::UnauthenticatedNonLoopback);
        }
        if !admin_ip.is_loopback() {
            return Err(ConfigError::UnauthenticatedNonLoopback);
        }
        if self.listeners.remote.is_some() && self.policy.default != policy::PolicyEffect::Deny {
            return Err(ConfigError::RemoteDefaultAllow);
        }
        if let Some(remote) = &self.listeners.remote {
            validate_remote(remote)?;
            if self.mcp_sources.iter().any(|source| {
                !matches!(
                    source.sharing,
                    SharingClass::ShareableStateless | SharingClass::ShareableWithSerialization
                )
            }) {
                return Err(ConfigError::InvalidRemote("mcp_sharing".into()));
            }
        }
        policy::compile(self.policy.clone())?;
        if self.mcp_sources.len() > 64 || self.models.len() > 64 {
            return Err(ConfigError::InvalidLimit("routes".into()));
        }
        if self.routing.max_queue_per_tenant == 0
            || self.routing.max_concurrent_per_tenant == 0
            || self.routing.max_concurrent_per_tenant > self.routing.max_queue_per_tenant
        {
            return Err(ConfigError::InvalidLimit("routing".into()));
        }
        let mut ids = std::collections::BTreeSet::new();
        for source in &self.mcp_sources {
            validate_id(&source.id)?;
            if !ids.insert(source.id.clone()) {
                return Err(ConfigError::DuplicateId(source.id.clone()));
            }
            if !source.reviewed {
                return Err(ConfigError::UnreviewedSource(source.id.clone()));
            }
            validate_approval(&source.approval, &source.id)?;
            crate::protocol::McpRevision::parse(&source.protocol_revision)
                .map_err(|_| ConfigError::Version)?;
            if let McpTransportConfig::StreamableHttp { url } = &source.transport {
                validate_remote_url(url, self.listeners.remote.is_none())?;
            } else if let McpTransportConfig::Stdio { command, args } = &source.transport {
                if !command.is_absolute()
                    || args.len() > 128
                    || args.iter().any(|argument| argument.len() > 8_192)
                {
                    return Err(ConfigError::InvalidLimit(source.id.clone()));
                }
            }
        }
        for model in &self.models {
            validate_id(&model.id)?;
            if !ids.insert(model.id.clone()) {
                return Err(ConfigError::DuplicateId(model.id.clone()));
            }
            validate_remote_url(&model.base_url, self.listeners.remote.is_none())?;
            if model.context_limit == 0
                || model.max_output_tokens == 0
                || model.max_output_tokens > model.context_limit
                || model.cost_table.version.is_empty()
                || model.cost_table.version.len() > 128
                || model.credential_env.as_ref().is_some_and(|name| {
                    name.is_empty()
                        || name.len() > 128
                        || !name
                            .chars()
                            .all(|character| character.is_ascii_alphanumeric() || character == '_')
                })
            {
                return Err(ConfigError::InvalidLimit(model.id.clone()));
            }
        }
        Ok(())
    }
}

fn validate_approval(approval: &ApprovalConfig, source: &str) -> Result<(), ConfigError> {
    match approval {
        ApprovalConfig::Deny | ApprovalConfig::LocalCli => Ok(()),
        ApprovalConfig::StaticPolicy { response } => {
            if !response.is_object()
                || serde_json::to_vec(response).map_or(true, |value| value.len() > 16 * 1024)
            {
                Err(ConfigError::InvalidLimit(format!("approval:{source}")))
            } else {
                Ok(())
            }
        }
        ApprovalConfig::SignedWebhook {
            url,
            secret_env,
            timeout_ms,
        } => {
            validate_remote_url(url, false)?;
            if url.scheme() != "https"
                || !(100..=10_000).contains(timeout_ms)
                || secret_env.is_empty()
                || secret_env.len() > 128
                || !secret_env
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '_')
            {
                Err(ConfigError::InvalidLimit(format!("approval:{source}")))
            } else {
                Ok(())
            }
        }
    }
}

fn validate_remote(remote: &RemoteConfig) -> Result<(), ConfigError> {
    if !remote.tls_certificate.is_absolute() || !remote.tls_private_key.is_absolute() {
        return Err(ConfigError::InvalidRemote("tls_path".into()));
    }
    validate_origin(&remote.public_origin, true, "public_origin")?;
    validate_origin(&remote.issuer, false, "issuer")?;
    validate_remote_url(&remote.jwks_url, false)?;
    if remote.jwks_url.scheme() != "https" {
        return Err(ConfigError::InvalidRemote("jwks_https".into()));
    }
    if remote.audience.is_empty()
        || remote.audience.len() > 256
        || remote.resource.is_empty()
        || remote.resource.len() > 512
        || remote.required_scopes.is_empty()
        || remote.required_scopes.len() > 32
        || remote.required_scopes.iter().any(|scope| {
            scope.is_empty()
                || scope.len() > 128
                || !scope.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, ':' | '.' | '_' | '-')
                })
        })
        || !(30..=86_400).contains(&remote.jwks_cache_ttl_seconds)
        || remote.clock_skew_seconds > 300
    {
        return Err(ConfigError::InvalidRemote("oidc_binding".into()));
    }
    if remote.trusted_proxies.iter().any(|address| {
        address.is_unspecified() || address.is_multicast() || is_link_local(*address)
    }) {
        return Err(ConfigError::InvalidRemote("trusted_proxy".into()));
    }
    Ok(())
}

fn validate_origin(url: &Url, root_only: bool, field: &str) -> Result<(), ConfigError> {
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
        || (root_only && url.path() != "/")
    {
        return Err(ConfigError::InvalidRemote(field.into()));
    }
    Ok(())
}

fn validate_id(id: &str) -> Result<(), ConfigError> {
    if id.is_empty()
        || id.len() > 64
        || !id.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
    {
        Err(ConfigError::InvalidId(id.into()))
    } else {
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
    if !matches!(url.scheme(), "http" | "https") {
        return Err(ConfigError::UnsafeUrl(url.to_string()));
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(ConfigError::UnsafeUrl(url.to_string()));
    }
    let host = url
        .host_str()
        .ok_or_else(|| ConfigError::UnsafeUrl(url.to_string()))?;
    if url.scheme() == "http"
        && (!allow_loopback
            || !(host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())))
    {
        return Err(ConfigError::UnsafeUrl(url.to_string()));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        let forbidden = ip.is_unspecified()
            || ip.is_multicast()
            || (!allow_loopback && ip.is_loopback())
            || is_link_local(ip)
            || (is_private(ip) && !ip.is_loopback());
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

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    fn fixture() -> Config {
        serde_yaml::from_str(include_str!("../../../examples/local-demo/gaugemesh.yaml")).unwrap()
    }

    #[test]
    fn checked_in_schema_matches_the_typed_configuration() {
        let expected: Value = serde_json::from_str(include_str!(
            "../../../schemas/gaugemesh-config-v1.schema.json"
        ))
        .unwrap();
        let actual = serde_json::to_value(schemars::schema_for!(Config)).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn unknown_fields_and_unauthenticated_remote_listeners_fail_closed() {
        let yaml = include_str!("../../../examples/local-demo/gaugemesh.yaml");
        assert!(serde_yaml::from_str::<Config>(&format!("{yaml}unknown: true\n")).is_err());

        let mut config = fixture();
        config.listeners.data_address = "0.0.0.0:8090".into();
        assert_eq!(
            config.validate().unwrap_err(),
            ConfigError::UnauthenticatedNonLoopback
        );
    }

    #[test]
    fn remote_mode_requires_tls_oidc_scopes_and_loopback_admin() {
        let mut config = fixture();
        config.listeners.data_address = "0.0.0.0:8090".into();
        config.listeners.remote = Some(RemoteConfig {
            tls_certificate: std::env::temp_dir().join("gaugemesh-cert.pem"),
            tls_private_key: std::env::temp_dir().join("gaugemesh-key.pem"),
            public_origin: Url::parse("https://mesh.example/").unwrap(),
            issuer: Url::parse("https://issuer.example/").unwrap(),
            audience: "gaugemesh".into(),
            resource: "https://mesh.example/".into(),
            jwks_url: Url::parse("https://issuer.example/.well-known/jwks.json").unwrap(),
            required_scopes: vec!["gaugemesh:invoke".into()],
            jwks_cache_ttl_seconds: 300,
            clock_skew_seconds: 30,
            trusted_proxies: Vec::new(),
        });
        assert!(config.validate().is_ok());

        config.listeners.admin_address = "0.0.0.0:8092".into();
        assert_eq!(
            config.validate().unwrap_err(),
            ConfigError::UnauthenticatedNonLoopback
        );
        config.listeners.admin_address = "127.0.0.1:8092".into();
        config
            .listeners
            .remote
            .as_mut()
            .unwrap()
            .required_scopes
            .clear();
        assert_eq!(
            config.validate().unwrap_err(),
            ConfigError::InvalidRemote("oidc_binding".into())
        );
        config.listeners.remote.as_mut().unwrap().required_scopes = vec!["gaugemesh:invoke".into()];
        config.mcp_sources.push(McpSourceConfig {
            id: "stateful".into(),
            transport: McpTransportConfig::Stdio {
                command: std::env::temp_dir().join("stateful-server"),
                args: Vec::new(),
            },
            protocol_revision: "2026-07-28".into(),
            capability_snapshot_digest: None,
            sharing: SharingClass::NonShareable,
            reviewed: true,
            approval: ApprovalConfig::Deny,
        });
        assert_eq!(
            config.validate().unwrap_err(),
            ConfigError::InvalidRemote("mcp_sharing".into())
        );
    }

    #[test]
    fn duplicate_ids_and_unreviewed_sources_are_rejected() {
        let mut config = fixture();
        config.mcp_sources.push(McpSourceConfig {
            id: "duplicate".into(),
            transport: McpTransportConfig::Stdio {
                command: PathBuf::from("/reviewed/server"),
                args: vec![],
            },
            protocol_revision: "2025-11-25".into(),
            capability_snapshot_digest: None,
            sharing: SharingClass::NonShareable,
            reviewed: false,
            approval: ApprovalConfig::Deny,
        });
        assert_eq!(
            config.validate().unwrap_err(),
            ConfigError::UnreviewedSource("duplicate".into())
        );
        config.mcp_sources[0].reviewed = true;
        config.models.push(ModelConfig {
            id: "duplicate".into(),
            base_url: Url::parse("http://127.0.0.1:11434/v1/").unwrap(),
            provider_model_id: "fixture".into(),
            context_limit: 4096,
            max_output_tokens: 256,
            cost_table: ModelCostConfig {
                version: "fixture".into(),
                input_micros_per_million_tokens: 0,
                output_micros_per_million_tokens: 0,
            },
            credential_env: None,
        });
        assert_eq!(
            config.validate().unwrap_err(),
            ConfigError::DuplicateId("duplicate".into())
        );
    }
}
