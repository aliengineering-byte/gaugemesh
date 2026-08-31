use std::{collections::BTreeMap, net::IpAddr};

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::context::TenantId;

pub struct IssuedApiKey {
    pub plaintext: String,
    pub record: StoredApiKey,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredApiKey {
    pub id: String,
    pub tenant: TenantId,
    pub scopes: Vec<String>,
    pub password_hash: String,
    pub revoked: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ApiKeyStore {
    records: BTreeMap<String, StoredApiKey>,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AuthError {
    #[error("GM_AUTH_API_KEY_INVALID")]
    ApiKeyInvalid,
    #[error("GM_AUTH_API_KEY_REVOKED")]
    ApiKeyRevoked,
    #[error("GM_AUTH_TENANT_MISMATCH")]
    TenantMismatch,
    #[error("GM_AUTH_SCOPE_DENIED")]
    ScopeDenied,
    #[error("GM_AUTH_TOKEN_HEADER")]
    TokenHeader,
    #[error("GM_AUTH_TOKEN_ALGORITHM")]
    TokenAlgorithm,
    #[error("GM_AUTH_TOKEN_KEY")]
    TokenKey,
    #[error("GM_AUTH_TOKEN_SIGNATURE")]
    TokenSignature,
    #[error("GM_AUTH_TOKEN_ISSUER")]
    TokenIssuer,
    #[error("GM_AUTH_TOKEN_AUDIENCE")]
    TokenAudience,
    #[error("GM_AUTH_TOKEN_RESOURCE")]
    TokenResource,
    #[error("GM_AUTH_TOKEN_EXPIRED")]
    TokenExpired,
    #[error("GM_AUTH_TOKEN_NOT_YET_VALID")]
    TokenNotYetValid,
}

impl ApiKeyStore {
    pub fn issue(
        &mut self,
        tenant: TenantId,
        mut scopes: Vec<String>,
    ) -> Result<IssuedApiKey, AuthError> {
        scopes.sort();
        scopes.dedup();
        let random: [u8; 32] = rand::random();
        let id = Uuid::new_v4().to_string();
        let plaintext = format!("gm_live_{id}_{}", URL_SAFE_NO_PAD.encode(random));
        let password_hash = Argon2::default()
            .hash_password(plaintext.as_bytes())
            .map_err(|_| AuthError::ApiKeyInvalid)?
            .to_string();
        let record = StoredApiKey {
            id,
            tenant,
            scopes,
            password_hash,
            revoked: false,
        };
        self.records.insert(record.id.clone(), record.clone());
        Ok(IssuedApiKey { plaintext, record })
    }

    pub fn verify(
        &self,
        id: &str,
        plaintext: &str,
        tenant: &TenantId,
        required_scope: &str,
    ) -> Result<&StoredApiKey, AuthError> {
        let record = self.records.get(id).ok_or(AuthError::ApiKeyInvalid)?;
        if record.revoked {
            return Err(AuthError::ApiKeyRevoked);
        }
        if &record.tenant != tenant {
            return Err(AuthError::TenantMismatch);
        }
        if !record.scopes.iter().any(|scope| scope == required_scope) {
            return Err(AuthError::ScopeDenied);
        }
        let hash =
            PasswordHash::new(&record.password_hash).map_err(|_| AuthError::ApiKeyInvalid)?;
        Argon2::default()
            .verify_password(plaintext.as_bytes(), &hash)
            .map_err(|_| AuthError::ApiKeyInvalid)?;
        Ok(record)
    }

    pub fn revoke(&mut self, id: &str) -> Result<(), AuthError> {
        self.records
            .get_mut(id)
            .ok_or(AuthError::ApiKeyInvalid)?
            .revoked = true;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OidcClaims {
    pub sub: String,
    pub iss: String,
    pub aud: Audience,
    pub exp: u64,
    #[serde(default)]
    pub nbf: Option<u64>,
    pub resource: String,
    pub tenant: String,
    #[serde(default)]
    pub scope: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.iter().any(|value| value == expected),
        }
    }
}

#[derive(Clone, Debug)]
pub struct OidcBinding {
    pub issuer: String,
    pub audience: String,
    pub resource: String,
    pub clock_skew_seconds: u64,
}

pub fn verify_oidc_token(
    token: &str,
    keys: &JwkSet,
    binding: &OidcBinding,
    now_unix_seconds: u64,
) -> Result<OidcClaims, AuthError> {
    let header = decode_header(token).map_err(|_| AuthError::TokenHeader)?;
    if !matches!(
        header.alg,
        Algorithm::RS256 | Algorithm::PS256 | Algorithm::ES256 | Algorithm::EdDSA
    ) {
        return Err(AuthError::TokenAlgorithm);
    }
    let key_id = header.kid.as_deref().ok_or(AuthError::TokenKey)?;
    let jwk = keys.find(key_id).ok_or(AuthError::TokenKey)?;
    let key = DecodingKey::from_jwk(jwk).map_err(|_| AuthError::TokenKey)?;
    let mut validation = Validation::new(header.alg);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    let claims = decode::<OidcClaims>(token, &key, &validation)
        .map_err(|_| AuthError::TokenSignature)?
        .claims;
    validate_claims(&claims, binding, now_unix_seconds)?;
    Ok(claims)
}

pub fn validate_claims(
    claims: &OidcClaims,
    binding: &OidcBinding,
    now_unix_seconds: u64,
) -> Result<(), AuthError> {
    if claims.iss != binding.issuer {
        return Err(AuthError::TokenIssuer);
    }
    if !claims.aud.contains(&binding.audience) {
        return Err(AuthError::TokenAudience);
    }
    if claims.resource != binding.resource {
        return Err(AuthError::TokenResource);
    }
    if claims.exp.saturating_add(binding.clock_skew_seconds) < now_unix_seconds {
        return Err(AuthError::TokenExpired);
    }
    if claims.nbf.unwrap_or(0) > now_unix_seconds.saturating_add(binding.clock_skew_seconds) {
        return Err(AuthError::TokenNotYetValid);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedOrigin {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub addresses: Vec<IpAddr>,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum OriginError {
    #[error("GM_ORIGIN_SCHEME_DENIED")]
    Scheme,
    #[error("GM_ORIGIN_CREDENTIALS_DENIED")]
    Credentials,
    #[error("GM_ORIGIN_HOST_REQUIRED")]
    Host,
    #[error("GM_ORIGIN_ADDRESS_DENIED:{0}")]
    Address(IpAddr),
    #[error("GM_ORIGIN_DNS_EMPTY")]
    DnsEmpty,
    #[error("GM_ORIGIN_DNS_REBIND")]
    DnsRebind,
    #[error("GM_ORIGIN_REDIRECT_DENIED")]
    Redirect,
}

impl ResolvedOrigin {
    pub async fn resolve(url: &Url, allow_private: bool) -> Result<Self, OriginError> {
        if !matches!(url.scheme(), "http" | "https") {
            return Err(OriginError::Scheme);
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(OriginError::Credentials);
        }
        let host = url.host_str().ok_or(OriginError::Host)?.to_owned();
        let port = url.port_or_known_default().ok_or(OriginError::Host)?;
        let mut addresses = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|_| OriginError::DnsEmpty)?
            .map(|address| address.ip())
            .collect::<Vec<_>>();
        addresses.sort();
        addresses.dedup();
        if addresses.is_empty() {
            return Err(OriginError::DnsEmpty);
        }
        for address in &addresses {
            if address_denied(*address, allow_private) {
                return Err(OriginError::Address(*address));
            }
        }
        Ok(Self {
            scheme: url.scheme().into(),
            host,
            port,
            addresses,
        })
    }

    pub fn validate_connected_peer(&self, address: IpAddr) -> Result<(), OriginError> {
        if self.addresses.contains(&address) {
            Ok(())
        } else {
            Err(OriginError::DnsRebind)
        }
    }

    pub fn validate_redirect(&self, target: &Url) -> Result<(), OriginError> {
        if target.scheme() == self.scheme
            && target.host_str() == Some(&self.host)
            && target.port_or_known_default() == Some(self.port)
        {
            Ok(())
        } else {
            Err(OriginError::Redirect)
        }
    }
}

fn address_denied(address: IpAddr, allow_private: bool) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_unspecified()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_multicast()
                || (!allow_private && address.is_private())
        }
        IpAddr::V6(address) => {
            address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || (address.segments()[0] & 0xffc0) == 0xfe80
                || (!allow_private && (address.segments()[0] & 0xfe00) == 0xfc00)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_keys_are_slow_hashed_tenant_bound_scope_bound_and_revocable() {
        let mut store = ApiKeyStore::default();
        let issued = store
            .issue(TenantId("tenant-a".into()), vec!["mcp:read".into()])
            .unwrap();
        assert!(!issued.record.password_hash.contains(&issued.plaintext));
        assert!(
            store
                .verify(
                    &issued.record.id,
                    &issued.plaintext,
                    &TenantId("tenant-a".into()),
                    "mcp:read",
                )
                .is_ok()
        );
        assert_eq!(
            store.verify(
                &issued.record.id,
                &issued.plaintext,
                &TenantId("tenant-b".into()),
                "mcp:read",
            ),
            Err(AuthError::TenantMismatch)
        );
        store.revoke(&issued.record.id).unwrap();
        assert_eq!(
            store.verify(
                &issued.record.id,
                &issued.plaintext,
                &TenantId("tenant-a".into()),
                "mcp:read",
            ),
            Err(AuthError::ApiKeyRevoked)
        );
    }

    #[test]
    fn issuer_audience_resource_expiry_and_not_before_are_exact() {
        let binding = OidcBinding {
            issuer: "https://issuer.example".into(),
            audience: "gaugemesh".into(),
            resource: "https://mesh.example".into(),
            clock_skew_seconds: 0,
        };
        let mut claims = OidcClaims {
            sub: "alice".into(),
            iss: binding.issuer.clone(),
            aud: Audience::One(binding.audience.clone()),
            exp: 101,
            nbf: Some(99),
            resource: binding.resource.clone(),
            tenant: "tenant-a".into(),
            scope: "mcp:read".into(),
        };
        assert!(validate_claims(&claims, &binding, 100).is_ok());
        claims.exp = 99;
        assert_eq!(
            validate_claims(&claims, &binding, 100),
            Err(AuthError::TokenExpired)
        );
        claims.exp = 101;
        claims.nbf = Some(102);
        assert_eq!(
            validate_claims(&claims, &binding, 100),
            Err(AuthError::TokenNotYetValid)
        );
        claims.nbf = Some(99);
        claims.iss = "https://evil.example/".into();
        assert_eq!(
            validate_claims(&claims, &binding, 100),
            Err(AuthError::TokenIssuer)
        );
        claims.iss = binding.issuer.clone();
        claims.aud = Audience::One("another-audience".into());
        assert_eq!(
            validate_claims(&claims, &binding, 100),
            Err(AuthError::TokenAudience)
        );
        claims.aud = Audience::One(binding.audience.clone());
        claims.resource = "https://another-resource.example/".into();
        assert_eq!(
            validate_claims(&claims, &binding, 100),
            Err(AuthError::TokenResource)
        );
    }

    #[test]
    fn signed_oidc_token_is_bound_to_allowed_algorithm_and_key_id() {
        use jsonwebtoken::{EncodingKey, Header, encode, jwk::Jwk};

        let private_key = base64::engine::general_purpose::STANDARD
            .decode("MC4CAQAwBQYDK2VwBCIEIGrD/e7uKYqSY4twDEsRfMMuLSrODf14dpTiTK6K1YI0")
            .unwrap();
        let encoding = EncodingKey::from_ed_der(&private_key);
        let mut jwk = Jwk::from_encoding_key(&encoding, Algorithm::EdDSA).unwrap();
        jwk.common.key_id = Some("active-key".into());
        let keys = JwkSet { keys: vec![jwk] };
        let binding = OidcBinding {
            issuer: "https://issuer.example/".into(),
            audience: "gaugemesh".into(),
            resource: "https://mesh.example/".into(),
            clock_skew_seconds: 0,
        };
        let claims = OidcClaims {
            sub: "alice".into(),
            iss: binding.issuer.clone(),
            aud: Audience::One(binding.audience.clone()),
            exp: 101,
            nbf: Some(99),
            resource: binding.resource.clone(),
            tenant: "tenant-a".into(),
            scope: "gaugemesh:invoke".into(),
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("active-key".into());
        let token = encode(&header, &claims, &encoding).unwrap();
        assert_eq!(
            verify_oidc_token(&token, &keys, &binding, 100)
                .unwrap()
                .tenant,
            "tenant-a"
        );

        let mut unknown_header = header;
        unknown_header.kid = Some("retired-key".into());
        let unknown = encode(&unknown_header, &claims, &encoding).unwrap();
        assert!(matches!(
            verify_oidc_token(&unknown, &keys, &binding, 100),
            Err(AuthError::TokenKey)
        ));
    }

    #[tokio::test]
    async fn loopback_metadata_and_cross_origin_redirects_are_denied() {
        let loopback = Url::parse("http://127.0.0.1:80/metadata").unwrap();
        assert!(matches!(
            ResolvedOrigin::resolve(&loopback, false).await,
            Err(OriginError::Address(_))
        ));
        let origin = ResolvedOrigin {
            scheme: "https".into(),
            host: "api.example".into(),
            port: 443,
            addresses: vec!["203.0.113.1".parse().unwrap()],
        };
        assert_eq!(
            origin.validate_redirect(&Url::parse("https://evil.example/path").unwrap()),
            Err(OriginError::Redirect)
        );
        assert_eq!(
            origin.validate_connected_peer("203.0.113.2".parse().unwrap()),
            Err(OriginError::DnsRebind)
        );
    }
}
