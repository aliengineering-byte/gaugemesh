use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use axum::{
    Json,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use futures_util::StreamExt as _;
use gaugemesh_core::{
    config::RemoteConfig,
    context::{PrincipalId, TenantId},
    security::{AuthError, OidcBinding, ResolvedOrigin, verify_oidc_token},
};
use jsonwebtoken::jwk::JwkSet;
use serde_json::json;

const MAX_JWKS_BYTES: usize = 1024 * 1024;
const MAX_BEARER_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug)]
pub struct AuthenticatedIdentity {
    pub principal: PrincipalId,
    pub tenant: TenantId,
    pub scopes: Vec<String>,
}

#[derive(Clone)]
pub struct RemoteAuthState {
    config: RemoteConfig,
    keys: Arc<tokio::sync::RwLock<CachedKeys>>,
    refresh: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Clone)]
struct CachedKeys {
    set: JwkSet,
    expires_at: Instant,
}

impl RemoteAuthState {
    pub async fn initialize(config: RemoteConfig) -> Result<Self> {
        let set = fetch_jwks(&config.jwks_url).await?;
        let expires_at = Instant::now() + Duration::from_secs(config.jwks_cache_ttl_seconds);
        Ok(Self {
            config,
            keys: Arc::new(tokio::sync::RwLock::new(CachedKeys { set, expires_at })),
            refresh: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    async fn keys(&self, force_refresh: bool) -> Result<JwkSet> {
        if !force_refresh {
            let cached = self.keys.read().await;
            if cached.expires_at > Instant::now() {
                return Ok(cached.set.clone());
            }
        }
        let _refresh = self.refresh.lock().await;
        if !force_refresh {
            let cached = self.keys.read().await;
            if cached.expires_at > Instant::now() {
                return Ok(cached.set.clone());
            }
        }
        let set = fetch_jwks(&self.config.jwks_url).await?;
        *self.keys.write().await = CachedKeys {
            set: set.clone(),
            expires_at: Instant::now() + Duration::from_secs(self.config.jwks_cache_ttl_seconds),
        };
        Ok(set)
    }

    async fn authenticate(&self, headers: &HeaderMap) -> Result<AuthenticatedIdentity, AuthError> {
        let token = bearer_token(headers)?;
        let binding = OidcBinding {
            issuer: self.config.issuer.as_str().into(),
            audience: self.config.audience.clone(),
            resource: self.config.resource.clone(),
            clock_skew_seconds: self.config.clock_skew_seconds,
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AuthError::TokenExpired)?
            .as_secs();
        let keys = self.keys(false).await.map_err(|_| AuthError::TokenKey)?;
        let claims = match verify_oidc_token(token, &keys, &binding, now) {
            Err(AuthError::TokenKey) => {
                let refreshed = self.keys(true).await.map_err(|_| AuthError::TokenKey)?;
                verify_oidc_token(token, &refreshed, &binding, now)?
            }
            outcome => outcome?,
        };
        let scopes = claims
            .scope
            .split_ascii_whitespace()
            .collect::<BTreeSet<_>>();
        if !self
            .config
            .required_scopes
            .iter()
            .all(|required| scopes.contains(required.as_str()))
        {
            return Err(AuthError::ScopeDenied);
        }
        validate_identity(&claims.sub, &claims.tenant)?;
        Ok(AuthenticatedIdentity {
            principal: PrincipalId(claims.sub),
            tenant: TenantId(claims.tenant),
            scopes: scopes.into_iter().map(str::to_owned).collect(),
        })
    }
}

pub async fn authorize_remote(
    State(state): State<Arc<RemoteAuthState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut request: Request,
    next: Next,
) -> Response {
    if let Err(code) = validate_request_origin(&state.config, peer.ip(), request.headers()) {
        return auth_response(StatusCode::BAD_REQUEST, code);
    }
    match state.authenticate(request.headers()).await {
        Ok(identity) => {
            request.extensions_mut().insert(identity);
            next.run(request).await
        }
        Err(AuthError::ScopeDenied) => auth_response(StatusCode::FORBIDDEN, "GM_AUTH_SCOPE_DENIED"),
        Err(error) => auth_response(StatusCode::UNAUTHORIZED, error.to_string()),
    }
}

fn validate_request_origin(
    config: &RemoteConfig,
    peer: IpAddr,
    headers: &HeaderMap,
) -> Result<&'static str, &'static str> {
    const FORWARDED_HEADERS: [&str; 5] = [
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-port",
        "x-forwarded-proto",
    ];
    let has_forwarding = FORWARDED_HEADERS
        .iter()
        .any(|name| headers.contains_key(*name));
    let trusted = config.trusted_proxies.contains(&peer);
    if has_forwarding && !trusted {
        return Err("GM_AUTH_UNTRUSTED_PROXY_HEADERS");
    }
    if headers.contains_key("forwarded") {
        return Err("GM_AUTH_FORWARDED_HEADER_UNSUPPORTED");
    }
    if trusted {
        if let Some(proto) = single_header(headers, "x-forwarded-proto")? {
            if !proto.eq_ignore_ascii_case("https") {
                return Err("GM_AUTH_PUBLIC_ORIGIN_MISMATCH");
            }
        }
    }
    let authority = if trusted {
        single_header(headers, "x-forwarded-host")?
            .or_else(|| single_header(headers, header::HOST.as_str()).ok().flatten())
    } else {
        single_header(headers, header::HOST.as_str())?
    }
    .ok_or("GM_AUTH_PUBLIC_ORIGIN_MISMATCH")?;
    if !authority_matches(authority, &config.public_origin) {
        return Err("GM_AUTH_PUBLIC_ORIGIN_MISMATCH");
    }
    Ok("ok")
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, &'static str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next();
    if values.next().is_some() {
        return Err("GM_AUTH_AMBIGUOUS_HEADER");
    }
    value
        .map(|value| value.to_str().map_err(|_| "GM_AUTH_INVALID_HEADER"))
        .transpose()
}

fn authority_matches(authority: &str, origin: &url::Url) -> bool {
    let Ok(authority) = authority.parse::<axum::http::uri::Authority>() else {
        return false;
    };
    authority
        .host()
        .eq_ignore_ascii_case(origin.host_str().unwrap_or(""))
        && authority.port_u16().unwrap_or(443) == origin.port_or_known_default().unwrap_or(443)
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, AuthError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next().ok_or(AuthError::TokenHeader)?;
    if values.next().is_some() {
        return Err(AuthError::TokenHeader);
    }
    let value = value.to_str().map_err(|_| AuthError::TokenHeader)?;
    let (scheme, token) = value.split_once(' ').ok_or(AuthError::TokenHeader)?;
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || token.len() > MAX_BEARER_BYTES
        || token.contains(char::is_whitespace)
    {
        return Err(AuthError::TokenHeader);
    }
    Ok(token)
}

fn validate_identity(principal: &str, tenant: &str) -> Result<(), AuthError> {
    let valid = |value: &str| {
        !value.is_empty()
            && value.len() <= 256
            && value
                .chars()
                .all(|character| !character.is_control() && !character.is_whitespace())
    };
    if !valid(principal) || !valid(tenant) {
        return Err(AuthError::TokenSignature);
    }
    Ok(())
}

async fn fetch_jwks(url: &url::Url) -> Result<JwkSet> {
    let origin = ResolvedOrigin::resolve(url, false)
        .await
        .context("GM_AUTH_JWKS_ORIGIN")?;
    let addresses = origin
        .addresses
        .iter()
        .map(|address| SocketAddr::new(*address, origin.port))
        .collect::<Vec<_>>();
    let client = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .resolve_to_addrs(&origin.host, &addresses)
        .build()
        .context("GM_AUTH_JWKS_CLIENT")?;
    let response = client
        .get(url.clone())
        .send()
        .await
        .context("GM_AUTH_JWKS_FETCH")?;
    if !response.status().is_success() {
        bail!("GM_AUTH_JWKS_STATUS:{}", response.status());
    }
    if response
        .content_length()
        .is_some_and(|size| usize::try_from(size).map_or(true, |size| size > MAX_JWKS_BYTES))
    {
        bail!("GM_AUTH_JWKS_TOO_LARGE");
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("GM_AUTH_JWKS_BODY")?;
        if body.len().saturating_add(chunk.len()) > MAX_JWKS_BYTES {
            bail!("GM_AUTH_JWKS_TOO_LARGE");
        }
        body.extend_from_slice(&chunk);
    }
    let set: JwkSet = serde_json::from_slice(&body).context("GM_AUTH_JWKS_PARSE")?;
    let mut ids = BTreeSet::new();
    if set.keys.is_empty()
        || set.keys.len() > 128
        || set.keys.iter().any(|key| {
            key.common
                .key_id
                .as_deref()
                .is_none_or(|id| id.is_empty() || id.len() > 256 || !ids.insert(id.to_owned()))
        })
    {
        bail!("GM_AUTH_JWKS_INVALID");
    }
    Ok(set)
}

fn auth_response(status: StatusCode, code: impl Into<String>) -> Response {
    let mut response = (status, Json(json!({"error":{"code":code.into()}}))).into_response();
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            axum::http::HeaderValue::from_static("Bearer"),
        );
    }
    response
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use axum::{body::Body, extract::Extension, routing::get};
    use base64::Engine as _;
    use gaugemesh_core::security::{Audience, OidcClaims};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, jwk::Jwk};
    use tower::ServiceExt as _;

    use super::*;

    fn remote() -> RemoteConfig {
        RemoteConfig {
            tls_certificate: PathBuf::from("/cert.pem"),
            tls_private_key: PathBuf::from("/key.pem"),
            public_origin: url::Url::parse("https://mesh.example/").unwrap(),
            issuer: url::Url::parse("https://issuer.example/").unwrap(),
            audience: "mesh".into(),
            resource: "https://mesh.example/".into(),
            jwks_url: url::Url::parse("https://issuer.example/jwks.json").unwrap(),
            required_scopes: vec!["gaugemesh:invoke".into()],
            jwks_cache_ttl_seconds: 300,
            clock_skew_seconds: 30,
            trusted_proxies: vec!["10.0.0.2".parse().unwrap()],
        }
    }

    #[test]
    fn bearer_parser_rejects_duplicates_whitespace_and_oversize_values() {
        let mut headers = HeaderMap::new();
        headers.append(header::AUTHORIZATION, "Bearer one".parse().unwrap());
        headers.append(header::AUTHORIZATION, "Bearer two".parse().unwrap());
        assert_eq!(bearer_token(&headers), Err(AuthError::TokenHeader));
        headers.clear();
        headers.insert(header::AUTHORIZATION, "Bearer one two".parse().unwrap());
        assert_eq!(bearer_token(&headers), Err(AuthError::TokenHeader));
    }

    #[test]
    fn public_origin_and_proxy_headers_are_fail_closed() {
        let config = remote();
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "mesh.example".parse().unwrap());
        assert_eq!(
            validate_request_origin(&config, "203.0.113.9".parse().unwrap(), &headers),
            Ok("ok")
        );
        headers.insert("x-forwarded-host", "mesh.example".parse().unwrap());
        assert_eq!(
            validate_request_origin(&config, "203.0.113.9".parse().unwrap(), &headers),
            Err("GM_AUTH_UNTRUSTED_PROXY_HEADERS")
        );
        headers.insert("x-forwarded-host", "evil.example".parse().unwrap());
        assert_eq!(
            validate_request_origin(&config, "10.0.0.2".parse().unwrap(), &headers),
            Err("GM_AUTH_PUBLIC_ORIGIN_MISMATCH")
        );
    }

    #[tokio::test]
    async fn signed_token_reaches_the_router_as_bound_identity() {
        let private_key = base64::engine::general_purpose::STANDARD
            .decode("MC4CAQAwBQYDK2VwBCIEIGrD/e7uKYqSY4twDEsRfMMuLSrODf14dpTiTK6K1YI0")
            .unwrap();
        let encoding = EncodingKey::from_ed_der(&private_key);
        let mut jwk = Jwk::from_encoding_key(&encoding, Algorithm::EdDSA).unwrap();
        jwk.common.key_id = Some("active-key".into());
        let state = Arc::new(RemoteAuthState {
            config: remote(),
            keys: Arc::new(tokio::sync::RwLock::new(CachedKeys {
                set: JwkSet { keys: vec![jwk] },
                expires_at: Instant::now() + Duration::from_secs(60),
            })),
            refresh: Arc::new(tokio::sync::Mutex::new(())),
        });
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = OidcClaims {
            sub: "alice".into(),
            iss: "https://issuer.example/".into(),
            aud: Audience::One("mesh".into()),
            exp: now + 60,
            nbf: Some(now.saturating_sub(1)),
            resource: "https://mesh.example/".into(),
            tenant: "tenant-a".into(),
            scope: "gaugemesh:invoke extra:read".into(),
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("active-key".into());
        let token = encode(&header, &claims, &encoding).unwrap();
        let app = axum::Router::new()
            .route(
                "/",
                get(
                    |Extension(identity): Extension<AuthenticatedIdentity>| async move {
                        format!("{}:{}", identity.tenant.0, identity.principal.0)
                    },
                ),
            )
            .layer(axum::middleware::from_fn_with_state(
                state,
                authorize_remote,
            ));
        let mut request = Request::builder()
            .uri("/")
            .header(header::HOST, "mesh.example")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            "203.0.113.9".parse().unwrap(),
            443,
        )));
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(&body[..], b"tenant-a:alice");
    }
}
