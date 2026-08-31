use std::{collections::BTreeMap, sync::Arc};

use axum::{
    Json,
    extract::{Extension, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use gaugemesh_core::policy::{CompiledPolicy, PolicyEffect, PolicyPhase};
use serde_json::json;

use crate::auth::AuthenticatedIdentity;

pub async fn authorize(
    State(policy): State<Arc<CompiledPolicy>>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    request: Request,
    next: Next,
) -> Response {
    let protocol = match request.uri().path() {
        "/mcp" => "mcp",
        path if path == "/v1" || path.starts_with("/v1/") => "openai",
        _ => "unknown",
    };
    let fields = BTreeMap::from([
        ("principal.id".into(), identity.principal.0.clone()),
        ("tenant.id".into(), identity.tenant.0.clone()),
        ("request.protocol".into(), protocol.into()),
        ("request.data_classification".into(), "public".into()),
    ]);
    if policy.evaluate(PolicyPhase::RequestMetadata, &fields) != PolicyEffect::Allow {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":{"code":"GM_POLICY_REQUEST_DENIED"}})),
        )
            .into_response();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, http::Request, middleware, routing::get};
    use gaugemesh_core::{
        context::{PrincipalId, TenantId},
        policy::{Condition, PolicyDocument, PolicyRule, compile},
    };
    use tower::ServiceExt;

    fn identity() -> AuthenticatedIdentity {
        AuthenticatedIdentity {
            principal: PrincipalId("principal-a".into()),
            tenant: TenantId("tenant-a".into()),
            scopes: vec!["gaugemesh:invoke".into()],
        }
    }

    #[tokio::test]
    async fn remote_requests_require_an_explicit_matching_allow() {
        let policy = Arc::new(
            compile(PolicyDocument {
                default: PolicyEffect::Deny,
                rules: vec![PolicyRule {
                    id: "allow-tenant-mcp".into(),
                    phase: PolicyPhase::RequestMetadata,
                    priority: 1,
                    effect: PolicyEffect::Allow,
                    all: vec![
                        Condition {
                            field: "tenant.id".into(),
                            equals: "tenant-a".into(),
                        },
                        Condition {
                            field: "request.protocol".into(),
                            equals: "mcp".into(),
                        },
                    ],
                }],
            })
            .unwrap(),
        );
        let app = Router::new()
            .route("/mcp", get(|| async { StatusCode::OK }))
            .route("/v1/models", get(|| async { StatusCode::OK }))
            .layer(middleware::from_fn_with_state(policy, authorize))
            .layer(Extension(identity()));

        let allowed = app
            .clone()
            .oneshot(Request::get("/mcp").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
        let denied = app
            .oneshot(Request::get("/v1/models").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    }
}
