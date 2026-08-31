use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    capability::CapabilityId,
    context::{
        CapabilityScope, MoneyBudgetMicros, PrincipalId, RetryBudget, SideEffectClass, TenantId,
        TokenBudget,
    },
    digest::Sha256Digest,
};

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct LeaseId(pub String);

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityLease {
    pub id: LeaseId,
    pub principal: PrincipalId,
    pub tenant: TenantId,
    pub request_identity: String,
    pub capabilities: Vec<CapabilityId>,
    pub scope: CapabilityScope,
    pub expires_at_monotonic_ms: u64,
    pub monetary_budget: MoneyBudgetMicros,
    pub token_budget: TokenBudget,
    pub retry_budget: RetryBudget,
    pub side_effects: BTreeSet<SideEffectClass>,
    pub manifest_digest: Sha256Digest,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LeaseError {
    #[error("GM_LEASE_EXPIRED")]
    Expired,
    #[error("GM_LEASE_PRINCIPAL_MISMATCH")]
    Principal,
    #[error("GM_LEASE_TENANT_MISMATCH")]
    Tenant,
    #[error("GM_LEASE_CAPABILITY_OUTSIDE_CONE")]
    Capability,
    #[error("GM_LEASE_STALE_SCHEMA")]
    StaleSchema,
    #[error("GM_LEASE_MANIFEST_TAMPERED")]
    Manifest,
}

impl CapabilityLease {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        principal: PrincipalId,
        tenant: TenantId,
        request_identity: String,
        capabilities: Vec<CapabilityId>,
        scope: CapabilityScope,
        expires_at_monotonic_ms: u64,
        monetary_budget: MoneyBudgetMicros,
        token_budget: TokenBudget,
        retry_budget: RetryBudget,
    ) -> Self {
        Self::issue_with_side_effects(
            principal,
            tenant,
            request_identity,
            capabilities,
            scope,
            expires_at_monotonic_ms,
            monetary_budget,
            token_budget,
            retry_budget,
            BTreeSet::from([SideEffectClass::ReadOnly]),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue_with_side_effects(
        principal: PrincipalId,
        tenant: TenantId,
        request_identity: String,
        mut capabilities: Vec<CapabilityId>,
        scope: CapabilityScope,
        expires_at_monotonic_ms: u64,
        monetary_budget: MoneyBudgetMicros,
        token_budget: TokenBudget,
        retry_budget: RetryBudget,
        side_effects: BTreeSet<SideEffectClass>,
    ) -> Self {
        capabilities.sort();
        capabilities.dedup();
        let manifest_digest = manifest_digest(
            &principal,
            &tenant,
            &request_identity,
            &capabilities,
            &scope,
            expires_at_monotonic_ms,
            monetary_budget,
            token_budget,
            retry_budget,
            &side_effects,
        );
        Self {
            id: LeaseId(Uuid::new_v4().to_string()),
            principal,
            tenant,
            request_identity,
            capabilities,
            scope,
            expires_at_monotonic_ms,
            monetary_budget,
            token_budget,
            retry_budget,
            side_effects,
            manifest_digest,
        }
    }

    pub fn authorize(
        &self,
        principal: &PrincipalId,
        tenant: &TenantId,
        capability: &CapabilityId,
        now_monotonic_ms: u64,
    ) -> Result<(), LeaseError> {
        if now_monotonic_ms >= self.expires_at_monotonic_ms {
            return Err(LeaseError::Expired);
        }
        if principal != &self.principal {
            return Err(LeaseError::Principal);
        }
        if tenant != &self.tenant {
            return Err(LeaseError::Tenant);
        }
        if manifest_digest(
            &self.principal,
            &self.tenant,
            &self.request_identity,
            &self.capabilities,
            &self.scope,
            self.expires_at_monotonic_ms,
            self.monetary_budget,
            self.token_budget,
            self.retry_budget,
            &self.side_effects,
        ) != self.manifest_digest
        {
            return Err(LeaseError::Manifest);
        }
        let matching = self.capabilities.iter().find(|candidate| {
            candidate.source == capability.source
                && candidate.kind == capability.kind
                && candidate.native_identity_digest == capability.native_identity_digest
        });
        match matching {
            None => Err(LeaseError::Capability),
            Some(stored) if stored.schema_digest != capability.schema_digest => {
                Err(LeaseError::StaleSchema)
            }
            Some(stored) if stored != capability => Err(LeaseError::Capability),
            Some(_) => Ok(()),
        }
    }

    pub fn authorize_invocation(
        &self,
        principal: &PrincipalId,
        tenant: &TenantId,
        capability: &CapabilityId,
        side_effect: SideEffectClass,
        now_monotonic_ms: u64,
    ) -> Result<(), LeaseError> {
        self.authorize(principal, tenant, capability, now_monotonic_ms)?;
        if self.side_effects.contains(&side_effect) {
            Ok(())
        } else {
            Err(LeaseError::Capability)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn manifest_digest(
    principal: &PrincipalId,
    tenant: &TenantId,
    request_identity: &str,
    capabilities: &[CapabilityId],
    scope: &CapabilityScope,
    expires_at_monotonic_ms: u64,
    monetary_budget: MoneyBudgetMicros,
    token_budget: TokenBudget,
    retry_budget: RetryBudget,
    side_effects: &BTreeSet<SideEffectClass>,
) -> Sha256Digest {
    Sha256Digest::of_json(&serde_json::json!({
        "principal": principal,
        "tenant": tenant,
        "requestIdentity": request_identity,
        "capabilities": capabilities,
        "scope": scope,
        "expiresAtMonotonicMs": expires_at_monotonic_ms,
        "monetaryBudget": monetary_budget,
        "tokenBudget": token_budget,
        "retryBudget": retry_budget,
        "sideEffects": side_effects,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        capability::{CapabilityKind, CapabilityRevision, SourceId},
        digest::Sha256Digest,
    };

    fn capability(schema: &str) -> CapabilityId {
        CapabilityId::new(
            SourceId("docs".into()),
            CapabilityKind::Tool,
            "search",
            Sha256Digest::of_bytes(schema),
            CapabilityRevision("2026-07-28".into()),
            Sha256Digest::of_bytes("source-config"),
        )
    }

    fn lease() -> CapabilityLease {
        CapabilityLease::issue(
            PrincipalId("alice".into()),
            TenantId("tenant-a".into()),
            "request-a".into(),
            vec![capability("v1")],
            CapabilityScope::default(),
            100,
            MoneyBudgetMicros(10),
            TokenBudget(20),
            RetryBudget(1),
        )
    }

    #[test]
    fn stale_schema_and_cross_tenant_use_fail_closed() {
        let lease = lease();
        assert_eq!(
            lease.authorize(
                &PrincipalId("alice".into()),
                &TenantId("tenant-a".into()),
                &capability("v2"),
                0,
            ),
            Err(LeaseError::StaleSchema)
        );
        assert_eq!(
            lease.authorize(
                &PrincipalId("alice".into()),
                &TenantId("tenant-b".into()),
                &capability("v1"),
                0,
            ),
            Err(LeaseError::Tenant)
        );
        assert_eq!(
            lease.authorize(
                &PrincipalId("mallory".into()),
                &TenantId("tenant-a".into()),
                &capability("v1"),
                0,
            ),
            Err(LeaseError::Principal)
        );
    }

    #[test]
    fn expiry_uses_monotonic_deadline() {
        assert_eq!(
            lease().authorize(
                &PrincipalId("alice".into()),
                &TenantId("tenant-a".into()),
                &capability("v1"),
                100,
            ),
            Err(LeaseError::Expired)
        );
    }

    #[test]
    fn budgets_and_side_effects_are_manifest_bound() {
        let mut tampered = lease();
        tampered.retry_budget.0 += 1;
        assert_eq!(
            tampered.authorize(
                &PrincipalId("alice".into()),
                &TenantId("tenant-a".into()),
                &capability("v1"),
                0,
            ),
            Err(LeaseError::Manifest)
        );

        assert_eq!(
            lease().authorize_invocation(
                &PrincipalId("alice".into()),
                &TenantId("tenant-a".into()),
                &capability("v1"),
                SideEffectClass::NonIdempotentWrite,
                0,
            ),
            Err(LeaseError::Capability)
        );
    }
}
