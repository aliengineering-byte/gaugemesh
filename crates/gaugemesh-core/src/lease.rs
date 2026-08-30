use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    capability::CapabilityId,
    context::{
        CapabilityScope, MoneyBudgetMicros, PrincipalId, RetryBudget, TenantId, TokenBudget,
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
        mut capabilities: Vec<CapabilityId>,
        scope: CapabilityScope,
        expires_at_monotonic_ms: u64,
        monetary_budget: MoneyBudgetMicros,
        token_budget: TokenBudget,
        retry_budget: RetryBudget,
    ) -> Self {
        capabilities.sort();
        capabilities.dedup();
        let manifest_digest = manifest_digest(&principal, &tenant, &capabilities, &scope);
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
            &self.capabilities,
            &self.scope,
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
}

fn manifest_digest(
    principal: &PrincipalId,
    tenant: &TenantId,
    capabilities: &[CapabilityId],
    scope: &CapabilityScope,
) -> Sha256Digest {
    Sha256Digest::of_json(&serde_json::json!({
        "principal": principal,
        "tenant": tenant,
        "capabilities": capabilities,
        "scope": scope,
    }))
}
