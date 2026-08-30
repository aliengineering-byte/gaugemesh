use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{capability::CapabilityId, digest::Sha256Digest};

macro_rules! string_id {
    ($name:ident) => {
        #[derive(
            Clone, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
                let value = value.into();
                if value.is_empty() || value.len() > 128 {
                    return Err("identifier length must be 1..=128 bytes");
                }
                if value.chars().any(char::is_control) {
                    return Err("identifier contains a control character");
                }
                Ok(Self(value))
            }
        }
    };
}

string_id!(PrincipalId);
string_id!(TenantId);
string_id!(RequestId);
string_id!(CausalId);
string_id!(IdempotencyIdentity);

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub id: PrincipalId,
    #[serde(default)]
    pub groups: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationLink {
    pub from: PrincipalId,
    pub to: PrincipalId,
    pub scope: CapabilityScope,
    pub proof_digest: Sha256Digest,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct DelegationChain(pub Vec<DelegationLink>);

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct CapabilityScope(pub BTreeSet<String>);

impl CapabilityScope {
    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.0.is_subset(&other.0)
    }
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(transparent)]
pub struct Deadline(pub u64);

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(transparent)]
pub struct MoneyBudgetMicros(pub u64);

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(transparent)]
pub struct TokenBudget(pub u64);

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(transparent)]
pub struct RetryBudget(pub u16);

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectClass {
    ReadOnly,
    IdempotentWrite,
    NonIdempotentWrite,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SideEffectContract {
    pub class: SideEffectClass,
    pub idempotency_identity: Option<IdempotencyIdentity>,
    #[serde(default)]
    pub compensation_allowed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolRevision {
    Mcp2025_11_25,
    Mcp2026_07_28,
    OpenAiCompatibleV1,
    InternalV1,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolIdentity {
    pub revision: ProtocolRevision,
    pub peer_digest: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestContext {
    pub request_id: RequestId,
    pub principal: Principal,
    pub delegation: DelegationChain,
    pub tenant: TenantId,
    pub scope: CapabilityScope,
    pub data_classification: DataClassification,
    pub deadline: Deadline,
    pub monetary_budget: MoneyBudgetMicros,
    pub token_budget: TokenBudget,
    pub retry_budget: RetryBudget,
    pub side_effect: SideEffectContract,
    pub causal_root: CausalId,
    pub causal_parent: Option<CausalId>,
    pub trace_parent: String,
    pub protocol: ProtocolIdentity,
    pub capability: Option<CapabilityId>,
    pub schema_digest: Sha256Digest,
    pub route_policy_digest: Sha256Digest,
    pub data_provenance_digest: Sha256Digest,
    #[serde(default)]
    pub causal_observations: Vec<Sha256Digest>,
    #[serde(default)]
    pub route_decisions: Vec<Sha256Digest>,
    #[serde(default)]
    pub policy_decisions: Vec<Sha256Digest>,
    #[serde(default)]
    pub retry_attempts: Vec<Sha256Digest>,
    #[serde(default)]
    pub budget_debits: Vec<Sha256Digest>,
}

impl RequestContext {
    pub fn local_fixture() -> Self {
        let zero = Sha256Digest::of_bytes([]);
        Self {
            request_id: RequestId(Uuid::new_v4().to_string()),
            principal: Principal {
                id: PrincipalId("local-demo".into()),
                groups: BTreeSet::from(["local".into()]),
            },
            delegation: DelegationChain::default(),
            tenant: TenantId("local".into()),
            scope: CapabilityScope(BTreeSet::from(["capability:invoke".into()])),
            data_classification: DataClassification::Public,
            deadline: Deadline(30_000),
            monetary_budget: MoneyBudgetMicros(0),
            token_budget: TokenBudget(4_096),
            retry_budget: RetryBudget(1),
            side_effect: SideEffectContract {
                class: SideEffectClass::ReadOnly,
                idempotency_identity: None,
                compensation_allowed: false,
            },
            causal_root: CausalId(Uuid::new_v4().to_string()),
            causal_parent: None,
            trace_parent: "00-00000000000000000000000000000001-0000000000000001-01".into(),
            protocol: ProtocolIdentity {
                revision: ProtocolRevision::InternalV1,
                peer_digest: zero,
            },
            capability: None,
            schema_digest: zero,
            route_policy_digest: zero,
            data_provenance_digest: zero,
            causal_observations: Vec::new(),
            route_decisions: Vec::new(),
            policy_decisions: Vec::new(),
            retry_attempts: Vec::new(),
            budget_debits: Vec::new(),
        }
    }
}
