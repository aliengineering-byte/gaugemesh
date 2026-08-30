use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{context::RequestContext, digest::Sha256Digest};

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConservationRule {
    Equal,
    Subset,
    NonIncreasing,
    NonDecreasing,
    AppendOnly,
    ExplicitDelegation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantId {
    Principal,
    Tenant,
    Scope,
    Deadline,
    MonetaryBudget,
    TokenBudget,
    RetryBudget,
    DataClassification,
    CausalRoot,
    Capability,
    SideEffect,
    Schema,
    TraceParent,
    DataProvenance,
    Delegation,
    CausalObservations,
    RouteDecisions,
    PolicyDecisions,
    RetryAttempts,
    BudgetDebits,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticLoss {
    pub field: String,
    pub reason: String,
    pub weight: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvariantViolation {
    pub invariant: InvariantId,
    pub code: InvariantErrorCode,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Error, JsonSchema, PartialEq, Serialize)]
pub enum InvariantErrorCode {
    #[error("GM_INVARIANT_PRINCIPAL_LOST")]
    PrincipalLost,
    #[error("GM_INVARIANT_TENANT_CHANGED")]
    TenantChanged,
    #[error("GM_INVARIANT_SCOPE_EXPANDED")]
    ScopeExpanded,
    #[error("GM_INVARIANT_DEADLINE_EXTENDED")]
    DeadlineExtended,
    #[error("GM_INVARIANT_BUDGET_INCREASED")]
    BudgetIncreased,
    #[error("GM_INVARIANT_RETRY_AMPLIFIED")]
    RetryAmplified,
    #[error("GM_INVARIANT_DATA_DOWNGRADED")]
    DataDowngraded,
    #[error("GM_INVARIANT_CAUSALITY_BROKEN")]
    CausalityBroken,
    #[error("GM_INVARIANT_SCHEMA_UNBOUND")]
    SchemaUnbound,
    #[error("GM_TRANSLATION_LOSS_EXCEEDED")]
    TranslationLossExceeded,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConservationReport {
    pub preserved: Vec<InvariantId>,
    pub strengthened: Vec<InvariantId>,
    pub optional_losses: Vec<SemanticLoss>,
    pub semantic_loss_score: u64,
    pub violations: Vec<InvariantViolation>,
    pub source_digest: Sha256Digest,
    pub target_digest: Option<Sha256Digest>,
}

impl ConservationReport {
    pub fn passed(&self) -> bool {
        self.violations.is_empty()
    }
}

pub fn conserve(source: &RequestContext, target: &RequestContext) -> ConservationReport {
    let source_value = serde_json::to_value(source).expect("request context serializes");
    let target_value = serde_json::to_value(target).expect("request context serializes");
    let mut preserved = Vec::new();
    let mut strengthened = Vec::new();
    let mut violations = Vec::new();

    macro_rules! equal {
        ($field:ident, $id:expr, $code:expr) => {
            if source.$field == target.$field {
                preserved.push($id);
            } else {
                violations.push(InvariantViolation {
                    invariant: $id,
                    code: $code,
                    detail: stringify!($field).into(),
                });
            }
        };
    }

    if source.principal == target.principal {
        preserved.push(InvariantId::Principal);
    } else if target.delegation.0.last().is_some_and(|link| {
        link.from == source.principal.id
            && link.to == target.principal.id
            && link.scope.is_subset_of(&source.scope)
    }) {
        strengthened.push(InvariantId::Principal);
    } else {
        violations.push(InvariantViolation {
            invariant: InvariantId::Principal,
            code: InvariantErrorCode::PrincipalLost,
            detail: "principal changed without an explicit bounded delegation proof".into(),
        });
    }

    equal!(
        tenant,
        InvariantId::Tenant,
        InvariantErrorCode::TenantChanged
    );
    equal!(
        causal_root,
        InvariantId::CausalRoot,
        InvariantErrorCode::CausalityBroken
    );
    equal!(
        side_effect,
        InvariantId::SideEffect,
        InvariantErrorCode::CausalityBroken
    );
    equal!(
        schema_digest,
        InvariantId::Schema,
        InvariantErrorCode::SchemaUnbound
    );
    equal!(
        trace_parent,
        InvariantId::TraceParent,
        InvariantErrorCode::CausalityBroken
    );
    equal!(
        data_provenance_digest,
        InvariantId::DataProvenance,
        InvariantErrorCode::CausalityBroken
    );
    if source.capability == target.capability {
        preserved.push(InvariantId::Capability);
    } else {
        violations.push(InvariantViolation {
            invariant: InvariantId::Capability,
            code: InvariantErrorCode::SchemaUnbound,
            detail: "capability identity changed across the adapter boundary".into(),
        });
    }

    append_only(
        &source.delegation.0,
        &target.delegation.0,
        InvariantId::Delegation,
        InvariantErrorCode::CausalityBroken,
        &mut preserved,
        &mut strengthened,
        &mut violations,
    );
    append_only(
        &source.causal_observations,
        &target.causal_observations,
        InvariantId::CausalObservations,
        InvariantErrorCode::CausalityBroken,
        &mut preserved,
        &mut strengthened,
        &mut violations,
    );
    append_only(
        &source.route_decisions,
        &target.route_decisions,
        InvariantId::RouteDecisions,
        InvariantErrorCode::CausalityBroken,
        &mut preserved,
        &mut strengthened,
        &mut violations,
    );
    append_only(
        &source.policy_decisions,
        &target.policy_decisions,
        InvariantId::PolicyDecisions,
        InvariantErrorCode::CausalityBroken,
        &mut preserved,
        &mut strengthened,
        &mut violations,
    );
    append_only(
        &source.retry_attempts,
        &target.retry_attempts,
        InvariantId::RetryAttempts,
        InvariantErrorCode::RetryAmplified,
        &mut preserved,
        &mut strengthened,
        &mut violations,
    );
    append_only(
        &source.budget_debits,
        &target.budget_debits,
        InvariantId::BudgetDebits,
        InvariantErrorCode::BudgetIncreased,
        &mut preserved,
        &mut strengthened,
        &mut violations,
    );

    monotone(
        target.scope.is_subset_of(&source.scope),
        target.scope == source.scope,
        InvariantId::Scope,
        InvariantErrorCode::ScopeExpanded,
        &mut preserved,
        &mut strengthened,
        &mut violations,
    );
    monotone(
        target.deadline <= source.deadline,
        target.deadline == source.deadline,
        InvariantId::Deadline,
        InvariantErrorCode::DeadlineExtended,
        &mut preserved,
        &mut strengthened,
        &mut violations,
    );
    monotone(
        target.monetary_budget <= source.monetary_budget,
        target.monetary_budget == source.monetary_budget,
        InvariantId::MonetaryBudget,
        InvariantErrorCode::BudgetIncreased,
        &mut preserved,
        &mut strengthened,
        &mut violations,
    );
    monotone(
        target.token_budget <= source.token_budget,
        target.token_budget == source.token_budget,
        InvariantId::TokenBudget,
        InvariantErrorCode::BudgetIncreased,
        &mut preserved,
        &mut strengthened,
        &mut violations,
    );
    monotone(
        target.retry_budget <= source.retry_budget,
        target.retry_budget == source.retry_budget,
        InvariantId::RetryBudget,
        InvariantErrorCode::RetryAmplified,
        &mut preserved,
        &mut strengthened,
        &mut violations,
    );
    monotone(
        target.data_classification >= source.data_classification,
        target.data_classification == source.data_classification,
        InvariantId::DataClassification,
        InvariantErrorCode::DataDowngraded,
        &mut preserved,
        &mut strengthened,
        &mut violations,
    );

    ConservationReport {
        preserved,
        strengthened,
        optional_losses: Vec::new(),
        semantic_loss_score: 0,
        violations,
        source_digest: Sha256Digest::of_json(&source_value),
        target_digest: Some(Sha256Digest::of_json(&target_value)),
    }
}

#[allow(clippy::too_many_arguments)]
fn append_only<T: PartialEq>(
    source: &[T],
    target: &[T],
    id: InvariantId,
    code: InvariantErrorCode,
    preserved: &mut Vec<InvariantId>,
    strengthened: &mut Vec<InvariantId>,
    violations: &mut Vec<InvariantViolation>,
) {
    if target == source {
        preserved.push(id);
    } else if target.starts_with(source) {
        strengthened.push(id);
    } else {
        violations.push(InvariantViolation {
            invariant: id,
            code,
            detail: format!("{id:?} is not append-only"),
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn monotone(
    valid: bool,
    equal: bool,
    id: InvariantId,
    code: InvariantErrorCode,
    preserved: &mut Vec<InvariantId>,
    strengthened: &mut Vec<InvariantId>,
    violations: &mut Vec<InvariantViolation>,
) {
    if equal {
        preserved.push(id);
    } else if valid {
        strengthened.push(id);
    } else {
        violations.push(InvariantViolation {
            invariant: id,
            code,
            detail: format!("{id:?} monotonicity violated"),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{DataClassification, RetryBudget, TokenBudget};
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn token_budget_never_increases(start in 0_u64..1_000_000, debit in 0_u64..1_000_000) {
            let mut source = RequestContext::local_fixture();
            source.token_budget = TokenBudget(start);
            let mut target = source.clone();
            target.token_budget = TokenBudget(start.saturating_sub(debit));
            prop_assert!(conserve(&source, &target).passed());
        }

        #[test]
        fn retry_amplification_is_rejected(start in 0_u16..u16::MAX) {
            let mut source = RequestContext::local_fixture();
            source.retry_budget = RetryBudget(start);
            let mut target = source.clone();
            target.retry_budget = RetryBudget(start + 1);
            prop_assert_eq!(conserve(&source, &target).violations[0].code, InvariantErrorCode::RetryAmplified);
        }
    }

    #[test]
    fn data_downgrade_is_rejected() {
        let mut source = RequestContext::local_fixture();
        source.data_classification = DataClassification::Confidential;
        let mut target = source.clone();
        target.data_classification = DataClassification::Public;
        assert!(!conserve(&source, &target).passed());
    }

    #[test]
    fn decision_ledgers_are_append_only() {
        let source = RequestContext::local_fixture();
        let mut target = source.clone();
        target
            .route_decisions
            .push(Sha256Digest::of_bytes("route-a"));
        assert!(conserve(&source, &target).passed());

        let mut rewritten = target.clone();
        rewritten.route_decisions[0] = Sha256Digest::of_bytes("route-b");
        assert!(!conserve(&target, &rewritten).passed());
    }
}
