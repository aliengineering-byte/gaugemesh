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
    Request,
    Principal,
    Tenant,
    Scope,
    Deadline,
    MonetaryBudget,
    TokenBudget,
    RetryBudget,
    DataClassification,
    CausalRoot,
    CausalParent,
    Capability,
    SideEffect,
    Schema,
    TraceParent,
    DataProvenance,
    RoutePolicy,
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
    } else if valid_delegation_extension(source, target) {
        strengthened.push(InvariantId::Principal);
    } else {
        violations.push(InvariantViolation {
            invariant: InvariantId::Principal,
            code: InvariantErrorCode::PrincipalLost,
            detail: "principal changed without an explicit bounded delegation proof".into(),
        });
    }

    equal!(
        request_id,
        InvariantId::Request,
        InvariantErrorCode::CausalityBroken
    );

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
        causal_parent,
        InvariantId::CausalParent,
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
    equal!(
        route_policy_digest,
        InvariantId::RoutePolicy,
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
    if target.delegation.0.len() > source.delegation.0.len()
        && !valid_delegation_extension(source, target)
    {
        violations.push(InvariantViolation {
            invariant: InvariantId::Delegation,
            code: InvariantErrorCode::PrincipalLost,
            detail: "delegation extension is disconnected, cyclic, or expands scope".into(),
        });
    }

    let causal_observations_are_acyclic = {
        let unique = target
            .causal_observations
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        unique.len() == target.causal_observations.len()
            && target.causal_parent.as_ref() != Some(&target.causal_root)
    };
    if !causal_observations_are_acyclic {
        violations.push(InvariantViolation {
            invariant: InvariantId::CausalObservations,
            code: InvariantErrorCode::CausalityBroken,
            detail: "causal path contains a self-edge or repeated observation".into(),
        });
    }
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

fn valid_delegation_extension(source: &RequestContext, target: &RequestContext) -> bool {
    if !target.delegation.0.starts_with(&source.delegation.0) {
        return false;
    }
    let mut current = source.principal.id.clone();
    let mut scope = source.scope.clone();
    let mut seen = source
        .delegation
        .0
        .iter()
        .flat_map(|link| [&link.from, &link.to])
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    seen.insert(current.clone());
    let extension = &target.delegation.0[source.delegation.0.len()..];
    if extension.is_empty() {
        return false;
    }
    for link in extension {
        if link.from != current || !link.scope.is_subset_of(&scope) || !seen.insert(link.to.clone())
        {
            return false;
        }
        current = link.to.clone();
        scope = link.scope.clone();
    }
    current == target.principal.id && target.scope.is_subset_of(&scope)
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
    use crate::context::{
        CapabilityScope, DataClassification, Deadline, DelegationLink, MoneyBudgetMicros,
        PrincipalId, RetryBudget, TenantId, TokenBudget,
    };
    use proptest::prelude::*;

    proptest! {
        #[test]
        #[cfg_attr(miri, ignore = "proptest persistence requires host filesystem access")]
        fn token_budget_never_increases(start in 0_u64..1_000_000, debit in 0_u64..1_000_000) {
            let mut source = RequestContext::local_fixture();
            source.token_budget = TokenBudget(start);
            let mut target = source.clone();
            target.token_budget = TokenBudget(start.saturating_sub(debit));
            prop_assert!(conserve(&source, &target).passed());
        }

        #[test]
        #[cfg_attr(miri, ignore = "proptest persistence requires host filesystem access")]
        fn retry_amplification_is_rejected(start in 0_u16..u16::MAX) {
            let mut source = RequestContext::local_fixture();
            source.retry_budget = RetryBudget(start);
            let mut target = source.clone();
            target.retry_budget = RetryBudget(start + 1);
            prop_assert_eq!(conserve(&source, &target).violations[0].code, InvariantErrorCode::RetryAmplified);
        }

        #[test]
        #[cfg_attr(miri, ignore = "proptest persistence requires host filesystem access")]
        fn deadline_and_money_budget_cannot_increase(start in 0_u64..u64::MAX) {
            let mut source = RequestContext::local_fixture();
            source.deadline = Deadline(start);
            source.monetary_budget = MoneyBudgetMicros(start);
            let mut target = source.clone();
            target.deadline = Deadline(start.saturating_sub(1));
            target.monetary_budget = MoneyBudgetMicros(start.saturating_sub(1));
            prop_assert!(conserve(&source, &target).passed());
            if start < u64::MAX {
                target.deadline = Deadline(start + 1);
                target.monetary_budget = MoneyBudgetMicros(start + 1);
                prop_assert!(!conserve(&source, &target).passed());
            }
        }
    }

    #[test]
    fn scope_tenant_principal_and_route_snapshot_are_bound() {
        let source = RequestContext::local_fixture();
        let mut target = source.clone();
        target.scope.0.insert("admin".into());
        assert_eq!(
            conserve(&source, &target)
                .violations
                .iter()
                .find(|violation| violation.invariant == InvariantId::Scope)
                .unwrap()
                .code,
            InvariantErrorCode::ScopeExpanded
        );
        target = source.clone();
        target.tenant = TenantId("another".into());
        assert!(!conserve(&source, &target).passed());
        target = source.clone();
        target.principal.id = PrincipalId("mallory".into());
        assert!(!conserve(&source, &target).passed());
        target = source.clone();
        target.route_policy_digest = Sha256Digest::of_bytes("different snapshot");
        assert!(!conserve(&source, &target).passed());
    }

    #[test]
    fn bounded_delegation_passes_but_cycles_and_scope_expansion_fail() {
        let source = RequestContext::local_fixture();
        let mut target = source.clone();
        target.principal.id = PrincipalId("worker".into());
        target.delegation.0.push(DelegationLink {
            from: source.principal.id.clone(),
            to: target.principal.id.clone(),
            scope: CapabilityScope::default(),
            proof_digest: Sha256Digest::of_bytes("proof"),
        });
        target.scope = CapabilityScope::default();
        assert!(conserve(&source, &target).passed());

        let mut cyclic = source.clone();
        cyclic.delegation.0.extend([
            DelegationLink {
                from: source.principal.id.clone(),
                to: PrincipalId("worker".into()),
                scope: source.scope.clone(),
                proof_digest: Sha256Digest::of_bytes("proof-a"),
            },
            DelegationLink {
                from: PrincipalId("worker".into()),
                to: source.principal.id.clone(),
                scope: source.scope.clone(),
                proof_digest: Sha256Digest::of_bytes("proof-b"),
            },
        ]);
        assert!(!conserve(&source, &cyclic).passed());

        let mut causal_cycle = source.clone();
        causal_cycle.causal_parent = Some(source.causal_root.clone());
        assert!(!conserve(&source, &causal_cycle).passed());
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

    #[test]
    fn every_delegation_link_must_preserve_prefix_connectivity_scope_and_acyclicity() {
        let original = RequestContext::local_fixture();
        let mut source = original.clone();
        source.principal.id = PrincipalId("worker".into());
        source.delegation.0.push(DelegationLink {
            from: original.principal.id.clone(),
            to: source.principal.id.clone(),
            scope: source.scope.clone(),
            proof_digest: Sha256Digest::of_bytes("proof-a"),
        });

        let mut valid = source.clone();
        valid.principal.id = PrincipalId("leaf".into());
        valid.delegation.0.push(DelegationLink {
            from: source.principal.id.clone(),
            to: valid.principal.id.clone(),
            scope: source.scope.clone(),
            proof_digest: Sha256Digest::of_bytes("proof-b"),
        });
        assert!(valid_delegation_extension(&source, &valid));
        assert!(conserve(&source, &valid).passed());

        let mut rewritten_prefix = valid.clone();
        rewritten_prefix.delegation.0[0].proof_digest = Sha256Digest::of_bytes("rewritten");
        assert!(!valid_delegation_extension(&source, &rewritten_prefix));

        let mut disconnected = valid.clone();
        disconnected.delegation.0[1].from = PrincipalId("intruder".into());
        assert!(!valid_delegation_extension(&source, &disconnected));

        let mut expanded = valid.clone();
        expanded.delegation.0[1].scope.0.insert("admin".into());
        assert!(!valid_delegation_extension(&source, &expanded));

        let mut cyclic = valid.clone();
        cyclic.delegation.0[1].to = original.principal.id.clone();
        cyclic.principal.id = original.principal.id.clone();
        assert!(!valid_delegation_extension(&source, &cyclic));

        let mut wrong_principal = valid.clone();
        wrong_principal.principal.id = PrincipalId("other".into());
        assert!(!valid_delegation_extension(&source, &wrong_principal));

        let mut expanded_target = valid.clone();
        expanded_target.scope.0.insert("admin".into());
        assert!(!valid_delegation_extension(&source, &expanded_target));
    }

    #[test]
    fn a_strict_money_debit_is_strengthening_not_a_violation() {
        let mut source = RequestContext::local_fixture();
        source.monetary_budget = MoneyBudgetMicros(10);
        let mut target = source.clone();
        target.monetary_budget = MoneyBudgetMicros(9);
        let report = conserve(&source, &target);
        assert!(report.passed());
        assert!(report.strengthened.contains(&InvariantId::MonetaryBudget));
        assert!(!report.preserved.contains(&InvariantId::MonetaryBudget));
    }

    #[test]
    fn each_causal_acyclicity_condition_fails_independently() {
        let mut self_parent = RequestContext::local_fixture();
        self_parent.causal_parent = Some(self_parent.causal_root.clone());
        let report = conserve(&self_parent, &self_parent);
        assert!(report.violations.iter().any(|violation| {
            violation.invariant == InvariantId::CausalObservations
                && violation.code == InvariantErrorCode::CausalityBroken
        }));

        let mut duplicate = RequestContext::local_fixture();
        let observation = Sha256Digest::of_bytes("same observation");
        duplicate.causal_observations = vec![observation; 2];
        let report = conserve(&duplicate, &duplicate);
        assert!(report.violations.iter().any(|violation| {
            violation.invariant == InvariantId::CausalObservations
                && violation.code == InvariantErrorCode::CausalityBroken
        }));
    }

    #[test]
    fn unchanged_monotone_values_are_preserved_not_strengthened() {
        let context = RequestContext::local_fixture();
        let report = conserve(&context, &context);
        assert!(report.passed());
        for invariant in [
            InvariantId::Scope,
            InvariantId::Deadline,
            InvariantId::MonetaryBudget,
            InvariantId::TokenBudget,
            InvariantId::RetryBudget,
            InvariantId::DataClassification,
        ] {
            assert!(report.preserved.contains(&invariant));
            assert!(!report.strengthened.contains(&invariant));
        }
    }
}
