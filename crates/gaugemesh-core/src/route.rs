use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::digest::Sha256Digest;

/// Maximum generated score term: normalized weight 10_000 × normalized metric 10_000.
pub const MAX_SCORE_TERM: u64 = 100_000_000;
pub const MAX_ACTION_SCORE: u64 = 7 * MAX_SCORE_TERM;

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RouteId(pub String);

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConstraintResult {
    pub allowed: bool,
    #[serde(default)]
    pub rejections: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteMetricSnapshot {
    pub latency: u32,
    pub cost: u32,
    pub failure: u32,
    pub pressure: u32,
    pub exposure: u32,
    pub switching: u32,
}

impl RouteMetricSnapshot {
    pub fn validate(self) -> Result<Self, RouteError> {
        if [
            self.latency,
            self.cost,
            self.failure,
            self.pressure,
            self.exposure,
            self.switching,
        ]
        .into_iter()
        .all(|metric| metric <= 10_000)
        {
            Ok(self)
        } else {
            Err(RouteError::MetricOutOfRange)
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteWeights {
    pub latency: u32,
    pub cost: u32,
    pub failure: u32,
    pub semantic_loss: u32,
    pub pressure: u32,
    pub exposure: u32,
    pub switching: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteCandidate {
    pub route_id: RouteId,
    pub endpoint_id: String,
    pub hard_constraints: ConstraintResult,
    pub metrics: RouteMetricSnapshot,
    pub semantic_loss: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScoreTerms {
    pub latency: u64,
    pub cost: u64,
    pub failure: u64,
    pub semantic_loss: u64,
    pub pressure: u64,
    pub exposure: u64,
    pub switching: u64,
}

impl ScoreTerms {
    pub fn total(&self) -> Result<u64, RouteError> {
        let terms = [
            self.latency,
            self.cost,
            self.failure,
            self.semantic_loss,
            self.pressure,
            self.exposure,
            self.switching,
        ];
        if terms.into_iter().any(|term| term > MAX_SCORE_TERM) {
            return Err(RouteError::DecisionScoreOutOfRange);
        }
        terms
            .into_iter()
            .try_fold(0_u64, u64::checked_add)
            .ok_or(RouteError::DecisionScoreOutOfRange)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateExplanation {
    pub route_id: RouteId,
    pub allowed: bool,
    pub rejections: Vec<String>,
    pub terms: Option<ScoreTerms>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteExplanation {
    pub candidates: Vec<CandidateExplanation>,
    pub selected: RouteId,
    pub tie_breaker: String,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoutePlan {
    pub selected: RouteId,
    pub action_score: u64,
    pub explanation: RouteExplanation,
    pub snapshot_digest: Sha256Digest,
    pub route_policy_digest: Sha256Digest,
    pub metric_snapshot_digest: Sha256Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub enum RouteDenialCode {
    #[serde(rename = "GM_ROUTE_NO_ELIGIBLE_CANDIDATE")]
    NoEligibleCandidate,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteDenial {
    pub code: RouteDenialCode,
    pub candidates: Vec<CandidateExplanation>,
    pub snapshot_digest: Sha256Digest,
    pub route_policy_digest: Sha256Digest,
    pub metric_snapshot_digest: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum RouteDecision {
    Selected {
        schema_version: u16,
        decision_digest: Sha256Digest,
        plan: RoutePlan,
    },
    Denied {
        schema_version: u16,
        decision_digest: Sha256Digest,
        denial: RouteDenial,
    },
}

impl RouteDecision {
    pub fn decision_digest(&self) -> Sha256Digest {
        match self {
            Self::Selected {
                decision_digest, ..
            }
            | Self::Denied {
                decision_digest, ..
            } => *decision_digest,
        }
    }

    pub fn verify_integrity(&self) -> Result<(), RouteError> {
        let (schema_version, explanations) = match self {
            Self::Selected {
                schema_version,
                decision_digest,
                plan,
            } => {
                if *decision_digest != selected_digest(*schema_version, plan) {
                    return Err(RouteError::DecisionDigestMismatch);
                }
                if plan.action_score > MAX_ACTION_SCORE {
                    return Err(RouteError::DecisionScoreOutOfRange);
                }
                if plan.selected != plan.explanation.selected
                    || plan.explanation.tie_breaker != "lexicographically smallest stable route_id"
                {
                    return Err(RouteError::DecisionContractInvalid);
                }
                let selected = plan
                    .explanation
                    .candidates
                    .iter()
                    .find(|candidate| candidate.route_id == plan.selected)
                    .ok_or(RouteError::DecisionContractInvalid)?;
                let selected_score = selected
                    .terms
                    .as_ref()
                    .ok_or(RouteError::DecisionContractInvalid)?
                    .total()?;
                if !selected.allowed
                    || !selected.rejections.is_empty()
                    || selected_score != plan.action_score
                {
                    return Err(RouteError::DecisionContractInvalid);
                }
                let mut ranked = Vec::new();
                for candidate in &plan.explanation.candidates {
                    if let Some(terms) = &candidate.terms {
                        ranked.push((terms.total()?, candidate.route_id.clone()));
                    }
                }
                ranked.sort();
                if ranked.first() != Some(&(plan.action_score, plan.selected.clone())) {
                    return Err(RouteError::DecisionContractInvalid);
                }
                (*schema_version, &plan.explanation.candidates)
            }
            Self::Denied {
                schema_version,
                decision_digest,
                denial,
            } => {
                if *decision_digest != denied_digest(*schema_version, denial) {
                    return Err(RouteError::DecisionDigestMismatch);
                }
                (*schema_version, &denial.candidates)
            }
        };
        if schema_version != 1 {
            return Err(RouteError::UnsupportedDecisionSchema);
        }
        validate_explanations(explanations, matches!(self, Self::Denied { .. }))
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RouteError {
    #[error("GM_ROUTE_NO_ELIGIBLE_CANDIDATE")]
    NoEligibleCandidate,
    #[error("GM_ROUTE_METRIC_OUT_OF_RANGE")]
    MetricOutOfRange,
    #[error("GM_ROUTE_DUPLICATE_ROUTE_ID")]
    DuplicateRouteId,
    #[error("GM_ROUTE_INVALID_ROUTE_ID")]
    InvalidRouteId,
    #[error("GM_ROUTE_REJECTION_REQUIRED")]
    RejectionRequired,
    #[error("GM_ROUTE_DECISION_DIGEST_MISMATCH")]
    DecisionDigestMismatch,
    #[error("GM_ROUTE_DECISION_CONTRACT_INVALID")]
    DecisionContractInvalid,
    #[error("GM_ROUTE_DECISION_SCORE_OUT_OF_RANGE")]
    DecisionScoreOutOfRange,
    #[error("GM_ROUTE_DECISION_SCHEMA_UNSUPPORTED")]
    UnsupportedDecisionSchema,
}

pub fn plan(
    candidates: Vec<RouteCandidate>,
    weights: RouteWeights,
) -> Result<RoutePlan, RouteError> {
    match decide(candidates, weights)? {
        RouteDecision::Selected { plan, .. } => Ok(plan),
        RouteDecision::Denied { .. } => Err(RouteError::NoEligibleCandidate),
    }
}

pub fn decide(
    mut candidates: Vec<RouteCandidate>,
    weights: RouteWeights,
) -> Result<RouteDecision, RouteError> {
    if [
        weights.latency,
        weights.cost,
        weights.failure,
        weights.semantic_loss,
        weights.pressure,
        weights.exposure,
        weights.switching,
    ]
    .into_iter()
    .any(|weight| weight > 10_000)
        || candidates
            .iter()
            .any(|candidate| candidate.semantic_loss > 10_000)
    {
        return Err(RouteError::MetricOutOfRange);
    }
    if candidates
        .iter()
        .any(|candidate| candidate.route_id.0.is_empty())
    {
        return Err(RouteError::InvalidRouteId);
    }
    candidates.sort_by(|left, right| left.route_id.cmp(&right.route_id));
    if candidates
        .windows(2)
        .any(|pair| pair[0].route_id == pair[1].route_id)
    {
        return Err(RouteError::DuplicateRouteId);
    }
    for candidate in &mut candidates {
        if !candidate.hard_constraints.allowed {
            if candidate.hard_constraints.rejections.is_empty()
                || candidate
                    .hard_constraints
                    .rejections
                    .iter()
                    .any(|rejection| rejection.trim().is_empty())
            {
                return Err(RouteError::RejectionRequired);
            }
            candidate.hard_constraints.rejections.sort();
            candidate.hard_constraints.rejections.dedup();
        }
    }
    let snapshot_digest = Sha256Digest::of_json(
        &serde_json::to_value((&candidates, weights)).expect("route snapshot serializes"),
    );
    let route_policy_digest =
        Sha256Digest::of_json(&serde_json::to_value(weights).expect("route weights serialize"));
    let metric_snapshot_digest = Sha256Digest::of_json(
        &serde_json::to_value(
            candidates
                .iter()
                .map(|candidate| {
                    (
                        &candidate.route_id,
                        &candidate.endpoint_id,
                        candidate.metrics,
                        candidate.semantic_loss,
                    )
                })
                .collect::<Vec<_>>(),
        )
        .expect("metric snapshot serializes"),
    );
    let mut explanation = Vec::with_capacity(candidates.len());
    let mut eligible = Vec::new();
    for candidate in &candidates {
        if !candidate.hard_constraints.allowed {
            explanation.push(CandidateExplanation {
                route_id: candidate.route_id.clone(),
                allowed: false,
                rejections: candidate.hard_constraints.rejections.clone(),
                terms: None,
            });
            continue;
        }
        let metric = candidate.metrics.validate()?;
        let terms = ScoreTerms {
            latency: u64::from(weights.latency) * u64::from(metric.latency),
            cost: u64::from(weights.cost) * u64::from(metric.cost),
            failure: u64::from(weights.failure) * u64::from(metric.failure),
            semantic_loss: u64::from(weights.semantic_loss) * u64::from(candidate.semantic_loss),
            pressure: u64::from(weights.pressure) * u64::from(metric.pressure),
            exposure: u64::from(weights.exposure) * u64::from(metric.exposure),
            switching: u64::from(weights.switching) * u64::from(metric.switching),
        };
        eligible.push((terms.total()?, candidate.route_id.clone()));
        explanation.push(CandidateExplanation {
            route_id: candidate.route_id.clone(),
            allowed: true,
            rejections: Vec::new(),
            terms: Some(terms),
        });
    }
    eligible.sort();
    let Some((action_score, selected)) = eligible.first().cloned() else {
        let schema_version = 1;
        let denial = RouteDenial {
            code: RouteDenialCode::NoEligibleCandidate,
            candidates: explanation,
            snapshot_digest,
            route_policy_digest,
            metric_snapshot_digest,
        };
        return Ok(RouteDecision::Denied {
            schema_version,
            decision_digest: denied_digest(schema_version, &denial),
            denial,
        });
    };
    let schema_version = 1;
    let plan = RoutePlan {
        selected: selected.clone(),
        action_score,
        explanation: RouteExplanation {
            candidates: explanation,
            selected,
            tie_breaker: "lexicographically smallest stable route_id".into(),
        },
        snapshot_digest,
        route_policy_digest,
        metric_snapshot_digest,
    };
    Ok(RouteDecision::Selected {
        schema_version,
        decision_digest: selected_digest(schema_version, &plan),
        plan,
    })
}

fn selected_digest(schema_version: u16, plan: &RoutePlan) -> Sha256Digest {
    Sha256Digest::of_json(&serde_json::json!({
        "status": "selected",
        "schema_version": schema_version,
        "plan": plan,
    }))
}

fn denied_digest(schema_version: u16, denial: &RouteDenial) -> Sha256Digest {
    Sha256Digest::of_json(&serde_json::json!({
        "status": "denied",
        "schema_version": schema_version,
        "denial": denial,
    }))
}

fn validate_explanations(
    explanations: &[CandidateExplanation],
    require_all_denied: bool,
) -> Result<(), RouteError> {
    if explanations
        .windows(2)
        .any(|pair| pair[0].route_id >= pair[1].route_id)
    {
        return Err(RouteError::DecisionContractInvalid);
    }
    for candidate in explanations {
        if candidate.route_id.0.is_empty() {
            return Err(RouteError::DecisionContractInvalid);
        }
        if candidate.allowed {
            if require_all_denied || !candidate.rejections.is_empty() || candidate.terms.is_none() {
                return Err(RouteError::DecisionContractInvalid);
            }
        } else if candidate.terms.is_some()
            || candidate.rejections.is_empty()
            || candidate
                .rejections
                .iter()
                .any(|rejection| rejection.trim().is_empty())
            || candidate
                .rejections
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(RouteError::DecisionContractInvalid);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(id: &str) -> RouteCandidate {
        RouteCandidate {
            route_id: RouteId(id.into()),
            endpoint_id: id.into(),
            hard_constraints: ConstraintResult {
                allowed: true,
                rejections: vec![],
            },
            metrics: RouteMetricSnapshot {
                latency: 1,
                cost: 1,
                failure: 1,
                pressure: 1,
                exposure: 1,
                switching: 1,
            },
            semantic_loss: 0,
        }
    }

    fn weights() -> RouteWeights {
        RouteWeights {
            latency: 10,
            cost: 30,
            failure: 30,
            semantic_loss: 1_000,
            pressure: 20,
            exposure: 50,
            switching: 10,
        }
    }

    #[test]
    fn reordering_does_not_change_route() {
        let first = plan(vec![candidate("b"), candidate("a")], weights()).unwrap();
        let second = plan(vec![candidate("a"), candidate("b")], weights()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.selected, RouteId("a".into()));
    }

    #[test]
    fn hard_constraints_run_before_scoring() {
        let mut forbidden = candidate("a");
        forbidden.hard_constraints = ConstraintResult {
            allowed: false,
            rejections: vec!["tenant mismatch".into()],
        };
        assert_eq!(
            plan(vec![forbidden, candidate("b")], weights())
                .unwrap()
                .selected,
            RouteId("b".into())
        );
    }

    #[test]
    fn all_rejected_candidates_return_a_digest_bound_denial() {
        let mut tenant_mismatch = candidate("tenant-mismatch");
        tenant_mismatch.hard_constraints = ConstraintResult {
            allowed: false,
            rejections: vec!["tenant scope mismatch".into()],
        };
        let mut budget_exhausted = candidate("budget-exhausted");
        budget_exhausted.hard_constraints = ConstraintResult {
            allowed: false,
            rejections: vec!["monetary budget exhausted".into()],
        };

        assert_eq!(
            plan(
                vec![tenant_mismatch.clone(), budget_exhausted.clone()],
                weights(),
            ),
            Err(RouteError::NoEligibleCandidate)
        );
        let first = decide(
            vec![tenant_mismatch.clone(), budget_exhausted.clone()],
            weights(),
        )
        .unwrap();
        let second = decide(vec![budget_exhausted, tenant_mismatch], weights()).unwrap();
        assert_eq!(first, second);
        let RouteDecision::Denied {
            schema_version,
            denial,
            ..
        } = first
        else {
            panic!("all rejected candidates must deny");
        };
        assert_eq!(schema_version, 1);
        assert_eq!(denial.code, RouteDenialCode::NoEligibleCandidate);
        assert_eq!(denial.candidates[0].route_id.0, "budget-exhausted");
        assert_eq!(
            denial.candidates[0].rejections,
            vec!["monetary budget exhausted"]
        );
        assert_eq!(denial.candidates[1].route_id.0, "tenant-mismatch");
        assert_eq!(
            denial.candidates[1].rejections,
            vec!["tenant scope mismatch"]
        );
        assert!(denial.candidates.iter().all(|candidate| {
            !candidate.allowed && candidate.terms.is_none() && !candidate.rejections.is_empty()
        }));
        let decision_digest = denied_digest(schema_version, &denial);
        let encoded = serde_json::to_value(RouteDecision::Denied {
            schema_version,
            decision_digest,
            denial,
        })
        .unwrap();
        assert_eq!(encoded["status"], "denied");
        assert_eq!(encoded["denial"]["code"], "GM_ROUTE_NO_ELIGIBLE_CANDIDATE");
        assert!(
            encoded["decision_digest"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
    }

    #[test]
    fn duplicate_route_ids_and_unexplained_denials_fail_closed() {
        assert_eq!(
            decide(
                vec![candidate("duplicate"), candidate("duplicate")],
                weights(),
            ),
            Err(RouteError::DuplicateRouteId)
        );
        let mut unexplained = candidate("unexplained");
        unexplained.hard_constraints.allowed = false;
        assert_eq!(
            decide(vec![unexplained], weights()),
            Err(RouteError::RejectionRequired)
        );
        assert_eq!(
            decide(vec![candidate("")], weights()),
            Err(RouteError::InvalidRouteId)
        );
        let mut blank = candidate("blank");
        blank.hard_constraints = ConstraintResult {
            allowed: false,
            rejections: vec!["   ".into()],
        };
        assert_eq!(
            decide(vec![blank], weights()),
            Err(RouteError::RejectionRequired)
        );
    }

    #[test]
    fn denial_reason_order_is_canonical_and_tampering_is_detected() {
        let mut denied = candidate("denied");
        denied.hard_constraints = ConstraintResult {
            allowed: false,
            rejections: vec!["z reason".into(), "a reason".into(), "z reason".into()],
        };
        let decision = decide(vec![denied], weights()).unwrap();
        decision.verify_integrity().unwrap();
        let RouteDecision::Denied { denial, .. } = &decision else {
            panic!("candidate must be denied");
        };
        assert_eq!(
            denial.candidates[0].rejections,
            vec!["a reason".to_string(), "z reason".to_string()]
        );

        let mut value = serde_json::to_value(decision).unwrap();
        value["denial"]["candidates"][0]["rejections"][0] = "tampered".into();
        let tampered: RouteDecision = serde_json::from_value(value).unwrap();
        assert_eq!(
            tampered.verify_integrity(),
            Err(RouteError::DecisionDigestMismatch)
        );
    }

    #[test]
    fn exact_ties_use_the_documented_lexical_breaker() {
        let route = plan(vec![candidate("z"), candidate("a")], weights()).unwrap();
        assert_eq!(route.selected, RouteId("a".into()));
        assert_eq!(
            route.explanation.tie_breaker,
            "lexicographically smallest stable route_id"
        );
    }

    #[test]
    fn switching_penalty_prevents_flapping_for_subthreshold_changes() {
        let mut incumbent = candidate("incumbent");
        incumbent.metrics.latency = 11;
        incumbent.metrics.switching = 0;
        let mut alternative = candidate("alternative");
        alternative.metrics.latency = 10;
        alternative.metrics.switching = 2;
        assert_eq!(
            plan(vec![alternative, incumbent], weights())
                .unwrap()
                .selected,
            RouteId("incumbent".into())
        );
    }

    #[test]
    fn unnormalized_metrics_and_weights_fail_closed() {
        let mut invalid = candidate("invalid");
        invalid.semantic_loss = 10_001;
        assert_eq!(
            plan(vec![invalid], weights()),
            Err(RouteError::MetricOutOfRange)
        );
        let mut invalid_weights = weights();
        invalid_weights.switching = 10_001;
        assert_eq!(
            plan(vec![candidate("route")], invalid_weights),
            Err(RouteError::MetricOutOfRange)
        );

        let mut boundary = candidate("boundary");
        boundary.metrics.latency = 10_000;
        boundary.semantic_loss = 10_000;
        let mut boundary_weights = weights();
        boundary_weights.latency = 10_000;
        assert!(plan(vec![boundary], boundary_weights).is_ok());
    }

    #[test]
    fn every_score_term_is_independently_weighted_and_included_once() {
        let terms = ScoreTerms {
            latency: 2,
            cost: 3,
            failure: 5,
            semantic_loss: 7,
            pressure: 11,
            exposure: 13,
            switching: 17,
        };
        assert_eq!(terms.total(), Ok(58));

        let candidate = RouteCandidate {
            route_id: RouteId("only".into()),
            endpoint_id: "endpoint".into(),
            hard_constraints: ConstraintResult {
                allowed: true,
                rejections: vec![],
            },
            metrics: RouteMetricSnapshot {
                latency: 2,
                cost: 3,
                failure: 5,
                pressure: 7,
                exposure: 11,
                switching: 13,
            },
            semantic_loss: 17,
        };
        let weights = RouteWeights {
            latency: 19,
            cost: 23,
            failure: 29,
            semantic_loss: 31,
            pressure: 37,
            exposure: 41,
            switching: 43,
        };
        let plan = plan(vec![candidate], weights).unwrap();
        let expected = ScoreTerms {
            latency: 38,
            cost: 69,
            failure: 145,
            semantic_loss: 527,
            pressure: 259,
            exposure: 451,
            switching: 559,
        };
        assert_eq!(plan.explanation.candidates[0].terms, Some(expected.clone()));
        assert_eq!(plan.action_score, expected.total().unwrap());
    }

    fn external_decision_with_scores(latency: u64, cost: u64) -> RouteDecision {
        let decision = decide(vec![candidate("external")], weights()).unwrap();
        let mut value = serde_json::to_value(decision).unwrap();
        value["plan"]["explanation"]["candidates"][0]["terms"]["latency"] = latency.into();
        value["plan"]["explanation"]["candidates"][0]["terms"]["cost"] = cost.into();
        let mut external: RouteDecision = serde_json::from_value(value).unwrap();
        let RouteDecision::Selected {
            schema_version,
            decision_digest,
            plan,
        } = &mut external
        else {
            panic!("candidate must be selected");
        };
        *decision_digest = selected_digest(*schema_version, plan);
        external
    }

    #[test]
    fn external_score_overflow_and_out_of_range_terms_fail_closed() {
        let overflow = external_decision_with_scores(u64::MAX, 1);
        assert_eq!(
            overflow.verify_integrity(),
            Err(RouteError::DecisionScoreOutOfRange)
        );

        let out_of_range = external_decision_with_scores(MAX_SCORE_TERM + 1, 0);
        assert_eq!(
            out_of_range.verify_integrity(),
            Err(RouteError::DecisionScoreOutOfRange)
        );

        let decision = decide(vec![candidate("external")], weights()).unwrap();
        let mut value = serde_json::to_value(decision).unwrap();
        value["plan"]["action_score"] = (MAX_ACTION_SCORE + 1).into();
        let mut out_of_range_score: RouteDecision = serde_json::from_value(value).unwrap();
        let RouteDecision::Selected {
            schema_version,
            decision_digest,
            plan,
        } = &mut out_of_range_score
        else {
            panic!("candidate must be selected");
        };
        *decision_digest = selected_digest(*schema_version, plan);
        assert_eq!(
            out_of_range_score.verify_integrity(),
            Err(RouteError::DecisionScoreOutOfRange)
        );
    }

    #[test]
    fn checked_in_schema_matches_generated_score_bounds() {
        let schema: serde_json::Value = serde_json::from_str(include_str!(
            "../../../schemas/gaugemesh-route-decision-v1.schema.json"
        ))
        .unwrap();
        for term in [
            "latency",
            "cost",
            "failure",
            "semantic_loss",
            "pressure",
            "exposure",
            "switching",
        ] {
            assert_eq!(
                schema["$defs"]["scoreTerms"]["properties"][term]["maximum"],
                MAX_SCORE_TERM
            );
        }
        assert_eq!(
            schema["$defs"]["routePlan"]["properties"]["action_score"]["maximum"],
            MAX_ACTION_SCORE
        );
    }
}
