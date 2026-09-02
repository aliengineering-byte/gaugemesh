use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::digest::Sha256Digest;

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
    pub fn total(&self) -> u64 {
        self.latency
            + self.cost
            + self.failure
            + self.semantic_loss
            + self.pressure
            + self.exposure
            + self.switching
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
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RouteDecision {
    Selected { schema_version: u16, plan: RoutePlan },
    Denied {
        schema_version: u16,
        denial: RouteDenial,
    },
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RouteError {
    #[error("GM_ROUTE_NO_ELIGIBLE_CANDIDATE")]
    NoEligibleCandidate,
    #[error("GM_ROUTE_METRIC_OUT_OF_RANGE")]
    MetricOutOfRange,
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
    candidates.sort_by(|left, right| left.route_id.cmp(&right.route_id));
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
        eligible.push((terms.total(), candidate.route_id.clone()));
        explanation.push(CandidateExplanation {
            route_id: candidate.route_id.clone(),
            allowed: true,
            rejections: Vec::new(),
            terms: Some(terms),
        });
    }
    eligible.sort();
    let Some((action_score, selected)) = eligible.first().cloned() else {
        return Ok(RouteDecision::Denied {
            schema_version: 1,
            denial: RouteDenial {
                code: RouteDenialCode::NoEligibleCandidate,
                candidates: explanation,
                snapshot_digest,
                route_policy_digest,
                metric_snapshot_digest,
            },
        });
    };
    Ok(RouteDecision::Selected {
        schema_version: 1,
        plan: RoutePlan {
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
        },
    })
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
        let encoded = serde_json::to_value(RouteDecision::Denied {
            schema_version,
            denial,
        })
        .unwrap();
        assert_eq!(encoded["status"], "denied");
        assert_eq!(
            encoded["denial"]["code"],
            "GM_ROUTE_NO_ELIGIBLE_CANDIDATE"
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
        assert_eq!(terms.total(), 58);

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
        assert_eq!(plan.action_score, expected.total());
    }
}
