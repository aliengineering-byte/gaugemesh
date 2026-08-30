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
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RouteError {
    #[error("GM_ROUTE_NO_ELIGIBLE_CANDIDATE")]
    NoEligibleCandidate,
    #[error("GM_ROUTE_METRIC_OUT_OF_RANGE")]
    MetricOutOfRange,
}

pub fn plan(
    mut candidates: Vec<RouteCandidate>,
    weights: RouteWeights,
) -> Result<RoutePlan, RouteError> {
    candidates.sort_by(|left, right| left.route_id.cmp(&right.route_id));
    let snapshot_digest = Sha256Digest::of_json(
        &serde_json::to_value((&candidates, weights)).expect("route snapshot serializes"),
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
    let (action_score, selected) = eligible
        .first()
        .cloned()
        .ok_or(RouteError::NoEligibleCandidate)?;
    Ok(RoutePlan {
        selected: selected.clone(),
        action_score,
        explanation: RouteExplanation {
            candidates: explanation,
            selected,
            tie_breaker: "lexicographically smallest stable route_id".into(),
        },
        snapshot_digest,
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
}
