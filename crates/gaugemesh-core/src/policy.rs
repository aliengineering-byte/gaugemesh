use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum PolicyPhase {
    Discovery,
    RequestMetadata,
    RequestBody,
    ResponseMetadata,
    ResponseBody,
    PostEffect,
    Cleanup,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffect {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    pub field: String,
    pub equals: String,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub id: String,
    pub phase: PolicyPhase,
    pub priority: u32,
    pub effect: PolicyEffect,
    #[serde(default)]
    pub all: Vec<Condition>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    pub default: PolicyEffect,
    pub rules: Vec<PolicyRule>,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PolicyCompileError {
    #[error("GM_POLICY_UNKNOWN_FIELD:{0}")]
    UnknownField(String),
    #[error("GM_POLICY_FIELD_UNAVAILABLE:{field}:{phase:?}")]
    FieldUnavailable { field: String, phase: PolicyPhase },
    #[error("GM_POLICY_AMBIGUOUS_PRIORITY:{0}")]
    AmbiguousPriority(u32),
    #[error("GM_POLICY_DUPLICATE_RULE:{0}")]
    DuplicateRule(String),
    #[error("GM_POLICY_CONTRADICTORY_RULE:{0}")]
    ContradictoryRule(String),
    #[error("GM_POLICY_UNREACHABLE_RULE:{0}")]
    UnreachableRule(String),
}

#[derive(Clone, Debug)]
pub struct CompiledPolicy(PolicyDocument);

impl CompiledPolicy {
    pub fn document(&self) -> &PolicyDocument {
        &self.0
    }

    pub fn evaluate(&self, phase: PolicyPhase, fields: &BTreeMap<String, String>) -> PolicyEffect {
        self.0
            .rules
            .iter()
            .filter(|rule| rule.phase == phase)
            .filter(|rule| {
                rule.all.iter().all(|condition| {
                    fields
                        .get(&condition.field)
                        .is_some_and(|value| value == &condition.equals)
                })
            })
            .min_by_key(|rule| rule.priority)
            .map_or(self.0.default, |rule| rule.effect)
    }
}

pub fn compile(mut document: PolicyDocument) -> Result<CompiledPolicy, PolicyCompileError> {
    let availability = field_availability();
    let mut ids = BTreeSet::new();
    let mut priorities = BTreeSet::new();
    for rule in &document.rules {
        if !ids.insert(rule.id.clone()) {
            return Err(PolicyCompileError::DuplicateRule(rule.id.clone()));
        }
        if !priorities.insert((rule.phase, rule.priority)) {
            return Err(PolicyCompileError::AmbiguousPriority(rule.priority));
        }
        for condition in &rule.all {
            let available = availability
                .get(condition.field.as_str())
                .ok_or_else(|| PolicyCompileError::UnknownField(condition.field.clone()))?;
            if rule.phase < *available {
                return Err(PolicyCompileError::FieldUnavailable {
                    field: condition.field.clone(),
                    phase: rule.phase,
                });
            }
        }
        let mut equalities = BTreeMap::new();
        for condition in &rule.all {
            if equalities
                .insert(&condition.field, &condition.equals)
                .is_some_and(|previous| previous != &condition.equals)
            {
                return Err(PolicyCompileError::ContradictoryRule(rule.id.clone()));
            }
        }
    }
    document.rules.sort_by(|left, right| {
        (left.phase, left.priority, &left.id).cmp(&(right.phase, right.priority, &right.id))
    });
    let mut terminal_phases = BTreeSet::new();
    for rule in &document.rules {
        if terminal_phases.contains(&rule.phase) {
            return Err(PolicyCompileError::UnreachableRule(rule.id.clone()));
        }
        if rule.all.is_empty() {
            terminal_phases.insert(rule.phase);
        }
    }
    Ok(CompiledPolicy(document))
}

fn field_availability() -> BTreeMap<&'static str, PolicyPhase> {
    BTreeMap::from([
        ("principal.id", PolicyPhase::Discovery),
        ("principal.group", PolicyPhase::Discovery),
        ("tenant.id", PolicyPhase::Discovery),
        ("capability.source", PolicyPhase::Discovery),
        ("capability.kind", PolicyPhase::Discovery),
        ("request.protocol", PolicyPhase::RequestMetadata),
        ("request.data_classification", PolicyPhase::RequestMetadata),
        ("request.argument", PolicyPhase::RequestBody),
        ("response.status", PolicyPhase::ResponseMetadata),
        ("response.body_classification", PolicyPhase::ResponseBody),
        ("effect.observed", PolicyPhase::PostEffect),
        ("cleanup.result", PolicyPhase::Cleanup),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_field_at_discovery_fails_at_compile_time() {
        let result = compile(PolicyDocument {
            default: PolicyEffect::Deny,
            rules: vec![PolicyRule {
                id: "bad".into(),
                phase: PolicyPhase::Discovery,
                priority: 1,
                effect: PolicyEffect::Allow,
                all: vec![Condition {
                    field: "request.argument".into(),
                    equals: "x".into(),
                }],
            }],
        });
        assert!(matches!(
            result,
            Err(PolicyCompileError::FieldUnavailable { .. })
        ));
    }

    #[test]
    fn contradictory_and_unreachable_rules_fail_at_compile_time() {
        let contradictory = PolicyDocument {
            default: PolicyEffect::Deny,
            rules: vec![PolicyRule {
                id: "never".into(),
                phase: PolicyPhase::Discovery,
                priority: 1,
                effect: PolicyEffect::Allow,
                all: vec![
                    Condition {
                        field: "tenant.id".into(),
                        equals: "a".into(),
                    },
                    Condition {
                        field: "tenant.id".into(),
                        equals: "b".into(),
                    },
                ],
            }],
        };
        assert_eq!(
            compile(contradictory).unwrap_err(),
            PolicyCompileError::ContradictoryRule("never".into())
        );

        let unreachable = PolicyDocument {
            default: PolicyEffect::Deny,
            rules: vec![
                PolicyRule {
                    id: "terminal".into(),
                    phase: PolicyPhase::Discovery,
                    priority: 1,
                    effect: PolicyEffect::Deny,
                    all: vec![],
                },
                PolicyRule {
                    id: "hidden".into(),
                    phase: PolicyPhase::Discovery,
                    priority: 2,
                    effect: PolicyEffect::Allow,
                    all: vec![Condition {
                        field: "tenant.id".into(),
                        equals: "a".into(),
                    }],
                },
            ],
        };
        assert_eq!(
            compile(unreachable).unwrap_err(),
            PolicyCompileError::UnreachableRule("hidden".into())
        );
    }

    #[test]
    fn evaluation_matches_phase_and_every_condition_then_falls_back_to_default() {
        let policy = compile(PolicyDocument {
            default: PolicyEffect::Deny,
            rules: vec![PolicyRule {
                id: "tenant-mcp".into(),
                phase: PolicyPhase::RequestMetadata,
                priority: 7,
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
        .unwrap();
        assert_eq!(policy.document().default, PolicyEffect::Deny);
        assert_eq!(policy.document().rules[0].id, "tenant-mcp");

        let matching = BTreeMap::from([
            ("tenant.id".into(), "tenant-a".into()),
            ("request.protocol".into(), "mcp".into()),
        ]);
        assert_eq!(
            policy.evaluate(PolicyPhase::RequestMetadata, &matching),
            PolicyEffect::Allow
        );
        assert_eq!(
            policy.evaluate(PolicyPhase::Discovery, &matching),
            PolicyEffect::Deny
        );

        let mut mismatch = matching;
        mismatch.insert("request.protocol".into(), "openai".into());
        assert_eq!(
            policy.evaluate(PolicyPhase::RequestMetadata, &mismatch),
            PolicyEffect::Deny
        );
    }
}
