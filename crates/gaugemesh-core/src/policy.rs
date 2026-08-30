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
    }
    document.rules.sort_by(|left, right| {
        (left.phase, left.priority, &left.id).cmp(&(right.phase, right.priority, &right.id))
    });
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
}
