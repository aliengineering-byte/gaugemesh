use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::digest::Sha256Digest;

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelIdentity {
    pub provider: String,
    pub endpoint_identity: Sha256Digest,
    pub provider_model_id: String,
    pub capability_set: Vec<String>,
    pub context_limit: u64,
    pub tool_call_support: bool,
    pub structured_output_support: bool,
    pub streaming_support: bool,
    pub cost_table_version: String,
    pub policy_digest: Sha256Digest,
}

impl ModelIdentity {
    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::of_json(&serde_json::to_value(self).expect("model identity serializes"))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CostTable {
    pub version: String,
    pub input_micros_per_million_tokens: u64,
    pub output_micros_per_million_tokens: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelBudget {
    pub max_input_tokens: u64,
    pub max_output_tokens: u64,
    pub money_micros: u64,
    pub deadline_remaining_ms: u64,
    pub tool_loop_limit: u16,
    pub retry_limit: u16,
    pub provider_allowlist: Vec<String>,
    pub model_allowlist: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolMode {
    Off,
    Transparent,
    Lease,
}

impl Default for ToolMode {
    fn default() -> Self {
        Self::Off
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalMode {
    Deny,
    StaticPolicy,
    LocalCli,
    SignedWebhook,
}

impl Default for ApprovalMode {
    fn default() -> Self {
        Self::Deny
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelRouteError {
    #[error("GM_MODEL_NOT_ALLOWED")]
    ModelNotAllowed,
    #[error("GM_PROVIDER_NOT_ALLOWED")]
    ProviderNotAllowed,
    #[error("GM_MODEL_INPUT_TOKEN_BUDGET")]
    InputTokens,
    #[error("GM_MODEL_OUTPUT_TOKEN_BUDGET")]
    OutputTokens,
    #[error("GM_MODEL_MONEY_BUDGET")]
    Money,
    #[error("GM_MODEL_DEADLINE_EXHAUSTED")]
    Deadline,
    #[error("GM_MODEL_TOOL_LOOP_DISABLED")]
    ToolLoop,
}

pub fn estimate_cost_micros(input: u64, output: u64, table: &CostTable) -> u64 {
    input
        .saturating_mul(table.input_micros_per_million_tokens)
        .saturating_add(output.saturating_mul(table.output_micros_per_million_tokens))
        .saturating_add(999_999)
        / 1_000_000
}

pub fn enforce_budget(
    identity: &ModelIdentity,
    table: &CostTable,
    budget: &ModelBudget,
    estimated_input: u64,
    requested_output: u64,
    tool_mode: ToolMode,
) -> Result<u64, ModelRouteError> {
    if !budget.provider_allowlist.is_empty()
        && !budget.provider_allowlist.contains(&identity.provider)
    {
        return Err(ModelRouteError::ProviderNotAllowed);
    }
    if !budget.model_allowlist.is_empty()
        && !budget.model_allowlist.contains(&identity.provider_model_id)
    {
        return Err(ModelRouteError::ModelNotAllowed);
    }
    if estimated_input > budget.max_input_tokens || estimated_input > identity.context_limit {
        return Err(ModelRouteError::InputTokens);
    }
    if requested_output > budget.max_output_tokens {
        return Err(ModelRouteError::OutputTokens);
    }
    if budget.deadline_remaining_ms == 0 {
        return Err(ModelRouteError::Deadline);
    }
    if tool_mode != ToolMode::Off && budget.tool_loop_limit == 0 {
        return Err(ModelRouteError::ToolLoop);
    }
    let estimated = estimate_cost_micros(estimated_input, requested_output, table);
    if estimated > budget.money_micros {
        return Err(ModelRouteError::Money);
    }
    Ok(estimated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> ModelIdentity {
        ModelIdentity {
            provider: "fixture".into(),
            endpoint_identity: Sha256Digest::of_bytes("local"),
            provider_model_id: "deterministic-echo".into(),
            capability_set: vec!["chat".into(), "streaming".into()],
            context_limit: 4_096,
            tool_call_support: true,
            structured_output_support: false,
            streaming_support: true,
            cost_table_version: "fixture-v1".into(),
            policy_digest: Sha256Digest::of_bytes("deny-remote"),
        }
    }

    fn budget() -> ModelBudget {
        ModelBudget {
            max_input_tokens: 100,
            max_output_tokens: 100,
            money_micros: 10,
            deadline_remaining_ms: 1_000,
            tool_loop_limit: 1,
            retry_limit: 0,
            provider_allowlist: vec!["fixture".into()],
            model_allowlist: vec!["deterministic-echo".into()],
        }
    }

    #[test]
    fn hard_money_budget_rejects_before_provider() {
        let mut budget = budget();
        budget.money_micros = 0;
        let table = CostTable {
            version: "fixture-v1".into(),
            input_micros_per_million_tokens: 1_000_000,
            output_micros_per_million_tokens: 1_000_000,
        };
        assert_eq!(
            enforce_budget(&identity(), &table, &budget, 1, 1, ToolMode::Off),
            Err(ModelRouteError::Money)
        );
    }

    #[test]
    fn friendly_alias_is_not_model_identity() {
        assert_ne!(identity().digest(), Sha256Digest::of_bytes("local"));
    }

    #[test]
    fn tool_mode_requires_a_round_budget() {
        let mut budget = budget();
        budget.tool_loop_limit = 0;
        let table = CostTable {
            version: "fixture-v1".into(),
            input_micros_per_million_tokens: 0,
            output_micros_per_million_tokens: 0,
        };
        assert_eq!(
            enforce_budget(&identity(), &table, &budget, 1, 1, ToolMode::Lease),
            Err(ModelRouteError::ToolLoop)
        );
    }
}
