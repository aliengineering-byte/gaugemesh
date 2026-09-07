//! Application-level, caller-supplied DAG composition over existing durable Tasks.
//! No scheduler, command execution, compensation, or alternative task dispatch path.
use anyhow::{Context, Result, bail, ensure};
use gaugemesh_core::{
    context::SideEffectClass,
    digest::Sha256Digest,
    federation::Federation,
    run::RunRecord,
    storage::{LeaseStorage, SqliteStorage},
    task::TaskRouteCaller,
};
use rmcp::model::{CallToolResponse, CancelTaskParams, GetTaskParams};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
#[cfg(unix)]
use std::io::Read;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use crate::{
    auth::AuthenticatedIdentity, mcp::authorize_current_invocation, task_proxy::TaskProxy,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunPlan {
    pub schema_version: String,
    pub run_key: String,
    pub deadline_unix_ms: u64,
    pub max_concurrency: usize,
    pub max_attempts: u16,
    pub failure_policy: String,
    pub uncertainty_policy: String,
    pub cancellation_policy: String,
    pub artifact_root: PathBuf,
    pub steps: Vec<Step>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Step {
    pub id: String,
    pub depends_on: Vec<String>,
    pub alias: String,
    pub capability_id: Sha256Digest,
    pub provider_interface_version: String,
    pub arguments: BTreeMap<String, Input>,
    pub inputs_sha256: Sha256Digest,
    pub policy: Policy,
    pub policy_sha256: Sha256Digest,
    pub permitted_effect: SideEffectClass,
    pub max_runtime_ms: u64,
    pub max_artifact_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Input {
    Literal { value: Value },
    Predecessor { step: String, pointer: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Policy {
    pub schema_version: String,
    pub checks: Vec<Check>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub pointer: String,
    pub expected: Value,
    pub required: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    #[default]
    Pending,
    Submitting,
    Routed,
    Verified,
    Failed,
    Unknown,
    Cancelled,
    Skipped,
}

impl Phase {
    fn active(&self) -> bool {
        matches!(self, Self::Submitting | Self::Routed)
    }
    fn blocks(&self) -> bool {
        matches!(self, Self::Failed | Self::Unknown | Self::Cancelled)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StepState {
    pub phase: Phase,
    pub arguments: Option<Map<String, Value>>,
    pub submission: Option<Value>,
    pub task_id: Option<String>,
    pub terminal: Option<Value>,
    pub verified_artifact: Option<Value>,
    pub verification: Option<Value>,
    pub cancellation_intent: bool,
    pub cancellation_request_sent: bool,
    pub cancellation_acknowledged: bool,
    pub diagnostic: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct State {
    plan: RunPlan,
    accepted_at_unix_ms: u64,
    cancel_requested: bool,
    deadline_observed: bool,
    steps: BTreeMap<String, StepState>,
}

fn hash<T: Serialize>(value: &T) -> Result<Sha256Digest> {
    Ok(Sha256Digest::of_json(&serde_json::to_value(value)?))
}

fn now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

fn pointer_valid(value: &str) -> bool {
    value.len() <= 256
        && value.starts_with('/')
        && !value.contains("/binding")
        && !value.contains("/artifact")
        && value
            .split('~')
            .skip(1)
            .all(|part| part.starts_with('0') || part.starts_with('1'))
}

impl RunPlan {
    fn validate(&self, accepted_at: u64) -> Result<()> {
        ensure!(
            self.schema_version == "gaugemesh.run-plan/1",
            "GM_RUN_SCHEMA_UNSUPPORTED"
        );
        ensure!(identifier(&self.run_key), "GM_RUN_KEY_INVALID");
        ensure!(
            !self.steps.is_empty()
                && self.steps.len() <= 16
                && (1..=4).contains(&self.max_concurrency)
                && self.max_attempts == 1,
            "GM_RUN_BOUND_UNSUPPORTED"
        );
        ensure!(
            self.deadline_unix_ms > accepted_at
                && self.deadline_unix_ms <= accepted_at.saturating_add(3_600_000),
            "GM_RUN_DEADLINE_INVALID"
        );
        ensure!(
            self.failure_policy == "fail_fast_account_inflight"
                && self.uncertainty_policy == "stop_no_replay"
                && self.cancellation_policy == "intent_then_poll",
            "GM_RUN_GUARANTEE_UNSUPPORTED"
        );
        ensure!(
            self.artifact_root.is_absolute(),
            "GM_RUN_ARTIFACT_ROOT_INVALID"
        );
        let ids: BTreeSet<_> = self.steps.iter().map(|s| &s.id).collect();
        ensure!(ids.len() == self.steps.len(), "GM_RUN_DUPLICATE_STEP");
        for step in &self.steps {
            ensure!(
                identifier(&step.id)
                    && step.id.len() <= 64
                    && !step.alias.is_empty()
                    && step.alias.len() <= 256,
                "GM_RUN_STEP_INVALID"
            );
            ensure!(
                step.depends_on.len() <= 8
                    && step.depends_on.iter().collect::<BTreeSet<_>>().len()
                        == step.depends_on.len()
                    && step
                        .depends_on
                        .iter()
                        .all(|id| ids.contains(id) && id != &step.id),
                "GM_RUN_EDGE_INVALID"
            );
            ensure!(
                self.steps
                    .iter()
                    .filter(|s| s.depends_on.contains(&step.id))
                    .count()
                    <= 8,
                "GM_RUN_FANOUT_BOUND"
            );
            ensure!(
                step.arguments.len() <= 32
                    && serde_json::to_vec(&step.arguments)?.len() <= 8_192
                    && hash(&step.arguments)? == step.inputs_sha256,
                "GM_RUN_INPUT_IDENTITY_INVALID"
            );
            for input in step.arguments.values() {
                if let Input::Predecessor {
                    step: source,
                    pointer,
                } = input
                {
                    ensure!(
                        step.depends_on.contains(source) && pointer_valid(pointer),
                        "GM_RUN_REFERENCE_INVALID"
                    );
                }
            }
            ensure!(
                step.policy.schema_version == "gaugemesh.json-artifact-policy/1"
                    && !step.policy.checks.is_empty()
                    && step.policy.checks.len() <= 16
                    && step.policy.checks.iter().any(|c| c.required)
                    && step.policy.checks.iter().all(|c| pointer_valid(&c.pointer))
                    && serde_json::to_vec(&step.policy)?.len() <= 32_768
                    && hash(&step.policy)? == step.policy_sha256,
                "GM_RUN_POLICY_INVALID"
            );
            ensure!(
                step.permitted_effect == SideEffectClass::NonIdempotentWrite
                    && (1..=30_000).contains(&step.max_runtime_ms)
                    && (1..=1_048_576).contains(&step.max_artifact_bytes),
                "GM_RUN_EFFECT_OR_BOUND_UNSUPPORTED"
            );
        }
        let mut visited = BTreeSet::new();
        loop {
            let old = visited.len();
            for step in &self.steps {
                if step.depends_on.iter().all(|id| visited.contains(id)) {
                    visited.insert(step.id.clone());
                }
            }
            if old == visited.len() {
                break;
            }
        }
        ensure!(visited.len() == self.steps.len(), "GM_RUN_CYCLE");
        Ok(())
    }
}

pub struct RunDriver {
    store: Arc<SqliteStorage>,
    // Bounded, single-process driver. SQLite CAS also fences stale snapshots from other processes.
    drive_lock: tokio::sync::Mutex<()>,
}

pub struct RunContext<'a> {
    pub federation: &'a Federation,
    pub leases: &'a dyn LeaseStorage,
    pub proxy: &'a TaskProxy,
    pub identity: &'a AuthenticatedIdentity,
}

impl RunDriver {
    pub fn new(store: Arc<SqliteStorage>) -> Self {
        Self {
            store,
            drive_lock: tokio::sync::Mutex::new(()),
        }
    }

    pub async fn call(&self, args: &Map<String, Value>, context: RunContext<'_>) -> Result<Value> {
        // Remote Runs remain disabled until their public multi-principal surface is qualified.
        ensure!(
            context.identity.principal.0 == "local-demo" && context.identity.tenant.0 == "local",
            "GM_RUN_REMOTE_NOT_QUALIFIED"
        );
        let caller = TaskRouteCaller::new(
            context.identity.principal.clone(),
            context.identity.tenant.clone(),
        )?;
        let action = args
            .get("action")
            .and_then(Value::as_str)
            .context("GM_RUN_ACTION_REQUIRED")?;
        if action == "submit" {
            let value = args.get("plan").context("GM_RUN_PLAN_REQUIRED")?;
            ensure!(
                serde_json::to_vec(value)?.len() <= 256 * 1024,
                "GM_RUN_PLAN_BOUND"
            );
            let plan: RunPlan =
                serde_json::from_value(value.clone()).context("GM_RUN_PLAN_INVALID")?;
            let accepted_at = now()?;
            // Validate structural/time rules against original acceptance on retained-key retries.
            // begin_run performs the final atomic identity comparison; no dispatch occurs here.
            let existing = self.store.find_run(&caller, &plan.run_key)?;
            let validation_time = existing
                .as_ref()
                .and_then(|r| r.data["acceptedAtUnixMs"].as_u64())
                .unwrap_or(accepted_at);
            plan.validate(validation_time)?;
            open_root(&plan.artifact_root)?;
            authorize_plan(&plan, args, &context)?;
            let states = plan
                .steps
                .iter()
                .map(|s| (s.id.clone(), StepState::default()))
                .collect();
            let state = State {
                plan: plan.clone(),
                accepted_at_unix_ms: accepted_at,
                cancel_requested: false,
                deadline_observed: false,
                steps: states,
            };
            return summary(self.store.begin_run(
                caller,
                &plan.run_key,
                serde_json::to_value(state)?,
            )?);
        }
        let id = args
            .get("runId")
            .and_then(Value::as_str)
            .context("GM_RUN_ID_REQUIRED")?;
        ensure!(id.len() <= 128, "GM_RUN_ID_INVALID");
        let mut record = self
            .store
            .get_run(&caller, id)?
            .context("GM_RUN_NOT_FOUND")?;
        match action {
            "status" => summary(record),
            "export" => Ok(serde_json::to_value(record)?),
            "verify" => verify_record(&record),
            "cancel" => {
                let mut state = state_from(&record)?;
                if !state.cancel_requested {
                    state.cancel_requested = true;
                    record = self.store.advance_run(
                        &record,
                        serde_json::to_value(state)?,
                        "cancellation_intent",
                    )?;
                }
                summary(record)
            }
            "resume" => {
                let _guard = self.drive_lock.lock().await;
                record = self
                    .store
                    .get_run(&caller, id)?
                    .context("GM_RUN_NOT_FOUND")?;
                self.drive(record, args, &context).await
            }
            _ => bail!("GM_RUN_ACTION_UNSUPPORTED"),
        }
    }

    fn save(&self, record: &mut RunRecord, state: &State, event: &str) -> Result<()> {
        *record = self
            .store
            .advance_run(record, serde_json::to_value(state)?, event)?;
        Ok(())
    }

    async fn drive(
        &self,
        mut record: RunRecord,
        args: &Map<String, Value>,
        ctx: &RunContext<'_>,
    ) -> Result<Value> {
        let mut state = state_from(&record)?;
        if !state.cancel_requested {
            authorize_plan(&state.plan, args, ctx)?;
        }
        if now()? >= state.plan.deadline_unix_ms && !state.deadline_observed {
            state.deadline_observed = true;
            self.save(&mut record, &state, "deadline_observed")?;
        }
        // Reverify accepted artifacts on every resume, including terminal reopen.
        for step in state.plan.steps.clone() {
            let s = &state.steps[&step.id];
            if matches!(s.phase, Phase::Verified) {
                if let Err(error) = verify_step(&record.run_id, &state.plan, &step, s) {
                    let s = state.steps.get_mut(&step.id).unwrap();
                    s.phase = Phase::Failed;
                    s.diagnostic = Some(format!("GM_RUN_PREDECESSOR_INVALID:{error}"));
                    self.save(&mut record, &state, "artifact_reverification_failed")?;
                }
            }
        }
        // Recover submissions whose Task was accepted before its public ID reached this ledger.
        for step in state.plan.steps.clone() {
            if matches!(state.steps[&step.id].phase, Phase::Submitting) {
                self.submit_step(&mut record, &mut state, &step, ctx)
                    .await?;
            }
        }
        let mut outcome_observed = false;
        for step in state.plan.steps.clone() {
            let s = state.steps.get_mut(&step.id).unwrap();
            if !matches!(s.phase, Phase::Routed | Phase::Unknown) || s.task_id.is_none() {
                continue;
            }
            let id = s.task_id.clone().context("GM_RUN_STATE_INVALID")?;
            let stop = state.cancel_requested || state.deadline_observed;
            if stop && !s.cancellation_acknowledged {
                // Persist intent before attempting cancellation. An ack is not process termination.
                if !s.cancellation_intent {
                    s.cancellation_intent = true;
                    self.save(&mut record, &state, "task_cancellation_intent")?;
                }
                let cancellation = ctx
                    .proxy
                    .cancel_task(CancelTaskParams::new(id.clone()), ctx.identity)
                    .await;
                let s = state.steps.get_mut(&step.id).unwrap();
                let previous = hash(s)?;
                s.cancellation_request_sent = true;
                s.cancellation_acknowledged = cancellation.is_ok();
                if let Err(e) = cancellation {
                    s.diagnostic = Some(e.to_string());
                }
                if hash(s)? != previous {
                    self.save(&mut record, &state, "task_cancellation_response")?;
                }
            }
            let result = ctx
                .proxy
                .get_task(GetTaskParams::new(id), ctx.identity)
                .await;
            let s = state.steps.get_mut(&step.id).unwrap();
            match result {
                Err(error) => {
                    if matches!(s.phase, Phase::Unknown)
                        && s.diagnostic.as_deref() == Some(error.to_string().as_str())
                    {
                        continue;
                    }
                    s.phase = Phase::Unknown;
                    s.diagnostic = Some(error.to_string());
                }
                Ok(result) => {
                    let value = serde_json::to_value(result)?;
                    if value["_meta"]["dev.gaugemesh/taskRoute"]["routePhase"]
                        == "reconciliation_required"
                    {
                        if matches!(s.phase, Phase::Unknown) && s.terminal.as_ref() == Some(&value)
                        {
                            continue;
                        }
                        s.phase = Phase::Unknown;
                        s.terminal = Some(value);
                        s.diagnostic = Some("GM_RUN_TASK_RECONCILIATION_REQUIRED".into());
                    } else {
                        match value["status"].as_str() {
                            Some("completed") => {
                                s.terminal = Some(value);
                                match verify_step(&record.run_id, &state.plan, &step, s) {
                                    Ok((artifact, report)) => {
                                        s.phase = Phase::Verified;
                                        s.verified_artifact = Some(artifact);
                                        s.verification = Some(report);
                                    }
                                    Err(error) => {
                                        s.phase = Phase::Failed;
                                        s.diagnostic = Some(error.to_string());
                                    }
                                }
                            }
                            Some("failed") => {
                                s.phase = Phase::Failed;
                                s.terminal = Some(value);
                            }
                            Some("cancelled") => {
                                s.phase = Phase::Cancelled;
                                s.terminal = Some(value);
                            }
                            _ => continue,
                        }
                    }
                }
            }
            self.save(&mut record, &state, "task_outcome_observed")?;
            outcome_observed = true;
        }
        let stop = state.cancel_requested
            || state.deadline_observed
            || state.steps.values().any(|s| s.phase.blocks());
        if stop {
            let mut changed = false;
            for s in state.steps.values_mut() {
                if matches!(s.phase, Phase::Pending) {
                    s.phase = Phase::Skipped;
                    changed = true;
                }
            }
            if changed {
                self.save(&mut record, &state, "unsent_steps_skipped")?;
            }
            return summary(record);
        }
        // Leave verified checkpoints observable before the next explicit dispatch sweep.
        if outcome_observed {
            return summary(record);
        }
        for step in state.plan.steps.clone() {
            if state.steps.values().filter(|s| s.phase.active()).count()
                >= state.plan.max_concurrency
            {
                break;
            }
            if !matches!(state.steps[&step.id].phase, Phase::Pending)
                || !step
                    .depends_on
                    .iter()
                    .all(|id| matches!(state.steps[id].phase, Phase::Verified))
            {
                continue;
            }
            // Refresh time-limited/revocable lease authority immediately before each dispatch.
            authorize_plan(&state.plan, args, ctx)?;
            let arguments = resolve_inputs(&step, &state)?;
            validate_input(
                &ctx.federation.tool(&step.alias)?.input_schema,
                &Value::Object(arguments.clone()),
                0,
            )?;
            ensure!(
                serde_json::to_vec(&arguments)?.len() <= 8192,
                "GM_RUN_RESOLVED_INPUT_BOUND"
            );
            let key = format!(
                "gms_{}",
                hex::encode(hash(&json!([record.run_id, step.id]))?.as_bytes())
            );
            let submission = json!({"schemaVersion":"gaugemesh.task-submission/1",
                "logicalTaskId":format!("{}/{}",record.run_id,step.id), "attemptId":key,
                "correlationId":record.run_id,"idempotencyKey":key,
                "inputSha256":hash(&arguments)?,"acceptancePolicySha256":step.policy_sha256,
                "artifactScopeSha256":hash(&json!({"runId":record.run_id,"root":state.plan.artifact_root}))?,
                "providerInterfaceVersion":step.provider_interface_version,
                "deadlineUnixMs":state.plan.deadline_unix_ms.min(now()?.saturating_add(step.max_runtime_ms)),
                "retentionMs":3_600_000,"limits":{"maxRuntimeMs":step.max_runtime_ms,"maxOutputBytes":32768,
                    "maxArtifactBytes":step.max_artifact_bytes,"maxAttempts":1},
                "permittedEffect":step.permitted_effect,"cleanupRequired":true});
            let s = state.steps.get_mut(&step.id).unwrap();
            s.phase = Phase::Submitting;
            s.arguments = Some(arguments);
            s.submission = Some(submission);
            self.save(&mut record, &state, "task_submission_intent")?;
            self.submit_step(&mut record, &mut state, &step, ctx)
                .await?;
            if state.steps.values().any(|s| s.phase.blocks()) {
                break;
            }
        }
        summary(record)
    }

    async fn submit_step(
        &self,
        record: &mut RunRecord,
        state: &mut State,
        step: &Step,
        ctx: &RunContext<'_>,
    ) -> Result<()> {
        let recovery_only = state.cancel_requested
            || state.deadline_observed
            || state.steps.values().any(|s| s.phase.blocks());
        let s = state.steps.get_mut(&step.id).unwrap();
        let tool = ctx.federation.tool(&step.alias)?;
        let arguments = s.arguments.clone().context("GM_RUN_STATE_INVALID")?;
        let submission = s.submission.as_ref().context("GM_RUN_STATE_INVALID")?;
        let response = if recovery_only {
            ctx.proxy
                .recover_submission(tool, arguments, submission, ctx.identity)
                .await
        } else {
            ctx.proxy
                .submit(tool, arguments, submission, ctx.identity)
                .await
        };
        match response {
            Ok(CallToolResponse::Task(task)) => {
                s.task_id = Some(task.task.task_id);
                if task
                    .meta
                    .as_ref()
                    .and_then(|m| m.get("dev.gaugemesh/taskRoute"))
                    .is_some_and(|r| r["reconciliationRequired"] == true)
                {
                    s.phase = Phase::Unknown;
                } else {
                    s.phase = Phase::Routed;
                }
            }
            other => {
                s.phase = Phase::Unknown;
                s.diagnostic = Some(format!("GM_RUN_SUBMISSION_UNCERTAIN:{other:?}"));
            }
        }
        self.save(record, state, "task_identity_observed")
    }
}

fn authorize_plan(plan: &RunPlan, args: &Map<String, Value>, ctx: &RunContext<'_>) -> Result<()> {
    let lease_id = args
        .get("leaseId")
        .and_then(Value::as_str)
        .context("GM_RUN_LEASE_REQUIRED")?;
    let lease = ctx
        .leases
        .get(lease_id)?
        .context("GM_RUN_LEASE_REVOKED_OR_UNKNOWN")?;
    for step in &plan.steps {
        let tool = ctx.federation.tool(&step.alias)?;
        ensure!(
            tool.identity.digest() == step.capability_id
                && tool.identity.schema_digest.to_string() == step.provider_interface_version
                && ctx.proxy.source_supported(&tool.identity.source),
            "GM_RUN_PROVIDER_BINDING_CHANGED"
        );
        let mut sample_arguments = Map::new();
        for (name, input) in &step.arguments {
            let value = match input {
                Input::Literal { value } => value,
                Input::Predecessor {
                    step: source,
                    pointer,
                } => {
                    let predecessor = plan
                        .steps
                        .iter()
                        .find(|s| &s.id == source)
                        .context("GM_RUN_REFERENCE_INVALID")?;
                    let checks: Vec<_> = predecessor
                        .policy
                        .checks
                        .iter()
                        .filter(|check| check.required && &check.pointer == pointer)
                        .collect();
                    ensure!(
                        checks.len() == 1,
                        "GM_RUN_REFERENCE_REQUIRES_EXACT_REQUIRED_CHECK"
                    );
                    &checks[0].expected
                }
            };
            sample_arguments.insert(name.clone(), value.clone());
        }
        ensure!(
            serde_json::to_vec(&sample_arguments)?.len() <= 8192,
            "GM_RUN_RESOLVED_INPUT_BOUND"
        );
        validate_input(&tool.input_schema, &Value::Object(sample_arguments), 0)?;
        authorize_current_invocation(
            &lease,
            ctx.identity,
            &tool.identity,
            step.permitted_effect,
            now()?,
        )
        .map_err(anyhow::Error::msg)?;
    }
    Ok(())
}

/// Deliberately bounded JSON Schema subset. Unknown validation keywords are refused,
/// not silently ignored. Reference values must have a required exact predecessor check.
fn validate_input(schema: &Value, value: &Value, depth: usize) -> Result<()> {
    validate_schema_shape(schema, depth)?;
    ensure!(depth <= 16, "GM_RUN_INPUT_SCHEMA_BOUND");
    let object = schema
        .as_object()
        .context("GM_RUN_INPUT_SCHEMA_UNSUPPORTED")?;
    let allowed = [
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "enum",
        "const",
        "minimum",
        "maximum",
        "minLength",
        "maxLength",
        "minItems",
        "maxItems",
        "$schema",
        "title",
        "description",
    ];
    ensure!(
        object.keys().all(|k| allowed.contains(&k.as_str())),
        "GM_RUN_INPUT_SCHEMA_UNSUPPORTED"
    );
    let kind = schema["type"]
        .as_str()
        .context("GM_RUN_INPUT_SCHEMA_UNSUPPORTED")?;
    ensure!(
        match kind {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "integer" => value.is_i64() || value.is_u64(),
            "number" => value.is_number(),
            "string" => value.is_string(),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            _ => false,
        },
        "GM_RUN_INPUT_TYPE_INVALID"
    );
    if let Some(expected) = object.get("const") {
        ensure!(expected == value, "GM_RUN_INPUT_CONST_INVALID");
    }
    if let Some(choices) = object.get("enum") {
        ensure!(
            choices
                .as_array()
                .is_some_and(|choices| choices.contains(value)),
            "GM_RUN_INPUT_ENUM_INVALID"
        );
    }
    if kind == "object" {
        let properties = schema["properties"]
            .as_object()
            .context("GM_RUN_INPUT_SCHEMA_UNSUPPORTED")?;
        ensure!(
            schema["additionalProperties"] == false,
            "GM_RUN_INPUT_SCHEMA_UNSUPPORTED"
        );
        let map = value.as_object().unwrap();
        if let Some(required) = object.get("required") {
            let required = required
                .as_array()
                .context("GM_RUN_INPUT_SCHEMA_UNSUPPORTED")?;
            ensure!(
                required
                    .iter()
                    .all(|k| k.as_str().is_some_and(|k| map.contains_key(k))),
                "GM_RUN_INPUT_REQUIRED"
            );
        }
        for (name, entry) in map {
            let property = properties
                .get(name)
                .context("GM_RUN_INPUT_UNKNOWN_PROPERTY")?;
            validate_input(property, entry, depth + 1)?;
        }
        // Validate unused schema branches too, so unsupported future inputs are not accepted.
        for property in properties.values() {
            validate_schema_shape(property, depth + 1)?;
        }
    }
    if kind == "array" {
        let items = value.as_array().unwrap();
        ensure!(items.len() <= 1024, "GM_RUN_INPUT_BOUND");
        for entry in items {
            validate_input(&schema["items"], entry, depth + 1)?;
        }
        validate_schema_shape(&schema["items"], depth + 1)?;
        check_size(schema, items.len(), "minItems", "maxItems")?;
    }
    if kind == "string" {
        check_size(
            schema,
            value.as_str().unwrap().chars().count(),
            "minLength",
            "maxLength",
        )?;
    }
    if matches!(kind, "number" | "integer") {
        let number = value.as_f64().context("GM_RUN_INPUT_NUMBER_INVALID")?;
        ensure!(
            number.is_finite() && number.abs() <= 9_007_199_254_740_991.0,
            "GM_RUN_INPUT_NUMBER_BOUND"
        );
        for (key, lower) in [("minimum", true), ("maximum", false)] {
            if let Some(bound) = object.get(key) {
                let bound = bound.as_f64().context("GM_RUN_INPUT_SCHEMA_UNSUPPORTED")?;
                ensure!(
                    if lower {
                        number >= bound
                    } else {
                        number <= bound
                    },
                    "GM_RUN_INPUT_NUMBER_BOUND"
                );
            }
        }
    }
    Ok(())
}

fn check_size(schema: &Value, size: usize, minimum: &str, maximum: &str) -> Result<()> {
    if let Some(bound) = schema.get(minimum) {
        ensure!(
            size as u64 >= bound.as_u64().context("GM_RUN_INPUT_SCHEMA_UNSUPPORTED")?,
            "GM_RUN_INPUT_BOUND"
        );
    }
    if let Some(bound) = schema.get(maximum) {
        ensure!(
            size as u64 <= bound.as_u64().context("GM_RUN_INPUT_SCHEMA_UNSUPPORTED")?,
            "GM_RUN_INPUT_BOUND"
        );
    }
    Ok(())
}

fn validate_schema_shape(schema: &Value, depth: usize) -> Result<()> {
    ensure!(depth <= 16, "GM_RUN_INPUT_SCHEMA_BOUND");
    let object = schema
        .as_object()
        .context("GM_RUN_INPUT_SCHEMA_UNSUPPORTED")?;
    let allowed = [
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "enum",
        "const",
        "minimum",
        "maximum",
        "minLength",
        "maxLength",
        "minItems",
        "maxItems",
        "$schema",
        "title",
        "description",
    ];
    ensure!(
        object.keys().all(|k| allowed.contains(&k.as_str()))
            && matches!(
                schema["type"].as_str(),
                Some("object" | "array" | "string" | "integer" | "number" | "boolean" | "null")
            ),
        "GM_RUN_INPUT_SCHEMA_UNSUPPORTED"
    );
    if let Some(dialect) = schema.get("$schema") {
        ensure!(
            dialect == "https://json-schema.org/draft/2020-12/schema",
            "GM_RUN_INPUT_SCHEMA_DIALECT_UNSUPPORTED"
        );
    }
    for name in ["title", "description"] {
        if let Some(value) = object.get(name) {
            ensure!(value.is_string(), "GM_RUN_INPUT_SCHEMA_INVALID");
        }
    }
    if let Some(choices) = object.get("enum") {
        ensure!(
            choices
                .as_array()
                .is_some_and(|c| !c.is_empty() && c.len() <= 64),
            "GM_RUN_INPUT_SCHEMA_INVALID"
        );
    }
    for name in ["minimum", "maximum"] {
        if let Some(value) = object.get(name) {
            ensure!(
                matches!(schema["type"].as_str(), Some("integer" | "number"))
                    && value.as_f64().is_some_and(f64::is_finite),
                "GM_RUN_INPUT_SCHEMA_INVALID"
            );
        }
    }
    for (minimum, maximum, kind) in [
        ("minLength", "maxLength", "string"),
        ("minItems", "maxItems", "array"),
    ] {
        for name in [minimum, maximum] {
            if let Some(value) = object.get(name) {
                ensure!(
                    schema["type"] == kind && value.as_u64().is_some_and(|n| n <= u32::MAX as u64),
                    "GM_RUN_INPUT_SCHEMA_INVALID"
                );
            }
        }
        if let (Some(min), Some(max)) = (schema[minimum].as_u64(), schema[maximum].as_u64()) {
            ensure!(min <= max, "GM_RUN_INPUT_SCHEMA_INVALID");
        }
    }
    if let (Some(min), Some(max)) = (schema["minimum"].as_f64(), schema["maximum"].as_f64()) {
        ensure!(min <= max, "GM_RUN_INPUT_SCHEMA_INVALID");
    }
    if schema["type"] == "object" {
        ensure!(
            schema["additionalProperties"] == false,
            "GM_RUN_INPUT_SCHEMA_UNSUPPORTED"
        );
        let properties = schema["properties"]
            .as_object()
            .context("GM_RUN_INPUT_SCHEMA_UNSUPPORTED")?;
        if let Some(required) = object.get("required") {
            let required = required.as_array().context("GM_RUN_INPUT_SCHEMA_INVALID")?;
            ensure!(
                required
                    .iter()
                    .all(|v| v.as_str().is_some_and(|name| properties.contains_key(name)))
                    && required
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<BTreeSet<_>>()
                        .len()
                        == required.len(),
                "GM_RUN_INPUT_SCHEMA_INVALID"
            );
        }
        for property in schema["properties"]
            .as_object()
            .context("GM_RUN_INPUT_SCHEMA_UNSUPPORTED")?
            .values()
        {
            validate_schema_shape(property, depth + 1)?;
        }
    }
    if schema["type"] == "array" {
        validate_schema_shape(&schema["items"], depth + 1)?;
    }
    ensure!(
        schema["type"] == "object"
            || !["properties", "required", "additionalProperties"]
                .iter()
                .any(|k| object.contains_key(*k)),
        "GM_RUN_INPUT_SCHEMA_INVALID"
    );
    ensure!(
        schema["type"] == "array" || !object.contains_key("items"),
        "GM_RUN_INPUT_SCHEMA_INVALID"
    );
    Ok(())
}

fn state_from(record: &RunRecord) -> Result<State> {
    record.verify_integrity()?;
    let state: State =
        serde_json::from_value(record.data.clone()).context("GM_RUN_STATE_INVALID")?;
    state.plan.validate(state.accepted_at_unix_ms)?;
    ensure!(
        state.steps.len() == state.plan.steps.len()
            && state
                .plan
                .steps
                .iter()
                .all(|step| state.steps.contains_key(&step.id)),
        "GM_RUN_STATE_INVALID"
    );
    for step in &state.plan.steps {
        let stored = &state.steps[&step.id];
        if !matches!(stored.phase, Phase::Pending | Phase::Skipped) {
            ensure!(
                stored.arguments.as_ref() == Some(&resolve_inputs(step, &state)?),
                "GM_RUN_STATE_INPUT_BINDING_INVALID"
            );
            ensure!(
                stored.submission.is_some(),
                "GM_RUN_STATE_SUBMISSION_MISSING"
            );
        }
        if matches!(
            stored.phase,
            Phase::Routed | Phase::Verified | Phase::Cancelled
        ) {
            ensure!(stored.task_id.is_some(), "GM_RUN_STATE_TASK_ID_MISSING");
        }
        if matches!(stored.phase, Phase::Verified) {
            ensure!(
                stored.terminal.is_some()
                    && stored.verified_artifact.is_some()
                    && stored
                        .verification
                        .as_ref()
                        .is_some_and(|v| v["status"] == "verified"),
                "GM_RUN_STATE_VERIFICATION_MISSING"
            );
        }
        if matches!(stored.phase, Phase::Pending | Phase::Skipped) {
            ensure!(
                stored.arguments.is_none()
                    && stored.submission.is_none()
                    && stored.task_id.is_none()
                    && stored.terminal.is_none()
                    && stored.verified_artifact.is_none()
                    && stored.verification.is_none(),
                "GM_RUN_STATE_UNSENT_HAS_EXECUTION"
            );
        }
    }
    Ok(state)
}

fn resolve_inputs(step: &Step, state: &State) -> Result<Map<String, Value>> {
    step.arguments
        .iter()
        .map(|(name, input)| {
            let value = match input {
                Input::Literal { value } => value.clone(),
                Input::Predecessor { step, pointer } => state.steps[step]
                    .verified_artifact
                    .as_ref()
                    .and_then(|v| v.pointer(pointer))
                    .context("GM_RUN_REFERENCE_MISSING")?
                    .clone(),
            };
            Ok((name.clone(), value))
        })
        .collect()
}

fn summary(record: RunRecord) -> Result<Value> {
    let state = state_from(&record)?;
    let active = state.steps.values().any(|s| s.phase.active());
    let status = if active {
        "in_progress"
    } else if state
        .steps
        .values()
        .any(|s| matches!(s.phase, Phase::Unknown))
    {
        "reconciliation_required"
    } else if state
        .steps
        .values()
        .all(|s| matches!(s.phase, Phase::Verified))
    {
        "verified"
    } else if state.cancel_requested {
        "cancelled_or_stopped"
    } else if state.deadline_observed {
        "deadline_exceeded"
    } else if state.steps.values().any(|s| s.phase.blocks()) {
        "failed"
    } else {
        "ready"
    };
    Ok(
        json!({"runId":record.run_id,"planSha256":record.plan_sha256,"version":record.version,
        "status":status,"cancelRequested":state.cancel_requested,"deadlineObserved":state.deadline_observed,
        "steps":state.steps,"guarantee":"single-process poll-driven composition; no exactly-once side effects or autonomous watchdog"}),
    )
}

fn verify_step(
    run_id: &str,
    plan: &RunPlan,
    step: &Step,
    state: &StepState,
) -> Result<(Value, Value)> {
    let terminal = state.terminal.as_ref().context("GM_RUN_RESULT_MISSING")?;
    ensure!(
        terminal["status"] == "completed" && terminal["result"]["isError"] != true,
        "GM_RUN_EXECUTION_NOT_SUCCESSFUL"
    );
    let result = &terminal["result"]["structuredContent"];
    let binding = &terminal["result"]["_meta"]["dev.gaugemesh/taskExecution"];
    let submission = state
        .submission
        .as_ref()
        .context("GM_RUN_SUBMISSION_MISSING")?;
    let attempt = format!(
        "gms_{}",
        hex::encode(hash(&json!([run_id, step.id]))?.as_bytes())
    );
    ensure!(
        binding.is_object()
            && result["binding"] == *binding
            && binding["publicTaskId"].as_str() == state.task_id.as_deref()
            && binding["submission"]["task"] == *submission
            && binding["requestSha256"] == hash(&binding["submission"])?.to_string()
            && binding["submission"]["capabilityId"] == step.capability_id.to_string()
            && submission["attemptId"] == attempt
            && submission["idempotencyKey"] == attempt
            && submission["artifactScopeSha256"]
                == hash(&json!({"runId":run_id,"root":plan.artifact_root}))?.to_string()
            && submission["correlationId"] == run_id
            && submission["logicalTaskId"] == format!("{run_id}/{}", step.id)
            && submission["acceptancePolicySha256"] == serde_json::to_value(step.policy_sha256)?
            && submission["inputSha256"] == serde_json::to_value(hash(&state.arguments)?)?,
        "GM_RUN_RESULT_BINDING_INVALID"
    );
    let path = result["artifact"]["path"]
        .as_str()
        .context("GM_RUN_ARTIFACT_DESCRIPTOR_MISSING")?;
    let bytes = read_artifact(
        &plan.artifact_root,
        Path::new(path),
        step.max_artifact_bytes,
    )?;
    ensure!(
        result["artifact"]["sha256"] == Sha256Digest::of_bytes(&bytes).to_string(),
        "GM_RUN_ARTIFACT_DIGEST_MISMATCH"
    );
    let artifact: Value = serde_json::from_slice(&bytes).context("GM_RUN_ARTIFACT_JSON_INVALID")?;
    let mut expected = result.clone();
    expected
        .as_object_mut()
        .context("GM_RUN_RESULT_INVALID")?
        .remove("artifact");
    ensure!(
        artifact == expected && artifact["binding"] == *binding,
        "GM_RUN_ARTIFACT_SWAPPED_OR_STALE"
    );
    if let Some(stored) = &state.verified_artifact {
        ensure!(*stored == artifact, "GM_RUN_STORED_VERIFICATION_MISMATCH");
    }
    let checks: Vec<_> = step.policy.checks.iter().map(|check| json!({"pointer":check.pointer,
        "required":check.required,"passed":artifact.pointer(&check.pointer) == Some(&check.expected)})).collect();
    ensure!(
        checks
            .iter()
            .all(|c| c["required"] != true || c["passed"] == true),
        "GM_RUN_REQUIRED_VERIFICATION_FAILED"
    );
    Ok((
        artifact,
        json!({"status":"verified","policySha256":step.policy_sha256,
        "artifactSha256":Sha256Digest::of_bytes(bytes),"checks":checks}),
    ))
}

pub fn verify_record(record: &RunRecord) -> Result<Value> {
    let state = state_from(record)?;
    let mut verified = 0;
    for step in &state.plan.steps {
        if matches!(state.steps[&step.id].phase, Phase::Verified) {
            verify_step(&record.run_id, &state.plan, step, &state.steps[&step.id])?;
            verified += 1;
        }
    }
    Ok(
        json!({"schemaVersion":"gaugemesh.run-verification/1","runId":record.run_id,
        "integrity":"verified","verifiedSteps":verified,"totalSteps":state.plan.steps.len(),
        "complete":verified == state.plan.steps.len(),"executionPerformed":false,
        "authenticity":"integrity hashes are not signatures; a trusted original export is required"}),
    )
}

// Anchor every directory component with an open descriptor; never follow symlinks,
// including ancestors. No arbitrary write or executable verifier is supported.
#[cfg(unix)]
fn open_root(path: &Path) -> Result<std::fs::File> {
    use rustix::fs::{Mode, OFlags, open, openat};
    ensure!(path.is_absolute(), "GM_RUN_ARTIFACT_ROOT_INVALID");
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = open("/", flags, Mode::empty())?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = openat(&directory, name, flags, Mode::empty())
                    .context("GM_RUN_ARTIFACT_PATH_UNSAFE")?
            }
            _ => bail!("GM_RUN_ARTIFACT_PATH_UNSAFE"),
        }
    }
    Ok(directory.into())
}

#[cfg(not(unix))]
fn open_root(_path: &Path) -> Result<std::fs::File> {
    bail!("GM_RUN_PLATFORM_UNSUPPORTED")
}

fn read_artifact(root: &Path, path: &Path, limit: u64) -> Result<Vec<u8>> {
    ensure!(
        !path.as_os_str().is_empty()
            && path.as_os_str().len() <= 1024
            && path.components().all(|c| matches!(c, Component::Normal(_))),
        "GM_RUN_ARTIFACT_PATH_UNSAFE"
    );
    let directory = open_root(root)?;
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags, openat};
        let mut directory = directory;
        let components: Vec<_> = path.components().collect();
        for (i, component) in components.iter().enumerate() {
            let flags = OFlags::RDONLY
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK
                | if i + 1 == components.len() {
                    OFlags::empty()
                } else {
                    OFlags::DIRECTORY
                };
            directory = openat(&directory, component.as_os_str(), flags, Mode::empty())
                .context("GM_RUN_ARTIFACT_MISSING_OR_UNSAFE")?
                .into();
        }
        ensure!(
            directory.metadata()?.is_file(),
            "GM_RUN_ARTIFACT_NOT_REGULAR"
        );
        let mut bytes = vec![];
        directory.take(limit + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() as u64 <= limit, "GM_RUN_ARTIFACT_BOUND");
        Ok(bytes)
    }
    #[cfg(not(unix))]
    {
        let _ = (directory, limit);
        bail!("GM_RUN_PLATFORM_UNSUPPORTED")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_input_schema_refuses_unknown_validation_and_bad_values() {
        let schema = json!({"type":"object","properties":{"value":{"type":"integer","minimum":0,"maximum":9}},
            "required":["value"],"additionalProperties":false});
        assert!(validate_input(&schema, &json!({"value":7}), 0).is_ok());
        for value in [
            json!({}),
            json!({"value":"7"}),
            json!({"value":10}),
            json!({"value":7,"extra":true}),
        ] {
            assert!(validate_input(&schema, &value, 0).is_err());
        }
        let mut unsupported = schema.clone();
        unsupported["allOf"] = json!([]);
        assert!(validate_input(&unsupported, &json!({"value":7}), 0).is_err());
        let mut malformed_unused = schema.clone();
        malformed_unused["properties"]["optional"] = json!({"type":"string","maxLength":"bad"});
        assert!(validate_input(&malformed_unused, &json!({"value":7}), 0).is_err());
        let mut dialect = schema.clone();
        dialect["$schema"] = json!("unsupported-dialect");
        assert!(validate_input(&dialect, &json!({"value":7}), 0).is_err());
        assert!(pointer_valid("/a~1b/~0value"));
        for bad in ["/~bad", "/dangling~", "normalized", "/binding", ""] {
            assert!(!pointer_valid(bad));
        }
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_relative_artifacts_refuse_escape_symlinks_special_files_and_bounds() {
        let temp = tempfile::tempdir().unwrap();
        let canonical_root = temp.path().canonicalize().unwrap();
        let root = canonical_root.as_path();
        std::fs::write(root.join("result.json"), b"{\"value\":7}").unwrap();
        assert!(read_artifact(root, Path::new("result.json"), 100).is_ok());
        assert!(read_artifact(root, Path::new("result.json"), 2).is_err());
        assert!(read_artifact(root, Path::new("../result.json"), 100).is_err());
        assert!(read_artifact(root, &root.join("result.json"), 100).is_err());
        std::os::unix::fs::symlink(root.join("result.json"), root.join("linked")).unwrap();
        assert!(read_artifact(root, Path::new("linked"), 100).is_err());
        std::fs::create_dir(root.join("directory")).unwrap();
        assert!(read_artifact(root, Path::new("directory"), 100).is_err());
        std::os::unix::fs::symlink(root, root.join("linked-root")).unwrap();
        assert!(open_root(&root.join("linked-root")).is_err());
    }
}
