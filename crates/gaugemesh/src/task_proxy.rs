use std::{
    collections::BTreeMap,
    sync::{Arc, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use chrono::{SecondsFormat, TimeZone as _, Utc};
use gaugemesh_core::{
    context::SideEffectClass,
    digest::Sha256Digest,
    federation::FederatedTool,
    storage::{BeginTaskRouteResult, TaskRouteStorage, TaskRouteStorageError},
    task::{
        MAX_CACHED_TERMINAL_STATE_BYTES, PublicTaskId, TaskRouteCaller, TaskRouteIdempotencyKey,
        TaskRoutePhase, TaskRouteRecord, TaskRouteUpdate, UpstreamTaskId,
    },
};
use rmcp::{
    ErrorData as McpError,
    model::{
        CallToolRequestParams, CallToolResponse, CancelTaskParams, CreateTaskResult, DetailedTask,
        GetTaskParams, GetTaskResult, JsonObject, MetaObject, RequestMetaObject, Task, TaskPayload,
        TaskStatus, UpdateTaskParams,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    auth::AuthenticatedIdentity,
    outbound::{TASK_EXECUTION_META_KEY, UpstreamRuntime},
};

const TASK_SUBMISSION_SCHEMA: &str = "gaugemesh.task-submission/1";
const TASK_EXECUTION_SCHEMA: &str = "gaugemesh.task-execution/1";
const MAX_TASK_INPUT_BYTES: usize = 64 * 1024;
const MAX_TASK_RUNTIME_MS: u64 = 30_000;
const MAX_TASK_LIFECYCLE_REQUEST_MS: u64 = 5_000;
const MAX_TASK_OUTPUT_BYTES: u64 = 64 * 1024;
const MAX_TASK_ARTIFACT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_TASK_RETENTION_MS: u64 = 60 * 60 * 1_000;
const MAX_TASK_IDENTIFIER_BYTES: usize = 128;
const MAX_ROUTE_CAS_ATTEMPTS: usize = 4;
const MAX_RAW_MANAGEMENT_TASK_ID_BYTES: usize = 4 * 1024;

type RouteLockMap = BTreeMap<(TaskRouteCaller, PublicTaskId), Weak<tokio::sync::Mutex<()>>>;

#[derive(Clone)]
pub struct TaskProxy {
    store: Arc<dyn TaskRouteStorage>,
    upstreams: Arc<UpstreamRuntime>,
    instance_id: String,
    route_locks: Arc<tokio::sync::Mutex<RouteLockMap>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskSubmission {
    pub schema_version: String,
    pub logical_task_id: String,
    pub attempt_id: String,
    pub correlation_id: String,
    pub idempotency_key: String,
    pub input_sha256: Sha256Digest,
    pub acceptance_policy_sha256: Sha256Digest,
    pub artifact_scope_sha256: Sha256Digest,
    pub provider_interface_version: String,
    pub deadline_unix_ms: u64,
    pub retention_ms: u64,
    pub limits: TaskLimits,
    pub permitted_effect: SideEffectClass,
    pub cleanup_required: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskLimits {
    pub max_runtime_ms: u64,
    pub max_output_bytes: u64,
    pub max_artifact_bytes: u64,
    pub max_attempts: u16,
}

impl TaskSubmission {
    pub fn parse(
        value: &Value,
        arguments: &JsonObject,
        expected_provider_interface_version: &str,
        required_effect: SideEffectClass,
        now_unix_ms: u64,
    ) -> Result<Self, &'static str> {
        if serde_json::to_vec(arguments)
            .map_err(|_| "GM_TASK_SUBMISSION_INVALID")?
            .len()
            > MAX_TASK_INPUT_BYTES
        {
            return Err("GM_TASK_INPUT_LIMIT_EXCEEDED");
        }
        let submission: Self =
            serde_json::from_value(value.clone()).map_err(|_| "GM_TASK_SUBMISSION_INVALID")?;
        if submission.schema_version != TASK_SUBMISSION_SCHEMA {
            return Err("GM_TASK_SCHEMA_UNSUPPORTED");
        }
        for value in [
            submission.logical_task_id.as_str(),
            submission.attempt_id.as_str(),
            submission.correlation_id.as_str(),
            submission.idempotency_key.as_str(),
            submission.provider_interface_version.as_str(),
        ] {
            if !valid_identifier(value) {
                return Err("GM_TASK_IDENTITY_INVALID");
            }
        }
        if submission.input_sha256 != Sha256Digest::of_json(&Value::Object(arguments.clone())) {
            return Err("GM_TASK_INPUT_IDENTITY_MISMATCH");
        }
        if submission.provider_interface_version != expected_provider_interface_version {
            return Err("GM_TASK_PROVIDER_VERSION_UNSUPPORTED");
        }
        if submission.acceptance_policy_sha256 == Sha256Digest::default()
            || submission.artifact_scope_sha256 == Sha256Digest::default()
        {
            return Err("GM_TASK_POLICY_IDENTITY_INVALID");
        }
        if submission.deadline_unix_ms <= now_unix_ms
            || submission.deadline_unix_ms.saturating_sub(now_unix_ms) > MAX_TASK_RETENTION_MS
        {
            return Err("GM_TASK_DEADLINE_INVALID");
        }
        if submission.retention_ms < submission.limits.max_runtime_ms
            || submission.deadline_unix_ms > now_unix_ms.saturating_add(submission.retention_ms)
            || submission.retention_ms > MAX_TASK_RETENTION_MS
            || submission.limits.max_runtime_ms == 0
            || submission.limits.max_runtime_ms > MAX_TASK_RUNTIME_MS
            || submission.limits.max_output_bytes == 0
            || submission.limits.max_output_bytes > MAX_TASK_OUTPUT_BYTES
            || submission.limits.max_artifact_bytes == 0
            || submission.limits.max_artifact_bytes > MAX_TASK_ARTIFACT_BYTES
            || submission.limits.max_attempts != 1
        {
            return Err("GM_TASK_RESOURCE_LIMIT_INVALID");
        }
        if submission.permitted_effect != required_effect {
            return Err("GM_TASK_EFFECT_MISMATCH");
        }
        if !submission.cleanup_required {
            return Err("GM_TASK_CLEANUP_REQUIRED");
        }
        Ok(submission)
    }
}

impl TaskProxy {
    pub fn new(store: Arc<dyn TaskRouteStorage>, upstreams: Arc<UpstreamRuntime>) -> Self {
        Self {
            store,
            upstreams,
            instance_id: format!("gmci_{}", uuid::Uuid::new_v4()),
            route_locks: Arc::new(tokio::sync::Mutex::new(BTreeMap::new())),
        }
    }

    pub fn source_supported(&self, source: &gaugemesh_core::capability::SourceId) -> bool {
        self.upstreams.source_supports_tasks(source)
    }

    pub async fn submit(
        &self,
        tool: &FederatedTool,
        arguments: JsonObject,
        submission: &Value,
        identity: &AuthenticatedIdentity,
    ) -> Result<CallToolResponse, McpError> {
        let caller = caller(identity)?;
        let now = now_unix_ms()?;
        self.store
            .purge_expired_task_routes(now, 128)
            .map_err(storage_error)?;
        let expected_provider_interface_version = tool.identity.schema_digest.to_string();
        let submission = TaskSubmission::parse(
            submission,
            &arguments,
            &expected_provider_interface_version,
            SideEffectClass::NonIdempotentWrite,
            now,
        )
        .map_err(|code| McpError::invalid_params(code, None))?;
        let source_snapshot_digest = self
            .upstreams
            .source_snapshot_digest(&tool.identity.source)
            .ok_or_else(|| McpError::invalid_params("GM_TASK_UPSTREAM_UNAVAILABLE", None))?;
        let upstream_session_id = self
            .upstreams
            .source_session_id(&tool.identity.source)
            .await
            .ok_or_else(|| McpError::invalid_params("GM_TASK_UPSTREAM_UNAVAILABLE", None))?;
        let binding = submission_binding(tool, &submission, source_snapshot_digest);
        let request_digest = Sha256Digest::of_json(&binding);
        let record = TaskRouteRecord::prepare(
            caller,
            Some(
                TaskRouteIdempotencyKey::new(submission.idempotency_key.clone())
                    .map_err(invalid_task_route)?,
            ),
            request_digest,
            binding,
            tool.identity.clone(),
            upstream_session_id,
            now,
            submission.retention_ms,
        )
        .map_err(invalid_task_route)?;
        let (record, inserted) = match self
            .store
            .begin_or_existing(&record)
            .map_err(storage_error)?
        {
            BeginTaskRouteResult::Existing(existing) => (existing, false),
            BeginTaskRouteResult::Inserted(record) => (record, true),
        };
        if !inserted
            && record.phase != TaskRoutePhase::Terminal
            && !self.source_binding_is_current(&record).await
        {
            let unknown = self.mark_reconciliation_required(&record)?;
            return self.existing_submission(unknown);
        }
        let record = if inserted {
            self.claim_dispatch(&record)?
                .ok_or_else(|| McpError::internal_error("GM_TASK_DISPATCH_CLAIM_FAILED", None))?
        } else {
            match record.phase {
                TaskRoutePhase::Prepared => match self.claim_dispatch(&record)? {
                    Some(claimed) => claimed,
                    None => return self.existing_submission(record),
                },
                TaskRoutePhase::Dispatching
                    if record.dispatch_owner_id.as_deref() != Some(&self.instance_id)
                        || now >= execution_cutoff(&record) =>
                {
                    let unknown = self.mark_reconciliation_required(&record)?;
                    return self.existing_submission(unknown);
                }
                _ => return self.existing_submission(record),
            }
        };

        let mut request =
            CallToolRequestParams::new(tool.native_name.clone()).with_arguments(arguments);
        let mut request_meta = RequestMetaObject::new();
        request_meta.insert(TASK_EXECUTION_META_KEY.into(), execution_envelope(&record));
        request.meta = Some(request_meta);
        let remaining_ms = execution_cutoff(&record)
            .saturating_sub(now_unix_ms()?)
            .min(MAX_TASK_RUNTIME_MS);
        if remaining_ms == 0 {
            return self.finish_known_non_dispatch(&record, "GM_TASK_RUNTIME_BOUND_REACHED");
        }
        let response = tokio::time::timeout(
            Duration::from_millis(remaining_ms),
            self.upstreams.call_tool_with_task_capability_for_session(
                &tool.identity.source,
                request,
                true,
                &record.upstream_session_id,
            ),
        )
        .await;
        let response = match response {
            Ok(response) => response,
            Err(_) => {
                let unknown = self.mark_reconciliation_required(&record)?;
                return Ok(task_handle(&unknown, Some(TaskStatus::Working)));
            }
        };
        match response {
            Ok(CallToolResponse::Task(created)) => {
                let raw_upstream_task_id = created.task.task_id.clone();
                let upstream_task_id = match UpstreamTaskId::new(raw_upstream_task_id.clone()) {
                    Ok(task_id) => task_id,
                    Err(_) => {
                        let _ = self
                            .cancel_raw_upstream(&record, raw_upstream_task_id.as_str())
                            .await;
                        let unknown = self.mark_reconciliation_required(&record)?;
                        return Ok(task_handle(&unknown, Some(TaskStatus::Working)));
                    }
                };
                let (routed, cancellation_required) =
                    match self.bind_upstream_task(&record, upstream_task_id.clone()) {
                        Ok(routed) => routed,
                        Err(error) => {
                            let _ = self.cancel_upstream(&record, upstream_task_id).await;
                            return Err(error);
                        }
                    };
                if cancellation_required {
                    if routed.upstream_task_id.as_ref() == Some(&upstream_task_id)
                        && routed.phase != TaskRoutePhase::Terminal
                    {
                        let cancelling = self.request_cancellation(routed).await?;
                        return Ok(task_handle(&cancelling, None));
                    }
                    let _ = self.cancel_upstream(&routed, upstream_task_id).await;
                    return Ok(task_handle(&routed, None));
                }
                if routed.phase != TaskRoutePhase::Routed {
                    let _ = self.cancel_upstream(&routed, upstream_task_id).await;
                    return Ok(task_handle(&routed, None));
                }
                if !execution_ack_matches(created.meta.as_ref(), &routed) {
                    let cancelling = self.request_cancellation(routed).await?;
                    let unknown = self.mark_reconciliation_required(&cancelling)?;
                    return Ok(task_handle(&unknown, Some(TaskStatus::Working)));
                }
                if now_unix_ms()? >= execution_cutoff(&routed) {
                    let cancelling = self.request_cancellation(routed).await?;
                    return Ok(task_handle(&cancelling, None));
                }
                Ok(task_handle(&routed, Some(TaskStatus::Working)))
            }
            Ok(CallToolResponse::Complete(result)) => {
                if !execution_ack_matches(result.meta.as_ref(), &record) {
                    let unknown = self.mark_reconciliation_required(&record)?;
                    return Ok(task_handle(&unknown, Some(TaskStatus::Working)));
                }
                if now_unix_ms()? >= execution_cutoff(&record) {
                    return self.finish_known_rejection(&record, "GM_TASK_DEADLINE_EXCEEDED");
                }
                let result = json_object(&result)
                    .map_err(|_| McpError::internal_error("GM_TASK_RESULT_SERIALIZATION", None))?;
                let detailed = DetailedTask::new(
                    task_from_record(&record, TaskStatus::Completed, "execution completed"),
                    TaskPayload::Completed { result },
                );
                let serialized = serde_json::to_value(&detailed)
                    .map_err(|_| McpError::internal_error("GM_TASK_RESULT_SERIALIZATION", None))?;
                let serialized_bytes = serde_json::to_vec(&serialized)
                    .map_err(|_| McpError::internal_error("GM_TASK_RESULT_SERIALIZATION", None))?;
                if serialized_bytes.len() > output_limit(&record)
                    || serialized_bytes.len() > MAX_CACHED_TERMINAL_STATE_BYTES
                {
                    return self.finish_known_rejection(&record, "GM_TASK_OUTPUT_LIMIT_EXCEEDED");
                }
                let terminal = self.finish_terminal(&record, detailed)?;
                let status = cached_detailed_task(&terminal)?.status();
                Ok(task_handle(&terminal, Some(status)))
            }
            Ok(CallToolResponse::InputRequired(_)) => {
                let unknown = self.mark_reconciliation_required(&record)?;
                Ok(task_handle(&unknown, Some(TaskStatus::Working)))
            }
            Ok(_) => {
                let unknown = self.mark_reconciliation_required(&record)?;
                Ok(task_handle(&unknown, Some(TaskStatus::Working)))
            }
            Err(_) => {
                let unknown = self.mark_reconciliation_required(&record)?;
                Ok(task_handle(&unknown, Some(TaskStatus::Working)))
            }
        }
    }

    pub async fn get_task(
        &self,
        request: GetTaskParams,
        identity: &AuthenticatedIdentity,
    ) -> Result<GetTaskResult, McpError> {
        let caller = caller(identity)?;
        let public_id = PublicTaskId::new(request.task_id).map_err(invalid_task_route)?;
        let route_lock = self.route_lock(&caller, &public_id).await;
        let _route_guard = route_lock.lock().await;
        let record = self
            .store
            .get_task_route(&caller, &public_id)
            .map_err(storage_error)?
            .ok_or_else(unknown_task)?;
        let now = now_unix_ms()?;
        if record.is_expired(now) {
            return Err(unknown_task());
        }
        if record.phase == TaskRoutePhase::Terminal {
            return cached_task(&record);
        }
        if record.upstream_task_id.is_some() && !self.source_binding_is_current(&record).await {
            let unknown = self.mark_reconciliation_required(&record)?;
            return Ok(reconciliation_task_with_code(
                &unknown,
                "GM_TASK_SOURCE_SNAPSHOT_CHANGED",
            ));
        }
        match record.phase {
            TaskRoutePhase::Terminal => unreachable!("terminal routes return before drift checks"),
            TaskRoutePhase::Dispatching
                if record.dispatch_owner_id.as_deref() != Some(&self.instance_id) =>
            {
                let unknown = self.mark_reconciliation_required(&record)?;
                Ok(reconciliation_task(&unknown))
            }
            TaskRoutePhase::Prepared if now >= execution_cutoff(&record) => {
                self.finish_known_non_dispatch_result(&record, "GM_TASK_RUNTIME_BOUND_REACHED")
            }
            TaskRoutePhase::Dispatching if now >= execution_cutoff(&record) => {
                let unknown = self.mark_reconciliation_required(&record)?;
                Ok(reconciliation_task_with_code(
                    &unknown,
                    "GM_TASK_RUNTIME_BOUND_REACHED",
                ))
            }
            TaskRoutePhase::Prepared | TaskRoutePhase::Dispatching => Ok(working_task(&record)),
            TaskRoutePhase::Routed | TaskRoutePhase::ReconciliationRequired
                if now >= execution_cutoff(&record) && record.upstream_task_id.is_some() =>
            {
                let cancelling = self.request_cancellation(record).await?;
                Ok(working_task_with_code(
                    &cancelling,
                    "GM_TASK_RUNTIME_BOUND_REACHED",
                ))
            }
            TaskRoutePhase::ReconciliationRequired if record.upstream_task_id.is_none() => {
                Ok(reconciliation_task(&record))
            }
            TaskRoutePhase::CancelRequested if record.upstream_task_id.is_none() => Ok(
                working_task_with_code(&record, "GM_TASK_CANCELLATION_RECONCILIATION_REQUIRED"),
            ),
            TaskRoutePhase::Routed
            | TaskRoutePhase::ReconciliationRequired
            | TaskRoutePhase::CancelRequested => self.poll_upstream(record).await,
        }
    }

    pub async fn update_task(
        &self,
        request: UpdateTaskParams,
        identity: &AuthenticatedIdentity,
    ) -> Result<(), McpError> {
        let caller = caller(identity)?;
        let public_id = PublicTaskId::new(request.task_id.clone()).map_err(invalid_task_route)?;
        let route_lock = self.route_lock(&caller, &public_id).await;
        let _route_guard = route_lock.lock().await;
        let record = self
            .store
            .get_task_route(&caller, &public_id)
            .map_err(storage_error)?
            .ok_or_else(unknown_task)?;
        let now = now_unix_ms()?;
        if record.is_expired(now) {
            return Err(unknown_task());
        }
        if record.phase != TaskRoutePhase::Routed {
            return Err(McpError::invalid_params("GM_TASK_NOT_UPDATEABLE", None));
        }
        // An input-response update is itself an externally visible mutation. This
        // route schema has no durable update-intent/receipt state, so forwarding it
        // would make an acknowledgement-loss window indistinguishable from a
        // never-sent update. Refuse explicitly instead of claiming durability.
        let _ = now;
        Err(McpError::invalid_params(
            "GM_TASK_UPDATE_UNSUPPORTED_DURABLE",
            None,
        ))
    }

    pub async fn cancel_task(
        &self,
        request: CancelTaskParams,
        identity: &AuthenticatedIdentity,
    ) -> Result<(), McpError> {
        let caller = caller(identity)?;
        let public_id = PublicTaskId::new(request.task_id).map_err(invalid_task_route)?;
        let route_lock = self.route_lock(&caller, &public_id).await;
        let _route_guard = route_lock.lock().await;
        let record = self
            .store
            .get_task_route(&caller, &public_id)
            .map_err(storage_error)?
            .ok_or_else(unknown_task)?;
        if record.is_expired(now_unix_ms()?) {
            return Err(unknown_task());
        }
        if record.phase == TaskRoutePhase::Terminal {
            return Ok(());
        }
        let cancelling = self.persist_cancellation_intent(record)?;
        if cancelling.upstream_task_id.is_some()
            && !self.source_binding_is_current(&cancelling).await
        {
            return Err(McpError::internal_error(
                "GM_TASK_SOURCE_SNAPSHOT_CHANGED",
                None,
            ));
        }
        let _ = self.request_cancellation(cancelling).await?;
        Ok(())
    }

    fn existing_submission(&self, record: TaskRouteRecord) -> Result<CallToolResponse, McpError> {
        match record.phase {
            TaskRoutePhase::Terminal => {
                let cached = cached_detailed_task(&record)?;
                Ok(task_handle(&record, Some(cached.status())))
            }
            TaskRoutePhase::Routed | TaskRoutePhase::CancelRequested => {
                Ok(task_handle(&record, None))
            }
            TaskRoutePhase::Prepared | TaskRoutePhase::Dispatching => {
                Ok(task_handle(&record, Some(TaskStatus::Working)))
            }
            TaskRoutePhase::ReconciliationRequired => {
                Ok(task_handle(&record, Some(TaskStatus::Working)))
            }
        }
    }

    async fn poll_upstream(&self, record: TaskRouteRecord) -> Result<GetTaskResult, McpError> {
        let upstream_id = routed_upstream_id(&record)?;
        if record.phase == TaskRoutePhase::CancelRequested {
            // Cancellation is a durable intent. Each caller-driven poll makes
            // one bounded retry without ever replaying the task submission.
            let _ = self.cancel_upstream(&record, upstream_id.clone()).await;
        }
        let remaining_ms = execution_cutoff(&record).saturating_sub(now_unix_ms()?);
        if remaining_ms == 0 && record.phase != TaskRoutePhase::CancelRequested {
            let cancelling = self.request_cancellation(record).await?;
            return Ok(working_task_with_code(
                &cancelling,
                "GM_TASK_RUNTIME_BOUND_REACHED",
            ));
        }
        let poll_timeout_ms = if remaining_ms == 0 {
            MAX_TASK_LIFECYCLE_REQUEST_MS
        } else {
            remaining_ms.min(MAX_TASK_LIFECYCLE_REQUEST_MS)
        };
        let response = tokio::time::timeout(
            Duration::from_millis(poll_timeout_ms),
            self.upstreams.get_task_for_session(
                &record.capability_source,
                GetTaskParams::new(upstream_id.0.clone()),
                &record.upstream_session_id,
            ),
        )
        .await;
        let mut response = match response {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => {
                let unknown = self.mark_reconciliation_required(&record)?;
                return Ok(reconciliation_task(&unknown));
            }
            Err(_) => {
                let cancelling = self.request_cancellation(record).await?;
                return Ok(working_task_with_code(
                    &cancelling,
                    "GM_TASK_RUNTIME_BOUND_REACHED",
                ));
            }
        };
        if !response.result_type.is_complete()
            || response.task.task.task_id != upstream_id.0
            || !execution_ack_matches(response.meta.as_ref(), &record)
        {
            let unknown = self.mark_reconciliation_required(&record)?;
            return Ok(reconciliation_task_with_code(
                &unknown,
                "GM_TASK_EXECUTION_BINDING_MISMATCH",
            ));
        }
        let upstream_status = response.task.status();
        if now_unix_ms()? >= execution_cutoff(&record) && upstream_status != TaskStatus::Cancelled {
            if upstream_status.is_terminal() {
                return self.finish_known_rejection_result(&record, "GM_TASK_DEADLINE_EXCEEDED");
            }
            let cancelling = self.request_cancellation(record).await?;
            return Ok(working_task_with_code(
                &cancelling,
                "GM_TASK_RUNTIME_BOUND_REACHED",
            ));
        }

        let oversized = serde_json::to_vec(&response)
            .map_err(|_| McpError::internal_error("GM_TASK_RESULT_SERIALIZATION", None))?
            .len()
            > output_limit(&record);
        if oversized && !response.task.status().is_terminal() {
            let cancelling = self.request_cancellation(record).await?;
            return Ok(working_task_with_code(
                &cancelling,
                "GM_TASK_OUTPUT_LIMIT_EXCEEDED",
            ));
        }
        if oversized {
            return self.finish_known_rejection_result(&record, "GM_TASK_OUTPUT_LIMIT_EXCEEDED");
        }

        let active = if record.phase == TaskRoutePhase::ReconciliationRequired {
            self.update(
                &record,
                TaskRouteUpdate::routed(upstream_id.clone(), transition_time(&record)?),
            )?
        } else {
            record
        };
        if active.phase == TaskRoutePhase::Terminal {
            return cached_task(&active);
        }
        if active.phase == TaskRoutePhase::CancelRequested && !upstream_status.is_terminal() {
            return Ok(working_task_with_code(
                &active,
                "cancellation requested; upstream terminal state is pending",
            ));
        }
        let status_message = if upstream_status.is_terminal() {
            "upstream reported a terminal execution state"
        } else {
            "upstream reported a nonterminal execution state"
        };
        response.task = DetailedTask::new(
            task_from_record(&active, upstream_status, status_message),
            response.task.payload,
        );
        response.meta = Some(route_meta(&active, "not_performed"));
        if upstream_status.is_terminal() {
            let terminal = self.finish_terminal(&active, response.task)?;
            return cached_task(&terminal);
        }
        Ok(response)
    }

    async fn request_cancellation(
        &self,
        record: TaskRouteRecord,
    ) -> Result<TaskRouteRecord, McpError> {
        let cancelling = self.persist_cancellation_intent(record)?;
        if cancelling.phase == TaskRoutePhase::Terminal {
            return Ok(cancelling);
        }
        let Some(upstream_task_id) = cancelling.upstream_task_id.clone() else {
            return Ok(cancelling);
        };
        if !self.cancel_upstream(&cancelling, upstream_task_id).await {
            return self.mark_reconciliation_required(&cancelling);
        }
        Ok(cancelling)
    }

    fn persist_cancellation_intent(
        &self,
        record: TaskRouteRecord,
    ) -> Result<TaskRouteRecord, McpError> {
        let mut current = record;
        for _ in 0..MAX_ROUTE_CAS_ATTEMPTS {
            if matches!(
                current.phase,
                TaskRoutePhase::CancelRequested | TaskRoutePhase::Terminal
            ) {
                return Ok(current);
            }
            current = self.update(
                &current,
                TaskRouteUpdate::cancel_requested(transition_time(&current)?),
            )?;
        }
        Err(McpError::internal_error("GM_TASK_STALE_TRANSITION", None))
    }

    fn claim_dispatch(
        &self,
        record: &TaskRouteRecord,
    ) -> Result<Option<TaskRouteRecord>, McpError> {
        match self.store.compare_and_set_task_route(
            &record.caller,
            &record.public_task_id,
            record.transition_version,
            TaskRouteUpdate::dispatching(self.instance_id.clone(), transition_time(record)?),
        ) {
            Ok(Some(claimed)) => Ok(Some(claimed)),
            Ok(None) => Err(unknown_task()),
            Err(TaskRouteStorageError::StaleTransition) => Ok(None),
            Err(error) => Err(storage_error(error)),
        }
    }

    async fn route_lock(
        &self,
        caller: &TaskRouteCaller,
        public_id: &PublicTaskId,
    ) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.route_locks.lock().await;
        locks.retain(|_, lock| lock.strong_count() > 0);
        let key = (caller.clone(), public_id.clone());
        if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        locks.insert(key, Arc::downgrade(&lock));
        lock
    }

    fn bind_upstream_task(
        &self,
        record: &TaskRouteRecord,
        upstream_task_id: UpstreamTaskId,
    ) -> Result<(TaskRouteRecord, bool), McpError> {
        let mut current = record.clone();
        for _ in 0..MAX_ROUTE_CAS_ATTEMPTS {
            if current.upstream_task_id.as_ref() == Some(&upstream_task_id) {
                let cancellation_required = current.phase == TaskRoutePhase::CancelRequested;
                return Ok((current, cancellation_required));
            }
            if current.upstream_task_id.is_some() || current.phase == TaskRoutePhase::Terminal {
                return Ok((current, true));
            }
            let update = match current.phase {
                TaskRoutePhase::Dispatching
                    if current.dispatch_owner_id == record.dispatch_owner_id =>
                {
                    TaskRouteUpdate::routed(upstream_task_id.clone(), transition_time(&current)?)
                }
                TaskRoutePhase::ReconciliationRequired => {
                    TaskRouteUpdate::routed(upstream_task_id.clone(), transition_time(&current)?)
                }
                TaskRoutePhase::CancelRequested => TaskRouteUpdate::cancel_requested_with_upstream(
                    upstream_task_id.clone(),
                    transition_time(&current)?,
                ),
                TaskRoutePhase::Dispatching => return Ok((current, true)),
                TaskRoutePhase::Prepared | TaskRoutePhase::Routed | TaskRoutePhase::Terminal => {
                    return Err(McpError::internal_error("GM_TASK_ROUTE_INVALID", None));
                }
            };
            match self.store.compare_and_set_task_route(
                &current.caller,
                &current.public_task_id,
                current.transition_version,
                update,
            ) {
                Ok(Some(bound)) => {
                    let cancellation_required = bound.phase == TaskRoutePhase::CancelRequested;
                    return Ok((bound, cancellation_required));
                }
                Ok(None) => return Err(unknown_task()),
                Err(TaskRouteStorageError::StaleTransition) => {
                    current = self
                        .store
                        .get_task_route(&record.caller, &record.public_task_id)
                        .map_err(storage_error)?
                        .ok_or_else(unknown_task)?;
                }
                Err(error) => return Err(storage_error(error)),
            }
        }
        Err(McpError::internal_error("GM_TASK_STALE_TRANSITION", None))
    }

    async fn cancel_upstream(
        &self,
        record: &TaskRouteRecord,
        upstream_task_id: UpstreamTaskId,
    ) -> bool {
        matches!(
            tokio::time::timeout(
                Duration::from_millis(MAX_TASK_LIFECYCLE_REQUEST_MS),
                self.upstreams.cancel_task_for_session(
                    &record.capability_source,
                    CancelTaskParams::new(upstream_task_id.0),
                    &record.upstream_session_id,
                ),
            )
            .await,
            Ok(Ok(()))
        )
    }

    async fn cancel_raw_upstream(&self, record: &TaskRouteRecord, upstream_task_id: &str) -> bool {
        if upstream_task_id.is_empty()
            || upstream_task_id.len() > MAX_RAW_MANAGEMENT_TASK_ID_BYTES
            || upstream_task_id.chars().any(char::is_control)
        {
            return false;
        }
        matches!(
            tokio::time::timeout(
                Duration::from_millis(MAX_TASK_LIFECYCLE_REQUEST_MS),
                self.upstreams.cancel_task_for_session(
                    &record.capability_source,
                    CancelTaskParams::new(upstream_task_id.to_owned()),
                    &record.upstream_session_id,
                ),
            )
            .await,
            Ok(Ok(()))
        )
    }

    fn finish_known_rejection(
        &self,
        record: &TaskRouteRecord,
        code: &str,
    ) -> Result<CallToolResponse, McpError> {
        let terminal =
            self.finish_terminal(record, known_rejection_task(record, code, "completed").task)?;
        let status = cached_detailed_task(&terminal)?.status();
        Ok(task_handle(&terminal, Some(status)))
    }

    fn finish_known_non_dispatch(
        &self,
        record: &TaskRouteRecord,
        code: &str,
    ) -> Result<CallToolResponse, McpError> {
        let terminal = self.finish_terminal(
            record,
            known_rejection_task(record, code, "not_dispatched").task,
        )?;
        let status = cached_detailed_task(&terminal)?.status();
        Ok(task_handle(&terminal, Some(status)))
    }

    fn finish_known_rejection_result(
        &self,
        record: &TaskRouteRecord,
        code: &str,
    ) -> Result<GetTaskResult, McpError> {
        let terminal =
            self.finish_terminal(record, known_rejection_task(record, code, "completed").task)?;
        cached_task(&terminal)
    }

    fn finish_known_non_dispatch_result(
        &self,
        record: &TaskRouteRecord,
        code: &str,
    ) -> Result<GetTaskResult, McpError> {
        let terminal = self.finish_terminal(
            record,
            known_rejection_task(record, code, "not_dispatched").task,
        )?;
        cached_task(&terminal)
    }

    fn finish_terminal(
        &self,
        record: &TaskRouteRecord,
        mut detailed: DetailedTask,
    ) -> Result<TaskRouteRecord, McpError> {
        let mut current = record.clone();
        for _ in 0..MAX_ROUTE_CAS_ATTEMPTS {
            if current.phase == TaskRoutePhase::Terminal {
                return Ok(current);
            }
            let terminal_time = transition_time(&current)?;
            detailed.task.last_updated_at = rfc3339(terminal_time);
            let cached = serde_json::to_value(&detailed)
                .map_err(|_| McpError::internal_error("GM_TASK_RESULT_SERIALIZATION", None))?;
            current = self.update(&current, TaskRouteUpdate::terminal(terminal_time, cached))?;
        }
        Err(McpError::internal_error(
            "GM_TASK_RECONCILIATION_REQUIRED",
            None,
        ))
    }

    fn update(
        &self,
        record: &TaskRouteRecord,
        update: TaskRouteUpdate,
    ) -> Result<TaskRouteRecord, McpError> {
        match self.store.compare_and_set_task_route(
            &record.caller,
            &record.public_task_id,
            record.transition_version,
            update,
        ) {
            Ok(Some(updated)) => Ok(updated),
            Ok(None) => Err(unknown_task()),
            Err(TaskRouteStorageError::StaleTransition) => self
                .store
                .get_task_route(&record.caller, &record.public_task_id)
                .map_err(storage_error)?
                .ok_or_else(unknown_task),
            Err(error) => Err(storage_error(error)),
        }
    }

    fn mark_reconciliation_required(
        &self,
        record: &TaskRouteRecord,
    ) -> Result<TaskRouteRecord, McpError> {
        let mut current = record.clone();
        for _ in 0..MAX_ROUTE_CAS_ATTEMPTS {
            if matches!(
                current.phase,
                TaskRoutePhase::ReconciliationRequired
                    | TaskRoutePhase::CancelRequested
                    | TaskRoutePhase::Terminal
            ) {
                return Ok(current);
            }
            current = self.update(
                &current,
                TaskRouteUpdate::reconciliation_required(transition_time(&current)?),
            )?;
        }
        Err(McpError::internal_error("GM_TASK_STALE_TRANSITION", None))
    }

    async fn source_binding_is_current(&self, record: &TaskRouteRecord) -> bool {
        let expected = record
            .submission_binding
            .get("sourceSnapshotSha256")
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<Sha256Digest>().ok());
        expected.is_some()
            && self
                .upstreams
                .source_session_id(&record.capability_source)
                .await
                .as_deref()
                == Some(record.upstream_session_id.as_str())
            && self
                .upstreams
                .source_snapshot_digest(&record.capability_source)
                == expected
            && self
                .upstreams
                .source_configuration_digest(&record.capability_source)
                == Some(record.capability.source_configuration_digest)
    }
}

fn submission_binding(
    tool: &FederatedTool,
    task: &TaskSubmission,
    source_snapshot_digest: Sha256Digest,
) -> Value {
    json!({
        "schemaVersion": "gaugemesh.task-route/1",
        "capabilityId": tool.identity.digest(),
        "capabilitySource": tool.identity.source,
        "capabilitySchemaSha256": tool.identity.schema_digest,
        "sourceConfigurationSha256": tool.identity.source_configuration_digest,
        "sourceSnapshotSha256": source_snapshot_digest,
        "task": task,
    })
}

fn execution_envelope(record: &TaskRouteRecord) -> Value {
    json!({
        "schemaVersion": TASK_EXECUTION_SCHEMA,
        "publicTaskId": record.public_task_id,
        "requestSha256": record.request_digest,
        "submission": record.submission_binding,
        "upstreamSessionId": record.upstream_session_id,
    })
}

fn execution_ack_matches(meta: Option<&MetaObject>, record: &TaskRouteRecord) -> bool {
    meta.and_then(|meta| meta.get(TASK_EXECUTION_META_KEY)) == Some(&execution_envelope(record))
}

fn task_handle(record: &TaskRouteRecord, status: Option<TaskStatus>) -> CallToolResponse {
    let status = status.unwrap_or_else(|| match record.phase {
        TaskRoutePhase::Terminal => record
            .cached_terminal_state
            .clone()
            .and_then(|value| serde_json::from_value::<DetailedTask>(value).ok())
            .map(|task| task.status())
            .unwrap_or(TaskStatus::Failed),
        TaskRoutePhase::Prepared
        | TaskRoutePhase::Dispatching
        | TaskRoutePhase::Routed
        | TaskRoutePhase::ReconciliationRequired
        | TaskRoutePhase::CancelRequested => TaskStatus::Working,
    });
    let message = match record.phase {
        TaskRoutePhase::Prepared => "submission is durable; routing acknowledgement is pending",
        TaskRoutePhase::Dispatching => {
            "dispatch intent is durable; upstream acknowledgement is pending"
        }
        TaskRoutePhase::ReconciliationRequired => "GM_TASK_RECONCILIATION_REQUIRED",
        TaskRoutePhase::CancelRequested => "cancellation requested; poll for terminal state",
        TaskRoutePhase::Routed => "routed to the bound upstream capability",
        TaskRoutePhase::Terminal => "terminal state is durably cached",
    };
    let result = CreateTaskResult::new(task_from_record(record, status, message))
        .with_meta(route_meta(record, "not_performed"));
    CallToolResponse::Task(result)
}

fn cached_task(record: &TaskRouteRecord) -> Result<GetTaskResult, McpError> {
    let mut detailed = cached_detailed_task(record)?;
    detailed.task.task_id = record.public_task_id.0.clone();
    let mut result = GetTaskResult::new(detailed);
    result.meta = Some(route_meta(record, "not_performed"));
    Ok(result)
}

fn cached_detailed_task(record: &TaskRouteRecord) -> Result<DetailedTask, McpError> {
    serde_json::from_value(
        record
            .cached_terminal_state
            .clone()
            .ok_or_else(|| McpError::internal_error("GM_TASK_TERMINAL_STATE_MISSING", None))?,
    )
    .map_err(|_| McpError::internal_error("GM_TASK_TERMINAL_STATE_INVALID", None))
}

fn reconciliation_task(record: &TaskRouteRecord) -> GetTaskResult {
    reconciliation_task_with_code(record, "GM_TASK_RECONCILIATION_REQUIRED")
}

fn working_task(record: &TaskRouteRecord) -> GetTaskResult {
    working_task_with_code(
        record,
        "submission is durable; routing acknowledgement is pending",
    )
}

fn working_task_with_code(record: &TaskRouteRecord, code: &str) -> GetTaskResult {
    let mut result = GetTaskResult::new(DetailedTask::new(
        task_from_record(record, TaskStatus::Working, code),
        TaskPayload::Working,
    ));
    result.meta = Some(route_meta(record, "not_performed"));
    result
}

fn reconciliation_task_with_code(record: &TaskRouteRecord, code: &str) -> GetTaskResult {
    working_task_with_code(record, code)
}

fn known_rejection_task(
    record: &TaskRouteRecord,
    code: &str,
    execution_state: &str,
) -> GetTaskResult {
    let error = json!({
        "code": -32001,
        "message": code,
        "data": {
            "executionState": execution_state,
            "brokerAcceptance": "rejected",
            "reconciliationRequired": false,
            "automaticResubmission": false,
        }
    })
    .as_object()
    .expect("failure is an object")
    .clone();
    let mut result = GetTaskResult::new(DetailedTask::new(
        task_from_record(record, TaskStatus::Failed, code),
        TaskPayload::Failed { error },
    ));
    result.meta = Some(route_meta(record, "rejected"));
    result
}

fn task_from_record(record: &TaskRouteRecord, status: TaskStatus, message: &str) -> Task {
    let mut task = Task::new(
        record.public_task_id.0.clone(),
        status,
        rfc3339(record.created_at_unix_ms),
        rfc3339(record.updated_at_unix_ms),
    )
    .with_ttl_ms(record.ttl_ms)
    .with_poll_interval_ms(100);
    task.status_message = Some(message.into());
    task
}

fn route_meta(record: &TaskRouteRecord, verification_status: &str) -> MetaObject {
    let execution_state = match record.phase {
        TaskRoutePhase::Prepared => "not_dispatched",
        TaskRoutePhase::Dispatching => "acknowledgement_pending",
        TaskRoutePhase::Routed => "upstream_reported",
        TaskRoutePhase::CancelRequested => "cancellation_requested",
        TaskRoutePhase::ReconciliationRequired => "unknown",
        TaskRoutePhase::Terminal => record
            .cached_terminal_state
            .as_ref()
            .and_then(|value| value.pointer("/error/data/executionState"))
            .and_then(Value::as_str)
            .unwrap_or("upstream_reported"),
    };
    MetaObject(
        json!({
            "dev.gaugemesh/taskRoute": {
                "schemaVersion": "gaugemesh.task-route/1",
                "publicTaskId": record.public_task_id,
                "requestSha256": record.request_digest,
                "capabilityId": record.capability.digest(),
                "source": record.capability_source,
                "routePhase": record.phase,
                "transitionVersion": record.transition_version,
                "submission": record.submission_binding,
                "executionState": execution_state,
                "reconciliationRequired": matches!(
                    record.phase,
                    TaskRoutePhase::ReconciliationRequired | TaskRoutePhase::CancelRequested
                ),
                "verificationStatus": verification_status,
                "policyAcceptance": "not_evaluated_by_gaugemesh",
                "transactionOutcome": "not_applicable_to_task_routing",
                "limitations": [
                    "upstream completion is not independent verification",
                    "task routing does not provide hostile-code containment",
                    "remote workers must enforce declared runtime and artifact limits; no autonomous watchdog runs after acknowledgement",
                    "no exactly-once external-execution claim"
                ]
            }
        })
        .as_object()
        .expect("route metadata is an object")
        .clone(),
    )
}

fn routed_upstream_id(record: &TaskRouteRecord) -> Result<UpstreamTaskId, McpError> {
    if !matches!(
        record.phase,
        TaskRoutePhase::Routed
            | TaskRoutePhase::ReconciliationRequired
            | TaskRoutePhase::CancelRequested
    ) {
        return Err(McpError::invalid_params(
            "GM_TASK_RECONCILIATION_REQUIRED",
            None,
        ));
    }
    record
        .upstream_task_id
        .clone()
        .ok_or_else(|| McpError::internal_error("GM_TASK_ROUTE_INVALID", None))
}

fn caller(identity: &AuthenticatedIdentity) -> Result<TaskRouteCaller, McpError> {
    TaskRouteCaller::new(identity.principal.clone(), identity.tenant.clone())
        .map_err(invalid_task_route)
}

fn now_unix_ms() -> Result<u64, McpError> {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| McpError::internal_error("GM_CLOCK_INVALID", None))?
        .as_millis();
    u64::try_from(milliseconds).map_err(|_| McpError::internal_error("GM_CLOCK_INVALID", None))
}

fn transition_time(record: &TaskRouteRecord) -> Result<u64, McpError> {
    Ok(now_unix_ms()?.max(record.updated_at_unix_ms))
}

fn rfc3339(unix_ms: u64) -> String {
    i64::try_from(unix_ms)
        .ok()
        .and_then(|value| Utc.timestamp_millis_opt(value).single())
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Millis, true))
        .unwrap_or_else(|| "1970-01-01T00:00:00.000Z".into())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TASK_IDENTIFIER_BYTES
        && value
            .chars()
            .all(|character| !character.is_control() && !character.is_whitespace())
}

fn output_limit(record: &TaskRouteRecord) -> usize {
    record
        .submission_binding
        .pointer("/task/limits/maxOutputBytes")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(MAX_TASK_OUTPUT_BYTES as usize)
}

fn execution_cutoff(record: &TaskRouteRecord) -> u64 {
    let deadline = record
        .submission_binding
        .pointer("/task/deadlineUnixMs")
        .and_then(Value::as_u64)
        .unwrap_or(record.expires_at_unix_ms);
    let runtime = record
        .submission_binding
        .pointer("/task/limits/maxRuntimeMs")
        .and_then(Value::as_u64)
        .unwrap_or(MAX_TASK_RUNTIME_MS);
    deadline.min(record.created_at_unix_ms.saturating_add(runtime))
}

fn json_object(value: &impl Serialize) -> Result<JsonObject, ()> {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .ok_or(())
}

fn unknown_task() -> McpError {
    McpError::invalid_params("GM_TASK_NOT_FOUND", None)
}

fn invalid_task_route(error: impl std::fmt::Display) -> McpError {
    McpError::invalid_params(error.to_string(), None)
}

fn storage_error(error: TaskRouteStorageError) -> McpError {
    match error {
        TaskRouteStorageError::IdempotencyConflict => {
            McpError::invalid_params("GM_TASK_IDEMPOTENCY_CONFLICT", None)
        }
        TaskRouteStorageError::StaleTransition => {
            McpError::invalid_params("GM_TASK_STALE_TRANSITION", None)
        }
        TaskRouteStorageError::TaskRouteCapacity => {
            McpError::invalid_params("GM_TASK_ROUTE_CAPACITY", None)
        }
        other => McpError::internal_error(other.to_string(), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gaugemesh_core::{
        capability::{CapabilityId, CapabilityKind, CapabilityRevision, SourceId},
        context::{PrincipalId, TenantId},
        federation::FederatedTool,
    };

    fn tool() -> FederatedTool {
        let source = SourceId("worker-a".into());
        FederatedTool {
            identity: CapabilityId::new(
                source.clone(),
                CapabilityKind::Tool,
                "normalize_json",
                Sha256Digest::of_bytes("schema"),
                CapabilityRevision("2026-07-28".into()),
                Sha256Digest::of_bytes("config"),
            ),
            native_name: "normalize_json".into(),
            alias: "worker-a__normalize_json".into(),
            description: "test".into(),
            input_schema: json!({"type":"object"}),
            side_effect: SideEffectClass::IdempotentWrite,
            fixture_result: Value::Null,
        }
    }

    fn submission(arguments: &JsonObject, now: u64) -> Value {
        json!({
            "schemaVersion": TASK_SUBMISSION_SCHEMA,
            "logicalTaskId": "task-1",
            "attemptId": "attempt-1",
            "correlationId": "correlation-1",
            "idempotencyKey": "key-1",
            "inputSha256": Sha256Digest::of_json(&Value::Object(arguments.clone())),
            "acceptancePolicySha256": Sha256Digest::of_bytes("policy"),
            "artifactScopeSha256": Sha256Digest::of_bytes("scope"),
            "providerInterfaceVersion": Sha256Digest::of_bytes("schema"),
            "deadlineUnixMs": now + 10_000,
            "retentionMs": 60_000,
            "limits": {
                "maxRuntimeMs": 10_000,
                "maxOutputBytes": 32_768,
                "maxArtifactBytes": 1_048_576,
                "maxAttempts": 1
            },
            "permittedEffect": "idempotent_write",
            "cleanupRequired": true
        })
    }

    #[test]
    fn submission_binds_input_policy_provider_limits_and_effect() {
        let arguments = json!({"input":{"b":2,"a":1},"outputDirectory":"artifacts"})
            .as_object()
            .unwrap()
            .clone();
        let parsed = TaskSubmission::parse(
            &submission(&arguments, 1_000),
            &arguments,
            &Sha256Digest::of_bytes("schema").to_string(),
            SideEffectClass::IdempotentWrite,
            1_000,
        )
        .unwrap();
        assert_eq!(parsed.logical_task_id, "task-1");
        assert_eq!(parsed.limits.max_attempts, 1);
    }

    #[test]
    fn changed_input_or_invalid_worker_contract_fails_before_execution() {
        let arguments = json!({"input":{"a":1}}).as_object().unwrap().clone();
        let mut wrong_input = submission(&arguments, 1_000);
        wrong_input["inputSha256"] = json!(Sha256Digest::of_bytes("other"));
        assert_eq!(
            TaskSubmission::parse(
                &wrong_input,
                &arguments,
                &Sha256Digest::of_bytes("schema").to_string(),
                SideEffectClass::IdempotentWrite,
                1_000,
            )
            .unwrap_err(),
            "GM_TASK_INPUT_IDENTITY_MISMATCH"
        );

        let mut wrong_provider = submission(&arguments, 1_000);
        wrong_provider["providerInterfaceVersion"] = json!("");
        assert_eq!(
            TaskSubmission::parse(
                &wrong_provider,
                &arguments,
                &Sha256Digest::of_bytes("schema").to_string(),
                SideEffectClass::IdempotentWrite,
                1_000,
            )
            .unwrap_err(),
            "GM_TASK_IDENTITY_INVALID"
        );

        let mut unsupported_provider = submission(&arguments, 1_000);
        unsupported_provider["providerInterfaceVersion"] = json!("worker-contract/other");
        assert_eq!(
            TaskSubmission::parse(
                &unsupported_provider,
                &arguments,
                &Sha256Digest::of_bytes("schema").to_string(),
                SideEffectClass::IdempotentWrite,
                1_000,
            )
            .unwrap_err(),
            "GM_TASK_PROVIDER_VERSION_UNSUPPORTED"
        );

        let oversized_arguments = json!({"input": "x".repeat(MAX_TASK_INPUT_BYTES)})
            .as_object()
            .unwrap()
            .clone();
        assert_eq!(
            TaskSubmission::parse(
                &submission(&oversized_arguments, 1_000),
                &oversized_arguments,
                &Sha256Digest::of_bytes("schema").to_string(),
                SideEffectClass::IdempotentWrite,
                1_000,
            )
            .unwrap_err(),
            "GM_TASK_INPUT_LIMIT_EXCEEDED"
        );
    }

    #[test]
    fn route_metadata_keeps_execution_and_verification_separate() {
        let arguments = json!({"input":{"a":1}}).as_object().unwrap().clone();
        let parsed = TaskSubmission::parse(
            &submission(&arguments, 1_000),
            &arguments,
            &Sha256Digest::of_bytes("schema").to_string(),
            SideEffectClass::IdempotentWrite,
            1_000,
        )
        .unwrap();
        let binding = submission_binding(&tool(), &parsed, Sha256Digest::of_bytes("snapshot"));
        let record = TaskRouteRecord::prepare_with_id(
            PublicTaskId::new("public-1").unwrap(),
            TaskRouteCaller::new(PrincipalId("alice".into()), TenantId("tenant-a".into())).unwrap(),
            Some(TaskRouteIdempotencyKey::new("key-1").unwrap()),
            Sha256Digest::of_json(&binding),
            binding,
            tool().identity,
            "session-1".into(),
            1_000,
            60_000,
        )
        .unwrap();
        let meta = route_meta(&record, "not_performed");
        let task = &meta.0["dev.gaugemesh/taskRoute"];
        assert_eq!(task["verificationStatus"], "not_performed");
        assert_eq!(task["executionState"], "not_dispatched");
        assert_eq!(task["policyAcceptance"], "not_evaluated_by_gaugemesh");
        assert_eq!(task["transactionOutcome"], "not_applicable_to_task_routing");
    }
}
