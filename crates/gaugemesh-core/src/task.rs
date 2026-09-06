use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    capability::{CapabilityId, SourceId},
    context::{PrincipalId, TenantId},
    digest::{Sha256Digest, canonical_json},
};

pub const TASK_ROUTE_SCHEMA_VERSION: u16 = 1;
pub const MAX_SUBMISSION_BINDING_BYTES: usize = 16 * 1024;
pub const MAX_CACHED_TERMINAL_STATE_BYTES: usize = 64 * 1024;

const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_UPSTREAM_TASK_ID_BYTES: usize = 1_024;
const MAX_SQLITE_INTEGER: u64 = i64::MAX as u64;

#[derive(
    Clone, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(transparent)]
pub struct PublicTaskId(pub String);

impl PublicTaskId {
    pub fn new(value: impl Into<String>) -> Result<Self, TaskRouteError> {
        let value = value.into();
        validate_identifier(&value, MAX_IDENTIFIER_BYTES, "public task ID")?;
        Ok(Self(value))
    }

    pub fn random() -> Self {
        Self(format!("gmt_{}", Uuid::new_v4()))
    }
}

#[derive(
    Clone, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(transparent)]
pub struct TaskRouteIdempotencyKey(pub String);

impl TaskRouteIdempotencyKey {
    pub fn new(value: impl Into<String>) -> Result<Self, TaskRouteError> {
        let value = value.into();
        validate_identifier(&value, MAX_IDENTIFIER_BYTES, "idempotency key")?;
        Ok(Self(value))
    }
}

#[derive(
    Clone, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(transparent)]
pub struct UpstreamTaskId(pub String);

impl UpstreamTaskId {
    pub fn new(value: impl Into<String>) -> Result<Self, TaskRouteError> {
        let value = value.into();
        validate_identifier(&value, MAX_UPSTREAM_TASK_ID_BYTES, "upstream task ID")?;
        Ok(Self(value))
    }
}

#[derive(
    Clone, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(deny_unknown_fields)]
pub struct TaskRouteCaller {
    pub principal: PrincipalId,
    pub tenant: TenantId,
}

impl TaskRouteCaller {
    pub fn new(principal: PrincipalId, tenant: TenantId) -> Result<Self, TaskRouteError> {
        validate_identifier(&principal.0, MAX_IDENTIFIER_BYTES, "principal ID")?;
        validate_identifier(&tenant.0, MAX_IDENTIFIER_BYTES, "tenant ID")?;
        Ok(Self { principal, tenant })
    }
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum TaskRoutePhase {
    Prepared,
    Dispatching,
    Routed,
    Terminal,
    ReconciliationRequired,
    CancelRequested,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRouteRecord {
    pub schema_version: u16,
    pub public_task_id: PublicTaskId,
    pub caller: TaskRouteCaller,
    pub idempotency_key: Option<TaskRouteIdempotencyKey>,
    pub request_digest: Sha256Digest,
    pub submission_binding: Value,
    pub capability: CapabilityId,
    pub capability_source: SourceId,
    pub upstream_session_id: String,
    pub upstream_task_id: Option<UpstreamTaskId>,
    pub dispatch_owner_id: Option<String>,
    pub phase: TaskRoutePhase,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub ttl_ms: u64,
    pub expires_at_unix_ms: u64,
    pub transition_version: u64,
    pub cached_terminal_state: Option<Value>,
    pub integrity_digest: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRouteUpdate {
    pub phase: TaskRoutePhase,
    pub upstream_task_id: Option<UpstreamTaskId>,
    pub dispatch_owner_id: Option<String>,
    pub updated_at_unix_ms: u64,
    pub cached_terminal_state: Option<Value>,
}

impl TaskRouteUpdate {
    pub fn dispatching(dispatch_owner_id: String, updated_at_unix_ms: u64) -> Self {
        Self {
            phase: TaskRoutePhase::Dispatching,
            upstream_task_id: None,
            dispatch_owner_id: Some(dispatch_owner_id),
            updated_at_unix_ms,
            cached_terminal_state: None,
        }
    }

    pub fn routed(upstream_task_id: UpstreamTaskId, updated_at_unix_ms: u64) -> Self {
        Self {
            phase: TaskRoutePhase::Routed,
            upstream_task_id: Some(upstream_task_id),
            dispatch_owner_id: None,
            updated_at_unix_ms,
            cached_terminal_state: None,
        }
    }

    pub fn terminal(updated_at_unix_ms: u64, cached_terminal_state: Value) -> Self {
        Self {
            phase: TaskRoutePhase::Terminal,
            upstream_task_id: None,
            dispatch_owner_id: None,
            updated_at_unix_ms,
            cached_terminal_state: Some(cached_terminal_state),
        }
    }

    pub fn reconciliation_required(updated_at_unix_ms: u64) -> Self {
        Self {
            phase: TaskRoutePhase::ReconciliationRequired,
            upstream_task_id: None,
            dispatch_owner_id: None,
            updated_at_unix_ms,
            cached_terminal_state: None,
        }
    }

    pub fn cancel_requested(updated_at_unix_ms: u64) -> Self {
        Self {
            phase: TaskRoutePhase::CancelRequested,
            upstream_task_id: None,
            dispatch_owner_id: None,
            updated_at_unix_ms,
            cached_terminal_state: None,
        }
    }

    pub fn cancel_requested_with_upstream(
        upstream_task_id: UpstreamTaskId,
        updated_at_unix_ms: u64,
    ) -> Self {
        Self {
            phase: TaskRoutePhase::CancelRequested,
            upstream_task_id: Some(upstream_task_id),
            dispatch_owner_id: None,
            updated_at_unix_ms,
            cached_terminal_state: None,
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TaskRouteError {
    #[error("GM_TASK_ROUTE_INVALID_IDENTIFIER:{0}")]
    InvalidIdentifier(&'static str),
    #[error("GM_TASK_ROUTE_INVALID_TTL")]
    InvalidTtl,
    #[error("GM_TASK_ROUTE_INVALID_TIMESTAMP")]
    InvalidTimestamp,
    #[error("GM_TASK_ROUTE_NUMERIC_RANGE")]
    NumericRange,
    #[error("GM_TASK_ROUTE_CAPABILITY_SOURCE_MISMATCH")]
    CapabilitySourceMismatch,
    #[error("GM_TASK_ROUTE_REQUEST_DIGEST_MISMATCH")]
    RequestDigestMismatch,
    #[error("GM_TASK_ROUTE_SUBMISSION_BINDING_TOO_LARGE:{actual}>{maximum}")]
    SubmissionBindingTooLarge { actual: usize, maximum: usize },
    #[error("GM_TASK_ROUTE_TERMINAL_STATE_TOO_LARGE:{actual}>{maximum}")]
    TerminalStateTooLarge { actual: usize, maximum: usize },
    #[error("GM_TASK_ROUTE_TERMINAL_STATE_OUTSIDE_TERMINAL_PHASE")]
    TerminalStateOutsideTerminalPhase,
    #[error("GM_TASK_ROUTE_TERMINAL_STATE_MISSING")]
    TerminalStateMissing,
    #[error("GM_TASK_ROUTE_PREPARED_HAS_UPSTREAM_TASK")]
    PreparedHasUpstreamTask,
    #[error("GM_TASK_ROUTE_ROUTED_WITHOUT_UPSTREAM_TASK")]
    RoutedWithoutUpstreamTask,
    #[error("GM_TASK_ROUTE_NOT_PREPARED_FOR_BEGIN")]
    NotPreparedForBegin,
    #[error("GM_TASK_ROUTE_UPSTREAM_TASK_CHANGED")]
    UpstreamTaskChanged,
    #[error("GM_TASK_ROUTE_UPSTREAM_TASK_ASSIGNED_OUTSIDE_ROUTED_TRANSITION")]
    UpstreamTaskAssignedOutsideRoutedTransition,
    #[error("GM_TASK_ROUTE_INVALID_TRANSITION:{from:?}->{to:?}")]
    InvalidTransition {
        from: TaskRoutePhase,
        to: TaskRoutePhase,
    },
    #[error("GM_TASK_ROUTE_INTEGRITY_MISMATCH")]
    IntegrityMismatch,
}

impl TaskRouteRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        caller: TaskRouteCaller,
        idempotency_key: Option<TaskRouteIdempotencyKey>,
        request_digest: Sha256Digest,
        submission_binding: Value,
        capability: CapabilityId,
        upstream_session_id: String,
        created_at_unix_ms: u64,
        ttl_ms: u64,
    ) -> Result<Self, TaskRouteError> {
        Self::prepare_with_id(
            PublicTaskId::random(),
            caller,
            idempotency_key,
            request_digest,
            submission_binding,
            capability,
            upstream_session_id,
            created_at_unix_ms,
            ttl_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_with_id(
        public_task_id: PublicTaskId,
        caller: TaskRouteCaller,
        idempotency_key: Option<TaskRouteIdempotencyKey>,
        request_digest: Sha256Digest,
        submission_binding: Value,
        capability: CapabilityId,
        upstream_session_id: String,
        created_at_unix_ms: u64,
        ttl_ms: u64,
    ) -> Result<Self, TaskRouteError> {
        let expires_at_unix_ms = created_at_unix_ms
            .checked_add(ttl_ms)
            .ok_or(TaskRouteError::NumericRange)?;
        let capability_source = capability.source.clone();
        let mut record = Self {
            schema_version: TASK_ROUTE_SCHEMA_VERSION,
            public_task_id,
            caller,
            idempotency_key,
            request_digest,
            submission_binding,
            capability,
            capability_source,
            upstream_session_id,
            upstream_task_id: None,
            dispatch_owner_id: None,
            phase: TaskRoutePhase::Prepared,
            created_at_unix_ms,
            updated_at_unix_ms: created_at_unix_ms,
            ttl_ms,
            expires_at_unix_ms,
            transition_version: 0,
            cached_terminal_state: None,
            integrity_digest: Sha256Digest::default(),
        };
        record.validate_shape()?;
        record.integrity_digest = record.expected_integrity_digest();
        Ok(record)
    }

    pub fn verify_integrity(&self) -> Result<(), TaskRouteError> {
        self.validate_shape()?;
        if self.integrity_digest != self.expected_integrity_digest() {
            return Err(TaskRouteError::IntegrityMismatch);
        }
        Ok(())
    }

    pub fn verify_prepared_for_begin(&self) -> Result<(), TaskRouteError> {
        self.verify_integrity()?;
        if self.phase != TaskRoutePhase::Prepared
            || self.transition_version != 0
            || self.upstream_task_id.is_some()
            || self.cached_terminal_state.is_some()
            || self.updated_at_unix_ms != self.created_at_unix_ms
        {
            return Err(TaskRouteError::NotPreparedForBegin);
        }
        Ok(())
    }

    pub fn transition(&self, update: TaskRouteUpdate) -> Result<Self, TaskRouteError> {
        self.verify_integrity()?;
        if !can_transition(self.phase, update.phase) {
            return Err(TaskRouteError::InvalidTransition {
                from: self.phase,
                to: update.phase,
            });
        }
        if update.updated_at_unix_ms < self.updated_at_unix_ms {
            return Err(TaskRouteError::InvalidTimestamp);
        }
        if self.upstream_task_id.is_none()
            && update.upstream_task_id.is_some()
            && !matches!(
                update.phase,
                TaskRoutePhase::Routed | TaskRoutePhase::CancelRequested
            )
        {
            return Err(TaskRouteError::UpstreamTaskAssignedOutsideRoutedTransition);
        }
        let upstream_task_id = match (&self.upstream_task_id, update.upstream_task_id) {
            (Some(current), Some(next)) if current != &next => {
                return Err(TaskRouteError::UpstreamTaskChanged);
            }
            (Some(current), _) => Some(current.clone()),
            (None, next) => next,
        };
        let transition_version = self
            .transition_version
            .checked_add(1)
            .filter(|version| *version <= MAX_SQLITE_INTEGER)
            .ok_or(TaskRouteError::NumericRange)?;
        let mut next = Self {
            upstream_task_id,
            dispatch_owner_id: update.dispatch_owner_id,
            phase: update.phase,
            updated_at_unix_ms: update.updated_at_unix_ms,
            transition_version,
            cached_terminal_state: update.cached_terminal_state,
            integrity_digest: Sha256Digest::default(),
            ..self.clone()
        };
        next.validate_shape()?;
        next.integrity_digest = next.expected_integrity_digest();
        Ok(next)
    }

    pub fn is_expired(&self, now_unix_ms: u64) -> bool {
        now_unix_ms >= self.expires_at_unix_ms
    }

    fn validate_shape(&self) -> Result<(), TaskRouteError> {
        if self.schema_version != TASK_ROUTE_SCHEMA_VERSION {
            return Err(TaskRouteError::IntegrityMismatch);
        }
        validate_identifier(
            &self.public_task_id.0,
            MAX_IDENTIFIER_BYTES,
            "public task ID",
        )?;
        validate_identifier(
            &self.caller.principal.0,
            MAX_IDENTIFIER_BYTES,
            "principal ID",
        )?;
        validate_identifier(&self.caller.tenant.0, MAX_IDENTIFIER_BYTES, "tenant ID")?;
        if let Some(key) = &self.idempotency_key {
            validate_identifier(&key.0, MAX_IDENTIFIER_BYTES, "idempotency key")?;
        }
        validate_identifier(
            &self.capability_source.0,
            MAX_IDENTIFIER_BYTES,
            "capability source",
        )?;
        if self.capability.source != self.capability_source {
            return Err(TaskRouteError::CapabilitySourceMismatch);
        }
        validate_identifier(
            &self.upstream_session_id,
            MAX_IDENTIFIER_BYTES,
            "upstream session ID",
        )?;
        if let Some(upstream_task_id) = &self.upstream_task_id {
            validate_identifier(
                &upstream_task_id.0,
                MAX_UPSTREAM_TASK_ID_BYTES,
                "upstream task ID",
            )?;
        }
        let canonical_binding = canonical_json(&self.submission_binding);
        let binding_bytes = serde_json::to_vec(&canonical_binding)
            .map_err(|_| TaskRouteError::IntegrityMismatch)?;
        if binding_bytes.len() > MAX_SUBMISSION_BINDING_BYTES {
            return Err(TaskRouteError::SubmissionBindingTooLarge {
                actual: binding_bytes.len(),
                maximum: MAX_SUBMISSION_BINDING_BYTES,
            });
        }
        if self.request_digest != Sha256Digest::of_json(&self.submission_binding) {
            return Err(TaskRouteError::RequestDigestMismatch);
        }
        if self.ttl_ms == 0 {
            return Err(TaskRouteError::InvalidTtl);
        }
        let expected_expiry = self
            .created_at_unix_ms
            .checked_add(self.ttl_ms)
            .ok_or(TaskRouteError::NumericRange)?;
        if expected_expiry != self.expires_at_unix_ms {
            return Err(TaskRouteError::InvalidTtl);
        }
        if [
            self.created_at_unix_ms,
            self.updated_at_unix_ms,
            self.ttl_ms,
            self.expires_at_unix_ms,
            self.transition_version,
        ]
        .into_iter()
        .any(|value| value > MAX_SQLITE_INTEGER)
        {
            return Err(TaskRouteError::NumericRange);
        }
        if self.updated_at_unix_ms < self.created_at_unix_ms {
            return Err(TaskRouteError::InvalidTimestamp);
        }
        if matches!(
            self.phase,
            TaskRoutePhase::Prepared | TaskRoutePhase::Dispatching
        ) && self.upstream_task_id.is_some()
        {
            return Err(TaskRouteError::PreparedHasUpstreamTask);
        }
        if self.phase == TaskRoutePhase::Routed && self.upstream_task_id.is_none() {
            return Err(TaskRouteError::RoutedWithoutUpstreamTask);
        }
        if (self.phase == TaskRoutePhase::Dispatching) != self.dispatch_owner_id.is_some() {
            return Err(TaskRouteError::InvalidIdentifier("dispatch owner ID"));
        }
        if let Some(dispatch_owner_id) = &self.dispatch_owner_id {
            validate_identifier(dispatch_owner_id, MAX_IDENTIFIER_BYTES, "dispatch owner ID")?;
        }
        if self.phase != TaskRoutePhase::Terminal && self.cached_terminal_state.is_some() {
            return Err(TaskRouteError::TerminalStateOutsideTerminalPhase);
        }
        if self.phase == TaskRoutePhase::Terminal && self.cached_terminal_state.is_none() {
            return Err(TaskRouteError::TerminalStateMissing);
        }
        if let Some(value) = &self.cached_terminal_state {
            let bytes = serde_json::to_vec(&canonical_json(value))
                .map_err(|_| TaskRouteError::IntegrityMismatch)?;
            if bytes.len() > MAX_CACHED_TERMINAL_STATE_BYTES {
                return Err(TaskRouteError::TerminalStateTooLarge {
                    actual: bytes.len(),
                    maximum: MAX_CACHED_TERMINAL_STATE_BYTES,
                });
            }
        }
        Ok(())
    }

    fn expected_integrity_digest(&self) -> Sha256Digest {
        Sha256Digest::of_json(&serde_json::json!({
            "schema_version": self.schema_version,
            "public_task_id": self.public_task_id,
            "caller": self.caller,
            "idempotency_key": self.idempotency_key,
            "request_digest": self.request_digest,
            "submission_binding": self.submission_binding,
            "capability": self.capability,
            "capability_source": self.capability_source,
            "upstream_session_id": self.upstream_session_id,
            "upstream_task_id": self.upstream_task_id,
            "dispatch_owner_id": self.dispatch_owner_id,
            "phase": self.phase,
            "created_at_unix_ms": self.created_at_unix_ms,
            "updated_at_unix_ms": self.updated_at_unix_ms,
            "ttl_ms": self.ttl_ms,
            "expires_at_unix_ms": self.expires_at_unix_ms,
            "transition_version": self.transition_version,
            "cached_terminal_state": self.cached_terminal_state,
        }))
    }
}

fn validate_identifier(
    value: &str,
    maximum_bytes: usize,
    name: &'static str,
) -> Result<(), TaskRouteError> {
    if value.is_empty() || value.len() > maximum_bytes || value.chars().any(char::is_control) {
        return Err(TaskRouteError::InvalidIdentifier(name));
    }
    Ok(())
}

fn can_transition(from: TaskRoutePhase, to: TaskRoutePhase) -> bool {
    matches!(
        (from, to),
        (
            TaskRoutePhase::Prepared,
            TaskRoutePhase::Dispatching
                | TaskRoutePhase::Terminal
                | TaskRoutePhase::ReconciliationRequired
                | TaskRoutePhase::CancelRequested
        ) | (
            TaskRoutePhase::Dispatching,
            TaskRoutePhase::Routed
                | TaskRoutePhase::Terminal
                | TaskRoutePhase::ReconciliationRequired
                | TaskRoutePhase::CancelRequested
        ) | (
            TaskRoutePhase::Routed,
            TaskRoutePhase::Terminal
                | TaskRoutePhase::ReconciliationRequired
                | TaskRoutePhase::CancelRequested
        ) | (
            TaskRoutePhase::ReconciliationRequired,
            TaskRoutePhase::Routed | TaskRoutePhase::Terminal | TaskRoutePhase::CancelRequested
        ) | (
            TaskRoutePhase::CancelRequested,
            TaskRoutePhase::CancelRequested | TaskRoutePhase::Terminal
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{CapabilityKind, CapabilityRevision};
    use serde_json::json;

    fn capability() -> CapabilityId {
        CapabilityId::new(
            SourceId("worker-a".into()),
            CapabilityKind::Tool,
            "normalize-json",
            Sha256Digest::of_bytes("schema"),
            CapabilityRevision("v1".into()),
            Sha256Digest::of_bytes("source-config"),
        )
    }

    fn prepared() -> TaskRouteRecord {
        let binding = json!({"task_id": "task-1", "policy_id": "policy-1"});
        TaskRouteRecord::prepare_with_id(
            PublicTaskId::new("public-1").unwrap(),
            TaskRouteCaller::new(PrincipalId("alice".into()), TenantId("tenant-a".into())).unwrap(),
            Some(TaskRouteIdempotencyKey::new("retry-1").unwrap()),
            Sha256Digest::of_json(&binding),
            binding,
            capability(),
            "session-1".into(),
            1_000,
            10_000,
        )
        .unwrap()
    }

    #[test]
    fn submission_and_mutable_state_are_integrity_bound() {
        let record = prepared();
        assert_eq!(record.verify_integrity(), Ok(()));
        assert!(!record.is_expired(10_999));
        assert!(record.is_expired(11_000));

        let mut tampered = record;
        tampered.submission_binding["policy_id"] = json!("other-policy");
        assert_eq!(
            tampered.verify_integrity(),
            Err(TaskRouteError::RequestDigestMismatch)
        );
    }

    #[test]
    fn transitions_are_ordered_and_upstream_identity_is_write_once() {
        let assigning_without_routing = TaskRouteUpdate {
            phase: TaskRoutePhase::Terminal,
            upstream_task_id: Some(UpstreamTaskId::new("upstream-1").unwrap()),
            dispatch_owner_id: None,
            updated_at_unix_ms: 1_001,
            cached_terminal_state: Some(json!({"status": "failed"})),
        };
        assert_eq!(
            prepared().transition(assigning_without_routing),
            Err(TaskRouteError::UpstreamTaskAssignedOutsideRoutedTransition)
        );

        let dispatching = prepared()
            .transition(TaskRouteUpdate::dispatching("instance-1".into(), 1_001))
            .unwrap();
        let routed = dispatching
            .transition(TaskRouteUpdate::routed(
                UpstreamTaskId::new("upstream-1").unwrap(),
                1_002,
            ))
            .unwrap();
        assert_eq!(routed.phase, TaskRoutePhase::Routed);
        assert_eq!(routed.transition_version, 2);

        let changing_upstream = TaskRouteUpdate {
            phase: TaskRoutePhase::Terminal,
            upstream_task_id: Some(UpstreamTaskId::new("upstream-2").unwrap()),
            dispatch_owner_id: None,
            updated_at_unix_ms: 1_003,
            cached_terminal_state: Some(json!({"status": "failed"})),
        };
        assert_eq!(
            routed.transition(changing_upstream),
            Err(TaskRouteError::UpstreamTaskChanged)
        );

        let terminal = routed
            .transition(TaskRouteUpdate::terminal(
                1_003,
                json!({"status": "completed"}),
            ))
            .unwrap();
        assert_eq!(terminal.phase, TaskRoutePhase::Terminal);
        assert_eq!(terminal.transition_version, 3);
        assert_eq!(terminal.verify_integrity(), Ok(()));
        assert!(matches!(
            terminal.transition(TaskRouteUpdate::cancel_requested(1_003)),
            Err(TaskRouteError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn reconciliation_can_resolve_to_a_routed_task() {
        let unknown = prepared()
            .transition(TaskRouteUpdate::reconciliation_required(1_001))
            .unwrap();
        let routed = unknown
            .transition(TaskRouteUpdate::routed(
                UpstreamTaskId::new("upstream-1").unwrap(),
                1_002,
            ))
            .unwrap();
        assert_eq!(routed.phase, TaskRoutePhase::Routed);
    }

    #[test]
    fn cancellation_intent_can_bind_a_late_ack_without_becoming_routed() {
        let dispatching = prepared()
            .transition(TaskRouteUpdate::dispatching("instance-1".into(), 1_001))
            .unwrap();
        let cancelling = dispatching
            .transition(TaskRouteUpdate::cancel_requested(1_002))
            .unwrap();
        let bound = cancelling
            .transition(TaskRouteUpdate::cancel_requested_with_upstream(
                UpstreamTaskId::new("upstream-1").unwrap(),
                1_003,
            ))
            .unwrap();
        assert_eq!(bound.phase, TaskRoutePhase::CancelRequested);
        assert_eq!(bound.upstream_task_id.unwrap().0, "upstream-1");
    }

    #[test]
    fn submission_and_terminal_cache_bounds_fail_closed() {
        let large_binding = json!({"value": "x".repeat(MAX_SUBMISSION_BINDING_BYTES)});
        assert!(matches!(
            TaskRouteRecord::prepare(
                TaskRouteCaller::new(PrincipalId("alice".into()), TenantId("tenant-a".into()))
                    .unwrap(),
                None,
                Sha256Digest::of_json(&large_binding),
                large_binding,
                capability(),
                "session-1".into(),
                1_000,
                10_000,
            ),
            Err(TaskRouteError::SubmissionBindingTooLarge { .. })
        ));

        let large_terminal = json!({"value": "x".repeat(MAX_CACHED_TERMINAL_STATE_BYTES)});
        assert!(matches!(
            prepared().transition(TaskRouteUpdate::terminal(1_001, large_terminal)),
            Err(TaskRouteError::TerminalStateTooLarge { .. })
        ));

        let mut missing_terminal_cache = prepared();
        missing_terminal_cache.phase = TaskRoutePhase::Terminal;
        assert_eq!(
            missing_terminal_cache.validate_shape(),
            Err(TaskRouteError::TerminalStateMissing)
        );
    }
}
