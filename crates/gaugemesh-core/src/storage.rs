use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{Mutex, RwLock},
    time::Duration,
};

use rusqlite::{Connection, OptionalExtension, Row, TransactionBehavior, params};
use thiserror::Error;

use crate::{
    digest::Sha256Digest,
    lease::CapabilityLease,
    task::{
        PublicTaskId, TaskRouteCaller, TaskRouteError, TaskRouteIdempotencyKey, TaskRouteRecord,
        TaskRouteUpdate,
    },
};

const STORAGE_SCHEMA_VERSION: i64 = 3;
const MAX_TASK_ROUTE_PURGE_RECORDS_PER_CALL: usize = 10_000;
const MAX_STORED_TASK_ROUTES: usize = 4_096;
const MAX_ACTIVE_TASK_ROUTES_PER_CALLER: usize = 256;
const TASK_ROUTE_COLUMNS: &str = "public_task_id, principal_id, tenant_id, idempotency_key, \
    request_digest, capability_source, upstream_task_id, phase, created_at_unix_ms, \
    updated_at_unix_ms, ttl_ms, expires_at_unix_ms, transition_version, record_schema_version, \
    integrity_digest, document_json";

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("GM_STORAGE_SQLITE:{0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("GM_STORAGE_SERIALIZATION:{0}")]
    Json(#[from] serde_json::Error),
    #[error("GM_STORAGE_LOCK_POISONED")]
    Poisoned,
}

#[derive(Debug, Error)]
pub enum TaskRouteStorageError {
    #[error("GM_STORAGE_SQLITE:{0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("GM_STORAGE_SERIALIZATION:{0}")]
    Json(#[from] serde_json::Error),
    #[error("GM_STORAGE_TASK_ROUTE:{0}")]
    TaskRoute(#[from] TaskRouteError),
    #[error("GM_STORAGE_LOCK_POISONED")]
    Poisoned,
    #[error("GM_STORAGE_TASK_ROUTE_INTEGRITY")]
    TaskRouteIntegrity,
    #[error("GM_STORAGE_IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[error("GM_STORAGE_PUBLIC_TASK_ID_COLLISION")]
    PublicTaskIdCollision,
    #[error("GM_STORAGE_TASK_ROUTE_CAPACITY")]
    TaskRouteCapacity,
    #[error("GM_STORAGE_STALE_TRANSITION")]
    StaleTransition,
}

pub trait LeaseStorage: Send + Sync {
    fn put(&self, lease: &CapabilityLease) -> Result<(), StorageError>;
    fn get(&self, id: &str) -> Result<Option<CapabilityLease>, StorageError>;
    fn remove(&self, id: &str) -> Result<(), StorageError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BeginTaskRouteResult {
    Inserted(TaskRouteRecord),
    Existing(TaskRouteRecord),
}

impl BeginTaskRouteResult {
    pub fn record(&self) -> &TaskRouteRecord {
        match self {
            Self::Inserted(record) | Self::Existing(record) => record,
        }
    }

    pub fn into_record(self) -> TaskRouteRecord {
        match self {
            Self::Inserted(record) | Self::Existing(record) => record,
        }
    }

    pub fn was_inserted(&self) -> bool {
        matches!(self, Self::Inserted(_))
    }
}

pub trait TaskRouteStorage: Send + Sync {
    /// Read-only recovery by caller-scoped key. This never creates or extends a route.
    fn find_task_route(
        &self,
        caller: &TaskRouteCaller,
        key: &TaskRouteIdempotencyKey,
    ) -> Result<Option<TaskRouteRecord>, TaskRouteStorageError>;

    /// Atomically persists a prepared route before acknowledging it to the caller.
    ///
    /// Before its retention expiry, a caller-scoped idempotency key with the same immutable
    /// request digest returns the existing logical task and reuse with a different digest fails
    /// closed. At expiry, the old binding is atomically replaced by the new prepared route.
    fn begin_or_existing(
        &self,
        record: &TaskRouteRecord,
    ) -> Result<BeginTaskRouteResult, TaskRouteStorageError>;

    /// Looks up a route only within the supplied caller scope. An unknown ID and a route owned
    /// by another caller both return `None`.
    fn get_task_route(
        &self,
        caller: &TaskRouteCaller,
        public_task_id: &PublicTaskId,
    ) -> Result<Option<TaskRouteRecord>, TaskRouteStorageError>;

    /// Applies one legal transition when the durable version equals `expected_transition_version`.
    /// Wrong-caller and unknown IDs are deliberately indistinguishable and both return `None`.
    fn compare_and_set_task_route(
        &self,
        caller: &TaskRouteCaller,
        public_task_id: &PublicTaskId,
        expected_transition_version: u64,
        update: TaskRouteUpdate,
    ) -> Result<Option<TaskRouteRecord>, TaskRouteStorageError>;

    /// Removes at most `max_records` expired routes, oldest expiry first. Implementations may
    /// enforce a smaller internal per-call cap. A zero bound is always a no-op.
    fn purge_expired_task_routes(
        &self,
        now_unix_ms: u64,
        max_records: usize,
    ) -> Result<usize, TaskRouteStorageError>;
}

#[derive(Debug, Default)]
struct MemoryTaskRoutes {
    by_id: BTreeMap<String, TaskRouteRecord>,
    by_idempotency: BTreeMap<(TaskRouteCaller, TaskRouteIdempotencyKey), PublicTaskId>,
    by_expiry: BTreeSet<(u64, String)>,
}

#[derive(Debug, Default)]
pub struct MemoryStorage {
    leases: RwLock<BTreeMap<String, CapabilityLease>>,
    task_routes: RwLock<MemoryTaskRoutes>,
}

impl LeaseStorage for MemoryStorage {
    fn put(&self, lease: &CapabilityLease) -> Result<(), StorageError> {
        self.leases
            .write()
            .map_err(|_| StorageError::Poisoned)?
            .insert(lease.id.0.clone(), lease.clone());
        Ok(())
    }

    fn get(&self, id: &str) -> Result<Option<CapabilityLease>, StorageError> {
        Ok(self
            .leases
            .read()
            .map_err(|_| StorageError::Poisoned)?
            .get(id)
            .cloned())
    }

    fn remove(&self, id: &str) -> Result<(), StorageError> {
        self.leases
            .write()
            .map_err(|_| StorageError::Poisoned)?
            .remove(id);
        Ok(())
    }
}

impl TaskRouteStorage for MemoryStorage {
    fn find_task_route(
        &self,
        caller: &TaskRouteCaller,
        key: &TaskRouteIdempotencyKey,
    ) -> Result<Option<TaskRouteRecord>, TaskRouteStorageError> {
        let routes = self
            .task_routes
            .read()
            .map_err(|_| TaskRouteStorageError::Poisoned)?;
        let result = routes
            .by_idempotency
            .get(&(caller.clone(), key.clone()))
            .and_then(|id| routes.by_id.get(&id.0))
            .cloned();
        if let Some(record) = &result {
            record.verify_integrity()?;
        }
        Ok(result)
    }

    fn begin_or_existing(
        &self,
        record: &TaskRouteRecord,
    ) -> Result<BeginTaskRouteResult, TaskRouteStorageError> {
        record.verify_prepared_for_begin()?;
        let mut routes = self
            .task_routes
            .write()
            .map_err(|_| TaskRouteStorageError::Poisoned)?;
        let expired_idempotency = if let Some(key) = &record.idempotency_key {
            let scope = (record.caller.clone(), key.clone());
            if let Some(existing_id) = routes.by_idempotency.get(&scope) {
                let existing = routes
                    .by_id
                    .get(&existing_id.0)
                    .ok_or(TaskRouteStorageError::TaskRouteIntegrity)?;
                existing.verify_integrity()?;
                if existing.is_expired(record.created_at_unix_ms) {
                    Some((scope, existing_id.clone()))
                } else {
                    if existing.request_digest != record.request_digest {
                        return Err(TaskRouteStorageError::IdempotencyConflict);
                    }
                    return Ok(BeginTaskRouteResult::Existing(existing.clone()));
                }
            } else {
                None
            }
        } else {
            None
        };
        let candidate_collides = routes.by_id.contains_key(&record.public_task_id.0);
        let collision_is_expired_record = expired_idempotency
            .as_ref()
            .is_some_and(|(_, existing_id)| existing_id == &record.public_task_id);
        if candidate_collides && !collision_is_expired_record {
            return Err(TaskRouteStorageError::PublicTaskIdCollision);
        }
        let stored_after_replacement = routes
            .by_id
            .len()
            .saturating_sub(usize::from(expired_idempotency.is_some()));
        let active_for_caller = routes
            .by_id
            .values()
            .filter(|existing| {
                existing.caller == record.caller && !existing.is_expired(record.created_at_unix_ms)
            })
            .count();
        if stored_after_replacement >= MAX_STORED_TASK_ROUTES
            || active_for_caller >= MAX_ACTIVE_TASK_ROUTES_PER_CALLER
        {
            return Err(TaskRouteStorageError::TaskRouteCapacity);
        }
        if let Some((scope, existing_id)) = expired_idempotency {
            if let Some(expired) = routes.by_id.remove(&existing_id.0) {
                routes
                    .by_expiry
                    .remove(&(expired.expires_at_unix_ms, expired.public_task_id.0));
            }
            routes.by_idempotency.remove(&scope);
        }
        if let Some(key) = &record.idempotency_key {
            routes.by_idempotency.insert(
                (record.caller.clone(), key.clone()),
                record.public_task_id.clone(),
            );
        }
        routes
            .by_id
            .insert(record.public_task_id.0.clone(), record.clone());
        routes
            .by_expiry
            .insert((record.expires_at_unix_ms, record.public_task_id.0.clone()));
        Ok(BeginTaskRouteResult::Inserted(record.clone()))
    }

    fn get_task_route(
        &self,
        caller: &TaskRouteCaller,
        public_task_id: &PublicTaskId,
    ) -> Result<Option<TaskRouteRecord>, TaskRouteStorageError> {
        let routes = self
            .task_routes
            .read()
            .map_err(|_| TaskRouteStorageError::Poisoned)?;
        let Some(record) = routes.by_id.get(&public_task_id.0) else {
            return Ok(None);
        };
        if &record.caller != caller {
            return Ok(None);
        }
        record.verify_integrity()?;
        Ok(Some(record.clone()))
    }

    fn compare_and_set_task_route(
        &self,
        caller: &TaskRouteCaller,
        public_task_id: &PublicTaskId,
        expected_transition_version: u64,
        update: TaskRouteUpdate,
    ) -> Result<Option<TaskRouteRecord>, TaskRouteStorageError> {
        let mut routes = self
            .task_routes
            .write()
            .map_err(|_| TaskRouteStorageError::Poisoned)?;
        let Some(current) = routes.by_id.get(&public_task_id.0) else {
            return Ok(None);
        };
        if &current.caller != caller {
            return Ok(None);
        }
        current.verify_integrity()?;
        if current.transition_version != expected_transition_version {
            return Err(TaskRouteStorageError::StaleTransition);
        }
        let next = current.transition(update)?;
        routes.by_id.insert(public_task_id.0.clone(), next.clone());
        Ok(Some(next))
    }

    fn purge_expired_task_routes(
        &self,
        now_unix_ms: u64,
        max_records: usize,
    ) -> Result<usize, TaskRouteStorageError> {
        let limit = bounded_task_route_purge_limit(max_records);
        if limit == 0 {
            return Ok(0);
        }
        let mut routes = self
            .task_routes
            .write()
            .map_err(|_| TaskRouteStorageError::Poisoned)?;
        let expired = routes
            .by_expiry
            .iter()
            .take_while(|(expiry, _)| *expiry <= now_unix_ms)
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        for (expiry, public_task_id) in &expired {
            if let Some(record) = routes.by_id.remove(public_task_id)
                && let Some(key) = record.idempotency_key
            {
                routes.by_idempotency.remove(&(record.caller, key));
            }
            routes.by_expiry.remove(&(*expiry, public_task_id.clone()));
        }
        Ok(expired.len())
    }
}

fn bounded_task_route_purge_limit(max_records: usize) -> usize {
    max_records.min(MAX_TASK_ROUTE_PURGE_RECORDS_PER_CALL)
}

#[derive(Debug)]
pub struct SqliteStorage {
    pub(crate) connection: Mutex<Connection>,
}

impl SqliteStorage {
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        migrate(&mut connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }
}

fn migrate(connection: &mut Connection) -> Result<(), StorageError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY);",
    )?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current: i64 = transaction.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        [],
        |row| row.get(0),
    )?;
    if current > STORAGE_SCHEMA_VERSION {
        return Err(StorageError::Sqlite(rusqlite::Error::InvalidParameterName(
            format!("GM_STORAGE_UNSUPPORTED_SCHEMA:{current}"),
        )));
    }
    if current < 1 {
        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS leases(
               id TEXT PRIMARY KEY,
               manifest_digest TEXT NOT NULL,
               document_json TEXT NOT NULL
             );
             INSERT OR IGNORE INTO schema_migrations(version) VALUES (1);",
        )?;
    }
    if current < 2 {
        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS task_routes(
               public_task_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
               principal_id TEXT NOT NULL COLLATE BINARY,
               tenant_id TEXT NOT NULL COLLATE BINARY,
               idempotency_key TEXT COLLATE BINARY,
               request_digest TEXT NOT NULL,
               capability_source TEXT NOT NULL COLLATE BINARY,
               upstream_task_id TEXT COLLATE BINARY,
               phase TEXT NOT NULL CHECK(
                 phase IN ('prepared', 'dispatching', 'routed', 'terminal', 'reconciliation_required', 'cancel_requested')
               ),
               created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
               updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= 0),
               ttl_ms INTEGER NOT NULL CHECK(ttl_ms > 0),
               expires_at_unix_ms INTEGER NOT NULL CHECK(expires_at_unix_ms >= 0),
               transition_version INTEGER NOT NULL CHECK(transition_version >= 0),
               record_schema_version INTEGER NOT NULL CHECK(record_schema_version > 0),
               integrity_digest TEXT NOT NULL,
               document_json TEXT NOT NULL
             );
             CREATE UNIQUE INDEX IF NOT EXISTS task_routes_caller_idempotency
               ON task_routes(principal_id, tenant_id, idempotency_key)
               WHERE idempotency_key IS NOT NULL;
             CREATE INDEX IF NOT EXISTS task_routes_expiry ON task_routes(expires_at_unix_ms);
             INSERT OR IGNORE INTO schema_migrations(version) VALUES (2);",
        )?;
    }
    if current < 3 {
        transaction.execute_batch(
            "CREATE TABLE runs(
                run_id TEXT PRIMARY KEY, principal TEXT NOT NULL, tenant TEXT NOT NULL,
                run_key TEXT NOT NULL, plan_digest TEXT NOT NULL, version INTEGER NOT NULL,
                document TEXT NOT NULL, UNIQUE(principal, tenant, run_key));
             CREATE TABLE run_journal(
                run_id TEXT NOT NULL, version INTEGER NOT NULL, event TEXT NOT NULL,
                PRIMARY KEY(run_id, version));
             INSERT INTO schema_migrations(version) VALUES (3);",
        )?;
    }
    transaction.commit()?;
    Ok(())
}

impl LeaseStorage for SqliteStorage {
    fn put(&self, lease: &CapabilityLease) -> Result<(), StorageError> {
        let document = serde_json::to_string(lease)?;
        self.connection
            .lock()
            .map_err(|_| StorageError::Poisoned)?
            .execute(
                "INSERT INTO leases(id, manifest_digest, document_json) VALUES (?1, ?2, ?3)
                 ON CONFLICT(id) DO UPDATE SET manifest_digest=excluded.manifest_digest,
                 document_json=excluded.document_json",
                params![lease.id.0, lease.manifest_digest.to_string(), document],
            )?;
        Ok(())
    }

    fn get(&self, id: &str) -> Result<Option<CapabilityLease>, StorageError> {
        let connection = self.connection.lock().map_err(|_| StorageError::Poisoned)?;
        let row: Option<(String, String)> = connection
            .query_row(
                "SELECT manifest_digest, document_json FROM leases WHERE id=?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((stored_digest, document)) = row else {
            return Ok(None);
        };
        let lease: CapabilityLease = serde_json::from_str(&document)?;
        let parsed: Sha256Digest = stored_digest.parse().map_err(|_| StorageError::Poisoned)?;
        if parsed != lease.manifest_digest {
            return Err(StorageError::Poisoned);
        }
        Ok(Some(lease))
    }

    fn remove(&self, id: &str) -> Result<(), StorageError> {
        self.connection
            .lock()
            .map_err(|_| StorageError::Poisoned)?
            .execute("DELETE FROM leases WHERE id=?1", [id])?;
        Ok(())
    }
}

impl TaskRouteStorage for SqliteStorage {
    fn find_task_route(
        &self,
        caller: &TaskRouteCaller,
        key: &TaskRouteIdempotencyKey,
    ) -> Result<Option<TaskRouteRecord>, TaskRouteStorageError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| TaskRouteStorageError::Poisoned)?;
        select_task_route_by_idempotency(&connection, caller, key)
    }

    fn begin_or_existing(
        &self,
        record: &TaskRouteRecord,
    ) -> Result<BeginTaskRouteResult, TaskRouteStorageError> {
        record.verify_prepared_for_begin()?;
        let document = serde_json::to_string(record)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| TaskRouteStorageError::Poisoned)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(key) = &record.idempotency_key
            && let Some(existing) =
                select_task_route_by_idempotency(&transaction, &record.caller, key)?
        {
            if existing.is_expired(record.created_at_unix_ms) {
                let deleted = transaction.execute(
                    "DELETE FROM task_routes
                     WHERE public_task_id=?1 AND principal_id=?2 AND tenant_id=?3
                       AND idempotency_key=?4",
                    params![
                        existing.public_task_id.0,
                        existing.caller.principal.0,
                        existing.caller.tenant.0,
                        key.0,
                    ],
                )?;
                if deleted != 1 {
                    return Err(TaskRouteStorageError::TaskRouteIntegrity);
                }
            } else {
                if existing.request_digest != record.request_digest {
                    return Err(TaskRouteStorageError::IdempotencyConflict);
                }
                transaction.commit()?;
                return Ok(BeginTaskRouteResult::Existing(existing));
            }
        }
        let collision: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM task_routes WHERE public_task_id=?1)",
            [&record.public_task_id.0],
            |row| row.get(0),
        )?;
        if collision {
            return Err(TaskRouteStorageError::PublicTaskIdCollision);
        }
        let stored_routes: i64 =
            transaction.query_row("SELECT COUNT(*) FROM task_routes", [], |row| row.get(0))?;
        let created_at_unix_ms = to_sqlite_integer(record.created_at_unix_ms)?;
        let active_for_caller: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM task_routes
             WHERE principal_id=?1 AND tenant_id=?2 AND expires_at_unix_ms>?3",
            params![
                record.caller.principal.0,
                record.caller.tenant.0,
                created_at_unix_ms,
            ],
            |row| row.get(0),
        )?;
        if stored_routes >= MAX_STORED_TASK_ROUTES as i64
            || active_for_caller >= MAX_ACTIVE_TASK_ROUTES_PER_CALLER as i64
        {
            return Err(TaskRouteStorageError::TaskRouteCapacity);
        }
        transaction.execute(
            "INSERT INTO task_routes(
               public_task_id, principal_id, tenant_id, idempotency_key, request_digest,
               capability_source, upstream_task_id, phase, created_at_unix_ms,
               updated_at_unix_ms, ttl_ms, expires_at_unix_ms, transition_version,
               record_schema_version, integrity_digest, document_json
             ) VALUES (
               ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16
             )",
            params![
                record.public_task_id.0,
                record.caller.principal.0,
                record.caller.tenant.0,
                record.idempotency_key.as_ref().map(|key| &key.0),
                record.request_digest.to_string(),
                record.capability_source.0,
                record.upstream_task_id.as_ref().map(|id| &id.0),
                phase_name(record.phase),
                created_at_unix_ms,
                to_sqlite_integer(record.updated_at_unix_ms)?,
                to_sqlite_integer(record.ttl_ms)?,
                to_sqlite_integer(record.expires_at_unix_ms)?,
                to_sqlite_integer(record.transition_version)?,
                i64::from(record.schema_version),
                record.integrity_digest.to_string(),
                document,
            ],
        )?;
        transaction.commit()?;
        Ok(BeginTaskRouteResult::Inserted(record.clone()))
    }

    fn get_task_route(
        &self,
        caller: &TaskRouteCaller,
        public_task_id: &PublicTaskId,
    ) -> Result<Option<TaskRouteRecord>, TaskRouteStorageError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| TaskRouteStorageError::Poisoned)?;
        select_task_route_by_public_id(&connection, caller, public_task_id)
    }

    fn compare_and_set_task_route(
        &self,
        caller: &TaskRouteCaller,
        public_task_id: &PublicTaskId,
        expected_transition_version: u64,
        update: TaskRouteUpdate,
    ) -> Result<Option<TaskRouteRecord>, TaskRouteStorageError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| TaskRouteStorageError::Poisoned)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(current) = select_task_route_by_public_id(&transaction, caller, public_task_id)?
        else {
            return Ok(None);
        };
        if current.transition_version != expected_transition_version {
            return Err(TaskRouteStorageError::StaleTransition);
        }
        let next = current.transition(update)?;
        let document = serde_json::to_string(&next)?;
        let changed = transaction.execute(
            "UPDATE task_routes SET
               upstream_task_id=?1,
               phase=?2,
               updated_at_unix_ms=?3,
               transition_version=?4,
               integrity_digest=?5,
               document_json=?6
             WHERE public_task_id=?7 AND principal_id=?8 AND tenant_id=?9
               AND transition_version=?10",
            params![
                next.upstream_task_id.as_ref().map(|id| &id.0),
                phase_name(next.phase),
                to_sqlite_integer(next.updated_at_unix_ms)?,
                to_sqlite_integer(next.transition_version)?,
                next.integrity_digest.to_string(),
                document,
                next.public_task_id.0,
                next.caller.principal.0,
                next.caller.tenant.0,
                to_sqlite_integer(expected_transition_version)?,
            ],
        )?;
        if changed != 1 {
            return Err(TaskRouteStorageError::StaleTransition);
        }
        transaction.commit()?;
        Ok(Some(next))
    }

    fn purge_expired_task_routes(
        &self,
        now_unix_ms: u64,
        max_records: usize,
    ) -> Result<usize, TaskRouteStorageError> {
        let limit = bounded_task_route_purge_limit(max_records);
        if limit == 0 {
            return Ok(0);
        }
        let now_unix_ms = i64::try_from(now_unix_ms).unwrap_or(i64::MAX);
        let limit = i64::try_from(limit).map_err(|_| TaskRouteStorageError::TaskRouteIntegrity)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| TaskRouteStorageError::Poisoned)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let deleted = transaction.execute(
            "DELETE FROM task_routes
             WHERE public_task_id IN (
               SELECT public_task_id FROM task_routes
               WHERE expires_at_unix_ms <= ?1
               ORDER BY expires_at_unix_ms, public_task_id
               LIMIT ?2
             )",
            params![now_unix_ms, limit],
        )?;
        transaction.commit()?;
        Ok(deleted)
    }
}

#[derive(Debug)]
struct StoredTaskRoute {
    public_task_id: String,
    principal_id: String,
    tenant_id: String,
    idempotency_key: Option<String>,
    request_digest: String,
    capability_source: String,
    upstream_task_id: Option<String>,
    phase: String,
    created_at_unix_ms: i64,
    updated_at_unix_ms: i64,
    ttl_ms: i64,
    expires_at_unix_ms: i64,
    transition_version: i64,
    record_schema_version: i64,
    integrity_digest: String,
    document_json: String,
}

fn stored_task_route(row: &Row<'_>) -> rusqlite::Result<StoredTaskRoute> {
    Ok(StoredTaskRoute {
        public_task_id: row.get(0)?,
        principal_id: row.get(1)?,
        tenant_id: row.get(2)?,
        idempotency_key: row.get(3)?,
        request_digest: row.get(4)?,
        capability_source: row.get(5)?,
        upstream_task_id: row.get(6)?,
        phase: row.get(7)?,
        created_at_unix_ms: row.get(8)?,
        updated_at_unix_ms: row.get(9)?,
        ttl_ms: row.get(10)?,
        expires_at_unix_ms: row.get(11)?,
        transition_version: row.get(12)?,
        record_schema_version: row.get(13)?,
        integrity_digest: row.get(14)?,
        document_json: row.get(15)?,
    })
}

fn decode_task_route(stored: StoredTaskRoute) -> Result<TaskRouteRecord, TaskRouteStorageError> {
    let record: TaskRouteRecord = serde_json::from_str(&stored.document_json)?;
    record.verify_integrity()?;
    let stored_request_digest: Sha256Digest = stored
        .request_digest
        .parse()
        .map_err(|_| TaskRouteStorageError::TaskRouteIntegrity)?;
    let stored_integrity_digest: Sha256Digest = stored
        .integrity_digest
        .parse()
        .map_err(|_| TaskRouteStorageError::TaskRouteIntegrity)?;
    let indexed_fields_match = stored.public_task_id == record.public_task_id.0
        && stored.principal_id == record.caller.principal.0
        && stored.tenant_id == record.caller.tenant.0
        && stored.idempotency_key.as_deref()
            == record.idempotency_key.as_ref().map(|key| key.0.as_str())
        && stored_request_digest == record.request_digest
        && stored.capability_source == record.capability_source.0
        && stored.upstream_task_id.as_deref()
            == record.upstream_task_id.as_ref().map(|id| id.0.as_str())
        && stored.phase == phase_name(record.phase)
        && from_sqlite_integer(stored.created_at_unix_ms)? == record.created_at_unix_ms
        && from_sqlite_integer(stored.updated_at_unix_ms)? == record.updated_at_unix_ms
        && from_sqlite_integer(stored.ttl_ms)? == record.ttl_ms
        && from_sqlite_integer(stored.expires_at_unix_ms)? == record.expires_at_unix_ms
        && from_sqlite_integer(stored.transition_version)? == record.transition_version
        && stored.record_schema_version == i64::from(record.schema_version)
        && stored_integrity_digest == record.integrity_digest;
    if !indexed_fields_match {
        return Err(TaskRouteStorageError::TaskRouteIntegrity);
    }
    Ok(record)
}

fn select_task_route_by_public_id(
    connection: &Connection,
    caller: &TaskRouteCaller,
    public_task_id: &PublicTaskId,
) -> Result<Option<TaskRouteRecord>, TaskRouteStorageError> {
    let sql = format!(
        "SELECT {TASK_ROUTE_COLUMNS} FROM task_routes
         WHERE public_task_id=?1 AND principal_id=?2 AND tenant_id=?3"
    );
    let stored = connection
        .query_row(
            &sql,
            params![public_task_id.0, caller.principal.0, caller.tenant.0],
            stored_task_route,
        )
        .optional()?;
    stored.map(decode_task_route).transpose()
}

fn select_task_route_by_idempotency(
    connection: &Connection,
    caller: &TaskRouteCaller,
    key: &TaskRouteIdempotencyKey,
) -> Result<Option<TaskRouteRecord>, TaskRouteStorageError> {
    let sql = format!(
        "SELECT {TASK_ROUTE_COLUMNS} FROM task_routes
         WHERE principal_id=?1 AND tenant_id=?2 AND idempotency_key=?3"
    );
    let stored = connection
        .query_row(
            &sql,
            params![caller.principal.0, caller.tenant.0, key.0],
            stored_task_route,
        )
        .optional()?;
    stored.map(decode_task_route).transpose()
}

fn phase_name(phase: crate::task::TaskRoutePhase) -> &'static str {
    match phase {
        crate::task::TaskRoutePhase::Prepared => "prepared",
        crate::task::TaskRoutePhase::Dispatching => "dispatching",
        crate::task::TaskRoutePhase::Routed => "routed",
        crate::task::TaskRoutePhase::Terminal => "terminal",
        crate::task::TaskRoutePhase::ReconciliationRequired => "reconciliation_required",
        crate::task::TaskRoutePhase::CancelRequested => "cancel_requested",
    }
}

fn to_sqlite_integer(value: u64) -> Result<i64, TaskRouteStorageError> {
    value
        .try_into()
        .map_err(|_| TaskRouteStorageError::TaskRouteIntegrity)
}

fn from_sqlite_integer(value: i64) -> Result<u64, TaskRouteStorageError> {
    value
        .try_into()
        .map_err(|_| TaskRouteStorageError::TaskRouteIntegrity)
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, thread};

    use super::*;
    use crate::{
        capability::{CapabilityId, CapabilityKind, CapabilityRevision, SourceId},
        context::{
            CapabilityScope, MoneyBudgetMicros, PrincipalId, RetryBudget, TenantId, TokenBudget,
        },
        lease::CapabilityLease,
        task::{TaskRoutePhase, UpstreamTaskId},
    };
    use serde_json::json;

    fn caller(principal: &str, tenant: &str) -> TaskRouteCaller {
        TaskRouteCaller::new(PrincipalId(principal.into()), TenantId(tenant.into())).unwrap()
    }

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

    fn route(
        public_id: &str,
        route_caller: TaskRouteCaller,
        key: Option<&str>,
        request: &str,
    ) -> TaskRouteRecord {
        route_at(public_id, route_caller, key, request, 1_000, 10_000)
    }

    fn route_at(
        public_id: &str,
        route_caller: TaskRouteCaller,
        key: Option<&str>,
        request: &str,
        created_at_unix_ms: u64,
        ttl_ms: u64,
    ) -> TaskRouteRecord {
        route_at_in_session(
            public_id,
            route_caller,
            key,
            request,
            "session-1",
            created_at_unix_ms,
            ttl_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn route_at_in_session(
        public_id: &str,
        route_caller: TaskRouteCaller,
        key: Option<&str>,
        request: &str,
        upstream_session_id: &str,
        created_at_unix_ms: u64,
        ttl_ms: u64,
    ) -> TaskRouteRecord {
        let binding = json!({"request": request});
        TaskRouteRecord::prepare_with_id(
            PublicTaskId::new(public_id).unwrap(),
            route_caller,
            key.map(|value| TaskRouteIdempotencyKey::new(value).unwrap()),
            Sha256Digest::of_json(&binding),
            binding,
            capability(),
            upstream_session_id.into(),
            created_at_unix_ms,
            ttl_ms,
        )
        .unwrap()
    }

    fn exercise_begin_semantics(storage: &dyn TaskRouteStorage) {
        let alice = caller("alice", "tenant-a");
        let first = route("public-1", alice.clone(), Some("retry-1"), "request-a");
        assert!(storage.begin_or_existing(&first).unwrap().was_inserted());

        let retry = route_at_in_session(
            "public-2",
            alice.clone(),
            Some("retry-1"),
            "request-a",
            "replacement-session",
            1_000,
            10_000,
        );
        let existing = storage.begin_or_existing(&retry).unwrap();
        assert!(!existing.was_inserted());
        assert_eq!(existing.record().public_task_id, first.public_task_id);
        assert_eq!(existing.record().upstream_session_id, "session-1");

        let changed = route("public-3", alice.clone(), Some("retry-1"), "request-b");
        assert!(matches!(
            storage.begin_or_existing(&changed),
            Err(TaskRouteStorageError::IdempotencyConflict)
        ));

        let other_principal = route(
            "public-4",
            caller("bob", "tenant-a"),
            Some("retry-1"),
            "request-b",
        );
        assert!(
            storage
                .begin_or_existing(&other_principal)
                .unwrap()
                .was_inserted()
        );
        let other_tenant = route(
            "public-5",
            caller("alice", "tenant-b"),
            Some("retry-1"),
            "request-b",
        );
        assert!(
            storage
                .begin_or_existing(&other_tenant)
                .unwrap()
                .was_inserted()
        );

        let colliding_id = route("public-1", caller("carol", "tenant-b"), None, "request-c");
        assert!(matches!(
            storage.begin_or_existing(&colliding_id),
            Err(TaskRouteStorageError::PublicTaskIdCollision)
        ));
    }

    fn exercise_caller_scope_and_cas(storage: &dyn TaskRouteStorage) {
        let alice = caller("alice", "tenant-a");
        let mallory = caller("mallory", "tenant-a");
        let record = route("cas-route", alice.clone(), None, "request-a");
        storage.begin_or_existing(&record).unwrap();

        let unknown = PublicTaskId::new("not-present").unwrap();
        assert_eq!(
            storage
                .get_task_route(&mallory, &record.public_task_id)
                .unwrap(),
            None
        );
        assert_eq!(storage.get_task_route(&mallory, &unknown).unwrap(), None);
        assert_eq!(
            storage
                .compare_and_set_task_route(
                    &mallory,
                    &record.public_task_id,
                    0,
                    TaskRouteUpdate::reconciliation_required(1_001),
                )
                .unwrap(),
            None
        );

        let _dispatching = storage
            .compare_and_set_task_route(
                &alice,
                &record.public_task_id,
                0,
                TaskRouteUpdate::dispatching("instance-1".into(), 1_001),
            )
            .unwrap()
            .unwrap();
        let routed = storage
            .compare_and_set_task_route(
                &alice,
                &record.public_task_id,
                1,
                TaskRouteUpdate::routed(UpstreamTaskId::new("upstream-1").unwrap(), 1_002),
            )
            .unwrap()
            .unwrap();
        assert_eq!(routed.phase, TaskRoutePhase::Routed);
        assert_eq!(routed.transition_version, 2);
        assert!(matches!(
            storage.compare_and_set_task_route(
                &alice,
                &record.public_task_id,
                0,
                TaskRouteUpdate::terminal(1_002, json!({"status": "completed"})),
            ),
            Err(TaskRouteStorageError::StaleTransition)
        ));
        assert_eq!(
            storage
                .get_task_route(&alice, &record.public_task_id)
                .unwrap()
                .unwrap()
                .phase,
            TaskRoutePhase::Routed
        );
    }

    fn exercise_expired_key_reuse_and_bounded_gc(storage: &dyn TaskRouteStorage) {
        let route_caller = caller("alice", "tenant-a");

        let expired_same = route_at(
            "expired-same-old",
            route_caller.clone(),
            Some("expired-same-key"),
            "request-a",
            100,
            10,
        );
        assert!(
            storage
                .begin_or_existing(&expired_same)
                .unwrap()
                .was_inserted()
        );
        let replacement_same = route_at(
            "expired-same-new",
            route_caller.clone(),
            Some("expired-same-key"),
            "request-a",
            110,
            10_000,
        );
        assert!(
            storage
                .begin_or_existing(&replacement_same)
                .unwrap()
                .was_inserted()
        );
        assert_eq!(
            storage
                .get_task_route(&route_caller, &expired_same.public_task_id)
                .unwrap(),
            None
        );

        let expired_changed = route_at(
            "expired-changed-old",
            route_caller.clone(),
            Some("expired-changed-key"),
            "request-a",
            100,
            10,
        );
        assert!(
            storage
                .begin_or_existing(&expired_changed)
                .unwrap()
                .was_inserted()
        );
        let replacement_changed = route_at(
            "expired-changed-new",
            route_caller.clone(),
            Some("expired-changed-key"),
            "request-b",
            110,
            10_000,
        );
        assert!(
            storage
                .begin_or_existing(&replacement_changed)
                .unwrap()
                .was_inserted()
        );

        let occupied_id = route_at(
            "replacement-collision",
            caller("bob", "tenant-b"),
            None,
            "occupied",
            100,
            10_000,
        );
        assert!(
            storage
                .begin_or_existing(&occupied_id)
                .unwrap()
                .was_inserted()
        );
        let expired_rollback = route_at(
            "expired-rollback-old",
            route_caller.clone(),
            Some("expired-rollback-key"),
            "request-a",
            100,
            10,
        );
        assert!(
            storage
                .begin_or_existing(&expired_rollback)
                .unwrap()
                .was_inserted()
        );
        let colliding_replacement = route_at(
            "replacement-collision",
            route_caller.clone(),
            Some("expired-rollback-key"),
            "request-b",
            110,
            10_000,
        );
        assert!(matches!(
            storage.begin_or_existing(&colliding_replacement),
            Err(TaskRouteStorageError::PublicTaskIdCollision)
        ));
        assert!(
            storage
                .get_task_route(&route_caller, &expired_rollback.public_task_id)
                .unwrap()
                .is_some()
        );
        let replacement_after_collision = route_at(
            "expired-rollback-new",
            route_caller.clone(),
            Some("expired-rollback-key"),
            "request-b",
            110,
            10_000,
        );
        assert!(
            storage
                .begin_or_existing(&replacement_after_collision)
                .unwrap()
                .was_inserted()
        );

        let active = route_at(
            "active-old",
            route_caller.clone(),
            Some("active-key"),
            "request-a",
            200,
            1_000,
        );
        assert!(storage.begin_or_existing(&active).unwrap().was_inserted());
        let active_retry = route_at(
            "active-retry",
            route_caller.clone(),
            Some("active-key"),
            "request-a",
            250,
            1_000,
        );
        assert_eq!(
            storage
                .begin_or_existing(&active_retry)
                .unwrap()
                .record()
                .public_task_id,
            active.public_task_id
        );
        let active_conflict = route_at(
            "active-conflict",
            route_caller.clone(),
            Some("active-key"),
            "request-b",
            250,
            1_000,
        );
        assert!(matches!(
            storage.begin_or_existing(&active_conflict),
            Err(TaskRouteStorageError::IdempotencyConflict)
        ));

        let gc_b = route_at("gc-b", route_caller.clone(), None, "gc-b", 200, 100);
        let gc_a = route_at("gc-a", route_caller.clone(), None, "gc-a", 200, 100);
        let gc_c = route_at(
            "gc-c",
            route_caller.clone(),
            Some("gc-key"),
            "gc-c",
            300,
            100,
        );
        let gc_live = route_at("gc-live", route_caller.clone(), None, "live", 400, 1_000);
        for record in [&gc_b, &gc_a, &gc_c, &gc_live] {
            assert!(storage.begin_or_existing(record).unwrap().was_inserted());
        }

        assert_eq!(storage.purge_expired_task_routes(500, 0).unwrap(), 0);
        assert!(
            storage
                .get_task_route(&route_caller, &gc_a.public_task_id)
                .unwrap()
                .is_some()
        );
        assert_eq!(storage.purge_expired_task_routes(500, 1).unwrap(), 1);
        assert_eq!(
            storage
                .get_task_route(&route_caller, &gc_a.public_task_id)
                .unwrap(),
            None
        );
        assert!(
            storage
                .get_task_route(&route_caller, &gc_b.public_task_id)
                .unwrap()
                .is_some()
        );
        assert_eq!(storage.purge_expired_task_routes(500, 2).unwrap(), 2);
        for record in [&gc_b, &gc_c] {
            assert_eq!(
                storage
                    .get_task_route(&route_caller, &record.public_task_id)
                    .unwrap(),
                None
            );
        }
        assert!(
            storage
                .get_task_route(&route_caller, &gc_live.public_task_id)
                .unwrap()
                .is_some()
        );
        assert_eq!(storage.purge_expired_task_routes(500, 2).unwrap(), 0);
        let gc_key_reuse = route_at(
            "gc-key-reuse",
            route_caller,
            Some("gc-key"),
            "changed-after-gc",
            500,
            1_000,
        );
        assert!(
            storage
                .begin_or_existing(&gc_key_reuse)
                .unwrap()
                .was_inserted()
        );
    }

    fn exercise_per_caller_capacity(storage: &dyn TaskRouteStorage) {
        let bounded_caller = caller("bounded", "tenant-a");
        for index in 0..MAX_ACTIVE_TASK_ROUTES_PER_CALLER {
            let record = route_at(
                &format!("bounded-{index}"),
                bounded_caller.clone(),
                None,
                &format!("request-{index}"),
                1_000,
                10_000,
            );
            assert!(storage.begin_or_existing(&record).unwrap().was_inserted());
        }
        let over_limit = route_at(
            "bounded-over-limit",
            bounded_caller,
            None,
            "over-limit",
            1_000,
            10_000,
        );
        assert!(matches!(
            storage.begin_or_existing(&over_limit),
            Err(TaskRouteStorageError::TaskRouteCapacity)
        ));

        let other_caller = route_at(
            "other-caller-still-admitted",
            caller("other", "tenant-a"),
            None,
            "other",
            1_000,
            10_000,
        );
        assert!(
            storage
                .begin_or_existing(&other_caller)
                .unwrap()
                .was_inserted()
        );
    }

    #[test]
    fn memory_task_routes_are_atomic_scoped_and_versioned() {
        let storage = MemoryStorage::default();
        exercise_begin_semantics(&storage);
        exercise_caller_scope_and_cas(&storage);
    }

    #[test]
    fn sqlite_task_routes_are_atomic_scoped_and_versioned() {
        let directory = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(&directory.path().join("state.db")).unwrap();
        exercise_begin_semantics(&storage);
        exercise_caller_scope_and_cas(&storage);
    }

    #[test]
    fn memory_expired_keys_are_reusable_and_gc_is_bounded() {
        exercise_expired_key_reuse_and_bounded_gc(&MemoryStorage::default());
    }

    #[test]
    fn sqlite_expired_keys_are_reusable_and_gc_is_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(&directory.path().join("state.db")).unwrap();
        exercise_expired_key_reuse_and_bounded_gc(&storage);
    }

    #[test]
    fn memory_task_routes_enforce_per_caller_capacity() {
        exercise_per_caller_capacity(&MemoryStorage::default());
    }

    #[test]
    fn sqlite_task_routes_enforce_per_caller_capacity() {
        let directory = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(&directory.path().join("state.db")).unwrap();
        exercise_per_caller_capacity(&storage);
    }

    #[test]
    fn memory_task_routes_enforce_global_capacity() {
        let storage = MemoryStorage::default();
        for index in 0..MAX_STORED_TASK_ROUTES {
            let record = route_at(
                &format!("global-{index}"),
                caller(
                    &format!("caller-{}", index / MAX_ACTIVE_TASK_ROUTES_PER_CALLER),
                    "tenant-a",
                ),
                None,
                &format!("request-{index}"),
                1_000,
                10_000,
            );
            assert!(storage.begin_or_existing(&record).unwrap().was_inserted());
        }
        let over_limit = route_at(
            "global-over-limit",
            caller("new-caller", "tenant-a"),
            None,
            "over-limit",
            1_000,
            10_000,
        );
        assert!(matches!(
            storage.begin_or_existing(&over_limit),
            Err(TaskRouteStorageError::TaskRouteCapacity)
        ));
    }

    #[test]
    fn sqlite_insert_is_durable_before_ack_and_survives_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("state.db");
        let alice = caller("alice", "tenant-a");
        let record = route("restart-route", alice.clone(), Some("retry-1"), "request-a");
        let dispatching = {
            let storage = SqliteStorage::open(&database).unwrap();
            assert!(storage.begin_or_existing(&record).unwrap().was_inserted());
            storage
                .compare_and_set_task_route(
                    &alice,
                    &record.public_task_id,
                    0,
                    TaskRouteUpdate::dispatching("coordinator-before-crash".into(), 1_001),
                )
                .unwrap()
                .unwrap()
        };
        {
            let storage = SqliteStorage::open(&database).unwrap();
            let reopened = storage
                .get_task_route(&alice, &record.public_task_id)
                .unwrap()
                .unwrap();
            assert_eq!(reopened, dispatching);
            assert_eq!(
                reopened.dispatch_owner_id.as_deref(),
                Some("coordinator-before-crash")
            );
            let retry = route("other-id", alice.clone(), Some("retry-1"), "request-a");
            assert_eq!(
                storage.begin_or_existing(&retry).unwrap().into_record(),
                dispatching
            );
            storage
                .compare_and_set_task_route(
                    &alice,
                    &record.public_task_id,
                    1,
                    TaskRouteUpdate::reconciliation_required(1_002),
                )
                .unwrap()
                .unwrap();
        }
        let storage = SqliteStorage::open(&database).unwrap();
        assert_eq!(
            storage
                .get_task_route(&alice, &record.public_task_id)
                .unwrap()
                .unwrap()
                .phase,
            TaskRoutePhase::ReconciliationRequired
        );
    }

    #[test]
    fn two_sqlite_connections_deduplicate_the_same_submission() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("state.db");
        let first_storage = Arc::new(SqliteStorage::open(&database).unwrap());
        let second_storage = Arc::new(SqliteStorage::open(&database).unwrap());
        let route_caller = caller("alice", "tenant-a");
        let first = route(
            "race-one",
            route_caller.clone(),
            Some("race-key"),
            "request-a",
        );
        let second = route("race-two", route_caller, Some("race-key"), "request-a");
        let first_thread = {
            let storage = Arc::clone(&first_storage);
            thread::spawn(move || storage.begin_or_existing(&first).unwrap())
        };
        let second_thread = {
            let storage = Arc::clone(&second_storage);
            thread::spawn(move || storage.begin_or_existing(&second).unwrap())
        };
        let outcomes = [first_thread.join().unwrap(), second_thread.join().unwrap()];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| outcome.was_inserted())
                .count(),
            1
        );
        assert_eq!(outcomes[0].record(), outcomes[1].record());
    }

    #[test]
    fn sqlite_detects_index_or_document_tampering() {
        let directory = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(&directory.path().join("state.db")).unwrap();
        let alice = caller("alice", "tenant-a");
        let record = route("integrity-route", alice.clone(), None, "request-a");
        storage.begin_or_existing(&record).unwrap();
        storage
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE task_routes SET capability_source='tampered' WHERE public_task_id=?1",
                [&record.public_task_id.0],
            )
            .unwrap();
        assert!(matches!(
            storage.get_task_route(&alice, &record.public_task_id),
            Err(TaskRouteStorageError::TaskRouteIntegrity)
        ));
    }

    #[test]
    fn future_storage_schema_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("state.db");
        {
            let storage = SqliteStorage::open(&database).unwrap();
            storage
                .connection
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO schema_migrations(version) VALUES (?1)",
                    [STORAGE_SCHEMA_VERSION + 1],
                )
                .unwrap();
        }
        assert!(matches!(
            SqliteStorage::open(&database),
            Err(StorageError::Sqlite(rusqlite::Error::InvalidParameterName(message)))
                if message
                    == format!(
                        "GM_STORAGE_UNSUPPORTED_SCHEMA:{}",
                        STORAGE_SCHEMA_VERSION + 1
                    )
        ));
    }

    #[test]
    fn sqlite_round_trip_uses_wal() {
        let directory = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(&directory.path().join("state.db")).unwrap();
        let lease = CapabilityLease::issue(
            PrincipalId("p".into()),
            TenantId("t".into()),
            "request".into(),
            vec![],
            CapabilityScope::default(),
            10,
            MoneyBudgetMicros(0),
            TokenBudget(0),
            RetryBudget(0),
        );
        storage.put(&lease).unwrap();
        assert_eq!(
            LeaseStorage::get(&storage, &lease.id.0).unwrap(),
            Some(lease)
        );
    }
}
