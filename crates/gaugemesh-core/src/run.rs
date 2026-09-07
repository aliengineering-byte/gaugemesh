//! Bounded application-run snapshots and their atomic journal in the existing SQLite store.
//! This module does not dispatch work. Task routes remain the only execution authority.
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{digest::Sha256Digest, storage::SqliteStorage, task::TaskRouteCaller};

type Result<T> = std::result::Result<T, RunError>;

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("GM_RUN_STORAGE:{0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("GM_RUN_DOCUMENT:{0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Invalid(&'static str),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunEvent {
    pub version: u64,
    pub kind: String,
    pub state_sha256: Sha256Digest,
    pub previous_sha256: Sha256Digest,
    pub event_sha256: Sha256Digest,
}

impl RunEvent {
    fn digest(&self) -> Sha256Digest {
        Sha256Digest::of_json(&json!({"version": self.version, "kind": self.kind,
            "stateSha256": self.state_sha256, "previousSha256": self.previous_sha256}))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunRecord {
    pub schema_version: String,
    pub run_id: String,
    pub caller: TaskRouteCaller,
    pub run_key: String,
    pub plan_sha256: Sha256Digest,
    pub version: u64,
    pub data: Value,
    pub journal: Vec<RunEvent>,
}

impl RunRecord {
    fn state_digest(&self) -> Sha256Digest {
        Sha256Digest::of_json(&json!({"schemaVersion": self.schema_version,
            "runId": self.run_id, "caller": self.caller, "runKey": self.run_key,
            "planSha256": self.plan_sha256, "version": self.version, "data": self.data}))
    }

    pub fn verify_integrity(&self) -> Result<()> {
        if self.schema_version != "gaugemesh.run-evidence/1"
            || self.version > 512
            || self.journal.len() != self.version as usize + 1
            || self.data.get("plan").map(Sha256Digest::of_json) != Some(self.plan_sha256)
            || self.data["plan"]["runKey"] != self.run_key
        {
            return Err(RunError::Invalid("GM_RUN_INTEGRITY"));
        }
        let mut previous = Sha256Digest::default();
        for (i, entry) in self.journal.iter().enumerate() {
            if entry.version != i as u64
                || entry.previous_sha256 != previous
                || entry.digest() != entry.event_sha256
            {
                return Err(RunError::Invalid("GM_RUN_JOURNAL_INTEGRITY"));
            }
            previous = entry.event_sha256;
        }
        if self.journal.last().map(|e| e.state_sha256) != Some(self.state_digest()) {
            return Err(RunError::Invalid("GM_RUN_INTEGRITY"));
        }
        Ok(())
    }

    fn append(&mut self, kind: &str) -> Result<()> {
        if self.version > 512
            || kind.len() > 128
            || serde_json::to_vec(&self.data)?.len() > 2 * 1024 * 1024
        {
            return Err(RunError::Invalid("GM_RUN_STORAGE_BOUND"));
        }
        let mut entry = RunEvent {
            version: self.version,
            kind: kind.into(),
            state_sha256: self.state_digest(),
            previous_sha256: self
                .journal
                .last()
                .map(|e| e.event_sha256)
                .unwrap_or_default(),
            event_sha256: Sha256Digest::default(),
        };
        entry.event_sha256 = entry.digest();
        self.journal.push(entry);
        self.verify_integrity()
    }
}

impl SqliteStorage {
    pub fn find_run(&self, caller: &TaskRouteCaller, key: &str) -> Result<Option<RunRecord>> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| RunError::Invalid("GM_RUN_STORAGE_LOCK"))?;
        let id: Option<String> = connection
            .query_row(
                "SELECT run_id FROM runs WHERE principal=?1 AND tenant=?2 AND run_key=?3",
                params![caller.principal.0, caller.tenant.0, key],
                |r| r.get(0),
            )
            .optional()?;
        match id {
            Some(id) => load(&connection, caller, &id),
            None => Ok(None),
        }
    }

    /// Accept an immutable plan before any dispatch. Existing identity never expires implicitly.
    pub fn begin_run(
        &self,
        caller: TaskRouteCaller,
        run_key: &str,
        data: Value,
    ) -> Result<RunRecord> {
        if run_key.is_empty() || run_key.len() > 128 || !data["plan"].is_object() {
            return Err(RunError::Invalid("GM_RUN_PLAN_INVALID"));
        }
        let digest = Sha256Digest::of_json(&data["plan"]);
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| RunError::Invalid("GM_RUN_STORAGE_LOCK"))?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT run_id FROM runs WHERE principal=?1 AND tenant=?2 AND run_key=?3",
                params![caller.principal.0, caller.tenant.0, run_key],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(id) = existing {
            let record = load(&tx, &caller, &id)?.ok_or(RunError::Invalid("GM_RUN_INTEGRITY"))?;
            if record.plan_sha256 != digest {
                return Err(RunError::Invalid("GM_RUN_IDEMPOTENCY_CONFLICT"));
            }
            return Ok(record);
        }
        let total: i64 = tx.query_row("SELECT COUNT(*) FROM runs", [], |r| r.get(0))?;
        if total >= 128 {
            return Err(RunError::Invalid("GM_RUN_STORAGE_CAPACITY"));
        }
        let mut record = RunRecord {
            schema_version: "gaugemesh.run-evidence/1".into(),
            run_id: format!("gmr_{}", uuid::Uuid::new_v4()),
            caller,
            run_key: run_key.into(),
            plan_sha256: digest,
            version: 0,
            data,
            journal: vec![],
        };
        record.append("accepted")?;
        tx.execute(
            "INSERT INTO runs VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                record.run_id,
                record.caller.principal.0,
                record.caller.tenant.0,
                record.run_key,
                digest.to_string(),
                0,
                serde_json::to_string(&record.data)?
            ],
        )?;
        insert_event(&tx, &record)?;
        tx.commit()?;
        Ok(record)
    }

    pub fn get_run(&self, caller: &TaskRouteCaller, id: &str) -> Result<Option<RunRecord>> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| RunError::Invalid("GM_RUN_STORAGE_LOCK"))?;
        load(&connection, caller, id)
    }

    /// State and journal advance together; callers cannot overwrite another driver's version.
    pub fn advance_run(&self, old: &RunRecord, data: Value, kind: &str) -> Result<RunRecord> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| RunError::Invalid("GM_RUN_STORAGE_LOCK"))?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut current =
            load(&tx, &old.caller, &old.run_id)?.ok_or(RunError::Invalid("GM_RUN_NOT_FOUND"))?;
        if current.version != old.version {
            return Err(RunError::Invalid("GM_RUN_STALE_DRIVER"));
        }
        if data.get("plan") != current.data.get("plan") {
            return Err(RunError::Invalid("GM_RUN_PLAN_IMMUTABLE"));
        }
        current.version += 1;
        current.data = data;
        current.append(kind)?;
        let changed = tx.execute(
            "UPDATE runs SET document=?1, version=?2 WHERE run_id=?3 AND version=?4",
            params![
                serde_json::to_string(&current.data)?,
                current.version,
                current.run_id,
                old.version
            ],
        )?;
        if changed != 1 {
            return Err(RunError::Invalid("GM_RUN_STALE_DRIVER"));
        }
        insert_event(&tx, &current)?;
        tx.commit()?;
        Ok(current)
    }
}

fn insert_event(connection: &Connection, record: &RunRecord) -> Result<()> {
    connection.execute(
        "INSERT INTO run_journal VALUES(?1,?2,?3)",
        params![
            record.run_id,
            record.version,
            serde_json::to_string(record.journal.last().unwrap())?
        ],
    )?;
    Ok(())
}

fn load(connection: &Connection, caller: &TaskRouteCaller, id: &str) -> Result<Option<RunRecord>> {
    let row: Option<(String, String, u64, String)> = connection.query_row(
        "SELECT run_key, plan_digest, version, document FROM runs WHERE run_id=?1 AND principal=?2 AND tenant=?3",
        params![id, caller.principal.0, caller.tenant.0], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
    let Some((run_key, digest, version, document)) = row else {
        return Ok(None);
    };
    if document.len() > 2 * 1024 * 1024 || version > 512 {
        return Err(RunError::Invalid("GM_RUN_STORAGE_BOUND"));
    }
    let mut statement = connection
        .prepare("SELECT event FROM run_journal WHERE run_id=?1 ORDER BY version LIMIT 514")?;
    let entries = statement
        .query_map([id], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let record = RunRecord {
        schema_version: "gaugemesh.run-evidence/1".into(),
        run_id: id.into(),
        caller: caller.clone(),
        run_key,
        plan_sha256: digest
            .parse()
            .map_err(|_| RunError::Invalid("GM_RUN_INTEGRITY"))?,
        version,
        data: serde_json::from_str(&document)?,
        journal: entries
            .into_iter()
            .map(|entry| serde_json::from_str(&entry))
            .collect::<std::result::Result<_, _>>()?,
    };
    record.verify_integrity()?;
    Ok(Some(record))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{PrincipalId, TenantId};

    #[test]
    fn finite_numeric_evidence_survives_storage_and_export_round_trips() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("numbers.sqlite");
        let caller = TaskRouteCaller::new(PrincipalId("a".into()), TenantId("t".into())).unwrap();
        let store = SqliteStorage::open(&path).unwrap();
        let numbers: Value = serde_json::from_str(
            r#"[200.0000000003638,6.766666666678794e-8,1.1000000000000001e-8,4.0999999999890864e-7,0.000600009999998363,2.7284258976578712e-6,1.001e-6]"#,
        ).unwrap();
        let first = store
            .begin_run(
                caller.clone(),
                "numeric",
                json!({"plan":{"runKey":"numeric"},"evidence":numbers}),
            )
            .unwrap();
        let reloaded = store.get_run(&caller, &first.run_id).unwrap().unwrap();
        assert_eq!(reloaded.data, first.data);
        let mut exported = serde_json::to_string(&reloaded).unwrap();
        for _ in 0..4 {
            let decoded: RunRecord = serde_json::from_str(&exported).unwrap();
            decoded.verify_integrity().unwrap();
            let encoded = serde_json::to_string(&decoded).unwrap();
            assert_eq!(encoded, exported);
            exported = encoded;
        }
    }

    #[test]
    fn durable_caller_identity_cas_journal_and_tamper() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.sqlite");
        let caller = TaskRouteCaller::new(PrincipalId("a".into()), TenantId("t".into())).unwrap();
        let store = SqliteStorage::open(&path).unwrap();
        let data = json!({"plan":{"runKey":"key"},"state":"pending"});
        let first = store
            .begin_run(caller.clone(), "key", data.clone())
            .unwrap();
        assert_eq!(
            first.run_id,
            store.begin_run(caller.clone(), "key", data).unwrap().run_id
        );
        assert!(
            store
                .begin_run(
                    caller.clone(),
                    "key",
                    json!({"plan":{"runKey":"key","changed":true}})
                )
                .is_err()
        );
        let mut next = first.data.clone();
        next["state"] = json!("done");
        let second = store.advance_run(&first, next.clone(), "verified").unwrap();
        assert!(store.advance_run(&first, next, "stale").is_err());
        let other =
            TaskRouteCaller::new(PrincipalId("other".into()), TenantId("t".into())).unwrap();
        assert!(store.get_run(&other, &first.run_id).unwrap().is_none());
        drop(store);
        let reopened = SqliteStorage::open(&path).unwrap();
        assert_eq!(
            reopened
                .get_run(&caller, &first.run_id)
                .unwrap()
                .unwrap()
                .version,
            1
        );
        let mut tampered = second;
        tampered.data["state"] = json!("forged");
        assert!(tampered.verify_integrity().is_err());
        reopened
            .connection
            .lock()
            .unwrap()
            .execute("DELETE FROM run_journal WHERE version=0", [])
            .unwrap();
        assert!(reopened.get_run(&caller, &first.run_id).is_err());
    }
}
