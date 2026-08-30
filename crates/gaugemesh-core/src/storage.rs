use std::{collections::BTreeMap, path::Path, sync::RwLock};

use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;

use crate::{digest::Sha256Digest, lease::CapabilityLease};

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("GM_STORAGE_SQLITE:{0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("GM_STORAGE_SERIALIZATION:{0}")]
    Json(#[from] serde_json::Error),
    #[error("GM_STORAGE_LOCK_POISONED")]
    Poisoned,
}

pub trait LeaseStorage: Send + Sync {
    fn put(&self, lease: &CapabilityLease) -> Result<(), StorageError>;
    fn get(&self, id: &str) -> Result<Option<CapabilityLease>, StorageError>;
    fn remove(&self, id: &str) -> Result<(), StorageError>;
}

#[derive(Debug, Default)]
pub struct MemoryStorage {
    leases: RwLock<BTreeMap<String, CapabilityLease>>,
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

#[derive(Debug)]
pub struct SqliteStorage {
    connection: std::sync::Mutex<Connection>,
}

impl SqliteStorage {
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY);
             INSERT OR IGNORE INTO schema_migrations(version) VALUES (1);
             CREATE TABLE IF NOT EXISTS leases(
               id TEXT PRIMARY KEY,
               manifest_digest TEXT NOT NULL,
               document_json TEXT NOT NULL
             );",
        )?;
        Ok(Self {
            connection: std::sync::Mutex::new(connection),
        })
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        context::{
            CapabilityScope, MoneyBudgetMicros, PrincipalId, RetryBudget, TenantId, TokenBudget,
        },
        lease::CapabilityLease,
    };

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
        assert_eq!(storage.get(&lease.id.0).unwrap(), Some(lease));
    }
}
