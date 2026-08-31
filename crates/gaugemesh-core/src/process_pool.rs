use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, OwnedMutexGuard, OwnedSemaphorePermit, Semaphore};

use crate::digest::Sha256Digest;

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ShareabilityClass {
    ShareableStateless,
    ShareableWithSerialization,
    PrincipalIsolated,
    TenantIsolated,
    NonShareable,
}

impl Default for ShareabilityClass {
    fn default() -> Self {
        Self::NonShareable
    }
}

#[derive(
    Clone, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(deny_unknown_fields)]
pub struct ProcessKey {
    pub server_configuration_digest: Sha256Digest,
    pub executable_identity: String,
    pub protocol_revision: String,
    pub tenant_security_partition: String,
    pub upstream_credential_identity: Sha256Digest,
    pub environment_digest: Sha256Digest,
    pub shareability_class: ShareabilityClass,
    pub principal_partition: Option<String>,
    pub instance_nonce: Option<String>,
}

impl ProcessKey {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.executable_identity.is_empty()
            || self.protocol_revision.is_empty()
            || self.tenant_security_partition.is_empty()
        {
            return Err("GM_POOL_KEY_INCOMPLETE");
        }
        match self.shareability_class {
            ShareabilityClass::PrincipalIsolated
                if self.principal_partition.is_none() || self.instance_nonce.is_some() =>
            {
                Err("GM_POOL_PRINCIPAL_PARTITION_REQUIRED")
            }
            ShareabilityClass::NonShareable if self.instance_nonce.is_none() => {
                Err("GM_POOL_INSTANCE_NONCE_REQUIRED")
            }
            ShareabilityClass::ShareableStateless
            | ShareabilityClass::ShareableWithSerialization
            | ShareabilityClass::TenantIsolated
                if self.principal_partition.is_some() || self.instance_nonce.is_some() =>
            {
                Err("GM_POOL_PARTITION_CONTRADICTION")
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProcessPool {
    entries: Arc<Mutex<BTreeMap<ProcessKey, PoolEntry>>>,
    slots: Arc<Semaphore>,
    pub startup_timeout: Duration,
    pub shutdown_timeout: Duration,
    pub idle_ttl: Duration,
}

#[derive(Debug)]
struct PoolEntry {
    generation: u64,
    references: usize,
    restart_budget: u8,
    last_idle_at: Option<Instant>,
    serialization: Arc<Mutex<()>>,
    _slot: OwnedSemaphorePermit,
}

#[derive(Debug)]
pub struct ProcessPermit {
    pub key: ProcessKey,
    pub generation: u64,
    _serialization: Option<OwnedMutexGuard<()>>,
}

impl ProcessPool {
    pub fn bounded(max_processes: usize) -> Self {
        assert!(max_processes > 0, "a process pool must have capacity");
        Self {
            entries: Arc::new(Mutex::new(BTreeMap::new())),
            slots: Arc::new(Semaphore::new(max_processes)),
            startup_timeout: Duration::from_secs(10),
            shutdown_timeout: Duration::from_secs(5),
            idle_ttl: Duration::from_secs(30),
        }
    }

    pub async fn acquire(&self, key: ProcessKey) -> Result<ProcessPermit, &'static str> {
        key.validate()?;
        if let Some((generation, serialization)) = self.acquire_existing(&key).await {
            return Ok(ProcessPermit {
                key,
                generation,
                _serialization: serialization,
            });
        }
        let slot = tokio::time::timeout(self.startup_timeout, self.slots.clone().acquire_owned())
            .await
            .map_err(|_| "GM_POOL_CAPACITY_TIMEOUT")?
            .map_err(|_| "GM_POOL_CLOSED")?;
        let (generation, serialization) = {
            let mut entries = self.entries.lock().await;
            if entries.contains_key(&key) {
                let serialization = entries
                    .get(&key)
                    .and_then(|entry| serialization_lock(&key, entry));
                let serialization = match serialization {
                    Some(lock) => Some(lock.lock_owned().await),
                    None => None,
                };
                let entry = entries.get_mut(&key).expect("entry remained locked");
                entry.references += 1;
                entry.last_idle_at = None;
                (entry.generation, serialization)
            } else {
                let serialization = Arc::new(Mutex::new(()));
                let serialization_guard = if needs_serialization(&key) {
                    Some(serialization.clone().lock_owned().await)
                } else {
                    None
                };
                entries.insert(
                    key.clone(),
                    PoolEntry {
                        generation: 1,
                        references: 1,
                        restart_budget: 2,
                        last_idle_at: None,
                        serialization: serialization.clone(),
                        _slot: slot,
                    },
                );
                (1, serialization_guard)
            }
        };
        Ok(ProcessPermit {
            key,
            generation,
            _serialization: serialization,
        })
    }

    async fn acquire_existing(
        &self,
        key: &ProcessKey,
    ) -> Option<(u64, Option<OwnedMutexGuard<()>>)> {
        let mut entries = self.entries.lock().await;
        if !entries.contains_key(key) {
            return None;
        }
        let serialization = entries
            .get(key)
            .and_then(|entry| serialization_lock(key, entry));
        let serialization = match serialization {
            Some(lock) => Some(lock.lock_owned().await),
            None => None,
        };
        let entry = entries.get_mut(key).expect("entry remained locked");
        entry.references += 1;
        entry.last_idle_at = None;
        Some((entry.generation, serialization))
    }

    pub async fn release(&self, permit: ProcessPermit) {
        let ProcessPermit {
            key,
            _serialization,
            ..
        } = permit;
        drop(_serialization);
        let mut entries = self.entries.lock().await;
        if let Some(entry) = entries.get_mut(&key) {
            entry.references = entry.references.saturating_sub(1);
            if entry.references == 0 {
                entry.last_idle_at = Some(Instant::now());
            }
        }
    }

    pub async fn reap_idle(&self) -> Vec<ProcessKey> {
        let now = Instant::now();
        let mut entries = self.entries.lock().await;
        let expired = entries
            .iter()
            .filter(|(_, entry)| {
                entry.references == 0
                    && entry
                        .last_idle_at
                        .is_some_and(|idle| now.saturating_duration_since(idle) >= self.idle_ttl)
            })
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in &expired {
            entries.remove(key);
        }
        expired
    }

    pub async fn process_count(&self) -> usize {
        self.entries.lock().await.len()
    }

    pub async fn record_crash(&self, key: &ProcessKey) -> Result<u64, &'static str> {
        let mut entries = self.entries.lock().await;
        let entry = entries.get_mut(key).ok_or("GM_POOL_PROCESS_NOT_FOUND")?;
        if entry.restart_budget == 0 {
            return Err("GM_POOL_RESTART_BUDGET_EXHAUSTED");
        }
        entry.restart_budget -= 1;
        entry.generation += 1;
        Ok(entry.generation)
    }
}

fn needs_serialization(key: &ProcessKey) -> bool {
    key.shareability_class == ShareabilityClass::ShareableWithSerialization
}

fn serialization_lock(key: &ProcessKey, entry: &PoolEntry) -> Option<Arc<Mutex<()>>> {
    needs_serialization(key).then(|| entry.serialization.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(class: ShareabilityClass, principal: Option<&str>, nonce: Option<&str>) -> ProcessKey {
        ProcessKey {
            server_configuration_digest: Sha256Digest::of_bytes("config"),
            executable_identity: "/reviewed/server".into(),
            protocol_revision: "2026-07-28".into(),
            tenant_security_partition: "tenant-a".into(),
            upstream_credential_identity: Sha256Digest::of_bytes("credential-a"),
            environment_digest: Sha256Digest::of_bytes("clean-env"),
            shareability_class: class,
            principal_partition: principal.map(str::to_owned),
            instance_nonce: nonce.map(str::to_owned),
        }
    }

    #[tokio::test]
    async fn safe_namespaces_reuse_one_generation() {
        let pool = ProcessPool::bounded(2);
        let key = key(ShareabilityClass::ShareableStateless, None, None);
        let first = pool.acquire(key.clone()).await.unwrap();
        let second = pool.acquire(key).await.unwrap();
        assert_eq!(first.generation, second.generation);
        pool.release(first).await;
        pool.release(second).await;
    }

    #[tokio::test]
    async fn process_slots_are_per_process_and_idle_entries_are_reaped() {
        let mut pool = ProcessPool::bounded(1);
        pool.startup_timeout = Duration::from_millis(10);
        pool.idle_ttl = Duration::ZERO;
        let shared = key(ShareabilityClass::ShareableStateless, None, None);
        let first = pool.acquire(shared.clone()).await.unwrap();
        let second = pool.acquire(shared).await.unwrap();
        assert_eq!(pool.process_count().await, 1);
        assert_eq!(
            pool.acquire(key(ShareabilityClass::NonShareable, None, Some("another")))
                .await
                .unwrap_err(),
            "GM_POOL_CAPACITY_TIMEOUT"
        );
        pool.release(first).await;
        pool.release(second).await;
        assert_eq!(pool.reap_idle().await.len(), 1);
        assert_eq!(pool.process_count().await, 0);
    }

    #[tokio::test]
    async fn serialized_sharing_allows_only_one_active_reference() {
        let pool = ProcessPool::bounded(1);
        let process_key = key(ShareabilityClass::ShareableWithSerialization, None, None);
        let first = pool.acquire(process_key.clone()).await.unwrap();
        let waiting_pool = pool.clone();
        let waiting = tokio::spawn(async move { waiting_pool.acquire(process_key).await.unwrap() });
        assert!(
            tokio::time::timeout(Duration::from_millis(10), async {
                while !waiting.is_finished() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .is_err()
        );
        pool.release(first).await;
        let second = waiting.await.unwrap();
        pool.release(second).await;
    }

    #[test]
    fn principal_and_nonshareable_classes_require_partitioning() {
        assert_eq!(
            key(ShareabilityClass::PrincipalIsolated, None, None).validate(),
            Err("GM_POOL_PRINCIPAL_PARTITION_REQUIRED")
        );
        assert_eq!(
            key(ShareabilityClass::NonShareable, None, None).validate(),
            Err("GM_POOL_INSTANCE_NONCE_REQUIRED")
        );
        assert!(
            key(ShareabilityClass::PrincipalIsolated, Some("alice"), None)
                .validate()
                .is_ok()
        );
    }

    #[tokio::test]
    async fn restart_is_bounded() {
        let pool = ProcessPool::bounded(1);
        let key = key(ShareabilityClass::ShareableStateless, None, None);
        let permit = pool.acquire(key.clone()).await.unwrap();
        pool.release(permit).await;
        assert_eq!(pool.record_crash(&key).await.unwrap(), 2);
        assert_eq!(pool.record_crash(&key).await.unwrap(), 3);
        assert_eq!(
            pool.record_crash(&key).await,
            Err("GM_POOL_RESTART_BUDGET_EXHAUSTED")
        );
    }
}
