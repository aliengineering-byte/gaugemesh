use std::{collections::BTreeMap, sync::Arc, time::Duration};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

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
        match self.shareability_class {
            ShareabilityClass::PrincipalIsolated if self.principal_partition.is_none() => {
                Err("GM_POOL_PRINCIPAL_PARTITION_REQUIRED")
            }
            ShareabilityClass::NonShareable if self.instance_nonce.is_none() => {
                Err("GM_POOL_INSTANCE_NONCE_REQUIRED")
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

#[derive(Clone, Debug)]
struct PoolEntry {
    generation: u64,
    references: usize,
    restart_budget: u8,
}

#[derive(Debug)]
pub struct ProcessPermit {
    pub key: ProcessKey,
    pub generation: u64,
    slot: OwnedSemaphorePermit,
}

impl ProcessPermit {
    pub fn slot_is_held(&self) -> bool {
        std::hint::black_box(&self.slot);
        true
    }
}

impl ProcessPool {
    pub fn bounded(max_processes: usize) -> Self {
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
        let slot = self
            .slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| "GM_POOL_CLOSED")?;
        let mut entries = self.entries.lock().await;
        let entry = entries.entry(key.clone()).or_insert(PoolEntry {
            generation: 1,
            references: 0,
            restart_budget: 2,
        });
        entry.references += 1;
        Ok(ProcessPermit {
            key,
            generation: entry.generation,
            slot,
        })
    }

    pub async fn release(&self, permit: ProcessPermit) {
        let mut entries = self.entries.lock().await;
        if let Some(entry) = entries.get_mut(&permit.key) {
            entry.references = entry.references.saturating_sub(1);
        }
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
