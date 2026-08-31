use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Json,
    extract::{Extension, Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

use crate::auth::AuthenticatedIdentity;

const MAX_TRACKED_TENANTS: usize = 1_024;
const MAX_GLOBAL_INFLIGHT: usize = 256;

pub struct AdmissionControl {
    tenants: Mutex<BTreeMap<String, Arc<TenantAdmission>>>,
    max_concurrent_per_tenant: usize,
    max_queue_per_tenant: usize,
    global: Arc<Semaphore>,
}

struct TenantAdmission {
    permits: Arc<Semaphore>,
    queued: AtomicUsize,
    capacity: usize,
}

struct QueueReservation<'a>(&'a AtomicUsize);

impl Drop for QueueReservation<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug)]
struct AdmissionPermit {
    _tenant: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
}

impl AdmissionControl {
    pub fn new(max_concurrent_per_tenant: u16, max_queue_per_tenant: u16) -> Self {
        Self {
            tenants: Mutex::new(BTreeMap::new()),
            max_concurrent_per_tenant: usize::from(max_concurrent_per_tenant),
            max_queue_per_tenant: usize::from(max_queue_per_tenant),
            global: Arc::new(Semaphore::new(MAX_GLOBAL_INFLIGHT)),
        }
    }

    async fn acquire(&self, tenant: &str, wait: Duration) -> Result<AdmissionPermit, &'static str> {
        let admission = {
            let mut tenants = self.tenants.lock().await;
            if tenants.len() >= MAX_TRACKED_TENANTS && !tenants.contains_key(tenant) {
                tenants.retain(|_, state| {
                    Arc::strong_count(state) > 1
                        || state.queued.load(Ordering::Acquire) > 0
                        || state.permits.available_permits() != state.capacity
                });
            }
            if tenants.len() >= MAX_TRACKED_TENANTS && !tenants.contains_key(tenant) {
                return Err("GM_OVERLOADED_TENANT_CARDINALITY");
            }
            tenants
                .entry(tenant.into())
                .or_insert_with(|| {
                    Arc::new(TenantAdmission {
                        permits: Arc::new(Semaphore::new(self.max_concurrent_per_tenant)),
                        queued: AtomicUsize::new(0),
                        capacity: self.max_concurrent_per_tenant,
                    })
                })
                .clone()
        };
        let tenant_permit = match admission.permits.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                admission
                    .queued
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |queued| {
                        (queued < self.max_queue_per_tenant).then_some(queued + 1)
                    })
                    .map_err(|_| "GM_OVERLOADED_TENANT_QUEUE")?;
                let _reservation = QueueReservation(&admission.queued);
                tokio::time::timeout(wait, admission.permits.clone().acquire_owned())
                    .await
                    .map_err(|_| "GM_OVERLOADED_QUEUE_TIMEOUT")?
                    .map_err(|_| "GM_OVERLOADED_CLOSED")?
            }
        };
        let global = self
            .global
            .clone()
            .try_acquire_owned()
            .map_err(|_| "GM_OVERLOADED_GLOBAL")?;
        Ok(AdmissionPermit {
            _tenant: tenant_permit,
            _global: global,
        })
    }
}

pub async fn limit_requests(
    State(state): State<Arc<AdmissionControl>>,
    identity: Option<Extension<AuthenticatedIdentity>>,
    request: Request,
    next: Next,
) -> Response {
    let tenant = identity
        .as_deref()
        .map(|identity| identity.tenant.0.as_str())
        .unwrap_or("local");
    let wait = request
        .headers()
        .get("x-gaugemesh-deadline-ms")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(|milliseconds| Duration::from_millis(milliseconds.min(30_000)))
        .unwrap_or_else(|| Duration::from_secs(30));
    let _permit = match state.acquire(tenant, wait).await {
        Ok(permit) => permit,
        Err(code) => return overloaded(code),
    };
    next.run(request).await
}

fn overloaded(code: &'static str) -> Response {
    let mut response = (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error":{"code":code,"retryAfterMs":100}})),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tenant_queues_are_bounded_and_other_tenants_remain_admissible() {
        let admission = Arc::new(AdmissionControl::new(1, 1));
        let active = admission
            .acquire("tenant-a", Duration::from_secs(1))
            .await
            .unwrap();
        let waiting_control = admission.clone();
        let waiting = tokio::spawn(async move {
            waiting_control
                .acquire("tenant-a", Duration::from_secs(1))
                .await
        });
        while admission
            .tenants
            .lock()
            .await
            .get("tenant-a")
            .unwrap()
            .queued
            .load(Ordering::Acquire)
            == 0
        {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            admission
                .acquire("tenant-a", Duration::from_millis(1))
                .await
                .unwrap_err(),
            "GM_OVERLOADED_TENANT_QUEUE"
        );
        let other = admission
            .acquire("tenant-b", Duration::from_millis(1))
            .await
            .unwrap();
        drop(other);
        drop(active);
        assert!(waiting.await.unwrap().is_ok());
    }
}
