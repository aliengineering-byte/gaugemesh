use std::{collections::VecDeque, time::Duration};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("GM_OVERLOADED:retry_after_ms={retry_after_ms}")]
pub struct Overloaded {
    pub retry_after_ms: u64,
}

#[derive(Clone, Debug)]
pub struct DeficitRoundRobin<T> {
    tenants: VecDeque<TenantQueue<T>>,
    max_per_tenant: usize,
    max_tenants: usize,
    total_items: usize,
}

#[derive(Clone, Debug)]
struct TenantQueue<T> {
    tenant: String,
    deficit: usize,
    quantum: usize,
    items: VecDeque<(usize, T)>,
}

impl<T> DeficitRoundRobin<T> {
    pub fn new(max_per_tenant: usize) -> Self {
        Self::with_limits(max_per_tenant, 1_024)
    }

    pub fn with_limits(max_per_tenant: usize, max_tenants: usize) -> Self {
        assert!(max_per_tenant > 0 && max_tenants > 0);
        Self {
            tenants: VecDeque::new(),
            max_per_tenant,
            max_tenants,
            total_items: 0,
        }
    }

    pub fn push(&mut self, tenant: &str, cost: usize, value: T) -> Result<(), Overloaded> {
        if tenant.is_empty()
            || cost > 10_000
            || (!self.tenants.iter().any(|queue| queue.tenant == tenant)
                && self.tenants.len() >= self.max_tenants)
        {
            return Err(Overloaded {
                retry_after_ms: 100,
            });
        }
        let queue =
            if let Some(position) = self.tenants.iter().position(|queue| queue.tenant == tenant) {
                &mut self.tenants[position]
            } else {
                self.tenants.push_back(TenantQueue {
                    tenant: tenant.into(),
                    deficit: 0,
                    quantum: 1,
                    items: VecDeque::new(),
                });
                self.tenants.back_mut().expect("just inserted")
            };
        if queue.items.len() >= self.max_per_tenant {
            return Err(Overloaded {
                retry_after_ms: 100,
            });
        }
        queue.items.push_back((cost.max(1), value));
        self.total_items += 1;
        Ok(())
    }

    pub fn pop(&mut self) -> Option<T> {
        for _ in 0..self.tenants.len() {
            let mut queue = self.tenants.pop_front()?;
            queue.deficit = queue.deficit.saturating_add(queue.quantum);
            if let Some((cost, _)) = queue.items.front()
                && *cost <= queue.deficit
            {
                let (cost, value) = queue.items.pop_front().expect("front existed");
                queue.deficit -= cost;
                self.total_items = self.total_items.saturating_sub(1);
                if !queue.items.is_empty() {
                    self.tenants.push_back(queue);
                }
                return Some(value);
            }
            self.tenants.push_back(queue);
        }
        None
    }

    pub fn len(&self) -> usize {
        self.total_items
    }

    pub fn is_empty(&self) -> bool {
        self.total_items == 0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Clone, Debug)]
pub struct CircuitBreaker {
    state: BreakerState,
    failures: u16,
    successes: u16,
    opened_at_ms: Option<u64>,
    open_threshold: u16,
    recovery_threshold: u16,
    open_interval: Duration,
}

impl CircuitBreaker {
    pub fn new(open_threshold: u16, recovery_threshold: u16, open_interval: Duration) -> Self {
        assert!(open_threshold > recovery_threshold && recovery_threshold > 0);
        Self {
            state: BreakerState::Closed,
            failures: 0,
            successes: 0,
            opened_at_ms: None,
            open_threshold,
            recovery_threshold,
            open_interval,
        }
    }

    pub fn state(&mut self, now_ms: u64) -> BreakerState {
        if self.state == BreakerState::Open
            && self.opened_at_ms.is_some_and(|opened| {
                now_ms.saturating_sub(opened) >= self.open_interval.as_millis() as u64
            })
        {
            self.state = BreakerState::HalfOpen;
            self.successes = 0;
        }
        self.state
    }

    pub fn record_failure(&mut self, now_ms: u64) {
        self.failures = self.failures.saturating_add(1);
        self.successes = 0;
        if self.failures >= self.open_threshold {
            self.state = BreakerState::Open;
            self.opened_at_ms = Some(now_ms);
        }
    }

    pub fn record_success(&mut self) {
        self.failures = 0;
        if self.state == BreakerState::HalfOpen {
            self.successes = self.successes.saturating_add(1);
            if self.successes >= self.recovery_threshold {
                self.state = BreakerState::Closed;
                self.opened_at_ms = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_tenant_cannot_fill_an_unbounded_queue() {
        let mut queue = DeficitRoundRobin::new(1);
        queue.push("a", 1, 1).unwrap();
        assert!(queue.push("a", 1, 2).is_err());
        queue.push("b", 1, 3).unwrap();
        assert_eq!(queue.pop(), Some(1));
        assert_eq!(queue.pop(), Some(3));
        assert!(queue.is_empty());
    }

    #[test]
    fn tenant_cardinality_is_bounded_and_scheduling_is_fair() {
        let mut queue = DeficitRoundRobin::with_limits(2, 2);
        queue.push("a", 1, "a1").unwrap();
        queue.push("a", 1, "a2").unwrap();
        queue.push("b", 1, "b1").unwrap();
        assert!(queue.push("c", 1, "c1").is_err());
        assert_eq!(queue.len(), 3);
        assert_eq!(queue.pop(), Some("a1"));
        assert_eq!(queue.pop(), Some("b1"));
        assert_eq!(queue.pop(), Some("a2"));
    }

    #[test]
    fn breaker_has_hysteresis() {
        let mut breaker = CircuitBreaker::new(3, 2, Duration::from_millis(10));
        breaker.record_failure(0);
        breaker.record_failure(1);
        breaker.record_failure(2);
        assert_eq!(breaker.state(3), BreakerState::Open);
        assert_eq!(breaker.state(12), BreakerState::HalfOpen);
        breaker.record_success();
        assert_eq!(breaker.state(13), BreakerState::HalfOpen);
        breaker.record_success();
        assert_eq!(breaker.state(14), BreakerState::Closed);
    }
}
