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
        Self {
            tenants: VecDeque::new(),
            max_per_tenant,
        }
    }

    pub fn push(&mut self, tenant: &str, cost: usize, value: T) -> Result<(), Overloaded> {
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
                if !queue.items.is_empty() {
                    self.tenants.push_back(queue);
                }
                return Some(value);
            }
            self.tenants.push_back(queue);
        }
        None
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
