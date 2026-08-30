//! GaugeMesh invariant and deterministic routing core.

pub mod budget;
pub mod capability;
pub mod causal;
pub mod config;
pub mod context;
pub mod digest;
pub mod invariant;
pub mod lease;
pub mod policy;
pub mod route;
pub mod runtime;
pub mod storage;
pub mod translation;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
