//! GaugeMesh invariant and deterministic routing core.

pub mod budget;
pub mod capability;
pub mod causal;
pub mod config;
pub mod context;
pub mod digest;
pub mod federation;
pub mod invariant;
pub mod lease;
pub mod model;
pub mod policy;
pub mod process_pool;
pub mod protocol;
pub mod route;
pub mod runtime;
pub mod security;
pub mod storage;
pub mod translation;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
