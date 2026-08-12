//! Security audit trail.
//!
//! This module implements:
//! - [`kind`]: `AuditEventKind`, `AuditEventResult`, `ActorKind`
//! - [`alert`]: `SecurityAlertState`, `SecurityAlert`, `SecurityAlertsRepository`
//! - [`writer`]: `AuditWriter` — append-only NDJSON writer with rolling hash chain
//! - [`reader`]: `AuditReader` — file scanner and chain verifier

pub mod alert;
pub mod kind;
pub mod reader;
pub mod writer;

pub use alert::{
    InMemorySecurityAlertsRepository, SecurityAlert, SecurityAlertState, SecurityAlertsRepository,
};
pub use kind::{ActorKind, AuditEventKind, AuditEventResult};
pub use reader::{AuditChainVerification, AuditQueryFilter, AuditReader};
pub use writer::{
    compute_chain_hash, local_date_string, utc_date_string, AuditEventInput, AuditWriter,
    AuditWriterConfig, AUDIT_CHAIN_GENESIS, DEFAULT_MAX_FILE_SIZE_BYTES,
};
