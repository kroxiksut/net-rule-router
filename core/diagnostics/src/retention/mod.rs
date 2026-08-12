//! Storage retention, cleanup, and health.
//!
//! # Three components
//!
//! | Module      | Responsibility                                             |
//! |-------------|------------------------------------------------------------|
//! | `policy`    | `LogRetentionPolicy`, `AuditRetentionPolicy`, `ManualCleanupScope` |
//! | `cleanup`   | `CleanupJob` — age/size/count-based file deletion          |
//! | `health`    | `StorageHealthSnapshot` — live health status for GUI/tray  |
//!
//! # Audit trail protection
//!
//! `CleanupJob::run_logs` only touches files with the `nrr_service_` prefix.
//! `CleanupJob::run_audit` is service-internal and not user-triggerable.
//! `security_alerts` rows in `nrr_service_state.db` are never touched by
//! any file-based cleanup.

pub mod cleanup;
pub mod health;
pub mod policy;

pub use cleanup::{CleanupJob, CleanupResult};
pub use health::{AuditWriteStatus, StorageHealthCollector, StorageHealthSnapshot};
pub use policy::{
    AuditRetentionPolicy, LogRetentionPolicy, ManualCleanupScope, DEFAULT_AUDIT_MAX_AGE_DAYS,
    DEFAULT_AUDIT_MAX_SIZE_BYTES, DEFAULT_DIAGNOSTIC_MODE_MAX_HOURS, DEFAULT_LOG_MAX_AGE_DAYS,
    DEFAULT_LOG_MAX_FILES, DEFAULT_LOG_MAX_SIZE_BYTES,
};
