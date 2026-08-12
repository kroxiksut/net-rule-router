//! GUI/tray diagnostics facade.
//!
//! # Components
//!
//! | Module       | Responsibility                                             |
//! |--------------|------------------------------------------------------------|
//! | `dto`        | All serialisable DTOs (status, log entry, audit entry, alert) |
//! | `pagination` | `PageCursor`, `PageResult`, `PaginationParams`             |
//! | `service`    | `DiagnosticsFacade` trait                                  |
//! | `mock`       | `MockDiagnosticsFacade` for scaffold/testing               |
//!
//! # GUI contract
//!
//! GUI and tray receive a `Arc<dyn DiagnosticsFacade>` through the IPC
//! channel.  They must never access service-owned storage directly.

pub mod dto;
pub mod mock;
pub mod pagination;
pub mod service;

pub use dto::{
    audit_write_status_to_str, AcknowledgeAlertRequest, AuditEntryDto, AuditEntryFilter,
    CacheHealthCard, ClearLogsRequest, ClearLogsResult, DiagnosticModeStateDto,
    DiagnosticsStatusDto, LogEntryDto, LogEntryFilter, LogHealthCard, SecurityAlertDto,
    SecurityStatusCard, ServiceHealthCard, SetDiagnosticModeRequest,
};
pub use mock::{MockDiagnosticsFacade, MockScenario};
pub use pagination::{PageCursor, PageResult, PaginationParams, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE};
pub use service::DiagnosticsFacade;
