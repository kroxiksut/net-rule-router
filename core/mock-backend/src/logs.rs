//! Log- and audit-page DTOs, so the desktop shell can name them without
//! depending on `nrr-diagnostics` directly.

pub use nrr_diagnostics::facade::{
    AuditEntryDto, AuditEntryFilter, LogEntryDto, LogEntryFilter, PageResult, PaginationParams,
};
