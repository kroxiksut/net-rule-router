//! GUI/tray facade DTOs — re-export shim.
//!
//! All DTO definitions live in [`nrr_shared::diagnostics_dto`]; this
//! module re-exports them so consumers that previously imported from
//! `nrr_diagnostics::facade::dto::*` keep working untouched. The
//! converter [`audit_write_status_to_str`] stays here because it
//! references the engine-internal `AuditWriteStatus` from the
//! retention module (which is not part of the wire-DTO surface).

pub use nrr_shared::diagnostics_dto::*;

use crate::retention::health::AuditWriteStatus;

/// Converts `AuditWriteStatus` to a stable string for the DTO.
pub fn audit_write_status_to_str(status: AuditWriteStatus) -> &'static str {
    match status {
        AuditWriteStatus::Healthy => "healthy",
        AuditWriteStatus::Degraded { .. } => "degraded",
        AuditWriteStatus::Unavailable => "unavailable",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_write_status_to_str_stable() {
        assert_eq!(
            audit_write_status_to_str(AuditWriteStatus::Healthy),
            "healthy"
        );
        assert_eq!(
            audit_write_status_to_str(AuditWriteStatus::Unavailable),
            "unavailable"
        );
        assert_eq!(
            audit_write_status_to_str(AuditWriteStatus::Degraded { last_error_ms: 0 }),
            "degraded"
        );
    }
}
