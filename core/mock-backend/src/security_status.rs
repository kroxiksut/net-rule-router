#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityLevel {
    Ok,
    Warning,
    Alert,
}

impl SecurityLevel {
    pub const fn title(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warning => "warning",
            Self::Alert => "alert",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecurityStatusSnapshot {
    pub active_revision: &'static str,
    pub pending_changes: SecurityLevel,
    pub tamper_alerts: SecurityLevel,
    pub rollback_state: SecurityLevel,
    pub service_status: SecurityLevel,
    pub explain_warnings: SecurityLevel,
}

pub const fn security_status_preview_snapshot() -> SecurityStatusSnapshot {
    SecurityStatusSnapshot {
        active_revision: "rev-preview-001",
        pending_changes: SecurityLevel::Warning,
        tamper_alerts: SecurityLevel::Ok,
        rollback_state: SecurityLevel::Ok,
        service_status: SecurityLevel::Alert,
        explain_warnings: SecurityLevel::Warning,
    }
}

#[cfg(test)]
mod tests {
    use super::{security_status_preview_snapshot, SecurityLevel};

    #[test]
    fn security_status_contains_all_required_indicators() {
        let snapshot = security_status_preview_snapshot();
        assert_eq!(snapshot.active_revision, "rev-preview-001");
        assert_eq!(snapshot.pending_changes, SecurityLevel::Warning);
        assert_eq!(snapshot.tamper_alerts, SecurityLevel::Ok);
        assert_eq!(snapshot.rollback_state, SecurityLevel::Ok);
        assert_eq!(snapshot.service_status, SecurityLevel::Alert);
        assert_eq!(snapshot.explain_warnings, SecurityLevel::Warning);
    }
}
