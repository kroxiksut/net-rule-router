//! Audit event kinds and result types.

use serde::{Deserialize, Serialize};

// ── AuditEventKind ────────────────────────────────────────────────────────────

/// The security-visible kind of an audit event.
///
/// Each variant maps to a stable lowercase `snake_case` string that is
/// persisted in NDJSON audit files.  Do not rename string values without
/// an alias mapping and migration note.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    /// A configuration artifact was imported; a review candidate was created.
    ImportCreated,
    /// A pending revision was reviewed and approved for activation.
    ReviewApproved,
    /// A pending revision was reviewed and rejected.
    ReviewRejected,
    /// A revision was activated as the current active policy.
    RevisionActivated,
    /// A rollback of the current active revision was initiated.
    RollbackStarted,
    /// A rollback completed successfully.
    RollbackCompleted,
    /// A tamper alert was raised (e.g., audit chain mismatch, unexpected delta).
    TamperAlertRaised,
    /// A user acknowledged a tamper alert.
    TamperAlertAcknowledged,
    /// An integrity verification failure was detected.
    IntegrityFailureDetected,
    /// A recovery action was requested by the operator or service.
    RecoveryActionRequested,
    /// A `revisions` row failed its `row_hmac`
    /// verification at service load (external DB tampering or a key
    /// rotation without re-signing). Routing keeps running; this is a
    /// notification, not a fail-closed.
    DbTamperDetected,
    /// The DB-MAC key file was missing at startup
    /// while the `revisions` table was non-empty. The service
    /// regenerated a key and blocks mutations until the user
    /// acknowledges, closing the "delete key → forged data becomes
    /// trusted" attack.
    KeyResetWithExistingData,
    /// A revision that was `active` (or about to become `active`) failed
    /// the row-signature or Free rule-cap check — a row written into the
    /// database outside the app. It was not applied; the service rolled
    /// back to the last trusted revision, or cleared to no active
    /// revision when none verified. Does not block further mutations —
    /// the service is already running on trusted content.
    UntrustedRevisionRejected,
}

impl AuditEventKind {
    /// Stable string representation persisted in NDJSON files.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ImportCreated => "import_created",
            Self::ReviewApproved => "review_approved",
            Self::ReviewRejected => "review_rejected",
            Self::RevisionActivated => "revision_activated",
            Self::RollbackStarted => "rollback_started",
            Self::RollbackCompleted => "rollback_completed",
            Self::TamperAlertRaised => "tamper_alert_raised",
            Self::TamperAlertAcknowledged => "tamper_alert_acknowledged",
            Self::IntegrityFailureDetected => "integrity_failure_detected",
            Self::RecoveryActionRequested => "recovery_action_requested",
            Self::DbTamperDetected => "db_tamper_detected",
            Self::KeyResetWithExistingData => "key_reset_with_existing_data",
            Self::UntrustedRevisionRejected => "untrusted_revision_rejected",
        }
    }

    /// Parses a kind from its stable string representation.
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "import_created" => Some(Self::ImportCreated),
            "review_approved" => Some(Self::ReviewApproved),
            "review_rejected" => Some(Self::ReviewRejected),
            "revision_activated" => Some(Self::RevisionActivated),
            "rollback_started" => Some(Self::RollbackStarted),
            "rollback_completed" => Some(Self::RollbackCompleted),
            "tamper_alert_raised" => Some(Self::TamperAlertRaised),
            "tamper_alert_acknowledged" => Some(Self::TamperAlertAcknowledged),
            "integrity_failure_detected" => Some(Self::IntegrityFailureDetected),
            "recovery_action_requested" => Some(Self::RecoveryActionRequested),
            "db_tamper_detected" => Some(Self::DbTamperDetected),
            "key_reset_with_existing_data" => Some(Self::KeyResetWithExistingData),
            "untrusted_revision_rejected" => Some(Self::UntrustedRevisionRejected),
            _ => None,
        }
    }

    /// Returns `true` if this kind always requires a security alert entry.
    #[must_use]
    pub fn requires_alert(self) -> bool {
        matches!(
            self,
            Self::TamperAlertRaised
                | Self::IntegrityFailureDetected
                | Self::DbTamperDetected
                | Self::KeyResetWithExistingData
                | Self::UntrustedRevisionRejected
        )
    }
}

impl std::fmt::Display for AuditEventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── AuditEventResult ──────────────────────────────────────────────────────────

/// Outcome of the audited action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventResult {
    /// The action completed successfully.
    Success,
    /// The action failed.
    Failure,
    /// The action was blocked (e.g., audit write failed → security-critical action blocked).
    Blocked,
}

impl AuditEventResult {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Blocked => "blocked",
        }
    }
}

// ── ActorKind ─────────────────────────────────────────────────────────────────

/// Who performed the audited action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    /// An interactive user via GUI or tray.
    User,
    /// The Windows background service acting autonomously.
    Service,
    /// An internal system-triggered action (e.g., recovery, watchdog).
    System,
}

impl ActorKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Service => "service",
            Self::System => "system",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_event_kind_round_trip_via_str() {
        for kind in [
            AuditEventKind::ImportCreated,
            AuditEventKind::ReviewApproved,
            AuditEventKind::ReviewRejected,
            AuditEventKind::RevisionActivated,
            AuditEventKind::RollbackStarted,
            AuditEventKind::RollbackCompleted,
            AuditEventKind::TamperAlertRaised,
            AuditEventKind::TamperAlertAcknowledged,
            AuditEventKind::IntegrityFailureDetected,
            AuditEventKind::RecoveryActionRequested,
            AuditEventKind::DbTamperDetected,
            AuditEventKind::KeyResetWithExistingData,
            AuditEventKind::UntrustedRevisionRejected,
        ] {
            let s = kind.as_str();
            let back = AuditEventKind::from_str(s).expect("round trip");
            assert_eq!(back, kind, "round trip failed for {s}");
        }
    }

    #[test]
    fn audit_event_kind_stable_strings() {
        assert_eq!(AuditEventKind::ImportCreated.as_str(), "import_created");
        assert_eq!(
            AuditEventKind::TamperAlertRaised.as_str(),
            "tamper_alert_raised"
        );
        assert_eq!(
            AuditEventKind::IntegrityFailureDetected.as_str(),
            "integrity_failure_detected"
        );
        assert_eq!(
            AuditEventKind::RecoveryActionRequested.as_str(),
            "recovery_action_requested"
        );
    }

    #[test]
    fn audit_event_kind_serde_round_trip() {
        let kind = AuditEventKind::RevisionActivated;
        let json = serde_json::to_string(&kind).expect("serialize");
        assert_eq!(json, r#""revision_activated""#);
        let back: AuditEventKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, kind);
    }

    #[test]
    fn requires_alert_for_tamper_and_integrity() {
        assert!(AuditEventKind::TamperAlertRaised.requires_alert());
        assert!(AuditEventKind::IntegrityFailureDetected.requires_alert());
        assert!(AuditEventKind::DbTamperDetected.requires_alert());
        assert!(AuditEventKind::KeyResetWithExistingData.requires_alert());
        assert!(AuditEventKind::UntrustedRevisionRejected.requires_alert());
        assert!(!AuditEventKind::ReviewApproved.requires_alert());
        assert!(!AuditEventKind::RevisionActivated.requires_alert());
    }

    #[test]
    fn audit_event_result_stable_strings() {
        assert_eq!(AuditEventResult::Success.as_str(), "success");
        assert_eq!(AuditEventResult::Failure.as_str(), "failure");
        assert_eq!(AuditEventResult::Blocked.as_str(), "blocked");
    }

    #[test]
    fn actor_kind_stable_strings() {
        assert_eq!(ActorKind::User.as_str(), "user");
        assert_eq!(ActorKind::Service.as_str(), "service");
        assert_eq!(ActorKind::System.as_str(), "system");
    }
}
