//! Alert domain types for security-visible policy change notifications.
//!
//! Alerts are raised when a candidate revision carries high or medium risk, or when
//! a non-interactive external change is detected. They persist until the user
//! acknowledges, reviews, or resolves them.
//!
//! # Lifecycle
//!
//! ```text
//! Created → Acknowledged → Reviewed → Resolved
//!                                   ↘ Superseded  (candidate was displaced)
//! ```
//!
//! [`AlertLifecycle::is_terminal`] returns `true` for `Resolved` and `Superseded`.
//! Terminal alerts may be archived or pruned by the store.
//!
//! # Storage
//!
//! Alert persistence (`alerts_cache.json`) is owned by the GUI and migrates
//! to service ownership. See `nrr-application::alert_store`.

use core::fmt;

use crate::revision::{RevisionId, RiskLevel, UnixTimestamp};

// ── AlertId ───────────────────────────────────────────────────────────────────

/// Stable identifier for an alert. Format: `"alert-{non-empty-suffix}"`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AlertId(String);

impl AlertId {
    const PREFIX: &'static str = "alert-";

    /// Constructs an `AlertId` from a prefixed string.
    ///
    /// Returns `Err` if the string does not start with `"alert-"` or the
    /// suffix is empty.
    pub fn from_prefixed_string(s: String) -> Result<Self, &'static str> {
        let suffix = s
            .strip_prefix(Self::PREFIX)
            .ok_or("alert id must start with \"alert-\"")?;
        if suffix.is_empty() {
            return Err("alert id suffix must not be empty");
        }
        Ok(Self(s))
    }

    /// Returns the full identifier string including prefix.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AlertId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── AlertSeverity ─────────────────────────────────────────────────────────────

/// Severity of an alert, derived from the associated revision's [`RiskLevel`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AlertSeverity {
    /// Medium-risk change requiring user attention before the next routing cycle.
    Warning,
    /// High-risk change. Mandatory review required; silent activation is blocked.
    Critical,
}

impl AlertSeverity {
    /// Maps a [`RiskLevel`] to an `AlertSeverity`.
    ///
    /// Returns `None` for `Low` risk — low-risk changes do not produce alerts.
    pub fn from_risk_level(level: RiskLevel) -> Option<Self> {
        match level {
            RiskLevel::Low => None,
            RiskLevel::Medium => Some(Self::Warning),
            // `High` and `Critical` both map to `AlertSeverity::Critical`: the
            // wire-level `ReviewRiskLevel` keeps the four-way distinction, but
            // the alert store collapses to two since the persistent-alert
            // lifecycle is the same for both.
            RiskLevel::High | RiskLevel::Critical => Some(Self::Critical),
        }
    }

    /// Returns a stable string slug for serialization and logging.
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

// ── AlertLifecycle ────────────────────────────────────────────────────────────

/// Lifecycle state of an alert.
///
/// Transitions: `Created → Acknowledged → Reviewed → Resolved | Superseded`.
/// Terminal states (`Resolved`, `Superseded`) have no valid forward transitions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AlertLifecycle {
    /// Alert was created; user has not yet been notified.
    Created,
    /// User was shown the alert notification and dismissed it.
    Acknowledged,
    /// User opened the review screen for the associated revision.
    Reviewed,
    /// Associated revision was explicitly confirmed or rejected by the user.
    Resolved,
    /// The candidate revision was displaced by a newer import before the user
    /// could resolve this alert. No further action is possible on this alert.
    Superseded,
}

impl AlertLifecycle {
    /// Returns `true` for terminal states (`Resolved`, `Superseded`).
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Resolved | Self::Superseded)
    }

    /// Returns `true` for states where the alert still requires user action.
    pub fn is_active(self) -> bool {
        !self.is_terminal()
    }

    /// Returns a stable string slug for serialization and logging.
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Acknowledged => "acknowledged",
            Self::Reviewed => "reviewed",
            Self::Resolved => "resolved",
            Self::Superseded => "superseded",
        }
    }

    /// Parses a slug produced by [`Self::slug`].
    pub fn from_slug(s: &str) -> Option<Self> {
        match s {
            "created" => Some(Self::Created),
            "acknowledged" => Some(Self::Acknowledged),
            "reviewed" => Some(Self::Reviewed),
            "resolved" => Some(Self::Resolved),
            "superseded" => Some(Self::Superseded),
            _ => None,
        }
    }
}

impl fmt::Display for AlertLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

// ── Alert ─────────────────────────────────────────────────────────────────────

/// A persistent security-visible notification tied to a candidate revision.
///
/// Alerts are raised by the risk scoring pipeline when a candidate's
/// [`RiskAssessment`](crate::risk::RiskAssessment) reaches `Medium` or `High`.
/// They remain visible until the user resolves or supersedes them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alert {
    /// Stable identifier for this alert.
    pub id: AlertId,
    /// Severity derived from the candidate revision's risk level.
    pub severity: AlertSeverity,
    /// Current lifecycle state.
    pub lifecycle: AlertLifecycle,
    /// ID of the candidate revision that triggered this alert, if applicable.
    pub source_revision_id: Option<RevisionId>,
    /// UTC timestamp when this alert was created.
    pub created_at: UnixTimestamp,
    /// UTC timestamp when the user acknowledged this alert (`None` until then).
    pub acknowledged_at: Option<UnixTimestamp>,
    /// Human-readable description of why this alert was raised.
    pub description: String,
}

impl Alert {
    /// Creates a new alert in the [`AlertLifecycle::Created`] state.
    pub fn new(
        id: AlertId,
        severity: AlertSeverity,
        source_revision_id: Option<RevisionId>,
        created_at: UnixTimestamp,
        description: String,
    ) -> Self {
        Self {
            id,
            severity,
            lifecycle: AlertLifecycle::Created,
            source_revision_id,
            created_at,
            acknowledged_at: None,
            description,
        }
    }

    /// Returns `true` when this alert still requires user action.
    pub fn is_active(&self) -> bool {
        self.lifecycle.is_active()
    }

    /// Returns `true` when this alert is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        self.lifecycle.is_terminal()
    }

    /// Advances the lifecycle to `Acknowledged` and records the timestamp.
    ///
    /// Has no effect if the alert is already terminal.
    pub fn acknowledge(&mut self, at: UnixTimestamp) {
        if self.lifecycle == AlertLifecycle::Created {
            self.lifecycle = AlertLifecycle::Acknowledged;
            self.acknowledged_at = Some(at);
        }
    }

    /// Advances the lifecycle to `Reviewed`.
    ///
    /// Valid only from `Created` or `Acknowledged`. Returns `false` if the
    /// current state does not permit this transition.
    pub fn mark_reviewed(&mut self) -> bool {
        match self.lifecycle {
            AlertLifecycle::Created | AlertLifecycle::Acknowledged => {
                self.lifecycle = AlertLifecycle::Reviewed;
                true
            }
            _ => false,
        }
    }

    /// Marks the alert as `Resolved` (revision was confirmed or rejected).
    ///
    /// Has no effect on already-terminal alerts. Returns `false` in that case.
    pub fn resolve(&mut self) -> bool {
        if self.lifecycle.is_terminal() {
            return false;
        }
        self.lifecycle = AlertLifecycle::Resolved;
        true
    }

    /// Marks the alert as `Superseded` (the associated candidate was displaced).
    ///
    /// Has no effect on already-terminal alerts. Returns `false` in that case.
    pub fn supersede(&mut self) -> bool {
        if self.lifecycle.is_terminal() {
            return false;
        }
        self.lifecycle = AlertLifecycle::Superseded;
        true
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::revision::{RevisionId, UnixTimestamp};

    fn alert_id(s: &str) -> AlertId {
        AlertId::from_prefixed_string(s.to_string()).expect("valid id")
    }

    fn rev_id(s: &str) -> RevisionId {
        RevisionId::from_prefixed_string(s.to_string()).expect("valid id")
    }

    fn ts(secs: u64) -> UnixTimestamp {
        UnixTimestamp::from_secs(secs)
    }

    fn make_alert(severity: AlertSeverity) -> Alert {
        Alert::new(
            alert_id("alert-test-001"),
            severity,
            Some(rev_id("rev-candidate-001")),
            ts(1_700_000_000),
            "Test alert".to_string(),
        )
    }

    // ── AlertId ───────────────────────────────────────────────────────────────

    #[test]
    fn alert_id_accepts_valid_prefixed_string() {
        let id = AlertId::from_prefixed_string("alert-abc123".to_string());
        assert!(id.is_ok());
        assert_eq!(id.expect("ok").as_str(), "alert-abc123");
    }

    #[test]
    fn alert_id_rejects_missing_prefix() {
        assert!(AlertId::from_prefixed_string("abc123".to_string()).is_err());
    }

    #[test]
    fn alert_id_rejects_prefix_only() {
        assert!(AlertId::from_prefixed_string("alert-".to_string()).is_err());
    }

    // ── AlertSeverity ─────────────────────────────────────────────────────────

    #[test]
    fn severity_from_risk_level_low_is_none() {
        assert!(AlertSeverity::from_risk_level(RiskLevel::Low).is_none());
    }

    #[test]
    fn severity_from_risk_level_medium_is_warning() {
        assert_eq!(
            AlertSeverity::from_risk_level(RiskLevel::Medium),
            Some(AlertSeverity::Warning)
        );
    }

    #[test]
    fn severity_from_risk_level_high_is_critical() {
        assert_eq!(
            AlertSeverity::from_risk_level(RiskLevel::High),
            Some(AlertSeverity::Critical)
        );
    }

    #[test]
    fn severity_slugs_are_stable() {
        assert_eq!(AlertSeverity::Warning.slug(), "warning");
        assert_eq!(AlertSeverity::Critical.slug(), "critical");
    }

    // ── AlertLifecycle ────────────────────────────────────────────────────────

    #[test]
    fn lifecycle_terminal_states() {
        assert!(AlertLifecycle::Resolved.is_terminal());
        assert!(AlertLifecycle::Superseded.is_terminal());
        assert!(!AlertLifecycle::Created.is_terminal());
        assert!(!AlertLifecycle::Acknowledged.is_terminal());
        assert!(!AlertLifecycle::Reviewed.is_terminal());
    }

    #[test]
    fn lifecycle_slug_roundtrip() {
        for lc in [
            AlertLifecycle::Created,
            AlertLifecycle::Acknowledged,
            AlertLifecycle::Reviewed,
            AlertLifecycle::Resolved,
            AlertLifecycle::Superseded,
        ] {
            assert_eq!(AlertLifecycle::from_slug(lc.slug()), Some(lc));
        }
    }

    // ── Alert transitions ─────────────────────────────────────────────────────

    #[test]
    fn new_alert_starts_in_created_state() {
        let alert = make_alert(AlertSeverity::Warning);
        assert_eq!(alert.lifecycle, AlertLifecycle::Created);
        assert!(alert.is_active());
        assert!(alert.acknowledged_at.is_none());
    }

    #[test]
    fn acknowledge_transitions_from_created() {
        let mut alert = make_alert(AlertSeverity::Warning);
        alert.acknowledge(ts(1_700_000_100));
        assert_eq!(alert.lifecycle, AlertLifecycle::Acknowledged);
        assert_eq!(alert.acknowledged_at, Some(ts(1_700_000_100)));
    }

    #[test]
    fn acknowledge_no_effect_if_already_terminal() {
        let mut alert = make_alert(AlertSeverity::Warning);
        assert!(alert.resolve());
        alert.acknowledge(ts(1_700_000_100)); // should not change state
        assert_eq!(alert.lifecycle, AlertLifecycle::Resolved);
    }

    #[test]
    fn mark_reviewed_from_acknowledged() {
        let mut alert = make_alert(AlertSeverity::Critical);
        alert.acknowledge(ts(1_700_000_100));
        assert!(alert.mark_reviewed());
        assert_eq!(alert.lifecycle, AlertLifecycle::Reviewed);
    }

    #[test]
    fn mark_reviewed_from_created_is_allowed() {
        let mut alert = make_alert(AlertSeverity::Critical);
        assert!(alert.mark_reviewed()); // skip acknowledge step
        assert_eq!(alert.lifecycle, AlertLifecycle::Reviewed);
    }

    #[test]
    fn mark_reviewed_from_terminal_returns_false() {
        let mut alert = make_alert(AlertSeverity::Warning);
        assert!(alert.resolve());
        assert!(!alert.mark_reviewed());
        assert_eq!(alert.lifecycle, AlertLifecycle::Resolved); // unchanged
    }

    #[test]
    fn resolve_transitions_to_terminal() {
        let mut alert = make_alert(AlertSeverity::Warning);
        assert!(alert.resolve());
        assert!(alert.is_terminal());
        assert!(!alert.is_active());
    }

    #[test]
    fn resolve_returns_false_if_already_terminal() {
        let mut alert = make_alert(AlertSeverity::Warning);
        assert!(alert.resolve());
        assert!(!alert.resolve()); // already terminal
    }

    #[test]
    fn supersede_transitions_to_terminal() {
        let mut alert = make_alert(AlertSeverity::Critical);
        assert!(alert.supersede());
        assert_eq!(alert.lifecycle, AlertLifecycle::Superseded);
        assert!(alert.is_terminal());
    }

    #[test]
    fn supersede_returns_false_if_already_terminal() {
        let mut alert = make_alert(AlertSeverity::Critical);
        assert!(alert.resolve()); // first to Resolved
        assert!(!alert.supersede()); // cannot transition from Resolved
    }

    #[test]
    fn severity_ordering_warning_lt_critical() {
        assert!(AlertSeverity::Warning < AlertSeverity::Critical);
    }
}
