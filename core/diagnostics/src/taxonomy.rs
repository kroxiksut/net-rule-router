//! Shared event taxonomy.
//!
//! Defines the foundational discriminants that every diagnostic and audit event
//! carries: level, category, privacy class, and correlation identifiers.
//!
//! # Serialization contract
//!
//! All enums are serialized as lowercase `snake_case` strings in NDJSON output.
//! These string forms are **stable**: do not rename variants without an alias
//! mapping and a migration note.
//!
//! # Timestamp format
//!
//! All timestamps are UTC Unix milliseconds (`i64`), matching the convention
//! established in the storage layer.

use serde::{Deserialize, Serialize};

// ── EventLevel ────────────────────────────────────────────────────────────────

/// Severity level for operational log events.
///
/// Default runtime logging emits only `Info` and above.  `Trace` and `Debug`
/// are enabled only in explicit diagnostic mode or dev/test profiles.
///
/// Ordered from least to most severe: `Trace < Debug < Info < Warn < Error`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl EventLevel {
    /// The minimum level emitted in normal (non-diagnostic) runtime.
    pub const DEFAULT_MINIMUM: Self = Self::Info;

    /// Stable string representation used in NDJSON output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }

    /// Returns `true` if this level would be emitted in normal runtime mode.
    #[must_use]
    pub fn is_default_visible(self) -> bool {
        self >= Self::DEFAULT_MINIMUM
    }
}

// ── EventCategory ─────────────────────────────────────────────────────────────

/// Logical stream a diagnostic event belongs to.
///
/// Used to route events to the correct log section and to apply
/// category-specific filters and rate limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    /// Windows Service lifecycle (start, stop, degraded, health changes).
    Service,
    /// Rule engine routing decisions.
    Decision,
    /// FQDN/IP cache lookups and freshness events.
    Cache,
    /// Network route apply/verification/rollback operations.
    Apply,
    /// Configuration import operations.
    Import,
    /// Review and approval flow events.
    Review,
    /// Storage/revision integrity checks and recovery.
    Integrity,
    /// Security-significant actions written to the audit trail.
    Security,
    /// Diagnostics subsystem internal events (mode changes, export, cleanup).
    Diagnostics,
    /// Explicit user actions routed through GUI/tray.
    UserAction,
}

impl EventCategory {
    /// Stable string representation used in NDJSON output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Decision => "decision",
            Self::Cache => "cache",
            Self::Apply => "apply",
            Self::Import => "import",
            Self::Review => "review",
            Self::Integrity => "integrity",
            Self::Security => "security",
            Self::Diagnostics => "diagnostics",
            Self::UserAction => "user_action",
        }
    }
}

// ── PrivacyClass ──────────────────────────────────────────────────────────────

/// Privacy classification of an event's payload fields.
///
/// Ordered from least to most sensitive: `PublicSummary < Diagnostic < Sensitive
/// < SecretNeverLog`.  The redaction layer uses this ordering to decide what to
/// include in output for a given [`DiagnosticRedactionLevel`].
///
/// # `SecretNeverLog` enforcement
///
/// Payloads tagged `SecretNeverLog` must never be serialised into any log,
/// audit, or export output under any circumstance.  This is enforced
/// architecturally by the privacy/redaction layer.
///
/// [`DiagnosticRedactionLevel`]: crate::redaction::DiagnosticRedactionLevel
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyClass {
    /// Safe for the normal explain panel: categorical summaries only.
    PublicSummary,
    /// Requires explicit diagnostic mode: adds selected IPs, ambiguity flags.
    Diagnostic,
    /// Requires explicit diagnostic mode and user acknowledgement: process
    /// paths, adapter identifiers, resolver details.
    Sensitive,
    /// Must never appear in any log, audit, or export output.
    SecretNeverLog,
}

impl PrivacyClass {
    /// Stable string representation used in NDJSON output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicSummary => "public_summary",
            Self::Diagnostic => "diagnostic",
            Self::Sensitive => "sensitive",
            Self::SecretNeverLog => "secret_never_log",
        }
    }

    /// Returns `true` if this payload may be included in default (non-diagnostic)
    /// log output without redaction.
    #[must_use]
    pub fn is_default_safe(self) -> bool {
        self == Self::PublicSummary
    }
}

// ── EventCorrelation ──────────────────────────────────────────────────────────

/// Correlation identifiers that link a diagnostic event to related entities.
///
/// All fields are optional because not every event has all correlations.
/// Missing fields serialize as `null` and are omitted from JSON output.
///
/// # Stable string prefixes
///
/// | Field             | ID prefix   | Source crate  |
/// |-------------------|-------------|---------------|
/// | `decision_id`     | `d-`        | `nrr-domain`  |
/// | `revision_id`     | `rev-`      | `nrr-domain`  |
/// | `event_id`        | `evt-`      | `nrr-diagnostics` |
/// | Other fields      | none        | caller-assigned |
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventCorrelation {
    /// The routing decision this event relates to (`d-{uuid}`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<String>,

    /// A caller-assigned request or session identifier for tracing a flow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,

    /// The active policy revision at the time of the event (`rev-{uuid}`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision_id: Option<String>,

    /// The FQDN/IP cache lookup entry identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lookup_id: Option<String>,

    /// An apply-layer attempt identifier for tracing route apply chains.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apply_attempt_id: Option<String>,

    /// The import operation identifier that triggered this event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub import_id: Option<String>,
}

impl EventCorrelation {
    /// Returns `true` if no correlation identifiers are set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.decision_id.is_none()
            && self.request_id.is_none()
            && self.revision_id.is_none()
            && self.lookup_id.is_none()
            && self.apply_attempt_id.is_none()
            && self.import_id.is_none()
    }

    /// Sets the decision id and returns `self` for builder-style construction.
    #[must_use]
    pub fn with_decision(mut self, id: impl Into<String>) -> Self {
        self.decision_id = Some(id.into());
        self
    }

    /// Sets the revision id and returns `self`.
    #[must_use]
    pub fn with_revision(mut self, id: impl Into<String>) -> Self {
        self.revision_id = Some(id.into());
        self
    }

    /// Sets the apply_attempt_id and returns `self`.
    #[must_use]
    pub fn with_apply(mut self, id: impl Into<String>) -> Self {
        self.apply_attempt_id = Some(id.into());
        self
    }

    /// Sets the import_id and returns `self`.
    #[must_use]
    pub fn with_import(mut self, id: impl Into<String>) -> Self {
        self.import_id = Some(id.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── EventLevel ────────────────────────────────────────────────────────────

    #[test]
    fn event_level_ordering() {
        assert!(EventLevel::Trace < EventLevel::Debug);
        assert!(EventLevel::Debug < EventLevel::Info);
        assert!(EventLevel::Info < EventLevel::Warn);
        assert!(EventLevel::Warn < EventLevel::Error);
    }

    #[test]
    fn event_level_stable_strings() {
        assert_eq!(EventLevel::Trace.as_str(), "trace");
        assert_eq!(EventLevel::Debug.as_str(), "debug");
        assert_eq!(EventLevel::Info.as_str(), "info");
        assert_eq!(EventLevel::Warn.as_str(), "warn");
        assert_eq!(EventLevel::Error.as_str(), "error");
    }

    #[test]
    fn event_level_serde_round_trip() {
        for level in [
            EventLevel::Trace,
            EventLevel::Debug,
            EventLevel::Info,
            EventLevel::Warn,
            EventLevel::Error,
        ] {
            let json = serde_json::to_string(&level).expect("serialize");
            let back: EventLevel = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, level);
        }
    }

    #[test]
    fn event_level_default_minimum_is_info() {
        assert_eq!(EventLevel::DEFAULT_MINIMUM, EventLevel::Info);
    }

    #[test]
    fn event_level_default_visibility() {
        assert!(!EventLevel::Trace.is_default_visible());
        assert!(!EventLevel::Debug.is_default_visible());
        assert!(EventLevel::Info.is_default_visible());
        assert!(EventLevel::Warn.is_default_visible());
        assert!(EventLevel::Error.is_default_visible());
    }

    // ── EventCategory ─────────────────────────────────────────────────────────

    #[test]
    fn event_category_stable_strings() {
        assert_eq!(EventCategory::Service.as_str(), "service");
        assert_eq!(EventCategory::Decision.as_str(), "decision");
        assert_eq!(EventCategory::Cache.as_str(), "cache");
        assert_eq!(EventCategory::Apply.as_str(), "apply");
        assert_eq!(EventCategory::Import.as_str(), "import");
        assert_eq!(EventCategory::Review.as_str(), "review");
        assert_eq!(EventCategory::Integrity.as_str(), "integrity");
        assert_eq!(EventCategory::Security.as_str(), "security");
        assert_eq!(EventCategory::Diagnostics.as_str(), "diagnostics");
        assert_eq!(EventCategory::UserAction.as_str(), "user_action");
    }

    #[test]
    fn event_category_serde_round_trip() {
        for cat in [
            EventCategory::Service,
            EventCategory::Decision,
            EventCategory::Cache,
            EventCategory::Apply,
            EventCategory::Import,
            EventCategory::Review,
            EventCategory::Integrity,
            EventCategory::Security,
            EventCategory::Diagnostics,
            EventCategory::UserAction,
        ] {
            let json = serde_json::to_string(&cat).expect("serialize");
            let back: EventCategory = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, cat);
        }
    }

    // ── PrivacyClass ──────────────────────────────────────────────────────────

    #[test]
    fn privacy_class_ordering() {
        assert!(PrivacyClass::PublicSummary < PrivacyClass::Diagnostic);
        assert!(PrivacyClass::Diagnostic < PrivacyClass::Sensitive);
        assert!(PrivacyClass::Sensitive < PrivacyClass::SecretNeverLog);
    }

    #[test]
    fn privacy_class_stable_strings() {
        assert_eq!(PrivacyClass::PublicSummary.as_str(), "public_summary");
        assert_eq!(PrivacyClass::Diagnostic.as_str(), "diagnostic");
        assert_eq!(PrivacyClass::Sensitive.as_str(), "sensitive");
        assert_eq!(PrivacyClass::SecretNeverLog.as_str(), "secret_never_log");
    }

    #[test]
    fn privacy_class_default_safe() {
        assert!(PrivacyClass::PublicSummary.is_default_safe());
        assert!(!PrivacyClass::Diagnostic.is_default_safe());
        assert!(!PrivacyClass::Sensitive.is_default_safe());
        assert!(!PrivacyClass::SecretNeverLog.is_default_safe());
    }

    #[test]
    fn privacy_class_serde_round_trip() {
        for cls in [
            PrivacyClass::PublicSummary,
            PrivacyClass::Diagnostic,
            PrivacyClass::Sensitive,
            PrivacyClass::SecretNeverLog,
        ] {
            let json = serde_json::to_string(&cls).expect("serialize");
            let back: PrivacyClass = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, cls);
        }
    }

    // ── EventCorrelation ──────────────────────────────────────────────────────

    #[test]
    fn event_correlation_default_is_empty() {
        assert!(EventCorrelation::default().is_empty());
    }

    #[test]
    fn event_correlation_builder() {
        let corr = EventCorrelation::default()
            .with_decision("d-abc")
            .with_revision("rev-xyz");
        assert_eq!(corr.decision_id.as_deref(), Some("d-abc"));
        assert_eq!(corr.revision_id.as_deref(), Some("rev-xyz"));
        assert!(corr.apply_attempt_id.is_none());
        assert!(!corr.is_empty());
    }

    #[test]
    fn event_correlation_omits_none_fields_in_json() {
        let corr = EventCorrelation::default().with_decision("d-1");
        let json = serde_json::to_string(&corr).expect("serialize");
        assert!(json.contains("decision_id"));
        assert!(!json.contains("revision_id"));
        assert!(!json.contains("apply_attempt_id"));
    }

    #[test]
    fn event_correlation_full_round_trip() {
        let corr = EventCorrelation {
            decision_id: Some("d-001".into()),
            request_id: Some("req-1".into()),
            revision_id: Some("rev-001".into()),
            lookup_id: Some("lkp-1".into()),
            apply_attempt_id: Some("apl-1".into()),
            import_id: Some("imp-1".into()),
        };
        let json = serde_json::to_string(&corr).expect("serialize");
        let back: EventCorrelation = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, corr);
    }
}
