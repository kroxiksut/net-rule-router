//! Diagnostic and audit event envelopes.
//!
//! # Event types
//!
//! | Type           | Stream              | Storage                        |
//! |----------------|---------------------|--------------------------------|
//! | [`LogEvent`]   | Operational logs    | `nrr_service_YYYYMMDD-N.ndjson`|
//! | [`AuditEvent`] | Security audit trail| `nrr_audit_YYYYMMDD-N.ndjson`  |
//!
//! `DiagnosticEvent` is represented as a `LogEvent` with
//! `category = EventCategory::Diagnostics` — no separate type is needed.
//!
//! `SecurityAlert` state is stored in the `security_alerts` table in
//! `nrr_service_state.db`.
//!
//! # Schema versioning
//!
//! Both event types carry a `schema_version` field.  The current version for
//! both is `1`.  If the shape changes incompatibly, the version is incremented
//! and a migration/decoder is provided before the old shape is retired.
//!
//! # Timestamp format
//!
//! Stored timestamps are UTC Unix milliseconds (`i64`); the `created_at_iso`
//! rendering beside them is local wall-clock time with its offset.
//!
//! # Event id format
//!
//! Operational log events: `"evt-{uuid_v4}"`.
//! Audit events: `"adt-{uuid_v4}"`.
//! IDs are assigned by the caller (the service layer); this crate
//! defines the type only, following the same pattern as `DecisionId`.

use serde::{Deserialize, Serialize};

use crate::reason::ReasonCode;
use crate::taxonomy::{EventCategory, EventCorrelation, EventLevel, PrivacyClass};

/// Current NDJSON schema version for [`LogEvent`].
pub const LOG_EVENT_SCHEMA_VERSION: u16 = 1;

/// Current NDJSON schema version for [`AuditEvent`].
pub const AUDIT_EVENT_SCHEMA_VERSION: u16 = 1;

// ── LogEvent ──────────────────────────────────────────────────────────────────

/// A single operational log event serialised as one NDJSON line.
///
/// The `payload` field carries event-specific detail filtered through the
/// privacy redaction layer before serialisation.  Callers must
/// not include `SecretNeverLog` data in `payload`.
///
/// # Default mode
///
/// In normal (non-diagnostic) runtime, only events with
/// `level >= EventLevel::DEFAULT_MINIMUM` and `privacy_class ==
/// PrivacyClass::PublicSummary` are written.  Higher-privacy events are
/// emitted only when explicit diagnostic mode is active.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogEvent {
    /// NDJSON schema version.  Always [`LOG_EVENT_SCHEMA_VERSION`].
    pub schema_version: u16,

    /// Unique event identifier (`evt-{uuid_v4}`).
    pub event_id: String,

    /// UTC Unix milliseconds.
    pub created_at: i64,

    /// Human-readable LOCAL timestamp derived from [`Self::created_at`]
    /// (`YYYY-MM-DDTHH:MM:SS.mmm+HH:MM`), so a line reads as the clock on the
    /// wall when it was written. `#[serde(default)]` keeps log files written
    /// before this field existed deserializable at query time.
    #[serde(default)]
    pub created_at_iso: String,

    /// Severity level.
    pub level: EventLevel,

    /// Logical event stream.
    pub category: EventCategory,

    /// Stable snake_case event kind (the reason code string).
    ///
    /// `String` rather than `&'static str` so the struct can be deserialized
    /// from NDJSON files at query time.  At write time, use `ReasonCode::as_str()`.
    pub kind: String,

    /// Cross-entity correlation identifiers.
    #[serde(default, skip_serializing_if = "EventCorrelation::is_empty")]
    pub correlation: EventCorrelation,

    /// Privacy classification of the payload.
    pub privacy_class: PrivacyClass,

    /// Localization key for GUI display — must not be user-visible text.
    pub message_key: String,

    /// Structured event payload after redaction.
    ///
    /// `None` means no additional detail is available.  Must not contain
    /// `SecretNeverLog` fields; the redaction layer enforces this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

/// Formats UTC Unix milliseconds in LOCAL time as RFC-3339
/// (`YYYY-MM-DDTHH:MM:SS.mmm+HH:MM`) — what the reader's clock showed.
/// `created_at` next to it stays the UTC millisecond value machines parse.
#[must_use]
pub(crate) fn rfc3339_local_millis(ms: i64) -> String {
    let offset = crate::local_offset::seconds();
    let mut out = iso8601_utc_millis(ms + i64::from(offset) * 1000);
    out.pop(); // the UTC 'Z' the shifted value no longer is
    out.push_str(&crate::local_offset::rfc3339_suffix(offset));
    out
}

/// Formats UTC Unix milliseconds as an ISO-8601 / RFC-3339 timestamp
/// (`YYYY-MM-DDTHH:MM:SS.mmmZ`). Pure integer arithmetic (Howard Hinnant's
/// `civil_from_days`) — total, no panics.
#[must_use]
pub(crate) fn iso8601_utc_millis(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let hour = tod / 3600;
    let minute = (tod % 3600) / 60;
    let second = tod % 60;
    // civil_from_days: days since 1970-01-01 → (year, month, day).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year_civil = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 {
        year_civil + 1
    } else {
        year_civil
    };
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

impl LogEvent {
    /// Constructs a minimal `LogEvent` with no correlation and no payload.
    #[must_use]
    pub fn new(
        event_id: impl Into<String>,
        created_at: i64,
        level: EventLevel,
        reason: ReasonCode,
    ) -> Self {
        Self {
            schema_version: LOG_EVENT_SCHEMA_VERSION,
            event_id: event_id.into(),
            created_at,
            created_at_iso: rfc3339_local_millis(created_at),
            level,
            category: crate::reason::reason_code_meta(reason)
                .map(|m| m.category)
                .unwrap_or(EventCategory::Service),
            kind: reason.as_str().to_string(),
            correlation: EventCorrelation::default(),
            privacy_class: PrivacyClass::PublicSummary,
            message_key: crate::reason::reason_code_meta(reason)
                .map(|m| m.ui_key)
                .unwrap_or("diag.unknown.summary")
                .to_string(),
            payload: None,
        }
    }

    /// Attaches correlation ids.
    #[must_use]
    pub fn with_correlation(mut self, correlation: EventCorrelation) -> Self {
        self.correlation = correlation;
        self
    }

    /// Attaches a redacted payload.
    #[must_use]
    pub fn with_payload(mut self, payload: serde_json::Value) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Raises the privacy class (never lowers it).
    #[must_use]
    pub fn with_privacy(mut self, class: PrivacyClass) -> Self {
        if class > self.privacy_class {
            self.privacy_class = class;
        }
        self
    }

    /// Serialises this event to a NDJSON line (no trailing newline).
    ///
    /// Returns an error if serde_json serialisation fails.
    pub fn to_ndjson(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

// ── AuditEvent ────────────────────────────────────────────────────────────────

/// A single security audit event serialised as one NDJSON line.
///
/// Audit events are written to the append-only audit NDJSON trail.
/// Each event carries a monotonic sequence number within its file and
/// a rolling hash chain for tamper detection.
///
/// # Tamper detection
///
/// `event_hash = FNV-1a(prev_hash + canonical_payload_json)`
///
/// On startup the audit reader verifies the chain for the most recent file.
/// A mismatch raises `integrity.audit_chain_mismatch` and sets the service
/// health to degraded.
///
/// # Actor identity
///
/// `actor_id_hash` is a one-way hash of the actor identifier (e.g. username
/// or service account) — never the raw identifier.  This provides
/// accountability without exposing PII in the audit trail.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    /// NDJSON schema version.  Always [`AUDIT_EVENT_SCHEMA_VERSION`].
    pub schema_version: u16,

    /// Monotonic sequence number within the current audit file.
    /// Resets to `1` on file rotation; the file index preserves global order.
    pub seq: u64,

    /// Unique audit event identifier (`adt-{uuid_v4}`).
    pub event_id: String,

    /// Stable audit event kind string (e.g. `"import_created"`).
    ///
    /// Full set of kinds defined in `AuditEventKind`.
    pub kind: String,

    /// UTC Unix milliseconds.
    pub created_at: i64,

    /// Stable string identifying the actor type (e.g. `"user"`, `"service"`).
    pub actor_kind: String,

    /// One-way hash of the actor identifier.  Never the raw username/path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id_hash: Option<String>,

    /// The active policy revision id (`rev-{uuid}`) at the time of the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision_id: Option<String>,

    /// Risk level associated with this event (from the review/import system).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,

    /// Outcome of the audited action: `"success"`, `"failure"`, `"blocked"`.
    pub result: String,

    /// Namespaced reason code for this event.
    pub reason_code: String,

    /// Compact JSON summary of the event payload after redaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_summary_json: Option<String>,

    /// Hash of the previous audit event in this file's chain.
    /// `None` only for the very first event in a new file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,

    /// Rolling hash of this event: `hash(prev_hash || canonical_payload)`.
    pub event_hash: String,
}

impl AuditEvent {
    /// Serialises this event to a NDJSON line (no trailing newline).
    pub fn to_ndjson(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reason;

    fn now_ms() -> i64 {
        // Fixed timestamp for deterministic tests.
        1_745_000_000_000_i64
    }

    // ── Timestamp rendering ───────────────────────────────────────────────────

    #[test]
    fn local_rendering_carries_its_own_offset_and_matches_the_shifted_clock() {
        let offset = crate::local_offset::seconds();
        let rendered = rfc3339_local_millis(now_ms());
        let expected_clock = iso8601_utc_millis(now_ms() + i64::from(offset) * 1000);

        assert!(
            rendered.starts_with(expected_clock.trim_end_matches('Z')),
            "{rendered} should read as the local wall clock"
        );
        assert!(rendered.ends_with(&crate::local_offset::rfc3339_suffix(offset)));
        // The epoch value beside it is what stays absolute.
        let e = LogEvent::new(
            "evt-tz",
            now_ms(),
            EventLevel::Info,
            reason::service::STARTED,
        );
        assert_eq!(e.created_at, now_ms());
        assert_eq!(e.created_at_iso, rendered);
    }

    // ── LogEvent ──────────────────────────────────────────────────────────────

    #[test]
    fn log_event_schema_version_is_one() {
        assert_eq!(LOG_EVENT_SCHEMA_VERSION, 1);
    }

    #[test]
    fn log_event_minimal_construction() {
        let e = LogEvent::new(
            "evt-001",
            now_ms(),
            EventLevel::Info,
            reason::service::STARTED,
        );
        assert_eq!(e.schema_version, 1);
        assert_eq!(e.kind, "service.started");
        assert_eq!(e.level, EventLevel::Info);
        assert_eq!(e.category, EventCategory::Service);
        assert!(e.payload.is_none());
        assert!(e.correlation.is_empty());
    }

    #[test]
    fn log_event_with_correlation_and_payload() {
        let corr = EventCorrelation::default().with_revision("rev-abc");
        let e = LogEvent::new(
            "evt-002",
            now_ms(),
            EventLevel::Warn,
            reason::decision::FAIL_CLOSED,
        )
        .with_correlation(corr)
        .with_payload(serde_json::json!({ "route": "secondary" }));
        assert_eq!(e.correlation.revision_id.as_deref(), Some("rev-abc"));
        assert!(e.payload.is_some());
    }

    #[test]
    fn log_event_ndjson_is_valid_json() {
        let e = LogEvent::new("evt-003", now_ms(), EventLevel::Info, reason::cache::HIT);
        let line = e.to_ndjson().expect("serialize");
        let v: serde_json::Value = serde_json::from_str(&line).expect("valid JSON");
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["kind"], "cache.hit");
        assert_eq!(v["level"], "info");
        assert_eq!(v["category"], "cache");
    }

    #[test]
    fn log_event_omits_null_correlation_in_json() {
        let e = LogEvent::new(
            "evt-004",
            now_ms(),
            EventLevel::Info,
            reason::service::STARTED,
        );
        let line = e.to_ndjson().expect("serialize");
        // Empty correlation must be omitted (skip_serializing_if).
        assert!(
            !line.contains("correlation"),
            "empty correlation must be omitted"
        );
    }

    #[test]
    fn log_event_omits_null_payload_in_json() {
        let e = LogEvent::new(
            "evt-005",
            now_ms(),
            EventLevel::Info,
            reason::service::STOPPED,
        );
        let line = e.to_ndjson().expect("serialize");
        assert!(!line.contains("payload"));
    }

    #[test]
    fn log_event_default_privacy_is_public_summary() {
        let e = LogEvent::new(
            "evt-006",
            now_ms(),
            EventLevel::Info,
            reason::service::STARTED,
        );
        assert_eq!(e.privacy_class, PrivacyClass::PublicSummary);
    }

    #[test]
    fn log_event_with_privacy_only_raises() {
        let e = LogEvent::new(
            "evt-007",
            now_ms(),
            EventLevel::Info,
            reason::service::STARTED,
        )
        .with_privacy(PrivacyClass::Sensitive);
        assert_eq!(e.privacy_class, PrivacyClass::Sensitive);

        // Attempting to lower after raising must be a no-op.
        let e2 = e.with_privacy(PrivacyClass::PublicSummary);
        assert_eq!(e2.privacy_class, PrivacyClass::Sensitive);
    }

    #[test]
    fn log_event_round_trip() {
        let original = LogEvent::new("evt-rt", now_ms(), EventLevel::Warn, reason::apply::FAILED)
            .with_correlation(EventCorrelation::default().with_decision("d-999"))
            .with_payload(serde_json::json!({ "reason": "timeout" }));
        let json = original.to_ndjson().expect("serialize");
        let back: LogEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.event_id, original.event_id);
        assert_eq!(back.kind, original.kind);
        assert_eq!(back.level, original.level);
        assert_eq!(
            back.correlation.decision_id,
            original.correlation.decision_id
        );
    }

    // ── AuditEvent ────────────────────────────────────────────────────────────

    #[test]
    fn audit_event_schema_version_is_one() {
        assert_eq!(AUDIT_EVENT_SCHEMA_VERSION, 1);
    }

    #[test]
    fn audit_event_ndjson_is_valid_json() {
        let e = AuditEvent {
            schema_version: AUDIT_EVENT_SCHEMA_VERSION,
            seq: 1,
            event_id: "adt-001".into(),
            kind: "revision_activated".into(),
            created_at: now_ms(),
            actor_kind: "user".into(),
            actor_id_hash: Some("abc123".into()),
            revision_id: Some("rev-001".into()),
            risk_level: None,
            result: "success".into(),
            reason_code: reason::review::APPROVED.as_str().to_string(),
            payload_summary_json: None,
            prev_hash: None,
            event_hash: "deadbeef".into(),
        };
        let line = e.to_ndjson().expect("serialize");
        let v: serde_json::Value = serde_json::from_str(&line).expect("valid JSON");
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["seq"], 1);
        assert_eq!(v["kind"], "revision_activated");
        assert_eq!(v["result"], "success");
    }

    #[test]
    fn audit_event_omits_none_fields() {
        let e = AuditEvent {
            schema_version: AUDIT_EVENT_SCHEMA_VERSION,
            seq: 1,
            event_id: "adt-002".into(),
            kind: "revision_activated".into(),
            created_at: now_ms(),
            actor_kind: "service".into(),
            actor_id_hash: None,
            revision_id: None,
            risk_level: None,
            result: "success".into(),
            reason_code: reason::review::AUTO_ACTIVATED.as_str().to_string(),
            payload_summary_json: None,
            prev_hash: None,
            event_hash: "cafebabe".into(),
        };
        let line = e.to_ndjson().expect("serialize");
        assert!(!line.contains("actor_id_hash"));
        assert!(!line.contains("revision_id"));
        assert!(!line.contains("risk_level"));
        assert!(!line.contains("payload_summary_json"));
        assert!(!line.contains("prev_hash"));
    }

    #[test]
    fn audit_event_includes_all_set_fields() {
        let e = AuditEvent {
            schema_version: AUDIT_EVENT_SCHEMA_VERSION,
            seq: 5,
            event_id: "adt-003".into(),
            kind: "tamper_alert_raised".into(),
            created_at: now_ms(),
            actor_kind: "service".into(),
            actor_id_hash: Some("hash_abc".into()),
            revision_id: Some("rev-xyz".into()),
            risk_level: Some("high".into()),
            result: "failure".into(),
            reason_code: reason::integrity::AUDIT_CHAIN_MISMATCH.as_str().to_string(),
            payload_summary_json: Some(r#"{"details":"chain broken at seq 4"}"#.into()),
            prev_hash: Some("prev123".into()),
            event_hash: "newhash456".into(),
        };
        let line = e.to_ndjson().expect("serialize");
        let v: serde_json::Value = serde_json::from_str(&line).expect("valid JSON");
        assert_eq!(v["seq"], 5);
        assert_eq!(v["actor_id_hash"], "hash_abc");
        assert_eq!(v["risk_level"], "high");
        assert_eq!(v["prev_hash"], "prev123");
        assert_eq!(v["event_hash"], "newhash456");
    }

    #[test]
    fn log_event_default_mode_only_emits_info_and_above() {
        // Verify the design contract: Trace/Debug are not default-visible.
        let trace = LogEvent::new("t", now_ms(), EventLevel::Trace, reason::cache::HIT);
        let info = LogEvent::new("i", now_ms(), EventLevel::Info, reason::service::STARTED);
        assert!(!trace.level.is_default_visible());
        assert!(info.level.is_default_visible());
    }

    #[test]
    fn log_event_secret_never_log_privacy_not_default_safe() {
        let e = LogEvent::new("s", now_ms(), EventLevel::Info, reason::service::STARTED)
            .with_privacy(PrivacyClass::SecretNeverLog);
        assert!(!e.privacy_class.is_default_safe());
    }
}
