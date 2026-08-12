//! Taxonomy and classification of external change events.
//!
//! External changes are events where something outside the normal GUI→service
//! interactive flow modifies or appears to modify policy-relevant state. They
//! fall into three categories:
//!
//! | Category             | Examples                                               | Response                     |
//! |----------------------|--------------------------------------------------------|------------------------------|
//! | Informational        | Snapshot source file edited after import               | Notify user; no policy change|
//! | Pending revision     | Linked source file changed normally                    | Build candidate for review   |
//! | Tamper-visible alert | Integrity failure, suspicious linked churn, unexplained active pointer change | Freeze + alert + audit |
//!
//! # Taxonomy
//!
//! - [`ExternalChangeEvent::SnapshotSourceChanged`] — the external file at the
//!   originally imported path was edited. The active revision is **unaffected**;
//!   this is informational only.
//! - [`ExternalChangeEvent::LinkedSourceChanged`] — a linked source produced a
//!   normal content change. The service should build a candidate and queue it for
//!   review.
//! - [`ExternalChangeEvent::LinkedSourceSuspicious`] — a linked source change
//!   triggered a suspicion signal (see [`crate::linked_source::SuspicionReason`]).
//!   A tamper-visible alert is raised; the import is held.
//! - [`ExternalChangeEvent::ServiceStateIntegrityFailed`] — the SHA-256 hash of
//!   a stored revision no longer matches its content. Activation is frozen until
//!   the user reviews and the service recovers or rolls back.
//! - [`ExternalChangeEvent::UnexpectedServiceStateDelta`] — the active revision
//!   pointer changed without a corresponding audit event. Treated as a tamper
//!   indicator.
//!
//! # Tamper reaction policy
//!
//! Tamper-visible events trigger a fixed sequence regardless of severity:
//! 1. Freeze further imports/activations until user acknowledgement.
//! 2. Fallback to last known good revision (service layer).
//! 3. Create a persistent tamper alert.
//! 4. Write an audit event.
//! 5. Notify the user via security-visible status.
//!
//! # Deduplication
//!
//! Repeated identical events (same source, same hash) within a service session
//! must be deduplicated. [`ExternalChangeEvent::deduplication_key`] returns a
//! stable key for this purpose. Time-window tracking is the service layer's
//! responsibility.
//!
//! # Service integration
//!
//! [`classify_change_event`] is a pure domain function. The service wraps
//! it with I/O, persistence, and the actual alert/audit emission pipeline
//! in `nrr-service-runtime::production_security_alerts`.

use crate::alert::AlertSeverity;
use crate::linked_source::{LinkedSourceId, SuspicionReason};
use crate::revision::{ContentHash, RevisionId};

// ── ExternalChangeEvent ───────────────────────────────────────────────────────

/// An externally observed change to policy-relevant state.
///
/// All variants are produced by the service after observing a change.
/// The service passes the event to [`classify_change_event`] to determine the
/// appropriate response before taking any further action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExternalChangeEvent {
    /// The external file at the path of an original snapshot import was edited
    /// after the import completed.
    ///
    /// The active revision is **unchanged**. This is a purely informational event.
    /// The user should be notified that the source file has diverged from the
    /// imported revision, but no policy action is taken automatically.
    SnapshotSourceChanged {
        /// Absolute path of the source file that changed.
        source_path: String,
        /// Content hash of the file as it was at import time (original).
        original_hash: ContentHash,
        /// Content hash of the file as observed now.
        current_hash: ContentHash,
    },

    /// A linked source file produced a normal content change (no suspicion signals).
    ///
    /// The service should proceed with the import pipeline and queue a candidate
    /// revision for user review.
    LinkedSourceChanged {
        /// Identifier of the linked source.
        source_id: LinkedSourceId,
        /// Content hash of the new file content.
        new_file_hash: ContentHash,
    },

    /// A linked source change triggered a suspicion signal.
    ///
    /// The import is held. A tamper-visible alert must be raised and the user
    /// must explicitly review before the import can proceed.
    LinkedSourceSuspicious {
        /// Identifier of the linked source.
        source_id: LinkedSourceId,
        /// Content hash of the suspicious new content.
        new_file_hash: ContentHash,
        /// Why the change was flagged as suspicious.
        suspicion: SuspicionReason,
    },

    /// The SHA-256 hash of a stored revision's content no longer matches its
    /// recorded `ContentHash`.
    ///
    /// This is a high-confidence tamper indicator. The service must freeze
    /// further imports and activations, fall back to last known good, raise a
    /// tamper alert, and write an audit event.
    ServiceStateIntegrityFailed {
        /// ID of the revision whose integrity check failed.
        revision_id: RevisionId,
        /// Hash stored in the revision record at creation time.
        stored_hash: ContentHash,
        /// Hash recomputed from the revision content now.
        detected_hash: ContentHash,
    },

    /// The active revision pointer changed without a corresponding audit event
    /// in the audit trail, or without an active operation that could explain it.
    ///
    /// Treated as a tamper indicator. The user must be notified and the service
    /// must not apply any further policy changes until the situation is resolved.
    UnexpectedServiceStateDelta {
        /// Human-readable description of the unexpected delta.
        description: String,
    },
}

impl ExternalChangeEvent {
    /// Returns a stable key for deduplication of repeated identical events.
    ///
    /// Events with the same key within a service session should be deduplicated
    /// to avoid spamming the user with repeated alerts for the same root cause.
    pub fn deduplication_key(&self) -> DeduplicationKey {
        match self {
            Self::SnapshotSourceChanged {
                source_path,
                current_hash,
                ..
            } => DeduplicationKey::SnapshotChanged {
                source_path: source_path.clone(),
                current_hash: current_hash.clone(),
            },
            Self::LinkedSourceChanged {
                source_id,
                new_file_hash,
            } => DeduplicationKey::LinkedChanged {
                source_id: source_id.clone(),
                new_file_hash: new_file_hash.clone(),
            },
            Self::LinkedSourceSuspicious {
                source_id,
                new_file_hash,
                ..
            } => DeduplicationKey::LinkedSuspicious {
                source_id: source_id.clone(),
                new_file_hash: new_file_hash.clone(),
            },
            Self::ServiceStateIntegrityFailed {
                revision_id,
                detected_hash,
                ..
            } => DeduplicationKey::IntegrityFailed {
                revision_id: revision_id.clone(),
                detected_hash: detected_hash.clone(),
            },
            Self::UnexpectedServiceStateDelta { description } => {
                DeduplicationKey::UnexpectedDelta {
                    description: description.clone(),
                }
            }
        }
    }
}

// ── DeduplicationKey ──────────────────────────────────────────────────────────

/// Stable key used to suppress repeated identical events within a service session.
///
/// Two events with the same `DeduplicationKey` within the same session represent
/// the same root cause and should produce at most one alert. The service layer
/// (`nrr-service-runtime::production_security_alerts`, 16.10) maintains the
/// session-scoped dedup table.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DeduplicationKey {
    /// A snapshot source file changed, identified by path and current content.
    SnapshotChanged {
        source_path: String,
        current_hash: ContentHash,
    },
    /// A linked source changed normally, identified by source id and new content.
    LinkedChanged {
        source_id: LinkedSourceId,
        new_file_hash: ContentHash,
    },
    /// A linked source changed suspiciously, identified by source id and content.
    LinkedSuspicious {
        source_id: LinkedSourceId,
        new_file_hash: ContentHash,
    },
    /// A revision integrity failure, identified by revision id and detected hash.
    IntegrityFailed {
        revision_id: RevisionId,
        detected_hash: ContentHash,
    },
    /// An unexpected service state delta, identified by its description string.
    UnexpectedDelta { description: String },
}

// ── ChangeEventClassification ─────────────────────────────────────────────────

/// How a change event is classified and what class of response it requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChangeEventClassification {
    /// The event is informational. The user should be notified but no policy
    /// change or blocking action is required.
    Informational,
    /// The event requires building a candidate revision and queuing it for
    /// user review before activation.
    PendingRevision,
    /// The event indicates potential tampering or integrity violation. A
    /// security-visible tamper alert must be raised immediately.
    TamperAlert,
}

// ── RequiredActions ───────────────────────────────────────────────────────────

/// The set of actions the service must take in response to a change event.
///
/// Populated by [`classify_change_event`]. The service layer executes
/// each action that is `true`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequiredActions {
    /// Build a candidate revision from the new content and queue it for review.
    pub create_pending_revision: bool,
    /// Freeze further imports and activations until user acknowledges the alert.
    pub freeze_activation: bool,
    /// Initiate a fallback to the last known good revision.
    ///
    /// Applicable only when `freeze_activation` is also `true`. The service
    /// must verify last-known-good integrity before applying.
    pub fallback_to_last_known_good: bool,
    /// Create a persistent `Alert` with the appropriate severity.
    pub create_alert: bool,
    /// Write an `AuditEvent` for this change.
    pub write_audit_event: bool,
    /// Show a security-visible notification to the user.
    pub notify_user: bool,
}

// ── ChangeEventResponse ───────────────────────────────────────────────────────

/// The complete classified response for an external change event.
///
/// Returned by [`classify_change_event`]. The service layer uses this
/// to decide what to do next without needing to re-examine the event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangeEventResponse {
    /// How this event is classified.
    pub classification: ChangeEventClassification,
    /// Alert severity, if an alert should be created. `None` for informational events.
    pub alert_severity: Option<AlertSeverity>,
    /// The set of actions the service must perform.
    pub required_actions: RequiredActions,
    /// Locale key for the user-visible notification copy.
    ///
    /// Formatted as `security.event.<event-slug>` for use with the localization system.
    pub user_copy_key: &'static str,
}

// ── classify_change_event ─────────────────────────────────────────────────────

/// Pure function: maps an [`ExternalChangeEvent`] to its [`ChangeEventResponse`].
///
/// No I/O, no side effects. The service layer wraps this with persistence and
/// alert/audit emission.
pub fn classify_change_event(event: &ExternalChangeEvent) -> ChangeEventResponse {
    match event {
        ExternalChangeEvent::SnapshotSourceChanged { .. } => ChangeEventResponse {
            classification: ChangeEventClassification::Informational,
            alert_severity: None,
            required_actions: RequiredActions {
                create_pending_revision: false,
                freeze_activation: false,
                fallback_to_last_known_good: false,
                create_alert: false,
                write_audit_event: false,
                notify_user: true,
            },
            user_copy_key: "security.event.snapshot-source-changed",
        },

        ExternalChangeEvent::LinkedSourceChanged { .. } => ChangeEventResponse {
            classification: ChangeEventClassification::PendingRevision,
            alert_severity: None,
            required_actions: RequiredActions {
                create_pending_revision: true,
                freeze_activation: false,
                fallback_to_last_known_good: false,
                create_alert: false,
                write_audit_event: true,
                notify_user: true,
            },
            user_copy_key: "security.event.linked-source-changed",
        },

        ExternalChangeEvent::LinkedSourceSuspicious { .. } => ChangeEventResponse {
            classification: ChangeEventClassification::TamperAlert,
            alert_severity: Some(AlertSeverity::Critical),
            required_actions: RequiredActions {
                create_pending_revision: false,
                freeze_activation: true,
                fallback_to_last_known_good: false,
                create_alert: true,
                write_audit_event: true,
                notify_user: true,
            },
            user_copy_key: "security.event.linked-source-suspicious",
        },

        ExternalChangeEvent::ServiceStateIntegrityFailed { .. } => ChangeEventResponse {
            classification: ChangeEventClassification::TamperAlert,
            alert_severity: Some(AlertSeverity::Critical),
            required_actions: RequiredActions {
                create_pending_revision: false,
                freeze_activation: true,
                fallback_to_last_known_good: true,
                create_alert: true,
                write_audit_event: true,
                notify_user: true,
            },
            user_copy_key: "security.event.service-state-integrity-failed",
        },

        ExternalChangeEvent::UnexpectedServiceStateDelta { .. } => ChangeEventResponse {
            classification: ChangeEventClassification::TamperAlert,
            alert_severity: Some(AlertSeverity::Critical),
            required_actions: RequiredActions {
                create_pending_revision: false,
                freeze_activation: true,
                fallback_to_last_known_good: false,
                create_alert: true,
                write_audit_event: true,
                notify_user: true,
            },
            user_copy_key: "security.event.unexpected-service-state-delta",
        },
    }
}

// ── SuspiciousLinkedChangeIndicator ───────────────────────────────────────────

/// Observable indicators that a linked source change should be classified as
/// suspicious rather than a normal update.
///
/// These are the signals the service evaluates before calling
/// [`classify_change_event`] with [`ExternalChangeEvent::LinkedSourceSuspicious`].
/// They complement [`crate::linked_source::SuspicionReason`], which is embedded
/// in the event itself.
///
/// # Note
///
/// `SuspicionReason` captures the *specific* suspicion at the linked-check level.
/// This enum documents the *full catalogue* of observable indicators the service
/// must watch for when deciding whether to raise a suspicion signal at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SuspiciousLinkedChangeIndicator {
    /// The file changed while a candidate from a previous check was still awaiting
    /// user review (handled via `SuspicionReason::ChangedWhilePendingUnreviewed`).
    PendingReviewNotYetResolved,
    /// The diff between the previous and new content exceeds the mass-change
    /// threshold (handled via `SuspicionReason::MassReplacementDetected`).
    MassRuleReplacement,
    /// The file changed rapidly multiple times in a short window, suggesting
    /// external automated manipulation rather than a deliberate user edit.
    /// Churn detection is deferred to the service's auto-poll loop —
    /// `TODO`: implement when `LinkedSourceAutoPoll` lands.
    RapidContentChurn,
    /// The file's observed schema version or format marker is incompatible with
    /// the previously imported version — suggesting content substitution.
    /// Schema-consistency checking is deferred — `TODO`: wire when the
    /// parser exposes the read schema_version on the outcome.
    IncompatibleSchemaVersion,
}

// ── ServiceStateDeltaKind ─────────────────────────────────────────────────────

/// The kind of an unexpected service-owned state delta.
///
/// Documents the full taxonomy of unexpected state changes the service must
/// watch for. Used when constructing an
/// [`ExternalChangeEvent::UnexpectedServiceStateDelta`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ServiceStateDeltaKind {
    /// The active revision ID pointer changed without a corresponding `Activation`
    /// audit event.
    ActiveRevisionPointerChanged,
    /// A revision record was deleted or truncated from the store without a
    /// corresponding `Rejection` or `RolledBack` audit event.
    RevisionRecordMissing,
    /// The last-known-good pointer was updated without a corresponding
    /// `Activation` event.
    LastKnownGoodPointerChanged,
    /// The audit log has a gap — sequence numbers are not contiguous.
    AuditLogGap,
}

impl ServiceStateDeltaKind {
    /// Returns a stable string slug for logging and the `description` field of
    /// [`ExternalChangeEvent::UnexpectedServiceStateDelta`].
    pub const fn slug(self) -> &'static str {
        match self {
            Self::ActiveRevisionPointerChanged => "active-revision-pointer-changed",
            Self::RevisionRecordMissing => "revision-record-missing",
            Self::LastKnownGoodPointerChanged => "last-known-good-pointer-changed",
            Self::AuditLogGap => "audit-log-gap",
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::linked_source::{LinkedSourceId, SuspicionReason};
    use crate::revision::{ContentHash, RevisionId};

    fn hash(byte: u8) -> ContentHash {
        ContentHash::from_bytes([byte; 32])
    }

    fn rev_id(s: &str) -> RevisionId {
        RevisionId::from_prefixed_string(s.to_string()).expect("valid rev id")
    }

    fn lsrc_id(s: &str) -> LinkedSourceId {
        LinkedSourceId::from_prefixed_string(s.to_string()).expect("valid lsrc id")
    }

    fn snapshot_changed() -> ExternalChangeEvent {
        ExternalChangeEvent::SnapshotSourceChanged {
            source_path: "C:/rules/primary.txt".to_string(),
            original_hash: hash(0xAA),
            current_hash: hash(0xBB),
        }
    }

    fn linked_changed() -> ExternalChangeEvent {
        ExternalChangeEvent::LinkedSourceChanged {
            source_id: lsrc_id("lsrc-test-001"),
            new_file_hash: hash(0xCC),
        }
    }

    fn linked_suspicious() -> ExternalChangeEvent {
        ExternalChangeEvent::LinkedSourceSuspicious {
            source_id: lsrc_id("lsrc-test-001"),
            new_file_hash: hash(0xDD),
            suspicion: SuspicionReason::MassReplacementDetected { changed_count: 25 },
        }
    }

    fn integrity_failed() -> ExternalChangeEvent {
        ExternalChangeEvent::ServiceStateIntegrityFailed {
            revision_id: rev_id("rev-tampered-001"),
            stored_hash: hash(0x01),
            detected_hash: hash(0x02),
        }
    }

    fn unexpected_delta() -> ExternalChangeEvent {
        ExternalChangeEvent::UnexpectedServiceStateDelta {
            description: "active-revision-pointer-changed".to_string(),
        }
    }

    // ── Snapshot source changed ──────────────────────────────────────────────

    #[test]
    fn snapshot_source_changed_is_informational() {
        let resp = classify_change_event(&snapshot_changed());
        assert_eq!(
            resp.classification,
            ChangeEventClassification::Informational
        );
        assert!(resp.alert_severity.is_none());
    }

    #[test]
    fn snapshot_source_changed_notifies_but_does_not_create_pending() {
        let resp = classify_change_event(&snapshot_changed());
        assert!(!resp.required_actions.create_pending_revision);
        assert!(!resp.required_actions.freeze_activation);
        assert!(!resp.required_actions.create_alert);
        assert!(!resp.required_actions.write_audit_event);
        assert!(resp.required_actions.notify_user);
    }

    // ── Linked source changed normally ───────────────────────────────────────

    #[test]
    fn linked_source_changed_creates_pending_revision() {
        let resp = classify_change_event(&linked_changed());
        assert_eq!(
            resp.classification,
            ChangeEventClassification::PendingRevision
        );
        assert!(resp.required_actions.create_pending_revision);
        assert!(resp.required_actions.write_audit_event);
        assert!(!resp.required_actions.freeze_activation);
        assert!(resp.alert_severity.is_none());
    }

    // ── Linked source suspicious ─────────────────────────────────────────────

    #[test]
    fn linked_source_suspicious_is_tamper_alert() {
        let resp = classify_change_event(&linked_suspicious());
        assert_eq!(resp.classification, ChangeEventClassification::TamperAlert);
        assert_eq!(resp.alert_severity, Some(AlertSeverity::Critical));
    }

    #[test]
    fn linked_source_suspicious_freezes_and_alerts_but_no_fallback() {
        let resp = classify_change_event(&linked_suspicious());
        assert!(resp.required_actions.freeze_activation);
        assert!(resp.required_actions.create_alert);
        assert!(resp.required_actions.write_audit_event);
        assert!(!resp.required_actions.fallback_to_last_known_good);
        assert!(!resp.required_actions.create_pending_revision);
    }

    // ── Service state integrity failed ───────────────────────────────────────

    #[test]
    fn integrity_failure_is_critical_tamper_alert() {
        let resp = classify_change_event(&integrity_failed());
        assert_eq!(resp.classification, ChangeEventClassification::TamperAlert);
        assert_eq!(resp.alert_severity, Some(AlertSeverity::Critical));
    }

    #[test]
    fn integrity_failure_triggers_full_tamper_reaction() {
        let resp = classify_change_event(&integrity_failed());
        let actions = &resp.required_actions;
        assert!(actions.freeze_activation);
        assert!(actions.fallback_to_last_known_good);
        assert!(actions.create_alert);
        assert!(actions.write_audit_event);
        assert!(actions.notify_user);
        assert!(!actions.create_pending_revision);
    }

    // ── Unexpected service state delta ───────────────────────────────────────

    #[test]
    fn unexpected_delta_is_tamper_alert() {
        let resp = classify_change_event(&unexpected_delta());
        assert_eq!(resp.classification, ChangeEventClassification::TamperAlert);
        assert_eq!(resp.alert_severity, Some(AlertSeverity::Critical));
    }

    #[test]
    fn unexpected_delta_freezes_but_no_fallback() {
        let resp = classify_change_event(&unexpected_delta());
        assert!(resp.required_actions.freeze_activation);
        assert!(!resp.required_actions.fallback_to_last_known_good);
        assert!(resp.required_actions.create_alert);
        assert!(resp.required_actions.write_audit_event);
    }

    // ── Deduplication keys ───────────────────────────────────────────────────

    #[test]
    fn same_snapshot_event_produces_same_dedup_key() {
        let a = snapshot_changed();
        let b = snapshot_changed();
        assert_eq!(a.deduplication_key(), b.deduplication_key());
    }

    #[test]
    fn different_snapshot_hash_produces_different_dedup_key() {
        let a = ExternalChangeEvent::SnapshotSourceChanged {
            source_path: "C:/rules/primary.txt".to_string(),
            original_hash: hash(0xAA),
            current_hash: hash(0xBB),
        };
        let b = ExternalChangeEvent::SnapshotSourceChanged {
            source_path: "C:/rules/primary.txt".to_string(),
            original_hash: hash(0xAA),
            current_hash: hash(0xCC),
        };
        assert_ne!(a.deduplication_key(), b.deduplication_key());
    }

    #[test]
    fn linked_changed_and_linked_suspicious_produce_different_dedup_key_types() {
        let changed_key = linked_changed().deduplication_key();
        let suspicious_key = ExternalChangeEvent::LinkedSourceSuspicious {
            source_id: lsrc_id("lsrc-test-001"),
            new_file_hash: hash(0xCC),
            suspicion: SuspicionReason::MassReplacementDetected { changed_count: 25 },
        }
        .deduplication_key();
        assert_ne!(changed_key, suspicious_key);
    }

    #[test]
    fn integrity_failure_dedup_key_uses_revision_id_and_detected_hash() {
        let a = integrity_failed();
        let b = ExternalChangeEvent::ServiceStateIntegrityFailed {
            revision_id: rev_id("rev-tampered-001"),
            stored_hash: hash(0x01),
            detected_hash: hash(0x03), // different detected hash
        };
        assert_ne!(a.deduplication_key(), b.deduplication_key());
    }

    // ── Locale key coverage ──────────────────────────────────────────────────

    #[test]
    fn all_events_have_non_empty_user_copy_key() {
        let events = [
            snapshot_changed(),
            linked_changed(),
            linked_suspicious(),
            integrity_failed(),
            unexpected_delta(),
        ];
        for event in &events {
            let resp = classify_change_event(event);
            assert!(
                !resp.user_copy_key.is_empty(),
                "user_copy_key must not be empty for {event:?}"
            );
            assert!(
                resp.user_copy_key.starts_with("security.event."),
                "user_copy_key must start with security.event. for {event:?}"
            );
        }
    }

    // ── ServiceStateDeltaKind slugs ──────────────────────────────────────────

    #[test]
    fn service_state_delta_kind_slugs_are_stable() {
        assert_eq!(
            ServiceStateDeltaKind::ActiveRevisionPointerChanged.slug(),
            "active-revision-pointer-changed"
        );
        assert_eq!(
            ServiceStateDeltaKind::RevisionRecordMissing.slug(),
            "revision-record-missing"
        );
        assert_eq!(
            ServiceStateDeltaKind::LastKnownGoodPointerChanged.slug(),
            "last-known-good-pointer-changed"
        );
        assert_eq!(ServiceStateDeltaKind::AuditLogGap.slug(), "audit-log-gap");
    }
}
