//! Linked import source domain types and state machine.
//!
//! A *linked source* is an external file that the user has associated with the
//! active configuration. In `ManualRefresh` mode (the only mode implemented in
//! the Free edition) the user triggers a re-read of the file via the
//! "Update rules from file" button; there is no background polling.
//!
//! # Lifecycle
//!
//! ```text
//! (register) → Active
//!   Active   → TemporarilyUnreachable   (file gone for a short time)
//!   Active   → TamperSuspected          (suspicious content delta)
//!   Active   → DisabledAfterErrors      (repeated inaccessibility)
//!   Any      → (unlinked)               (user removes the source)
//! ```
//!
//! The state machine is intentionally minimal for the scaffold phase.
//! `AutoPoll` mode and the full error-counter–driven disable logic are
//! deferred until the Windows service takes ownership of file-system
//! watching.
//!
//! # Service-owned watcher
//!
//! `LinkedWatchMode::AutoPoll`, error counters, and all file-system watching
//! belong to the service layer. This module defines the types and the pure
//! state-machine function only.

use core::fmt;

use crate::revision::{ContentHash, RevisionId, UnixTimestamp};

// ── LinkedSourceId ────────────────────────────────────────────────────────────

/// Stable identifier for a linked import source. Format: `"lsrc-{suffix}"`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LinkedSourceId(String);

impl LinkedSourceId {
    const PREFIX: &'static str = "lsrc-";

    /// Constructs a `LinkedSourceId` from a prefixed string.
    ///
    /// Returns `Err` if the string does not start with `"lsrc-"` or the
    /// suffix is empty.
    pub fn from_prefixed_string(s: String) -> Result<Self, &'static str> {
        let suffix = s
            .strip_prefix(Self::PREFIX)
            .ok_or("linked source id must start with \"lsrc-\"")?;
        if suffix.is_empty() {
            return Err("linked source id suffix must not be empty");
        }
        Ok(Self(s))
    }

    /// Returns the full identifier string including prefix.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LinkedSourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── LinkedSourceLocator ───────────────────────────────────────────────────────

/// Location of the external file that serves as the linked import source.
///
/// Carries the absolute path as it was configured by the user. The locator is
/// stored as provenance; the service resolves the path at check time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkedSourceLocator {
    /// Absolute path to the external rules file.
    pub path: String,
}

impl LinkedSourceLocator {
    /// Constructs a locator from an absolute path string.
    pub fn from_path(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }
}

// ── LinkedWatchMode ───────────────────────────────────────────────────────────

/// How the service monitors the linked source for changes.
///
/// Only `ManualRefresh` is implemented in the Free edition.
/// `AutoPoll` is reserved and must not be used in any live code path.
///
/// # Reserved for a future service-side auto-poll watcher
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LinkedWatchMode {
    /// The user triggers checks explicitly via the "Update rules from file"
    /// button. No background polling occurs.
    ManualRefresh,
    /// The service periodically polls the file for changes. Not implemented.
    ///
    /// # Reserved for a future service-side auto-poll watcher
    AutoPoll,
}

impl LinkedWatchMode {
    /// Returns a stable slug for logging and serialization.
    pub const fn slug(self) -> &'static str {
        match self {
            Self::ManualRefresh => "manual-refresh",
            Self::AutoPoll => "auto-poll",
        }
    }
}

// ── LinkedWatchStatus ─────────────────────────────────────────────────────────

/// Operational status of a linked import source.
///
/// `Active` is the normal steady state. Other variants represent degraded or
/// suspended states that require user attention or service intervention.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LinkedWatchStatus {
    /// The source is reachable and being monitored normally.
    Active,
    /// The source was unreachable on the last check but the failure may be
    /// transient (e.g. file temporarily locked or on a disconnected drive).
    TemporarilyUnreachable,
    /// Monitoring was manually paused by the user.
    Paused,
    /// The source was disabled automatically after repeated inaccessibility
    /// (threshold defined by the service).
    DisabledAfterErrors,
    /// The source content changed in a way that triggered a suspicion signal.
    /// The service holds the import until the user explicitly reviews it.
    TamperSuspected,
}

impl LinkedWatchStatus {
    /// Returns `true` when the source requires user attention before the next
    /// check can proceed normally.
    pub fn requires_user_attention(self) -> bool {
        matches!(self, Self::DisabledAfterErrors | Self::TamperSuspected)
    }

    /// Returns `true` when the source is in a state where normal checks may run.
    pub fn is_checkable(self) -> bool {
        matches!(self, Self::Active | Self::TemporarilyUnreachable)
    }

    /// Returns a stable slug for logging and serialization.
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::TemporarilyUnreachable => "temporarily-unreachable",
            Self::Paused => "paused",
            Self::DisabledAfterErrors => "disabled-after-errors",
            Self::TamperSuspected => "tamper-suspected",
        }
    }
}

// ── LinkedSourceRegistration ──────────────────────────────────────────────────

/// A registered linked import source and its current monitoring state.
///
/// Created when the user links an external file. Updated by the service after
/// each check cycle and after user-triggered refreshes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkedSourceRegistration {
    /// Stable identifier for this linked source.
    pub id: LinkedSourceId,
    /// Location of the external file.
    pub locator: LinkedSourceLocator,
    /// How the service monitors this source.
    pub watch_mode: LinkedWatchMode,
    /// Current operational status.
    pub status: LinkedWatchStatus,
    /// UTC timestamp when this source was first registered.
    pub registered_at: UnixTimestamp,
    /// UTC timestamp of the last successful read of the source file.
    pub last_successful_check_at: Option<UnixTimestamp>,
    /// Content hash of the file at the time of the last successful check.
    ///
    /// Used to detect whether the file changed between checks. `None` on first
    /// registration (no check has occurred yet).
    pub last_known_file_hash: Option<ContentHash>,
    /// ID of the candidate revision produced by the last successful import of
    /// this source, if any. `None` when no import has been performed yet or
    /// after the pending revision was resolved.
    pub pending_revision_id: Option<RevisionId>,
}

// ── SuspicionReason ───────────────────────────────────────────────────────────

/// Why a content change was flagged as suspicious.
///
/// Suspicious changes are those where the delta between the previous and new
/// content triggers a high-risk signal that warrants holding the import for
/// explicit user review rather than proceeding normally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SuspicionReason {
    /// The file content changed while a pending revision from a previous check
    /// was still awaiting user review. A second unreviewed change compounds
    /// the risk and must not auto-queue.
    ChangedWhilePendingUnreviewed {
        /// The revision ID of the pending (unreviewed) candidate.
        pending_id: RevisionId,
    },
    /// The change appears to overwrite a large portion of the rule set in a
    /// single step, exceeding the mass-change threshold.
    MassReplacementDetected {
        /// Number of rules that changed.
        changed_count: u32,
    },
}

// ── LinkedSourceCheckOutcome ──────────────────────────────────────────────────

/// Result of checking a linked source for changes.
///
/// Returned by [`process_linked_check`]. The caller is responsible for
/// translating the outcome into the appropriate import pipeline call or
/// status update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkedSourceCheckOutcome {
    /// The file was read successfully and its content hash matches the last
    /// known hash. No import is required.
    SourceUnchanged,
    /// The file was read successfully and its content hash differs from the
    /// last known hash. The caller should proceed with the import pipeline.
    SourceChanged {
        /// Hash of the new file content.
        new_file_hash: ContentHash,
    },
    /// The file could not be read. The registration status should be
    /// updated to reflect the failure.
    SourceInaccessible {
        /// Human-readable description of why the file was not readable.
        reason: String,
    },
    /// The file changed, but the delta raised a suspicion signal. The import
    /// is held pending explicit user review. The status transitions to
    /// [`LinkedWatchStatus::TamperSuspected`].
    SourceSuspiciouslyChanged {
        /// Hash of the suspicious new content.
        new_file_hash: ContentHash,
        /// Why the change was flagged.
        suspicion: SuspicionReason,
    },
}

// ── LinkedCheckInput ──────────────────────────────────────────────────────────

/// Inputs to the linked check state machine.
///
/// All context is supplied by the caller so [`process_linked_check`] remains
/// a pure function with no I/O. The caller reads the file and computes the
/// hash before invoking the state machine.
#[derive(Debug)]
pub struct LinkedCheckInput {
    /// The current registration being checked.
    pub registration: LinkedSourceRegistration,
    /// Result of reading the file: `Ok(hash)` if readable, `Err(reason)` if not.
    pub file_read_result: Result<ContentHash, String>,
    /// UTC timestamp of this check attempt.
    pub checked_at: UnixTimestamp,
    /// Number of rules that changed, supplied by the caller after a preliminary
    /// parse of the new content. Used to detect mass replacements.
    ///
    /// `None` when the file was not readable or content has not changed.
    pub changed_rule_count: Option<u32>,
}

// ── process_linked_check ──────────────────────────────────────────────────────

/// Maximum number of changed rules before the change is flagged as a
/// mass replacement. Mirrors [`crate::risk::MASS_CHANGE_THRESHOLD`].
pub const LINKED_MASS_CHANGE_THRESHOLD: u32 = 20;

/// Pure state machine for a single linked source check cycle.
///
/// Consumes a [`LinkedCheckInput`] and returns the appropriate
/// [`LinkedSourceCheckOutcome`]. No I/O occurs inside this function.
///
/// # Decision logic
///
/// 1. If the file is unreadable → [`LinkedSourceCheckOutcome::SourceInaccessible`].
/// 2. If the hash matches `last_known_file_hash` → [`LinkedSourceCheckOutcome::SourceUnchanged`].
/// 3. If a pending revision exists and the file changed →
///    [`LinkedSourceCheckOutcome::SourceSuspiciouslyChanged`] with
///    [`SuspicionReason::ChangedWhilePendingUnreviewed`].
/// 4. If `changed_rule_count` exceeds [`LINKED_MASS_CHANGE_THRESHOLD`] →
///    [`LinkedSourceCheckOutcome::SourceSuspiciouslyChanged`] with
///    [`SuspicionReason::MassReplacementDetected`].
/// 5. Otherwise → [`LinkedSourceCheckOutcome::SourceChanged`].
pub fn process_linked_check(input: LinkedCheckInput) -> LinkedSourceCheckOutcome {
    let new_hash = match input.file_read_result {
        Ok(hash) => hash,
        Err(reason) => return LinkedSourceCheckOutcome::SourceInaccessible { reason },
    };

    // Unchanged if hash matches last known (or no prior hash — treat as changed).
    if let Some(ref last) = input.registration.last_known_file_hash {
        if *last == new_hash {
            return LinkedSourceCheckOutcome::SourceUnchanged;
        }
    }

    // File changed — check for suspicion signals.

    // Signal 1: changed while a pending revision is still awaiting review.
    if let Some(pending_id) = input.registration.pending_revision_id.clone() {
        return LinkedSourceCheckOutcome::SourceSuspiciouslyChanged {
            new_file_hash: new_hash,
            suspicion: SuspicionReason::ChangedWhilePendingUnreviewed { pending_id },
        };
    }

    // Signal 2: mass replacement.
    if let Some(count) = input.changed_rule_count {
        if count > LINKED_MASS_CHANGE_THRESHOLD {
            return LinkedSourceCheckOutcome::SourceSuspiciouslyChanged {
                new_file_hash: new_hash,
                suspicion: SuspicionReason::MassReplacementDetected {
                    changed_count: count,
                },
            };
        }
    }

    LinkedSourceCheckOutcome::SourceChanged {
        new_file_hash: new_hash,
    }
}

// ── UnlinkOutcome ─────────────────────────────────────────────────────────────

/// Result of removing a linked import source registration.
///
/// The pending revision (if any) is not automatically rejected — the caller
/// must decide whether to keep or discard the pending candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnlinkOutcome {
    /// The source was removed cleanly — no pending revision was outstanding.
    Removed,
    /// The source was removed but a pending revision was waiting for user review.
    /// The caller should decide whether to keep the pending candidate or reject it.
    RemovedWithPendingRevision {
        /// ID of the pending revision that was outstanding at unlink time.
        pending_revision_id: RevisionId,
    },
}

/// Pure function describing the unlink outcome for a given registration.
///
/// No state mutation occurs here. The caller applies the outcome.
pub fn describe_unlink_outcome(registration: &LinkedSourceRegistration) -> UnlinkOutcome {
    match &registration.pending_revision_id {
        None => UnlinkOutcome::Removed,
        Some(id) => UnlinkOutcome::RemovedWithPendingRevision {
            pending_revision_id: id.clone(),
        },
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::revision::{ContentHash, RevisionId, UnixTimestamp};

    fn lsrc_id(s: &str) -> LinkedSourceId {
        LinkedSourceId::from_prefixed_string(s.to_string()).expect("valid id")
    }

    fn rev_id(s: &str) -> RevisionId {
        RevisionId::from_prefixed_string(s.to_string()).expect("valid id")
    }

    fn ts(secs: u64) -> UnixTimestamp {
        UnixTimestamp::from_secs(secs)
    }

    fn hash(byte: u8) -> ContentHash {
        ContentHash::from_bytes([byte; 32])
    }

    fn base_registration() -> LinkedSourceRegistration {
        LinkedSourceRegistration {
            id: lsrc_id("lsrc-test-001"),
            locator: LinkedSourceLocator::from_path("C:/rules/primary.txt"),
            watch_mode: LinkedWatchMode::ManualRefresh,
            status: LinkedWatchStatus::Active,
            registered_at: ts(1_700_000_000),
            last_successful_check_at: None,
            last_known_file_hash: None,
            pending_revision_id: None,
        }
    }

    // ── LinkedSourceId ────────────────────────────────────────────────────────

    #[test]
    fn linked_source_id_accepts_valid_prefixed_string() {
        let id = LinkedSourceId::from_prefixed_string("lsrc-abc123".to_string());
        assert!(id.is_ok());
        assert_eq!(id.expect("ok").as_str(), "lsrc-abc123");
    }

    #[test]
    fn linked_source_id_rejects_missing_prefix() {
        assert!(LinkedSourceId::from_prefixed_string("abc123".to_string()).is_err());
    }

    #[test]
    fn linked_source_id_rejects_prefix_only() {
        assert!(LinkedSourceId::from_prefixed_string("lsrc-".to_string()).is_err());
    }

    #[test]
    fn linked_source_id_display_matches_full_string() {
        let id = lsrc_id("lsrc-xyz-001");
        assert_eq!(id.to_string(), "lsrc-xyz-001");
    }

    // ── LinkedWatchMode ───────────────────────────────────────────────────────

    #[test]
    fn watch_mode_slugs_are_stable() {
        assert_eq!(LinkedWatchMode::ManualRefresh.slug(), "manual-refresh");
        assert_eq!(LinkedWatchMode::AutoPoll.slug(), "auto-poll");
    }

    // ── LinkedWatchStatus ─────────────────────────────────────────────────────

    #[test]
    fn watch_status_requires_user_attention_for_disabled_and_tamper() {
        assert!(LinkedWatchStatus::DisabledAfterErrors.requires_user_attention());
        assert!(LinkedWatchStatus::TamperSuspected.requires_user_attention());
        assert!(!LinkedWatchStatus::Active.requires_user_attention());
        assert!(!LinkedWatchStatus::TemporarilyUnreachable.requires_user_attention());
        assert!(!LinkedWatchStatus::Paused.requires_user_attention());
    }

    #[test]
    fn watch_status_is_checkable_for_active_and_temporarily_unreachable() {
        assert!(LinkedWatchStatus::Active.is_checkable());
        assert!(LinkedWatchStatus::TemporarilyUnreachable.is_checkable());
        assert!(!LinkedWatchStatus::Paused.is_checkable());
        assert!(!LinkedWatchStatus::DisabledAfterErrors.is_checkable());
        assert!(!LinkedWatchStatus::TamperSuspected.is_checkable());
    }

    #[test]
    fn watch_status_slugs_are_stable() {
        assert_eq!(LinkedWatchStatus::Active.slug(), "active");
        assert_eq!(
            LinkedWatchStatus::TemporarilyUnreachable.slug(),
            "temporarily-unreachable"
        );
        assert_eq!(LinkedWatchStatus::Paused.slug(), "paused");
        assert_eq!(
            LinkedWatchStatus::DisabledAfterErrors.slug(),
            "disabled-after-errors"
        );
        assert_eq!(
            LinkedWatchStatus::TamperSuspected.slug(),
            "tamper-suspected"
        );
    }

    // ── process_linked_check ──────────────────────────────────────────────────

    #[test]
    fn first_registration_with_new_content_returns_source_changed() {
        // No prior hash → any readable content counts as changed.
        let input = LinkedCheckInput {
            registration: base_registration(),
            file_read_result: Ok(hash(0xAA)),
            checked_at: ts(1_700_000_100),
            changed_rule_count: Some(3),
        };
        let outcome = process_linked_check(input);
        assert_eq!(
            outcome,
            LinkedSourceCheckOutcome::SourceChanged {
                new_file_hash: hash(0xAA)
            }
        );
    }

    #[test]
    fn unchanged_content_returns_source_unchanged() {
        let mut reg = base_registration();
        reg.last_known_file_hash = Some(hash(0xBB));

        let input = LinkedCheckInput {
            registration: reg,
            file_read_result: Ok(hash(0xBB)),
            checked_at: ts(1_700_000_200),
            changed_rule_count: None,
        };
        assert_eq!(
            process_linked_check(input),
            LinkedSourceCheckOutcome::SourceUnchanged
        );
    }

    #[test]
    fn inaccessible_file_returns_source_inaccessible() {
        let input = LinkedCheckInput {
            registration: base_registration(),
            file_read_result: Err("file not found".to_string()),
            checked_at: ts(1_700_000_300),
            changed_rule_count: None,
        };
        matches!(
            process_linked_check(input),
            LinkedSourceCheckOutcome::SourceInaccessible { .. }
        );
    }

    #[test]
    fn changed_while_pending_unreviewed_returns_suspiciously_changed() {
        let mut reg = base_registration();
        reg.last_known_file_hash = Some(hash(0xCC));
        reg.pending_revision_id = Some(rev_id("rev-pending-001"));

        let input = LinkedCheckInput {
            registration: reg,
            file_read_result: Ok(hash(0xDD)),
            checked_at: ts(1_700_000_400),
            changed_rule_count: Some(2),
        };
        match process_linked_check(input) {
            LinkedSourceCheckOutcome::SourceSuspiciouslyChanged {
                new_file_hash,
                suspicion: SuspicionReason::ChangedWhilePendingUnreviewed { pending_id },
            } => {
                assert_eq!(new_file_hash, hash(0xDD));
                assert_eq!(pending_id.as_str(), "rev-pending-001");
            }
            other => panic!(
                "expected SourceSuspiciouslyChanged(ChangedWhilePendingUnreviewed), got {other:?}"
            ),
        }
    }

    #[test]
    fn mass_replacement_returns_suspiciously_changed() {
        let mut reg = base_registration();
        reg.last_known_file_hash = Some(hash(0xEE));
        // no pending revision

        let input = LinkedCheckInput {
            registration: reg,
            file_read_result: Ok(hash(0xFF)),
            checked_at: ts(1_700_000_500),
            changed_rule_count: Some(LINKED_MASS_CHANGE_THRESHOLD + 1),
        };
        match process_linked_check(input) {
            LinkedSourceCheckOutcome::SourceSuspiciouslyChanged {
                suspicion: SuspicionReason::MassReplacementDetected { changed_count },
                ..
            } => {
                assert!(changed_count > LINKED_MASS_CHANGE_THRESHOLD);
            }
            other => panic!("expected MassReplacementDetected, got {other:?}"),
        }
    }

    #[test]
    fn exactly_at_threshold_is_not_suspicious() {
        let mut reg = base_registration();
        reg.last_known_file_hash = Some(hash(0x01));

        let input = LinkedCheckInput {
            registration: reg,
            file_read_result: Ok(hash(0x02)),
            checked_at: ts(1_700_000_600),
            changed_rule_count: Some(LINKED_MASS_CHANGE_THRESHOLD),
        };
        assert_eq!(
            process_linked_check(input),
            LinkedSourceCheckOutcome::SourceChanged {
                new_file_hash: hash(0x02)
            }
        );
    }

    // ── describe_unlink_outcome ───────────────────────────────────────────────

    #[test]
    fn unlink_with_no_pending_revision_returns_removed() {
        let reg = base_registration();
        assert_eq!(describe_unlink_outcome(&reg), UnlinkOutcome::Removed);
    }

    #[test]
    fn unlink_with_pending_revision_returns_removed_with_pending() {
        let mut reg = base_registration();
        reg.pending_revision_id = Some(rev_id("rev-pending-777"));

        match describe_unlink_outcome(&reg) {
            UnlinkOutcome::RemovedWithPendingRevision {
                pending_revision_id,
            } => {
                assert_eq!(pending_revision_id.as_str(), "rev-pending-777");
            }
            other => panic!("expected RemovedWithPendingRevision, got {other:?}"),
        }
    }
}
