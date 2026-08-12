//! SHA-256 content integrity helpers for the service-critical state database.
//!
//! # Integrity model
//!
//! The storage layer maintains SHA-256 hashes alongside each revision pointer
//! (`active_revision.integrity_hash`, `last_known_good.integrity_hash`) and
//! verifies them on every startup integrity check.
//!
//! SHA-256 provides tamper-evidence: a hash mismatch indicates that the row was
//! modified outside the normal write path.  It is **not** a secret — no key
//! material is stored in user storage.  HMAC with a service-owned key is a
//! future hardening step.
//!
//! # Boundary
//!
//! - This module **computes and verifies** hashes; it does not persist them.
//! - The `SqliteStateStore` writes and reads the hash columns.
//! - The service layer executes any `RecoveryAction`; this module
//!   only produces the action as data.

use std::time::SystemTime;

use sha2::{Digest, Sha256};

use crate::dto::{IntegrityCheckResult, RecoveryAction};
use crate::error::IntegrityFailureKind;

// ── Hash functions ────────────────────────────────────────────────────────────

/// Computes the lowercase hex SHA-256 digest of a UTF-8 string.
///
/// Used to produce the `integrity_hash` stored alongside each revision pointer.
pub fn compute_revision_hash(s: &str) -> String {
    let bytes: [u8; 32] = Sha256::digest(s.as_bytes()).into();
    bytes.iter().fold(String::with_capacity(64), |mut acc, b| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// Returns `true` when `stored_hash` matches the SHA-256 of `revision_id`.
///
/// The comparison is simple equality — no secret is involved, so a constant-
/// time comparison is not required for security.  The goal is tamper detection,
/// not secret protection.
pub fn verify_revision_hash(revision_id: &str, stored_hash: &str) -> bool {
    compute_revision_hash(revision_id) == stored_hash
}

// ── IntegrityTarget ───────────────────────────────────────────────────────────

/// Which component was checked during an integrity verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntegrityTarget {
    /// `PRAGMA integrity_check(1)` on `nrr_fqdn_ip_cache.db`.
    CacheDatabase,
    /// `PRAGMA integrity_check(1)` on `nrr_service_state.db`.
    StateDatabase,
    /// SHA-256 hash of `active_revision.revision_id` in `nrr_service_state.db`.
    ActiveRevisionHash,
    /// SHA-256 hash of `last_known_good.revision_id` in `nrr_service_state.db`.
    LastKnownGoodHash,
}

// ── IntegrityEvent ────────────────────────────────────────────────────────────

/// Audit/diagnostic event produced when an integrity check runs.
///
/// The storage layer produces this; the service/diagnostics layer
/// routes it to the audit trail and GUI health surface.
#[derive(Clone, Debug)]
pub struct IntegrityEvent {
    /// Which component was checked.
    pub check_target: IntegrityTarget,
    /// What the check found.
    pub result: IntegrityCheckResult,
    /// What the service layer should do in response.
    pub recovery_action: RecoveryAction,
    /// Specific failure classification when `result` is not `Ok`.
    pub failure_kind: Option<IntegrityFailureKind>,
    /// Wall-clock time when the check completed.
    pub checked_at: SystemTime,
}

impl IntegrityEvent {
    /// Convenience constructor for a successful check.
    pub fn ok(target: IntegrityTarget, checked_at: SystemTime) -> Self {
        Self {
            check_target: target,
            result: IntegrityCheckResult::Ok,
            recovery_action: RecoveryAction::None,
            failure_kind: None,
            checked_at,
        }
    }

    /// Convenience constructor for a failed check.
    pub fn failed(
        target: IntegrityTarget,
        result: IntegrityCheckResult,
        recovery_action: RecoveryAction,
        failure_kind: IntegrityFailureKind,
        checked_at: SystemTime,
    ) -> Self {
        Self {
            check_target: target,
            result,
            recovery_action,
            failure_kind: Some(failure_kind),
            checked_at,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── compute_revision_hash ────────────────────────────────────────────────

    #[test]
    fn compute_revision_hash_is_64_hex_chars() {
        let h = compute_revision_hash("rev-abc-001");
        assert_eq!(h.len(), 64, "SHA-256 hex must be 64 characters");
        assert!(
            h.chars().all(|c| c.is_ascii_hexdigit()),
            "must be hex digits only"
        );
    }

    #[test]
    fn compute_revision_hash_is_deterministic() {
        let a = compute_revision_hash("rev-001");
        let b = compute_revision_hash("rev-001");
        assert_eq!(a, b);
    }

    #[test]
    fn compute_revision_hash_different_inputs_differ() {
        let a = compute_revision_hash("rev-001");
        let b = compute_revision_hash("rev-002");
        assert_ne!(a, b);
    }

    #[test]
    fn compute_revision_hash_empty_string_is_stable() {
        // SHA-256("") = e3b0c44298fc1c149afb... — known value.
        let h = compute_revision_hash("");
        assert!(
            h.starts_with("e3b0c44298fc1c149afb"),
            "known SHA-256 of empty string"
        );
    }

    // ── verify_revision_hash ────────────────────────────────────────────────

    #[test]
    fn verify_revision_hash_correct_input_returns_true() {
        let id = "rev-xyz-007";
        let h = compute_revision_hash(id);
        assert!(verify_revision_hash(id, &h));
    }

    #[test]
    fn verify_revision_hash_wrong_input_returns_false() {
        let h = compute_revision_hash("rev-001");
        assert!(!verify_revision_hash("rev-002", &h));
    }

    #[test]
    fn verify_revision_hash_tampered_hash_returns_false() {
        let h = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(!verify_revision_hash("rev-001", h));
    }

    // ── IntegrityEvent constructors ──────────────────────────────────────────

    #[test]
    fn integrity_event_ok_has_no_failure_kind() {
        let ev = IntegrityEvent::ok(IntegrityTarget::StateDatabase, SystemTime::now());
        assert_eq!(ev.result, IntegrityCheckResult::Ok);
        assert_eq!(ev.recovery_action, RecoveryAction::None);
        assert!(ev.failure_kind.is_none());
    }

    #[test]
    fn integrity_event_failed_carries_failure_kind() {
        let ev = IntegrityEvent::failed(
            IntegrityTarget::ActiveRevisionHash,
            IntegrityCheckResult::PolicyIntegrityFailed {
                details: "hash mismatch".into(),
            },
            RecoveryAction::FallbackToLastKnownGood,
            IntegrityFailureKind::HashMismatch,
            SystemTime::now(),
        );
        assert_eq!(ev.check_target, IntegrityTarget::ActiveRevisionHash);
        assert_eq!(ev.failure_kind, Some(IntegrityFailureKind::HashMismatch));
        assert_eq!(ev.recovery_action, RecoveryAction::FallbackToLastKnownGood);
    }
}
