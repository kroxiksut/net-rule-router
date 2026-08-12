//! Cache rebuild lock, invalidation causes, and audit event payloads.
//!
//! # Design invariants
//!
//! - **`RebuildLock`** is a process-level mutex.  A single service process must
//!   not run two cache rebuilds concurrently; `try_acquire` prevents that.
//! - **`CacheAuditEvent`** payloads are produced by the storage layer and
//!   consumed by the service/diagnostics layer.  The storage
//!   layer never logs them itself.
//! - **`InvalidationCause`** drives the invalidation matrix: different causes
//!   require different actions (full clear vs. mark-stale vs. metadata-only).

use std::sync::{Mutex, MutexGuard};
use std::time::SystemTime;

use crate::dto::CacheResetReason;

// ── InvalidationCause ─────────────────────────────────────────────────────────

/// Why the FQDN/IP cache must be invalidated.
///
/// The service layer maps external events into one of these causes;
/// the storage layer uses the cause to choose the correct action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvalidationCause {
    /// The path to the user's rules files changed — derived SQL state may
    /// no longer correspond to the new file location.
    RulesFilePathChanged,
    /// The active policy revision changed — cache entries from the old revision
    /// are still useful as network observations but should be marked stale.
    ActiveRevisionChanged { new_revision_id: String },
    /// A file that backs the cache was modified outside the normal save/apply
    /// path (external tamper or linked import).
    ExternalFileModified,
    /// A schema migration was just completed — derived data may need rebuilding
    /// if the migration was destructive.
    SchemaMigrated { from_version: u32, to_version: u32 },
    /// SQLite `PRAGMA integrity_check` returned a non-ok result on the cache DB.
    CacheCorruptionDetected,
    /// The user explicitly requested a cache clear from the GUI.
    ManualUserReset,
}

impl InvalidationCause {
    /// Short tag used in diagnostic/audit logs.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::RulesFilePathChanged => "rules_path_changed",
            Self::ActiveRevisionChanged { .. } => "revision_changed",
            Self::ExternalFileModified => "external_file_modified",
            Self::SchemaMigrated { .. } => "schema_migrated",
            Self::CacheCorruptionDetected => "corruption_detected",
            Self::ManualUserReset => "manual_reset",
        }
    }

    /// Returns `true` when the cause requires a **full clear** of all cache
    /// rows rather than a mark-stale pass.
    ///
    /// `ActiveRevisionChanged` and `ExternalFileModified` use a mark-stale
    /// pass so that live network observations are preserved as background-
    /// refresh candidates.  All other causes clear completely.
    pub fn requires_full_clear(&self) -> bool {
        !matches!(
            self,
            Self::ActiveRevisionChanged { .. } | Self::ExternalFileModified
        )
    }

    /// Maps this cause to the [`CacheResetReason`] used by
    /// [`CacheRepository::clear_cache`][crate::repository::CacheRepository::clear_cache].
    ///
    /// Only meaningful when [`requires_full_clear`][Self::requires_full_clear]
    /// is `true`; callers should not invoke this on mark-stale causes.
    pub fn to_reset_reason(&self) -> CacheResetReason {
        match self {
            Self::ManualUserReset => CacheResetReason::ManualUserReset,
            Self::CacheCorruptionDetected => CacheResetReason::CorruptionDetected,
            Self::ActiveRevisionChanged { new_revision_id } => CacheResetReason::RevisionChanged {
                new_revision_id: new_revision_id.clone(),
            },
            Self::RulesFilePathChanged | Self::ExternalFileModified => {
                CacheResetReason::RulesFileChanged
            }
            Self::SchemaMigrated { .. } => CacheResetReason::SchemaUpgrade,
        }
    }
}

// ── RebuildOutcome ────────────────────────────────────────────────────────────

/// Detailed outcome of a completed (or skipped) cache rebuild.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RebuildOutcome {
    /// Cache was fully rebuilt from the rules file source of truth.
    FullRebuildCompleted {
        entries_restored: u64,
        duration_ms: u64,
    },
    /// Rebuild completed but some entries could not be restored.
    PartialRebuildCompleted {
        entries_restored: u64,
        failed_count: u64,
        duration_ms: u64,
    },
    /// No rebuild was needed — cache was already consistent with the source.
    NotNeeded,
}

// ── RebuildFailurePolicy ──────────────────────────────────────────────────────

/// What the service layer should do if a cache rebuild fails mid-way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RebuildFailurePolicy {
    /// Keep the stale (pre-clear) state as `stale_usable` entries.
    /// Routing continues on stale data until a fresh rebuild completes.
    KeepStaleState,
    /// Clear everything and operate in degraded mode — all lookups return
    /// `Missing` — until the next successful rebuild or manual reset.
    ClearAndDegrade,
}

// ── RebuildResult ─────────────────────────────────────────────────────────────

/// Overall result returned by the service rebuild flow.
///
/// The storage layer provides the `clear_cache` / `upsert_resolution`
/// primitives.  The service layer owns the rebuild loop and
/// reports the result here so the audit subsystem can surface it.
#[derive(Clone, Debug)]
pub enum RebuildResult {
    Completed(RebuildOutcome),
    /// Rebuild failed; stale data was preserved as background-refresh candidates.
    FailedKeepStale {
        error: String,
    },
    /// Rebuild failed and all cache data was cleared; operating in degraded mode.
    FailedDegraded {
        error: String,
    },
}

// ── RebuildLock ───────────────────────────────────────────────────────────────

/// Process-level mutex that prevents concurrent cache rebuilds.
///
/// The service loop must acquire this lock before starting any
/// rebuild operation.  If a rebuild is already in progress `try_acquire`
/// returns `None` and the caller should log a warning and skip.
///
/// # Example
///
/// ```rust
/// use nrr_storage::rebuild::RebuildLock;
///
/// let lock = RebuildLock::new();
/// let guard = lock.try_acquire();
/// if guard.is_some() {
///     // perform rebuild — guard released when dropped
/// }
/// ```
pub struct RebuildLock {
    inner: Mutex<()>,
}

impl RebuildLock {
    /// Creates a new, unlocked rebuild lock.
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(()),
        }
    }

    /// Tries to acquire the lock without blocking.
    ///
    /// Returns `Some(RebuildGuard)` when the lock was free; `None` when
    /// another rebuild is already running.  The lock is automatically
    /// released when the guard is dropped.
    pub fn try_acquire(&self) -> Option<RebuildGuard<'_>> {
        self.inner
            .try_lock()
            .ok()
            .map(|g| RebuildGuard { _guard: g })
    }
}

impl Default for RebuildLock {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII guard that holds the [`RebuildLock`] for the duration of a rebuild.
///
/// Created by [`RebuildLock::try_acquire`] and released when dropped.  Use a
/// nested scope for early release.
pub struct RebuildGuard<'a> {
    _guard: MutexGuard<'a, ()>,
}

// ── CacheAuditEvent ───────────────────────────────────────────────────────────

/// Audit/diagnostic event produced by the storage layer.
///
/// The storage layer **produces** these events and returns them from
/// operations, but does not log or persist them itself.  The service layer
/// is responsible for routing them to the audit trail.
#[derive(Clone, Debug)]
pub enum CacheAuditEvent {
    /// User-initiated cache clear (from the GUI or CLI).
    ManualReset {
        removed_rows: u64,
        initiated_at: SystemTime,
    },
    /// A cache rebuild has been initiated.
    RebuildStarted {
        cause: InvalidationCause,
        started_at: SystemTime,
    },
    /// A cache rebuild completed successfully (or was not needed).
    RebuildCompleted {
        cause: InvalidationCause,
        outcome: RebuildOutcome,
        completed_at: SystemTime,
    },
    /// A cache rebuild attempt failed.
    RebuildFailed {
        cause: InvalidationCause,
        error: String,
        failed_at: SystemTime,
        failure_policy: RebuildFailurePolicy,
    },
    /// SQLite integrity check detected corruption in the cache DB.
    CorruptionDetected {
        details: String,
        detected_at: SystemTime,
    },
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── InvalidationCause ─────────────────────────────────────────────────────

    #[test]
    fn invalidation_cause_tags_are_unique() {
        let causes = [
            InvalidationCause::RulesFilePathChanged,
            InvalidationCause::ActiveRevisionChanged {
                new_revision_id: "rev-1".into(),
            },
            InvalidationCause::ExternalFileModified,
            InvalidationCause::SchemaMigrated {
                from_version: 1,
                to_version: 2,
            },
            InvalidationCause::CacheCorruptionDetected,
            InvalidationCause::ManualUserReset,
        ];
        let tags: Vec<&str> = causes.iter().map(|c| c.tag()).collect();
        let unique: std::collections::HashSet<&str> = tags.iter().copied().collect();
        assert_eq!(unique.len(), tags.len(), "all cause tags must be distinct");
    }

    #[test]
    fn requires_full_clear_only_for_structural_causes() {
        // Mark-stale causes (do NOT require full clear).
        assert!(!InvalidationCause::ActiveRevisionChanged {
            new_revision_id: "rev-2".into()
        }
        .requires_full_clear());
        assert!(!InvalidationCause::ExternalFileModified.requires_full_clear());

        // Full-clear causes.
        assert!(InvalidationCause::RulesFilePathChanged.requires_full_clear());
        assert!(InvalidationCause::CacheCorruptionDetected.requires_full_clear());
        assert!(InvalidationCause::ManualUserReset.requires_full_clear());
        assert!(InvalidationCause::SchemaMigrated {
            from_version: 1,
            to_version: 2
        }
        .requires_full_clear());
    }

    #[test]
    fn to_reset_reason_maps_correctly() {
        assert_eq!(
            InvalidationCause::ManualUserReset.to_reset_reason(),
            CacheResetReason::ManualUserReset
        );
        assert_eq!(
            InvalidationCause::CacheCorruptionDetected.to_reset_reason(),
            CacheResetReason::CorruptionDetected
        );
        assert_eq!(
            InvalidationCause::RulesFilePathChanged.to_reset_reason(),
            CacheResetReason::RulesFileChanged
        );
        assert_eq!(
            InvalidationCause::SchemaMigrated {
                from_version: 1,
                to_version: 2
            }
            .to_reset_reason(),
            CacheResetReason::SchemaUpgrade
        );
        assert_eq!(
            InvalidationCause::ActiveRevisionChanged {
                new_revision_id: "rev-x".into()
            }
            .to_reset_reason(),
            CacheResetReason::RevisionChanged {
                new_revision_id: "rev-x".into()
            }
        );
    }

    // ── RebuildLock ───────────────────────────────────────────────────────────

    #[test]
    fn rebuild_lock_try_acquire_succeeds_when_free() {
        let lock = RebuildLock::new();
        let guard = lock.try_acquire();
        assert!(guard.is_some(), "should acquire when free");
    }

    #[test]
    fn rebuild_lock_try_acquire_fails_when_held() {
        let lock = RebuildLock::new();
        let _guard = lock.try_acquire().expect("first acquire");
        let second = lock.try_acquire();
        assert!(second.is_none(), "should fail when already held");
    }

    #[test]
    fn rebuild_lock_released_after_guard_dropped() {
        let lock = RebuildLock::new();
        {
            let _guard = lock.try_acquire().expect("first acquire");
        }
        // guard dropped — lock is free again
        let guard2 = lock.try_acquire();
        assert!(
            guard2.is_some(),
            "should acquire after previous guard dropped"
        );
    }

    #[test]
    fn rebuild_lock_default_is_unlocked() {
        let lock = RebuildLock::default();
        let guard = lock.try_acquire();
        assert!(guard.is_some());
    }

    // ── RebuildResult ────────────────────────────────────────────────────────

    #[test]
    fn rebuild_result_completed_holds_outcome() {
        let outcome = RebuildOutcome::FullRebuildCompleted {
            entries_restored: 42,
            duration_ms: 10,
        };
        let result = RebuildResult::Completed(outcome.clone());
        match result {
            RebuildResult::Completed(o) => assert_eq!(o, outcome),
            _ => panic!("expected Completed"),
        }
    }

    #[test]
    fn rebuild_result_failed_variants_carry_error() {
        let msg = "disk full".to_string();
        let ks = RebuildResult::FailedKeepStale { error: msg.clone() };
        let dg = RebuildResult::FailedDegraded { error: msg.clone() };
        match ks {
            RebuildResult::FailedKeepStale { error } => assert_eq!(error, msg),
            _ => panic!(),
        }
        match dg {
            RebuildResult::FailedDegraded { error } => assert_eq!(error, msg),
            _ => panic!(),
        }
    }

    // ── CacheAuditEvent ──────────────────────────────────────────────────────

    #[test]
    fn cache_audit_event_manual_reset_cloneable() {
        let ev = CacheAuditEvent::ManualReset {
            removed_rows: 99,
            initiated_at: SystemTime::now(),
        };
        let _ = ev.clone();
    }

    #[test]
    fn cache_audit_event_corruption_detected_cloneable() {
        let ev = CacheAuditEvent::CorruptionDetected {
            details: "page checksum mismatch".into(),
            detected_at: SystemTime::now(),
        };
        let _ = ev.clone();
    }
}
