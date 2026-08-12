//! Rules-only revision content and lifecycle state machine.
//!
//! Revisions version **rules only**. Per-SID bindings (`route_bindings`,
//! `behavior_mode`, `secondary_block_policy`) are live config and are NOT
//! revision-tracked. At apply time the service assembles a
//! `CanonicalProfile` from `(rules from active revision) + (per-SID
//! bindings from live tables)`.
//!
//! This module is pure: no I/O, no serde, no SQLite. Persistence is in
//! `nrr-storage::revisions`. Service-level orchestration is in
//! `nrr-service-runtime`'s `ActivationCoordinator`.
//!
//! # State machine
//!
//! Persisted statuses (5 — match SQL CHECK in schema v6):
//!
//! ```text
//! Candidate ──ApplySucceeded─► Active     (and previous Active → Superseded)
//! Candidate ──ApplyFailed────► Rejected
//! Active    ──Superseded─────► Superseded (when a new revision activates)
//! Active    ──RolledBack─────► RolledBack (when this revision is rolled back)
//!
//! Terminal (cannot transition out): Superseded, RolledBack, Rejected.
//! ```
//!
//! The transient `Activating` state lives in `apply_attempt_markers`, not
//! in this enum — `revisions.status` stays as `Candidate` while in flight
//! and flips on commit.

use crate::canonical::CanonicalRuleBook;

// ── RulesRevisionContent ──────────────────────────────────────────────────────

/// Format version embedded in serialised `RulesRevisionContent`.
///
/// Bumped when the JSON shape of `rule_book` or surrounding metadata
/// changes. Storage rejects unknown versions on load.
pub const RULES_REVISION_FORMAT_VERSION: u16 = 1;

/// Versioned content of a single rules revision.
///
/// Serialisation lives in the service layer. Storage persists
/// pre-serialised JSON strings opaquely (same pattern as
/// `apply_snapshots.snapshot_json`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RulesRevisionContent {
    /// Rule set — primary and secondary routes.
    pub rule_book: CanonicalRuleBook,
    /// Format version. New revisions use [`RULES_REVISION_FORMAT_VERSION`].
    pub format_version: u16,
}

impl RulesRevisionContent {
    /// Constructs new content tagged with the current format version.
    pub fn new(rule_book: CanonicalRuleBook) -> Self {
        Self {
            rule_book,
            format_version: RULES_REVISION_FORMAT_VERSION,
        }
    }
}

// ── RevisionStatus ────────────────────────────────────────────────────────────

/// Persisted lifecycle status of a rules revision.
///
/// Slug values match the `revisions.status` SQL CHECK constraint
/// (`'candidate' | 'active' | 'superseded' | 'rolled-back' | 'rejected'`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RevisionStatus {
    /// Submitted, not yet activated. Token may still be issued.
    Candidate,
    /// Currently applied. Exactly one revision is `Active` at a time
    /// (enforced by partial unique index in schema v6).
    Active,
    /// Was active; a newer revision became active.
    Superseded,
    /// Was active; rolled back via `rollback_to`. Retained for audit.
    RolledBack,
    /// Was a candidate; apply failed or pre-flight rejected it.
    Rejected,
}

impl RevisionStatus {
    /// Slug used in the `revisions.status` SQL column.
    pub const fn as_slug(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::RolledBack => "rolled-back",
            Self::Rejected => "rejected",
        }
    }

    /// Parses a slug from the SQL column. Returns `None` for unknown values.
    pub fn from_slug(slug: &str) -> Option<Self> {
        match slug {
            "candidate" => Some(Self::Candidate),
            "active" => Some(Self::Active),
            "superseded" => Some(Self::Superseded),
            "rolled-back" => Some(Self::RolledBack),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }

    /// Terminal statuses cannot transition out — they are retained for
    /// audit/rollback history but never become active again.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Superseded | Self::RolledBack | Self::Rejected)
    }
}

// ── RulesRevisionSource ───────────────────────────────────────────────────────

/// How a candidate revision was created.
///
/// Slugs match the `revisions.source` SQL CHECK constraint.
///
/// Distinct from the legacy `crate::revision::RevisionSource` (which
/// describes import provenance). This flow uses simpler,
/// transport-friendly slugs that map 1:1 to GUI initiation paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RulesRevisionSource {
    /// User edited rules directly in the GUI.
    GuiRulesEdit,
    /// Imported from a preset file (`rules_primary.txt` / `rules_secondary.txt`).
    PresetImport,
    /// Internally regenerated when rolling back to last-known-good after
    /// crash recovery decided the active revision was unsafe.
    RecoveryLkg,
    /// Internally regenerated when the user explicitly rolls back.
    Rollback,
}

impl RulesRevisionSource {
    /// Slug used in the `revisions.source` SQL column.
    pub const fn as_slug(self) -> &'static str {
        match self {
            Self::GuiRulesEdit => "gui-rules-edit",
            Self::PresetImport => "preset-import",
            Self::RecoveryLkg => "recovery-lkg",
            Self::Rollback => "rollback",
        }
    }

    /// Parses a slug from the SQL column.
    pub fn from_slug(slug: &str) -> Option<Self> {
        match slug {
            "gui-rules-edit" => Some(Self::GuiRulesEdit),
            "preset-import" => Some(Self::PresetImport),
            "recovery-lkg" => Some(Self::RecoveryLkg),
            "rollback" => Some(Self::Rollback),
            _ => None,
        }
    }
}

// ── RevisionTransition ────────────────────────────────────────────────────────

/// A single transition request applied to a [`RevisionStatus`].
///
/// Pure: `apply_to(current)` is a deterministic function. The caller wraps
/// the transition in a SQL transaction and emits an audit event after a
/// successful commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevisionTransition {
    /// Apply phase succeeded — `Candidate` → `Active`. The previous
    /// `Active` revision (if any) is paired-transitioned to `Superseded`
    /// in the same SQL transaction by the caller.
    ApplySucceeded,
    /// Apply phase failed — `Candidate` → `Rejected`.
    ApplyFailed,
    /// New revision is taking over — this revision: `Active` → `Superseded`.
    Superseded,
    /// User rolled back this revision — `Active` → `RolledBack`.
    RolledBack,
}

/// Why a transition was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionError {
    /// The current status is terminal — no transitions are allowed.
    TerminalState(RevisionStatus),
    /// The transition is not defined for this status.
    InvalidTransition {
        from: RevisionStatus,
        transition: RevisionTransition,
    },
}

impl RevisionTransition {
    /// Returns the new status if `self` is a valid transition from `current`.
    pub fn apply_to(self, current: RevisionStatus) -> Result<RevisionStatus, TransitionError> {
        if current.is_terminal() {
            return Err(TransitionError::TerminalState(current));
        }
        match (current, self) {
            (RevisionStatus::Candidate, Self::ApplySucceeded) => Ok(RevisionStatus::Active),
            (RevisionStatus::Candidate, Self::ApplyFailed) => Ok(RevisionStatus::Rejected),
            (RevisionStatus::Active, Self::Superseded) => Ok(RevisionStatus::Superseded),
            (RevisionStatus::Active, Self::RolledBack) => Ok(RevisionStatus::RolledBack),
            _ => Err(TransitionError::InvalidTransition {
                from: current,
                transition: self,
            }),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── RulesRevisionContent ──────────────────────────────────────────────────

    #[test]
    fn rules_revision_content_new_uses_current_format_version() {
        let content = RulesRevisionContent::new(CanonicalRuleBook::default());
        assert_eq!(content.format_version, RULES_REVISION_FORMAT_VERSION);
        assert_eq!(content.rule_book, CanonicalRuleBook::default());
    }

    #[test]
    fn rules_revision_format_version_is_one_at_block_16_9_1() {
        assert_eq!(RULES_REVISION_FORMAT_VERSION, 1);
    }

    // ── RevisionStatus slugs ──────────────────────────────────────────────────

    #[test]
    fn revision_status_slugs_match_sql_check_constraint() {
        assert_eq!(RevisionStatus::Candidate.as_slug(), "candidate");
        assert_eq!(RevisionStatus::Active.as_slug(), "active");
        assert_eq!(RevisionStatus::Superseded.as_slug(), "superseded");
        assert_eq!(RevisionStatus::RolledBack.as_slug(), "rolled-back");
        assert_eq!(RevisionStatus::Rejected.as_slug(), "rejected");
    }

    #[test]
    fn revision_status_slug_roundtrip() {
        for variant in [
            RevisionStatus::Candidate,
            RevisionStatus::Active,
            RevisionStatus::Superseded,
            RevisionStatus::RolledBack,
            RevisionStatus::Rejected,
        ] {
            let slug = variant.as_slug();
            let parsed = RevisionStatus::from_slug(slug)
                .unwrap_or_else(|| panic!("from_slug({slug:?}) must succeed"));
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn revision_status_from_unknown_slug_returns_none() {
        assert!(RevisionStatus::from_slug("activating").is_none());
        assert!(RevisionStatus::from_slug("ACTIVE").is_none());
        assert!(RevisionStatus::from_slug("").is_none());
    }

    #[test]
    fn revision_status_terminal_set() {
        assert!(!RevisionStatus::Candidate.is_terminal());
        assert!(!RevisionStatus::Active.is_terminal());
        assert!(RevisionStatus::Superseded.is_terminal());
        assert!(RevisionStatus::RolledBack.is_terminal());
        assert!(RevisionStatus::Rejected.is_terminal());
    }

    // ── RulesRevisionSource slugs ─────────────────────────────────────────────

    #[test]
    fn rules_revision_source_slugs_match_sql_check_constraint() {
        assert_eq!(
            RulesRevisionSource::GuiRulesEdit.as_slug(),
            "gui-rules-edit"
        );
        assert_eq!(RulesRevisionSource::PresetImport.as_slug(), "preset-import");
        assert_eq!(RulesRevisionSource::RecoveryLkg.as_slug(), "recovery-lkg");
        assert_eq!(RulesRevisionSource::Rollback.as_slug(), "rollback");
    }

    #[test]
    fn rules_revision_source_slug_roundtrip() {
        for variant in [
            RulesRevisionSource::GuiRulesEdit,
            RulesRevisionSource::PresetImport,
            RulesRevisionSource::RecoveryLkg,
            RulesRevisionSource::Rollback,
        ] {
            let parsed = RulesRevisionSource::from_slug(variant.as_slug())
                .unwrap_or_else(|| panic!("roundtrip failed: {variant:?}"));
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn rules_revision_source_unknown_slug_returns_none() {
        assert!(RulesRevisionSource::from_slug("direct-edit").is_none());
        assert!(RulesRevisionSource::from_slug("file-sync").is_none());
        assert!(RulesRevisionSource::from_slug("").is_none());
    }

    // ── State machine ─────────────────────────────────────────────────────────

    #[test]
    fn candidate_apply_succeeded_becomes_active() {
        let next = RevisionTransition::ApplySucceeded
            .apply_to(RevisionStatus::Candidate)
            .expect("valid transition");
        assert_eq!(next, RevisionStatus::Active);
    }

    #[test]
    fn candidate_apply_failed_becomes_rejected() {
        let next = RevisionTransition::ApplyFailed
            .apply_to(RevisionStatus::Candidate)
            .expect("valid transition");
        assert_eq!(next, RevisionStatus::Rejected);
    }

    #[test]
    fn active_superseded_becomes_superseded() {
        let next = RevisionTransition::Superseded
            .apply_to(RevisionStatus::Active)
            .expect("valid transition");
        assert_eq!(next, RevisionStatus::Superseded);
    }

    #[test]
    fn active_rolled_back_becomes_rolled_back() {
        let next = RevisionTransition::RolledBack
            .apply_to(RevisionStatus::Active)
            .expect("valid transition");
        assert_eq!(next, RevisionStatus::RolledBack);
    }

    #[test]
    fn terminal_states_reject_all_transitions() {
        let terminals = [
            RevisionStatus::Superseded,
            RevisionStatus::RolledBack,
            RevisionStatus::Rejected,
        ];
        let transitions = [
            RevisionTransition::ApplySucceeded,
            RevisionTransition::ApplyFailed,
            RevisionTransition::Superseded,
            RevisionTransition::RolledBack,
        ];
        for terminal in terminals {
            for t in transitions {
                let err = t
                    .apply_to(terminal)
                    .expect_err("terminal must reject all transitions");
                assert!(matches!(err, TransitionError::TerminalState(s) if s == terminal));
            }
        }
    }

    #[test]
    fn invalid_transitions_from_candidate_are_rejected() {
        // Candidate cannot directly become Superseded or RolledBack.
        let err = RevisionTransition::Superseded
            .apply_to(RevisionStatus::Candidate)
            .expect_err("Candidate → Superseded is not allowed");
        assert!(matches!(
            err,
            TransitionError::InvalidTransition {
                from: RevisionStatus::Candidate,
                transition: RevisionTransition::Superseded,
            }
        ));

        let err = RevisionTransition::RolledBack
            .apply_to(RevisionStatus::Candidate)
            .expect_err("Candidate → RolledBack is not allowed");
        assert!(matches!(
            err,
            TransitionError::InvalidTransition {
                from: RevisionStatus::Candidate,
                transition: RevisionTransition::RolledBack,
            }
        ));
    }

    #[test]
    fn invalid_transitions_from_active_are_rejected() {
        // Active cannot directly become Rejected (only Candidates fail apply).
        let err = RevisionTransition::ApplyFailed
            .apply_to(RevisionStatus::Active)
            .expect_err("Active → Rejected is not allowed");
        assert!(matches!(
            err,
            TransitionError::InvalidTransition {
                from: RevisionStatus::Active,
                transition: RevisionTransition::ApplyFailed,
            }
        ));

        // Active cannot ApplySucceeded (it's already active).
        let err = RevisionTransition::ApplySucceeded
            .apply_to(RevisionStatus::Active)
            .expect_err("Active → Active via ApplySucceeded is not allowed");
        assert!(matches!(
            err,
            TransitionError::InvalidTransition {
                from: RevisionStatus::Active,
                transition: RevisionTransition::ApplySucceeded,
            }
        ));
    }
}
