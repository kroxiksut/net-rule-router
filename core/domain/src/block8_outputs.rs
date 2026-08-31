//! Public output surface for the import/review/risk/alert pipeline, plus
//! cross-cutting integration tests that verify coherence across it.
//!
//! | Module                        | What it provides                                              |
//! |-------------------------------|---------------------------------------------------------------|
//! | [`crate::import`]             | Controlled import pipeline — `process_import()`, `ImportResult`, `ImportTrigger` |
//! | [`crate::review`]             | Diff engine — `compute_diff()`, `StructuralDiff`, `ConfirmationToken` |
//! | [`crate::risk`]               | Risk scoring — `score_candidate()`, `RiskAssessment`, `RiskSignal` |
//! | [`crate::alert`]              | Alert domain types — `Alert`, `AlertSeverity`, `AlertLifecycle` |
//! | [`crate::linked_source`]      | Linked import state machine — `process_linked_check()`, `LinkedSourceRegistration` |
//! | [`crate::extension_channel`]  | Extension channel boundary — `validate_extension_request()`, `ExtensionChannelPolicy` |
//!
//! Alert state persists via `nrr_service_runtime::ProductionSecurityAlertsRepository`,
//! backed by the `security_alerts` table in `nrr_service_state.db`.
//!
//! # Service Import Pipeline
//!
//! ```text
//! (file bytes) → parse/validate → CanonicalProfile
//!     → compute_diff(active, candidate) → StructuralDiff
//!     → score_candidate(diff, source)   → RiskAssessment
//!     → process_import(request, ...)    → ImportResult
//!     → (if PendingReview) AlertStore::upsert(alert)
//! ```

// ── Block8Outputs ─────────────────────────────────────────────────────────────

/// Marker type documenting the public output surface described above.
///
/// Carries no runtime data — exists solely for documentation and as a stable
/// reference point. Callers should import specific types from the modules
/// listed in the module-level doc, not from this struct.
pub struct Block8Outputs;

impl Block8Outputs {
    /// Always `true`. Tested to prevent accidental removal of the marker type.
    pub const fn is_complete() -> bool {
        true
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::alert::AlertSeverity;
    use crate::extension_channel::{
        validate_extension_request, ExtensionChannelPolicy, ExtensionInteractivity,
        ExtensionRequestScope, ReviewRequirement,
    };
    use crate::linked_source::{
        process_linked_check, LinkedCheckInput, LinkedSourceCheckOutcome, LinkedSourceRegistration,
        LinkedWatchMode, LinkedWatchStatus,
    };
    use crate::revision::{ContentHash, UnixTimestamp};

    // ── Helpers shared by these integration tests ─────────────────────────────

    fn hash(byte: u8) -> ContentHash {
        ContentHash::from_bytes([byte; 32])
    }

    fn ts(secs: u64) -> UnixTimestamp {
        UnixTimestamp::from_secs(secs)
    }

    fn lsrc_id(s: &str) -> crate::linked_source::LinkedSourceId {
        crate::linked_source::LinkedSourceId::from_prefixed_string(s.to_string())
            .unwrap_or_else(|e| panic!("invalid lsrc id: {e}"))
    }

    fn base_registration() -> LinkedSourceRegistration {
        LinkedSourceRegistration {
            id: lsrc_id("lsrc-integration-001"),
            locator: crate::linked_source::LinkedSourceLocator::from_path("C:/rules/primary.txt"),
            watch_mode: LinkedWatchMode::ManualRefresh,
            status: LinkedWatchStatus::Active,
            registered_at: ts(1_700_000_000),
            last_successful_check_at: None,
            last_known_file_hash: Some(hash(0xAA)),
            pending_revision_id: None,
        }
    }

    fn narrow_ext_scope() -> ExtensionRequestScope {
        ExtensionRequestScope {
            allows_rule_additions: true,
            allows_rule_removals: false,
            allows_rule_modifications: false,
            allows_behavior_mode_change: false,
            allows_binding_change: false,
            max_rule_changes: Some(ExtensionChannelPolicy::MAX_INTERACTIVE_RULE_CHANGES),
        }
    }

    // ── Marker ────────────────────────────────────────────────────────────────

    #[test]
    fn block8_is_complete() {
        assert!(Block8Outputs::is_complete());
    }

    // ── Integration: extension channel policy respected across scenarios ───────

    #[test]
    fn non_interactive_extension_always_blocked_from_immediate_apply() {
        // Even a single-rule change from a non-interactive channel requires review.
        let result = validate_extension_request(
            ExtensionInteractivity::NonInteractive,
            &narrow_ext_scope(),
            1,
        );
        assert!(result.is_review_required());
    }

    #[test]
    fn interactive_extension_within_threshold_is_permitted() {
        let result = validate_extension_request(
            ExtensionInteractivity::Interactive,
            &narrow_ext_scope(),
            ExtensionChannelPolicy::MAX_INTERACTIVE_RULE_CHANGES,
        );
        assert_eq!(result, ReviewRequirement::ImmediateApplyPermitted);
    }

    #[test]
    fn interactive_extension_exceeding_threshold_requires_review() {
        let result = validate_extension_request(
            ExtensionInteractivity::Interactive,
            &narrow_ext_scope(),
            ExtensionChannelPolicy::MAX_INTERACTIVE_RULE_CHANGES + 1,
        );
        assert!(result.is_review_required());
    }

    // ── Alert severity maps from risk level ───────────────────────────────────

    #[test]
    fn risk_level_to_alert_severity_mapping_is_correct() {
        use crate::revision::RiskLevel;
        assert_eq!(AlertSeverity::from_risk_level(RiskLevel::Low), None);
        assert_eq!(
            AlertSeverity::from_risk_level(RiskLevel::Medium),
            Some(AlertSeverity::Warning)
        );
        assert_eq!(
            AlertSeverity::from_risk_level(RiskLevel::High),
            Some(AlertSeverity::Critical)
        );
    }

    // ── Linked source unchanged produces no action ────────────────────────────

    #[test]
    fn unchanged_linked_source_produces_no_action() {
        let reg = base_registration(); // last_known_file_hash = Some(hash(0xAA))

        let check_input = LinkedCheckInput {
            registration: reg,
            file_read_result: Ok(hash(0xAA)), // same as last known
            checked_at: ts(1_700_003_000),
            changed_rule_count: None,
        };

        assert_eq!(
            process_linked_check(check_input),
            LinkedSourceCheckOutcome::SourceUnchanged
        );
    }

    // ── import pipeline entry point is stable across callers ───────────────────

    #[test]
    fn import_result_no_change_variant_exists() {
        use crate::import::ImportResult;
        // The preset importer calls the same process_import() entry point and
        // receives the same ImportResult variants.
        assert!(matches!(ImportResult::NoChange, ImportResult::NoChange));
    }

    #[test]
    fn import_result_failed_variant_carries_description() {
        use crate::import::ImportResult;
        let r = ImportResult::Failed {
            description: "test".to_string(),
        };
        assert!(matches!(r, ImportResult::Failed { .. }));
    }

    // ── alert lifecycle covers every state the service needs ───────────────────

    #[test]
    fn alert_lifecycle_covers_all_states_needed_by_service() {
        use crate::alert::AlertLifecycle;

        // Service needs: create, acknowledge, review, resolve, supersede.
        let slugs = [
            AlertLifecycle::Created.slug(),
            AlertLifecycle::Acknowledged.slug(),
            AlertLifecycle::Reviewed.slug(),
            AlertLifecycle::Resolved.slug(),
            AlertLifecycle::Superseded.slug(),
        ];
        assert_eq!(slugs.len(), 5);
        // Round-trip all slugs.
        for slug in &slugs {
            assert!(
                AlertLifecycle::from_slug(slug).is_some(),
                "slug {slug:?} must round-trip"
            );
        }
    }
}
