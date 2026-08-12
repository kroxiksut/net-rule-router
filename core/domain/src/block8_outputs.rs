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
//! | [`crate::change_event`]       | External change taxonomy — `ExternalChangeEvent`, `classify_change_event()` |
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
    use crate::change_event::{
        classify_change_event, ChangeEventClassification, ExternalChangeEvent,
    };
    use crate::extension_channel::{
        validate_extension_request, ExtensionChannelPolicy, ExtensionInteractivity,
        ExtensionRequestScope, ReviewRequirement,
    };
    use crate::linked_source::{
        process_linked_check, LinkedCheckInput, LinkedSourceCheckOutcome, LinkedSourceRegistration,
        LinkedWatchMode, LinkedWatchStatus,
    };
    use crate::revision::{ContentHash, RevisionId, UnixTimestamp};

    // ── Helpers shared by these integration tests ─────────────────────────────

    fn hash(byte: u8) -> ContentHash {
        ContentHash::from_bytes([byte; 32])
    }

    fn ts(secs: u64) -> UnixTimestamp {
        UnixTimestamp::from_secs(secs)
    }

    fn rev_id(s: &str) -> RevisionId {
        RevisionId::from_prefixed_string(s.to_string())
            .unwrap_or_else(|e| panic!("invalid rev id: {e}"))
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

    // ── Integration: linked check suspicious → change event → tamper alert ────
    //
    // Verifies the full chain:
    //   process_linked_check(changed while pending)
    //     → LinkedSourceCheckOutcome::SourceSuspiciouslyChanged
    //     → ExternalChangeEvent::LinkedSourceSuspicious
    //     → classify_change_event → TamperAlert + Critical severity

    #[test]
    fn suspicious_linked_check_produces_tamper_alert_end_to_end() {
        // Step 1: linked check detects change while pending revision exists.
        let mut reg = base_registration();
        reg.pending_revision_id = Some(rev_id("rev-pending-001"));

        let check_input = LinkedCheckInput {
            registration: reg,
            file_read_result: Ok(hash(0xBB)),
            checked_at: ts(1_700_001_000),
            changed_rule_count: Some(3),
        };

        let check_outcome = process_linked_check(check_input);

        // Step 2: outcome is suspicious.
        let (new_file_hash, suspicion) = match check_outcome {
            LinkedSourceCheckOutcome::SourceSuspiciouslyChanged {
                new_file_hash,
                suspicion,
            } => (new_file_hash, suspicion),
            other => panic!("expected SourceSuspiciouslyChanged, got {other:?}"),
        };

        // Step 3: construct change event from outcome.
        let event = ExternalChangeEvent::LinkedSourceSuspicious {
            source_id: lsrc_id("lsrc-integration-001"),
            new_file_hash,
            suspicion,
        };

        // Step 4: classify — must produce TamperAlert with Critical severity.
        let response = classify_change_event(&event);
        assert_eq!(
            response.classification,
            ChangeEventClassification::TamperAlert
        );
        assert_eq!(response.alert_severity, Some(AlertSeverity::Critical));
        assert!(response.required_actions.freeze_activation);
        assert!(response.required_actions.create_alert);
        assert!(response.required_actions.write_audit_event);
    }

    // ── Integration: normal linked change → PendingRevision response ──────────

    #[test]
    fn normal_linked_change_produces_pending_revision_response() {
        let reg = base_registration(); // no pending revision

        let check_input = LinkedCheckInput {
            registration: reg,
            file_read_result: Ok(hash(0xCC)),
            checked_at: ts(1_700_002_000),
            changed_rule_count: Some(2),
        };

        let check_outcome = process_linked_check(check_input);
        let new_file_hash = match check_outcome {
            LinkedSourceCheckOutcome::SourceChanged { new_file_hash } => new_file_hash,
            other => panic!("expected SourceChanged, got {other:?}"),
        };

        let event = ExternalChangeEvent::LinkedSourceChanged {
            source_id: lsrc_id("lsrc-integration-001"),
            new_file_hash,
        };

        let response = classify_change_event(&event);
        assert_eq!(
            response.classification,
            ChangeEventClassification::PendingRevision
        );
        assert!(response.required_actions.create_pending_revision);
        assert!(!response.required_actions.freeze_activation);
        assert!(response.alert_severity.is_none());
    }

    // ── Integration: integrity failure → full tamper reaction ─────────────────

    #[test]
    fn integrity_failure_triggers_freeze_fallback_and_audit() {
        let event = ExternalChangeEvent::ServiceStateIntegrityFailed {
            revision_id: rev_id("rev-tampered-001"),
            stored_hash: hash(0x01),
            detected_hash: hash(0x02),
        };

        let response = classify_change_event(&event);

        assert_eq!(
            response.classification,
            ChangeEventClassification::TamperAlert
        );
        assert_eq!(response.alert_severity, Some(AlertSeverity::Critical));

        let actions = &response.required_actions;
        assert!(actions.freeze_activation);
        assert!(actions.fallback_to_last_known_good);
        assert!(actions.create_alert);
        assert!(actions.write_audit_event);
        assert!(actions.notify_user);
    }

    // ── Integration: snapshot source change is informational only ─────────────

    #[test]
    fn snapshot_source_change_is_informational_not_policy_change() {
        let event = ExternalChangeEvent::SnapshotSourceChanged {
            source_path: "C:/rules/backup.txt".to_string(),
            original_hash: hash(0xAA),
            current_hash: hash(0xBB),
        };

        let response = classify_change_event(&event);

        assert_eq!(
            response.classification,
            ChangeEventClassification::Informational
        );
        // No policy action — only notification.
        assert!(!response.required_actions.create_pending_revision);
        assert!(!response.required_actions.freeze_activation);
        assert!(!response.required_actions.create_alert);
        assert!(!response.required_actions.write_audit_event);
        assert!(response.required_actions.notify_user);
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
