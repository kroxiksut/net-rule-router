use super::*;

// ── RevisionId ────────────────────────────────────────────────────────────

#[test]
fn revision_id_accepts_valid_prefixed_string() {
    let id =
        RevisionId::from_prefixed_string("rev-550e8400-e29b-41d4-a716-446655440000".to_string());
    assert!(id.is_ok());
    let id = id.unwrap_or_else(|e| panic!("expected Ok: {e}"));
    assert_eq!(id.as_str(), "rev-550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(id.uuid_part(), "550e8400-e29b-41d4-a716-446655440000");
}

#[test]
fn revision_id_rejects_missing_prefix() {
    assert!(
        RevisionId::from_prefixed_string("550e8400-e29b-41d4-a716-446655440000".to_string())
            .is_err()
    );
}

#[test]
fn revision_id_rejects_prefix_only() {
    assert!(RevisionId::from_prefixed_string("rev-".to_string()).is_err());
}

#[test]
fn revision_id_display_equals_full_string() {
    let id = RevisionId::from_prefixed_string("rev-abc-123".to_string())
        .unwrap_or_else(|e| panic!("expected Ok: {e}"));
    assert_eq!(id.to_string(), "rev-abc-123");
}

// ── RevisionSeq ───────────────────────────────────────────────────────────

#[test]
fn revision_seq_first_is_one() {
    assert_eq!(RevisionSeq::FIRST.value(), 1);
}

#[test]
fn revision_seq_rejects_zero() {
    assert!(RevisionSeq::new(0).is_err());
}

#[test]
fn revision_seq_next_increments_by_one() {
    let seq = RevisionSeq::FIRST;
    let next = seq.next().unwrap_or_else(|| panic!("overflow on seq 1"));
    assert_eq!(next.value(), 2);
    assert!(next > seq);
}

#[test]
fn revision_seq_ordering_is_monotonic() {
    let a = RevisionSeq::new(1).unwrap_or_else(|e| panic!("{e}"));
    let b = RevisionSeq::new(5).unwrap_or_else(|e| panic!("{e}"));
    let c = RevisionSeq::new(5).unwrap_or_else(|e| panic!("{e}"));
    assert!(a < b);
    assert_eq!(b, c);
}

// ── ContentHash ───────────────────────────────────────────────────────────

#[test]
fn content_hash_roundtrip_via_hex() {
    let bytes = [0xabu8; 32];
    let hash = ContentHash::from_bytes(bytes);
    let hex = hash.to_hex_string();
    assert_eq!(hex.len(), 64);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    let parsed =
        ContentHash::from_hex_string(&hex).unwrap_or_else(|e| panic!("hex roundtrip failed: {e}"));
    assert_eq!(hash, parsed);
}

#[test]
fn content_hash_rejects_wrong_length() {
    assert!(ContentHash::from_hex_string("ab").is_err());
    assert!(ContentHash::from_hex_string(&"ab".repeat(33)).is_err());
}

#[test]
fn content_hash_rejects_invalid_hex_chars() {
    let invalid = "zz".repeat(32);
    assert!(ContentHash::from_hex_string(&invalid).is_err());
}

#[test]
fn content_hash_accepts_uppercase_hex() {
    let upper = "AB".repeat(32);
    assert!(ContentHash::from_hex_string(&upper).is_ok());
}

#[test]
fn content_hash_all_zeros_is_valid() {
    let hash = ContentHash::from_bytes([0u8; 32]);
    assert_eq!(hash.to_hex_string(), "0".repeat(64));
}

// ── UnixTimestamp ─────────────────────────────────────────────────────────

#[test]
fn unix_timestamp_roundtrips() {
    let ts = UnixTimestamp::from_secs(1_700_000_000);
    assert_eq!(ts.as_secs(), 1_700_000_000);
    assert_eq!(ts.to_string(), "1700000000");
}

#[test]
fn unix_timestamp_ordering_is_chronological() {
    let earlier = UnixTimestamp::from_secs(100);
    let later = UnixTimestamp::from_secs(200);
    assert!(earlier < later);
}

// ── ImportedArtifact ──────────────────────────────────────────────────────

#[test]
fn imported_artifact_snapshot_channel_is_default_mode() {
    let artifact = ImportedArtifact {
        source_path: "C:/Users/user/Downloads/preset.yaml".to_string(),
        file_hash: ContentHash::from_bytes([0x01u8; 32]),
        imported_at: UnixTimestamp::from_secs(1_700_000_000),
        channel: ImportChannel::Snapshot,
    };
    assert_eq!(artifact.channel, ImportChannel::Snapshot);
    assert!(!artifact.source_path.is_empty());
}

#[test]
fn linked_channel_is_reserved_and_distinct_from_snapshot() {
    assert_ne!(ImportChannel::Snapshot, ImportChannel::Linked);
}

// ── CanonicalProfile linkage ───────────────────────────────────────────────
//
// CanonicalProfile is defined in crate::canonical and imported
// here via `pub use`. This test verifies that the type is accessible from
// the revision module and can be constructed, which confirms the import path.

#[test]
fn canonical_profile_is_accessible_from_revision_module() {
    use crate::{canonical::CanonicalRuleBook, AdapterIdentity, RouteBinding};
    use nrr_shared::{BindingSource, RouteBehaviorMode, RouteRole};

    let profile = CanonicalProfile {
        primary: RouteBinding {
            role: RouteRole::Primary,
            adapter: AdapterIdentity {
                stable_id: "eth0".to_string(),
                display_name: "Ethernet".to_string(),
            },
            source: BindingSource::UserAssigned,
        },
        secondary: None,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        rule_book: CanonicalRuleBook::default(),
    };
    assert!(profile.secondary.is_none());
    assert_eq!(profile.primary.adapter.stable_id, "eth0");
}

// ── RiskLevel ─────────────────────────────────────────────────────────────

#[test]
fn risk_level_ordering_low_lt_medium_lt_high() {
    assert!(RiskLevel::Low < RiskLevel::Medium);
    assert!(RiskLevel::Medium < RiskLevel::High);
    assert!(RiskLevel::Low < RiskLevel::High);
}

#[test]
fn risk_level_display_is_lowercase_slug() {
    assert_eq!(RiskLevel::Low.to_string(), "low");
    assert_eq!(RiskLevel::Medium.to_string(), "medium");
    assert_eq!(RiskLevel::High.to_string(), "high");
}

#[test]
fn risk_level_equality_is_reflexive() {
    assert_eq!(RiskLevel::High, RiskLevel::High);
    assert_ne!(RiskLevel::Low, RiskLevel::High);
}

// ── IntegrityStatus ───────────────────────────────────────────────────────

#[test]
fn integrity_status_variants_are_distinct() {
    assert_ne!(IntegrityStatus::Unverified, IntegrityStatus::Verified);
    assert_ne!(IntegrityStatus::Verified, IntegrityStatus::Tampered);
    assert_ne!(IntegrityStatus::Unverified, IntegrityStatus::Tampered);
}

// ── RevisionDiffSummary ───────────────────────────────────────────────────

#[test]
fn revision_diff_summary_is_empty_when_all_zero() {
    let diff = RevisionDiffSummary {
        changed_interface_bindings: false,
        changed_default_behavior: false,
        changed_rules: false,
        rules_added: 0,
        rules_removed: 0,
        rules_modified: 0,
    };
    assert!(diff.is_empty());
}

#[test]
fn revision_diff_summary_not_empty_when_binding_changed() {
    let diff = RevisionDiffSummary {
        changed_interface_bindings: true,
        changed_default_behavior: false,
        changed_rules: false,
        rules_added: 0,
        rules_removed: 0,
        rules_modified: 0,
    };
    assert!(!diff.is_empty());
}

#[test]
fn revision_diff_summary_not_empty_when_rules_added() {
    let diff = RevisionDiffSummary {
        changed_interface_bindings: false,
        changed_default_behavior: false,
        changed_rules: true,
        rules_added: 3,
        rules_removed: 0,
        rules_modified: 0,
    };
    assert!(!diff.is_empty());
}

// ── RevisionSource ────────────────────────────────────────────────────────

#[test]
fn revision_source_import_carries_artifact() {
    let artifact = ImportedArtifact {
        source_path: "preset.yaml".to_string(),
        file_hash: ContentHash::from_bytes([0xffu8; 32]),
        imported_at: UnixTimestamp::from_secs(1_700_000_000),
        channel: ImportChannel::Snapshot,
    };
    let source = RevisionSource::Import(artifact.clone());
    match source {
        RevisionSource::Import(a) => assert_eq!(a.source_path, "preset.yaml"),
        _ => panic!("expected Import variant"),
    }
}

#[test]
fn revision_source_direct_edit_and_file_sync_are_distinct() {
    assert_ne!(RevisionSource::DirectEdit, RevisionSource::FileSync);
}

// ── RevisionActor ─────────────────────────────────────────────────────────

#[test]
fn revision_actor_variants_are_distinct() {
    assert_ne!(RevisionActor::LocalUser, RevisionActor::Service);
}

// ── AuditEventId ─────────────────────────────────────────────────────────

#[test]
fn audit_event_id_accepts_valid_prefixed_string() {
    let id =
        AuditEventId::from_prefixed_string("evt-550e8400-e29b-41d4-a716-446655440000".to_string());
    assert!(id.is_ok());
    let id = id.unwrap_or_else(|e| panic!("expected Ok: {e}"));
    assert_eq!(id.as_str(), "evt-550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(id.to_string(), "evt-550e8400-e29b-41d4-a716-446655440000");
}

#[test]
fn audit_event_id_rejects_missing_prefix() {
    assert!(AuditEventId::from_prefixed_string("some-id".to_string()).is_err());
}

#[test]
fn audit_event_id_rejects_prefix_only() {
    assert!(AuditEventId::from_prefixed_string("evt-".to_string()).is_err());
}

// ── PolicyRevision ────────────────────────────────────────────────────────

fn make_test_profile() -> CanonicalProfile {
    use crate::{canonical::CanonicalRuleBook, AdapterIdentity, RouteBinding};
    use nrr_shared::{BindingSource, RouteBehaviorMode, RouteRole};
    CanonicalProfile {
        primary: RouteBinding {
            role: RouteRole::Primary,
            adapter: AdapterIdentity {
                stable_id: "eth0".to_string(),
                display_name: "Ethernet".to_string(),
            },
            source: BindingSource::UserAssigned,
        },
        secondary: None,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        rule_book: CanonicalRuleBook::default(),
    }
}

fn make_test_revision(id: &str, seq: u64) -> PolicyRevision {
    PolicyRevision {
        id: RevisionId::from_prefixed_string(id.to_string()).unwrap_or_else(|e| panic!("{e}")),
        seq: RevisionSeq::new(seq).unwrap_or_else(|e| panic!("{e}")),
        created_at: UnixTimestamp::from_secs(1_700_000_000 + seq),
        source: RevisionSource::DirectEdit,
        actor: RevisionActor::LocalUser,
        content: make_test_profile(),
        content_hash: ContentHash::from_bytes([seq as u8; 32]),
        diff_summary: None,
        risk_level: RiskLevel::Low,
        integrity_status: IntegrityStatus::Unverified,
    }
}

#[test]
fn policy_revision_fields_are_accessible() {
    let rev = make_test_revision("rev-abc-001", 1);
    assert_eq!(rev.id.as_str(), "rev-abc-001");
    assert_eq!(rev.seq.value(), 1);
    assert_eq!(rev.risk_level, RiskLevel::Low);
    assert_eq!(rev.integrity_status, IntegrityStatus::Unverified);
    assert_eq!(rev.actor, RevisionActor::LocalUser);
    assert!(rev.diff_summary.is_none());
}

#[test]
fn policy_revision_with_diff_summary() {
    let mut rev = make_test_revision("rev-abc-002", 2);
    rev.diff_summary = Some(RevisionDiffSummary {
        changed_interface_bindings: false,
        changed_default_behavior: false,
        changed_rules: true,
        rules_added: 1,
        rules_removed: 0,
        rules_modified: 0,
    });
    let diff = rev
        .diff_summary
        .as_ref()
        .unwrap_or_else(|| panic!("expected Some"));
    assert!(!diff.is_empty());
    assert_eq!(diff.rules_added, 1);
}

// ── PendingRevision ───────────────────────────────────────────────────────

#[test]
fn pending_revision_no_displaced_id_when_first_pending() {
    let pending = PendingRevision {
        candidate: make_test_revision("rev-p-001", 1),
        queued_at: UnixTimestamp::from_secs(1_700_000_100),
        displaced_revision_id: None,
    };
    assert!(pending.displaced_revision_id.is_none());
    assert_eq!(pending.candidate.seq.value(), 1);
}

#[test]
fn pending_revision_records_displaced_id_on_supersession() {
    let old_id = RevisionId::from_prefixed_string("rev-old-001".to_string())
        .unwrap_or_else(|e| panic!("{e}"));
    let pending = PendingRevision {
        candidate: make_test_revision("rev-new-002", 2),
        queued_at: UnixTimestamp::from_secs(1_700_000_200),
        displaced_revision_id: Some(old_id.clone()),
    };
    let displaced = pending
        .displaced_revision_id
        .as_ref()
        .unwrap_or_else(|| panic!("expected Some"));
    assert_eq!(displaced.as_str(), "rev-old-001");
}

// ── ActiveRevision ────────────────────────────────────────────────────────

#[test]
fn active_revision_wraps_policy_revision_with_activation_time() {
    let rev = make_test_revision("rev-act-001", 1);
    let activated_at = UnixTimestamp::from_secs(1_700_001_000);
    let active = ActiveRevision {
        revision: rev.clone(),
        activated_at,
    };
    assert_eq!(active.revision.id.as_str(), "rev-act-001");
    assert_eq!(active.activated_at.as_secs(), 1_700_001_000);
}

// ── LastKnownGoodRevision ─────────────────────────────────────────────────

#[test]
fn last_known_good_wraps_revision_with_confirmation_time() {
    let rev = make_test_revision("rev-lkg-001", 1);
    let confirmed_at = UnixTimestamp::from_secs(1_700_002_000);
    let lkg = LastKnownGoodRevision {
        revision: rev.clone(),
        confirmed_at,
    };
    assert_eq!(lkg.revision.seq.value(), 1);
    assert_eq!(lkg.confirmed_at.as_secs(), 1_700_002_000);
}

// ── AuditEvent / AuditEventKind ───────────────────────────────────────────

#[test]
fn audit_event_activation_kind_carries_revision_id() {
    let rev_id = RevisionId::from_prefixed_string("rev-act-007".to_string())
        .unwrap_or_else(|e| panic!("{e}"));
    let kind = AuditEventKind::Activation {
        revision_id: rev_id.clone(),
    };
    match kind {
        AuditEventKind::Activation { revision_id } => {
            assert_eq!(revision_id.as_str(), "rev-act-007");
        }
        _ => panic!("expected Activation variant"),
    }
}

#[test]
fn audit_event_rejection_carries_reason() {
    let rev_id = RevisionId::from_prefixed_string("rev-rej-001".to_string())
        .unwrap_or_else(|e| panic!("{e}"));
    let kind = AuditEventKind::Rejection {
        revision_id: rev_id,
        reason: RejectionReason::UserRejected,
    };
    match kind {
        AuditEventKind::Rejection { reason, .. } => {
            assert_eq!(reason, RejectionReason::UserRejected);
        }
        _ => panic!("expected Rejection variant"),
    }
}

#[test]
fn audit_event_rollback_records_both_revision_ids() {
    let from = RevisionId::from_prefixed_string("rev-from-001".to_string())
        .unwrap_or_else(|e| panic!("{e}"));
    let to = RevisionId::from_prefixed_string("rev-to-002".to_string())
        .unwrap_or_else(|e| panic!("{e}"));
    let kind = AuditEventKind::Rollback {
        from_revision_id: from,
        to_revision_id: to,
    };
    match kind {
        AuditEventKind::Rollback {
            from_revision_id,
            to_revision_id,
        } => {
            assert_eq!(from_revision_id.as_str(), "rev-from-001");
            assert_eq!(to_revision_id.as_str(), "rev-to-002");
        }
        _ => panic!("expected Rollback variant"),
    }
}

#[test]
fn audit_event_pending_superseded_records_both_seqs() {
    let old_id = RevisionId::from_prefixed_string("rev-old-001".to_string())
        .unwrap_or_else(|e| panic!("{e}"));
    let new_seq = RevisionSeq::new(5).unwrap_or_else(|e| panic!("{e}"));
    let kind = AuditEventKind::PendingSuperseded {
        old_revision_id: old_id,
        new_candidate_seq: new_seq,
    };
    match kind {
        AuditEventKind::PendingSuperseded {
            old_revision_id,
            new_candidate_seq,
        } => {
            assert_eq!(old_revision_id.as_str(), "rev-old-001");
            assert_eq!(new_candidate_seq.value(), 5);
        }
        _ => panic!("expected PendingSuperseded variant"),
    }
}

#[test]
fn audit_event_tamper_alert_carries_hash_pair() {
    let rev_id = RevisionId::from_prefixed_string("rev-tamper-001".to_string())
        .unwrap_or_else(|e| panic!("{e}"));
    let stored = ContentHash::from_bytes([0xaau8; 32]);
    let detected = ContentHash::from_bytes([0xbbu8; 32]);
    let kind = AuditEventKind::TamperAlert {
        revision_id: rev_id,
        detected_hash: detected.clone(),
        stored_hash: stored.clone(),
    };
    match kind {
        AuditEventKind::TamperAlert {
            detected_hash,
            stored_hash,
            ..
        } => {
            assert_ne!(detected_hash, stored_hash);
        }
        _ => panic!("expected TamperAlert variant"),
    }
}

#[test]
fn full_audit_event_struct_is_constructible() {
    let event = AuditEvent {
        id: AuditEventId::from_prefixed_string("evt-abc-001".to_string())
            .unwrap_or_else(|e| panic!("{e}")),
        timestamp: UnixTimestamp::from_secs(1_700_000_000),
        revision_id: Some(
            RevisionId::from_prefixed_string("rev-abc-001".to_string())
                .unwrap_or_else(|e| panic!("{e}")),
        ),
        actor: RevisionActor::LocalUser,
        kind: AuditEventKind::Activation {
            revision_id: RevisionId::from_prefixed_string("rev-abc-001".to_string())
                .unwrap_or_else(|e| panic!("{e}")),
        },
    };
    assert_eq!(event.id.as_str(), "evt-abc-001");
    assert_eq!(event.actor, RevisionActor::LocalUser);
    assert!(event.revision_id.is_some());
}

#[test]
fn audit_event_integrity_failure_has_no_revision_id() {
    let event = AuditEvent {
        id: AuditEventId::from_prefixed_string("evt-fail-001".to_string())
            .unwrap_or_else(|e| panic!("{e}")),
        timestamp: UnixTimestamp::from_secs(1_700_000_001),
        revision_id: None,
        actor: RevisionActor::Service,
        kind: AuditEventKind::IntegrityFailure {
            detail: "revision record unreadable".to_string(),
        },
    };
    assert!(event.revision_id.is_none());
    assert_eq!(event.actor, RevisionActor::Service);
}

// ── State machine ──────────────────────────────────────────────────────────

#[test]
fn pending_can_transition_to_active_and_rejected() {
    assert!(RevisionState::Pending.can_transition_to(RevisionState::Active));
    assert!(RevisionState::Pending.can_transition_to(RevisionState::Rejected));
}

#[test]
fn active_can_transition_to_superseded_and_rolled_back() {
    assert!(RevisionState::Active.can_transition_to(RevisionState::Superseded));
    assert!(RevisionState::Active.can_transition_to(RevisionState::RolledBack));
}

#[test]
fn invalid_transitions_are_rejected() {
    // Pending cannot jump to Superseded or RolledBack
    assert!(!RevisionState::Pending.can_transition_to(RevisionState::Superseded));
    assert!(!RevisionState::Pending.can_transition_to(RevisionState::RolledBack));
    // Active cannot go directly to Rejected
    assert!(!RevisionState::Active.can_transition_to(RevisionState::Rejected));
    // Active cannot transition to itself
    assert!(!RevisionState::Active.can_transition_to(RevisionState::Active));
    // Pending cannot transition to itself
    assert!(!RevisionState::Pending.can_transition_to(RevisionState::Pending));
}

#[test]
fn terminal_states_have_no_valid_transitions() {
    let terminals = [
        RevisionState::Superseded,
        RevisionState::Rejected,
        RevisionState::RolledBack,
    ];
    let all_states = [
        RevisionState::Pending,
        RevisionState::Active,
        RevisionState::Superseded,
        RevisionState::Rejected,
        RevisionState::RolledBack,
    ];
    for terminal in terminals {
        assert!(terminal.is_terminal(), "{terminal:?} should be terminal");
        for next in all_states {
            assert!(
                !terminal.can_transition_to(next),
                "{terminal:?} → {next:?} must be invalid"
            );
        }
    }
}

#[test]
fn non_terminal_states_are_pending_and_active() {
    assert!(!RevisionState::Pending.is_terminal());
    assert!(!RevisionState::Active.is_terminal());
}

// ── Rollback outcome model ─────────────────────────────────────────────────

// Scenario: normal apply flow (Pending → Active)
#[test]
fn rollback_success_carries_new_revision_identity() {
    let outcome = RollbackOutcome::Success {
        new_revision_id: RevisionId::from_prefixed_string("rev-rollback-001".to_string())
            .unwrap_or_else(|e| panic!("{e}")),
        new_seq: RevisionSeq::new(5).unwrap_or_else(|e| panic!("{e}")),
    };
    match outcome {
        RollbackOutcome::Success {
            new_revision_id,
            new_seq,
        } => {
            assert_eq!(new_revision_id.as_str(), "rev-rollback-001");
            assert_eq!(new_seq.value(), 5);
        }
        RollbackOutcome::Blocked(_) => panic!("expected Success"),
    }
}

// Scenario: rollback blocked — no last known good
#[test]
fn rollback_blocked_no_last_known_good() {
    let outcome = RollbackOutcome::Blocked(RollbackBlockedReason::NoLastKnownGood);
    match outcome {
        RollbackOutcome::Blocked(reason) => {
            assert_eq!(reason, RollbackBlockedReason::NoLastKnownGood);
        }
        RollbackOutcome::Success { .. } => panic!("expected Blocked"),
    }
}

// Scenario: rollback blocked — last known good is already active
#[test]
fn rollback_blocked_already_active() {
    let outcome = RollbackOutcome::Blocked(RollbackBlockedReason::LastKnownGoodIsAlreadyActive);
    assert_eq!(
        outcome,
        RollbackOutcome::Blocked(RollbackBlockedReason::LastKnownGoodIsAlreadyActive)
    );
}

// Scenario: rollback blocked — integrity check failed on last known good
#[test]
fn rollback_blocked_integrity_check_failed() {
    let outcome = RollbackOutcome::Blocked(RollbackBlockedReason::IntegrityCheckFailed);
    assert_eq!(
        outcome,
        RollbackOutcome::Blocked(RollbackBlockedReason::IntegrityCheckFailed)
    );
}

// Scenario: new import displaces existing pending (PendingSuperseded audit event)
#[test]
fn pending_superseded_audit_event_scenario() {
    let old_id = RevisionId::from_prefixed_string("rev-old-pending-001".to_string())
        .unwrap_or_else(|e| panic!("{e}"));
    let new_seq = RevisionSeq::new(3).unwrap_or_else(|e| panic!("{e}"));
    // Old pending transitions to Rejected (with SupersededByNewerImport reason)
    assert!(RevisionState::Pending.can_transition_to(RevisionState::Rejected));
    // Audit event type is PendingSuperseded
    let kind = AuditEventKind::PendingSuperseded {
        old_revision_id: old_id,
        new_candidate_seq: new_seq,
    };
    match kind {
        AuditEventKind::PendingSuperseded {
            new_candidate_seq, ..
        } => {
            assert_eq!(new_candidate_seq.value(), 3);
        }
        _ => panic!("expected PendingSuperseded"),
    }
}

// Scenario: integrity check failure on active revision triggers TamperAlert
#[test]
fn integrity_failure_scenario_tamper_alert() {
    let rev_id = RevisionId::from_prefixed_string("rev-tampered-001".to_string())
        .unwrap_or_else(|e| panic!("{e}"));
    let stored = ContentHash::from_bytes([0x01u8; 32]);
    let detected = ContentHash::from_bytes([0x02u8; 32]);
    // Hashes differ → TamperAlert event
    assert_ne!(stored, detected);
    let event = AuditEvent {
        id: AuditEventId::from_prefixed_string("evt-tamper-001".to_string())
            .unwrap_or_else(|e| panic!("{e}")),
        timestamp: UnixTimestamp::from_secs(1_700_000_999),
        revision_id: Some(rev_id.clone()),
        actor: RevisionActor::Service,
        kind: AuditEventKind::TamperAlert {
            revision_id: rev_id,
            detected_hash: detected,
            stored_hash: stored,
        },
    };
    assert_eq!(event.actor, RevisionActor::Service);
    assert!(event.revision_id.is_some());
}
