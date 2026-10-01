use nrr_shared::{gui_shell_v1, VisibilityScope};

#[test]
fn security_visibility_policy_marks_global_and_screen_only_indicators() {
    let shell = gui_shell_v1();
    assert!(shell.security_visibility.rules.iter().any(|rule| {
        rule.indicator.title() == "Tamper alerts"
            && matches!(rule.scope, VisibilityScope::AlwaysVisible)
    }));
    assert!(shell.security_visibility.rules.iter().any(|rule| {
        rule.indicator.title() == "Explain warnings"
            && matches!(rule.scope, VisibilityScope::ScreenOnly)
    }));
}

/// Anything that puts sensitive data on disk must leave a record that it
/// happened. The archive export was classified read-only, so it skipped the
/// pre-execution audit write entirely.
#[test]
fn writing_a_diagnostic_archive_is_an_audited_action() {
    use nrr_shared::ipc::IpcOperationName;
    use nrr_shared::ipc_transport::canonical_operation_class;

    let empty = serde_json::json!({});
    let class = canonical_operation_class(IpcOperationName::DiagnosticsExportArchive, &empty);
    assert!(
        class.is_mutating(),
        "an export that writes unredacted hosts and addresses to a file must be audited"
    );
    assert!(
        !class.requires_elevation() && !class.requires_confirmation_token(),
        "auditing it must not turn a support export into a UAC prompt"
    );
    assert_eq!(
        class,
        canonical_operation_class(IpcOperationName::LogsClear, &empty),
        "an export is diagnostic maintenance, like clearing the logs"
    );
}

/// The acknowledgement echoes back exactly the rows the dry-run listed; the
/// wire names and the "absent means adopt nothing" reading are the contract
/// both ends rely on.
#[test]
fn an_alert_acknowledgement_carries_the_rows_it_was_shown() {
    use nrr_shared::ipc_payloads::{
        IntegrityRowKind, IntegrityRowRef, SecurityAlertMutationPayload,
    };

    let bare: SecurityAlertMutationPayload =
        serde_json::from_value(serde_json::json!({ "alert-id": "alt-1" })).expect("bare ack");
    assert!(
        bare.adopt_rows.is_none(),
        "an old client's ack must read as adopting nothing"
    );
    assert!(
        !serde_json::to_value(&bare)
            .expect("serialise")
            .as_object()
            .expect("object")
            .contains_key("adopt-rows"),
        "no list is not an empty list"
    );

    let wire = serde_json::json!({
        "alert-id": "alt-1",
        "adopt-rows": [{
            "row-kind": "active-pointer",
            "principal": "S-1-5-21-1-2-3-1001",
            "revision-id": "rev-1",
            "content-hash": "ab12",
        }],
    });
    let parsed: SecurityAlertMutationPayload =
        serde_json::from_value(wire.clone()).expect("ack with rows");
    assert_eq!(
        parsed.adopt_rows,
        Some(vec![IntegrityRowRef {
            row_kind: IntegrityRowKind::ActivePointer,
            principal: "S-1-5-21-1-2-3-1001".into(),
            revision_id: "rev-1".into(),
            content_hash: "ab12".into(),
        }])
    );
    assert_eq!(serde_json::to_value(&parsed).expect("serialise"), wire);
}

/// The dry-run lists each row flat, so the dialog reads the reference and its
/// description from one object and sends the reference back unchanged.
#[test]
fn a_dry_run_lists_unverified_rows_flat_and_omits_an_empty_list() {
    use nrr_shared::ipc_payloads::{
        IntegrityRowKind, IntegrityRowRef, MutationDryRunResponse, ReviewRiskLevel,
        ReviewSummaryResponse, UnverifiedRowDto,
    };

    let mut resp = MutationDryRunResponse {
        review_summary: ReviewSummaryResponse {
            diff_summary: String::new(),
            provenance: "service".into(),
            risk_level: ReviewRiskLevel::Low,
            requires_review: true,
            changed_fields: Vec::new(),
            risk_signals: Vec::new(),
            rules_added: Vec::new(),
            rules_removed: Vec::new(),
            rules_modified: Vec::new(),
            rules_retargeted: Vec::new(),
            extended_sections: Vec::new(),
            cross_set_duplicates: Vec::new(),
        },
        confirmation_token: "tok".into(),
        review_risk_level: ReviewRiskLevel::Low,
        unverified_rows: Vec::new(),
        audit_chain: None,
    };
    let empty = serde_json::to_value(&resp).expect("serialise");
    assert!(!empty
        .as_object()
        .expect("object")
        .contains_key("unverified-rows"));

    resp.unverified_rows.push(UnverifiedRowDto {
        row: IntegrityRowRef {
            row_kind: IntegrityRowKind::Revision,
            principal: "__baseline__".into(),
            revision_id: "rev-1".into(),
            content_hash: "cd34".into(),
        },
        baseline: true,
        created_at: 1_700_000_000,
        source: Some("preset-import".into()),
        status: Some("active".into()),
        rule_count: Some(3),
    });
    let wire = serde_json::to_value(&resp).expect("serialise");
    assert_eq!(
        wire["unverified-rows"][0],
        serde_json::json!({
            "row-kind": "revision",
            "principal": "__baseline__",
            "revision-id": "rev-1",
            "content-hash": "cd34",
            "baseline": true,
            "created-at": 1_700_000_000,
            "source": "preset-import",
            "status": "active",
            "rule-count": 3,
        })
    );
    let back: MutationDryRunResponse = serde_json::from_value(wire).expect("round trip");
    assert_eq!(back.unverified_rows, resp.unverified_rows);
}
