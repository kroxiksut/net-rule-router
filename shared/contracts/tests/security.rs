use nrr_shared::{format_security_visibility_summary, gui_shell_v1, VisibilityScope};

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

    let summary = format_security_visibility_summary(&shell);
    assert!(summary.contains("always="));
    assert!(summary.contains("screen-only="));
}

/// Anything that puts sensitive data on disk must leave a record that it
/// happened. The archive export was classified read-only, so it skipped the
/// pre-execution audit write entirely — while `DiagnosticModeSet`, which lifts
/// the same redaction for on-screen viewers only, was audited.
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
        canonical_operation_class(IpcOperationName::DiagnosticModeSet, &empty),
        "the two operations lift the same redaction and belong in the same class"
    );
}
