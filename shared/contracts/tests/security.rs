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
