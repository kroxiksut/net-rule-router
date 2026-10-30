//! With rules and no additional connection, the window says why nothing is
//! routed. "Leak protection is blocking" is true only for a user whose saved
//! policy holds a level: a new user with nothing saved is not blocked by the
//! default level, and telling them so would send them to switch off
//! protection that holds nothing. The terminal reads the same from the policy.
#![allow(clippy::expect_used)]

#[path = "support/js.rs"]
mod js;
#[path = "support/qml_functions.rs"]
mod qml_functions;

const DECLARATION: &str = "readonly property bool policyInactiveKillSwitchBlocking:";

fn binding() -> String {
    let source = qml_functions::read("Main.qml");
    let start = source.find(DECLARATION).expect("declaration present") + DECLARATION.len();
    // The rest of the declaration line, then the binding's continuation lines.
    let mut lines = source[start..].lines();
    let first = lines.next().unwrap_or_default();
    std::iter::once(first)
        .chain(
            lines
                .take_while(|line| !line.trim().is_empty() && !line.trim_start().starts_with("//")),
        )
        .collect::<Vec<_>>()
        .join("\n")
}

/// The banner's reading for a service policy (`null`: none saved).
fn blames_protection(service_policy: &str) -> String {
    js::run_js(&format!(
        "{}\n\
         var policyInactiveBannerVisible = true, _policyIdlePrefsHaveSecondary = false;\n\
         var uiRevision = 0;\n\
         var _serviceRoutePolicy = {service_policy};\n\
         var routingState = {{ leakProtection: Pure.routePolicyEffective(_serviceRoutePolicy || {{}}, 'leak-protection') }};\n\
         console.log({});",
        qml_functions::pure(),
        binding()
    ))
}

#[test]
fn a_user_with_nothing_saved_is_not_told_protection_blocks() {
    assert_eq!(blames_protection("null"), "false\n");
}

#[test]
fn a_saved_level_is_named_as_the_reason() {
    assert_eq!(
        blames_protection("{ 'leak-protection': 'sites' }"),
        "true\n"
    );
    assert_eq!(blames_protection("{ 'leak-protection': 'off' }"), "false\n");
}
