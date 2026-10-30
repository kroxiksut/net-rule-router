//! A new user who clicks through the first-run setup without touching the
//! protection choice gets "Routed sites": the sites sent to the VPN wait while
//! it is off instead of going out directly. The window's own declaration is
//! evaluated, not a copy of it.
#![allow(clippy::expect_used)]

#[path = "support/js.rs"]
mod js;
#[path = "support/qml_functions.rs"]
mod qml_functions;

const DECLARATION: &str = "property string wantLeakProtection:";

/// The initial value of `wantLeakProtection` as written in the window.
fn declared_expression() -> String {
    let source = qml_functions::read("components/FirstRunWindow.qml");
    let start = source.find(DECLARATION).expect("declaration present") + DECLARATION.len();
    source[start..]
        .lines()
        .take_while(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn offered(sheet: &str) -> String {
    js::run_js(&format!(
        "{}\nvar _sheet = {sheet};\nconsole.log({});",
        qml_functions::pure(),
        declared_expression()
    ))
}

#[test]
fn a_new_user_is_offered_routed_sites() {
    assert_eq!(offered("null"), "sites\n");
}

#[test]
fn an_installer_answer_still_decides_the_offer() {
    assert_eq!(offered("{ leakProtection: 'off' }"), "off\n");
}
