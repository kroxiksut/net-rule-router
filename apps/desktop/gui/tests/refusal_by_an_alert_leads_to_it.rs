//! A change the service refuses until a security alert is acknowledged used to
//! end in a message that sent the user to find Diagnostics alone, and a rule
//! set picked in the welcome wizard was lost on the way: the user acknowledged
//! the alert, then had to pick and load the set again. The message now opens
//! the alert, and the refused set loads by itself once it is acknowledged.

#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

#[path = "support/js.rs"]
mod js;
#[path = "support/qml_functions.rs"]
mod qml_functions;

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

/// The text of `function <name>(` up to the next function at the same depth.
fn function_body<'a>(source: &'a str, name: &str) -> &'a str {
    let start = source
        .find(&format!("function {name}("))
        .unwrap_or_else(|| panic!("function {name} is gone"));
    let rest = &source[start..];
    let end = rest[1..]
        .find("\n    function ")
        .map_or(rest.len(), |at| at + 1);
    &rest[..end]
}

const TRANSPORT: &str = "apps/desktop/qml/flows/RpcTransport.qml";
const MAIN: &str = "apps/desktop/qml/Main.qml";
const NOTICE: &str = "apps/desktop/qml/components/InfoNoticeDialog.qml";
const IMPORT: &str = "apps/desktop/qml/flows/PresetImportController.qml";
const DIAGNOSTICS: &str = "apps/desktop/qml/sections/DiagnosticsSection.qml";
const TRAY: &str = "apps/desktop/qml/Tray.qml";
const TRAY_RULE: &str = "apps/desktop/qml/components/TrayRuleWindow.qml";

#[test]
fn every_answer_the_gate_refused_is_handled_as_such() {
    let source = repo_file(TRANSPORT);
    let dispatch = function_body(&source, "handleRpcResponse");
    assert!(
        dispatch
            .contains("_settleRefusal(!ok && String(errorCode || \"\") === securityAlertGateCode"),
        "a refused call's callback runs inside the gate's scope:\n{dispatch}"
    );
    let outcome = function_body(&source, "readMutationOutcome");
    assert!(
        outcome.contains("transport._settleRefusal(failure === transport.securityAlertGateCode"),
        "an operation the gate failed is handled the same way:\n{outcome}"
    );
    let settle = function_body(&source, "_settleRefusal");
    assert!(
        settle.contains("finally") && settle.contains("handlingAlertGate = false"),
        "the scope ends even when the callback throws:\n{settle}"
    );
}

#[test]
fn a_message_about_a_refused_change_opens_the_alert() {
    let main = repo_file(MAIN);
    let notice = function_body(&main, "showNotice");
    assert!(
        notice.contains("infoNoticeDialog.offerOpenAlert = rpcTransport.handlingAlertGate"),
        "{notice}"
    );
    let dialog = repo_file(NOTICE);
    assert!(
        dialog.contains("visible: root.offerOpenAlert")
            && dialog.contains("tr(\"action.open-security-alert\"")
            && dialog.contains("root.ownerRoot.openSecurityAlerts()"),
        "the notice offers the alert"
    );
    let open = function_body(&main, "openSecurityAlerts");
    assert!(
        open.contains("requestSectionChange(\"diagnostics\"")
            && open.contains("securityAlertsFocusPending = true")
            && open.contains("window.raise()"),
        "{open}"
    );
    let diagnostics = repo_file(DIAGNOSTICS);
    let focus = function_body(&diagnostics, "_consumeAlertsFocus");
    assert!(
        focus.contains("root.securityAlertsFocusPending = false")
            && focus.contains("securityCard.y")
            && focus.contains("forceActiveFocus"),
        "the alerts come into view once, under the keyboard:\n{focus}"
    );
}

#[test]
fn a_rule_set_the_gate_refused_loads_once_the_alert_is_acknowledged() {
    let source = repo_file(IMPORT);
    for flow in [
        "startPresetImportReviewFlow",
        "startBothRoutesPresetImportReviewFlow",
    ] {
        let body = function_body(&source, flow);
        let held = body
            .find("if (_holdForAlert(code, options, function() {")
            .unwrap_or_else(|| panic!("{flow} drops a set the gate refused"));
        let reported = body
            .find("_reportImportFailure(root.tr(\"status.preset-import-dry-run-failed\"")
            .expect("the ordinary failure");
        assert!(
            held < reported,
            "{flow}: held before it is reported as failed"
        );
        assert!(
            body.contains(&format!("presetImportController.{flow}(")),
            "{flow}: the held load is the same one again"
        );
    }
    let hold = function_body(&source, "_holdForAlert");
    assert!(
        hold.contains("options.hydration === true") && hold.contains("_afterAlertAck = again"),
        "only a load the user asked for is held:\n{hold}"
    );
    let resume = function_body(&source, "_resumeAfterAlertAck");
    assert!(
        resume.contains("root.securityAlertsUnreadable")
            && resume.contains("items[i].state === \"active\"")
            && resume.contains("_afterAlertAck = null"),
        "it resumes once, and only with no alert active:\n{resume}"
    );
    assert!(source.contains("function onSecurityAlertItemsChanged()"));
}

#[test]
fn the_trays_add_rule_opens_the_alert_that_refused_it() {
    let window = repo_file(TRAY_RULE);
    let failed = function_body(&window, "_failed");
    assert!(
        failed.contains("trayHost.rpc.securityAlertGateCode") && failed.contains("\"alert-gate\""),
        "{failed}"
    );
    assert!(window.contains("trayRuleWindow.trayHost.openSecurityAlerts()"));
    let tray = repo_file(TRAY);
    let open = function_body(&tray, "openSecurityAlerts");
    assert!(
        open.contains("openMainGuiFocused(\"diagnostics\", \"security-alerts\""),
        "{open}"
    );
    let main = repo_file(MAIN);
    let focus = function_body(&main, "focusSetting");
    assert!(
        focus.contains("id === \"security-alerts\"") && focus.contains("openSecurityAlerts()"),
        "{focus}"
    );
}

/// The owner was on Connections when the refusal sent him to the alert; once
/// it is acknowledged he is back on Connections. Sent there from Diagnostics
/// itself, the user stays.
#[test]
fn acknowledging_the_alert_brings_the_user_back() {
    let scenario = [
        "var section = 'interfaces';",
        "var window = { show: function() {}, raise: function() {}, requestActivate: function() {},",
        "    securityAlertsFocusPending: false };",
        "function requestSectionChange(next, arrive) { section = next; if (arrive) arrive() }",
        "var _sectionBeforeAlerts = '';",
        &qml_functions::functions(
            "Main.qml",
            &["openSecurityAlerts", "returnFromSecurityAlerts"],
        ),
        "openSecurityAlerts();",
        "console.log('sent to ' + section);",
        "returnFromSecurityAlerts();",
        "console.log('back at ' + section);",
        "section = 'diagnostics';",
        "openSecurityAlerts();",
        "returnFromSecurityAlerts();",
        "console.log('stays at ' + section);",
    ]
    .join("\n");
    let output = js::run_js(&scenario);
    for line in [
        "sent to diagnostics",
        "back at interfaces",
        "stays at diagnostics",
    ] {
        assert!(output.lines().any(|l| l == line), "{line}:\n{output}");
    }
}
