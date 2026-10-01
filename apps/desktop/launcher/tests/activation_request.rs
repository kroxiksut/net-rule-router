#![allow(clippy::expect_used)]

//! Verifies that the launcher writes the activation-request JSON in the
//! shape the C++ Qt host's `takePendingGuiRequest` consumes.
//!
//! Each test writes to its own `tempdir` path so parallel test execution is
//! independent of the shared `%TEMP%\NetRuleRouter\gui-activation.json` slot
//! that the production code uses.

use nrr_desktop_gui::app_shell::{FocusContext, LaunchRequest};
use nrr_launcher::write_activation_request;
use nrr_shared::{ActivationSource, AppSection};
use std::fs;
use tempfile::tempdir;

fn make_request(
    section: Option<AppSection>,
    open_about: bool,
    open_license: bool,
) -> LaunchRequest {
    LaunchRequest {
        source: ActivationSource::Tray,
        section,
        open_about,
        open_license,
        first_run_completed_override: None,
        action: None,
        reason: None,
        focus: None,
        focus_context: None,
    }
}

fn read_payload(path: &std::path::Path) -> serde_json::Map<String, serde_json::Value> {
    let raw = fs::read_to_string(path).expect("activation file must exist after write");
    let value: serde_json::Value = serde_json::from_str(&raw).expect("payload must be valid JSON");
    value
        .as_object()
        .cloned()
        .expect("payload must be a JSON object")
}

#[test]
fn minimal_request_writes_activate_only() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("activation.json");
    let request = make_request(None, false, false);
    write_activation_request(&request, &path).expect("write must succeed");

    let object = read_payload(&path);
    assert_eq!(object.get("activate"), Some(&serde_json::Value::Bool(true)));
    assert!(object.get("section").is_none());
    assert!(object.get("openAbout").is_none());
    assert!(object.get("openLicense").is_none());
}

#[test]
fn section_is_propagated_under_camel_case_key() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("activation.json");
    let request = make_request(Some(AppSection::Rules), false, false);
    write_activation_request(&request, &path).expect("write must succeed");

    let object = read_payload(&path);
    assert_eq!(
        object.get("section").and_then(|v| v.as_str()),
        Some("rules")
    );
}

#[test]
fn open_about_and_license_flags_are_propagated() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("activation.json");
    let request = make_request(Some(AppSection::Diagnostics), true, true);
    write_activation_request(&request, &path).expect("write must succeed");

    let object = read_payload(&path);
    assert_eq!(
        object.get("openAbout"),
        Some(&serde_json::Value::Bool(true))
    );
    assert_eq!(
        object.get("openLicense"),
        Some(&serde_json::Value::Bool(true))
    );
    assert_eq!(
        object.get("section").and_then(|v| v.as_str()),
        Some("diagnostics")
    );
}

#[test]
fn action_and_reason_are_propagated_when_set() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("activation.json");
    let mut request = make_request(None, false, false);
    request.action = Some("safe-disable".to_string());
    request.reason = Some("operator: testing".to_string());
    write_activation_request(&request, &path).expect("write must succeed");

    let object = read_payload(&path);
    assert_eq!(
        object.get("action").and_then(|v| v.as_str()),
        Some("safe-disable")
    );
    assert_eq!(
        object.get("reason").and_then(|v| v.as_str()),
        Some("operator: testing")
    );
}

#[test]
fn action_and_reason_are_omitted_when_unset() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("activation.json");
    let request = make_request(None, false, false);
    write_activation_request(&request, &path).expect("write must succeed");

    let object = read_payload(&path);
    assert!(object.get("action").is_none());
    assert!(object.get("reason").is_none());
}

#[test]
fn focus_and_its_context_are_propagated_when_set() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("activation.json");
    let mut request = make_request(Some(AppSection::Settings), false, false);
    request.focus = Some("doh-lockdown".to_string());
    request.focus_context = FocusContext::parse(
        r#"{"reason":"dns-lockdown","apps":["curl.exe"],"addresses":["192.0.2.1"],"more":2}"#,
    );
    write_activation_request(&request, &path).expect("write must succeed");

    let object = read_payload(&path);
    assert_eq!(
        object.get("focus").and_then(|v| v.as_str()),
        Some("doh-lockdown")
    );
    let context = object
        .get("focusContext")
        .and_then(|v| v.as_object())
        .expect("context is an object");
    assert_eq!(context["reason"], "dns-lockdown");
    assert_eq!(context["apps"], serde_json::json!(["curl.exe"]));
    assert_eq!(context["addresses"], serde_json::json!(["192.0.2.1"]));
    assert_eq!(context["more"], 2);
}

#[test]
fn focus_is_omitted_when_unset() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("activation.json");
    write_activation_request(&make_request(None, false, false), &path).expect("write must succeed");

    let object = read_payload(&path);
    assert!(object.get("focus").is_none());
    assert!(object.get("focusContext").is_none());
}

/// The cold-start counterpart: with no window running there is no activation
/// file to hand the intent to, so it has to reach QML through the context.
#[test]
fn cold_start_context_carries_the_launch_action() {
    let mut request = make_request(Some(AppSection::Rules), false, false);
    request.action = Some("rules-drift-compare".to_string());
    request.focus = Some("leak-protection".to_string());
    request.focus_context = FocusContext::parse(r#"{"reason":"ipv6-blocked","apps":["a.exe"]}"#);

    let shell = nrr_shared::gui_shell_v1();
    let preferences = nrr_ui_support::ui_preferences::UiPreferences::default();
    let first_run = nrr_ui_support::first_run::first_run_flow_snapshot(&shell);
    let backend = nrr_application::backend_facade::MockBackendFacade::default();
    let status = nrr_application::backend_facade::BackendConnectionStatus::Connected;

    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("context.json");
    nrr_desktop_gui::ui_surface::write_qt_context_file_at(
        &path,
        &shell,
        AppSection::Rules,
        preferences,
        &first_run,
        &request,
        &backend,
        &status,
        &nrr_launcher::rpc_dispatcher::host_answer_deadlines(),
    )
    .expect("write context");

    let raw = fs::read_to_string(&path).expect("read context");
    let json: serde_json::Value = serde_json::from_str(&raw).expect("parse context");
    assert_eq!(json["launchAction"], "rules-drift-compare");
    assert_eq!(json["entrySection"], "rules");
    assert_eq!(json["launchFocus"], "leak-protection");
    assert_eq!(
        json["launchFocusContext"]["apps"],
        serde_json::json!(["a.exe"])
    );
    let deadlines = &json[nrr_shared::launcher_rpc::HOST_ANSWER_DEADLINES_CONTEXT_KEY];
    assert!(
        deadlines["operationsMs"]["mutation.submit"].as_u64() > deadlines["defaultMs"].as_u64()
    );
}
