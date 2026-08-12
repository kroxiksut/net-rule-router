#![allow(clippy::expect_used)]

//! Verifies that the launcher writes the activation-request JSON in the
//! shape the C++ Qt host's `takePendingGuiRequest` consumes.
//!
//! Each test writes to its own `tempdir` path so parallel test execution is
//! independent of the shared `%TEMP%\NetRuleRouter\gui-activation.json` slot
//! that the production code uses.

use nrr_desktop_gui::app_shell::LaunchRequest;
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
        first_run_scenario_override: None,
        action: None,
        reason: None,
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
