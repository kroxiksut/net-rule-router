#![allow(clippy::expect_used)]

//! Coverage for the launch-arguments parser the launcher reuses from
//! `nrr-desktop-gui::app_shell`. Re-tests the shape under launcher import
//! paths so regressions in the integration boundary are visible.

use nrr_desktop_gui::app_shell::parse_launch_request_arguments;
use nrr_shared::{ActivationSource, AppSection, FirstRunScenarioId};

#[test]
fn defaults_without_arguments() {
    let request = parse_launch_request_arguments(std::iter::empty::<String>());
    assert_eq!(request.source, ActivationSource::Menu);
    assert!(request.section.is_none());
    assert!(!request.open_about);
    assert!(!request.open_license);
    assert!(request.first_run_completed_override.is_none());
    assert!(request.first_run_scenario_override.is_none());
}

#[test]
fn source_tray_is_parsed() {
    let request = parse_launch_request_arguments(["--source=tray".to_string()]);
    assert_eq!(request.source, ActivationSource::Tray);
}

#[test]
fn section_rules_is_parsed() {
    let request = parse_launch_request_arguments(["--section=rules".to_string()]);
    assert_eq!(request.section, Some(AppSection::Rules));
}

#[test]
fn about_and_license_flags_combine() {
    let request = parse_launch_request_arguments(["--about".to_string(), "--license".to_string()]);
    assert!(request.open_about);
    assert!(request.open_license);
}

#[test]
fn first_run_completed_override_accepts_aliases() {
    let req_completed = parse_launch_request_arguments(["--first-run=completed".to_string()]);
    assert_eq!(req_completed.first_run_completed_override, Some(true));

    let req_required = parse_launch_request_arguments(["--first-run=required".to_string()]);
    assert_eq!(req_required.first_run_completed_override, Some(false));
}

#[test]
fn scenario_override_supports_short_alias() {
    let request = parse_launch_request_arguments(["--scenario=quick".to_string()]);
    assert_eq!(
        request.first_run_scenario_override,
        Some(FirstRunScenarioId::QuickStart)
    );
}

#[test]
fn unknown_argument_is_ignored() {
    let request = parse_launch_request_arguments([
        "--source=tray".to_string(),
        "--something-unsupported".to_string(),
        "--section=settings".to_string(),
    ]);
    assert_eq!(request.source, ActivationSource::Tray);
    assert_eq!(request.section, Some(AppSection::Settings));
}
