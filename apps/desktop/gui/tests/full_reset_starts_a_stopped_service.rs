//! A full reset over a stopped service would clear nothing the service keeps:
//! every step goes over a channel nobody answers. So a stopped service is
//! started first and the steps run once it answers; the last one restarts it,
//! so the reset ends as a fresh install does: with the service running.

#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

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

const CONTROLLER: &str = "apps/desktop/qml/flows/FullResetController.qml";
const STARTER: &str = "apps/desktop/qml/flows/ServiceStarter.qml";
const DONE_DIALOG: &str = "apps/desktop/qml/components/FullResetCompleteDialog.qml";

#[test]
fn the_steps_wait_for_a_stopped_service_to_be_started() {
    let source = repo_file(CONTROLLER);
    let reset = function_body(&source, "fullReset");
    assert!(
        reset.contains("var steps = function() { _runResetSteps(")
            && reset.contains("root.serviceStarter.startIfStoppedThen(steps, steps)"),
        "the steps must run behind the start:\n{reset}"
    );
    assert!(
        !reset.contains("\n        _runResetSteps("),
        "no step may run before the start:\n{reset}"
    );
}

#[test]
fn only_a_stopped_service_is_started_and_its_answer_is_awaited() {
    let source = repo_file(STARTER);
    let start = function_body(&source, "startIfStoppedThen");
    assert!(
        start.contains("parseInt(ctl.status) !== 2"),
        "a running or absent service goes straight on:\n{start}"
    );
    assert!(start.contains("ctl.startService()"), "{start}");
    // The watch hands over once the service answers, or gives up in bounded
    // time when the start was declined.
    let watch = &source[source
        .find("property Timer _watch")
        .expect("the start watch")..];
    assert!(watch.contains("root._routingBackendConnected()"), "{watch}");
    assert!(watch.contains("attempts >= 60"), "{watch}");
}

/// After the reset the user was left with no routing and no protection until
/// they found the service controls: the last step stopped the service.
#[test]
fn the_reset_ends_with_the_service_restarted_not_stopped() {
    let source = repo_file(CONTROLLER);
    let step = function_body(&source, "_runResetStep");
    assert!(
        step.contains("step === \"restart-service\""),
        "the last step is the restart:\n{step}"
    );
    assert!(
        !source.contains("stopService()"),
        "nothing in the reset stops the service any more"
    );
    let restart = function_body(&source, "_restartService");
    assert!(
        restart.contains("root.serviceStarter.restartThen("),
        "{restart}"
    );
    // A restart is done only once the controller says so: the channel still
    // reads connected before the old process goes.
    let starter = repo_file(STARTER);
    let restart_then = function_body(&starter, "restartThen");
    assert!(
        restart_then.contains("ctl.restartService()"),
        "{restart_then}"
    );
    let watch = &starter[starter.find("property Timer _watch").expect("watch")..];
    assert!(watch.contains("_opDone"), "{watch}");
}

/// A restart that did not happen is said with its reason and a way to start
/// the service from the same place.
#[test]
fn a_failed_restart_is_told_with_its_reason_and_a_start_button() {
    let source = repo_file(CONTROLLER);
    let run = function_body(&source, "_runResetSteps");
    assert!(
        run.contains("serviceRestarted = !finished || next.restarted"),
        "the result reaches the dialog:\n{run}"
    );
    let dialog = repo_file(DONE_DIALOG);
    assert!(
        dialog.contains("visible: !root.serviceRestarted"),
        "{dialog}"
    );
    assert!(dialog.contains("root.restartFailure"), "{dialog}");
    assert!(
        dialog.contains("_startServiceFromBanner()"),
        "the start reuses the banner's start:\n{dialog}"
    );
}
