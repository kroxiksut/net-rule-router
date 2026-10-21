//! A full reset over a stopped service would clear nothing the service keeps:
//! every step goes over a channel nobody answers. So a stopped service is
//! started first and the steps run once it answers; the last one stops it.

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

#[test]
fn the_steps_wait_for_a_stopped_service_to_be_started() {
    let source = repo_file(CONTROLLER);
    let reset = function_body(&source, "fullReset");
    assert!(
        reset.contains("_startServiceThen(function() { _runResetSteps("),
        "the steps must run behind the start:\n{reset}"
    );
    assert!(
        !reset.contains("\n        _runResetSteps("),
        "no step may run before the start:\n{reset}"
    );
}

#[test]
fn only_a_stopped_service_is_started_and_its_answer_is_awaited() {
    let source = repo_file(CONTROLLER);
    let start = function_body(&source, "_startServiceThen");
    assert!(
        start.contains("parseInt(ctl.status) !== 2"),
        "a running or absent service goes straight to the steps:\n{start}"
    );
    assert!(start.contains("ctl.startService()"), "{start}");
    assert!(start.contains("_startWatch.restart()"), "{start}");
    // The watch hands over once the service answers, or gives up in bounded
    // time when the start was declined.
    let watch = &source[source
        .find("property Timer _startWatch")
        .expect("the start watch")..];
    assert!(watch.contains("root._routingBackendConnected()"), "{watch}");
    assert!(watch.contains("attempts >= 40"), "{watch}");
}
