#![allow(clippy::expect_used)]

//! The emergency path of `scripts/reset-network.ps1` runs when no binary can
//! clean up, so nothing else reports what it left behind. The gate never runs
//! it (it needs Administrator and changes the machine); these hold its shape.

use std::path::Path;

fn script() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/reset-network.ps1");
    std::fs::read_to_string(path)
        .expect("the reset script")
        .replace("\r\n", "\n")
}

#[test]
fn an_incomplete_reset_is_neither_reported_as_complete_nor_exits_with_zero() {
    let script = script();
    assert!(
        !script.contains("$null = Remove-NrrDnsRedirect"),
        "the outcome of the DNS redirect sweep is thrown away"
    );
    let done = script
        .lines()
        .find(|l| l.contains("\"Network reset complete.\""))
        .expect("the success line");
    assert!(
        done.starts_with("    "),
        "the success line is printed whatever failed"
    );
    assert!(script.contains("if ($failures.Count -gt 0) { exit 1 }"));
}

#[test]
fn one_route_that_will_not_go_does_not_keep_the_rest() {
    let script = script();
    let lines: Vec<&str> = script.lines().map(str::trim).collect();
    let at = lines
        .iter()
        .position(|l| l.starts_with("Remove-NetRoute "))
        .expect("the route removal");
    assert_eq!(
        lines[..at].iter().rev().find(|l| !l.is_empty()),
        Some(&"try {"),
        "each route needs its own try, or the first refusal ends the sweep"
    );
}

#[test]
fn the_emergency_path_takes_back_the_suffix_list_and_the_engine_options() {
    let script = script();
    for step in ["Restore-NrrDnsSearchList", "Restore-NrrWfpEngineOptions"] {
        assert!(script.contains(step), "{step} is not called");
    }
    let library = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/lib/service-paths.ps1"),
    )
    .expect("the script library");
    for step in [
        "function Restore-NrrDnsSearchList",
        "function Restore-NrrWfpEngineOptions",
    ] {
        assert!(library.contains(step), "{step} is missing");
    }
}
