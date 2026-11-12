#![allow(clippy::expect_used)]

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, JsLib};
use nrr_client_logic::discovery_probe::{discovery_previous_probe, discovery_probe_queue};
use serde_json::Value;

#[test]
fn discovery_previous_probe_matches_js() {
    check(
        "discovery_previous_probe",
        &mut JsLib::pure(),
        |input| format!("discoveryPreviousProbe({})", arg(input, "history")),
        |input| discovery_previous_probe(&input["history"]),
    );
}

#[test]
fn missing_history_does_not_mean_the_site_was_never_checked() {
    assert_eq!(discovery_previous_probe(&Value::Null), Value::Null);
}

#[test]
fn discovery_probe_queue_matches_js() {
    check(
        "discovery_probe_queue",
        &mut JsLib::pure(),
        |input| format!("discoveryProbeQueue({})", arg(input, "queue")),
        |input| discovery_probe_queue(&input["queue"]),
    );
}
