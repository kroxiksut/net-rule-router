//! One number per probing bound, across the three places that hold it.
//!
//! The wire, the stored row and the QML defaults table each carry their own
//! copy of "how long a main-link check may take", "how many targets it may
//! use" and "how often it may repeat". The GUI cannot read Rust constants and
//! the storage crate must not depend on the contracts crate, so the copies are
//! real and nothing structural keeps them equal — the comment that claimed a
//! test compared all three was, until this file existed, the only thing that
//! did.
//!
//! Drift is silent and one-sided: a peer that omits the keys agrees to the
//! wire's numbers, a fresh row gets storage's, and the settings window shows
//! QML's. The user then reads one bound, the service applies another.

#![allow(clippy::expect_used)]

use nrr_shared::ipc_payloads::RoutePolicyDto;
use nrr_storage::route_bindings::{
    DEFAULT_PRIMARY_PROBE_MAX_TARGETS, DEFAULT_PRIMARY_PROBE_REPEAT_SECS,
    DEFAULT_PRIMARY_PROBE_TIMEOUT_MS,
};

/// What a peer that omits every probing key agrees to. Read through serde
/// rather than the private `default_probe_*` helpers, so this is the value that
/// actually lands on a real message.
fn wire_defaults() -> RoutePolicyDto {
    // Only the keys serde genuinely requires; every probing bound is omitted,
    // which is the case under test.
    serde_json::from_str::<RoutePolicyDto>(
        r#"{"mode":"prefer-primary","block-secondary-when-unavailable":true,
            "binding-source":"user-assigned"}"#,
    )
    .expect("a policy without probing keys fills them in from the wire defaults")
}

#[test]
fn the_probe_defaults_agree_across_the_wire_and_the_stored_row() {
    let wire = wire_defaults();
    assert_eq!(
        wire.primary_probe_timeout_ms, DEFAULT_PRIMARY_PROBE_TIMEOUT_MS,
        "an omitted timeout must mean the same as a fresh row's"
    );
    assert_eq!(
        wire.primary_probe_max_targets, DEFAULT_PRIMARY_PROBE_MAX_TARGETS,
        "an omitted target count must mean the same as a fresh row's"
    );
    assert_eq!(
        wire.primary_probe_repeat_secs, DEFAULT_PRIMARY_PROBE_REPEAT_SECS,
        "an omitted repeat interval must mean the same as a fresh row's"
    );
}

/// The QML table the settings window shows before the service answers.
#[test]
fn the_qml_defaults_table_mirrors_the_wire_probe_defaults() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("apps/desktop/qml/lib/pure.js");
    let source =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

    let wire = wire_defaults();
    for (key, expected) in [
        ("primary-probe-timeout-ms", wire.primary_probe_timeout_ms),
        ("primary-probe-max-targets", wire.primary_probe_max_targets),
        ("primary-probe-repeat-secs", wire.primary_probe_repeat_secs),
    ] {
        assert_eq!(
            qml_default(&source, key),
            i64::from(expected),
            "`{key}` in the QML defaults table has drifted from the wire default"
        );
    }
}

/// The integer assigned to `"<key>":` in the QML defaults table.
fn qml_default(source: &str, key: &str) -> i64 {
    let needle = format!("\"{key}\":");
    let line = source
        .lines()
        .find(|l| l.trim_start().starts_with(&needle))
        .unwrap_or_else(|| panic!("no `{key}` entry in the QML defaults table"));
    let value = line
        .split(':')
        .next_back()
        .unwrap_or_default()
        .trim()
        .trim_end_matches(&[',', ';'][..]);
    value
        .parse()
        .unwrap_or_else(|e| panic!("`{key}` is not an integer literal ({value:?}): {e}"))
}

/// Positive control: the reader above must fail on a wrong value rather than
/// return something that matches anything.
#[test]
fn the_qml_reader_actually_reads_the_literal() {
    assert_eq!(qml_default("    \"demo-key\": 4242,\n", "demo-key"), 4242);
}
