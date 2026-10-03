//! A stability patch carries only the keys the platform's service applies. A
//! service without the whole row (Linux) still applies the verbose window and
//! the connection-trace switches, so the GUI offers and sends exactly those —
//! and nothing it would merely store. Runs the real `pure.js` through `node`
//! against the real platform profiles; the executable checks are skipped when
//! node is absent.
#![allow(clippy::expect_used)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use nrr_shared::ipc_payloads::ServiceStabilityConfigDto;
use nrr_shared::platform_profile::PlatformProfile;
use serde_json::{json, Value};

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn supports_of(profile: PlatformProfile) -> Value {
    serde_json::to_value(profile).expect("serialise the profile")["supports"].clone()
}

/// Every key the Diagnostics panel and the verbose control can send.
fn diagnostics_patch() -> Value {
    json!({
        "ipc-accept-policy": { "kind": "critical" },
        "verbose-logging-change": "one-hour",
        "conn-trace-ndjson": true,
        "conn-trace-gui": false,
        "cache-refresh-interval-secs": 600,
        "fake-ip-enabled": true
    })
}

fn filtered(supports: &Value) -> Option<Value> {
    let out = run_pure(&format!(
        "stabilityPatchForPlatform({}, {})",
        diagnostics_patch(),
        supports
    ))?;
    Some(out)
}

#[test]
fn a_platform_without_the_row_sends_only_the_verbose_and_trace_keys() {
    let Some(linux) = filtered(&supports_of(PlatformProfile::linux())) else {
        eprintln!("node not available — skipping the executable check");
        return;
    };
    assert_eq!(
        linux,
        json!({
            "verbose-logging-change": "one-hour",
            "conn-trace-ndjson": true,
            "conn-trace-gui": false
        })
    );
}

#[test]
fn a_platform_with_the_row_sends_the_patch_unchanged() {
    let Some(windows) = filtered(&supports_of(PlatformProfile::windows())) else {
        eprintln!("node not available — skipping the executable check");
        return;
    };
    assert_eq!(windows, diagnostics_patch());
    // No profile in the context (mock/preview) reads as "everything supported".
    assert_eq!(filtered(&Value::Null), Some(diagnostics_patch()));
}

#[test]
fn a_platform_without_any_of_it_sends_nothing() {
    let Some(macos) = filtered(&supports_of(PlatformProfile::macos())) else {
        eprintln!("node not available — skipping the executable check");
        return;
    };
    assert_eq!(macos, json!({}));
    let any = run_pure(&format!(
        "[{}, {}, {}].map(stabilityAnyKeyApplies)",
        supports_of(PlatformProfile::windows()),
        supports_of(PlatformProfile::linux()),
        supports_of(PlatformProfile::macos())
    ));
    assert_eq!(any, Some(json!([true, true, false])));
}

/// The capability table names real profile flags and real wire keys; a typo in
/// either reads as "supported" or "never applies" without any error.
#[test]
fn the_capability_table_names_real_flags_and_real_keys() {
    let Some(table) = run_pure("STABILITY_KEY_CAPABILITY") else {
        eprintln!("node not available — skipping the executable check");
        return;
    };
    let supports = supports_of(PlatformProfile::windows());
    // The one request-only key is echoed only when present, so the fixture names it.
    let dto: ServiceStabilityConfigDto = serde_json::from_value(json!({
        "ipc-accept-policy": { "kind": "critical" },
        "verbose-logging-change": "one-hour"
    }))
    .expect("a minimal config deserialises");
    let dto = serde_json::to_value(dto).expect("serialise the DTO");
    let table = table.as_object().expect("the table is an object");
    assert!(!table.is_empty());
    for (key, capability) in table {
        let capability = capability.as_str().expect("a capability name");
        assert!(
            supports.get(capability).is_some(),
            "{key}: `{capability}` is not a platform profile flag"
        );
        assert!(dto.get(key).is_some(), "{key} is not a stability wire key");
    }
}

#[test]
fn every_writer_and_reader_goes_through_the_one_rule() {
    let main = repo_file("apps/desktop/qml/Main.qml");
    assert!(!main.contains("isVerboseOnlyStabilityPatch"));
    let writer = &main[main
        .find("function applyServiceStabilityPatch(")
        .expect("the stability writer")..];
    let writer = &writer[..writer
        .find("_stabilityPatchQueue.push")
        .expect("the queue push")];
    assert!(
        writer.contains("stabilityPatchForPlatform(partial)")
            && writer.contains("partial = applicable"),
        "the writer does not narrow the patch to the platform: {writer}"
    );

    let settings = repo_file("apps/desktop/qml/sections/settings/DiagnosticsLogsSettings.qml");
    assert!(settings.contains("visible: root.verboseLoggingSupported"));
    assert!(
        settings.contains(
            "visible: !root.serviceStabilitySupported && root.supports(\"connTraceLog\")"
        ),
        "the trace switches have no card of their own where the row is not applied"
    );
    assert_eq!(
        settings.matches("ConnTraceSwitches {").count(),
        2,
        "one component draws the trace switches in both places"
    );
    let save = &settings[settings
        .find("function _saveStabilityConfig(")
        .expect("the panel save")..];
    let save = &save[..save.find("\n    }\n").expect("end of the save")];
    assert!(save.contains("root.stabilityPatchForPlatform({"));
    assert!(save.contains("root.applyServiceStabilityPatch(patch,"));
    assert!(save.contains("root._recordOfflineRoutingIntent(\"stability\", key, patch[key])"));

    let intent = repo_file("apps/desktop/qml/flows/ServiceIntentController.qml");
    assert!(intent.contains("intent = root.stabilityPatchForPlatform(intent)"));
    assert!(!intent.contains("if (!root.serviceStabilitySupported) return"));

    let offline = repo_file("apps/desktop/qml/flows/OfflinePendingController.qml");
    assert_eq!(
        offline
            .matches("root.stabilityPatchForPlatform(obj[\"stability\"] || {})")
            .count(),
        2,
        "both the backlog and the apply narrow the parked keys"
    );
}

/// Evaluate `expr` against `pure.js` in node and return it as JSON.
fn run_pure(expr: &str) -> Option<Value> {
    let program = format!(
        "{source}\nconsole.log(JSON.stringify({expr}));\n",
        source = repo_file("apps/desktop/qml/lib/pure.js").replace(".pragma library", ""),
    );
    let out = run_node(&program)?;
    Some(serde_json::from_str(out.trim()).unwrap_or_else(|e| panic!("{e}: {out}")))
}

/// Feed a program to `node` on stdin. `None` when node is not installed.
fn run_node(program: &str) -> Option<String> {
    let mut child = Command::new("node")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let Some(stdin) = child.stdin.as_mut() else {
        panic!("stdin was piped")
    };
    stdin
        .write_all(program.as_bytes())
        .unwrap_or_else(|e| panic!("write the harness to node: {e}"));
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("node runs to completion: {e}"));
    assert!(
        out.status.success(),
        "node rejected the harness: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}
