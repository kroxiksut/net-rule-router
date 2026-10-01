//! The Diagnostics page follows the service, not the launch context.
//!
//! The context is read once at cold start. An alert raised afterwards holds
//! every rule change shut while the window shows nothing to acknowledge, and a
//! GUI started before the service shows no data on any card. So the window
//! re-reads the snapshot on the service's push, on (re)connecting, whenever a
//! change comes back refused behind an alert, and on opening the page. These
//! tests pin the wire names both ends share and the mapping of the service's
//! answer onto the context's shape. Settings -> Diagnostics and logs draws its
//! storage card from the same snapshot.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use nrr_shared::diagnostics_dto::{
    DiagnosticsDataOrigin, DiagnosticsStatusDto, SecurityAlertDto, OTHER_PRINCIPAL_ALERT_ID,
};
use nrr_shared::ipc_payloads::StatusUpdateEvent;
use nrr_shared::ipc_transport::SECURITY_ALERT_UNACKNOWLEDGED_CLIENT_SLUG;

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The literal assigned to `name` in a QML `property string` line.
fn qml_string_property(source: &str, name: &str) -> String {
    let needle = format!("property string {name}:");
    let line = source
        .lines()
        .find(|l| l.contains(&needle))
        .unwrap_or_else(|| panic!("no `property string {name}`"));
    let value = line
        .split_once(':')
        .map(|(_, v)| v.trim())
        .unwrap_or_default();
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or_else(|| panic!("`{name}` is not a string literal: {value}"))
        .to_string()
}

#[test]
fn the_transport_recognises_the_alert_gate_by_the_shared_slug() {
    let transport = repo_file("apps/desktop/qml/flows/RpcTransport.qml");
    assert_eq!(
        qml_string_property(&transport, "securityAlertGateCode"),
        SECURITY_ALERT_UNACKNOWLEDGED_CLIENT_SLUG
    );
}

/// The stand-in for another user's alerts cannot be acknowledged, so the
/// Diagnostics list must recognise it by the id the service mints.
#[test]
fn the_list_offers_no_acknowledge_for_another_users_alerts() {
    let section = repo_file("apps/desktop/qml/sections/DiagnosticsSection.qml");
    assert_eq!(
        qml_string_property(&section, "otherPrincipalAlertId"),
        OTHER_PRINCIPAL_ALERT_ID
    );
    assert!(
        section.contains("modelData.alertId !== section.otherPrincipalAlertId"),
        "the Acknowledge button no longer skips the stand-in"
    );
}

#[test]
fn the_string_reader_actually_reads_the_literal() {
    let source = "    readonly property string demo: \"gate-slug\"\n";
    assert_eq!(qml_string_property(source, "demo"), "gate-slug");
}

#[test]
fn the_window_rereads_the_list_on_the_services_push() {
    let event = serde_json::to_value(StatusUpdateEvent::SecurityAlertsChanged)
        .unwrap_or_else(|e| panic!("event serialises: {e}"));
    let wire = event["type"].as_str().unwrap_or_default();
    let main = repo_file("apps/desktop/qml/Main.qml");
    let case = format!("case \"{wire}\":");
    let at = main
        .find(&case)
        .unwrap_or_else(|| panic!("Main.qml does not handle the `{wire}` push"));
    let arm = &main[at..];
    let arm = &arm[..arm.find("break").unwrap_or(arm.len())];
    assert!(
        arm.contains("refreshDiagnosticsSnapshot()"),
        "the `{wire}` push must re-read the list: {arm}"
    );
}

fn alert(id: &str, state: &str, requires_action: bool) -> SecurityAlertDto {
    SecurityAlertDto {
        alert_id: id.into(),
        kind: "db_tamper_detected".into(),
        state: state.into(),
        created_at: 10,
        updated_at: 20,
        reason_code: "integrity.db_row_hmac_mismatch".into(),
        raised_file: "scan".into(),
        requires_action,
    }
}

/// Executable half, through the real `pure.js`. Skipped without `node`.
#[test]
fn a_service_answer_maps_onto_the_context_shape_and_a_stale_one_keeps_the_list() {
    let mut status = DiagnosticsStatusDto::unavailable();
    status.stale = false;
    status.security_status.alerts_readable = true;
    status.active_alerts = vec![
        alert("alt-1", "active", true),
        alert("alt-2", "acknowledged", false),
    ];
    let live = serde_json::to_string(&status).unwrap_or_else(|e| panic!("serialise: {e}"));
    let stale = serde_json::to_string(&DiagnosticsStatusDto::unavailable())
        .unwrap_or_else(|e| panic!("serialise: {e}"));
    // The service answered, but its alert store could not be read.
    let mut unreadable_status = DiagnosticsStatusDto::unavailable();
    unreadable_status.stale = false;
    let unreadable =
        serde_json::to_string(&unreadable_status).unwrap_or_else(|e| panic!("serialise: {e}"));
    let harness = format!(
        "{source}\nconsole.log(JSON.stringify([\
         securityAlertItemsFromStatus({live}),\
         securityAlertItemsFromStatus({stale}),\
         securityAlertItemsFromStatus(null),\
         securityAlertItemsFromStatus({unreadable}),\
         [securityAlertsUnreadable({live}), securityAlertsUnreadable({stale}),\
          securityAlertsUnreadable(null), securityAlertsUnreadable({unreadable})]]))\n",
        source = repo_file("apps/desktop/qml/lib/pure.js").replace(".pragma library", ""),
    );
    let Some(output) = run_node(&harness) else {
        eprintln!("node not available — skipping the executable mapping check");
        return;
    };
    let got: serde_json::Value = serde_json::from_str(output.trim())
        .unwrap_or_else(|e| panic!("harness output is not JSON: {e}; output: {output}"));
    assert_eq!(
        got[0],
        serde_json::json!([
            {
                "alertId": "alt-1", "kind": "db_tamper_detected", "state": "active",
                "createdAt": 10, "updatedAt": 20,
                "reasonCode": "integrity.db_row_hmac_mismatch", "raisedFile": "scan",
                "requiresAction": true
            },
            {
                "alertId": "alt-2", "kind": "db_tamper_detected", "state": "acknowledged",
                "createdAt": 10, "updatedAt": 20,
                "reasonCode": "integrity.db_row_hmac_mismatch", "raisedFile": "scan",
                "requiresAction": false
            }
        ])
    );
    assert!(got[1].is_null(), "a stale status must not clear the list");
    assert!(got[2].is_null());
    assert!(
        got[3].is_null(),
        "an unreadable alert store must not read as no alerts"
    );
    assert_eq!(
        got[4],
        serde_json::json!([false, false, false, true]),
        "only a service answer that could not read its alerts is unreadable"
    );
}

/// The window names an unreadable alert store in both languages, and does not
/// fall back to "No active alerts" for it.
#[test]
fn an_unreadable_alert_store_is_shown_as_such() {
    let section = repo_file("apps/desktop/qml/sections/DiagnosticsSection.qml");
    assert!(section.contains("root.securityAlertsUnreadable"));
    assert!(section.contains("\"diag.alert.unreadable\""));
    let context = repo_file("apps/desktop/gui/src/ui_surface.rs");
    assert!(context.contains("\"alertsUnreadable\""));
    for locale in ["en", "ru"] {
        let json: serde_json::Value =
            serde_json::from_str(&repo_file(&format!("locales/{locale}.json")))
                .unwrap_or_else(|e| panic!("{locale}.json: {e}"));
        assert!(
            json["diag"]["alert"]["unreadable"].is_string(),
            "{locale}.json lacks diag.alert.unreadable"
        );
    }
}

/// The launch context spells each alert with the same keys the re-read does.
#[test]
fn the_context_and_the_reread_use_the_same_keys() {
    let context = repo_file("apps/desktop/gui/src/ui_surface.rs");
    for key in [
        "alertId",
        "kind",
        "state",
        "createdAt",
        "updatedAt",
        "reasonCode",
        "raisedFile",
        "requiresAction",
    ] {
        assert!(
            context.contains(&format!("\"{key}\": alert.")),
            "the launch context no longer carries `{key}`"
        );
    }
}

/// Card fields of the launch context, each with the DTO field it is read from.
/// Both ends must spell them alike, or a re-read paints a card the context
/// never had.
const CARD_FIELDS: &[(&str, &str)] = &[
    ("overallHealthy", "overall_healthy"),
    ("stale", "stale"),
    ("origin", "origin"),
    ("state", "service_health.state"),
    ("activeRevisionId", "service_health.active_revision_id"),
    ("pendingChanges", "service_health.pending_changes"),
    (
        "startRelativeToSignIn",
        "service_health.start_relative_to_sign_in",
    ),
    ("startSignInGapMs", "service_health.start_sign_in_gap_ms"),
    ("auditChainOk", "security_status.audit_chain_ok"),
    ("activeAlertCount", "security_status.active_alert_count"),
    ("auditWriteHealthy", "security_status.audit_write_healthy"),
    ("entryCount", "cache_health.entry_count"),
    ("healthy", "cache_health.healthy"),
    ("dirWritable", "log_health.dir_writable"),
    ("totalSizeBytes", "log_health.total_size_bytes"),
    ("auditSizeBytes", "log_health.audit_size_bytes"),
    ("fileCount", "log_health.file_count"),
    ("droppedCount", "log_health.dropped_count"),
    ("lastCleanupAt", "log_health.last_cleanup_at"),
];

#[test]
fn the_context_reads_each_card_field_from_the_dto_field_the_reread_maps() {
    // rustfmt may break a long pair after its key.
    let context = repo_file("apps/desktop/gui/src/ui_surface.rs")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for (key, field) in CARD_FIELDS {
        assert!(
            context.contains(&format!("\"{key}\": diagnostics_status.{field}")),
            "the launch context no longer reads `{key}` from `{field}`"
        );
    }
}

/// Executable half, through the real `pure.js`. Skipped without `node`.
#[test]
fn a_live_answer_replaces_every_card_and_a_failed_one_keeps_what_is_shown() {
    let mut status = DiagnosticsStatusDto::unavailable();
    status.overall_healthy = true;
    status.stale = false;
    status.origin = DiagnosticsDataOrigin::Service;
    status.service_health.state = "running".into();
    status.service_health.active_revision_id = Some("rev-7".into());
    status.service_health.pending_changes = 2;
    status.service_health.start_relative_to_sign_in = "after".into();
    status.service_health.start_sign_in_gap_ms = Some(1500);
    status.security_status.audit_chain_ok = true;
    status.security_status.active_alert_count = 1;
    status.security_status.audit_write_healthy = true;
    status.cache_health.entry_count = 42;
    status.cache_health.healthy = true;
    status.log_health.dir_writable = true;
    status.log_health.total_size_bytes = 4096;
    status.log_health.audit_size_bytes = 8192;
    status.log_health.file_count = 3;
    status.log_health.dropped_count = 5;
    status.log_health.last_cleanup_at = Some(1_700_000_000_000);
    let live = serde_json::to_string(&status).unwrap_or_else(|e| panic!("serialise: {e}"));
    let unavailable = serde_json::to_string(&DiagnosticsStatusDto::unavailable())
        .unwrap_or_else(|e| panic!("serialise: {e}"));
    // What the window shows before the service answered: the placeholder,
    // plus the alert fields the re-read must leave to the window's own list.
    let shown = r#"{"origin":"unavailable","stale":true,"overallHealthy":false,
        "activeAlerts":[{"alertId":"alt-1"}],"alertsStale":false,"alertsUnreadable":false,
        "explainSample":null,"serviceHealth":{"state":"unavailable"}}"#;
    let harness = format!(
        "{source}\nconsole.log(JSON.stringify([\
         diagnosticsSnapshotMerged({shown}, {live}),\
         diagnosticsSnapshotMerged({shown}, {unavailable}),\
         diagnosticsSnapshotMerged({shown}, null),\
         diagnosticsSnapshotMerged(null, {live}) !== null,\
         [diagnosticsSnapshotIsLive({shown}),\
          diagnosticsSnapshotIsLive(diagnosticsSnapshotMerged({shown}, {live})),\
          diagnosticsSnapshotIsLive(null)]]))\n",
        source = repo_file("apps/desktop/qml/lib/pure.js").replace(".pragma library", ""),
    );
    let Some(output) = run_node(&harness) else {
        eprintln!("node not available — skipping the executable merge check");
        return;
    };
    let got: serde_json::Value = serde_json::from_str(output.trim())
        .unwrap_or_else(|e| panic!("harness output is not JSON: {e}; output: {output}"));
    assert_eq!(
        got[0],
        serde_json::json!({
            "origin": "service", "stale": false, "overallHealthy": true,
            "activeAlerts": [{"alertId": "alt-1"}], "alertsStale": false,
            "alertsUnreadable": false, "explainSample": null,
            "serviceHealth": {
                "state": "running", "activeRevisionId": "rev-7", "pendingChanges": 2,
                "startRelativeToSignIn": "after", "startSignInGapMs": 1500
            },
            "securityStatus": {
                "auditChainOk": true, "activeAlertCount": 1, "auditWriteHealthy": true
            },
            "cacheHealth": { "entryCount": 42, "healthy": true },
            "logHealth": {
                "dirWritable": true, "totalSizeBytes": 4096, "auditSizeBytes": 8192,
                "fileCount": 3,
                "droppedCount": 5, "lastCleanupAt": 1_700_000_000_000_u64
            }
        })
    );
    assert!(
        got[1].is_null(),
        "a placeholder answer must not replace the cards"
    );
    assert!(got[2].is_null(), "no answer must not replace the cards");
    assert_eq!(
        got[3],
        serde_json::json!(true),
        "nothing shown yet still merges"
    );
    assert_eq!(
        got[4],
        serde_json::json!([false, true, false]),
        "only the service's own, non-stale answer is live"
    );
    // Every card field the context carries is one the merge writes.
    let merged = &got[0];
    for (key, _) in CARD_FIELDS {
        let present = merged.get(key).is_some()
            || [
                "serviceHealth",
                "securityStatus",
                "cacheHealth",
                "logHealth",
            ]
            .iter()
            .any(|card| merged[card].get(key).is_some());
        assert!(present, "the re-read does not write `{key}`");
    }
}

/// Opening the page reads at most once per window; events always read, and
/// nothing runs beside a read in flight.
#[test]
fn page_opens_are_throttled_by_the_last_live_answer_and_events_are_not() {
    let harness = format!(
        "{source}\nconsole.log(JSON.stringify([\
         diagnosticsReadDecision(true, true, 0, 1000, 30000),\
         diagnosticsReadDecision(true, false, 0, 1000, 30000),\
         diagnosticsReadDecision(false, false, 0, 1000, 30000),\
         diagnosticsReadDecision(false, false, 1000, 20000, 30000),\
         diagnosticsReadDecision(false, true, 1000, 20000, 30000),\
         diagnosticsReadDecision(false, false, 1000, 31000, 30000),\
         diagnosticsReadDecision(false, false, 50000, 1000, 30000)]))\n",
        source = repo_file("apps/desktop/qml/lib/pure.js").replace(".pragma library", ""),
    );
    let Some(output) = run_node(&harness) else {
        eprintln!("node not available — skipping the throttle check");
        return;
    };
    let got: serde_json::Value = serde_json::from_str(output.trim())
        .unwrap_or_else(|e| panic!("harness output is not JSON: {e}; output: {output}"));
    assert_eq!(
        got,
        serde_json::json!(["queue", "queue", "read", "skip", "read", "read", "read"])
    );
}

/// The page reads the window's snapshot, not the launch context, and asks for
/// a re-read when it is opened; a reconnect re-reads without asking the page.
#[test]
fn the_page_shows_the_window_snapshot_and_rereads_on_open_and_on_reconnect() {
    let section = repo_file("apps/desktop/qml/sections/DiagnosticsSection.qml");
    assert!(section.contains("readonly property var diag: root.diagnosticsSnapshot"));
    assert!(
        !section.contains("context.diagnostics"),
        "a card reading the launch context never sees a re-read"
    );
    assert!(section.contains("root.refreshDiagnosticsOnPageOpen()"));
    let main = repo_file("apps/desktop/qml/Main.qml");
    let at = main
        .find("if (wasDisconnected) {")
        .unwrap_or_else(|| panic!("Main.qml lost its reconnect transition"));
    let transition = &main[at..];
    let transition = &transition[..transition.find("\n    }\n").unwrap_or(transition.len())];
    assert!(
        transition.contains("Qt.callLater(refreshDiagnosticsSnapshot)"),
        "a reconnect must re-read the Diagnostics snapshot"
    );
}

/// The settings page reads the window's snapshot, not a launch copy of it, and
/// asks for a re-read when it is opened.
#[test]
fn the_settings_page_shows_the_window_snapshot_and_rereads_on_open() {
    let page = repo_file("apps/desktop/qml/sections/settings/DiagnosticsLogsSettings.qml");
    assert!(page.contains("Pure.diagnosticsStorageView(root.diagnosticsSnapshot)"));
    assert!(
        !page.contains("context.diagnostics"),
        "a card reading the launch context never sees a re-read"
    );
    assert!(page.contains("onVisibleChanged: if (visible) root.refreshDiagnosticsOnPageOpen()"));
    let flat = page.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flat.contains("Component.onCompleted: { root.refreshDiagnosticsOnPageOpen()"),
        "the first opening must ask for a re-read too"
    );
    let context = repo_file("apps/desktop/gui/src/ui_surface.rs");
    assert!(
        !context.contains("\"diagnosticsSettings\""),
        "a second launch copy of the storage card has no reader and no re-read"
    );
}

/// Executable half, through the real `pure.js`. Skipped without `node`.
#[test]
fn the_settings_view_maps_the_snapshot_and_draws_nothing_for_a_missing_card() {
    let mut status = DiagnosticsStatusDto::unavailable();
    status.stale = false;
    status.origin = DiagnosticsDataOrigin::Service;
    status.security_status.audit_chain_ok = true;
    status.log_health.dir_writable = true;
    status.log_health.total_size_bytes = 4096;
    status.log_health.audit_size_bytes = 8192;
    status.log_health.file_count = 3;
    status.log_health.dropped_count = 5;
    status.log_health.last_cleanup_at = Some(1_700_000_000_000);
    let live = serde_json::to_string(&status).unwrap_or_else(|e| panic!("serialise: {e}"));
    let broken = r#"{"securityStatus":{"auditChainOk":false},"logHealth":{"lastCleanupAt":null}}"#;
    let harness = format!(
        "{source}\nconsole.log(JSON.stringify([\
         diagnosticsStorageView(diagnosticsSnapshotMerged({{}}, {live})),\
         diagnosticsStorageView({broken}),\
         diagnosticsStorageView({{}}),\
         diagnosticsStorageView(null)]))\n",
        source = repo_file("apps/desktop/qml/lib/pure.js").replace(".pragma library", ""),
    );
    let Some(output) = run_node(&harness) else {
        eprintln!("node not available — skipping the settings view check");
        return;
    };
    let got: serde_json::Value = serde_json::from_str(output.trim())
        .unwrap_or_else(|e| panic!("harness output is not JSON: {e}; output: {output}"));
    assert_eq!(
        got[0],
        serde_json::json!({
            "storageHealth": {
                "logsSizeBytes": 4096, "auditSizeBytes": 8192, "logFileCount": 3,
                "droppedEvents": 5, "lastCleanup": 1_700_000_000_000_u64, "dirWritable": true
            },
            "auditChain": { "verified": true }
        })
    );
    assert_eq!(
        got[1]["auditChain"],
        serde_json::json!({ "verified": false }),
        "a broken chain must reach the warning"
    );
    assert!(got[1]["storageHealth"]["lastCleanup"].is_null());
    let empty = serde_json::json!({ "storageHealth": {}, "auditChain": {} });
    assert_eq!(got[2], empty, "nothing read yet draws as no data");
    assert_eq!(got[3], empty);
}

/// An acknowledgement is judged on the window's own forced re-read, so the
/// verdict and the list and cards on screen come from one answer, with no
/// second read of the page's own. A waiter queued behind a read in flight
/// rides the repeat, not the older answer.
#[test]
fn the_acknowledgement_verdict_rides_the_windows_reread() {
    let section = repo_file("apps/desktop/qml/sections/DiagnosticsSection.qml");
    assert!(
        !section.contains("rpcSnapshotDiagnosticsGet"),
        "the page must not read the snapshot beside the window"
    );
    let at = section
        .find("function _alertAckSettledByState(")
        .unwrap_or_else(|| panic!("DiagnosticsSection.qml lost _alertAckSettledByState"));
    let settle = &section[at..];
    let settle = &settle[..settle.find("\n    }\n").unwrap_or(settle.len())];
    assert!(
        settle.contains("root.refreshDiagnosticsSnapshot(true, function("),
        "the verdict must wait on a forced window re-read: {settle}"
    );
    assert!(settle.contains("Pure.alertAckOutcome("));
    // A verdict judged on a just-applied answer is not followed by another read.
    assert!(section.contains("section._announceAlertAckFailed(failure, read.fresh)"));
    assert!(section.contains("if (snapshotFresh !== true)"));
    let main = repo_file("apps/desktop/qml/Main.qml");
    assert!(main.contains("function refreshDiagnosticsSnapshot(forced, onDone)"));
    assert!(
        main.contains("_diagnosticsReadAgainWaiters.concat(waiters)")
            && main.contains("window._readDiagnosticsSnapshot(againForced, againWaiters)"),
        "a waiter queued behind a read in flight must be served by the repeat"
    );
}

/// Executable half, through the real `pure.js`. Skipped without `node`.
#[test]
fn an_acknowledgement_settles_only_on_a_readable_list_without_the_alert_active() {
    let mut still_active = DiagnosticsStatusDto::unavailable();
    still_active.stale = false;
    still_active.security_status.alerts_readable = true;
    still_active.active_alerts = vec![alert("alt-1", "active", true)];
    let mut handled = still_active.clone();
    handled.active_alerts = vec![alert("alt-1", "acknowledged", false)];
    let mut unreadable = DiagnosticsStatusDto::unavailable();
    unreadable.stale = false;
    let json = |s: &DiagnosticsStatusDto| {
        serde_json::to_string(s).unwrap_or_else(|e| panic!("serialise: {e}"))
    };
    let harness = format!(
        "{source}\nconsole.log(JSON.stringify([\
         alertAckOutcome({active}, \"alt-1\", \"\"),\
         alertAckOutcome({handled}, \"alt-1\", \"\"),\
         alertAckOutcome({active}, \"alt-2\", \"\"),\
         alertAckOutcome({unreadable}, \"alt-1\", \"\"),\
         alertAckOutcome({stale}, \"alt-1\", \"\"),\
         alertAckOutcome(null, \"alt-1\", \"timeout\")]))\n",
        source = repo_file("apps/desktop/qml/lib/pure.js").replace(".pragma library", ""),
        active = json(&still_active),
        handled = json(&handled),
        unreadable = json(&unreadable),
        stale = json(&DiagnosticsStatusDto::unavailable()),
    );
    let Some(output) = run_node(&harness) else {
        eprintln!("node not available — skipping the acknowledgement verdict check");
        return;
    };
    let got: serde_json::Value = serde_json::from_str(output.trim())
        .unwrap_or_else(|e| panic!("harness output is not JSON: {e}; output: {output}"));
    assert_eq!(
        got,
        serde_json::json!(["unknown", "", "", "unknown", "unknown", "timeout"]),
        "an unreadable or missing list must never read as the alert handled"
    );
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
