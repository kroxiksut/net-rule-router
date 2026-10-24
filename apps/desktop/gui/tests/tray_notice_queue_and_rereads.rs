//! The tray's notice queue and what it re-reads: an answer to the user's own
//! menu pick is never the notice the queue cap drops, notices that wait for an
//! answer retire on their own, an empty block batch frees the queue, the
//! "Move" of `?` rules covers only the list on screen, the route confirmation
//! honours "hide addresses", and a stored pause is read once the service runs.
//! The queue itself is run on the real `pure.js` in
//! `core/client-logic/tests/tray_notices.rs`.

use std::path::{Path, PathBuf};

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

/// The text of `function <name>(` through its closing brace. Braces inside
/// string literals and `//` comments are skipped.
fn function_body<'a>(source: &'a str, name: &str) -> &'a str {
    let start = source
        .find(&format!("function {name}("))
        .unwrap_or_else(|| panic!("function {name} is gone"));
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut opened = false;
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            quote @ (b'"' | b'\'') => {
                i += 1;
                while i < bytes.len() && bytes[i] != quote {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'{' => {
                depth += 1;
                opened = true;
            }
            b'}' => {
                depth = depth.saturating_sub(1);
                if opened && depth == 0 {
                    return &source[start..=i];
                }
            }
            _ => {}
        }
        i += 1;
    }
    panic!("function {name} never closes")
}

#[test]
fn the_tray_queues_through_the_shared_order() {
    let tray = repo_file("apps/desktop/qml/Tray.qml");
    assert!(
        function_body(&tray, "_presentOrQueue").contains("Pure.noticeQueueWith("),
        "the tray orders its notice queue on its own"
    );
}

#[test]
fn the_menu_picks_go_through_the_queue_as_the_users_own() {
    let tray = repo_file("apps/desktop/qml/Tray.qml");
    for name in [
        "_confirmLeakProtection",
        "_showPauseChoice",
        "_noteLeakProtectionFailed",
        "_notePauseFailed",
        "noteAddRuleOutcome",
    ] {
        assert!(
            function_body(&tray, name).contains("}, true)"),
            "{name} no longer marks its notice as the answer to a menu pick"
        );
    }
    assert!(function_body(&tray, "_showSuggestionsSilenceChoice")
        .contains("_presentOrQueue(\"suggestions-silence\", show, true)"));
}

#[test]
fn notices_that_wait_for_an_answer_retire_and_an_empty_batch_frees_the_queue() {
    let tray = repo_file("apps/desktop/qml/Tray.qml");
    for dismiss in [
        "dismissActionId: \"settings-lost-dismiss\",\n                    autoRetireMs: tray._promptAutoRetireMs",
        "secondaryAction: tray._noticeMuteAction(\"local-networks\"),\n                    dismissActionId: \"enforcement-dismiss\",\n                    autoRetireMs: tray._promptAutoRetireMs",
        "actionId: \"forwarded-traffic-open-settings\",\n                    accent: true\n                },\n                dismissActionId: \"enforcement-dismiss\",\n                autoRetireMs: tray._promptAutoRetireMs",
    ] {
        assert!(tray.contains(dismiss), "a notice holds the queue forever: {dismiss}");
    }
    assert!(
        function_body(&tray, "_showBlockNoticeBatch")
            .contains("if (batch.length === 0) { _scheduleDrain(); return }"),
        "a batch quieted while it waited stalls every notice behind it"
    );
}

#[test]
fn move_covers_only_the_list_on_screen() {
    let tray = repo_file("apps/desktop/qml/Tray.qml");
    assert!(function_body(&tray, "_showVerifyVerdicts")
        .contains("_verifyVerdictOnScreenIds = notice.ids.slice()"));
    assert!(function_body(&tray, "_moveVerifyVerdicts").contains("}, shownIds)"));
    assert!(tray.contains("_moveVerifyVerdicts(shownIds)"));
    let flow = repo_file("apps/desktop/qml/flows/VerifyVerdicts.qml");
    assert!(
        flow.contains("var corr = rpc[method]({ \"rule-ids\": asked })"),
        "the answer is sent for the list as it is now, not the one shown"
    );
}

#[test]
fn the_route_confirmation_hides_the_address_when_asked() {
    let tray = repo_file("apps/desktop/qml/Tray.qml");
    let confirm = function_body(&tray, "_confirmBlockNoticeRoute");
    assert!(
        confirm.contains("hideBlockNoticeAddresses")
            && confirm.contains("notifications.block-notice.destination-hidden"),
        "the second screen names a destination the first one hid"
    );
}

#[test]
fn a_stored_pause_is_read_once_the_service_runs() {
    let tray = repo_file("apps/desktop/qml/Tray.qml");
    let status = tray
        .split("onServiceStatusChanged: {")
        .nth(1)
        .unwrap_or_else(|| panic!("onServiceStatusChanged is gone"));
    let running = &status[..status.find("} else {").unwrap_or(status.len())];
    assert!(
        running.contains("_refreshRoutingPaused()"),
        "a tray started before the service shows the rules on during a pause"
    );
    assert!(function_body(&tray, "_subscribeStatusUpdatesTray")
        .contains("tray._refreshRoutingPaused()"));
    assert!(
        function_body(&tray, "_rereadAfterPushGap").contains("_refreshContractSkew()"),
        "a restart into another build is not noticed after a push gap"
    );
}
