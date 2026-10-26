//! "Is it us or the site?" is offered wherever the window tells of a site that
//! does not open: the notice of a site silent on both links, the connection
//! trace, and the suggestion of a site that kept failing. Each hands its host
//! to the one check in Diagnostics.

use std::path::{Path, PathBuf};

use nrr_shared::ipc_payloads::StatusUpdateEvent;

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The text of `case "<kind>":` up to the `break` that ends it.
fn case_body<'a>(source: &'a str, kind: &str) -> &'a str {
    let head = format!("case \"{kind}\":");
    let start = source
        .find(&head)
        .unwrap_or_else(|| panic!("Main.qml does not dispatch `{kind}`"));
    let rest = &source[start + head.len()..];
    &rest[..rest.find("break").unwrap_or(rest.len())]
}

#[test]
fn the_notice_of_a_site_silent_on_both_links_offers_the_site_check_for_its_host() {
    let event = serde_json::to_value(StatusUpdateEvent::HostUnreachableOnBothRoutes {
        sid: "S-1-5-21-0".into(),
        host: "site.example".into(),
    })
    .unwrap_or_else(|e| panic!("event serialises: {e}"));
    let kind = event["type"].as_str().unwrap_or_default();
    assert!(event.get("host").is_some(), "the push names its host");

    let main = repo_file("apps/desktop/qml/Main.qml");
    let body = case_body(&main, kind);
    assert!(
        body.contains("\"actionKey\": \"check-site\""),
        "the notice offers no site check:\n{body}"
    );
    assert!(
        body.contains("\"actionArg\": String(event[\"host\"]"),
        "the check must run on the host the notice names:\n{body}"
    );
}

#[test]
fn every_entry_point_reaches_the_one_check_in_diagnostics() {
    let notices = repo_file("apps/desktop/qml/flows/NotificationsController.qml");
    assert!(
        notices.contains("actionKey === \"check-site\") checkSiteInDiagnostics(String(actionArg"),
        "the notice action does not start the check"
    );
    for file in [
        "apps/desktop/qml/sections/ConnTraceSection.qml",
        "apps/desktop/qml/sections/RuleSuggestionsSection.qml",
    ] {
        assert!(
            repo_file(file).contains("notificationsController.checkSiteInDiagnostics("),
            "{file} no longer offers the site check"
        );
    }
    let diagnostics = repo_file("apps/desktop/qml/sections/DiagnosticsSection.qml");
    assert!(
        diagnostics.contains("siteCheckPanel.check(host)"),
        "Diagnostics does not run the handed-over check"
    );
}
