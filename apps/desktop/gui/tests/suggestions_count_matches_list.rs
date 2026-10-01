//! The suggestions badge counts exactly what the list shows by default.
//!
//! The service decides the number (`pending-count` on the list reply and the
//! push, `pending` on an answer's reply) from the same `served-by-main-link`
//! mark the list filters on. A window that re-counted the rows itself kept a
//! second rule that drifted: the tray said "Suggested addresses (1)" over an
//! empty list. These tests pin both ends: the QML takes the service's number,
//! and the list's default filter hides exactly the rows the service leaves out.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use nrr_shared::ipc_payloads::{
    AutoRuleCandidateDto, AutoRuleCandidatesListResponse, AutoRuleConsumerDto,
    AUTO_RULE_MATCH_KIND_SUFFIX, AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS,
    AUTO_RULE_SIGNAL_DELIVERY_NAME,
};
use nrr_shared::RouteRole;

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn candidate(id: &str, proposed: &str, served: bool) -> AutoRuleCandidateDto {
    AutoRuleCandidateDto {
        id: id.into(),
        anchor: "site.example".into(),
        proposed_match: proposed.into(),
        match_kind: AUTO_RULE_MATCH_KIND_SUFFIX.into(),
        route: RouteRole::Secondary.slug().into(),
        affinity: 1.0,
        observations: Some(2),
        first_seen_unix_ms: 1,
        last_seen_unix_ms: 2,
        signal: AUTO_RULE_SIGNAL_DELIVERY_NAME.into(),
        consumers: vec![AutoRuleConsumerDto {
            hostname: "site.example".into(),
            route: RouteRole::Secondary.slug().into(),
        }],
        consumers_changed_unix_ms: 2,
        primary_behavior: if served {
            AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS.into()
        } else {
            String::new()
        },
        anchor_refuses_main_link: false,
        observed_members: Vec::new(),
        served_by_main_link: served,
        third_party: Some(true),
        secondary_reach: None,
    }
}

#[test]
fn every_window_takes_the_count_from_the_service_instead_of_counting_rows() {
    let wire = serde_json::to_value(AutoRuleCandidatesListResponse::default())
        .unwrap_or_else(|e| panic!("list reply serialises: {e}"));
    assert!(
        wire.get("pending-count").is_some(),
        "the list reply must carry the count the windows read"
    );
    for (file, target) in [
        (
            "apps/desktop/qml/flows/AutoRuleSuggestionsController.qml",
            "autoRuleCandidatesPending",
        ),
        ("apps/desktop/qml/Tray.qml", "_autoRulePendingCount"),
    ] {
        let source = repo_file(file);
        let from_list = format!("{target} = Number(payload[\"pending-count\"]");
        assert!(
            source.contains(&from_list),
            "{file} must take its count from the list reply's `pending-count`"
        );
        let recounted = format!("{target} = list.length");
        assert!(
            !source.contains(&recounted),
            "{file} re-counts the list rows; that count includes rows the list hides"
        );
    }
}

/// Executable half, through the real `pure.js`. Skipped when no `node` is on
/// PATH — the structural test above stays the unconditional guard.
#[test]
fn the_default_list_shows_exactly_the_rows_the_service_counts() {
    let candidates = vec![
        candidate("arc-1", "assets.site-cdn.example", false),
        // Same registrable domain, but served: the mixed group must keep the
        // first host and hide this one.
        candidate("arc-2", "img.site-cdn.example", true),
        // A group whose every host is served disappears from the default view.
        candidate("arc-3", "tracker.example", true),
        candidate("arc-4", "video.example", false),
    ];
    let counted = candidates.iter().filter(|c| !c.served_by_main_link).count();
    let dismissed = serde_json::json!([{
        "candidate-id": "arc-5",
        "anchor": "site.example",
        "proposed-match": "old.example",
        "dismissed-at-unix-ms": 3
    }]);
    let harness = format!(
        "{source}\n\
         var groups = groupAutoRuleRows({candidates}, {dismissed});\n\
         var shown = filterAutoRuleGroupsServedByMainLink(\n\
             filterAutoRuleGroupsByStatus(groups, false), false);\n\
         var hosts = 0;\n\
         for (var i = 0; i < shown.length; i += 1) hosts += shown[i].hosts.length;\n\
         console.log(String(hosts));\n",
        source = repo_file("apps/desktop/qml/lib/pure.js").replace(".pragma library", ""),
        candidates = serde_json::to_string(&candidates)
            .unwrap_or_else(|e| panic!("candidates serialise: {e}")),
    );
    let Some(output) = run_node(&harness) else {
        eprintln!("node not available — skipping the executable list check");
        return;
    };
    let shown: usize = output
        .trim()
        .parse()
        .unwrap_or_else(|e| panic!("harness printed a count: {e}; output: {output}"));
    assert_eq!(counted, 2, "positive control: the fixture mixes both kinds");
    assert_eq!(
        shown, counted,
        "the list's default view and the service's count disagree"
    );
}

/// The group caption and the tray popup read the list's own filter instead of
/// a rule of their own: the caption counted `pendingIds` (hidden hosts
/// included), the popup offered every row the service returned.
#[test]
fn the_group_caption_and_the_tray_popup_read_the_lists_filter() {
    let section = repo_file("apps/desktop/qml/sections/RuleSuggestionsSection.qml");
    assert!(
        section.contains("Pure.countShownPendingAutoRuleHosts(modelData)"),
        "the group caption counts the hosts the card lists"
    );
    assert!(
        !section.contains("\" (\" + modelData.pendingIds.length + \")\""),
        "`pendingIds` holds hosts the default view hides"
    );
    let tray = repo_file("apps/desktop/qml/Tray.qml");
    let prompt = tray
        .split("function _presentAutoRulePrompt(")
        .nth(1)
        .unwrap_or_else(|| panic!("Tray.qml defines _presentAutoRulePrompt"));
    let body = prompt.split("\n    function ").next().unwrap_or(prompt);
    assert!(
        body.contains("Pure.autoRuleRowsShownByDefault(candidates)"),
        "the popup chooses only from rows the list shows by default"
    );
}

/// Executable half of the above, through the real `pure.js`.
#[test]
fn the_caption_and_the_popup_leave_out_what_the_list_hides() {
    let candidates = vec![
        candidate("arc-1", "assets.site-cdn.example", false),
        candidate("arc-2", "img.site-cdn.example", true),
        candidate("arc-3", "tracker.example", true),
        candidate("arc-4", "video.example", false),
    ];
    let expected_popup: Vec<&str> = candidates
        .iter()
        .filter(|c| !c.served_by_main_link)
        .map(|c| c.id.as_str())
        .collect();
    let harness = format!(
        "{source}\n\
         var rows = {candidates};\n\
         var groups = filterAutoRuleGroupsServedByMainLink(\n\
             filterAutoRuleGroupsByStatus(groupAutoRuleRows(rows, []), false), false);\n\
         var mixed = groups.filter(function(g) {{ return g.domain === 'site-cdn.example' }})[0];\n\
         var shownAll = filterAutoRuleGroupsServedByMainLink(\n\
             filterAutoRuleGroupsByStatus(groupAutoRuleRows(rows, []), false), true)\n\
             .filter(function(g) {{ return g.domain === 'site-cdn.example' }})[0];\n\
         console.log(JSON.stringify({{\n\
             caption: countShownPendingAutoRuleHosts(mixed),\n\
             ids: mixed.pendingIds.length,\n\
             captionShowingAll: countShownPendingAutoRuleHosts(shownAll),\n\
             popup: autoRuleRowsShownByDefault(rows).map(function(r) {{ return r.id }}),\n\
             empty: autoRuleRowsShownByDefault(null).length\n\
         }}));\n",
        source = repo_file("apps/desktop/qml/lib/pure.js").replace(".pragma library", ""),
        candidates = serde_json::to_string(&candidates)
            .unwrap_or_else(|e| panic!("candidates serialise: {e}")),
    );
    let Some(output) = run_node(&harness) else {
        eprintln!("node not available — skipping the executable caption check");
        return;
    };
    let got: serde_json::Value = serde_json::from_str(output.trim())
        .unwrap_or_else(|e| panic!("harness printed JSON: {e}; output: {output}"));
    assert_eq!(got["ids"], 1, "the hidden host's id leaves with the host");
    assert_eq!(got["caption"], 1, "the caption counts only the shown host");
    assert_eq!(
        got["captionShowingAll"], 2,
        "with the toggle on, the caption counts what the card then lists"
    );
    assert_eq!(got["popup"], serde_json::json!(expected_popup));
    assert_eq!(got["empty"], 0);
}

/// The card's "Add" / "Don't suggest again" / "Delete" and the selection panel
/// act on the group's id lists; a host the list hides must not ride along.
#[test]
fn a_groups_actions_carry_only_the_hosts_the_list_shows() {
    let candidates = vec![
        candidate("arc-1", "assets.site-cdn.example", false),
        candidate("arc-2", "img.site-cdn.example", true),
    ];
    let dismissed = serde_json::json!([{
        "candidate-id": "arc-5",
        "anchor": "site.example",
        "proposed-match": "old.site-cdn.example",
        "dismissed-at-unix-ms": 3
    }]);
    let harness = format!(
        "{source}\n\
         var groups = groupAutoRuleRows({candidates}, {dismissed});\n\
         function ids(showDismissed, showServed) {{\n\
             var g = filterAutoRuleGroupsServedByMainLink(\n\
                 filterAutoRuleGroupsByStatus(groups, showDismissed), showServed)[0];\n\
             return {{ pending: g.pendingIds, dismissed: g.dismissedIds }};\n\
         }}\n\
         console.log(JSON.stringify({{\n\
             merged: groups[0].pendingIds,\n\
             byDefault: ids(false, false),\n\
             withDismissed: ids(true, false),\n\
             withServed: ids(true, true)\n\
         }}));\n",
        source = repo_file("apps/desktop/qml/lib/pure.js").replace(".pragma library", ""),
        candidates = serde_json::to_string(&candidates)
            .unwrap_or_else(|e| panic!("candidates serialise: {e}")),
    );
    let Some(output) = run_node(&harness) else {
        eprintln!("node not available — skipping the executable group-actions check");
        return;
    };
    let got: serde_json::Value = serde_json::from_str(output.trim())
        .unwrap_or_else(|e| panic!("harness printed JSON: {e}; output: {output}"));
    assert_eq!(
        got["merged"],
        serde_json::json!(["arc-1", "arc-2"]),
        "positive control: the unfiltered group holds the served host"
    );
    assert_eq!(
        got["byDefault"],
        serde_json::json!({ "pending": ["arc-1"], "dismissed": [] })
    );
    assert_eq!(
        got["withDismissed"],
        serde_json::json!({ "pending": ["arc-1"], "dismissed": ["arc-5"] })
    );
    assert_eq!(
        got["withServed"],
        serde_json::json!({ "pending": ["arc-1", "arc-2"], "dismissed": ["arc-5"] }),
        "with the toggle on, the served host is shown and acted on again"
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
