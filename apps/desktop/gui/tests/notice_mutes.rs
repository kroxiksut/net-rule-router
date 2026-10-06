//! "Don't show…" on whole notice kinds. The kinds are named three times — the
//! service's `NoticeKind` (which refuses any other slug), the `pure.js` table
//! the windows read, and the tray buttons that offer the mute — and a kind
//! missing from one of them is a button that fails or a mute nobody honours.
//! The executable checks run the real `pure.js` through `node`; skipped when
//! node is absent.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

/// The slugs between `start` and the next `end`, each the first quoted string
/// on a line that holds `marker`.
fn quoted_slugs(source: &str, start: &str, end: &str, marker: &str) -> BTreeSet<String> {
    let from = source
        .find(start)
        .unwrap_or_else(|| panic!("{start:?} not found"));
    let block = &source[from..];
    let block = &block[..block.find(end).unwrap_or(block.len())];
    block
        .lines()
        .filter(|line| line.contains(marker))
        .filter_map(|line| line.split('"').nth(1).map(str::to_string))
        .collect()
}

fn domain_kinds() -> BTreeSet<String> {
    let domain = repo_file("core/domain/src/block_notice.rs");
    // BlockReason has a `slug` too; NoticeKind's is the one after its impl.
    let at = domain
        .find("impl NoticeKind")
        .unwrap_or_else(|| panic!("impl NoticeKind not found"));
    quoted_slugs(&domain[at..], "pub fn slug(self)", "\n    }\n", "Self::")
}

fn pure_kinds() -> BTreeSet<String> {
    let pure = repo_file("apps/desktop/qml/lib/pure.js");
    quoted_slugs(&pure, "var MUTABLE_NOTICE_KINDS", "\n}\n", "\": [")
}

#[test]
fn every_notice_kind_is_named_alike_in_the_service_and_the_windows() {
    let domain = domain_kinds();
    assert_eq!(domain.len(), 7, "{domain:?}");
    assert_eq!(pure_kinds(), domain);
}

#[test]
fn the_tray_offers_the_mute_on_every_kind_and_gates_each_one() {
    let tray = repo_file("apps/desktop/qml/Tray.qml");
    for kind in domain_kinds() {
        assert!(
            tray.contains(&format!("_noticeMuteAction(\"{kind}\")")),
            "no \"Don't show…\" button for {kind}"
        );
        let gated = tray.contains(&format!("_offerNotice(\"{kind}\""))
            || tray.contains(&format!("_noticeMutedNow(\"{kind}\")"));
        assert!(gated, "{kind} is offered a mute nothing honours");
    }
}

#[test]
fn settings_lists_every_kind_the_buttons_can_hide() {
    let page = repo_file("apps/desktop/qml/sections/settings/NotificationSettings.qml");
    assert!(
        page.contains("Object.keys(Pure.MUTABLE_NOTICE_KINDS)"),
        "the Notifications page no longer builds its rows from the shared kind table"
    );
    let card = repo_file("apps/desktop/qml/components/NotificationCenterPopup.qml");
    assert!(
        card.contains("muteNoticeFor("),
        "the cards lost their \"Don't show…\""
    );
}

#[test]
fn a_mute_silences_its_own_kind_until_it_lapses() {
    let harness = format!(
        "{source}\n\
         var mutes = [\n\
           {{ scope: {{ kind: 'notice', notice: 'external-address' }} }},\n\
           {{ scope: {{ kind: 'notice', notice: 'rules-drift' }}, 'until-unix-ms': 1000 }},\n\
           {{ scope: {{ kind: 'all' }} }}\n\
         ];\n\
         console.log([noticeKindMuted(mutes, 'external-address', 5),\n\
                      noticeKindMuted(mutes, 'rules-drift', 999),\n\
                      noticeKindMuted(mutes, 'rules-drift', 1000),\n\
                      noticeKindMuted(mutes, 'block-notice-backlog', 5),\n\
                      noticeKindMuted(null, 'external-address', 5)].join(','));\n",
        source = repo_file("apps/desktop/qml/lib/pure.js").replace(".pragma library", ""),
    );
    let Some(output) = run_node(&harness) else {
        eprintln!("node not available — skipping the executable check");
        return;
    };
    assert_eq!(output.trim(), "true,true,false,false,false", "{output}");
}

#[test]
fn the_chooser_answers_become_the_requests_the_service_accepts() {
    let harness = format!(
        "{source}\n\
         console.log(JSON.stringify([\n\
           noticeMuteRequest('secondary-down', '7d', 1000),\n\
           noticeMuteRequest('secondary-down', 'forever', 1000),\n\
           noticeMuteRequest('no-primary-route', '1d', 1000),\n\
           noticeMuteRequest('secondary-down', '2h', 1000)\n\
         ]));\n",
        source = repo_file("apps/desktop/qml/lib/pure.js").replace(".pragma library", ""),
    );
    let Some(output) = run_node(&harness) else {
        eprintln!("node not available — skipping the executable check");
        return;
    };
    assert_eq!(
        output.trim(),
        "[{\"scope\":{\"kind\":\"notice\",\"notice\":\"secondary-down\"},\"until-unix-ms\":604801000},\
         {\"scope\":{\"kind\":\"notice\",\"notice\":\"secondary-down\"}},null,null]",
        "{output}"
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
