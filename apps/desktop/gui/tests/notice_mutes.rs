//! "Don't show…" on whole notice kinds. The kinds are named three times — the
//! service's `NoticeKind` (which refuses any other slug), the `pure.js` table
//! the windows read, and the tray buttons that offer the mute — and a kind
//! missing from one of them is a button that fails or a mute nobody honours.
//! The executable checks run the real `pure.js`.

#[path = "support/js.rs"]
mod js;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

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
    assert_eq!(domain.len(), 11, "{domain:?}");
    assert_eq!(pure_kinds(), domain);
}

/// Kinds the tray lists in its menu and never raises as a notice: the window's
/// card carries their "Don't show…".
const LISTED_IN_TRAY_MENU_ONLY: [&str; 1] = ["external-address"];

/// Kinds whose card answers "don't report again" itself, for good: the user
/// asked for it in those words, and a duration chooser would ask again.
const MUTED_FOR_GOOD_FROM_ITS_CARD: [&str; 1] = ["site-not-opening"];

#[test]
fn the_tray_offers_the_mute_on_every_kind_and_gates_each_one() {
    let tray = repo_file("apps/desktop/qml/Tray.qml");
    for kind in domain_kinds() {
        if LISTED_IN_TRAY_MENU_ONLY.contains(&kind.as_str()) {
            assert!(
                !tray.contains(&format!("_offerNotice(\"{kind}\"")),
                "{kind} is raised by the tray again: give it its mute back"
            );
            continue;
        }
        let mute_button = if MUTED_FOR_GOOD_FROM_ITS_CARD.contains(&kind.as_str()) {
            format!("_muteNoticeForGood(\"{kind}\")")
        } else {
            format!("_noticeMuteAction(\"{kind}\")")
        };
        assert!(
            tray.contains(&mute_button),
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
    // A kind muted from a tray card stays listed so it can be lifted; the page
    // asks the shared decision rather than filtering by platform alone.
    assert!(
        page.contains("Pure.noticeKindRow(") && !page.contains("kind !== \"site-not-opening\""),
        "the Notifications page decides which kinds to list by itself"
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
    let output = js::run_js(&harness);
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
    let output = js::run_js(&harness);
    assert_eq!(
        output.trim(),
        "[{\"scope\":{\"kind\":\"notice\",\"notice\":\"secondary-down\"},\"until-unix-ms\":604801000},\
         {\"scope\":{\"kind\":\"notice\",\"notice\":\"secondary-down\"}},null,null]",
        "{output}"
    );
}

/// A card that checks its kind's mute on arrival must also carry the kind as
/// `noticeMuteKind`, or a mute set later in the tray or Settings never takes it
/// off the window's notification centre.
#[test]
fn every_mutable_card_names_its_kind_for_withdrawal() {
    let main = repo_file("apps/desktop/qml/Main.qml");
    let marker = "_addPushNoticeUnlessMuted(\"";
    let kinds: Vec<&str> = main
        .match_indices(marker)
        .filter_map(|(at, _)| main[at + marker.len()..].split('"').next())
        .collect();
    assert!(kinds.len() >= 4, "the scan found {kinds:?}");
    for kind in kinds {
        assert!(
            main.lines()
                .any(|line| line.contains("\"noticeMuteKind\"")
                    && line.contains(&format!("\"{kind}\""))),
            "a `{kind}` card is admitted by its mute but never withdrawn by it"
        );
    }
}

/// A mute set in the tray while Settings is still loading the list: the load
/// in flight may predate it, so one more load follows.
#[test]
fn a_mute_change_heard_mid_load_loads_again() {
    let settings = repo_file("apps/desktop/qml/sections/settings/NotificationSettings.qml");
    let load = settings
        .split("function _loadBlockNoticeMutes()")
        .nth(1)
        .expect("the settings page loads the mute list");
    let load = &load[..load.find("\n    function ").unwrap_or(load.len())];
    assert!(
        load.contains("_blockNoticeMutesReloadPending = true"),
        "{load}"
    );
    let callback = load
        .split("registerRpcCallback")
        .nth(1)
        .expect("the load answers in a callback");
    assert!(
        callback.contains("if (group._blockNoticeMutesReloadPending)")
            && callback.contains("group._loadBlockNoticeMutes()"),
        "{callback}"
    );
}
