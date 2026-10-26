//! The service starts the tray to say that a site does not open while nothing
//! of the user's runs. That tray shows one card and no icon, reads the flag
//! the service writes, and leaves once the card is answered.

use std::path::{Path, PathBuf};

use nrr_platform_api::session_notice::NOTICE_SITE_FLAG;

fn tray() -> String {
    let path: PathBuf =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../apps/desktop/qml/Tray.qml");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

#[test]
fn the_tray_reads_the_flag_the_service_writes() {
    let source = tray();
    assert!(
        source.contains(&format!("var flag = \"{NOTICE_SITE_FLAG}\"")),
        "Tray.qml does not read `{NOTICE_SITE_FLAG}`: the card would never show"
    );
}

#[test]
fn a_tray_started_for_one_card_shows_no_icon_and_nothing_else() {
    let source = tray();
    assert!(
        source.contains("visible = _noticeSite === \"\""),
        "the tray started for a card shows its icon"
    );
    assert!(
        source.contains(
            "if (_noticeSite !== \"\" && kind !== \"site-not-opening\" && kind !== \"tray-add-rule\") return"
        ),
        "other notices can follow the card"
    );
    assert!(source.contains("if (_noticeSite !== \"\") _showSiteNotice()"));
    assert!(
        source.contains("Qt.quit()") && source.contains("_noticeModeLimitMs"),
        "the tray started for a card never leaves"
    );
}

/// The text from `start` to the first line that closes a block at `indent`.
fn block<'a>(source: &'a str, start: &str, indent: &str) -> &'a str {
    let at = source
        .find(start)
        .unwrap_or_else(|| panic!("{start:?} not in Tray.qml"));
    let rest = &source[at..];
    let end = rest.find(&format!("\n{indent}}}")).unwrap_or(rest.len());
    &rest[..end]
}

/// A running tray that pops the card itself keeps the rule the service keeps
/// before starting a closed one: the mute, one card per half hour, a site
/// once a day unless answered — written where the other tray reads it.
#[test]
fn a_running_tray_holds_its_card_to_the_rule_a_closed_one_keeps() {
    let source = tray();
    let rule = block(&source, "function _siteNoticeDue(host) {", "    ");
    assert!(
        rule.contains("Pure.siteNoticeDue(_noticeMutedNow(\"site-not-opening\")"),
        "the card is not decided by the shared rule:\n{rule}"
    );
    assert!(rule.contains("noticeLedger.decidedAt(_siteShownAnyId)"));
    let popup = block(&source, "if (onlySitesNotOpening) {", "        ");
    assert!(
        popup.contains("tray._siteNoticeDue("),
        "the running tray pops the card past the rule:\n{popup}"
    );
    let card = block(&source, "function _showSiteNotice() {", "    ");
    assert!(
        card.contains("tray._siteNoticeDue(tray._noticeSite)"),
        "the tray started for one card ignores the rule:\n{card}"
    );
    assert!(
        source.matches("_recordSitesShown(").count() >= 3,
        "a card shown on one path is not written for the other"
    );
    assert!(
        source.contains("answered.concat(_siteHostsOnScreen.map(_siteAnsweredId))"),
        "an answer in the running tray is not recorded"
    );
}

/// Every place the offer is worded says only what the probe of the
/// additional route found: it opens there, or it may help.
#[test]
fn the_offer_says_no_more_than_the_additional_route_showed() {
    let source = tray();
    for key in [
        "tray.site-not-opening.body-confirmed",
        "tray.site-not-opening.body-unconfirmed",
    ] {
        assert!(source.contains(key), "the card lost `{key}`");
    }
    let detail = block(&source, "function _candidateDetailLine(c) {", "    ");
    assert!(
        detail.contains("Pure.siteOfferReach(signal, c[\"secondary-reach\"])"),
        "the tray's details do not say what the additional route did"
    );
    let inbox = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../apps/desktop/qml/sections/RuleSuggestionsSection.qml"),
    )
    .unwrap_or_else(|e| panic!("read the suggestions page: {e}"));
    assert!(
        inbox.contains("Pure.siteOfferReach(signal,"),
        "the window's suggestions do not say what the additional route did"
    );
}
