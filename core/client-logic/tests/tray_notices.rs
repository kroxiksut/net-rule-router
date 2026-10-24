#![allow(clippy::expect_used)]

//! The tray's notice queue and the notice settings it reads from the presence
//! file, run on the real `pure.js`. Each case is a way to lose the user's own
//! answer, or to break the tray with a presence file another process rewrote.

#[allow(dead_code)]
mod js_harness;

use js_harness::JsLib;
use serde_json::{json, Value};

/// Feeds `arrivals` (kind, from the user) to an empty queue with `cap` and
/// returns the kinds left, in order.
fn queue_after(pure: &mut JsLib, arrivals: &[(&str, bool)], cap: u32) -> Vec<String> {
    let list: Vec<Value> = arrivals
        .iter()
        .map(|(kind, user)| json!({ "kind": kind, "user": user }))
        .collect();
    let script = format!(
        "(function() {{ var q = []; {list}.forEach(function(e) {{ q = noticeQueueWith(q, e, {cap}) }}); \
         return q.map(function(n) {{ return n.kind }}) }})()",
        list = Value::Array(list)
    );
    pure.eval_json(&script)
        .as_array()
        .expect("kinds")
        .iter()
        .map(|k| k.as_str().expect("kind").to_owned())
        .collect()
}

/// What each reading of a standing question raises, in order.
fn standing_raises(pure: &mut JsLib, readings: &[&[&str]]) -> Vec<bool> {
    let script = format!(
        "(function() {{ var shown = []; return {readings}.map(function(keys) {{ \
         var step = standingOfferStep(shown, keys); shown = step.shown; return step.raise }}) }})()",
        readings = json!(readings)
    );
    pure.eval_json(&script)
        .as_array()
        .expect("raises")
        .iter()
        .map(|r| r.as_bool().expect("bool"))
        .collect()
}

/// A tray started after the service asked reads the question from the
/// snapshot, and re-reads it after every lost frame: the user is asked once
/// per waiting item, and again only for one that comes back.
#[test]
fn a_standing_question_is_asked_once_per_waiting_item() {
    let mut pure = JsLib::pure();
    assert_eq!(
        standing_raises(
            &mut pure,
            &[
                &["C:\\VPN\\Client.exe"],
                &["c:\\vpn\\client.exe"],
                &["c:\\vpn\\client.exe", "203.0.113.7"],
                &["203.0.113.7"],
                &[],
                &["c:\\vpn\\client.exe"],
            ],
        ),
        [true, false, true, false, false, true]
    );
}

#[test]
fn background_notices_never_push_out_the_users_answer() {
    let mut pure = JsLib::pure();
    let mut flood: Vec<(&str, bool)> = vec![("a", false), ("b", false), ("c", false), ("d", false)];
    flood.push(("pick", true));
    flood.extend([
        ("e", false),
        ("f", false),
        ("g", false),
        ("h", false),
        ("i", false),
    ]);
    assert_eq!(queue_after(&mut pure, &flood, 4), ["pick", "g", "h", "i"]);
}

#[test]
fn the_users_answers_keep_their_order_and_go_first() {
    let mut pure = JsLib::pure();
    let got = queue_after(
        &mut pure,
        &[
            ("bg1", false),
            ("pick1", true),
            ("bg2", false),
            ("pick2", true),
        ],
        4,
    );
    assert_eq!(got, ["pick1", "pick2", "bg1", "bg2"]);
}

/// More of the user's answers than the cap: none is dropped, the cap gives way.
#[test]
fn a_queue_of_answers_only_is_not_cut() {
    let mut pure = JsLib::pure();
    let picks: Vec<(&str, bool)> = ["p1", "p2", "p3", "p4", "p5", "p6"]
        .iter()
        .map(|k| (*k, true))
        .collect();
    assert_eq!(
        queue_after(&mut pure, &picks, 4),
        ["p1", "p2", "p3", "p4", "p5", "p6"]
    );
}

#[test]
fn a_second_notice_of_a_kind_replaces_the_first() {
    let mut pure = JsLib::pure();
    let got = queue_after(
        &mut pure,
        &[("addr", false), ("other", false), ("addr", false)],
        4,
    );
    assert_eq!(got, ["other", "addr"]);
}

/// The notice settings the tray takes from `json`, the text of the presence
/// file's `notices` field as `JSON.parse` reads it.
fn prefs_of(pure: &mut JsLib, json: &str) -> Value {
    let text = serde_json::to_string(json).expect("json");
    pure.eval_json(&format!("trayNoticePrefsOf(JSON.parse({text}))"))
}

const DEFAULTS: &str = r#"{"showNotifications":true,"notifySuggestionChanges":true,"notifyBlockNotices":true,"notifyRuleDuplicates":true,"hideBlockNoticeAddresses":false,"trayNoticeOpacityPercent":100}"#;

/// What another process can leave in the presence file. None of it throws, and
/// none of it turns address hiding on by accident: only `true` hides.
#[test]
fn a_rewritten_presence_file_cannot_break_the_tray() {
    let mut pure = JsLib::pure();
    assert_eq!(pure.eval_json("trayNoticePrefsOf(undefined)"), Value::Null);
    for not_an_object in ["null", "[1, 2]", "\"x\"", "42", "true"] {
        assert_eq!(
            prefs_of(&mut pure, not_an_object),
            Value::Null,
            "{not_an_object}"
        );
    }
    let defaults: Value = serde_json::from_str(DEFAULTS).expect("json");
    assert_eq!(prefs_of(&mut pure, "{}"), defaults);
    let odd = prefs_of(
        &mut pure,
        r#"{"hideBlockNoticeAddresses":"yes","showNotifications":0,"trayNoticeOpacityPercent":"abc","__proto__":{"hideBlockNoticeAddresses":true}}"#,
    );
    assert_eq!(odd["hideBlockNoticeAddresses"], false, "only true hides");
    assert_eq!(odd["showNotifications"], true, "only false silences");
    assert_eq!(odd["trayNoticeOpacityPercent"], 100);
    for (opacity, kept) in [
        ("5", 40),
        ("-3", 40),
        ("70", 70),
        ("250", 100),
        ("\"55abc\"", 55),
    ] {
        let got = prefs_of(
            &mut pure,
            &format!(r#"{{"trayNoticeOpacityPercent":{opacity}}}"#),
        );
        assert_eq!(got["trayNoticeOpacityPercent"], kept, "opacity {opacity}");
    }
    for huge in ["1e9", "1e21", "-1e21", "9007199254740993"] {
        let got = prefs_of(
            &mut pure,
            &format!(r#"{{"trayNoticeOpacityPercent":{huge}}}"#),
        );
        let opacity = got["trayNoticeOpacityPercent"].as_i64().expect("a number");
        assert!(
            (40..=100).contains(&opacity),
            "opacity {huge} gave {opacity}"
        );
    }
}
