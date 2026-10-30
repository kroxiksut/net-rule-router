//! The first-run window keeps what the user chose there: the additional
//! connection picked in its list (a VPN adapter is normally down at setup),
//! the country the system is set to whatever its display language, and every
//! bundled rule set within reach. Runs the real `pure.js`.

#[path = "support/js.rs"]
mod js;

use std::path::{Path, PathBuf};

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

fn wizard() -> String {
    repo_file("apps/desktop/qml/components/FirstRunWindow.qml")
}

fn pure_with(harness: &str) -> String {
    format!(
        "{}\n{harness}\n",
        repo_file("apps/desktop/qml/lib/pure.js").replace(".pragma library", "")
    )
}

/// The rows as the window holds them: an Ethernet main link and a VPN adapter
/// that is down because the VPN is not connected yet.
const ROWS: &str = "var rows = [\
    { persistentId: 'eth', name: 'Ethernet', availability: 'available', selectedRole: 'primary' },\
    { persistentId: 'tap', name: 'VPN', availability: 'unavailable', selectedRole: '' }];";

#[test]
fn a_vpn_adapter_picked_while_down_is_committed_when_the_window_closes() {
    let output = js::run_js(&pure_with(&format!(
        "{ROWS}\n\
         console.log(firstRunPickToCommit(rows, 'secondary', 'tap'));\n\
         // The list was rebuilt after the pick: found again by its identity.\n\
         console.log(firstRunPickToCommit(rows.slice().reverse(), 'secondary', 'tap'));\n\
         // Known only by name (no id), as some adapters report.\n\
         console.log(firstRunPickToCommit([{{ persistentId: '', name: 'VPN', selectedRole: '' }}], 'secondary', 'VPN'));"
    )));
    assert_eq!(output, "1\n0\n0\n", "{output}");
}

#[test]
fn a_pick_is_not_committed_over_a_settled_role_or_onto_the_other_one() {
    let output = js::run_js(&pure_with(&format!(
        "{ROWS}\n\
         // Nothing picked.\n\
         console.log(firstRunPickToCommit(rows, 'secondary', ''));\n\
         // The adapter left the computer since.\n\
         console.log(firstRunPickToCommit(rows, 'secondary', 'gone'));\n\
         // It holds the main role: one adapter cannot carry both.\n\
         console.log(firstRunPickToCommit(rows, 'secondary', 'eth'));\n\
         // The role is already assigned: the button's answer stands.\n\
         console.log(firstRunPickToCommit(rows, 'primary', 'tap'));"
    )));
    assert_eq!(output, "-1\n-1\n-1\n-1\n", "{output}");
}

/// The rule sets sit above the protection choice: a rule-set button that
/// closed the window skipped a question the user had not seen yet. Only the
/// one Finish button at the bottom closes it, and nothing is imported before.
#[test]
fn a_rule_set_button_marks_its_choice_and_only_finish_closes_the_window() {
    let source = wizard();
    let closes: Vec<usize> = source
        .match_indices("firstRunWindow.close()")
        .map(|(at, _)| at)
        .collect();
    assert_eq!(closes.len(), 1, "one way to close from inside: {closes:?}");
    let finish = source
        .find("root.tr(\"action.finish\", \"Finish\")")
        .expect("a Finish button");
    let last_section = source
        .find("dialog.first-run-wizard.protection-title")
        .expect("protection");
    assert!(finish > last_section, "Finish comes after the protection");
    assert!(
        closes[0] > finish,
        "the Finish button is the one that closes"
    );
    let imports = source
        .match_indices("ReviewFlow(")
        .map(|(at, _)| at)
        .collect::<Vec<_>>();
    let starter = source
        .find("function _startChosenRules()")
        .expect("_startChosenRules");
    let starter_end = starter + source[starter..].find("\n    }\n").expect("end");
    assert!(
        imports.iter().all(|&at| at > starter && at < starter_end),
        "rules are imported only when the window closes"
    );
    assert!(source.contains("dialog.first-run-wizard.rule-set-chosen"));
}

#[test]
fn a_chosen_additional_connection_that_is_down_is_shown_as_not_connected_yet() {
    let source = wizard();
    assert!(source.contains("dialog.first-run-wizard.secondary-adapter-assigned-down"));
    for locale in ["locales/en.json", "locales/ru.json"] {
        assert!(
            repo_file(locale).contains("\"secondary-adapter-assigned-down\""),
            "{locale} lacks secondary-adapter-assigned-down"
        );
    }
}

#[test]
fn the_country_comes_from_the_system_region_not_the_display_language() {
    let source = wizard();
    let detect = &source[source
        .find("function _detectCountryPreset()")
        .expect("_detectCountryPreset")..];
    let detect = &detect[..detect.find("\n    }\n").expect("end of function")];
    assert!(detect.contains("Pure.firstRunCountry("), "{detect}");
    assert!(detect.contains("systemRegion"), "{detect}");
    assert!(repo_file("apps/desktop/gui/src/ui_surface.rs").contains("\"systemRegion\""));
}

#[test]
fn every_bundled_rule_set_stays_within_reach() {
    let source = wizard();
    assert!(
        source.contains("listAllPresets("),
        "the window lists every bundled set, not only the detected country's"
    );
    assert!(source.contains("dialog.first-run-wizard.other-countries"));
}

/// The text of the object opened at `open` (its `{`), braces inside strings
/// and comments skipped.
fn object_at(source: &str, open: usize) -> &str {
    let bytes = source.as_bytes();
    let (mut depth, mut i, mut quote) = (0usize, open, None::<u8>);
    while i < bytes.len() {
        let c = bytes[i];
        if let Some(q) = quote {
            if c == b'\\' {
                i += 1;
            } else if c == q {
                quote = None;
            }
        } else if c == b'"' || c == b'\'' {
            quote = Some(c);
        } else if c == b'/' && bytes.get(i + 1) == Some(&b'/') {
            i += source[i..].find('\n').unwrap_or(source.len() - i);
            continue;
        } else if c == b'{' {
            depth += 1;
        } else if c == b'}' {
            depth -= 1;
            if depth == 0 {
                return &source[open..=i];
            }
        }
        i += 1;
    }
    panic!("unbalanced object at {open}")
}

fn wizard_scroller(source: &str) -> (usize, &str) {
    let id = source
        .find("id: wizardScroller")
        .unwrap_or_else(|| panic!("the scrolling area is gone"));
    let open = source[..id]
        .rfind("ScrollView {")
        .unwrap_or_else(|| panic!("the scrolling area is no ScrollView"))
        + "ScrollView ".len();
    (open, object_at(source, open))
}

/// Finish sat at the bottom of the scrolled content: a user who closed the
/// window without scrolling never saw it or the questions above it. It lives
/// in a bar pinned under the scrolling area, always in view, and says what it
/// does.
#[test]
fn finish_stays_in_view_outside_the_scrolling_area() {
    let source = wizard().replace("\r\n", "\n");
    let (open, scroller) = wizard_scroller(&source);
    let finish = source
        .find("root.tr(\"action.finish\", \"Finish\")")
        .expect("a Finish button");
    assert!(
        finish > open + scroller.len(),
        "Finish is outside the scrolling area"
    );
    assert!(
        scroller.contains("bottom: finishBar.top"),
        "the scrolling area ends where the Finish bar starts"
    );
    let bar = source.find("id: finishBar").expect("a Finish bar");
    let bar_open = source[..bar].rfind('{').expect("bar object");
    let bar_text = object_at(&source, bar_open);
    assert!(bar_text.contains("bottom: parent.bottom"), "{bar_text}");
    assert!(bar_text.contains("action.finish"), "{bar_text}");
    assert!(
        bar_text.contains("dialog.first-run-wizard.finish-hint"),
        "{bar_text}"
    );
    for locale in ["locales/en.json", "locales/ru.json"] {
        assert!(
            repo_file(locale).contains("\"finish-hint\""),
            "{locale} lacks finish-hint"
        );
    }
}

/// Nothing showed that more settings sat below the fold: the scrollbar is
/// drawn for as long as the content is taller than the window, and only then.
#[test]
fn the_scrollbar_is_shown_while_the_content_overflows() {
    let source = wizard().replace("\r\n", "\n");
    let (_, scroller) = wizard_scroller(&source);
    let bar = scroller
        .find("ScrollBar.vertical: ScrollBar {")
        .expect("an explicit vertical scrollbar");
    let bar = &scroller[bar..];
    assert!(
        bar.contains("visible: wizardScroller.contentHeight > wizardScroller.availableHeight")
            && bar.contains("ScrollBar.AlwaysOn"),
        "{bar}"
    );
}

/// The country comes from the system's region setting, and the line under the
/// country set says so, not "the OS locale".
#[test]
fn the_country_line_names_the_region_setting() {
    for (locale, stale) in [("locales/en.json", "locale"), ("locales/ru.json", "локали")] {
        let text = repo_file(locale);
        let line = text
            .lines()
            .find(|l| l.contains("\"option-country-preset-description\""))
            .unwrap_or_else(|| panic!("{locale} lacks the line"));
        assert!(!line.contains(stale), "{locale}: {line}");
    }
    assert!(!wizard().contains("Detected from your OS locale"));
}

/// The `ThemedButton` whose caption names `caption_key`.
fn button_with<'a>(source: &'a str, caption_key: &str) -> &'a str {
    let caption = source
        .find(caption_key)
        .unwrap_or_else(|| panic!("{caption_key} is gone"));
    let open = source[..caption]
        .rfind("ThemedButton {")
        .unwrap_or_else(|| panic!("{caption_key} is no button"))
        + "ThemedButton ".len();
    object_at(source, open)
}

/// The owner pressed the region's set and saw nothing happen: the choice was
/// only written in a line far below. The pressed option itself must read as
/// chosen — to the eye and to a screen reader — and only that one.
#[test]
fn the_chosen_rule_set_is_marked_on_the_option_itself() {
    let whole = wizard().replace("\r\n", "\n");
    let source = &whole[whole.find("ScrollView {").expect("the layout")..];
    let mut asked = Vec::new();
    for caption in [
        "\"dialog.first-run-wizard.option-country-preset\"",
        "\"action.choose\"",
        "\"dialog.first-run-wizard.option-builtin-demo\"",
        "\"dialog.first-run-wizard.import-button\"",
        "\"dialog.first-run-wizard.option-start-empty\"",
    ] {
        let button = button_with(source, caption);
        let chosen = |binding: &str| {
            let at = button
                .find(binding)
                .unwrap_or_else(|| panic!("{caption}: no {binding}\n{button}"));
            let line = &button[at..];
            let line = &line[..line.find('\n').unwrap_or(line.len())];
            let arg = line.split("_isChosen(").nth(1).unwrap_or_else(|| {
                panic!("{caption}: {binding} is not bound to the choice: {line}")
            });
            arg[..arg.rfind(')').unwrap_or(arg.len())].to_string()
        };
        let shown = chosen("highlighted:");
        assert!(button.contains("Accessible.checkable: true"), "{caption}");
        assert_eq!(chosen("Accessible.checked:"), shown, "{caption}");
        assert!(
            button.contains("uiIconSourceOnAccent(\"apply\")"),
            "{caption}: the chosen option carries no mark"
        );
        asked.push(shown);
    }
    // Every option asks about a choice of its own.
    let distinct: std::collections::BTreeSet<_> = asked.iter().collect();
    assert_eq!(distinct.len(), asked.len(), "{asked:?}");
    // The keys the options ask about are the keys the choosers record.
    let chooser = &whole[whole.find("function _isChosen(").expect("_isChosen")..];
    let chooser = &chooser[..chooser.find("\n    }\n").expect("end")];
    assert!(chooser.contains("chosenStart.key"), "{chooser}");
    for literal in asked.iter().filter(|a| a.starts_with('"')) {
        assert!(
            whole.matches(literal.as_str()).count() >= 2,
            "nothing records the choice {literal}"
        );
    }
    let records = whole.matches("chosenStart = {").count();
    let keyed = whole.matches("chosenStart = { key:").count();
    assert_eq!(records, keyed, "a choice recorded without its key");
    // The other country's button says what it does now: it chooses.
    assert!(!source.contains("rules.bundled-preset.load"));
}

/// The line that names the choice sits right under the options and stands out:
/// a grey footnote under a long list was the only sign anything happened.
#[test]
fn the_choice_line_follows_the_options_and_stands_out() {
    let whole = wizard().replace("\r\n", "\n");
    let source = &whole[whole.find("ScrollView {").expect("the layout")..];
    let last_option = source
        .find("dialog.first-run-wizard.option-start-empty-description")
        .expect("the last option");
    let line = source
        .find("dialog.first-run-wizard.rule-set-chosen")
        .expect("the choice line");
    let protection = source
        .find("dialog.first-run-wizard.protection-title")
        .expect("protection");
    assert!(last_option < line && line < protection);
    let frame = source[..line]
        .rfind("id: ruleSetChoiceLine")
        .expect("the choice line has its own frame");
    assert!(frame > last_option, "the frame is the choice line's own");
    assert!(
        !source[last_option..frame].contains("root.tr("),
        "something else sits between the options and the choice line"
    );
    let open = source[..frame].rfind('{').expect("frame object");
    let frame = object_at(source, open);
    assert!(frame.contains("border.color"), "{frame}");
    assert!(frame.contains("colorAccent"), "{frame}");
    assert!(frame.contains("uiIconSource(\"apply\")"), "{frame}");
}

/// The import runs after the window has closed; a set that then fails to
/// import must say so in a window, not only in the status bar.
#[test]
fn a_starting_set_that_fails_at_finish_says_so() {
    let source = wizard();
    let starter = &source[source
        .find("function _startChosenRules()")
        .expect("_startChosenRules")..];
    let starter = &starter[..starter.find("\n    }\n").expect("end")];
    // Both imports go out with the options, which are not hydration.
    assert!(
        starter.contains("var opts = { label: c.label, confirmed: true }"),
        "{starter}"
    );
    assert_eq!(starter.matches(", opts)").count(), 2, "{starter}");
    let flows = repo_file("apps/desktop/qml/flows/PresetImportController.qml");
    let report = &flows[flows
        .find("function _reportImportFailure(")
        .expect("_reportImportFailure")..];
    let report = &report[..report.find("\n    }\n").expect("end")];
    assert!(
        report.contains("options.hydration === true") && report.contains("showNotice("),
        "only hydration stays out of the box:\n{report}"
    );
    for flow in [
        "function startPresetImportReviewFlow(",
        "function startBothRoutesPresetImportReviewFlow(",
    ] {
        let body = &flows[flows.find(flow).expect(flow)..];
        let body = &body[..body.find("\n    }\n").expect("end")];
        assert!(
            !body.contains("root.statusLine ="),
            "{flow}: a failure only reaches the status bar"
        );
        // No bridge, a failed dry run, and a refusal of the set.
        assert!(
            body.matches("_reportImportFailure(").count() >= 2
                && body.contains("_announcePreviewRefusal(summary, options)"),
            "{flow}: not every failure is reported"
        );
    }
}

#[test]
fn the_rule_sets_follow_the_connections_and_precede_the_protection() {
    let whole = wizard();
    // The window's layout, in the order it is shown and tabbed through.
    let source = &whole[whole.find("ScrollView {").expect("the layout")..];
    let at = |needle: &str| {
        source
            .find(needle)
            .unwrap_or_else(|| panic!("{needle} is gone"))
    };
    let vpn = at("dialog.first-run-wizard.secondary-adapter-vpn-setup");
    let rules = at("dialog.first-run-wizard.option-country-preset\"");
    let protection = at("dialog.first-run-wizard.protection-title");
    assert!(vpn < rules && rules < protection);
}
