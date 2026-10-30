#![allow(clippy::expect_used)]

//! The owner walked the first-run window and found four things in the way:
//! "Set as main" needed an extra Next, a VPN started while the window asked
//! for it went unnoticed, an answer given could not be changed after Back,
//! and on a 1280x720 screen the window ran under the taskbar. Runs the
//! window's own functions against a stand-in window.

#[path = "support/first_run.rs"]
mod first_run;

/// An Ethernet main link, a Wi-Fi link and a VPN adapter that is down.
const MACHINE: &str = "rows = [wire('eth', 'Ethernet', {}), wire('wifi', 'Wi-Fi', {}),\n\
     tunnel('tap', 'VPN', { 'availability': 'unavailable' })];";

/// Pressing "Set as main" answers the page: the window goes on by itself.
/// Picking in the list alone does not.
#[test]
fn set_as_main_goes_on_to_the_additional_connection() {
    let output = first_run::run(&format!(
        "{MACHINE}\n\
         _pick('primary', 'eth');\n\
         console.log('after the pick: page ' + step);\n\
         _assignFromPage('primary', 0);\n\
         console.log('after the press: page ' + step);"
    ));
    assert!(output.contains("after the pick: page 0"), "{output}");
    assert!(output.contains("assign primary eth"), "{output}");
    assert!(
        output.contains("after the press: page 1"),
        "the window waited for Next after \"Set as main\":\n{output}"
    );
}

/// The controller may ask a question first (no way out, say) and the user may
/// decline it: the page stays until the role actually lands.
#[test]
fn a_main_connection_held_by_a_question_moves_on_only_once_it_lands() {
    let output = first_run::run(&format!(
        "{MACHINE}\n\
         var asked = root.interfacesRolesController.assignRole;\n\
         root.interfacesRolesController.assignRole = function() {{ say('asked') }};\n\
         _assignFromPage('primary', 0);\n\
         console.log('while asked: page ' + step);\n\
         rows[0].selectedRole = 'primary';\n\
         _afterAssign();\n\
         console.log('once answered: page ' + step);"
    ));
    assert!(output.contains("while asked: page 0"), "{output}");
    assert!(output.contains("once answered: page 1"), "{output}");
}

/// Back to a page already answered: the answer is shown with a way to change
/// it, the list comes back with the current answer picked, and a new answer
/// replaces it.
#[test]
fn back_to_an_answered_connection_page_gives_the_choice_back() {
    let output = first_run::run(&format!(
        "{MACHINE}\n\
         _assignFromPage('primary', 0);\n\
         step = 0;\n\
         console.log('choosing ' + choosingPrimary);\n\
         _changeChoice('primary');\n\
         console.log('choosing ' + choosingPrimary + ' picked ' + pickedPrimaryKey);\n\
         _pick('primary', 'wifi');\n\
         _assignFromPage('primary', 1);\n\
         console.log('main ' + assignedPrimaryName + ' choosing ' + choosingPrimary + ' page ' + step);\n\
         rows[2].availability = 'available';\n\
         _assignFromPage('secondary', 2);\n\
         console.log('additional ' + assignedSecondaryName + ' choosing ' + choosingSecondary + ' page ' + step);\n\
         _changeChoice('secondary');\n\
         console.log('choosing ' + choosingSecondary + ' picked ' + pickedSecondaryKey);\n\
         _keepChoice('secondary');\n\
         console.log('kept: choosing ' + choosingSecondary);"
    ));
    assert!(output.contains("choosing false\n"), "{output}");
    assert!(
        output.contains("choosing true picked eth"),
        "the current answer is not picked when changing:\n{output}"
    );
    assert!(
        output.contains("main Wi-Fi choosing false page 1"),
        "{output}"
    );
    assert!(
        output.contains("additional VPN choosing false page 1"),
        "the additional page left by itself or kept the list open:\n{output}"
    );
    assert!(output.contains("choosing true picked tap"), "{output}");
    assert!(output.contains("kept: choosing false"), "{output}");
}

/// The user starts the VPN while the additional connection is asked: the
/// adapter that comes up is named as the VPN and set in one press. One that
/// was already up, or the main connection coming back, is not news.
#[test]
fn a_vpn_started_on_the_additional_page_is_noticed() {
    let output = first_run::run(&format!(
        "{MACHINE}\n\
         rows[0].selectedRole = 'primary';\n\
         step = 1;\n\
         _watchAdapters();\n\
         console.log('before [' + justConnectedKey + ']');\n\
         rows[2].availability = 'available';\n\
         _watchAdapters();\n\
         console.log('came up [' + justConnectedKey + ']');\n\
         _watchAdapters();\n\
         console.log('next look [' + justConnectedKey + ']');\n\
         _assignJustConnected();\n\
         _watchAdapters();\n\
         console.log('assigned [' + justConnectedKey + ']');"
    ));
    assert!(output.contains("before []"), "{output}");
    assert!(
        output.contains("came up [tap]"),
        "the VPN that came up was not named:\n{output}"
    );
    assert!(
        output.contains("next look [tap]"),
        "the hint went away on the next look:\n{output}"
    );
    assert!(output.contains("assign secondary tap"), "{output}");
    assert!(output.contains("assigned []"), "{output}");
}

/// Adapters are watched on the additional connection's page only.
#[test]
fn adapters_are_watched_on_the_additional_page_only() {
    let output = first_run::run(&format!(
        "{MACHINE}\n\
         step = 0;\n\
         _watchAdapters();\n\
         rows[2].availability = 'available';\n\
         _watchAdapters();\n\
         console.log('main page [' + justConnectedKey + '] seen ' + (_adaptersSeen !== null));"
    ));
    assert!(output.contains("main page [] seen false"), "{output}");
}

/// "Set up my VPN" is how a user with several VPN programs adds the next one:
/// it stays on the page once an additional connection is set.
#[test]
fn set_up_my_vpn_stays_after_the_additional_connection_is_set() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../qml/components/FirstRunWindow.qml");
    let source = std::fs::read_to_string(&path)
        .expect("the window's source")
        .replace("\r\n", "\n");
    let at = source
        .find("\"dialog.first-run-wizard.secondary-adapter-vpn-setup\"")
        .expect("the Set up my VPN button");
    let gates = enclosing_visibility(&source, at);
    let hidden: Vec<&String> = gates
        .iter()
        .filter(|gate| gate.contains("secondaryAssigned") || gate.contains("choosingSecondary"))
        .collect();
    assert!(
        hidden.is_empty(),
        "the button hides once a VPN is set: {hidden:?}"
    );
}

/// The `visible:` lines of every element enclosing `at`.
fn enclosing_visibility(source: &str, at: usize) -> Vec<String> {
    let bytes = source.as_bytes();
    let mut gates = Vec::new();
    let mut depth = 0i32;
    let mut i = at;
    while i > 0 {
        i -= 1;
        match bytes[i] {
            b'}' => depth += 1,
            b'{' if depth > 0 => depth -= 1,
            b'{' => {
                let body_end = matching_close(source, i);
                let body = &source[i..body_end];
                let mut nested = 0i32;
                for line in body.lines().skip(1) {
                    let trimmed = line.trim_start();
                    if nested == 0 && trimmed.starts_with("visible:") {
                        gates.push(trimmed.to_owned());
                    }
                    nested += line.matches('{').count() as i32 - line.matches('}').count() as i32;
                }
            }
            _ => {}
        }
    }
    gates
}

fn matching_close(source: &str, open: usize) -> usize {
    let mut depth = 0i32;
    for (offset, c) in source[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return open + offset;
                }
            }
            _ => {}
        }
    }
    source.len()
}

/// A 1280x720 screen with a 40 px taskbar: the whole window, title bar and
/// the bar with Back and Next included, sits in the free area; on a large
/// screen it keeps its full size; on a second screen it stays on that screen.
#[test]
fn the_window_fits_the_free_part_of_a_small_screen() {
    let output = first_run::run(
        "function show(g) { console.log(g.x + ' ' + g.y + ' ' + g.width + ' ' + g.height) }\n\
         show(_fitIn({ x: 0, y: 0, width: 1280, height: 680 }, 320, 20));\n\
         show(_fitIn({ x: 0, y: 0, width: 1920, height: 1040 }, 640, 200));\n\
         show(_fitIn({ x: 1920, y: 0, width: 1280, height: 680 }, 100, 600));",
    );
    let fits: Vec<Vec<i64>> = output
        .lines()
        .map(|l| l.split(' ').map(|n| n.parse().expect("number")).collect())
        .collect();
    let small = &fits[0];
    // The title bar sits above `y`, the frame below `y + height`.
    assert!(small[1] >= 30, "the title bar is off the screen: {small:?}");
    assert!(
        small[1] + small[3] + 8 <= 680,
        "the bottom runs under the taskbar: {small:?}"
    );
    assert!(small[3] >= 480, "the window shrank too far: {small:?}");
    assert_eq!(fits[1][2..], [640, 640], "{output}");
    let second = &fits[2];
    assert!(
        second[0] >= 1920 && second[0] + second[2] <= 1920 + 1280,
        "{second:?}"
    );
    assert!(second[1] + second[3] + 8 <= 680, "{second:?}");
}

/// The main window still settling somewhere off the screen (a field laptop
/// showed the wizard pressed against the right edge): the wizard goes to the
/// middle of the free area; over a main window in place, over its middle.
#[test]
fn a_main_window_off_the_screen_does_not_push_the_wizard_to_the_edge() {
    let output = first_run::run(
        "var area = { x: 0, y: 0, width: 1920, height: 1040 };\n\
         width = 640; height = 640;\n\
         root.x = 2400; root.y = 0; root.width = 1200; root.height = 800;\n\
         _centerIn(area); console.log(x + ' ' + y);\n\
         root.x = 100; root.y = 100;\n\
         _centerIn(area); console.log(x + ' ' + y);",
    );
    assert_eq!(output, "640 80\n380 180\n");
}

/// Back to the rules page: another answer replaces the chosen one, and Finish
/// applies the last one.
#[test]
fn the_starting_rules_applied_are_the_last_ones_chosen() {
    let demo = "_choose('demo', 'the demo', 'cA==', 'cw==', 'p', 's');";
    let output = first_run::run(&format!(
        "{MACHINE}\n_seedProtection();\n{demo}\n_startEmpty();\n_commitRun();"
    ));
    assert!(
        !output.contains("rules "),
        "Finish applied the set the user moved away from:\n{output}"
    );
    let output = first_run::run(&format!(
        "{MACHINE}\n_seedProtection();\n_startEmpty();\n{demo}\n_commitRun();"
    ));
    assert!(output.contains("rules the demo"), "{output}");
}

/// The rules page asks for a decision: Next waits until a set or "Start
/// empty" is chosen, and the options pulse meanwhile. A choice that could not
/// be read is no decision.
#[test]
fn the_rules_page_waits_for_an_explicit_choice() {
    let output = first_run::run(&format!(
        "{MACHINE}
         step = 2;
         console.log('nothing: ' + _nextAllowed() + ' ' + _pulseTarget());
         _choose('demo', 'the demo', '', '', 'p', 's');
         console.log('unreadable: ' + _nextAllowed() + ' ' + _pulseTarget());
         _startEmpty();
         console.log('empty: ' + _nextAllowed() + ' ' + _pulseTarget());"
    ));
    assert!(output.contains("nothing: false rule-options"), "{output}");
    assert!(
        output.contains("unreadable: false rule-options"),
        "{output}"
    );
    assert!(output.contains("empty: true next"), "{output}");
}

/// One thing pulses at a time, the next thing to do: the unanswered page's
/// own button, the VPN that just came up, else Next, and Finish at the end.
#[test]
fn only_the_next_thing_to_do_pulses() {
    let output = first_run::run(&format!(
        "{MACHINE}
         function at(n) {{ step = n; console.log(n + ' ' + _pulseTarget() + ' ' + _nextAllowed()) }}
         at(0);
         rows[0].selectedRole = 'primary';
         at(0);
         at(1);
         justConnectedKey = 'tap';
         at(1);
         secondaryDeferred = true;
         at(1);
         at(3);
         at(4);"
    ));
    let pulses: Vec<&str> = output.lines().collect();
    assert_eq!(
        pulses,
        [
            "0 primary-assign true",
            "0 next true",
            "1 secondary-assign true",
            "1 just-connected true",
            "1 next true",
            "3 next true",
            "4 finish true",
        ],
        "{output}"
    );
}
