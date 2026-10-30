#![allow(clippy::expect_used)]

//! Every way out of the first-run window commits what was chosen there. That
//! made three promises easy to break: a connection the user never saw must
//! not become a binding, one adapter must never be picked for both routes,
//! and the starting rules must not run before the protection chosen with
//! them. Runs the window's own functions against a stand-in window.

#[path = "support/first_run.rs"]
mod first_run;

/// An Ethernet main link and a connected VPN.
const MACHINE: &str = "rows = [wire('eth', 'Ethernet', {}), tunnel('tun', 'VPN', {})];";

/// X on the first page: the main link the user saw is bound, the VPN that
/// would have been suggested on the next page is not.
#[test]
fn closing_on_the_first_page_binds_nothing_the_user_did_not_see() {
    let output = first_run::run(&format!(
        "{MACHINE}\n\
         _suggestPicks();\n\
         _commitRun();"
    ));
    assert!(output.contains("assign primary eth"), "{output}");
    assert!(
        !output.contains("assign secondary"),
        "an additional connection the user never saw was bound:\n{output}"
    );
}

/// On its own page the VPN is suggested, and closing there binds it.
#[test]
fn the_additional_connection_is_suggested_on_its_own_page() {
    let output = first_run::run(&format!(
        "{MACHINE}\n\
         _suggestPicks();\n\
         step = 1;\n\
         _suggestPicks();\n\
         _commitRun();"
    ));
    assert!(output.contains("assign primary eth"), "{output}");
    assert!(output.contains("assign secondary tun"), "{output}");
}

/// A VPN holding the only default route reads as the main link and as the
/// tunnel: it is suggested for one route, never for both.
#[test]
fn a_tunnel_holding_the_only_default_route_is_not_suggested_twice() {
    let output = first_run::run(
        "rows = [tunnel('tun', 'VPN', { 'has-default-route': true,\n\
             'recommendation': { 'class': 'preferred-primary' } })];\n\
         _suggestPicks();\n\
         step = 1;\n\
         _suggestPicks();\n\
         console.log('picks ' + pickedPrimaryKey + '|' + pickedSecondaryKey);\n\
         _commitRun();",
    );
    assert!(output.contains("picks tun|\n"), "{output}");
    assert_eq!(
        output.matches("assign ").count(),
        1,
        "one adapter was bound for both routes:\n{output}"
    );
}

/// The other route's pick is not listed, and picking it anyway moves it.
#[test]
fn one_adapter_is_never_picked_for_both_routes() {
    let output = first_run::run(&format!(
        "{MACHINE}\n\
         _pick('primary', 'tun');\n\
         console.log('listed ' + _shownInPicker(rows[1], 'secondary') + ' ' + _shownInPicker(rows[0], 'secondary'));\n\
         _pick('secondary', 'tun');\n\
         console.log('picks ' + pickedPrimaryKey + '|' + pickedSecondaryKey);\n\
         console.log(_reviewLines().join('\\n'));\n\
         _commitRun();"
    ));
    assert!(output.contains("listed false true"), "{output}");
    assert!(output.contains("picks |tun"), "{output}");
    assert!(
        output.contains("Your rules are not applied until a main connection is chosen."),
        "the review does not say the rules wait for a main connection:\n{output}"
    );
    assert_eq!(output.matches("assign ").count(), 1, "{output}");
}

/// Leak protection is off until the user's first save. The way out writes
/// the protection before the starting rules go, and the review page already
/// had it written once.
#[test]
fn the_protection_goes_before_the_starting_rules() {
    let output = first_run::run(&format!(
        "{MACHINE}\n\
         _seedProtection();\n\
         chosenStart = {{ key: 'demo', label: 'the demo', route: 'both', primB64: 'cA==', secB64: 'cw==' }};\n\
         step = 4;\n\
         _saveProtection();\n\
         _commitRun();"
    ));
    let protection = output
        .find("protection sites true")
        .expect("the protection was written");
    let rules = output.find("rules the demo").expect("the set was started");
    assert!(protection < rules, "{output}");
    assert_eq!(
        output.matches("protection ").count(),
        1,
        "an unchanged protection was written twice:\n{output}"
    );

    // Closed on the rules page, before the review was reached.
    let output = first_run::run(&format!(
        "{MACHINE}\n\
         _seedProtection();\n\
         step = 2;\n\
         chosenStart = {{ key: 'demo', label: 'the demo', route: 'both', primB64: 'cA==', secB64: 'cw==' }};\n\
         _commitRun();"
    ));
    let protection = output
        .find("protection sites true")
        .expect("the protection was written");
    let rules = output.find("rules the demo").expect("the set was started");
    assert!(protection < rules, "{output}");
}

/// Back from the review to change the protection: the new level is written,
/// and the review calls a level in force only once the service holds it.
#[test]
fn a_protection_changed_after_the_review_is_written_again() {
    let output = first_run::run(&format!(
        "{MACHINE}\n\
         _seedProtection();\n\
         _saveProtection();\n\
         root._serviceRoutePolicy = {{ 'leak-protection': 'sites', 'doh-lockdown-auto': true }};\n\
         console.log(_reviewLines().join('\\n'));\n\
         _protectionTouched = true; wantLeakProtection = 'everything';\n\
         console.log(_reviewLines().join('\\n'));\n\
         _saveProtection();"
    ));
    assert!(output.contains("protection sites true"), "{output}");
    assert!(output.contains("protection everything true"), "{output}");
    assert!(
        output.contains("Leak protection: sites — in force."),
        "{output}"
    );
    assert!(
        output.contains("Leak protection: everything — not in force yet."),
        "{output}"
    );
}

/// The protection write was refused (administrator approval declined): the
/// starting rules must not run without it. The set is held back with a word
/// to the user; a write that lands lets it go after the protection.
#[test]
fn a_protection_that_was_not_saved_holds_the_starting_rules_back() {
    let chosen = "_seedProtection();\n\
         chosenStart = { key: 'demo', label: 'the demo', route: 'both', primB64: 'cA==', secB64: 'cw==' };\n\
         holdWrites = true;\n\
         step = 2;\n\
         _commitRun();\n\
         console.log('-- answered');\n";
    let output = first_run::run(&format!(
        "{MACHINE}\n{chosen}lastWrite.onNotWritten('uac-declined');"
    ));
    assert!(
        !output.contains("rules the demo"),
        "the set went without its protection:\n{output}"
    );
    let told = output
        .lines()
        .find(|l| l.starts_with("notice "))
        .unwrap_or_else(|| panic!("nothing was said:\n{output}"));
    assert!(told.contains("the demo"), "{told}");

    let output = first_run::run(&format!("{MACHINE}\n{chosen}lastWrite.onApplied();"));
    let answered = output.find("-- answered").expect("marker");
    let rules = output
        .find("rules the demo")
        .expect("the set went once saved");
    assert!(answered < rules, "{output}");
}

/// A VPN program brought up another copy of its driver than the one chosen:
/// the window says so on the page of the role, for a bound adapter and for a
/// pick, and says nothing for a connected one.
#[test]
fn a_dead_copy_of_a_driver_names_its_live_sibling() {
    let output = first_run::run(
        "rows = [wire('eth', 'Ethernet', {}),\n\
             tunnel('tap10', 'Ethernet 10', { 'interface-description': 'TAP-Windows Adapter V9 #10',\n\
                 'availability': 'unavailable' }),\n\
             tunnel('tap15', 'Ethernet 15', { 'interface-description': 'TAP-Windows Adapter V9 #15' })];\n\
         rows[0].selectedRole = 'primary';\n\
         _pick('secondary', 'tap10');\n\
         console.log('picked: ' + _siblingWarning('secondary'));\n\
         rows[1].selectedRole = 'secondary';\n\
         console.log('bound: ' + _siblingWarning('secondary'));\n\
         console.log('main: [' + _siblingWarning('primary') + ']');",
    );
    for line in ["picked: ", "bound: "] {
        let said = output
            .lines()
            .find(|l| l.starts_with(line))
            .unwrap_or_else(|| panic!("{output}"));
        assert!(said.contains("Ethernet 15"), "{output}");
    }
    assert!(output.contains("main: []"), "{output}");
}
