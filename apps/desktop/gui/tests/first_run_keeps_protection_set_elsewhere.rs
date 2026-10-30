//! A user who set protection up in the terminal and then opens the window
//! for the first time must not have it lowered by closing the first-run
//! setup. The window starts from what the service holds and writes only what
//! changed, through the decision it shares with the terminal setup
//! (`route_policy::first_run_writes`, vectors in `first_run_writes.json`).
//! Runs the window's own functions against a stand-in window.
#![allow(clippy::expect_used)]

#[path = "support/first_run.rs"]
mod first_run;

/// Set up in the terminal: everything held, browser lockdown off.
const SET_UP: &str = "rows = [wire('eth', 'Ethernet', {})];\n\
    rows[0].selectedRole = 'primary';\n\
    root._serviceRoutePolicy = { 'leak-protection': 'everything',\n\
        'doh-lockdown-auto': false, 'doh-lockdown-enabled': false };\n\
    _seedProtection();";

#[test]
fn the_wizard_starts_from_what_the_service_holds_and_closing_lowers_nothing() {
    let output = first_run::run(&format!(
        "{SET_UP}\n\
         console.log('shown ' + leakProtectionChoice + ' ' + wantDohLockdown);\n\
         step = 4;\n\
         _saveProtection();\n\
         _commitRun();"
    ));
    assert!(output.contains("shown everything false"), "{output}");
    assert!(
        !output.contains("protection "),
        "closing the window rewrote the protection set elsewhere:\n{output}"
    );
    assert!(!output.contains("stability "), "{output}");
}

#[test]
fn a_choice_made_here_is_written() {
    let output = first_run::run(&format!(
        "{SET_UP}\n\
         _protectionTouched = true; wantLeakProtection = 'sites';\n\
         _commitRun();"
    ));
    assert!(output.contains("protection sites false"), "{output}");
}

/// A user already set up who changes only the log window must not have
/// fake-IP switched on by the window's offer.
#[test]
fn fake_ip_is_written_only_when_the_shared_decision_says_so() {
    let output = first_run::run(&format!(
        "{SET_UP}\n\
         _stabilityTouched = true; wantDiagnosticLogs = true;\n\
         _commitRun();"
    ));
    let stability = output
        .lines()
        .find(|l| l.starts_with("stability "))
        .expect("the log window was written");
    assert!(stability.contains("verbose-logging-change"), "{stability}");
    assert!(!stability.contains("fake-ip-enabled"), "{stability}");

    // A new user gets the offer: fake-IP on, protection written.
    let output = first_run::run(
        "rows = [wire('eth', 'Ethernet', {})];\n\
         _seedProtection();\n\
         _commitRun();",
    );
    assert!(output.contains("protection sites true"), "{output}");
    assert!(output.contains("\"fake-ip-enabled\":true"), "{output}");
}

/// Before the service answered, a user already set up cannot be told from a
/// new one: nothing is written until its first policy read.
#[test]
fn before_the_service_answers_the_write_waits_for_it() {
    let output = first_run::run(
        "rows = [wire('eth', 'Ethernet', {})];\n\
         root._servicePolicyRead = false;\n\
         _commitRun();\n\
         console.log('-- read');\n\
         root._servicePolicyRead = true;\n\
         root._serviceRoutePolicy = { 'leak-protection': 'everything' };\n\
         _onServicePolicyRead();",
    );
    let read = output.find("-- read").expect("marker");
    assert!(
        !output[..read].contains("protection ") && !output[..read].contains("stability "),
        "{output}"
    );
    assert!(
        !output.contains("protection sites"),
        "the offer was written over the service's policy:\n{output}"
    );
}
