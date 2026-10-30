#![allow(clippy::expect_used)]

//! A non-technical user lost their way in the first-run window: eight
//! questions on one long scrolling page. The window asks one thing per page,
//! in the terminal setup's order, and a window reopened from Settings is a new
//! run: an earlier "later" or an earlier protection write must not make it
//! skip a question or drop the protection chosen this time. Runs the window's
//! own functions.

#[path = "support/first_run.rs"]
mod first_run;

/// The pages in the order they are shown, as the terminal setup numbers them.
#[test]
fn the_pages_come_in_the_setup_order() {
    let output = first_run::run(
        "for (var i = 0; i < stepCount; i += 1) console.log(String(_stepTitle(i)));",
    );
    let pages: Vec<&str> = output.lines().collect();
    assert_eq!(
        pages,
        [
            "Main connection",
            "Additional connection (e.g. VPN)",
            "Starting rules",
            "Protection and options",
            "Ready to finish",
        ]
    );
}

/// A second run from Settings: the last run deferred the additional
/// connection and wrote "Routed sites"; this one starts on the first page,
/// asks the additional connection again, and writes the level chosen now.
#[test]
fn a_reopened_window_asks_everything_again_and_writes_its_protection() {
    let output = first_run::run(
        "rows = [wire('eth', 'Ethernet', {})];\n\
         rows[0].selectedRole = 'primary';\n\
         root._serviceRoutePolicy = { 'leak-protection': 'sites', 'doh-lockdown-auto': true };\n\
         // The first run.\n\
         _seedProtection();\n\
         step = 4; secondaryDeferred = true;\n\
         _commitRun();\n\
         // Reopened from Settings.\n\
         _startRun();\n\
         console.log('page ' + step + ' deferred ' + secondaryDeferred);\n\
         _seedProtection();\n\
         _protectionTouched = true; wantLeakProtection = 'everything';\n\
         _commitRun();",
    );
    assert!(output.contains("page 0 deferred false"), "{output}");
    assert!(
        output.contains("protection everything true"),
        "the second run's protection never reached the service:\n{output}"
    );
}
