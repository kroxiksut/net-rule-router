//! After a full reset on the owner's test machine, the red "Revoke
//! administrator approval" button appeared in the sidebar of a window that
//! held no administrator rights: the reset's service step went through the
//! broker, and that success alone set the flag the button shows by. The
//! broker's own answer is the one source: a success only asks it.

#[path = "support/js.rs"]
mod js;
#[path = "support/qml_functions.rs"]
mod qml_functions;

use std::path::Path;

/// Places in `source` that call a session elevated without the broker's word.
fn assumed_elevation(source: &str) -> Vec<usize> {
    source
        .lines()
        .enumerate()
        .filter(|(_, line)| {
            let code = line.split("//").next().unwrap_or_default();
            code.contains("_brokerSessionElevated = true")
        })
        .map(|(at, _)| at + 1)
        .collect()
}

#[test]
fn only_the_brokers_answer_shows_the_revoke_button() {
    let mut faults = Vec::new();
    let mut stack = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("../qml")];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        for path in entries.flatten().map(|e| e.path()) {
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "qml") {
                let source = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
                for line in assumed_elevation(&source) {
                    faults.push(format!("{}:{line}", path.display()));
                }
            }
        }
    }
    assert!(faults.is_empty(), "{}", faults.join("\n"));
}

#[test]
fn a_success_through_the_broker_asks_the_broker() {
    let program = [
        "var window = { _brokerSessionElevated: false,",
        "    refreshBackendStatus: function() { console.log('broker asked') } };",
        "var reviewFlowController = { _isAppElevated: function() { return false } };",
        &qml_functions::functions("Main.qml", &["onBrokerSessionEstablished"]),
        "onBrokerSessionEstablished();",
        "console.log('button ' + window._brokerSessionElevated);",
    ]
    .join("\n");
    let output = js::run_js(&program);
    assert!(output.contains("broker asked"), "{output}");
    assert!(output.contains("button false"), "{output}");
}

#[test]
fn a_flag_set_without_the_broker_is_caught() {
    let old = "function onBrokerSessionEstablished() {\n    if (!x) window._brokerSessionElevated = true\n}\n";
    assert_eq!(assumed_elevation(old), vec![2]);
}
