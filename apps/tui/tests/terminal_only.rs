#![allow(clippy::expect_used)]

//! A pipe or a script gets a refusal that names the console, never the
//! interface: reading and automation go through `nrr-cli`.

use std::process::{Command, Stdio};

#[test]
fn piped_input_and_output_are_refused_with_a_pointer_to_the_console() {
    let output = Command::new(env!("CARGO_BIN_EXE_nrr-tui"))
        .args(["--lang", "en"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("nrr-tui must start");
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains("nrr-cli"), "{message}");
    assert!(message.contains("interactively"), "{message}");
    assert!(output.stdout.is_empty(), "nothing is drawn into a pipe");
}

#[test]
fn the_refusal_follows_the_language_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_nrr-tui"))
        .args(["--lang", "ru"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("nrr-tui must start");
    assert_eq!(output.status.code(), Some(3));
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains("nrr-cli"), "{message}");
    assert!(message.contains("интерактивно"), "{message}");
}

#[test]
fn an_unknown_option_is_a_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_nrr-tui"))
        .args(["--lang", "en", "--colour"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("nrr-tui must start");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--colour"));
}
