//! Launcher-local RPC surface for the "add the console to my PATH" action.
//!
//! The store being read and written is the interactive user's own environment,
//! and the launcher is the only process in the runtime chain that runs AS that
//! user — the background service is `LocalSystem` on Windows and root on Linux,
//! so a registration performed there would land in the wrong account. These two
//! operations therefore never reach the service; the dispatcher answers them in
//! process, exactly as it does for autostart (see [`crate::autostart_local`]).
//!
//! The capability itself lives in [`crate::console_path`]; this module is only
//! the wire adapter — slug matching, payload-free requests, and the JSON shape
//! the Settings panel renders.

use serde_json::{json, Value};

use crate::console_path::{
    console_path_state, register_console_on_path, unregister_console_from_path, ConsolePathState,
};

/// Read the current state without changing anything.
const STATE_OP: &str = "local.console-path.state";

/// Register the console's directory on the user's `PATH`. Idempotent.
const REGISTER_OP: &str = "local.console-path.register";

/// Take our own entry back off it. Idempotent, and it removes only the entry we
/// wrote — a directory someone else put on the list stays there.
const UNREGISTER_OP: &str = "local.console-path.unregister";

/// `true` for the three operations this module answers.
///
/// Matched on every OS: unlike autostart, there is no per-OS split in ownership
/// here — the user's `PATH` belongs to the user's session on every host, so the
/// launcher is the right process everywhere. Hosts with no registration
/// mechanism surface that as an error from the capability itself rather than by
/// silently forwarding to a service that cannot help either.
pub fn is_console_path_op(operation: &str) -> bool {
    operation == STATE_OP || operation == REGISTER_OP || operation == UNREGISTER_OP
}

/// Answer one console-PATH operation. Returns the JSON the Settings panel
/// renders, or an error string the caller maps to a wire response. Only call
/// when [`is_console_path_op`] is true.
///
/// Neither operation reads the payload: the directory to register is derived
/// from where this executable runs, never from the request, so a malformed or
/// hostile payload cannot redirect the write.
pub fn handle_console_path(operation: &str, _payload: &Value) -> Result<Value, String> {
    match operation {
        STATE_OP => Ok(state_to_json(&console_path_state()?)),
        REGISTER_OP => Ok(state_to_json(&register_console_on_path()?)),
        UNREGISTER_OP => Ok(state_to_json(&unregister_console_from_path()?)),
        other => Err(format!("not a console-path op: {other}")),
    }
}

/// Project the capability's state onto the wire.
///
/// Two facts travel, because the panel needs both and they can disagree:
/// `reachable` drives the status line ("would the name work in a new shell"),
/// `ownedEntryPresent` drives the button ("is our entry in our store"). Sending
/// one `registered` flag made the button follow the wrong fact — on Unix a
/// removal leaves this process's inherited `PATH` untouched, so the toggle
/// flipped straight back and read as a failure.
///
/// `targetFile` is `null` wherever the host has a real per-user environment
/// store (Windows): there is no file to name, and the panel's "the line was
/// added to …" hint stays hidden rather than inventing a path.
fn state_to_json(state: &ConsolePathState) -> Value {
    json!({
        "reachable": state.reachable,
        "ownedEntryPresent": state.owned_entry_present,
        "directory": state.directory.display().to_string(),
        "currentSessionCommand": state.current_session_command,
        "targetFile": state
            .target_file
            .as_ref()
            .map(|p| Value::String(p.display().to_string()))
            .unwrap_or(Value::Null),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn recognises_the_three_console_path_ops() {
        assert!(is_console_path_op("local.console-path.state"));
        assert!(is_console_path_op("local.console-path.register"));
        assert!(is_console_path_op("local.console-path.unregister"));
        assert!(!is_console_path_op("local.console-path"));
        assert!(!is_console_path_op("local.service-control"));
        assert!(!is_console_path_op("autostart.get"));
    }

    #[test]
    fn an_unrelated_op_is_declined_by_the_handler_too() {
        // Belt and braces: the dispatcher guards with `is_console_path_op`, but
        // the handler must not silently answer something it was not asked.
        let err = handle_console_path("route.policy.update", &json!({}))
            .expect_err("must decline a foreign op");
        assert!(err.contains("route.policy.update"), "{err}");
    }

    #[test]
    fn a_file_based_state_names_the_file_it_wrote() {
        let state = ConsolePathState {
            directory: PathBuf::from("/opt/netrulerouter/bin"),
            reachable: true,
            owned_entry_present: true,
            current_session_command: "export PATH=\"$PATH:/opt/netrulerouter/bin\"".to_string(),
            target_file: Some(PathBuf::from("/home/u/.bashrc")),
        };
        let value = state_to_json(&state);
        assert_eq!(value["reachable"], json!(true));
        assert_eq!(value["ownedEntryPresent"], json!(true));
        assert_eq!(value["directory"], json!("/opt/netrulerouter/bin"));
        assert_eq!(value["targetFile"], json!("/home/u/.bashrc"));
        assert!(value["currentSessionCommand"]
            .as_str()
            .unwrap_or_default()
            .contains("/opt/netrulerouter/bin"));
    }

    #[test]
    fn an_environment_store_state_sends_a_null_target_file() {
        let state = ConsolePathState {
            directory: PathBuf::from("C:/Program Files/NetRuleRouter"),
            reachable: false,
            owned_entry_present: false,
            current_session_command: "$env:Path += ';C:/Program Files/NetRuleRouter'".to_string(),
            target_file: None,
        };
        let value = state_to_json(&state);
        assert_eq!(value["reachable"], json!(false));
        assert_eq!(value["targetFile"], Value::Null);
    }

    /// The two facts are independent on the wire. Straight after a removal on
    /// Unix this is the REAL state: our entry is gone from the start-up file,
    /// and the directory is still on the PATH this process inherited.
    #[test]
    fn a_removed_entry_can_still_be_reachable_in_this_session() {
        let state = ConsolePathState {
            directory: PathBuf::from("/opt/netrulerouter/bin"),
            reachable: true,
            owned_entry_present: false,
            current_session_command: "export PATH=\"$PATH:/opt/netrulerouter/bin\"".to_string(),
            target_file: Some(PathBuf::from("/home/u/.bashrc")),
        };
        let value = state_to_json(&state);
        assert_eq!(value["reachable"], json!(true));
        assert_eq!(value["ownedEntryPresent"], json!(false));
    }
}
