//! Cross-platform wire types + CLI contract for the launcher ↔ broker
//! local channel. No Win32 here — this module is unit-testable on any OS.
//!
//! ## Frame
//!
//! The broker channel reuses `nrr_ipc_client::wire` (4-byte BE length +
//! UTF-8 JSON). The launcher writes one [`BrokerRequest`] frame and reads
//! one [`BrokerResponse`] frame per connection.
//!
//! ## Authentication
//!
//! Every request carries the session `nonce`. The broker rejects any
//! frame whose nonce does not match the value it read from its token
//! file at startup. This is the third of three owner-binding checks
//! (DACL → PID/SID identity → nonce); see `server.rs`.

use serde::{Deserialize, Serialize};

/// CLI flag that puts the launcher binary into elevated-broker mode.
pub const BROKER_MODE_FLAG: &str = "--nrr-elevated-broker";

const PIPE_FLAG: &str = "--nrr-broker-pipe=";
const PARENT_PID_FLAG: &str = "--nrr-broker-parent-pid=";
const CLIENT_SID_FLAG: &str = "--nrr-broker-client-sid=";
const TOKEN_FILE_FLAG: &str = "--nrr-broker-token-file=";

/// Control operation: liveness probe. Handled inside the broker, never
/// forwarded to the service. Response payload carries `{pid, uptime-ms}`.
pub const BROKER_PING: &str = "broker.ping";

/// Control operation: graceful shutdown. The broker replies `ok` and then
/// retires its accept loop. Handled inside the broker.
pub const BROKER_SHUTDOWN: &str = "broker.shutdown";

/// Control operation: run a privileged service-control action
/// (start/stop/restart/install/uninstall) by executing the service binary
/// subcommand from the already-elevated broker — so the FIRST elevation
/// (an apply OR a service action) covers all later privileged actions, no
/// repeated UAC. Payload: `{ "action": "<verb>", "service-exe-path": "<abs path>" }`.
/// Handled inside the broker (not forwarded to the service over IPC).
pub const BROKER_SERVICE_CONTROL: &str = "broker.service-control";

/// Prefix for all broker-local control operations. Slugs that start with
/// this are handled by the broker itself; everything else is resolved to
/// an `IpcOperationName` and relayed to the service.
pub const BROKER_CONTROL_PREFIX: &str = "broker.";

/// Wire request sent launcher → broker. Argv is avoided for the payload
/// because mutation payloads carry base64 preset bytes (large, arbitrary
/// characters); the whole request is a length-prefixed JSON frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerRequest {
    /// Session nonce — must equal the broker's expected value.
    pub nonce: String,
    /// `IpcOperationName` slug, or a `broker.*` control slug.
    pub operation: String,
    /// Opaque operation payload, forwarded verbatim to the service.
    pub payload: serde_json::Value,
    /// Per-call timeout the broker applies to the service IPC call.
    pub timeout_ms: u64,
}

/// Wire response sent broker → launcher.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrokerResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

impl BrokerResponse {
    /// Build a success response carrying `payload`.
    pub fn ok(payload: serde_json::Value) -> Self {
        Self {
            ok: true,
            payload: Some(payload),
            ..Self::default()
        }
    }

    /// Build an error response with a wire `code` + human `message`.
    pub fn err(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            payload: None,
            error_code: Some(code.into()),
            error_message: Some(message.into()),
        }
    }
}

/// Parsed CLI arguments for the elevated broker process. The launcher
/// constructs the matching argv via [`build_broker_argv`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerServerArgs {
    /// Per-session pipe path (not secret — collision-avoidant only).
    pub pipe_name: String,
    /// PID of the launcher that spawned us. Watched for liveness, and the
    /// only PID allowed to connect.
    pub parent_pid: u32,
    /// String SID the launcher runs under; the only SID allowed to
    /// connect (also encoded into the pipe DACL).
    pub client_sid: String,
    /// Path to the file holding the session nonce. Read once on startup,
    /// then deleted.
    pub token_file: String,
}

impl BrokerServerArgs {
    /// Parse broker-server arguments out of the process argv. Returns
    /// `None` when the mode flag is absent (normal GUI/tray launch) or any
    /// required parameter is missing (treated as not-broker-mode so the
    /// binary falls through to its usual path rather than half-starting).
    pub fn from_cli(args: &[String]) -> Option<Self> {
        if !args.iter().any(|a| a == BROKER_MODE_FLAG) {
            return None;
        }
        let pipe_name = find_value(args, PIPE_FLAG)?;
        let parent_pid = find_value(args, PARENT_PID_FLAG)?.parse().ok()?;
        let client_sid = find_value(args, CLIENT_SID_FLAG)?;
        let token_file = find_value(args, TOKEN_FILE_FLAG)?;
        Some(Self {
            pipe_name,
            parent_pid,
            client_sid,
            token_file,
        })
    }
}

/// Build the argv the launcher passes to the elevated broker. The nonce
/// is intentionally NOT here — it travels through the token file so it
/// never appears in any process-listing of the command line.
pub fn build_broker_argv(
    pipe_name: &str,
    parent_pid: u32,
    client_sid: &str,
    token_file: &str,
) -> Vec<String> {
    vec![
        BROKER_MODE_FLAG.to_string(),
        format!("{PIPE_FLAG}{pipe_name}"),
        format!("{PARENT_PID_FLAG}{parent_pid}"),
        format!("{CLIENT_SID_FLAG}{client_sid}"),
        format!("{TOKEN_FILE_FLAG}{token_file}"),
    ]
}

/// Derive the per-session pipe path. The launcher PID + random suffix keep
/// it unique against a stale broker from a previous run.
pub fn derive_pipe_name(launcher_pid: u32, rand_suffix: &str) -> String {
    format!(r"\\.\pipe\NetRuleRouter\broker-{launcher_pid}-{rand_suffix}")
}

/// True when `slug` is a broker-local control operation.
pub fn is_control_operation(slug: &str) -> bool {
    slug.starts_with(BROKER_CONTROL_PREFIX)
}

fn find_value(args: &[String], prefix: &str) -> Option<String> {
    args.iter()
        .find_map(|a| a.strip_prefix(prefix))
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_ok_omits_error_fields() {
        let json = serde_json::to_string(&BrokerResponse::ok(serde_json::json!({"x": 1}))).unwrap();
        assert!(json.contains("\"ok\":true"));
        assert!(!json.contains("error_code"));
        assert!(!json.contains("error_message"));
    }

    #[test]
    fn response_err_carries_code_and_message() {
        let r = BrokerResponse::err("forbidden", "nope");
        assert!(!r.ok);
        assert_eq!(r.error_code.as_deref(), Some("forbidden"));
        assert_eq!(r.error_message.as_deref(), Some("nope"));
    }

    #[test]
    fn request_round_trips() {
        let req = BrokerRequest {
            nonce: "deadbeef".into(),
            operation: "mutation.submit".into(),
            payload: serde_json::json!({"k": 1}),
            timeout_ms: 30_000,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: BrokerRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.nonce, "deadbeef");
        assert_eq!(back.operation, "mutation.submit");
        assert_eq!(back.timeout_ms, 30_000);
    }

    #[test]
    fn argv_round_trips_through_from_cli() {
        let argv = build_broker_argv(
            r"\\.\pipe\NetRuleRouter\broker-42-aa",
            42,
            "S-1-5-21-1-2-3-1001",
            r"C:\Temp\t.token",
        );
        let parsed = BrokerServerArgs::from_cli(&argv).expect("parse");
        assert_eq!(parsed.parent_pid, 42);
        assert_eq!(parsed.client_sid, "S-1-5-21-1-2-3-1001");
        assert_eq!(parsed.pipe_name, r"\\.\pipe\NetRuleRouter\broker-42-aa");
        assert_eq!(parsed.token_file, r"C:\Temp\t.token");
    }

    #[test]
    fn from_cli_returns_none_without_mode_flag() {
        let argv = vec!["--something-else".to_string()];
        assert!(BrokerServerArgs::from_cli(&argv).is_none());
    }

    #[test]
    fn from_cli_returns_none_with_missing_required_param() {
        // Mode flag present but no pipe/pid/sid/token → not broker mode.
        let argv = vec![BROKER_MODE_FLAG.to_string()];
        assert!(BrokerServerArgs::from_cli(&argv).is_none());
    }

    #[test]
    fn control_operations_are_detected() {
        assert!(is_control_operation(BROKER_PING));
        assert!(is_control_operation(BROKER_SHUTDOWN));
        assert!(!is_control_operation("mutation.submit"));
        assert!(!is_control_operation("route.policy.update"));
    }

    #[test]
    fn derive_pipe_name_is_unique_per_pid_and_suffix() {
        assert_ne!(derive_pipe_name(1, "aa"), derive_pipe_name(2, "aa"));
        assert_ne!(derive_pipe_name(1, "aa"), derive_pipe_name(1, "bb"));
        assert!(derive_pipe_name(7, "zz").starts_with(r"\\.\pipe\NetRuleRouter\broker-7-"));
    }
}
