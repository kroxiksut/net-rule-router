//! The starting rule set reaches the service the way the GUI's import sends
//! it: a dry run that says what would change, then the confirmation that
//! carries the dry run's token, then the operation's own verdict.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nrr_ipc_client::{ipc_error_to_wire, ipc_operation_timeout, IpcClient};
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{MutationKind, MutationSubmitRequest, PresetImportPayload};
use serde_json::{json, Value};

use super::presets::RulesFile;
use crate::backend::{Job, Reply};
use crate::state::AppState;

/// How long the confirmation's operation is watched before its effect is
/// judged by a second dry run instead.
const OUTCOME_WAIT: Duration = Duration::from_secs(30);
const OUTCOME_POLL: Duration = Duration::from_millis(250);

/// What the dry run said.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preview {
    pub added: usize,
    pub removed: usize,
    pub changed: usize,
    /// Nothing would change: the rules in force already match.
    pub empty: bool,
    /// The refusal's code when the service would not take these rules.
    pub refused: Option<String>,
    pub token: String,
}

/// The import's payload, kept for the confirmation: it must match the dry run
/// byte for byte, or the token does not fit.
pub fn payload(primary: Option<&RulesFile>, secondary: Option<&RulesFile>) -> Value {
    let request = PresetImportPayload {
        primary_bytes_b64: primary.map(|f| f.base64.clone()),
        secondary_bytes_b64: secondary.map(|f| f.base64.clone()),
        include_child_processes: false,
        // The GUI's default: rules switched off in the file are not imported.
        import_only_active: true,
        correlation_id: Some(correlation_id("first-run")),
        ..PresetImportPayload::default()
    };
    serde_json::to_value(request).unwrap_or(Value::Null)
}

fn correlation_id(what: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("tui-{what}-{}-{nanos}", std::process::id())
}

pub fn preview_job(
    payload: Value,
    done: impl FnOnce(&mut AppState, Result<Preview, String>) + Send + 'static,
) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        let result = submit(client, &payload, None).map(|answer| read_preview(&answer));
        Reply::new(move |app| done(app, result))
    })
}

pub fn apply_job(
    payload: Value,
    token: String,
    done: impl FnOnce(&mut AppState, Result<(), String>) + Send + 'static,
) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        let result = apply(client, &payload, &token);
        Reply::new(move |app| done(app, result))
    })
}

fn apply(client: &dyn IpcClient, payload: &Value, token: &str) -> Result<(), String> {
    let answer = submit(client, payload, Some(token))?;
    let operation = answer
        .get("operation-id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if operation.is_empty() {
        return settle_by_preview(client, payload);
    }
    let op = IpcOperationName::OperationStatusGet;
    let deadline = Instant::now() + OUTCOME_WAIT;
    while Instant::now() < deadline {
        let Ok(status) = client.call(
            op,
            json!({ "operation-id": operation }),
            ipc_operation_timeout(op),
        ) else {
            break;
        };
        match status.get("state").and_then(Value::as_str) {
            Some("completed") => return Ok(()),
            Some("failed") => {
                return Err(status
                    .pointer("/error/code")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string())
            }
            _ => std::thread::sleep(OUTCOME_POLL),
        }
    }
    settle_by_preview(client, payload)
}

/// The import took effect exactly when the same rules now preview as no
/// change — the GUI's fallback when the operation's record says nothing.
fn settle_by_preview(client: &dyn IpcClient, payload: &Value) -> Result<(), String> {
    let mut again = payload.clone();
    if let Some(fields) = again.as_object_mut() {
        fields.insert(
            "correlation-id".into(),
            Value::from(correlation_id("first-run-outcome")),
        );
    }
    let preview = read_preview(&submit(client, &again, None)?);
    match preview.refused {
        Some(code) => Err(code),
        None if preview.empty => Ok(()),
        None => Err("unknown".into()),
    }
}

/// One `mutation.submit`: a dry run without a token, the confirmation with it.
fn submit(client: &dyn IpcClient, payload: &Value, token: Option<&str>) -> Result<Value, String> {
    let request = MutationSubmitRequest {
        mutation_kind: MutationKind::PresetImport,
        payload: payload.clone(),
        dry_run: token.is_none(),
    };
    let mut request =
        serde_json::to_value(request).map_err(|_| "serialization-failed".to_string())?;
    if let (Some(token), Some(fields)) = (token, request.as_object_mut()) {
        // The client lifts this key into the request envelope.
        fields.insert("_envelope_confirmation_token".into(), Value::from(token));
    }
    let op = IpcOperationName::MutationSubmit;
    client
        .call(op, request, ipc_operation_timeout(op))
        .map_err(|e| ipc_error_to_wire(&e).0.to_string())
}

fn read_preview(answer: &Value) -> Preview {
    let summary = answer.get("review-summary").unwrap_or(answer);
    let count = |key: &str| {
        summary
            .get(key)
            .and_then(Value::as_array)
            .map_or(0, Vec::len)
    };
    let added = count("rules-added");
    let removed = count("rules-removed");
    let changed = count("rules-modified") + count("rules-retargeted");
    Preview {
        added,
        removed,
        changed,
        empty: added + removed + changed + count("changed-fields") == 0,
        refused: refusal(summary),
        token: answer
            .get("confirmation-token")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    }
}

/// The refusal a dry run carries among its risk signals, as the GUI reads it.
fn refusal(summary: &Value) -> Option<String> {
    summary
        .get("risk-signals")?
        .as_array()?
        .iter()
        .find_map(|signal| match signal.get("kind").and_then(Value::as_str) {
            Some("invalid-rule-value") => Some("invalid-rule-value".to_string()),
            Some("change-refused") => Some(
                signal
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
            ),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_preview_counts_buckets_and_finds_a_refusal() {
        let answer = json!({
            "review-summary": {
                "rules-added": [{}, {}],
                "rules-removed": [{}],
                "rules-modified": [{}],
                "rules-retargeted": [{}],
                "risk-signals": [{ "kind": "change-refused", "code": "rule-cap-exceeded" }]
            },
            "confirmation-token": "tok"
        });
        let preview = read_preview(&answer);
        assert_eq!((preview.added, preview.removed, preview.changed), (2, 1, 2));
        assert!(!preview.empty);
        assert_eq!(preview.refused.as_deref(), Some("rule-cap-exceeded"));
        assert_eq!(preview.token, "tok");
    }

    #[test]
    fn an_unchanged_set_previews_empty() {
        let preview = read_preview(&json!({ "review-summary": {}, "confirmation-token": "t" }));
        assert!(preview.empty);
        assert_eq!(preview.refused, None);
    }
}
