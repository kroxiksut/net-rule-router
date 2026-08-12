//! Launcher-side handlers for `preset.*` RPC operations.
//!
//! Like `sidecar_handlers`, these operations are routed **locally** by
//! the launcher rather than forwarded to the Windows service: the
//! canonical txt parser is a pure function over UTF-8 text and doesn't
//! need any kernel state. Routing it here means:
//!
//! * QML can parse a preset before it reaches the service, surfacing
//!   the result in the import-review dialog (Phase 5).
//! * The offline import path (when the service is down) works without
//!   a service connection.
//! * Future service-side rewrites can link `nrr_shared::preset_parser`
//!   directly without going through this launcher hop.
//!
//! ## Operation catalogue
//!
//! | Slug             | Description                                  |
//! |------------------|----------------------------------------------|
//! | `preset.parse`   | Parse a canonical-txt body, return structured result |
//!
//! ## Wire shape
//!
//! Request payload:
//! ```json
//! { "text": "<canonical txt body, already utf-8 decoded by the bridge>" }
//! ```
//!
//! Response payload: serialised [`PresetParseResult`] in kebab-case
//! JSON (matches the `#[serde(rename_all = "kebab-case")]` derive on
//! the result type). See the parser module docs for the field shapes.

use serde_json::{json, Value};

use nrr_shared::preset_parser::{parse_canonical_rules, PresetParseResult};

/// Outcome of one `preset.*` request. The handler returns the payload
/// the dispatcher should attach to the RPC response; the dispatcher
/// wraps it in [`LauncherRpcResponse::ok`] / `err` envelope.
pub type PresetHandlerResult = Result<Value, PresetHandlerError>;

/// Errors that can occur while servicing a `preset.*` request.
///
/// The dispatcher maps these to kebab-case error codes for the wire
/// envelope. We keep this small enum (rather than reusing
/// `SidecarError` or `IpcErrorCode`) because the surface is narrow:
/// the parser itself is total, so the only failures are
/// malformed payloads from the caller.
#[derive(Debug, thiserror::Error)]
pub enum PresetHandlerError {
    /// Operation slug recognised as `preset.*` but the suffix is
    /// unknown to this binary.
    #[error("unknown preset operation: {0}")]
    UnknownOperation(String),

    /// Required payload field missing or wrong type.
    #[error("malformed payload: {0}")]
    MalformedPayload(String),
}

impl PresetHandlerError {
    /// Kebab-case wire slug for the RPC error envelope.
    pub fn wire_code(&self) -> &'static str {
        match self {
            PresetHandlerError::UnknownOperation(_) => "unknown-preset-operation",
            PresetHandlerError::MalformedPayload(_) => "malformed-preset-payload",
        }
    }
}

/// Dispatch a single `preset.*` request. The dispatcher already
/// verified the prefix; we match on the operation suffix here.
pub fn handle_preset_request(operation: &str, payload: &Value) -> PresetHandlerResult {
    match operation {
        "preset.parse" => handle_parse(payload),
        other => Err(PresetHandlerError::UnknownOperation(other.to_string())),
    }
}

/// Parse a canonical-txt preset body.
///
/// Returns the serialised [`PresetParseResult`]. Always succeeds for
/// any well-formed text payload — the parser itself is total
/// (see `nrr_shared::preset_parser::parse_canonical_rules`). The only
/// failure path is a missing or wrong-typed `text` field.
fn handle_parse(payload: &Value) -> PresetHandlerResult {
    let text = payload.get("text").and_then(Value::as_str).ok_or_else(|| {
        PresetHandlerError::MalformedPayload("missing required field `text` (string)".into())
    })?;

    let result: PresetParseResult = parse_canonical_rules(text);
    let serialised = serde_json::to_value(&result).map_err(|e| {
        PresetHandlerError::MalformedPayload(format!("failed to serialise parse result: {e}"))
    })?;
    Ok(json!({ "result": serialised }))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_empty_text_returns_empty_result() {
        let res = handle_preset_request("preset.parse", &json!({ "text": "" })).expect("call");
        let result = &res["result"];
        assert!(result["rules"].as_array().expect("rules").is_empty());
        assert!(result["passthrough"]
            .as_array()
            .expect("passthrough")
            .is_empty());
        assert!(result["duplicate-sections"]
            .as_array()
            .expect("duplicates")
            .is_empty());
    }

    #[test]
    fn parse_single_zone_rule() {
        let res = handle_preset_request("preset.parse", &json!({ "text": "--- Zones\nru\n" }))
            .expect("call");
        let rules = res["result"]["rules"].as_array().expect("rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["match-value"], "ru");
        assert_eq!(rules[0]["rule-type"], "zone");
        assert_eq!(rules[0]["enabled"], true);
    }

    #[test]
    fn parse_with_unknown_section_returns_passthrough() {
        let res = handle_preset_request(
            "preset.parse",
            &json!({ "text": "--- Linux\nfirefox\nchromium\n" }),
        )
        .expect("call");
        let passthrough = res["result"]["passthrough"]
            .as_array()
            .expect("passthrough");
        assert_eq!(passthrough.len(), 1);
        assert_eq!(passthrough[0]["section-name"], "Linux");
        assert_eq!(passthrough[0]["content-lines"], 2);
        assert_eq!(passthrough[0]["preview"][0], "firefox");
    }

    #[test]
    fn duplicate_sections_surfaced() {
        let res = handle_preset_request(
            "preset.parse",
            &json!({ "text": "--- Linux\na\n--- Linux\nb\n" }),
        )
        .expect("call");
        let dups = res["result"]["duplicate-sections"]
            .as_array()
            .expect("dups");
        assert_eq!(dups.len(), 1);
        assert_eq!(dups[0]["section-name"], "Linux");
        assert_eq!(dups[0]["occurrences"], 2);
        assert_eq!(dups[0]["is-known-section"], false);
    }

    #[test]
    fn cyrillic_text_round_trips_through_json() {
        let res = handle_preset_request(
            "preset.parse",
            &json!({ "text": "--- Zones\nрф          # Россия\n" }),
        )
        .expect("call");
        let rules = res["result"]["rules"].as_array().expect("rules");
        assert_eq!(rules[0]["match-value"], "рф");
        assert_eq!(rules[0]["comment"], "Россия");
    }

    #[test]
    fn missing_text_field_errors_cleanly() {
        let err = handle_preset_request("preset.parse", &json!({})).expect_err("missing field");
        assert_eq!(err.wire_code(), "malformed-preset-payload");
    }

    #[test]
    fn text_wrong_type_errors_cleanly() {
        let err =
            handle_preset_request("preset.parse", &json!({ "text": 42 })).expect_err("wrong type");
        assert_eq!(err.wire_code(), "malformed-preset-payload");
    }

    #[test]
    fn unknown_operation_errors_cleanly() {
        let err =
            handle_preset_request("preset.bogus", &json!({ "text": "" })).expect_err("unknown op");
        assert_eq!(err.wire_code(), "unknown-preset-operation");
    }

    #[test]
    fn id_hint_is_numeric_one_based() {
        let res = handle_preset_request("preset.parse", &json!({ "text": "--- Zones\nru\nsu\n" }))
            .expect("call");
        let rules = res["result"]["rules"].as_array().expect("rules");
        assert_eq!(rules[0]["id-hint"], 1);
        assert_eq!(rules[1]["id-hint"], 2);
    }

    #[test]
    fn line_numbers_one_based_track_file_position() {
        let res = handle_preset_request(
            "preset.parse",
            &json!({ "text": "# prelude\n--- Zones\n\nru\n" }),
        )
        .expect("call");
        let rules = res["result"]["rules"].as_array().expect("rules");
        // `ru` is on line 4 (1-based) — `# prelude`, `--- Zones`,
        // blank line, then `ru`.
        assert_eq!(rules[0]["line-number"], 4);
    }
}
