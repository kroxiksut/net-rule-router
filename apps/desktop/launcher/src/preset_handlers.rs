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
/// Returns the serialised [`PresetParseResult`], plus the SERVICE's verdict on
/// the same bytes: `rejected` when the service would refuse the file,
/// `format-version` when it would take the file but the header declares a
/// format newer than this build reads, and `validation` for the individual
/// rows the service would refuse.
///
/// The parse itself is total (see `nrr_shared::preset_parser::parse_canonical_rules`);
/// the only failure path is a missing or wrong-typed `text` field. The verdict
/// is separate because the parser has no limits at all: without it the import
/// dialog walked the user through choosing sections and resolving duplicates in
/// a file the service then rejected whole, and the refusal arrived after the
/// work instead of before it.
fn handle_parse(payload: &Value) -> PresetHandlerResult {
    let text = payload.get("text").and_then(Value::as_str).ok_or_else(|| {
        PresetHandlerError::MalformedPayload("missing required field `text` (string)".into())
    })?;

    let result: PresetParseResult = parse_canonical_rules(text);
    let serialised = serde_json::to_value(&result).map_err(|e| {
        PresetHandlerError::MalformedPayload(format!("failed to serialise parse result: {e}"))
    })?;
    let mut out = json!({ "result": serialised });
    let row_verdicts = row_validation(&result);
    if !row_verdicts.is_empty() {
        out["validation"] = Value::Array(row_verdicts);
    }
    let verdict = service_verdict(text);
    if let Some(rejected) = verdict.rejected {
        out["rejected"] = rejected;
    }
    if let Some(newer) = verdict.newer_format {
        out["format-version"] = newer;
    }
    Ok(out)
}

/// What the service would say about these bytes, in the two shapes the window
/// can act on.
#[derive(Default)]
struct ServiceVerdict {
    rejected: Option<Value>,
    newer_format: Option<Value>,
}

/// Per-row verdicts from the SAME validator the service applies, keyed by the
/// parser's `id-hint`.
///
/// Only the rows that are not plain `Valid` travel: a clean file adds nothing
/// to the payload, and a window that does not know the field behaves as before.
///
/// Why here rather than on the wire type: `PresetParseResult` lives in
/// `nrr-shared`, which must not depend on `nrr-domain`, so the validation
/// cannot be a field of the rule. It is a parallel array instead — the launcher
/// is the one place that already holds both halves.
///
/// The gap this closes: rows built from a service revision arrive carrying
/// `validation-status` and the rules table paints them, while rows built from
/// an imported file carried nothing and defaulted to "valid". An IPv6 address
/// in a hand-edited file therefore looked accepted right up until the apply
/// refused the whole file, with nothing on screen saying which line was wrong.
fn row_validation(result: &PresetParseResult) -> Vec<Value> {
    use nrr_application::rule_value_validation::validate_rule_value;

    result
        .rules
        .iter()
        .filter_map(|rule| {
            let verdict = validate_rule_value(rule.rule_type.slug(), &rule.match_value);
            if matches!(
                verdict,
                nrr_application::rule_value_validation::RuleValueValidation::Valid
            ) {
                return None;
            }
            Some(json!({
                "id-hint": rule.id_hint,
                "status": verdict.status_slug(),
                "message-key": verdict.message_key(),
                "args": verdict.args(),
            }))
        })
        .collect()
}

/// The service's own file-level verdict, as slugs plus the numbers the window
/// needs to say WHY. Slugs and numbers rather than sentences: the text is
/// localized in QML, and a message built here would ship English into a Russian
/// window.
///
/// The newer-format warning travels the same way for the same reason it exists
/// at all: the domain parser reads the version header and warns, the GUI parser
/// drops the whole prelude, and the warning had no consumer anywhere — so a
/// file written by a later build imported with the user told nothing about the
/// rules this build cannot read.
///
/// `text` has already been decoded, so the encoding rejection cannot arise on
/// this path — a file that was not UTF-8 never reached here as a string.
fn service_verdict(text: &str) -> ServiceVerdict {
    use nrr_application::preset_validation::{
        validate_preset_bytes, PresetFileValidationOutcome, PresetImportRejectedReason as R,
        PresetImportWarning as W,
    };

    let reason = match validate_preset_bytes(text.as_bytes()) {
        PresetFileValidationOutcome::Accepted { .. } => return ServiceVerdict::default(),
        PresetFileValidationOutcome::AcceptedWithWarnings { warnings, .. } => {
            return ServiceVerdict {
                rejected: None,
                newer_format: warnings.iter().find_map(|w| match w {
                    // Unknown sections are already on screen as passthrough
                    // blocks with a "not applied" badge; saying it twice is
                    // noise, and the format version is the half nothing shows.
                    W::UnknownSection { .. } => None,
                    W::FormatVersionMismatch { found, supported } => {
                        Some(json!({ "found": found, "supported": supported }))
                    }
                    _ => None,
                }),
            };
        }
        PresetFileValidationOutcome::Rejected(reason) => reason,
        // `#[non_exhaustive]`: an outcome this build does not know says
        // nothing here. The service gates the import either way, and
        // inventing a refusal would stop a file it would have taken.
        _ => return ServiceVerdict::default(),
    };
    let rejected = Some(match reason {
        R::FileTooLarge {
            size_bytes,
            limit_bytes,
        } => json!({
            "code": "file-too-large",
            "size": size_bytes,
            "limit": limit_bytes,
        }),
        R::EncodingError => json!({ "code": "encoding" }),
        R::TooManyRules { count, limit } => json!({
            "code": "too-many-rules",
            "count": count,
            "limit": limit,
        }),
        R::MatchValueTooLong {
            section,
            len,
            limit,
            ..
        } => json!({
            "code": "value-too-long",
            "section": section,
            "length": len,
            "limit": limit,
        }),
        R::InlineCommentTooLong {
            section,
            chars,
            limit,
            ..
        } => json!({
            "code": "comment-too-long",
            "section": section,
            "length": chars,
            "limit": limit,
        }),
        // `PresetImportRejectedReason` is `#[non_exhaustive]`: a reason this
        // build does not know still has to stop the import, and the window
        // renders the generic refusal for it.
        _ => json!({ "code": "unsupported" }),
    });
    ServiceVerdict {
        rejected,
        newer_format: None,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The parser has no limits at all, so an oversized file walked the user
    /// through choosing sections and resolving duplicates — and the service
    /// then refused the whole thing. The refusal has to arrive first.
    #[test]
    fn a_file_the_service_would_refuse_says_so_before_the_dialog() {
        let too_many = (0..20_000)
            .map(|i| format!("host{i}.example.test"))
            .collect::<Vec<_>>()
            .join(
                "
",
            );
        let text = format!(
            "--- Domains
{too_many}
"
        );

        let res = handle_preset_request("preset.parse", &json!({ "text": text })).expect("call");
        let rejected = &res["rejected"];
        assert_eq!(rejected["code"], json!("too-many-rules"));
        assert!(
            rejected["limit"].as_u64().is_some_and(|l| l > 0),
            "the window needs the number to say what the limit is",
        );
        // The parse result still travels: the caller decides what to show.
        assert!(res["result"]["rules"].as_array().is_some());
    }

    /// A file within every limit carries no verdict at all — absence is the
    /// answer, so an older window that ignores the field behaves as before.
    #[test]
    fn an_ordinary_file_carries_no_refusal() {
        let res = handle_preset_request(
            "preset.parse",
            &json!({ "text": "--- Zones
ru
" }),
        )
        .expect("call");
        assert!(res.get("rejected").is_none());
    }

    /// The domain parser reads the version header and warns; the GUI parser
    /// drops the whole prelude, and nothing anywhere read the warning. A file
    /// from a later build imported with the user told nothing about the rules
    /// this build cannot read.
    #[test]
    fn a_file_from_a_newer_build_says_so() {
        let text = "# NetRuleRouter preset \u{2014} version 99\n--- Zones\nru\n";
        let res = handle_preset_request("preset.parse", &json!({ "text": text })).expect("call");
        let newer = &res["format-version"];
        assert_eq!(newer["found"], json!(99));
        assert!(
            newer["supported"].as_u64().is_some_and(|v| v < 99),
            "the window needs both numbers to say what it can read",
        );
        // A warning, not a refusal: the file still imports.
        assert!(res.get("rejected").is_none());
        assert_eq!(res["result"]["rules"].as_array().expect("rules").len(), 1);
    }

    /// The other half: a file this build understands carries no version note,
    /// so a window that ignores the field behaves exactly as before.
    #[test]
    fn a_file_this_build_understands_carries_no_version_note() {
        let res = handle_preset_request("preset.parse", &json!({ "text": "--- Zones\nru\n" }))
            .expect("call");
        assert!(res.get("format-version").is_none());
    }

    /// Rows from a service revision arrive carrying `validation-status` and the
    /// table paints them; rows from an imported file carried nothing and
    /// defaulted to "valid". An IPv6 address in a hand-edited file looked
    /// accepted until the apply refused the whole file.
    #[test]
    fn a_row_the_service_would_refuse_is_flagged_before_the_apply() {
        let text = "--- IP\n192.168.1.1\n2001:db8::1\n";
        let res = handle_preset_request("preset.parse", &json!({ "text": text })).expect("call");
        let flagged = res["validation"].as_array().expect("validation array");
        assert_eq!(flagged.len(), 1, "only the bad row travels: {flagged:?}");
        // `id-hint` is what pairs the verdict with its row; the parser numbers
        // rules from 1, so the IPv6 line is the second rule.
        assert_eq!(flagged[0]["id-hint"], json!(2));
        assert_eq!(flagged[0]["status"], json!("error"));
        assert_eq!(
            flagged[0]["message-key"],
            json!("rules.validation.match-value-invalid.exact-ip-v6")
        );
    }

    /// A file every row of which the service accepts carries no verdicts at
    /// all, so an older window that ignores the field behaves as before.
    #[test]
    fn a_file_of_good_rows_carries_no_row_verdicts() {
        let res = handle_preset_request(
            "preset.parse",
            &json!({ "text": "--- Domains\nexample.com\n--- Zones\nru\n" }),
        )
        .expect("call");
        assert!(res.get("validation").is_none());
    }

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

    // A section name no build will ever claim as its own. `--- Linux` used to
    // stand in for "a section this host does not parse as rules" — true on
    // Windows, false on a Linux runner, where it is the native application
    // section and these two tests asserted the opposite of what happens.
    const FOREIGN_SECTION: &str = "Solaris";

    #[test]
    fn parse_with_unknown_section_returns_passthrough() {
        let res = handle_preset_request(
            "preset.parse",
            &json!({ "text": format!("--- {FOREIGN_SECTION}\nfirefox\nchromium\n") }),
        )
        .expect("call");
        let passthrough = res["result"]["passthrough"]
            .as_array()
            .expect("passthrough");
        assert_eq!(passthrough.len(), 1);
        assert_eq!(passthrough[0]["section-name"], FOREIGN_SECTION);
        assert_eq!(passthrough[0]["content-lines"], 2);
        assert_eq!(passthrough[0]["preview"][0], "firefox");
    }

    #[test]
    fn duplicate_sections_surfaced() {
        let res = handle_preset_request(
            "preset.parse",
            &json!({ "text": format!("--- {FOREIGN_SECTION}\na\n--- {FOREIGN_SECTION}\nb\n") }),
        )
        .expect("call");
        let dups = res["result"]["duplicate-sections"]
            .as_array()
            .expect("dups");
        assert_eq!(dups.len(), 1);
        assert_eq!(dups[0]["section-name"], FOREIGN_SECTION);
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
