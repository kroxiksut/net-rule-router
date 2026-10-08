#![allow(clippy::expect_used)]

//! The settings helpers — notice mutes, the stability row, byte counts —
//! answer every vector exactly as the GUI's `pure.js` does.

// Shared with `parity.rs`, which uses the parts this file does not.
#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, text, JsLib};
use nrr_client_logic::notice_mutes::{
    notice_kind_muted, notice_mute_request, MUTABLE_NOTICE_KINDS, NOTICE_MUTE_CHOICES_MS,
};
use nrr_client_logic::stability;
use nrr_client_logic::units::format_storage_bytes;
use serde_json::{json, Map, Value};

fn object(value: &Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}

fn int(input: &Value, key: &str) -> i64 {
    input[key].as_i64().expect("vector carries an integer")
}

// ---- notice mutes ----

#[test]
fn notice_mute_tables_match_js() {
    let mut js = JsLib::pure();
    let kinds: Map<String, Value> = MUTABLE_NOTICE_KINDS
        .iter()
        .map(|k| (k.slug.to_owned(), json!([k.title_key, k.title_en])))
        .collect();
    assert_eq!(js.eval_json("MUTABLE_NOTICE_KINDS"), Value::Object(kinds));
    let choices: Map<String, Value> = NOTICE_MUTE_CHOICES_MS
        .iter()
        .map(|(slug, span)| ((*slug).to_owned(), Value::from(*span)))
        .collect();
    assert_eq!(
        js.eval_json("NOTICE_MUTE_CHOICES_MS"),
        Value::Object(choices)
    );
}

#[test]
fn notice_kind_muted_matches_js() {
    check(
        "notice_kind_muted",
        &mut JsLib::pure(),
        |input| {
            format!(
                "noticeKindMuted({}, {}, {})",
                arg(input, "mutes"),
                arg(input, "kind"),
                arg(input, "now")
            )
        },
        |input| {
            Value::from(notice_kind_muted(
                &input["mutes"],
                text(input, "kind"),
                int(input, "now"),
            ))
        },
    );
}

#[test]
fn notice_mute_request_matches_js() {
    check(
        "notice_mute_request",
        &mut JsLib::pure(),
        |input| {
            format!(
                "noticeMuteRequest({}, {}, {})",
                arg(input, "kind"),
                arg(input, "choice"),
                arg(input, "now")
            )
        },
        |input| {
            notice_mute_request(
                text(input, "kind"),
                text(input, "choice"),
                int(input, "now"),
            )
            .unwrap_or(Value::Null)
        },
    );
}

// ---- service stability ----

#[test]
fn stability_tables_match_js() {
    let mut js = JsLib::pure();
    let defaults: Map<String, Value> = stability::FIELD_DEFAULTS
        .iter()
        .map(|(key, default)| ((*key).to_owned(), default.to_value()))
        .collect();
    assert_eq!(
        js.eval_json("STABILITY_FIELD_DEFAULTS"),
        Value::Object(defaults)
    );
    assert_eq!(
        js.eval_json("STABILITY_STRUCTURED_KEYS"),
        json!(stability::STRUCTURED_KEYS)
    );
    assert_eq!(
        js.eval_json("STABILITY_INTENT_EXCLUDED_KEYS"),
        json!(stability::INTENT_EXCLUDED_KEYS)
    );
    let clamps: Map<String, Value> = stability::FIELD_CLAMPS
        .iter()
        .map(|(key, c)| {
            (
                (*key).to_owned(),
                json!({ "min": c.min, "max": c.max, "non-positive": c.non_positive }),
            )
        })
        .collect();
    assert_eq!(
        js.eval_json("STABILITY_FIELD_CLAMPS"),
        Value::Object(clamps)
    );
    let choices: Map<String, Value> = stability::FIELD_CHOICES
        .iter()
        .map(|(key, values)| ((*key).to_owned(), json!(values)))
        .collect();
    assert_eq!(
        js.eval_json("STABILITY_FIELD_CHOICES"),
        Value::Object(choices)
    );
    assert_eq!(
        js.eval_json("LOG_WINDOW_CHANGES"),
        json!(stability::LOG_WINDOW_CHANGES)
    );
    let capabilities: Map<String, Value> = stability::KEY_CAPABILITY
        .iter()
        .map(|(key, capability)| ((*key).to_owned(), Value::from(*capability)))
        .collect();
    assert_eq!(
        js.eval_json("STABILITY_KEY_CAPABILITY"),
        Value::Object(capabilities)
    );
}

#[test]
fn stability_coerce_matches_js() {
    check(
        "stability_coerce",
        &mut JsLib::pure(),
        |input| {
            format!(
                "stabilityCoerce({}, {})",
                arg(input, "key"),
                arg(input, "raw")
            )
        },
        |input| stability::coerce(text(input, "key"), input.get("raw").unwrap_or(&Value::Null)),
    );
}

#[test]
fn stability_merge_write_matches_js() {
    check(
        "stability_merge_write",
        &mut JsLib::pure(),
        |input| {
            format!(
                "mergeStabilityWrite({}, {}, {}, {})",
                arg(input, "live"),
                arg(input, "intent"),
                arg(input, "parked"),
                arg(input, "partial")
            )
        },
        |input| {
            Value::Object(stability::merge_write(
                &object(&input["live"]),
                &object(&input["intent"]),
                &object(&input["parked"]),
                &object(&input["partial"]),
            ))
        },
    );
}

#[test]
fn stability_patch_for_platform_matches_js() {
    check(
        "stability_patch_for_platform",
        &mut JsLib::pure(),
        |input| {
            format!(
                "({{ patch: stabilityPatchForPlatform({p}, {s}), any: stabilityAnyKeyApplies({s}) }})",
                p = arg(input, "partial"),
                s = arg(input, "supports")
            )
        },
        |input| {
            let supports = input.get("supports").and_then(Value::as_object);
            json!({
                "patch": stability::patch_for_platform(&object(&input["partial"]), supports),
                "any": stability::any_key_applies(supports),
            })
        },
    );
}

// ---- units ----

#[test]
fn format_storage_bytes_matches_js() {
    check(
        "format_storage_bytes",
        &mut JsLib::pure(),
        |input| format!("formatStorageBytes({})", arg(input, "bytes")),
        |input| {
            let bytes = input["bytes"]
                .as_u64()
                .expect("vector carries a byte count");
            Value::from(format_storage_bytes(bytes))
        },
    );
}
