#![allow(clippy::expect_used)]

//! A foreign name made safe to show — the same text from `pure.js` and from
//! `nrr_shared::display_text`.

#[allow(dead_code)]
mod js_harness;

use js_harness::{check_cases, load_vectors, Case, JsLib};
use nrr_shared::display_text::display_text;
use serde_json::Value;

/// A `text` string, or `pieces` — `[string, count]` pairs joined in order, so
/// a vector past the cap stays readable.
fn spelled(value: &Value) -> String {
    if let Some(text) = value.as_str() {
        return text.to_owned();
    }
    if let Some(text) = value.get("text").and_then(Value::as_str) {
        return text.to_owned();
    }
    value["pieces"]
        .as_array()
        .expect("a vector value is a string, `text` or `pieces`")
        .iter()
        .map(|piece| {
            let text = piece[0].as_str().expect("piece text");
            let count = piece[1].as_u64().expect("piece count");
            text.repeat(usize::try_from(count).expect("piece count fits"))
        })
        .collect()
}

/// A JS string literal with every unit outside printable ASCII escaped, so
/// the engine's source reader never sees the characters under test raw.
fn js_literal(text: &str) -> String {
    let mut out = String::from("\"");
    for unit in text.encode_utf16() {
        match unit {
            0x22 => out.push_str("\\\""),
            0x5C => out.push_str("\\\\"),
            0x20..=0x7E => out.push(char::from(u8::try_from(unit).expect("ASCII"))),
            _ => out.push_str(&format!("\\u{unit:04x}")),
        }
    }
    out.push('"');
    out
}

#[test]
fn display_text_matches_js() {
    let (_, cases) = load_vectors("display_text");
    let cases: Vec<Case> = cases
        .into_iter()
        .map(|case| Case {
            input: Value::String(spelled(&case.input)),
            expected: case.expected.as_ref().map(|e| Value::String(spelled(e))),
            name: case.name,
        })
        .collect();
    check_cases(
        "display_text",
        &cases,
        &mut JsLib::pure(),
        |input| format!("displayText({})", js_literal(input.as_str().unwrap_or(""))),
        |input| Value::String(display_text(input.as_str().unwrap_or("")).into_owned()),
    );
}

#[test]
fn display_text_reads_a_missing_value_as_empty() {
    let mut js = JsLib::pure();
    assert_eq!(js.eval_json("displayText(undefined)"), Value::from(""));
    assert_eq!(js.eval_json("displayText(null)"), Value::from(""));
    // A lone surrogate reaches only the JS side; it is flagged like the rest.
    let lone = js.eval_json("displayText('a\\ud800b')");
    assert_eq!(lone, Value::from("a\u{b7}b"));
}
