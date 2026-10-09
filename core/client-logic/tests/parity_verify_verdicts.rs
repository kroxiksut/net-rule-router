#![allow(clippy::expect_used)]

//! The notice for `?` rules that work only on the other route — the same
//! answer from `pure.js` and from the crate.

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, JsLib};
use nrr_client_logic::verify_verdicts::verdict_notice;
use nrr_shared::ipc_payloads::VerifyVerdictDto;
use serde_json::{json, Value};

#[test]
fn verify_verdict_notice_matches_js() {
    check(
        "verify_verdict_notice",
        &mut JsLib::pure(),
        |input| format!("verifyVerdictNotice({})", arg(input, "verdicts")),
        |input| {
            let verdicts: Vec<VerifyVerdictDto> =
                serde_json::from_value(input["verdicts"].clone()).expect("verdicts decode");
            verdict_notice(&verdicts).map_or(Value::Null, |notice| {
                json!({
                    "ids": notice.rule_ids,
                    "shown": notice
                        .shown
                        .iter()
                        .map(|(value, to)| json!({ "value": value, "to": to }))
                        .collect::<Vec<_>>(),
                    "more": notice.more,
                })
            })
        },
    );
}
