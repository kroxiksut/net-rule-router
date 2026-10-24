#![allow(clippy::expect_used)]

//! The resolver list a client writes over a fresh read — the same from
//! `pure.js` and from the crate.

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, text, JsLib};
use nrr_client_logic::doh_resolvers::{rebase, Resolver};
use serde_json::{json, Value};

fn rows(value: &Value) -> Vec<Resolver> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|r| {
                    let kind = text(r, "target-kind");
                    Resolver {
                        kind: if kind.is_empty() { "host" } else { kind }.to_owned(),
                        target: text(r, "target").to_owned(),
                        comment: text(r, "comment").to_owned(),
                        enabled: r.get("enabled") != Some(&Value::Bool(false)),
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn doh_resolvers_rebase_matches_js() {
    check(
        "doh_resolvers_rebase",
        &mut JsLib::pure(),
        |input| {
            format!(
                "dohResolversRebase({}, {}, {})",
                arg(input, "base"),
                arg(input, "edited"),
                arg(input, "fresh")
            )
        },
        |input| {
            let out = rebase(
                &rows(&input["base"]),
                &rows(&input["edited"]),
                &rows(&input["fresh"]),
            );
            json!({
                "resolvers": out
                    .resolvers
                    .iter()
                    .map(|r| json!({
                        "target-kind": r.kind,
                        "target": r.target,
                        "comment": r.comment,
                        "enabled": r.enabled,
                    }))
                    .collect::<Vec<_>>(),
                "removed": out.removed,
            })
        },
    );
}
