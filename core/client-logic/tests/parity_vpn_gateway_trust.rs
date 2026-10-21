#![allow(clippy::expect_used)]

//! The question asked when leak protection stopped another VPN reaching its
//! gateway, and the list an answer writes — the same from `pure.js` and from
//! the crate.

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, text, JsLib};
use nrr_client_logic::vpn_gateway_trust::{
    confirmed_gateways, gateway_offers, removed_gateways, Gateway, GatewayOffer,
};
use serde_json::{json, Value};

fn gateways(value: &Value) -> Vec<Gateway> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|g| Gateway {
                    address: text(g, "address").to_owned(),
                    program: text(g, "program").to_owned(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn gateways_json(list: &[Gateway]) -> Value {
    Value::Array(
        list.iter()
            .map(|g| json!({ "address": g.address, "program": g.program }))
            .collect(),
    )
}

#[test]
fn vpn_gateway_offers_match_js() {
    check(
        "vpn_gateway_offers",
        &mut JsLib::pure(),
        |input| format!("vpnGatewayOffers({})", arg(input, "pending")),
        |input| {
            Value::Array(
                gateway_offers(&gateways(&input["pending"]))
                    .iter()
                    .map(|o| json!({ "address": o.address, "program": o.program, "name": o.name }))
                    .collect(),
            )
        },
    );
}

#[test]
fn vpn_gateways_confirmed_match_js() {
    check(
        "vpn_gateways_confirmed",
        &mut JsLib::pure(),
        |input| {
            format!(
                "vpnGatewaysConfirmed({}, {})",
                arg(input, "existing"),
                arg(input, "offer")
            )
        },
        |input| {
            let offer = &input["offer"];
            let offer = GatewayOffer {
                address: text(offer, "address").to_owned(),
                program: text(offer, "program").to_owned(),
                name: text(offer, "name").to_owned(),
            };
            gateways_json(&confirmed_gateways(&gateways(&input["existing"]), &offer))
        },
    );
}

#[test]
fn vpn_gateways_removed_match_js() {
    check(
        "vpn_gateways_removed",
        &mut JsLib::pure(),
        |input| {
            format!(
                "vpnGatewaysRemoved({}, {})",
                arg(input, "existing"),
                arg(input, "address")
            )
        },
        |input| {
            gateways_json(&removed_gateways(
                &gateways(&input["existing"]),
                text(input, "address"),
            ))
        },
    );
}
