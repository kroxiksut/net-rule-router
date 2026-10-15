#![allow(clippy::expect_used)]

//! The questions asked about a VPN-named program leak protection does not
//! trust by place, and the link provider set a yes writes — the same from
//! `pure.js` and from the crate.

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, text, JsLib};
use nrr_client_logic::vpn_client_trust::{
    confirmed_apps, trust_offers, LinkProviderApp, TrustOffer,
};
use serde_json::{json, Value};

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| items.iter().map(|v| text_of(v).to_owned()).collect())
        .unwrap_or_default()
}

fn text_of(value: &Value) -> &str {
    value.as_str().unwrap_or("")
}

fn offer_json(offer: &TrustOffer) -> Value {
    json!({
        "exePath": offer.exe_path,
        "name": offer.name,
        "bundledExePaths": offer.bundled_exe_paths,
    })
}

fn offer_of(value: &Value) -> TrustOffer {
    TrustOffer {
        exe_path: text(value, "exePath").to_owned(),
        name: text(value, "name").to_owned(),
        bundled_exe_paths: strings(&value["bundledExePaths"]),
    }
}

#[test]
fn vpn_client_trust_offers_match_js() {
    check(
        "vpn_client_trust_offers",
        &mut JsLib::pure(),
        |input| format!("vpnClientTrustOffers({})", arg(input, "pending")),
        |input| {
            let pending: Vec<(String, Vec<String>)> = input["pending"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .map(|entry| {
                            (
                                text(entry, "exe-path").to_owned(),
                                strings(&entry["bundled-exe-paths"]),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            Value::Array(trust_offers(&pending).iter().map(offer_json).collect())
        },
    );
}

#[test]
fn vpn_client_trust_confirmed_apps_match_js() {
    check(
        "vpn_client_trust_confirmed",
        &mut JsLib::pure(),
        |input| {
            format!(
                "vpnClientTrustConfirmedApps({}, {}, {})",
                arg(input, "existing"),
                arg(input, "offer"),
                arg(input, "withBundle")
            )
        },
        |input| {
            let existing: Vec<LinkProviderApp> = input["existing"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .map(|app| LinkProviderApp {
                            exe_path: text(app, "exe-path").to_owned(),
                            display_name: text(app, "display-name").to_owned(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            let with_bundle = input["withBundle"].as_bool().unwrap_or(false);
            Value::Array(
                confirmed_apps(&existing, &offer_of(&input["offer"]), with_bundle)
                    .iter()
                    .map(
                        |app| json!({ "exe-path": app.exe_path, "display-name": app.display_name }),
                    )
                    .collect(),
            )
        },
    );
}
