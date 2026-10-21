#![allow(clippy::expect_used)]

//! The questions asked about a VPN-named program leak protection does not
//! trust by place, and the link provider set a yes writes — the same from
//! `pure.js` and from the crate.

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, text, JsLib};
use nrr_client_logic::vpn_client_trust::{
    confirmed_apps, picker_preselected, picker_result, picker_rows, provider_names, removed_apps,
    trust_offers, LinkProviderApp, PickerRow, TrustOffer,
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

#[test]
fn vpn_client_trust_removed_apps_match_js() {
    check(
        "vpn_client_trust_removed",
        &mut JsLib::pure(),
        |input| {
            format!(
                "vpnClientTrustRemovedApps({}, {})",
                arg(input, "existing"),
                arg(input, "exePath")
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
            Value::Array(
                removed_apps(&existing, text(input, "exePath"))
                    .iter()
                    .map(
                        |app| json!({ "exe-path": app.exe_path, "display-name": app.display_name }),
                    )
                    .collect(),
            )
        },
    );
}

fn apps_of(value: &Value) -> Vec<LinkProviderApp> {
    value
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
        .unwrap_or_default()
}

fn apps_json(apps: &[LinkProviderApp]) -> Value {
    Value::Array(
        apps.iter()
            .map(|app| json!({ "exe-path": app.exe_path, "display-name": app.display_name }))
            .collect(),
    )
}

fn rows_of(value: &Value) -> Vec<PickerRow> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|row| PickerRow {
                    display_name: text(row, "displayName").to_owned(),
                    exe_path: text(row, "exePath").to_owned(),
                    running: row["running"].as_bool().unwrap_or(false),
                    source: text(row, "source").to_owned(),
                    interface_name: text(row, "interfaceName").to_owned(),
                })
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn vpn_provider_names_match_js() {
    check(
        "vpn_provider_names",
        &mut JsLib::pure(),
        |input| format!("vpnProviderNames({})", arg(input, "apps")),
        |input| json!(provider_names(&apps_of(&input["apps"]))),
    );
}

#[test]
fn vpn_picker_rows_match_js() {
    check(
        "vpn_picker_rows",
        &mut JsLib::pure(),
        |input| {
            format!(
                "vpnPickerRows({}, {})",
                arg(input, "found"),
                arg(input, "stored")
            )
        },
        |input| {
            let rows = picker_rows(&rows_of(&input["found"]), &apps_of(&input["stored"]));
            Value::Array(
                rows.iter()
                    .map(|r| {
                        json!({
                            "displayName": r.display_name,
                            "exePath": r.exe_path,
                            "running": r.running,
                            "source": r.source,
                            "interfaceName": r.interface_name,
                        })
                    })
                    .collect(),
            )
        },
    );
}

#[test]
fn vpn_picker_preselected_match_js() {
    check(
        "vpn_picker_preselected",
        &mut JsLib::pure(),
        |input| {
            format!(
                "vpnPickerPreselected({}, {})",
                arg(input, "rows"),
                arg(input, "stored")
            )
        },
        |input| {
            json!(picker_preselected(
                &rows_of(&input["rows"]),
                &apps_of(&input["stored"])
            ))
        },
    );
}

#[test]
fn vpn_picker_result_match_js() {
    check(
        "vpn_picker_result",
        &mut JsLib::pure(),
        |input| {
            format!(
                "vpnPickerResultApps({}, {}, {})",
                arg(input, "rows"),
                arg(input, "selected"),
                arg(input, "stored")
            )
        },
        |input| {
            apps_json(&picker_result(
                &rows_of(&input["rows"]),
                &strings(&input["selected"]),
                &apps_of(&input["stored"]),
            ))
        },
    );
}

/// What the picker shows equals what is stored: reopened over the set its
/// own confirm wrote, it ticks exactly that set, and confirming again
/// unchanged writes the same set back.
#[test]
fn reopening_the_picker_shows_what_its_confirm_stored() {
    let found = vec![
        PickerRow {
            display_name: "example-gui.exe".into(),
            exe_path: r"C:\Example\example-gui.exe".into(),
            running: true,
            source: "running-process".into(),
            interface_name: String::new(),
        },
        PickerRow {
            display_name: "Corp Client".into(),
            exe_path: r"C:\Corp\corp-client.exe".into(),
            running: false,
            source: "installed-program".into(),
            interface_name: String::new(),
        },
    ];
    let elsewhere = LinkProviderApp {
        exe_path: r"C:\Added\elsewhere.exe".into(),
        display_name: "Elsewhere".into(),
    };
    let rows = picker_rows(&found, std::slice::from_ref(&elsewhere));
    let ticked = vec![
        r"C:\Example\example-gui.exe".to_owned(),
        r"C:\Corp\corp-client.exe".to_owned(),
        r"C:\Added\elsewhere.exe".to_owned(),
    ];
    let stored = picker_result(&rows, &ticked, std::slice::from_ref(&elsewhere));
    assert_eq!(stored.len(), 3, "{stored:?}");

    let reopened = picker_rows(&found, &stored);
    assert_eq!(picker_preselected(&reopened, &stored), ticked);
    assert_eq!(
        picker_result(&reopened, &picker_preselected(&reopened, &stored), &stored),
        stored
    );
}
