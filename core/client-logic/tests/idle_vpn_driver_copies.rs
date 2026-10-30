#![allow(clippy::expect_used)]

//! A VPN program installs its driver many times over and brings up whichever
//! copy is free. On a machine with forty such copies, all down, the first-run
//! step bound the additional route to an arbitrary one; the VPN then came up
//! on another, and the additional connection stayed down until rebound by
//! hand. While every copy is down there is no telling which one the VPN takes.

use nrr_client_logic::adapters::first_run_idle_vpns;
use nrr_client_logic::vpn_client_trust::PickerRow;
use nrr_shared::ipc_payloads::InterfaceRowDto;
use serde_json::json;

fn row(id: &str, name: &str, description: &str, availability: &str) -> InterfaceRowDto {
    serde_json::from_value(json!({
        "persistent-id": id,
        "adapter-name": id,
        "name": name,
        "interface-description": description,
        "interface-type": "ethernet",
        "kind": "tunnel",
        "is-bluetooth-like": false,
        "local-ip": "-",
        "gateway": "-",
        "dns-servers": "-",
        "has-default-route": false,
        "has-forwarding-path": false,
        "availability": availability,
        "route-state": "not-selected",
        "observed-facts": {
            "connectivity-state": "unknown",
            "external-ip-status": "unknown",
            "external-ip": null,
            "external-probe-attempted": false,
            "external-probe-note": ""
        },
        "derived-assessment": {
            "vpn-tunnel-likelihood": "likely",
            "virtual-interface-likelihood": "unlikely",
            "service-interface-likelihood": "unlikely",
            "classification": "vpn-tunnel",
            "confidence-percent": 90,
            "heuristic-only": true,
            "signals": []
        },
        "recommendation": {
            "class": "preferred-secondary",
            "confidence": "high",
            "advisory-only": true,
            "key-signals": [],
            "excluded-alternatives": []
        }
    }))
    .expect("a wire row")
}

fn tap_copies(count: usize, availability: impl Fn(usize) -> &'static str) -> Vec<InterfaceRowDto> {
    (1..=count)
        .map(|n| {
            let description = if n == 1 {
                "TAP-Windows Adapter V9".to_owned()
            } else {
                format!("TAP-Windows Adapter V9 #{n}")
            };
            row(
                &format!("{{tap{n}}}"),
                &format!("Ethernet {}", n + 1),
                &description,
                availability(n),
            )
        })
        .collect()
}

fn example_vpn() -> Vec<PickerRow> {
    vec![PickerRow {
        display_name: "Example VPN".into(),
        exe_path: r"C:\Program Files\Example VPN\example.exe".into(),
        running: false,
        source: "installed".into(),
        interface_name: String::new(),
    }]
}

#[test]
fn forty_copies_of_one_driver_are_not_guessed_between() {
    let rows = tap_copies(40, |_| "unavailable");
    let found = first_run_idle_vpns(&rows, &example_vpn(), None);
    assert!(
        found.rows.is_empty(),
        "a dead copy was offered: {:?}",
        found.rows
    );
    assert_eq!(found.preselect, None, "a dead copy was picked");
    assert_eq!(found.start_vpn_first, vec!["Example VPN".to_owned()]);
}

/// The field machine: the pool of stock copies plus the VPN's own adapter of
/// another driver, all down. The VPN has come up on either kind, so the
/// vendor adapter is listed as the VPN's but not picked, and the program is
/// asked for.
#[test]
fn a_vendor_adapter_beside_the_pool_is_not_picked_while_the_vpn_is_off() {
    let mut rows = tap_copies(40, |_| "unavailable");
    rows.push(row(
        "{vendor}",
        "Example VPN OpenVPN Adapter",
        "Example VPN 3.0 OpenVPN Adapter",
        "unavailable",
    ));
    let found = first_run_idle_vpns(&rows, &example_vpn(), None);
    assert_eq!(
        found.rows.iter().map(|r| r.index).collect::<Vec<_>>(),
        vec![40],
        "the vendor adapter is listed as the VPN's: {:?}",
        found.rows
    );
    assert_eq!(found.preselect, None, "a guess was picked");
    assert_eq!(found.start_vpn_first, vec!["Example VPN".to_owned()]);
}

/// The lone copy of a driver is the VPN's, as before: offered and picked.
#[test]
fn a_lone_copy_is_still_offered_and_picked() {
    let rows = tap_copies(1, |_| "unavailable");
    let found = first_run_idle_vpns(&rows, &example_vpn(), None);
    assert_eq!(found.preselect, Some(0));
    assert!(found.start_vpn_first.is_empty());
}

/// One copy is up: the VPN is on and its link is the connected one, so the
/// step does not ask to turn it on, and no dead copy is offered either.
#[test]
fn a_copy_that_is_up_silences_the_request_to_turn_the_vpn_on() {
    let rows = tap_copies(3, |n| if n == 2 { "available" } else { "unavailable" });
    let found = first_run_idle_vpns(&rows, &example_vpn(), None);
    assert!(found.rows.is_empty(), "{:?}", found.rows);
    assert!(
        found.start_vpn_first.is_empty(),
        "{:?}",
        found.start_vpn_first
    );
}
