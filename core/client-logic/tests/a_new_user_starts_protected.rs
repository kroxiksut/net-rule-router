#![allow(clippy::expect_used)]

//! Someone who never opened the protection setting gets "Routed sites": a VPN
//! that is off, drops or starts after the computer must not send the sites
//! meant for it out directly. Both clients build a new user's first write from
//! the same table; a write that said "off" would switch protection off for a
//! user who never chose that.

#[allow(dead_code)]
mod js_harness;

use js_harness::JsLib;
use nrr_client_logic::route_policy::{build_full_update_request, DEFAULT_ROUTE_MAIN};
use serde_json::{json, Map, Value};

#[test]
fn the_first_write_of_a_user_with_no_saved_policy_protects_routed_sites() {
    let terminal = build_full_update_request(&Map::new(), DEFAULT_ROUTE_MAIN);
    assert_eq!(terminal["leak-protection"], json!("sites"));

    let mut window = JsLib::pure();
    let request = window.eval_json("buildFullRoutePolicyReq(null, \"prefer-primary\")");
    assert_eq!(request["leak-protection"], Value::from("sites"));
}

#[test]
fn a_stored_off_is_written_back_as_off() {
    let mut snapshot = Map::new();
    snapshot.insert("leak-protection".into(), json!("off"));
    let terminal = build_full_update_request(&snapshot, DEFAULT_ROUTE_MAIN);
    assert_eq!(terminal["leak-protection"], json!("off"));

    let mut window = JsLib::pure();
    let request = window
        .eval_json("buildFullRoutePolicyReq({\"leak-protection\": \"off\"}, \"prefer-primary\")");
    assert_eq!(request["leak-protection"], Value::from("off"));
}
