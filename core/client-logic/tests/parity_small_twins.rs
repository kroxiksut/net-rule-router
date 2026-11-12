#![allow(clippy::expect_used)]

//! One-question twins (a name, a path, a flag in a status) that had no
//! vectors: each answers the same in `pure.js`/`rules.js` and in Rust.

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, text, JsLib};
use nrr_client_logic::app_routes::{app_route_of, AppRule};
use serde_json::{json, Value};

#[test]
fn app_route_of_matches_js() {
    check(
        "app_route_of",
        &mut JsLib::pure(),
        |input| {
            format!(
                "appRouteOf({}, {})",
                arg(input, "rules"),
                arg(input, "program")
            )
        },
        |input| {
            let rules: Vec<AppRule<'_>> = input
                .get("rules")
                .and_then(Value::as_array)
                .map_or(&[][..], Vec::as_slice)
                .iter()
                .map(|r| AppRule {
                    value: text(r, "value"),
                    route: text(r, "route"),
                    enabled: r.get("enabled").and_then(Value::as_bool).unwrap_or(true),
                })
                .collect();
            json!(app_route_of(&rules, text(input, "program")))
        },
    );
}

#[test]
fn is_forwarding_adapter_name_matches_js() {
    check(
        "is_forwarding_adapter_name",
        &mut JsLib::pure(),
        |input| format!("isForwardingAdapterName({})", arg(input, "name")),
        |input| {
            json!(nrr_client_logic::forwarded::is_forwarding_adapter_name(
                text(input, "name")
            ))
        },
    );
}

#[test]
fn present_adapter_ids_match_js() {
    check(
        "present_adapter_ids",
        &mut JsLib::pure(),
        |input| format!("presentAdapterIds({})", arg(input, "snapshot")),
        |input| {
            json!(nrr_client_logic::restore::present_adapter_ids(
                input.get("snapshot").unwrap_or(&Value::Null)
            ))
        },
    );
}

#[test]
fn value_is_any_zone_matches_js() {
    check(
        "value_is_any_zone",
        &mut JsLib::rules(),
        |input| format!("valueIsAnyZone({})", arg(input, "value")),
        |input| {
            json!(nrr_client_logic::rules_table::value_is_any_zone(text(
                input, "value"
            )))
        },
    );
}

#[test]
fn is_usable_set_name_matches_js() {
    check(
        "is_usable_set_name",
        &mut JsLib::pure(),
        |input| format!("isUsableSetName({})", arg(input, "name")),
        |input| {
            json!(nrr_client_logic::rule_sets::is_usable_set_name(text(
                input, "name"
            )))
        },
    );
}

#[test]
fn rules_file_folder_matches_js() {
    check(
        "rules_file_folder",
        &mut JsLib::pure(),
        |input| format!("rulesFileFolder({})", arg(input, "path")),
        |input| {
            json!(nrr_client_logic::rule_sets::rules_file_folder(text(
                input, "path"
            )))
        },
    );
}

#[test]
fn first_run_country_matches_js() {
    check(
        "first_run_country",
        &mut JsLib::pure(),
        |input| {
            format!(
                "firstRunCountry({}, {})",
                arg(input, "region"),
                arg(input, "locales")
            )
        },
        |input| {
            let locales: Vec<String> = input
                .get("locales")
                .and_then(Value::as_array)
                .map_or(&[][..], Vec::as_slice)
                .iter()
                .filter_map(|l| l.as_str().map(str::to_owned))
                .collect();
            json!(nrr_client_logic::first_run::first_run_country(
                text(input, "region"),
                &locales
            ))
        },
    );
}

#[test]
fn first_run_finish_state_matches_js() {
    check(
        "first_run_finish_state",
        &mut JsLib::pure(),
        |input| {
            format!(
                "firstRunFinishState({}, {}, {})",
                arg(input, "requiresSecondary"),
                arg(input, "secondaryAssigned"),
                arg(input, "secondaryAvailable")
            )
        },
        |input| {
            json!(nrr_client_logic::first_run::first_run_finish_state(
                input
                    .get("requiresSecondary")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                input
                    .get("secondaryAssigned")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                input
                    .get("secondaryAvailable")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            ))
        },
    );
}

#[test]
fn routing_readiness_matches_js() {
    check(
        "routing_readiness",
        &mut JsLib::pure(),
        |input| {
            format!(
                "routingReadiness({}, {}, {}, {}, {}, {}, {}, {})",
                arg(input, "serviceHealthy"),
                arg(input, "primaryBound"),
                arg(input, "primaryStatus"),
                arg(input, "secondaryRequired"),
                arg(input, "secondaryBound"),
                arg(input, "secondaryStatus"),
                arg(input, "activeRuleCount"),
                arg(input, "secondaryRuleCount")
            )
        },
        |input| {
            let count = |key| {
                input
                    .get(key)
                    .and_then(Value::as_u64)
                    .and_then(|n| u32::try_from(n).ok())
            };
            let readiness = nrr_client_logic::routing_readiness::routing_readiness(
                input
                    .get("serviceHealthy")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                input
                    .get("primaryBound")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                text(input, "primaryStatus"),
                input
                    .get("secondaryRequired")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                input
                    .get("secondaryBound")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                text(input, "secondaryStatus"),
                count("activeRuleCount"),
                count("secondaryRuleCount"),
            );
            json!({
                "service": readiness.service,
                "routing": readiness.routing,
                "primary": readiness.primary,
                "secondary": readiness.secondary,
                "affectedAssignments": readiness.affected_assignments,
            })
        },
    );
}

#[test]
fn security_alerts_unreadable_matches_js() {
    check(
        "security_alerts_unreadable",
        &mut JsLib::pure(),
        |input| format!("securityAlertsUnreadable({})", arg(input, "status")),
        |input| {
            json!(nrr_client_logic::diagnostics::security_alerts_unreadable(
                input.get("status").unwrap_or(&Value::Null)
            ))
        },
    );
}

#[test]
fn dns_blocking_status_matches_the_service_verdict_in_both_clients() {
    check(
        "dns_blocking_status",
        &mut JsLib::pure(),
        |input| format!("dohLockdownStatus({})", input),
        |input| {
            let policy = input.as_object().cloned().unwrap_or_default();
            json!(nrr_client_logic::routing_settings::doh_lockdown_status(
                &policy
            ))
        },
    );
}

#[test]
fn a_service_restart_does_not_erase_the_dns_problem_in_either_client() {
    check(
        "dns_compatibility_merge",
        &mut JsLib::pure(),
        |input| {
            format!("(function() {{ var s = {}; var updates = {} || [{}]; updates.forEach(function(next) {{ s = mergeDnsCompatibility(s, next); }}); return {{status:s.status, issues:s.issues}}; }})()",
            arg(input, "previous"), arg(input, "updates"), arg(input, "incoming"))
        },
        |input| {
            use nrr_shared::ipc_payloads::DnsCompatibilityDto;
            let parse = |source: &Value| {
                let mut value =
                    serde_json::to_value(DnsCompatibilityDto::default()).expect("default state");
                if let Some(fields) = source.as_object() {
                    value
                        .as_object_mut()
                        .expect("state object")
                        .extend(fields.clone());
                }
                serde_json::from_value::<DnsCompatibilityDto>(value).expect("fixture state")
            };
            let updates = input
                .get("updates")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_else(|| vec![input.get("incoming").cloned().unwrap_or(Value::Null)]);
            let state = updates.iter().fold(
                parse(input.get("previous").unwrap_or(&Value::Null)),
                |state, next| nrr_client_logic::dns_compatibility::merge(&state, parse(next)),
            );
            json!({"status":state.status, "issues":state.issues})
        },
    );
}

#[test]
fn dns_history_overflow_cannot_become_a_full_recovery_notice() {
    use nrr_shared::ipc_payloads::{DnsCompatibilityDto, DnsCompatibilityStatus};
    let empty = serde_json::to_value(DnsCompatibilityDto::default()).expect("state");
    let mut incoming = empty.clone();
    incoming["instance-id"] = json!("bounded-service");
    incoming["sequence"] = json!(1);
    incoming["status"] = json!("limited");
    incoming["issues"] = json!((0..80)
        .map(|n| json!({
            "program":format!("browser-{n}"), "reason":"our-dns-block", "evidence":"confirmed",
            "first-seen-ms":1, "last-seen-ms":2, "attempts":1, "needs-recheck":false
        }))
        .collect::<Vec<_>>());
    let limited = nrr_client_logic::dns_compatibility::merge(
        &DnsCompatibilityDto::default(),
        serde_json::from_value(incoming.clone()).expect("bounded input"),
    );
    assert!(
        limited.issues.len() <= 64,
        "the client must bound retained programs"
    );
    let mut proof = DnsCompatibilityDto {
        status: DnsCompatibilityStatus::Verified,
        instance_id: "bounded-service".to_owned(),
        sequence: 2,
        verified_program: Some("browser-0".to_owned()),
        ..Default::default()
    };
    proof.last_checked_ms = Some(3);
    let result = nrr_client_logic::dns_compatibility::merge(&limited, proof.clone());
    assert_eq!(result.status, DnsCompatibilityStatus::NeedsRecheck);
    assert!(
        result.history_incomplete,
        "a truncated history cannot certify full recovery"
    );
    let from_js = JsLib::pure().eval_json(&format!(
        "mergeDnsCompatibility(mergeDnsCompatibility({}, {}), {})",
        empty,
        incoming,
        serde_json::to_value(proof).expect("proof")
    ));
    assert_eq!(serde_json::to_value(result).expect("result"), from_js);
}
