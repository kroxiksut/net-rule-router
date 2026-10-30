#![allow(clippy::expect_used)]

//! The Rust port answers every vector exactly as the GUI's JavaScript does.
//! A failure names the vector and both answers; whichever side moved, the
//! other follows in the same change.

mod js_harness;

use std::collections::BTreeMap;

use js_harness::{
    ace_decode, ace_encode, arg, check, check_cases, lit, load_vectors, merged, text, Case, JsLib,
    EXPORTED_AT,
};
use nrr_client_logic::adapters::{self, RoleHint, UnroutableReason};
use nrr_client_logic::placeholders::{
    fill_placeholders, format_log_line, list_summary, plural_category, PluralRule,
};
use nrr_client_logic::rebase::{merge_view, rebase_edits};
use nrr_client_logic::review::{self, Outcome};
use nrr_client_logic::route_policy;
use nrr_client_logic::rules_table::{
    build_rules_file_text, drift_row_from_parsed_rule, drift_row_from_service_wire,
    file_row_from_service_wire, main_route_check_hosts, main_route_rank, normalize_host_input,
    override_remaining, parsed_rule_target_route, parsed_rule_verify, rule_override_key,
    rule_row_to_wire_dto, RowOrigin, RuleRow, RuleType, RulesFileOptions, TargetRoute,
    WireDtoOptions, PRESET_FORMAT_VERSION, RULES_FILE_HINT_KEYS,
};
use nrr_client_logic::Route;
use nrr_shared::ipc_payloads::{
    InterfaceRowDto, OperationStatusResponse, ReviewSummaryResponse, RouteBindingDto, RuleRowEntry,
};
use nrr_shared::preset_parser::ParsedRule;
use serde_json::{json, Map, Value};

fn object(value: &Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| item.as_str().unwrap_or_default().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn route(input: &Value) -> Route {
    Route::from_slug(text(input, "route")).expect("vector route is primary or secondary")
}

// ---- placeholders ----

#[test]
fn fill_placeholders_matches_js() {
    check(
        "fill_placeholders",
        &mut JsLib::pure(),
        |input| {
            format!(
                "(function (pairs) {{ var values = {{}}; \
                 pairs.forEach(function (p) {{ values[p[0]] = p[1] }}); \
                 return fillPlaceholders({}, values) }})({})",
                arg(input, "text"),
                arg(input, "values")
            )
        },
        |input| {
            let pairs: Vec<(String, String)> = input["values"]
                .as_array()
                .expect("values is an array of pairs")
                .iter()
                .map(|pair| {
                    let pair = strings(pair);
                    (pair[0].clone(), pair[1].clone())
                })
                .collect();
            Value::from(fill_placeholders(text(input, "text"), pairs))
        },
    );
}

#[test]
fn format_log_line_matches_js() {
    check(
        "format_log_line",
        &mut JsLib::pure(),
        |input| {
            format!(
                "formatLogLine({}, {}, {}, {})",
                arg(input, "translated"),
                arg(input, "source"),
                arg(input, "args"),
                arg(input, "positional")
            )
        },
        |input| {
            let args: BTreeMap<String, String> = object(&input["args"])
                .into_iter()
                .map(|(k, v)| (k, v.as_str().unwrap_or_default().to_owned()))
                .collect();
            Value::from(format_log_line(
                text(input, "translated"),
                text(input, "source"),
                &args,
                &strings(&input["positional"]),
            ))
        },
    );
}

#[test]
fn list_summary_matches_js() {
    check(
        "list_summary",
        &mut JsLib::pure(),
        |input| {
            format!(
                "listSummary({}, {})",
                arg(input, "items"),
                arg(input, "more")
            )
        },
        |input| Value::from(list_summary(&strings(&input["items"]), text(input, "more"))),
    );
}

#[test]
fn plural_category_matches_js() {
    check(
        "plural_category",
        &mut JsLib::pure(),
        |input| {
            format!(
                "pluralCategory({}, {})",
                arg(input, "rule"),
                arg(input, "n")
            )
        },
        |input| {
            let n = input["n"].as_i64().expect("n is a whole number");
            Value::from(plural_category(PluralRule::from_slug(text(input, "rule")), n).as_str())
        },
    );
}

// ---- route policy ----

#[test]
fn route_policy_tables_match_js() {
    let mut js = JsLib::pure();
    let defaults: Map<String, Value> = route_policy::FIELD_DEFAULTS
        .iter()
        .map(|(key, default)| ((*key).to_owned(), default.to_value()))
        .collect();
    assert_eq!(
        js.eval_json("ROUTE_POLICY_FIELD_DEFAULTS"),
        Value::Object(defaults)
    );
    assert_eq!(
        js.eval_json("ROUTE_POLICY_SNAPSHOT_ONLY_KEYS"),
        json!(route_policy::SNAPSHOT_ONLY_KEYS)
    );
    let mut masks = Map::new();
    masks.insert(
        route_policy::KILL_SWITCH_PROTOCOLS_KEY.to_owned(),
        json!({
            "all": route_policy::KILL_SWITCH_PROTOCOLS_ALL,
            "enforced": route_policy::KILL_SWITCH_PROTOCOLS_ENFORCED,
        }),
    );
    assert_eq!(
        js.eval_json("ROUTE_POLICY_FIELD_MASKS"),
        Value::Object(masks)
    );
    let choices: Map<String, Value> = route_policy::FIELD_CHOICES
        .iter()
        .map(|(key, values)| ((*key).to_owned(), json!(values)))
        .collect();
    assert_eq!(
        js.eval_json("ROUTE_POLICY_FIELD_CHOICES"),
        Value::Object(choices)
    );
    assert_eq!(
        js.eval_json("LEAK_PROTECTION_LEVELS"),
        json!(route_policy::LEAK_PROTECTION_LEVELS)
    );
    assert_eq!(
        js.eval_json("DEFAULT_ROUTES"),
        json!(route_policy::DEFAULT_ROUTES)
    );
}

#[test]
fn leak_protection_choices_match_js() {
    check(
        "leak_protection_choices",
        &mut JsLib::pure(),
        |input| format!("leakProtectionChoices({})", arg(input, "route")),
        |input| json!(route_policy::leak_protection_choices(text(input, "route"))),
    );
}

#[test]
fn coerce_leak_protection_matches_js() {
    check(
        "coerce_leak_protection",
        &mut JsLib::pure(),
        |input| {
            format!(
                "coerceLeakProtection({}, {})",
                arg(input, "route"),
                arg(input, "current")
            )
        },
        |input| {
            Value::from(route_policy::coerce_leak_protection(
                text(input, "route"),
                text(input, "current"),
            ))
        },
    );
}

#[test]
fn leak_protection_choices_at_least_match_js() {
    check(
        "leak_protection_choices_at_least",
        &mut JsLib::pure(),
        |input| {
            format!(
                "leakProtectionChoicesAtLeast({}, {})",
                arg(input, "route"),
                arg(input, "floor")
            )
        },
        |input| {
            json!(route_policy::leak_protection_choices_at_least(
                text(input, "route"),
                text(input, "floor"),
            ))
        },
    );
}

#[test]
fn raise_leak_protection_matches_js() {
    check(
        "raise_leak_protection",
        &mut JsLib::pure(),
        |input| {
            format!(
                "raiseLeakProtection({}, {}, {})",
                arg(input, "route"),
                arg(input, "level"),
                arg(input, "floor")
            )
        },
        |input| {
            Value::from(route_policy::raise_leak_protection(
                text(input, "route"),
                text(input, "level"),
                text(input, "floor"),
            ))
        },
    );
}

#[test]
fn first_run_held_protection_matches_js() {
    check(
        "first_run_held_protection",
        &mut JsLib::pure(),
        |input| {
            format!(
                "firstRunHeldProtection({}, {}, {}, {}, {})",
                arg(input, "saved"),
                arg(input, "route"),
                arg(input, "leak"),
                arg(input, "auto"),
                arg(input, "enabled")
            )
        },
        |input| {
            let flag = |key: &str| input[key].as_bool().unwrap_or(false);
            route_policy::first_run_held_protection(
                flag("saved"),
                text(input, "route"),
                text(input, "leak"),
                flag("auto"),
                flag("enabled"),
            )
            .map_or(
                Value::Null,
                |(level, doh)| json!({ "level": level, "doh": doh }),
            )
        },
    );
}

#[test]
fn first_run_writes_match_js() {
    check(
        "first_run_writes",
        &mut JsLib::pure(),
        |input| {
            format!(
                "firstRunWrites({}, {}, {}, {}, {})",
                arg(input, "held"),
                arg(input, "level"),
                arg(input, "doh"),
                arg(input, "touched"),
                arg(input, "fake-ip-touched")
            )
        },
        |input| {
            let held = &input["held"];
            let held = held
                .is_object()
                .then(|| (text(held, "level"), held["doh"].as_bool().unwrap_or(false)));
            let chosen = (
                text(input, "level"),
                input["doh"].as_bool().unwrap_or(false),
            );
            let writes = route_policy::first_run_writes(
                held,
                chosen,
                input["touched"].as_bool().unwrap_or(false),
                input["fake-ip-touched"].as_bool().unwrap_or(false),
            );
            json!({
                "protection": writes.protection,
                "stability": writes.stability,
                "fakeIp": writes.fake_ip
            })
        },
    );
}

#[test]
fn leak_protection_confirm_matches_js() {
    let (adapters_document, _) = load_vectors("adapters");
    let base = &adapters_document["base-row"];
    let (_, cases) = load_vectors("leak_protection_confirm");
    let cases: Vec<Case> = cases
        .into_iter()
        .map(|case| {
            let mut input = case.input.clone();
            if !input["secondary"].is_null() {
                input["secondary"] = merged(base, &case.input["secondary"]);
            }
            Case { input, ..case }
        })
        .collect();
    check_cases(
        "leak_protection_confirm",
        &cases,
        &mut JsLib::pure(),
        |input| {
            format!(
                "(function (w) {{ return leakProtectionConfirmSlug({}, {}, \
                 w ? mapWireInterfaceRow(w) : null) }})({})",
                arg(input, "current"),
                arg(input, "next"),
                lit(&input["secondary"])
            )
        },
        |input| {
            let row: Option<InterfaceRowDto> = (!input["secondary"].is_null()).then(|| {
                serde_json::from_value(input["secondary"].clone())
                    .expect("vector is an InterfaceRowDto")
            });
            Value::from(
                route_policy::leak_protection_confirm(
                    text(input, "current"),
                    text(input, "next"),
                    row.as_ref(),
                )
                .map_or("", route_policy::LeakProtectionConfirm::as_str),
            )
        },
    );
}

/// The cases of `file`, each `secondary` patch laid over the adapters base row.
fn cases_with_secondary_row(file: &str) -> Vec<Case> {
    let (adapters_document, _) = load_vectors("adapters");
    let base = &adapters_document["base-row"];
    let (_, cases) = load_vectors(file);
    cases
        .into_iter()
        .map(|case| {
            let mut input = case.input.clone();
            if !input["secondary"].is_null() {
                input["secondary"] = merged(base, &case.input["secondary"]);
            }
            Case { input, ..case }
        })
        .collect()
}

fn secondary_row(input: &Value) -> Option<InterfaceRowDto> {
    (!input["secondary"].is_null()).then(|| {
        serde_json::from_value(input["secondary"].clone()).expect("vector is an InterfaceRowDto")
    })
}

#[test]
fn default_route_change_confirm_matches_js() {
    check_cases(
        "default_route_change_confirm",
        &cases_with_secondary_row("default_route_change_confirm"),
        &mut JsLib::pure(),
        |input| {
            format!(
                "(function (w) {{ return defaultRouteChangeConfirmSlug({}, {}, \
                 w ? mapWireInterfaceRow(w) : null) }})({})",
                arg(input, "level"),
                arg(input, "route"),
                lit(&input["secondary"])
            )
        },
        |input| {
            Value::from(
                route_policy::default_route_change_confirm(
                    text(input, "level"),
                    text(input, "route"),
                    secondary_row(input).as_ref(),
                )
                .map_or("", route_policy::LeakProtectionConfirm::as_str),
            )
        },
    );
}

#[test]
fn leak_protection_holds_now_matches_js() {
    check_cases(
        "leak_protection_holds_now",
        &cases_with_secondary_row("leak_protection_holds_now"),
        &mut JsLib::pure(),
        |input| {
            format!(
                "(function (w) {{ return leakProtectionHoldsNow({}, \
                 w ? mapWireInterfaceRow(w) : null) }})({})",
                arg(input, "level"),
                lit(&input["secondary"])
            )
        },
        |input| {
            Value::from(route_policy::leak_protection_holds_now(
                text(input, "level"),
                secondary_row(input).as_ref(),
            ))
        },
    );
}

/// The interface row `input[slot]` merged over the adapters base row, or null.
fn row_slot(base: &Value, input: &Value, slot: &str) -> Value {
    if input[slot].is_null() {
        Value::Null
    } else {
        merged(base, &input[slot])
    }
}

fn row_of(input: &Value, slot: &str) -> Option<InterfaceRowDto> {
    (!input[slot].is_null())
        .then(|| serde_json::from_value(input[slot].clone()).expect("vector is an InterfaceRowDto"))
}

#[test]
fn secondary_change_holds_now_matches_js() {
    let (adapters_document, _) = load_vectors("adapters");
    let base = &adapters_document["base-row"];
    let (_, cases) = load_vectors("secondary_change_holds_now");
    let cases: Vec<Case> = cases
        .into_iter()
        .map(|case| {
            let mut input = case.input.clone();
            input["before"] = row_slot(base, &case.input, "before");
            input["after"] = row_slot(base, &case.input, "after");
            Case { input, ..case }
        })
        .collect();
    check_cases(
        "secondary_change_holds_now",
        &cases,
        &mut JsLib::pure(),
        |input| {
            format!(
                "(function (b, a) {{ return secondaryChangeHoldsNow({}, \
                 b ? mapWireInterfaceRow(b) : null, a ? mapWireInterfaceRow(a) : null) }})({}, {})",
                arg(input, "level"),
                lit(&input["before"]),
                lit(&input["after"])
            )
        },
        |input| {
            Value::from(route_policy::secondary_change_holds_now(
                text(input, "level"),
                row_of(input, "before").as_ref(),
                row_of(input, "after").as_ref(),
            ))
        },
    );
}

#[test]
fn route_policy_coerce_matches_js() {
    check(
        "route_policy_coerce",
        &mut JsLib::pure(),
        |input| {
            format!(
                "routePolicyCoerce({}, {})",
                arg(input, "key"),
                arg(input, "raw")
            )
        },
        |input| route_policy::coerce(text(input, "key"), input.get("raw").unwrap_or(&Value::Null)),
    );
}

#[test]
fn route_policy_effective_matches_js() {
    check(
        "route_policy_effective",
        &mut JsLib::pure(),
        |input| {
            format!(
                "routePolicyEffective({}, {})",
                arg(input, "snapshot"),
                arg(input, "key")
            )
        },
        |input| {
            route_policy::effective(&object(&input["snapshot"]), text(input, "key"))
                .unwrap_or(Value::Null)
        },
    );
}

#[test]
fn route_policy_full_request_matches_js() {
    check(
        "route_policy_full_request",
        &mut JsLib::pure(),
        |input| {
            format!(
                "buildFullRoutePolicyReq({}, {})",
                arg(input, "snapshot"),
                arg(input, "modeFallback")
            )
        },
        |input| {
            Value::Object(route_policy::build_full_update_request(
                &object(&input["snapshot"]),
                text(input, "modeFallback"),
            ))
        },
    );
}

#[test]
fn route_policy_changed_keys_match_js() {
    check(
        "route_policy_changed_keys",
        &mut JsLib::pure(),
        |input| {
            format!(
                "routePolicyChangedKeys({}, {})",
                arg(input, "base"),
                arg(input, "request")
            )
        },
        |input| {
            Value::from(route_policy::changed_keys(
                &object(&input["base"]),
                &object(&input["request"]),
            ))
        },
    );
}

#[test]
fn kill_switch_protocol_locks_match_js() {
    check(
        "kill_switch_protocols",
        &mut JsLib::pure(),
        |input| {
            format!(
                "{{ locked: killSwitchProtocolLocked({mask}, {bit}), \
                 atLastOne: killSwitchProtocolsAtLastOne({mask}) }}",
                mask = arg(input, "mask"),
                bit = arg(input, "bit")
            )
        },
        |input| {
            let mask = input.get("mask").unwrap_or(&Value::Null);
            let bit = input["bit"]
                .as_i64()
                .and_then(|b| i32::try_from(b).ok())
                .expect("bit is an i32");
            json!({
                "locked": route_policy::kill_switch_protocol_locked(mask, bit),
                "atLastOne": route_policy::kill_switch_protocols_at_last_one(mask),
            })
        },
    );
}

// ---- adapters ----

#[test]
fn adapter_eligibility_matches_js() {
    let (document, cases) = load_vectors("adapters");
    let base = &document["base-row"];
    let cases: Vec<Case> = cases
        .into_iter()
        .map(|case| Case {
            input: merged(base, &case.input["patch"]),
            ..case
        })
        .collect();
    check_cases(
        "adapters",
        &cases,
        &mut JsLib::pure(),
        |wire| {
            format!(
                "(function (w) {{
                    var row = mapWireInterfaceRow(w);
                    row.selectedRole = w[\"selected-role\"] || \"\";
                    return {{
                        ownTun: isOwnFakeIpTunRow(row),
                        unroutable: unroutableInterfaceReasonSlug(row),
                        cannotCarry: interfaceCannotCarryTrafficOut(row),
                        displayName: adapterDisplayName(row),
                        hint: adapterRoleHintSlug(row),
                        heldOtherThanPrimary: adapterHeldOtherRole(row, \"primary\"),
                        heldOtherThanSecondary: adapterHeldOtherRole(row, \"secondary\"),
                        offeredPrimary: !isOwnFakeIpTunRow(row)
                            && adapterHeldOtherRole(row, \"primary\") === \"\",
                        offeredSecondary: !isOwnFakeIpTunRow(row)
                            && adapterHeldOtherRole(row, \"secondary\") === \"\"
                    }}
                }})({})",
                lit(wire)
            )
        },
        |wire| {
            let row: InterfaceRowDto =
                serde_json::from_value(wire.clone()).expect("vector is an InterfaceRowDto");
            json!({
                "ownTun": adapters::is_own_fake_ip_tun(&row),
                "unroutable": adapters::unroutable_reason(&row).map_or("", UnroutableReason::as_str),
                "cannotCarry": !adapters::can_carry_traffic_out(&row),
                "displayName": adapters::display_name(&row),
                "hint": adapters::role_hint(&row).map_or("", RoleHint::as_str),
                "heldOtherThanPrimary": adapters::held_other_role(&row, Route::Primary).unwrap_or(""),
                "heldOtherThanSecondary": adapters::held_other_role(&row, Route::Secondary).unwrap_or(""),
                "offeredPrimary": adapters::offered_for_role(&row, Route::Primary),
                "offeredSecondary": adapters::offered_for_role(&row, Route::Secondary),
            })
        },
    );
}

#[test]
fn first_run_suggestion_matches_js() {
    let (document, cases) = load_vectors("first_run_suggestion");
    let base = &document["base-row"];
    let cases: Vec<Case> = cases
        .into_iter()
        .map(|case| Case {
            input: json!({
                "role": case.input["role"],
                "skip": case.input.get("skip").cloned().unwrap_or(json!(-1)),
                "rows": case.input["rows"]
                    .as_array()
                    .map_or(&[][..], Vec::as_slice)
                    .iter()
                    .map(|patch| merged(base, patch))
                    .collect::<Vec<Value>>(),
            }),
            ..case
        })
        .collect();
    check_cases(
        "first_run_suggestion",
        &cases,
        &mut JsLib::pure(),
        |input| {
            format!(
                "(function (i) {{
                    var rows = i.rows.map(function (w) {{
                        var row = mapWireInterfaceRow(w);
                        row.selectedRole = w[\"selected-role\"] || \"\";
                        return row;
                    }});
                    return firstRunSuggestion(rows, i.role, i.skip);
                }})({})",
                lit(input)
            )
        },
        |input| {
            let rows: Vec<InterfaceRowDto> = serde_json::from_value(input["rows"].clone())
                .expect("vector rows are InterfaceRowDto");
            let role = if input["role"] == "primary" {
                Route::Primary
            } else {
                Route::Secondary
            };
            let skip = input["skip"].as_u64().and_then(|i| usize::try_from(i).ok());
            json!(adapters::first_run_suggestion(&rows, role, skip)
                .map_or(-1, |i| i64::try_from(i).unwrap_or(-1)))
        },
    );
}

#[test]
fn adapter_driver_siblings_match_js() {
    let (document, cases) = load_vectors("adapter_driver_siblings");
    let base = &document["base-row"];
    let cases: Vec<Case> = cases
        .into_iter()
        .map(|case| Case {
            input: json!({
                "role": case.input["role"],
                "index": case.input["index"],
                "rows": case.input["rows"]
                    .as_array()
                    .map_or(&[][..], Vec::as_slice)
                    .iter()
                    .map(|patch| merged(base, patch))
                    .collect::<Vec<Value>>(),
            }),
            ..case
        })
        .collect();
    check_cases(
        "adapter_driver_siblings",
        &cases,
        &mut JsLib::pure(),
        |input| {
            format!(
                "(function (i) {{
                    var rows = i.rows.map(function (w) {{
                        var row = mapWireInterfaceRow(w);
                        row.selectedRole = w[\"selected-role\"] || \"\";
                        return row;
                    }});
                    return adapterDriverSiblings(rows, i.index, i.role);
                }})({})",
                lit(input)
            )
        },
        |input| {
            let rows: Vec<InterfaceRowDto> = serde_json::from_value(input["rows"].clone())
                .expect("vector rows are InterfaceRowDto");
            let role = if input["role"] == "primary" {
                Route::Primary
            } else {
                Route::Secondary
            };
            let index = input["index"]
                .as_u64()
                .map_or(usize::MAX, |i| usize::try_from(i).unwrap_or(usize::MAX));
            let found = adapters::driver_siblings(&rows, index, role);
            json!({ "live": found.live, "idle": found.idle })
        },
    );
}

#[test]
fn adapter_filter_and_sort_rank_match_js() {
    let (document, cases) = load_vectors("adapter_view");
    let base = &document["base-row"];
    let cases: Vec<Case> = cases
        .into_iter()
        .map(|case| Case {
            input: json!({
                "row": merged(base, &case.input["patch"]),
                "showUnavailable": case.input["showUnavailable"],
                "search": case.input["search"],
                "sortBy": case.input["sortBy"],
            }),
            ..case
        })
        .collect();
    check_cases(
        "adapter_view",
        &cases,
        &mut JsLib::pure(),
        |input| {
            format!(
                "(function (i) {{
                    var row = mapWireInterfaceRow(i.row);
                    row.selectedRole = i.row[\"selected-role\"] || \"\";
                    return {{
                        passes: adapterPassesFilter(row, i.showUnavailable, i.search),
                        rank: adapterSortRank(row, i.sortBy)
                    }}
                }})({})",
                lit(input)
            )
        },
        |input| {
            let row: InterfaceRowDto =
                serde_json::from_value(input["row"].clone()).expect("vector is an InterfaceRowDto");
            json!({
                "passes": adapters::adapter_passes_filter(
                    &row,
                    input["showUnavailable"].as_bool().unwrap_or(false),
                    input["search"].as_str().unwrap_or_default(),
                ),
                "rank": adapters::adapter_sort_rank(&row, input["sortBy"].as_str().unwrap_or_default()),
            })
        },
    );
}

#[test]
fn bound_wire_row_index_matches_js() {
    let (base_document, _) = load_vectors("adapters");
    let base = &base_document["base-row"];
    check(
        "bound_wire_row_index",
        &mut JsLib::pure(),
        |input| {
            format!(
                "boundWireRowIndex({}, {})",
                arg(input, "rows"),
                arg(input, "binding")
            )
        },
        |input| {
            let rows: Vec<InterfaceRowDto> = input["rows"]
                .as_array()
                .expect("rows is an array")
                .iter()
                .map(|patch| {
                    serde_json::from_value(merged(base, patch)).expect("row is an InterfaceRowDto")
                })
                .collect();
            let binding: Option<RouteBindingDto> =
                serde_json::from_value(input["binding"].clone()).expect("binding or null");
            let index = binding
                .and_then(|binding| adapters::bound_row_index(&rows, &binding))
                .map_or(-1, |i| i64::try_from(i).expect("index fits"));
            Value::from(index)
        },
    );
}

#[test]
fn suggested_primary_binding_matches_js() {
    let (base_document, _) = load_vectors("adapters");
    let base = base_document["base-row"].clone();
    // Both sides read the same full rows: the base row under each patch.
    let rows_of = move |input: &Value| -> Value {
        Value::Array(
            input["rows"]
                .as_array()
                .expect("rows is an array")
                .iter()
                .map(|patch| merged(&base, patch))
                .collect(),
        )
    };
    let rows_for_js = rows_of.clone();
    check(
        "suggested_primary_binding",
        &mut JsLib::pure(),
        |input| {
            format!(
                "suggestedPrimaryBinding({}, {})",
                rows_for_js(input),
                arg(input, "name")
            )
        },
        |input| {
            let rows: Vec<InterfaceRowDto> =
                serde_json::from_value(rows_of(input)).expect("rows are InterfaceRowDto");
            let name = input["name"].as_str().expect("name is a string");
            serde_json::to_value(adapters::suggested_primary_binding(&rows, name))
                .expect("binding serialises")
        },
    );
}

#[test]
fn interfaces_source_is_live_matches_js() {
    check(
        "interfaces_source_is_live",
        &mut JsLib::pure(),
        |input| format!("interfacesSourceIsLive({})", arg(input, "source")),
        |input| Value::from(adapters::rows_are_live(text(input, "source"))),
    );
}

// ---- rules table ----

/// A table row in the GUI's model shape.
fn row_from_js(value: &Value) -> RuleRow {
    let has_origin = ["originReason", "originAnchor", "originAdded"]
        .iter()
        .any(|key| value.get(*key).is_some());
    RuleRow {
        id: text(value, "id").to_owned(),
        enabled: value["enabled"].as_bool().unwrap_or(false),
        rule_type: RuleType::from_slug(text(value, "ruleType")),
        match_value: text(value, "matchValue").to_owned(),
        target_route: TargetRoute::from_slug(text(value, "targetRoute")),
        verify: value["verify"].as_bool().unwrap_or(false),
        comment: text(value, "comment").to_owned(),
        origin: has_origin.then(|| RowOrigin {
            reason: text(value, "originReason").to_owned(),
            anchor: text(value, "originAnchor").to_owned(),
            added: text(value, "originAdded").to_owned(),
        }),
    }
}

fn rows_from_js(value: &Value) -> Vec<RuleRow> {
    value
        .as_array()
        .expect("rows is an array")
        .iter()
        .map(row_from_js)
        .collect()
}

fn file_row_to_js(row: &RuleRow) -> Value {
    let origin = row.origin.clone().unwrap_or_default();
    json!({
        "enabled": row.enabled,
        "ruleType": row.rule_type.as_str(),
        "matchValue": row.match_value,
        "targetRoute": row.target_route.as_str(),
        "verify": row.verify,
        "comment": row.comment,
        "originReason": origin.reason,
        "originAnchor": origin.anchor,
        "originAdded": origin.added,
    })
}

fn drift_row_to_js(row: &RuleRow) -> Value {
    json!({
        "enabled": row.enabled,
        "ruleType": row.rule_type.as_str(),
        "matchValue": row.match_value,
        "targetRoute": row.target_route.as_str(),
        "verify": row.verify,
    })
}

#[test]
fn preset_format_version_matches_js() {
    assert_eq!(
        JsLib::rules().eval_json("CANONICAL_PRESET_FORMAT_VERSION"),
        json!(PRESET_FORMAT_VERSION)
    );
}

/// One hint on both sides: the marker the parsers skip, the keys with their
/// English text, and that English as the lines when nothing translates.
#[test]
fn rules_file_hint_matches_js() {
    let mut js = JsLib::rules();
    assert_eq!(
        js.eval_json("RULES_FILE_HINT_PREFIX"),
        json!(nrr_shared::preset_parser::SYNTAX_HINT_PREFIX)
    );
    let keys: Vec<Value> = RULES_FILE_HINT_KEYS
        .iter()
        .map(|(id, en)| json!([id, en]))
        .collect();
    assert_eq!(js.eval_json("RULES_FILE_HINT_KEYS"), Value::from(keys));
    let english: Vec<&str> = RULES_FILE_HINT_KEYS.iter().map(|(_, en)| *en).collect();
    assert_eq!(js.eval_json("rulesFileHintLines(null)"), json!(english));
    let ids: Vec<&str> = RULES_FILE_HINT_KEYS.iter().map(|(id, _)| *id).collect();
    let by_key = "rulesFileHintLines(function (key, fallback) { return key })";
    assert_eq!(js.eval_json(by_key), json!(ids));
}

#[test]
fn route_bucket_matches_js() {
    check(
        "route_bucket",
        &mut JsLib::rules(),
        |input| format!("routeBucket({})", arg(input, "route")),
        |input| {
            let target = TargetRoute::from_slug(text(input, "route"));
            Value::from(
                target
                    .bucket()
                    .map_or(target.as_str(), |bucket| bucket.as_str()),
            )
        },
    );
}

#[test]
fn rule_type_allows_verify_matches_js() {
    check(
        "rule_type_allows_verify",
        &mut JsLib::rules(),
        |input| format!("ruleTypeAllowsVerify({})", arg(input, "ruleType")),
        |input| Value::from(RuleType::from_slug(text(input, "ruleType")).allows_verify()),
    );
}

#[test]
fn row_is_verify_matches_js() {
    check(
        "row_is_verify",
        &mut JsLib::rules(),
        |input| format!("rowIsVerify({})", arg(input, "row")),
        |input| Value::from(row_from_js(&input["row"]).is_verify()),
    );
}

#[test]
fn main_route_rank_matches_js() {
    check(
        "main_route_rank",
        &mut JsLib::rules(),
        |input| format!("mainRouteRank({})", arg(input, "slug")),
        |input| Value::from(main_route_rank(text(input, "slug"))),
    );
}

#[test]
fn rule_override_key_matches_js() {
    check(
        "rule_override_key",
        &mut JsLib::rules(),
        |input| {
            format!(
                "ruleOverrideKey({}, {}, {}, {})",
                arg(input, "ruleType"),
                arg(input, "value"),
                arg(input, "route"),
                arg(input, "os")
            )
        },
        |input| {
            Value::from(rule_override_key(
                text(input, "ruleType"),
                text(input, "value"),
                text(input, "route"),
                text(input, "os"),
            ))
        },
    );
}

#[test]
fn override_remaining_matches_js() {
    check(
        "override_remaining",
        &mut JsLib::rules(),
        |input| {
            format!(
                "overrideRemaining({}, {})",
                arg(input, "until"),
                arg(input, "now")
            )
        },
        |input| {
            let (kind, count) =
                override_remaining(input["until"].as_i64(), input["now"].as_i64().unwrap_or(0));
            json!({ "kind": kind, "count": count })
        },
    );
}

#[test]
fn main_route_check_hosts_matches_js() {
    check(
        "main_route_check_hosts",
        &mut JsLib::rules(),
        |input| format!("mainRouteCheckHosts({})", arg(input, "rows")),
        |input| {
            let given = input["rows"].as_array().expect("rows is an array");
            let rows: Vec<RuleRow> = given.iter().map(row_from_js).collect();
            let ace = given
                .iter()
                .map(|row| row.get("aceMatchValue").and_then(Value::as_str));
            Value::from(main_route_check_hosts(rows.iter().zip(ace)))
        },
    );
}

#[test]
fn row_identity_matches_js() {
    check(
        "row_identity",
        &mut JsLib::rules(),
        |input| {
            format!(
                "(function (row) {{ return {{ mergeKey: mergeKey(row), \
                 signature: ruleSignature(row) }} }})({})",
                arg(input, "row")
            )
        },
        |input| {
            let row = row_from_js(&input["row"]);
            json!({ "mergeKey": row.merge_key(), "signature": row.signature() })
        },
    );
}

#[test]
fn rebase_edits_matches_js() {
    check(
        "rebase_edits",
        &mut JsLib::rules(),
        |input| {
            format!(
                "(function (inp) {{ \
                var line = function (r) {{ return r ? String(r.id || '') + ' ' + String(r.ruleType || '') \
                + ' ' + String(r.matchValue || '') + ' ' + String(r.targetRoute || '') \
                + ' ' + (r.enabled ? 'on' : 'off') + (r.verify ? ' ?' : '') \
                + (r.comment ? ' #' + r.comment : '') : '-' }}; \
                var out = rebaseEdits(inp.base, inp.edited, inp.fresh, inp.keep); \
                return {{ rows: out.rows.map(line), added: out.added.map(line), \
                changed: out.changed.map(line), removed: out.removed.map(line), \
                conflicts: out.conflicts.map(function (c) {{ \
                return c.key + ' ' + c.kind + ' ' + line(c.mine) + ' / ' + line(c.theirs) }}) }} }})({})",
                lit(input)
            )
        },
        |input| {
            let out = rebase_edits(
                &rows_from_js(&input["base"]),
                &rows_from_js(&input["edited"]),
                &rows_from_js(&input["fresh"]),
                &strings(&input["keep"]),
            );
            let line = |row: &RuleRow| {
                format!(
                    "{} {} {} {} {}{}{}",
                    row.id,
                    row.rule_type.as_str(),
                    row.match_value,
                    row.target_route.as_str(),
                    if row.enabled { "on" } else { "off" },
                    if row.verify { " ?" } else { "" },
                    if row.comment.is_empty() {
                        String::new()
                    } else {
                        format!(" #{}", row.comment)
                    }
                )
            };
            let side = |row: &Option<RuleRow>| row.as_ref().map_or("-".to_owned(), line);
            let lines = |rows: &[RuleRow]| rows.iter().map(line).collect::<Vec<_>>();
            json!({
                "rows": lines(&out.rows),
                "added": lines(&out.added),
                "changed": lines(&out.changed),
                "removed": lines(&out.removed),
                "conflicts": out.conflicts.iter().map(|c| format!(
                    "{} {} {} / {}", c.key, c.kind.slug(), side(&c.mine), side(&c.theirs)
                )).collect::<Vec<_>>(),
            })
        },
    );
}

/// The merge review's buckets over the same cases as `rebase_edits`; their
/// own expected output is the agreement of the two sides.
#[test]
fn rebase_merge_view_matches_js() {
    let (_, cases) = load_vectors("rebase_edits");
    let cases: Vec<Case> = cases
        .into_iter()
        .map(|case| Case {
            expected: None,
            ..case
        })
        .collect();
    check_cases(
        "rebase_merge_view",
        &cases,
        &mut JsLib::rules(),
        |input| {
            format!(
                "(function (inp) {{ var item = function (i) {{ return i ? i['type-slug'] + ' ' + i.value : '-' }}; var view = rebaseMergeView(rebaseEdits(inp.base, inp.edited, inp.fresh, inp.keep)); return {{ added: view['file-only'].map(item), changed: view.changed.map(item), removed: view.removed.map(item), conflicts: view.conflicts.map(function (c) {{ return c['identity-key'] + ' ' + c.kind + ' ' + item(c.file) + ' / ' + item(c.service) }}), noop: view.noop }} }})({})",
                lit(input)
            )
        },
        |input| {
            let view = merge_view(&rebase_edits(
                &rows_from_js(&input["base"]),
                &rows_from_js(&input["edited"]),
                &rows_from_js(&input["fresh"]),
                &strings(&input["keep"]),
            ));
            let item = |row: &RuleRow| format!("{} {}", row.rule_type.as_str(), row.match_value);
            let side = |row: &Option<RuleRow>| row.as_ref().map_or("-".to_owned(), item);
            let items = |rows: &[RuleRow]| rows.iter().map(item).collect::<Vec<_>>();
            json!({
                "added": items(&view.added),
                "changed": items(&view.changed),
                "removed": items(&view.removed),
                "conflicts": view.conflicts.iter().map(|c| format!(
                    "{} {} {} / {}", c.key, c.kind.slug(), side(&c.mine), side(&c.theirs)
                )).collect::<Vec<_>>(),
                "noop": view.is_noop(),
            })
        },
    );
}

#[test]
fn rule_row_to_wire_dto_matches_js() {
    check(
        "wire_dto",
        &mut JsLib::rules(),
        |input| {
            format!(
                "(function () {{ try {{ return ruleRowToWireDto({}, {} ? __aceEncode : null, {}) }} \
                 catch (err) {{ return {{ refused: wireRefusalCode(err) }} }} }})()",
                arg(input, "row"),
                arg(input, "encode"),
                arg(input, "opts")
            )
        },
        |input| {
            let opts = &input["opts"];
            let options = WireDtoOptions {
                keep_id: opts.get("keepId") != Some(&Value::Bool(false)),
                keep_comment: opts.get("keepComment") != Some(&Value::Bool(false)),
            };
            let encode: &dyn Fn(&str) -> String = &ace_encode;
            let encode = input["encode"].as_bool().unwrap_or(false).then_some(encode);
            match rule_row_to_wire_dto(&row_from_js(&input["row"]), encode, options) {
                Ok(dto) => serde_json::to_value(dto).expect("RuleDto serialises"),
                Err(refusal) => json!({ "refused": refusal.code() }),
            }
        },
    );
}

#[test]
fn rows_from_service_wire_match_js() {
    check(
        "service_wire_rows",
        &mut JsLib::rules(),
        |input| {
            format!(
                "(function (w) {{ return {{ file: fileRowFromServiceWire(w, __aceDecode), \
                 drift: driftRowFromServiceWire(w) }} }})({})",
                arg(input, "entry")
            )
        },
        |input| {
            let entry: RuleRowEntry =
                serde_json::from_value(input["entry"].clone()).expect("vector is a RuleRowEntry");
            json!({
                "file": file_row_to_js(&file_row_from_service_wire(&entry, ace_decode)),
                "drift": drift_row_to_js(&drift_row_from_service_wire(&entry)),
            })
        },
    );
}

#[test]
fn rows_from_parsed_rules_match_js() {
    check(
        "parsed_rules",
        &mut JsLib::rules(),
        |input| {
            format!(
                "(function (r, route) {{ return {{ target: parsedRuleTargetRoute(r, route), \
                 verify: parsedRuleVerify(r), \
                 value: parsedRuleStoredValue(r), \
                 drift: driftRowFromParsedRule(r, route) }} }})({}, {})",
                arg(input, "rule"),
                arg(input, "route")
            )
        },
        |input| {
            let rule: ParsedRule =
                serde_json::from_value(input["rule"].clone()).expect("vector is a ParsedRule");
            let file = route(input);
            json!({
                "target": parsed_rule_target_route(&rule, file).as_str(),
                "verify": parsed_rule_verify(&rule),
                "value": rule.stored_value(),
                "drift": drift_row_to_js(&drift_row_from_parsed_rule(&rule, file)),
            })
        },
    );
}

/// The OS a vector writes for; the machine running the test when it names none.
fn os_of(input: &Value) -> &str {
    input["os"]
        .as_str()
        .unwrap_or(nrr_shared::platform_profile::PlatformProfile::current().os)
}

#[test]
fn rules_file_text_matches_js() {
    check(
        "rules_file_text",
        &mut JsLib::rules(),
        |input| {
            format!(
                "buildCanonicalRulesText(__model({}), {}, {}, {}, {}, {})",
                arg(input, "rows"),
                arg(input, "route"),
                arg(input, "passthrough"),
                arg(input, "includeComments"),
                lit(&Value::from(os_of(input))),
                arg(input, "hint")
            )
        },
        |input| {
            let passthrough: BTreeMap<String, String> = object(&input["passthrough"])
                .into_iter()
                .map(|(name, raw)| (name, raw.as_str().unwrap_or_default().to_owned()))
                .collect();
            let hint = strings(&input["hint"]);
            let options = RulesFileOptions {
                include_comments: input["includeComments"].as_bool().unwrap_or(true),
                exported_at: EXPORTED_AT,
                passthrough: &passthrough,
                os: os_of(input),
                syntax_hint: &hint,
            };
            Value::from(build_rules_file_text(
                &rows_from_js(&input["rows"]),
                route(input),
                &options,
            ))
        },
    );
}

// ---- search and review ----

#[test]
fn normalize_host_input_matches_js() {
    check(
        "host_input",
        &mut JsLib::rules(),
        |input| {
            format!(
                "normalizeHostInput({}, {})",
                arg(input, "type"),
                arg(input, "raw")
            )
        },
        |input| {
            Value::from(normalize_host_input(
                &RuleType::from_slug(text(input, "type")),
                text(input, "raw"),
            ))
        },
    );
}

fn outcome_json(outcome: Option<Outcome>) -> Value {
    match outcome {
        None => Value::Null,
        Some(Outcome::Applied) => Value::from(""),
        Some(Outcome::Failed(code)) => Value::from(code),
    }
}

#[test]
fn review_summary_matches_js() {
    let (document, cases) = load_vectors("review_summary");
    let base = document["base-summary"].clone();
    let summary_of = |input: &Value| merged(&base, &input["patch"]);
    check_cases(
        "review_summary",
        &cases,
        &mut JsLib::pure(),
        |input| {
            format!(
                "(function (s) {{ var r = previewRefusal(s); return {{ empty: reviewSummaryIsEmpty(s), refusal: r === null ? null : {{ code: r.code, values: r.values, args: r.args || {{}} }}, outcome: previewOutcome(s, reviewSummaryIsEmpty) }} }})({})",
                lit(&summary_of(input))
            )
        },
        |input| {
            let summary: ReviewSummaryResponse =
                serde_json::from_value(summary_of(input)).expect("vector summary parses");
            let refusal = review::preview_refusal(&summary)
                .map(|r| json!({ "code": r.code, "values": r.values, "args": r.args }));
            json!({
                "empty": review::review_summary_is_empty(&summary),
                "refusal": refusal,
                "outcome": outcome_json(Some(review::preview_outcome(
                    &summary,
                    review::review_summary_is_empty,
                ))),
            })
        },
    );
}

#[test]
fn refusal_detail_matches_js() {
    check(
        "refusal_detail",
        &mut JsLib::pure(),
        |input| {
            format!(
                "(function (d) {{ return d === null ? null : {{ key: d.key, values: Object.keys(d.values).map(function (k) {{ return [k, d.values[k]] }}) }} }}) (refusalDetail({}, {}))",
                arg(input, "code"),
                arg(input, "args")
            )
        },
        |input| {
            let args: BTreeMap<String, String> = object(&input["args"])
                .into_iter()
                .map(|(k, v)| (k, v.as_str().unwrap_or_default().to_owned()))
                .collect();
            review::refusal_detail(text(input, "code"), &args)
                .map_or(Value::Null, |d| json!({ "key": d.key, "values": d.values }))
        },
    );
}

#[test]
fn operation_outcome_matches_js() {
    check(
        "operation_outcome",
        &mut JsLib::pure(),
        |input| {
            format!(
                "operationOutcome({}, {})",
                arg(input, "ok"),
                arg(input, "status")
            )
        },
        |input| {
            let status: Option<OperationStatusResponse> = input["ok"]
                .as_bool()
                .filter(|ok| *ok)
                .and_then(|_| serde_json::from_value(input["status"].clone()).ok());
            outcome_json(review::operation_outcome(status.as_ref()))
        },
    );
}
