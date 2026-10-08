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
    fill_placeholders, format_log_line, plural_category, PluralRule,
};
use nrr_client_logic::review::{self, Outcome};
use nrr_client_logic::route_policy;
use nrr_client_logic::rules_table::{
    build_rules_file_text, drift_row_from_parsed_rule, drift_row_from_service_wire,
    file_row_from_service_wire, normalize_host_input, parsed_rule_target_route,
    rule_row_to_wire_dto, RowOrigin, RuleRow, RuleType, RulesFileOptions, TargetRoute,
    WireDtoOptions, PRESET_FORMAT_VERSION,
};
use nrr_client_logic::Route;
use nrr_shared::ipc_payloads::{
    InterfaceRowDto, OperationStatusResponse, ReviewSummaryResponse, RuleRowEntry,
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
    })
}

#[test]
fn preset_format_version_matches_js() {
    assert_eq!(
        JsLib::rules().eval_json("CANONICAL_PRESET_FORMAT_VERSION"),
        json!(PRESET_FORMAT_VERSION)
    );
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
fn route_for_rule_type_matches_js() {
    check(
        "route_for_rule_type",
        &mut JsLib::rules(),
        |input| {
            format!(
                "routeForRuleType({}, {})",
                arg(input, "route"),
                arg(input, "ruleType")
            )
        },
        |input| {
            let rule_type = RuleType::from_slug(text(input, "ruleType"));
            Value::from(
                TargetRoute::from_slug(text(input, "route"))
                    .for_rule_type(&rule_type)
                    .as_str(),
            )
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
fn rule_row_to_wire_dto_matches_js() {
    check(
        "wire_dto",
        &mut JsLib::rules(),
        |input| {
            format!(
                "ruleRowToWireDto({}, {} ? __aceEncode : null, {})",
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
            let dto = rule_row_to_wire_dto(&row_from_js(&input["row"]), encode, options);
            serde_json::to_value(dto).expect("RuleDto serialises")
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
                "buildCanonicalRulesText(__model({}), {}, {}, {}, {})",
                arg(input, "rows"),
                arg(input, "route"),
                arg(input, "passthrough"),
                arg(input, "includeComments"),
                lit(&Value::from(os_of(input)))
            )
        },
        |input| {
            let passthrough: BTreeMap<String, String> = object(&input["passthrough"])
                .into_iter()
                .map(|(name, raw)| (name, raw.as_str().unwrap_or_default().to_owned()))
                .collect();
            let options = RulesFileOptions {
                include_comments: input["includeComments"].as_bool().unwrap_or(true),
                exported_at: EXPORTED_AT,
                passthrough: &passthrough,
                os: os_of(input),
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
