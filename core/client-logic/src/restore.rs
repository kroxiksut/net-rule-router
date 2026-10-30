//! "Restore my settings" after the service lost them — its data reset or the
//! service reinstalled (`routePolicyIntentAfterWrite`,
//! `routePolicyIntentDivergence`, `routePolicyRestorePlan` and
//! `noticeMutesToRestore` in `pure.js`).
//!
//! The record is what the user asked for and the service confirmed, kept in
//! the user's own settings file. Nothing here writes: a difference is offered,
//! and only the user's answer sends it.

use serde_json::{json, Map, Value};

use crate::js;
use crate::route_policy::{
    build_full_update_request, coerce, coerce_leak_protection, effective, leak_protection_rank,
    settle_leak_protection, DEFAULT_ROUTES, DEFAULT_ROUTE_MAIN, LEAK_PROTECTION_EVERYTHING,
    LEAK_PROTECTION_KEY,
};

/// The two adapter-binding slots of the route policy.
pub const BINDING_KEYS: [&str; 2] = ["primary", "secondary"];

const APPLY_ONLY_KEY: &str = "apply-only";

/// The protective settings. After the service lost them they come back without
/// asking, and only ever made stronger that way: a damaged or stale record can
/// never be what weakens protection.
pub const PROTECTIVE_KEYS: [&str; 3] = [
    "doh-lockdown-enabled",
    "kill-switch-strict-shared-ips",
    LEAK_PROTECTION_KEY,
];

/// The default route an earlier build offered for "no leaks at all".
const RETIRED_STRICT_MODE: &str = "strict-secondary-fail-closed";

/// The leak-protection settings of an earlier build, folded into one choice.
const RETIRED_GUARD_KEYS: [&str; 4] = [
    "kill-switch-enabled",
    "kill-switch-fail-closed",
    "kill-switch-block-all",
    "mode-a-coverage-strategy",
];

/// A setting of an earlier build that nothing reads any more.
const RETIRED_DEAD_KEY: &str = "block-secondary-when-unavailable";

/// What the retired settings of `intent` meant, mapped as the service's own
/// migration maps its rows; `None` when the record holds none of them.
fn retired_level(intent: &Map<String, Value>) -> Option<&'static str> {
    let mode = intent.get("mode").and_then(Value::as_str);
    if mode == Some(RETIRED_STRICT_MODE) {
        return Some("everything");
    }
    if !RETIRED_GUARD_KEYS
        .iter()
        .any(|key| intent.contains_key(*key))
    {
        return None;
    }
    let on = |key: &str| intent.get(key) == Some(&Value::Bool(true));
    let fail_closed = intent.get("kill-switch-fail-closed") != Some(&Value::Bool(false));
    if !on("kill-switch-enabled") || !fail_closed {
        return Some("off");
    }
    let unresolved = intent
        .get("mode-a-coverage-strategy")
        .and_then(Value::as_str)
        == Some("fail-closed-unknown");
    let main = mode.filter(|m| !m.is_empty()).unwrap_or(DEFAULT_ROUTE_MAIN) == DEFAULT_ROUTE_MAIN;
    Some(if on("kill-switch-block-all") || unresolved || !main {
        "everything"
    } else {
        "sites"
    })
}

/// `intent` in this build's keys (`routePolicyIntentUpgrade`). A record kept
/// before leak protection was one choice still restores what it protected:
/// the strict mode becomes the additional default route with everything, the
/// old guard its level. A level the record holds was written by this build,
/// after them, and stands.
pub fn upgrade_record(intent: &Map<String, Value>) -> Map<String, Value> {
    let level = retired_level(intent);
    let mut next = intent.clone();
    for key in RETIRED_GUARD_KEYS.into_iter().chain([RETIRED_DEAD_KEY]) {
        next.remove(key);
    }
    if next.get("mode").and_then(Value::as_str) == Some(RETIRED_STRICT_MODE) {
        next.insert("mode".to_owned(), Value::from(DEFAULT_ROUTES[1]));
    }
    if let Some(level) = level.filter(|_| !next.contains_key(LEAK_PROTECTION_KEY)) {
        next.insert(LEAK_PROTECTION_KEY.to_owned(), Value::from(level));
    }
    next
}

/// The value that brings `key` back to what the record holds, when that is
/// stronger than what the service holds. Leak protection is read under the
/// service's default route, which the restore does not change.
fn strengthened(key: &str, mine: &Value, service: &Map<String, Value>) -> Option<Value> {
    if key != LEAK_PROTECTION_KEY {
        let on = coerce(key, mine) == Value::Bool(true)
            && effective(service, key) == Some(Value::Bool(false));
        return on.then_some(Value::Bool(true));
    }
    let mode = effective(service, "mode").unwrap_or(Value::Null);
    let mode = mode.as_str().unwrap_or_default();
    let wanted = coerce(key, mine);
    let wanted = coerce_leak_protection(mode, wanted.as_str().unwrap_or_default());
    let held = effective(service, key).unwrap_or(Value::Null);
    let held = coerce_leak_protection(mode, held.as_str().unwrap_or_default());
    // With no additional adapter bound "Everything" closes the internet: that
    // goes only on the user's answer, offered with the binding.
    let unbound = service.get("secondary").and_then(binding_id).is_none();
    if wanted == LEAK_PROTECTION_EVERYTHING && unbound {
        return None;
    }
    (leak_protection_rank(wanted) > leak_protection_rank(held)).then(|| Value::from(wanted))
}

fn protection_values(
    intent: &Map<String, Value>,
    service: &Map<String, Value>,
) -> Vec<(String, Value)> {
    let intent = &upgrade_record(intent);
    PROTECTIVE_KEYS
        .iter()
        .filter_map(|key| {
            let value = strengthened(key, intent.get(*key)?, service)?;
            Some(((*key).to_owned(), value))
        })
        .collect()
}

/// The protective keys the record holds stronger than the service, sorted
/// (`routePolicyProtectionToRestore`).
pub fn protection_to_restore(
    intent: &Map<String, Value>,
    service: &Map<String, Value>,
) -> Vec<String> {
    protection_values(intent, service)
        .into_iter()
        .map(|(key, _)| key)
        .collect()
}

/// The one apply-only write that brings them back, over the service's row;
/// `None` when the service holds nothing weaker than the record
/// (`routePolicyProtectionRestore`).
pub fn protection_restore(
    intent: &Map<String, Value>,
    service: &Map<String, Value>,
) -> Option<Map<String, Value>> {
    let values = protection_values(intent, service);
    if values.is_empty() {
        return None;
    }
    let mut request = build_full_update_request(service, "");
    let keys: Vec<String> = values.iter().map(|(key, _)| key.clone()).collect();
    request.extend(values);
    request.insert(APPLY_ONLY_KEY.to_owned(), Value::from(keys));
    Some(request)
}

/// A recorded binding whose adapter is not on this machine now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissingAdapter {
    /// `"primary"` or `"secondary"`.
    pub role: String,
    /// The name the adapter was recorded under.
    pub name: String,
}

/// What "Restore my settings" sends.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RestorePlan {
    /// An `apply-only` `route.policy.update` request, or `None` when nothing
    /// can be restored.
    pub request: Option<Map<String, Value>>,
    /// The keys the request restores, sorted.
    pub keys: Vec<String>,
    /// Bindings left out because their adapter is missing.
    pub missing: Vec<MissingAdapter>,
}

/// The route-policy record after a write the service confirmed: every key the
/// write named takes the request's value. A key the request leaves out or sets
/// to `null` — an unbinding — is dropped: it is not a setting to restore.
pub fn record_route_policy(
    intent: &Map<String, Value>,
    request: &Map<String, Value>,
    keys: &[String],
) -> Map<String, Value> {
    let mut next = upgrade_record(intent);
    for key in keys {
        match request.get(key) {
            Some(value) if !value.is_null() => {
                next.insert(key.clone(), value.clone());
            }
            _ => {
                next.remove(key);
            }
        }
    }
    next
}

fn binding_id(binding: &Value) -> Option<&str> {
    binding
        .get("stable-id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
}

/// Whether the service's slot holds the adapter `id`, under its current id or
/// one it re-matched from.
fn binding_holds(slot: Option<&Value>, id: &str) -> bool {
    let Some(slot) = slot.filter(|slot| slot.is_object()) else {
        return false;
    };
    let known = slot.get("known-stable-ids").and_then(Value::as_array);
    binding_id(slot) == Some(id)
        || known.is_some_and(|ids| ids.iter().any(|known| known.as_str() == Some(id)))
}

fn diverges(key: &str, mine: &Value, service: &Map<String, Value>) -> bool {
    if BINDING_KEYS.contains(&key) {
        return binding_id(mine).is_some_and(|id| !binding_holds(service.get(key), id));
    }
    // A default route the service no longer accepts is not a setting to restore.
    if key == "mode"
        && !coerce(key, mine)
            .as_str()
            .is_some_and(|m| DEFAULT_ROUTES.contains(&m))
    {
        return false;
    }
    effective(service, key).is_some_and(|current| as_service_reads(key, mine, service) != current)
}

/// The recorded value as the service's default route offers it: "Routed
/// sites" under the additional connection is "Everything" there.
fn as_service_reads(key: &str, mine: &Value, service: &Map<String, Value>) -> Value {
    let value = coerce(key, mine);
    if key != LEAK_PROTECTION_KEY {
        return value;
    }
    let mode = effective(service, "mode").unwrap_or(Value::Null);
    Value::from(coerce_leak_protection(
        mode.as_str().unwrap_or_default(),
        value.as_str().unwrap_or_default(),
    ))
}

/// The recorded keys the service holds otherwise, sorted. Values compare as
/// the wire reads them (`"1500"` is `1500`); a binding compares by adapter id;
/// a key this build has no field for is not compared.
pub fn route_policy_divergence(
    intent: &Map<String, Value>,
    service: &Map<String, Value>,
) -> Vec<String> {
    let intent = upgrade_record(intent);
    let mut keys: Vec<String> = intent
        .iter()
        .filter(|(key, mine)| diverges(key, mine, service))
        .map(|(key, _)| key.clone())
        .collect();
    keys.sort();
    keys
}

/// The restore of the diverging keys as one `apply-only` write over the
/// service's row. A binding goes only when its adapter is on the machine now
/// (`present_ids`); otherwise it is reported missing and left out. Protection
/// the record holds on is not offered: [`protection_restore`] has sent it.
pub fn restore_plan(
    intent: &Map<String, Value>,
    service: &Map<String, Value>,
    present_ids: &[&str],
) -> RestorePlan {
    let intent = &upgrade_record(intent);
    let mut request = build_full_update_request(service, "");
    let mut plan = RestorePlan::default();
    let automatic = protection_to_restore(intent, service);
    for key in route_policy_divergence(intent, service) {
        if automatic.contains(&key) {
            continue;
        }
        let Some(mine) = intent.get(&key) else {
            continue;
        };
        if BINDING_KEYS.contains(&key.as_str()) {
            let id = binding_id(mine).unwrap_or_default();
            if !present_ids.contains(&id) {
                let name = mine
                    .get("display-name")
                    .and_then(Value::as_str)
                    .filter(|name| !name.is_empty())
                    .unwrap_or(id);
                plan.missing.push(MissingAdapter {
                    role: key,
                    name: name.to_owned(),
                });
                continue;
            }
            request.insert(key.clone(), binding_request(mine, id));
        } else {
            request.insert(key.clone(), coerce(&key, mine));
        }
        plan.keys.push(key);
    }
    if !plan.keys.is_empty() {
        // A restored default route may not offer the level the row holds; the
        // level it moves to is then part of the write.
        let held = request.get(LEAK_PROTECTION_KEY).cloned();
        settle_leak_protection(&mut request);
        let key = LEAK_PROTECTION_KEY.to_owned();
        if request.get(LEAK_PROTECTION_KEY) != held.as_ref() && !plan.keys.contains(&key) {
            plan.keys.push(key);
            plan.keys.sort();
        }
        request.insert(APPLY_ONLY_KEY.to_owned(), Value::from(plan.keys.clone()));
        plan.request = Some(request);
    }
    plan
}

/// A recorded binding as the request carries it.
fn binding_request(mine: &Value, id: &str) -> Value {
    let name = mine
        .get("display-name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .unwrap_or(id);
    json!({
        "stable-id": id,
        "display-name": name,
        "user-confirmed": mine.get("user-confirmed") == Some(&Value::Bool(true)),
    })
}

/// The stable ids of the adapters a snapshot (`snapshot.initial.get`) lists:
/// the adapter entries and the presented rows, each id once.
pub fn present_adapter_ids(snapshot: &Value) -> Vec<String> {
    let adapters = snapshot.get("adapters");
    let mut ids: Vec<String> = Vec::new();
    for list in ["adapters", "rows"] {
        let entries = adapters.and_then(|a| a.get(list)).and_then(Value::as_array);
        for entry in entries.into_iter().flatten() {
            let id = entry.get("persistent-id").and_then(Value::as_str);
            if let Some(id) = id.filter(|id| !id.is_empty()) {
                if !ids.iter().any(|known| known == id) {
                    ids.push(id.to_owned());
                }
            }
        }
    }
    ids
}

/// The `block-notices.mutes.set` requests that bring back recorded mutes the
/// service does not hold, in the recorded order. A mute whose deadline has
/// passed is not brought back.
pub fn mutes_to_restore(intent: &Value, service: &Value, now_ms: i64) -> Vec<Value> {
    let Some(recorded) = intent.as_array() else {
        return Vec::new();
    };
    let held: Vec<&Value> = service
        .as_array()
        .map(|mutes| mutes.iter().filter_map(|mute| mute.get("scope")).collect())
        .unwrap_or_default();
    recorded
        .iter()
        .filter_map(|mute| {
            let scope = mute.get("scope").filter(|scope| scope.is_object())?;
            if held.contains(&scope) {
                return None;
            }
            let until = mute
                .get("until-unix-ms")
                .filter(|until| js::is_truthy(until));
            let deadline = until.map_or(0.0, js::to_number);
            if deadline > 0.0 && deadline <= now_ms as f64 {
                return None;
            }
            let mut request = json!({ "scope": scope });
            if let Some(until) = until {
                request["until-unix-ms"] = until.clone();
            }
            Some(request)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(value: Value) -> Map<String, Value> {
        value.as_object().cloned().unwrap_or_default()
    }

    #[test]
    fn a_wiped_service_diverges_from_the_record() {
        let intent = object(json!({
            "leak-protection": "sites",
            "primary-probe-timeout-ms": "2000",
            "secondary": { "stable-id": "B", "display-name": "Tunnel", "user-confirmed": true }
        }));
        let keys = route_policy_divergence(&intent, &Map::new());
        assert_eq!(
            keys,
            ["leak-protection", "primary-probe-timeout-ms", "secondary"]
        );
        let same = object(json!({
            "leak-protection": "sites",
            "primary-probe-timeout-ms": 2000,
            "secondary": { "stable-id": "B2", "known-stable-ids": ["B"] }
        }));
        assert!(route_policy_divergence(&intent, &same).is_empty());
    }

    #[test]
    fn a_missing_adapter_is_reported_and_left_out() {
        let intent = object(json!({
            "mode": "prefer-secondary-when-available",
            "secondary": { "stable-id": "B", "display-name": "Tunnel", "user-confirmed": true }
        }));
        let plan = restore_plan(&intent, &Map::new(), &["A"]);
        assert_eq!(plan.keys, ["mode"]);
        assert_eq!(
            plan.missing,
            [MissingAdapter {
                role: "secondary".into(),
                name: "Tunnel".into()
            }]
        );
        let request = plan.request.expect("a request");
        assert_eq!(request["apply-only"], json!(["mode"]));
        assert!(request.get("secondary").is_none());

        let with_adapter = restore_plan(&intent, &Map::new(), &["B"]);
        let request = with_adapter.request.expect("a request");
        assert_eq!(request["secondary"]["stable-id"], json!("B"));
    }

    #[test]
    fn an_expired_or_held_mute_is_not_brought_back() {
        let recorded = json!([
            { "scope": { "kind": "all" } },
            { "scope": { "kind": "host", "host": "a.example" }, "until-unix-ms": 10 },
            { "scope": { "kind": "app", "app": "x.exe" }, "until-unix-ms": 5000 }
        ]);
        let held = json!([{ "scope": { "kind": "all" } }]);
        let back = mutes_to_restore(&recorded, &held, 100);
        assert_eq!(
            back,
            [json!({ "scope": { "kind": "app", "app": "x.exe" }, "until-unix-ms": 5000 })]
        );
    }

    #[test]
    fn present_adapters_come_from_entries_and_rows() {
        let snapshot = json!({ "adapters": {
            "adapters": [{ "persistent-id": "A" }, { "persistent-id": "" }],
            "rows": [{ "persistent-id": "A" }, { "persistent-id": "B" }]
        }});
        assert_eq!(present_adapter_ids(&snapshot), ["A", "B"]);
        assert!(present_adapter_ids(&json!({})).is_empty());
    }

    #[test]
    fn a_write_records_its_keys_and_an_unbinding_drops_one() {
        let intent = object(json!({ "primary": { "stable-id": "A" }, "mode": "prefer-primary" }));
        let request = object(json!({ "mode": "prefer-secondary-when-available" }));
        let keys = ["mode".to_owned(), "primary".to_owned()];
        let next = record_route_policy(&intent, &request, &keys);
        assert_eq!(
            Value::Object(next),
            json!({ "mode": "prefer-secondary-when-available" })
        );
    }

    #[test]
    fn leak_protection_comes_back_only_stronger_and_as_the_route_offers_it() {
        let secondary = object(json!({
            "mode": "prefer-secondary-when-available",
            "leak-protection": "off",
            "secondary": { "stable-id": "B" }
        }));
        let request =
            protection_restore(&object(json!({ "leak-protection": "sites" })), &secondary)
                .expect("off is weaker than what the record holds");
        assert_eq!(request["leak-protection"], json!("everything"));
        assert_eq!(request["apply-only"], json!(["leak-protection"]));

        let everything = object(json!({ "leak-protection": "everything" }));
        let weaker = object(json!({ "leak-protection": "sites" }));
        assert!(protection_to_restore(&weaker, &everything).is_empty());
    }

    #[test]
    fn everything_is_never_sent_unasked_to_a_service_with_no_additional_adapter() {
        let intent = object(json!({
            "leak-protection": "everything",
            "secondary": { "stable-id": "B", "display-name": "Tunnel", "user-confirmed": true }
        }));
        assert_eq!(protection_restore(&intent, &Map::new()), None);
        let unbound = object(json!({ "leak-protection": "sites", "secondary": null }));
        assert_eq!(protection_restore(&intent, &unbound), None);
    }

    #[test]
    fn a_restored_default_route_settles_the_level_it_cannot_offer() {
        let intent = object(json!({ "mode": "prefer-secondary-when-available" }));
        let service = object(json!({ "mode": "prefer-primary", "leak-protection": "sites" }));
        let plan = restore_plan(&intent, &service, &[]);
        assert_eq!(plan.keys, ["leak-protection", "mode"]);
        let request = plan.request.expect("the default route diverges");
        assert_eq!(request["leak-protection"], json!("everything"));
        assert_eq!(request["apply-only"], json!(["leak-protection", "mode"]));
    }
}
