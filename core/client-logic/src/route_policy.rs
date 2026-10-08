//! The read-modify-write of `route.policy.update`.
//!
//! The operation is a FULL replacement: every field a request leaves out falls
//! back to the service's serde default and silently resets what the user had
//! configured. A writer therefore starts from [`build_full_update_request`]
//! over the live snapshot and overlays only the keys it changes.
//!
//! [`FIELD_DEFAULTS`] mirrors `ROUTE_POLICY_FIELD_DEFAULTS` in `pure.js`; each
//! value equals the serde default of the same field in
//! `nrr_shared::ipc_payloads::RoutePolicyUpdateRequest`, which is normative.

use serde_json::{Map, Value};

use crate::js;

/// The value a route-policy field takes when the snapshot does not carry it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldDefault {
    Bool(bool),
    Int(i32),
    Text(&'static str),
}

impl FieldDefault {
    /// The default as a wire value.
    pub fn to_value(self) -> Value {
        match self {
            Self::Bool(b) => Value::Bool(b),
            Self::Int(n) => Value::from(n),
            Self::Text(s) => Value::from(s),
        }
    }
}

/// Every route-policy field this build writes, with its default.
/// `binding-source` is absent on purpose: the writer always stamps it.
pub const FIELD_DEFAULTS: [(&str, FieldDefault); 25] = [
    ("mode", FieldDefault::Text("prefer-primary")),
    (
        "block-secondary-when-unavailable",
        FieldDefault::Bool(false),
    ),
    ("kill-switch-fail-closed", FieldDefault::Bool(true)),
    ("kill-switch-protocols", FieldDefault::Int(127)),
    ("kill-switch-block-all", FieldDefault::Bool(false)),
    ("kill-switch-enabled", FieldDefault::Bool(false)),
    ("allow-dns-over-primary", FieldDefault::Bool(true)),
    ("include-subdomains", FieldDefault::Bool(true)),
    ("shared-ip-policy", FieldDefault::Text("majority-of-ip")),
    ("mode-a-coverage-strategy", FieldDefault::Text("per-ip")),
    ("resolve-hosts-bypass", FieldDefault::Bool(true)),
    ("doh-lockdown-enabled", FieldDefault::Bool(false)),
    (
        "doh-lockdown-scope",
        FieldDefault::Text("leak-protection-only"),
    ),
    ("browser-history-auto-seed", FieldDefault::Bool(false)),
    ("kill-switch-strict-shared-ips", FieldDefault::Bool(false)),
    ("auto-rules-mode", FieldDefault::Text("suggest")),
    ("auto-rules-eager-delivery-names", FieldDefault::Bool(false)),
    ("primary-probe-auto", FieldDefault::Bool(false)),
    ("primary-probe-timeout-ms", FieldDefault::Int(1500)),
    ("primary-probe-max-targets", FieldDefault::Int(8)),
    ("primary-probe-repeat-secs", FieldDefault::Int(300)),
    ("local-networks-auto-accept", FieldDefault::Bool(false)),
    ("zone-priority-over-ip", FieldDefault::Bool(false)),
    ("short-name-completion", FieldDefault::Bool(false)),
    ("short-name-suffix", FieldDefault::Text("")),
];

/// Keys the snapshot carries but the request has no field for: each is
/// written through its own operation.
pub const SNAPSHOT_ONLY_KEYS: [&str; 1] = ["secondary-link-provider-apps"];

/// The key of the leak-protection protocol bitmask.
pub const KILL_SWITCH_PROTOCOLS_KEY: &str = "kill-switch-protocols";
/// Every bit the protocol mask may set.
pub const KILL_SWITCH_PROTOCOLS_ALL: i32 = 0x7F;
/// The bits that block something; "other" (64) blocks nothing.
pub const KILL_SWITCH_PROTOCOLS_ENFORCED: i32 = 0x3F;

const BINDING_SOURCE_KEY: &str = "binding-source";
const BINDING_SOURCE_USER_ASSIGNED: &str = "user-assigned";

/// The declared default of `key`; `None` for a key that is not a
/// route-policy field.
pub fn field_default(key: &str) -> Option<FieldDefault> {
    FIELD_DEFAULTS
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, default)| *default)
}

/// One value normalised to the shape the wire expects (`routePolicyCoerce`).
///
/// Absent (`Null`) and `""` read as the default, so a snapshot value, a parked
/// intent and a literal stay comparable. A boolean is `true` only when it is
/// `true`; a number goes through JS `| 0`; the protocol mask falls back to the
/// default when it blocks nothing or sets a bit outside its mask. A key that
/// is not a route-policy field passes through unchanged.
pub fn coerce(key: &str, raw: &Value) -> Value {
    let Some(default) = field_default(key) else {
        return raw.clone();
    };
    if raw.is_null() || raw.as_str() == Some("") {
        return default.to_value();
    }
    match default {
        FieldDefault::Bool(_) => Value::Bool(*raw == Value::Bool(true)),
        FieldDefault::Int(fallback) => {
            let n = js::to_int32(js::to_number(raw));
            let valid = key != KILL_SWITCH_PROTOCOLS_KEY || is_protocol_selection(n);
            Value::from(if valid { n } else { fallback })
        }
        FieldDefault::Text(_) => Value::String(js::to_display_string(raw)),
    }
}

/// The rule of `nrr_shared::ipc_payloads::is_valid_kill_switch_protocols`.
fn is_protocol_selection(mask: i32) -> bool {
    (mask & KILL_SWITCH_PROTOCOLS_ENFORCED) != 0 && (mask & !KILL_SWITCH_PROTOCOLS_ALL) == 0
}

/// The effective current value of `key` in a snapshot (or any map with the
/// same wire keys); `None` when `key` is not a route-policy field.
pub fn effective(snapshot: &Map<String, Value>, key: &str) -> Option<Value> {
    field_default(key)?;
    Some(coerce(key, snapshot.get(key).unwrap_or(&Value::Null)))
}

/// The full `route.policy.update` request built from a policy snapshot
/// (`buildFullRoutePolicyReq`).
///
/// Everything the snapshot carries rides back unchanged — a field this build
/// has never heard of included — except the snapshot-only keys and nulls; then
/// every declared field is normalised and filled, so neither an empty snapshot
/// nor an older one lets a serde default win. `mode_fallback` is the local
/// behaviour-mode preference, consulted before the contract default.
pub fn build_full_update_request(
    snapshot: &Map<String, Value>,
    mode_fallback: &str,
) -> Map<String, Value> {
    let mut request: Map<String, Value> = snapshot
        .iter()
        .filter(|(key, value)| !value.is_null() && !SNAPSHOT_ONLY_KEYS.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    if !request.get("mode").is_some_and(js::is_truthy) {
        request.insert("mode".to_owned(), Value::from(mode_fallback));
    }
    for (key, _) in FIELD_DEFAULTS {
        let value = coerce(key, request.get(key).unwrap_or(&Value::Null));
        request.insert(key.to_owned(), value);
    }
    // `recovery` / `migrated-from-preferences` belong to the service and to
    // migration; echoing one back would misattribute a user edit.
    request.insert(
        BINDING_SOURCE_KEY.to_owned(),
        Value::from(BINDING_SOURCE_USER_ASSIGNED),
    );
    request
}

/// The fields `request` changes against `base`, the full request built from
/// the same snapshot (`routePolicyChangedKeys`), sorted. `binding-source` is
/// the write's provenance and is sent with every write.
pub fn changed_keys(base: &Map<String, Value>, request: &Map<String, Value>) -> Vec<String> {
    let mut changed: Vec<String> = base
        .keys()
        .chain(request.keys().filter(|key| !base.contains_key(*key)))
        .filter(|key| key.as_str() != BINDING_SOURCE_KEY && key.as_str() != APPLY_ONLY_KEY)
        .filter(|key| base.get(*key) != request.get(*key))
        .cloned()
        .collect();
    changed.sort();
    changed
}

/// `request` naming only what it changes against `base`, so a concurrent
/// write from the tray or the window is not reverted; `None` when it changes
/// nothing and there is nothing to send.
pub fn name_changes(
    base: &Map<String, Value>,
    mut request: Map<String, Value>,
) -> Option<Map<String, Value>> {
    let changed = changed_keys(base, &request);
    if changed.is_empty() {
        return None;
    }
    request.insert(APPLY_ONLY_KEY.to_owned(), Value::from(changed));
    Some(request)
}

/// The request field naming the fields a write changes.
const APPLY_ONLY_KEY: &str = "apply-only";

fn enforced_protocols(mask: &Value) -> i32 {
    let coerced = coerce(KILL_SWITCH_PROTOCOLS_KEY, mask);
    let n = coerced
        .as_i64()
        .and_then(|n| i32::try_from(n).ok())
        .unwrap_or(0);
    n & KILL_SWITCH_PROTOCOLS_ENFORCED
}

/// Whether protocol box `bit` must stay ticked: it is the last one that
/// blocks something, and the service refuses a selection that blocks nothing.
pub fn kill_switch_protocol_locked(mask: &Value, bit: i32) -> bool {
    let m = enforced_protocols(mask);
    (m & bit) != 0 && (m & !bit) == 0
}

/// Whether exactly one blocking protocol is left, i.e. its box is locked.
pub fn kill_switch_protocols_at_last_one(mask: &Value) -> bool {
    let m = enforced_protocols(mask);
    m != 0 && (m & (m - 1)) == 0
}
