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
/// `mode` and `leak-protection` have no wire default; theirs is the fallback
/// for a snapshot that lacks them, and protection never reads as on by guess.
pub const FIELD_DEFAULTS: [(&str, FieldDefault); 25] = [
    ("mode", FieldDefault::Text(DEFAULT_ROUTE_MAIN)),
    (LEAK_PROTECTION_KEY, FieldDefault::Text(LEAK_PROTECTION_OFF)),
    ("kill-switch-protocols", FieldDefault::Int(127)),
    ("allow-dns-over-primary", FieldDefault::Bool(true)),
    ("include-subdomains", FieldDefault::Bool(true)),
    ("shared-ip-policy", FieldDefault::Text("majority-of-ip")),
    ("resolve-hosts-bypass", FieldDefault::Bool(true)),
    ("doh-lockdown-enabled", FieldDefault::Bool(false)),
    (
        "doh-lockdown-scope",
        FieldDefault::Text("leak-protection-only"),
    ),
    ("doh-lockdown-auto", FieldDefault::Bool(true)),
    ("browser-history-auto-seed", FieldDefault::Bool(false)),
    ("kill-switch-strict-shared-ips", FieldDefault::Bool(true)),
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
    ("app-rules-take-all-addresses", FieldDefault::Bool(false)),
    ("forwarded-outage", FieldDefault::Text("")),
    ("external-address-auto-check", FieldDefault::Bool(true)),
];

/// Keys the snapshot carries but the request has no field for: each is
/// written through its own operation.
pub const SNAPSHOT_ONLY_KEYS: [&str; 2] =
    ["secondary-link-provider-apps", "doh-lockdown-effective"];

/// Legal values of the slug fields; anything else reads as the default.
pub const FIELD_CHOICES: [(&str, &[&str]); 1] = [(LEAK_PROTECTION_KEY, &LEAK_PROTECTION_LEVELS)];

/// The default route that keeps unmatched traffic on the main connection.
pub const DEFAULT_ROUTE_MAIN: &str = "prefer-primary";
/// Every default route the service accepts.
pub const DEFAULT_ROUTES: [&str; 2] = [DEFAULT_ROUTE_MAIN, "prefer-secondary-when-available"];
/// The key of the leak-protection choice.
pub const LEAK_PROTECTION_KEY: &str = "leak-protection";
const LEAK_PROTECTION_OFF: &str = "off";
const LEAK_PROTECTION_SITES: &str = "sites";
pub(crate) const LEAK_PROTECTION_EVERYTHING: &str = "everything";
/// Every leak-protection level, weakest first.
pub const LEAK_PROTECTION_LEVELS: [&str; 3] = [
    LEAK_PROTECTION_OFF,
    LEAK_PROTECTION_SITES,
    LEAK_PROTECTION_EVERYTHING,
];

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
        FieldDefault::Text(fallback) => {
            let text = js::to_display_string(raw);
            let refused = FIELD_CHOICES
                .iter()
                .find(|(name, _)| *name == key)
                .is_some_and(|(_, choices)| !choices.contains(&text.as_str()));
            Value::String(if refused { fallback.to_owned() } else { text })
        }
    }
}

/// Whether `default_route` keeps unmatched traffic on the main connection; an
/// unset one is the default, which does.
fn is_main_route(default_route: &str) -> bool {
    default_route.is_empty() || default_route == DEFAULT_ROUTE_MAIN
}

/// The leak-protection levels offered under `default_route`, weakest first.
/// "Routed sites" only means something while unmatched traffic stays on the
/// main connection; under the additional one it would be "Everything".
pub fn leak_protection_choices(default_route: &str) -> Vec<&'static str> {
    LEAK_PROTECTION_LEVELS
        .into_iter()
        .filter(|level| *level != LEAK_PROTECTION_SITES || is_main_route(default_route))
        .collect()
}

/// `current` as a level `default_route` offers: "Routed sites" under the
/// additional connection becomes "Everything", never weaker; an unknown value
/// reads as off.
pub fn coerce_leak_protection(default_route: &str, current: &str) -> &'static str {
    match current {
        LEAK_PROTECTION_SITES if is_main_route(default_route) => LEAK_PROTECTION_SITES,
        LEAK_PROTECTION_SITES | LEAK_PROTECTION_EVERYTHING => LEAK_PROTECTION_EVERYTHING,
        _ => LEAK_PROTECTION_OFF,
    }
}

/// The levels a first save offers under `default_route` when the
/// administrator set `floor` at install time: none weaker than it.
pub fn leak_protection_choices_at_least(default_route: &str, floor: &str) -> Vec<&'static str> {
    let least = leak_protection_rank(coerce_leak_protection(default_route, floor));
    leak_protection_choices(default_route)
        .into_iter()
        .filter(|level| leak_protection_rank(level) >= least)
        .collect()
}

/// `level` raised to `floor`, both as `default_route` offers them.
pub fn raise_leak_protection(default_route: &str, level: &str, floor: &str) -> &'static str {
    let level = coerce_leak_protection(default_route, level);
    let floor = coerce_leak_protection(default_route, floor);
    if leak_protection_rank(floor) > leak_protection_rank(level) {
        floor
    } else {
        level
    }
}

/// The protection a user already set up holds, as the first-run setup starts
/// from it: `(level, lockdown)`, `None` while the service holds no policy for
/// them (a new user starts from the offer). A saved policy is a choice even
/// with no connection bound: the window's setup sends it before any binding.
/// Lockdown counts as on when automatic or chosen.
pub fn first_run_held_protection(
    policy_saved: bool,
    default_route: &str,
    leak_protection: &str,
    doh_lockdown_auto: bool,
    doh_lockdown_enabled: bool,
) -> Option<(&'static str, bool)> {
    policy_saved.then(|| {
        (
            coerce_leak_protection(default_route, leak_protection),
            doh_lockdown_auto || doh_lockdown_enabled,
        )
    })
}

/// What the first-run setup writes when it ends, however it ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirstRunWrites {
    /// Leak protection and lockdown, as one write.
    pub protection: bool,
    /// The machine-wide answers (fake-IP, diagnostic logs).
    pub stability: bool,
    /// Fake-IP is among them: a changed log window alone never resends it.
    pub fake_ip: bool,
}

/// A new user's answers always go; a user already set up keeps what the
/// service holds unless a choice was changed in the setup. Closing it
/// untouched must never lower protection someone chose elsewhere.
pub fn first_run_writes(
    held: Option<(&str, bool)>,
    chosen: (&str, bool),
    stability_touched: bool,
    fake_ip_touched: bool,
) -> FirstRunWrites {
    FirstRunWrites {
        protection: held != Some(chosen),
        stability: held.is_none() || stability_touched || fake_ip_touched,
        fake_ip: held.is_none() || fake_ip_touched,
    }
}

/// Why a change of leak protection needs a yes before it is sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeakProtectionConfirm {
    /// "Everything" while the additional connection is not available: the
    /// internet stops at once and waits for it.
    HoldsNow,
    /// Protection switched on over an additional adapter with no way out:
    /// what the rules send there is blocked.
    Unroutable,
}

impl LeakProtectionConfirm {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HoldsNow => "holds-now",
            Self::Unroutable => "unroutable",
        }
    }
}

/// What moving from `current` to `next` (both as the default route settles
/// them) must be confirmed for. `secondary` is the bound additional adapter's
/// row, `None` when nothing is bound or the adapter is gone.
pub fn leak_protection_confirm(
    current: &str,
    next: &str,
    secondary: Option<&nrr_shared::ipc_payloads::InterfaceRowDto>,
) -> Option<LeakProtectionConfirm> {
    if next == current || next == LEAK_PROTECTION_OFF {
        return None;
    }
    let up = secondary.is_some_and(|row| row.availability == "available");
    if next == LEAK_PROTECTION_EVERYTHING && !up {
        return Some(LeakProtectionConfirm::HoldsNow);
    }
    (current == LEAK_PROTECTION_OFF
        && secondary.is_some_and(|row| crate::adapters::unroutable_reason(row).is_some()))
    .then_some(LeakProtectionConfirm::Unroutable)
}

/// What moving the default route to `next_route` must be confirmed for while
/// `level` is in force: the write itself raises "Routed sites" to
/// "Everything" under the additional connection.
pub fn default_route_change_confirm(
    level: &str,
    next_route: &str,
    secondary: Option<&nrr_shared::ipc_payloads::InterfaceRowDto>,
) -> Option<LeakProtectionConfirm> {
    leak_protection_confirm(level, coerce_leak_protection(next_route, level), secondary)
}

/// Whether `level` holds the internet the moment it applies: "Everything"
/// while the additional connection is not available. The first-run note.
pub fn leak_protection_holds_now(
    level: &str,
    secondary: Option<&nrr_shared::ipc_payloads::InterfaceRowDto>,
) -> bool {
    leak_protection_confirm(LEAK_PROTECTION_OFF, level, secondary)
        == Some(LeakProtectionConfirm::HoldsNow)
}

/// Whether moving the additional role from `before` to `after` (`None`:
/// unbound) is what makes `level` hold the internet. Asked before a role is
/// removed or reassigned; a change that leaves it as it was asks nothing.
pub fn secondary_change_holds_now(
    level: &str,
    before: Option<&nrr_shared::ipc_payloads::InterfaceRowDto>,
    after: Option<&nrr_shared::ipc_payloads::InterfaceRowDto>,
) -> bool {
    leak_protection_holds_now(level, after) && !leak_protection_holds_now(level, before)
}

/// How strong a level is, for "only ever switched on" comparisons.
pub(crate) fn leak_protection_rank(level: &str) -> usize {
    LEAK_PROTECTION_LEVELS
        .iter()
        .position(|known| *known == level)
        .unwrap_or(0)
}

/// Brings `request`'s leak protection in line with its own default route, so
/// a write that changes either never carries a pair the service refuses
/// (`settleLeakProtection`).
pub fn settle_leak_protection(request: &mut Map<String, Value>) {
    let mode = coerce("mode", request.get("mode").unwrap_or(&Value::Null));
    let level = coerce(
        LEAK_PROTECTION_KEY,
        request.get(LEAK_PROTECTION_KEY).unwrap_or(&Value::Null),
    );
    let settled = coerce_leak_protection(
        mode.as_str().unwrap_or_default(),
        level.as_str().unwrap_or_default(),
    );
    request.insert(LEAK_PROTECTION_KEY.to_owned(), Value::from(settled));
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
    settle_leak_protection(&mut request);
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
