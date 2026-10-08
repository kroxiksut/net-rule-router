//! The read-modify-write of `settings.service-stability.set`.
//!
//! Like `route.policy.update`, the operation replaces the whole row: a field
//! the request leaves out falls back to the service's serde default. A writer
//! starts from the live row and overlays only what it changes
//! ([`merge_write`]).
//!
//! [`FIELD_DEFAULTS`] mirrors `STABILITY_FIELD_DEFAULTS` in `pure.js`; each
//! value equals the serde default of the same field in
//! `nrr_shared::ipc_payloads::ServiceStabilityConfigDto`, which is normative.

use serde_json::{Map, Value};

use crate::js;
use crate::route_policy::FieldDefault;

/// Every scalar field of the row this build knows, with its default.
pub const FIELD_DEFAULTS: [(&str, FieldDefault); 17] = [
    ("verbose-logging-mode", FieldDefault::Text("off")),
    ("verbose-logging-until-ms", FieldDefault::Int(0)),
    ("conn-trace-ndjson-mode", FieldDefault::Text("off")),
    ("conn-trace-ndjson-until-ms", FieldDefault::Int(0)),
    ("conn-trace-ndjson-forced", FieldDefault::Bool(false)),
    ("conn-trace-ndjson-forced-by", FieldDefault::Text("")),
    ("conn-trace-gui", FieldDefault::Bool(true)),
    ("rule-scope-service-driven", FieldDefault::Bool(true)),
    ("routing-stop-policy", FieldDefault::Text("teardown")),
    ("cache-refresh-interval-secs", FieldDefault::Int(300)),
    ("enforcement-mode", FieldDefault::Text("resolver")),
    ("secondary-liveness-window-secs", FieldDefault::Int(0)),
    ("fake-ip-enabled", FieldDefault::Bool(false)),
    ("dns-via-secondary", FieldDefault::Bool(false)),
    ("dns-fast-answers", FieldDefault::Bool(true)),
    ("fake-ip-udp-relay", FieldDefault::Bool(false)),
    ("fake-ip-instant-rst", FieldDefault::Bool(true)),
];

/// Row fields whose value is not a scalar, still round-tripped by a write.
pub const STRUCTURED_KEYS: [&str; 1] = ["ipc-accept-policy"];

/// The administrator's rules lock: never carried forward out of a user's
/// recorded intent.
pub const INTENT_EXCLUDED_KEYS: [&str; 1] = ["allow-user-rule-edits"];

/// A service-side clamp: `non_positive` is what zero or less resolves to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clamp {
    pub min: i32,
    pub max: i32,
    pub non_positive: i32,
}

pub const FIELD_CLAMPS: [(&str, Clamp); 2] = [
    (
        "secondary-liveness-window-secs",
        Clamp {
            min: 5,
            max: 3600,
            non_positive: 0,
        },
    ),
    (
        "cache-refresh-interval-secs",
        Clamp {
            min: 60,
            max: 86400,
            non_positive: 300,
        },
    ),
];

/// Legal values of the slug fields; anything else resolves to the default.
pub const FIELD_CHOICES: [(&str, &[&str]); 4] = [
    ("verbose-logging-mode", &["off", "timed", "until-restart"]),
    ("conn-trace-ndjson-mode", &["off", "timed", "until-restart"]),
    ("enforcement-mode", &["resolver", "reactive"]),
    ("routing-stop-policy", &["teardown", "persist"]),
];

/// The requests a log-window control (verbose logging, the connection trace
/// on disk) offers, in display order.
pub const LOG_WINDOW_CHANGES: [&str; 4] = ["off", "one-hour", "four-hours", "until-restart"];

/// Keys a service without the whole row still applies, each with the
/// platform capability that says so.
pub const KEY_CAPABILITY: [(&str, &str); 3] = [
    ("verbose-logging-change", "verboseLogging"),
    ("conn-trace-ndjson-change", "connTraceLog"),
    ("conn-trace-gui", "connTraceLog"),
];

const WHOLE_ROW_CAPABILITY: &str = "serviceStabilityConfig";

/// The declared default of a scalar field.
pub fn field_default(key: &str) -> Option<FieldDefault> {
    FIELD_DEFAULTS
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, default)| *default)
}

/// Whether `key` is a field of the row this build knows about.
pub fn key_is_known(key: &str) -> bool {
    field_default(key).is_some() || STRUCTURED_KEYS.contains(&key)
}

/// One scalar value normalised to the wire shape (`stabilityCoerce`): absent
/// and `""` read as the default, numbers are clamped, an unknown slug falls
/// back to the default. A key that is not a scalar field passes unchanged.
pub fn coerce(key: &str, raw: &Value) -> Value {
    let Some(default) = field_default(key) else {
        return raw.clone();
    };
    if raw.is_null() || raw.as_str() == Some("") {
        return default.to_value();
    }
    match default {
        FieldDefault::Bool(_) => Value::Bool(*raw == Value::Bool(true)),
        FieldDefault::Int(_) => {
            let n = js::to_int32(js::to_number(raw));
            let clamped = match FIELD_CLAMPS.iter().find(|(name, _)| *name == key) {
                None => n,
                Some((_, clamp)) if n <= 0 => clamp.non_positive,
                Some((_, clamp)) => n.clamp(clamp.min, clamp.max),
            };
            Value::from(clamped)
        }
        FieldDefault::Text(_) => {
            let text = js::to_display_string(raw);
            let refused = FIELD_CHOICES
                .iter()
                .find(|(name, _)| *name == key)
                .is_some_and(|(_, choices)| !choices.contains(&text.as_str()));
            if refused {
                default.to_value()
            } else {
                Value::String(text)
            }
        }
    }
}

/// The effective current value of a scalar field in a config (or any map with
/// the same wire keys); `None` for a key that is not a scalar field.
pub fn effective(config: &Map<String, Value>, key: &str) -> Option<Value> {
    field_default(key)?;
    Some(coerce(key, config.get(key).unwrap_or(&Value::Null)))
}

/// The FULL `settings.service-stability.set` config for one write
/// (`mergeStabilityWrite`): the live row echoed, then the recorded `intent`
/// for known keys that are neither excluded nor `parked`, then the keys this
/// write changes.
pub fn merge_write(
    live: &Map<String, Value>,
    intent: &Map<String, Value>,
    parked: &Map<String, Value>,
    partial: &Map<String, Value>,
) -> Map<String, Value> {
    let mut out = live.clone();
    for (key, value) in intent {
        if INTENT_EXCLUDED_KEYS.contains(&key.as_str())
            || !key_is_known(key)
            || parked.contains_key(key)
        {
            continue;
        }
        out.insert(key.clone(), value.clone());
    }
    for (key, value) in partial {
        out.insert(key.clone(), value.clone());
    }
    out
}

/// An absent capability map, or an absent flag, reads as supported.
fn profile_supports(supports: Option<&Map<String, Value>>, feature: &str) -> bool {
    supports.is_none_or(|map| map.get(feature) != Some(&Value::Bool(false)))
}

/// Whether this platform's service applies `key`.
pub fn key_applies(key: &str, supports: Option<&Map<String, Value>>) -> bool {
    if profile_supports(supports, WHOLE_ROW_CAPABILITY) {
        return true;
    }
    KEY_CAPABILITY
        .iter()
        .find(|(name, _)| *name == key)
        .is_some_and(|(_, capability)| profile_supports(supports, capability))
}

/// The part of a patch this platform's service applies: a key it would only
/// store must not be sent as if it took effect.
pub fn patch_for_platform(
    partial: &Map<String, Value>,
    supports: Option<&Map<String, Value>>,
) -> Map<String, Value> {
    partial
        .iter()
        .filter(|(key, _)| key_applies(key, supports))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// Whether this platform's service applies any stability key at all.
pub fn any_key_applies(supports: Option<&Map<String, Value>>) -> bool {
    profile_supports(supports, WHOLE_ROW_CAPABILITY)
        || KEY_CAPABILITY
            .iter()
            .any(|(_, capability)| profile_supports(supports, capability))
}
