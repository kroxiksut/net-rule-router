//! What an operational log event is allowed to disclose.
//!
//! Every event used to be stamped `PublicSummary` regardless of content, so the
//! two privacy checks in [`LogFilter`](crate::logs::filter::LogFilter) could not
//! fire once, in any mode. A measurement on one production file: 10 092 lines,
//! all `public_summary`, of which 7500 carried a path to an `.exe` and 7334 a
//! remote address — in a directory local users can read.
//!
//! The classification is not invented here. [`PrivacyClass`] already says what
//! belongs where: `Diagnostic` "adds selected IPs", `Sensitive` covers "process
//! paths, adapter identifiers, resolver details". This module only reads the
//! field names an event carries and applies that.
//!
//! Names, not values: a field called `host` holds a hostname whatever it
//! happens to contain, and inspecting values would mean guessing (is
//! `192.168.1.1` an address or a version string?). Producers name their fields
//! honestly — `host = %q.qname`, `path = %path.display()` — so the name is the
//! reliable signal.
//!
//! When a class outranks the current mode the FIELD is redacted and the event
//! is kept: dropping it would take the timeline with it, and the timeline is
//! what the log is for.

use crate::taxonomy::PrivacyClass;

/// Placeholder written in place of a value the current mode may not disclose.
pub const REDACTED: &str = "<redacted>";

/// Field names that carry a process path, an adapter identity or resolver
/// detail — [`PrivacyClass::Sensitive`] in the taxonomy's own words.
const SENSITIVE_FIELDS: &[&str] = &[
    "adapter",
    "adapter_name",
    "app",
    "app_key",
    // Lists of executables, not one path: an app-rule roster and a per-process
    // drop summary disclose the same thing `process` does, several times over.
    "conflicts",
    "exe",
    "ifname",
    "image",
    "interface",
    "intruder",
    "owner",
    "path",
    "primary_app_rules",
    "process",
    "processes",
    "resolver",
    "secondary_app_rules",
    "upstream",
    // An adapter's human-readable NAME, unlike its opaque id, says who it
    // belongs to — a tunnel adapter is usually named after its provider.
    // `was`/`now` are the rename pair: one of the two drift events puts names
    // in them and the other puts identities, and a field name cannot tell
    // those apart, so both are treated as the more revealing case.
    "display_name",
    "now",
    "was",
];

/// Suffixes for the same class, so `vpn_exe_path` is caught alongside `path`.
const SENSITIVE_SUFFIXES: &[&str] = &["_path", "_exe", "_adapter", "_interface", "_resolver"];

/// Field names that carry a hostname, an address, or an opaque adapter id —
/// [`PrivacyClass::Diagnostic`].
///
/// An adapter GUID sits here rather than with the sensitive names above: it
/// identifies an interface without saying whose it is, and it is what every
/// routing question is debugged against.
const DIAGNOSTIC_FIELDS: &[&str] = &[
    "active",
    "addr",
    "address",
    "addresses",
    "admitted",
    "also_answered_for",
    "bound",
    "dest",
    "destination",
    "domain",
    "effective_id",
    "evicted",
    "fake",
    "fqdn",
    "host",
    "hostname",
    "hosts",
    "identity",
    "ip",
    "ipv4",
    "live_adapters",
    // The socket's own endpoint, paired with `remote` in every trace line —
    // it was the one half of the pair nobody classified.
    "local",
    // Both carry `ip_set=[…]` inside a filter-plan summary.
    "only_live",
    "only_neutral",
    "next_hop",
    "peer",
    "previous",
    "qname",
    "real",
    "rejected",
    "remote",
    "retired",
    "sample",
    "server",
    "source",
    "stable_id",
    "table",
];

const DIAGNOSTIC_SUFFIXES: &[&str] = &[
    "_addr",
    "_address",
    "_fqdn",
    "_host",
    "_hostname",
    "_ip",
    "_qname",
];

fn matches(name: &str, exact: &[&str], suffixes: &[&str]) -> bool {
    exact.contains(&name) || suffixes.iter().any(|s| name.ends_with(s))
}

/// The class of one field name.
fn field_class(name: &str) -> PrivacyClass {
    if matches(name, SENSITIVE_FIELDS, SENSITIVE_SUFFIXES) {
        PrivacyClass::Sensitive
    } else if matches(name, DIAGNOSTIC_FIELDS, DIAGNOSTIC_SUFFIXES) {
        PrivacyClass::Diagnostic
    } else {
        PrivacyClass::PublicSummary
    }
}

/// The class of a whole event: the highest class any of its fields carries.
#[must_use]
pub fn classify(payload: Option<&serde_json::Value>) -> PrivacyClass {
    let Some(serde_json::Value::Object(map)) = payload else {
        return PrivacyClass::PublicSummary;
    };
    map.keys()
        .map(|k| field_class(k))
        .max()
        .unwrap_or(PrivacyClass::PublicSummary)
}

/// Replace the values of fields that outrank `ceiling`, in place.
///
/// Only the offending fields lose their value — the event, its message and
/// every field the mode does allow stay readable.
pub fn redact_above(payload: &mut serde_json::Value, ceiling: PrivacyClass) {
    let Some(map) = payload.as_object_mut() else {
        return;
    };
    for (name, value) in map.iter_mut() {
        if field_class(name) > ceiling {
            *value = serde_json::Value::String(REDACTED.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_hostname_field_is_diagnostic_and_a_process_path_is_sensitive() {
        assert_eq!(field_class("host"), PrivacyClass::Diagnostic);
        assert_eq!(field_class("qname"), PrivacyClass::Diagnostic);
        assert_eq!(field_class("remote_ip"), PrivacyClass::Diagnostic);
        assert_eq!(field_class("path"), PrivacyClass::Sensitive);
        assert_eq!(field_class("exe_path"), PrivacyClass::Sensitive);
        assert_eq!(field_class("adapter"), PrivacyClass::Sensitive);
        assert_eq!(field_class("count"), PrivacyClass::PublicSummary);
        assert_eq!(field_class("message"), PrivacyClass::PublicSummary);
    }

    #[test]
    fn an_event_takes_the_class_of_its_most_revealing_field() {
        let payload = json!({ "message": "x", "host": "example.com", "count": 3 });
        assert_eq!(classify(Some(&payload)), PrivacyClass::Diagnostic);

        let payload = json!({ "host": "example.com", "path": "C:\\app.exe" });
        assert_eq!(classify(Some(&payload)), PrivacyClass::Sensitive);

        let payload = json!({ "message": "x", "count": 3 });
        assert_eq!(classify(Some(&payload)), PrivacyClass::PublicSummary);
        assert_eq!(classify(None), PrivacyClass::PublicSummary);
    }

    #[test]
    fn the_field_names_production_actually_emits_are_covered() {
        // Taken from the producers the audit measured, verbatim: `dns_listener`
        // (`host = %q.qname`), `dns_observation_consumer`, `dns_refresh`,
        // `adapters/sqlite_cache` (`fqdn = %fqdn`), `linux-service/runtime_deps`
        // (`path = %path.display()`). A rule that misses the names actually in
        // use is a rule that classifies nothing.
        for name in [
            "host",
            "hostname",
            "fqdn",
            "qname",
            "direct_host",
            "secondary_rule_host",
            "shared_ip",
        ] {
            assert!(
                field_class(name) >= PrivacyClass::Diagnostic,
                "{name} carries a hostname or address and must not read as public",
            );
        }
        for name in ["path", "exe_path", "app_key", "adapter"] {
            assert_eq!(
                field_class(name),
                PrivacyClass::Sensitive,
                "{name} identifies a process or an adapter",
            );
        }
        // Categorical fields stay public — otherwise every line would redact and
        // the log would say nothing at all.
        for name in ["error", "reason", "count", "message", "kind", "elapsed_ms"] {
            assert_eq!(field_class(name), PrivacyClass::PublicSummary, "{name}");
        }
    }

    /// A second audit of a production file found the classification leaking in
    /// the direction nobody had checked: the rule was written from the fields
    /// that WERE being redacted, so whole families that were not on any list
    /// went out verbatim.
    #[test]
    fn the_families_the_first_pass_missed_are_covered_too() {
        // Addresses and hostnames. `local` is the one that shows how the gap
        // happened: its pair `remote` was classified and it was not, in the
        // very same trace line.
        for name in [
            "local",
            "addresses",
            "hosts",
            "next_hop",
            "admitted",
            "evicted",
            "real",
            "fake",
            "source",
            "server",
            "table",
            "only_live",
            "only_neutral",
            "sample",
            "also_answered_for",
            "rejected",
            "active",
            "previous",
            "retired",
        ] {
            assert!(
                field_class(name) >= PrivacyClass::Diagnostic,
                "{name} carries a hostname or address and must not read as public",
            );
        }
        // Executables, named in the plural or as a roster.
        for name in [
            "processes",
            "primary_app_rules",
            "secondary_app_rules",
            "conflicts",
            "intruder",
            "owner",
        ] {
            assert_eq!(
                field_class(name),
                PrivacyClass::Sensitive,
                "{name} names executables",
            );
        }
        // An adapter's NAME says whose it is — a tunnel adapter carries its
        // provider's name — while its opaque id does not, and every routing
        // question is debugged against the id.
        for name in ["display_name", "was", "now"] {
            assert_eq!(
                field_class(name),
                PrivacyClass::Sensitive,
                "{name} can hold an adapter's human-readable name",
            );
        }
        // The positive control for the line above: were these sensitive too,
        // the split would be pointless and route debugging would go dark.
        for name in [
            "bound",
            "stable_id",
            "effective_id",
            "live_adapters",
            "identity",
        ] {
            assert_eq!(
                field_class(name),
                PrivacyClass::Diagnostic,
                "{name} is an opaque adapter id, readable in diagnostic mode",
            );
        }
    }

    #[test]
    fn redaction_takes_the_value_and_leaves_the_event() {
        // The point of redacting instead of dropping: the line, its message and
        // the fields the mode does allow all survive, so the timeline stays.
        let mut payload = json!({
            "message": "resolved",
            "count": 2,
            "host": "example.com",
            "path": "C:\\Program Files\\app.exe"
        });
        redact_above(&mut payload, PrivacyClass::PublicSummary);
        assert_eq!(payload["message"], json!("resolved"));
        assert_eq!(payload["count"], json!(2));
        assert_eq!(payload["host"], json!(REDACTED));
        assert_eq!(payload["path"], json!(REDACTED));
    }

    #[test]
    fn a_mode_that_allows_addresses_still_hides_process_paths() {
        let mut payload = json!({ "host": "example.com", "path": "C:\\app.exe" });
        redact_above(&mut payload, PrivacyClass::Diagnostic);
        assert_eq!(payload["host"], json!("example.com"));
        assert_eq!(payload["path"], json!(REDACTED));
    }
}
