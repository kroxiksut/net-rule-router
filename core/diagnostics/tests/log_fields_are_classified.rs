//! Every field a translated log line carries is classified by the privacy
//! layer, or named here as one that discloses nothing about a person.
//!
//! The layer redacts by field NAME, so a name it does not know ships its value
//! in every mode: a list of addresses under `destinations` or a program path
//! under `program` went out raw in default logs and the standard archive. A new
//! field name fails this test until it is classified or added to [`PUBLIC`].
//! The message itself may not interpolate a value: a value inside the text is
//! one no name can catch.

use nrr_diagnostics::logs::privacy::field_privacy_class;
use nrr_diagnostics::PrivacyClass;
use std::path::{Path, PathBuf};

/// Counts, flags, durations, ids, slugs and states: nothing that names a site,
/// an address, a program, a file or a person's choice.
const PUBLIC: &[&str] = &[
    "accepted",
    "action",
    "active_count",
    "actual",
    "adapter_changes",
    "adapter_key",
    "added",
    "adopted",
    "alert_id",
    "already_cached",
    "anchor_reset",
    "anchor_seq",
    "anchor_skipped",
    "anchors",
    "answered",
    "answers_delta",
    "apex_absent",
    "app_covered",
    "app_ips_added",
    "app_ips_retracted",
    "app_scoped",
    "applied",
    "at_start",
    "attempt",
    "attempted",
    "attempts",
    "authored",
    "authority",
    "avail",
    "available",
    "avg_us",
    "backend",
    "backfilled",
    "backoff_base_ms",
    "backoff_cap_ms",
    "block_all",
    "block_all_armed",
    "blocked_by",
    "blocked_foreign",
    "blocked_nrr",
    "boot_mode",
    "bootstrap_ms",
    "breaks",
    "bringing_up",
    "budget",
    "budget_ms",
    "budget_secs",
    "buf_len",
    "buffers",
    "bus_wired",
    "bytes",
    "bytes_freed",
    "cache_errors",
    "cached",
    "caller",
    "calls",
    "candidates",
    "cap",
    "capability",
    "cause",
    "change",
    "changed",
    "class",
    "clean",
    "clients",
    "code",
    "collect_restores_to",
    "companions",
    "completed",
    "concurrent",
    "confirmations",
    "connected",
    "consecutive_errors",
    "content_hash",
    "control",
    "cooldown_secs",
    "correlation_id",
    "count",
    "counter_overlay",
    "damaged",
    "data_source",
    "deadline_secs",
    "decision_id",
    "declared",
    "deferred",
    "delay_ms",
    "deleted",
    "desired_routes",
    "destinations",
    "detached",
    "detail",
    "differs_live",
    "differs_neutral",
    "dismissed",
    "drop_filter_id",
    "dropped",
    "duplicates",
    "duration_us",
    "egress",
    "egress_ifindex",
    "elapsed_minutes",
    "elapsed_ms",
    "elapsed_secs",
    "enabled",
    "error",
    "error_code",
    "error_message",
    "errors",
    "event_id",
    "event_type",
    "events",
    "excluded",
    "expected",
    "fail_closed_active",
    "fail_closed_filters",
    "failed",
    "failed_authoritative",
    "failed_transient",
    "failure",
    "failures",
    "fake_intercepted",
    "family",
    "fields",
    "files",
    "filter_count",
    "filter_id",
    "filters",
    "first_line",
    "flows",
    "forced",
    "forgotten",
    "found",
    "found_seq",
    "from",
    "grace_ms",
    "guarded",
    "has_app",
    "has_global",
    "has_ipv4",
    "healed_id",
    "held",
    "ifindex",
    "ignored",
    "indeterminate",
    "inherited",
    "installed",
    "ipv6",
    "kept",
    "kept_on_course",
    "kept_other_link",
    "kept_other_owner",
    "kept_shared",
    "kept_unknown_owner",
    "key_reset",
    "keywords_restore_to",
    "kill_switch_filters",
    "killswitch_drops_live_secondary_app_scope",
    "kind",
    "known_rules",
    "known_sections",
    "ledger_ids",
    "left",
    "limit_secs",
    "lingering",
    "link",
    "listener",
    "live",
    "live_reload",
    "local_port",
    "lockdown_ms",
    "lookup_events",
    "loopback",
    "loopback_pinned",
    "lost_rows",
    "lower_ms",
    "matched",
    "max_restarts",
    "max_us",
    "mechanism",
    "metric",
    "mode",
    "msg_key",
    "name_match_ambiguous",
    "negative",
    "network_routes",
    "neutral",
    "nft_ms",
    "not_logged",
    "note",
    "offered",
    "ok",
    "omitted",
    "on_secondary",
    "op",
    "oper_status",
    "operation",
    "origin",
    "other",
    "outcome",
    "outstanding",
    "overlays_only",
    "packet_len",
    "parked",
    "part",
    "pass",
    "payload_size",
    "pending",
    "persist",
    "persistent",
    "phantom",
    "phases",
    "pid",
    "pinned",
    "policy",
    "prefix_len",
    "present",
    "previous_peak",
    "primary",
    "principal",
    "principal_count",
    "prior",
    "priority",
    "problem",
    "profile",
    "proto",
    "protocol",
    "published",
    "purpose",
    "re_offered",
    "re_signed",
    "reason",
    "redirect_error",
    "refreshed",
    "refusals_not_logged",
    "refused",
    "rejected_revision_id",
    "remote_port",
    "removed",
    "removed_overlays",
    "request_id",
    "requested",
    "requested_conn_trace_log",
    "requested_enforcement_mode",
    "requested_verbose",
    "resends",
    "resolutions",
    "resolved",
    "resolver_live",
    "restored",
    "retry",
    "retry_in_secs",
    "retry_secs",
    "revision_count",
    "revision_id",
    "revisions",
    "role",
    "rolled_back",
    "route",
    "routed_now",
    "routes",
    "rows",
    "rule_id",
    "rule_matching",
    "rules_json_len",
    "same_order",
    "same_set",
    "second_source",
    "secondary",
    "secondary_ifindex",
    "secondary_routes",
    "seconds",
    "seeded",
    "shared_sites",
    "shed",
    "shown",
    "sid",
    "silent",
    "silent_s",
    "since_process_start_ms",
    "skipped",
    "skipped_over_limit",
    "skipped_recent",
    "slept_seconds",
    "slow",
    "sources",
    "spec_id",
    "stage",
    "stale",
    "stale_id",
    "stalled",
    "stalls",
    "state",
    "status",
    "step",
    "stopping",
    "stored",
    "stripped_blocks",
    "stripped_filters",
    "subnet_count",
    "subscribers",
    "subscription_id",
    "succeeded",
    "superseded",
    "swept",
    "tampered",
    "task",
    "tcp_dial_failed",
    "tcp_dial_ok",
    "tcp_dial_refused",
    "tcp_flows_opened",
    "term",
    "threshold",
    "timeout_secs",
    "to",
    "torn_down",
    "total",
    "total_ms",
    "tracked_deleted",
    "tried",
    "trigger",
    "tunnel_came_up",
    "udp_dial_failed",
    "udp_dial_ok",
    "udp_dial_refused",
    "udp_flows_opened",
    "udp_unreachable_sent",
    "uid",
    "unknown",
    "unknown_rules",
    "unknown_sections",
    "unnamed",
    "unrecognized",
    "until_ms",
    "user_sid",
    "users",
    "verbose",
    "verdict",
    "version",
    "visited",
    "vpn_client_apps_learned",
    "wait_ms",
    "waited",
    "waited_secs",
    "weight",
    "what",
    "why",
    "widest_prefix",
    "window_secs",
    "written",
    "zombies",
];

const LEVELS: [&str; 5] = ["error", "warn", "info", "debug", "trace"];
/// Production sources only: a test may spell a log call out as a fixture, and
/// what a test logs never reaches a user's log.
const SKIPPED_DIRS: [&str; 7] = [
    "target",
    "fuzz",
    "third_party",
    ".git",
    "node_modules",
    "tests",
    "test_support",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if !SKIPPED_DIRS.contains(&name.as_str()) {
                rust_files(&path, out);
            }
        } else if name.ends_with(".rs") && name != "tests.rs" && !name.ends_with("_tests.rs") {
            out.push(path);
        }
    }
}

/// Index just past the string literal opening at `start`. Every delimiter is
/// ASCII, so byte indices always fall on character boundaries.
fn skip_string(bytes: &[u8], start: usize) -> usize {
    let mut i = start + 1;
    while i < bytes.len() && bytes[i] != b'"' {
        if bytes[i] == b'\\' {
            i += 1;
        }
        i += 1;
    }
    (i + 1).min(bytes.len())
}

/// The argument lists of every `tracing::<level>!(…)` call in `source`.
fn call_bodies(source: &str) -> Vec<&str> {
    let bytes = source.as_bytes();
    let mut bodies = Vec::new();
    for level in LEVELS {
        let needle = format!("tracing::{level}!(");
        let mut from = 0;
        while let Some(found) = source[from..].find(&needle) {
            let start = from + found + needle.len();
            let mut depth = 1;
            let mut i = start;
            while i < bytes.len() && depth > 0 {
                match bytes[i] {
                    b'(' | b'[' | b'{' => depth += 1,
                    b')' | b']' | b'}' => depth -= 1,
                    b'"' => {
                        i = skip_string(bytes, i);
                        continue;
                    }
                    _ => {}
                }
                i += 1;
            }
            bodies.push(&source[start..i.saturating_sub(1).max(start)]);
            from = start;
        }
    }
    bodies
}

/// Top-level comma-separated arguments, string literals kept whole.
fn segments(body: &str) -> Vec<&str> {
    let bytes = body.as_bytes();
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut begin = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                i = skip_string(bytes, i);
                continue;
            }
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b',' if depth == 0 => {
                out.push(body[begin..i].trim());
                begin = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if !body[begin..].trim().is_empty() {
        out.push(body[begin..].trim());
    }
    out
}

fn is_ident(token: &str) -> bool {
    let mut chars = token.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The field names of one call, and its message literal if it has one.
fn fields_and_message(body: &str) -> (Vec<&str>, Option<&str>) {
    let mut names = Vec::new();
    for segment in segments(body) {
        if segment.starts_with('"') {
            return (names, Some(segment));
        }
        if segment.starts_with("target:") || segment.starts_with("parent:") {
            continue;
        }
        let bytes = segment.as_bytes();
        let eq = (1..bytes.len()).find(|&k| {
            bytes[k] == b'='
                && !matches!(bytes.get(k + 1), Some(b'=') | Some(b'>'))
                && !matches!(bytes[k - 1], b'=' | b'!' | b'<' | b'>')
        });
        let name = match eq {
            Some(k) => segment[..k].trim(),
            None => segment.trim_start_matches(['%', '?']).trim(),
        };
        if is_ident(name) {
            names.push(name);
        }
    }
    (names, None)
}

/// A format placeholder (`{}`, `{name}`, `{:?}`, `{name:>4}`) in a message.
fn interpolates(message: &str) -> bool {
    let unescaped = message.replace("{{", "").replace("}}", "");
    let mut rest = unescaped.as_str();
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            return false;
        };
        let inside = &after[..close];
        if inside
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.:?#<>^ ".contains(c))
        {
            return true;
        }
        rest = &after[close + 1..];
    }
    false
}

#[test]
fn every_translated_log_field_is_classified_or_known_public() {
    let root = workspace_root();
    let mut files = Vec::new();
    for base in ["core", "apps", "shared"] {
        rust_files(&root.join(base), &mut files);
    }
    assert!(
        files.len() > 100,
        "the workspace was not found from {root:?}"
    );
    let mut unknown = std::collections::BTreeMap::new();
    let mut interpolated = Vec::new();
    for file in &files {
        let Ok(source) = std::fs::read_to_string(file) else {
            continue;
        };
        for body in call_bodies(&source) {
            if !body.contains("msg_key") {
                continue;
            }
            let (names, message) = fields_and_message(body);
            for name in names {
                if field_privacy_class(name) == PrivacyClass::PublicSummary
                    && !PUBLIC.contains(&name)
                {
                    unknown
                        .entry(name.to_string())
                        .or_insert_with(|| file.clone());
                }
            }
            if message.is_some_and(interpolates) {
                interpolated.push(file.clone());
            }
        }
    }
    assert!(
        unknown.is_empty(),
        "log fields the privacy layer does not classify (add each to privacy.rs, or to PUBLIC if it names nothing): {unknown:#?}"
    );
    assert!(
        interpolated.is_empty(),
        "a translated log message interpolates a value; pass it as a field instead: {interpolated:#?}"
    );
}

#[test]
fn the_names_the_review_found_are_classified() {
    for name in [
        "gateway",
        "servers",
        "rules",
        "suffix",
        "suffixes",
        "label",
        "query",
        "addresses",
    ] {
        assert_eq!(
            field_privacy_class(name),
            PrivacyClass::Diagnostic,
            "{name}"
        );
    }
    for name in ["program", "apps", "launched_by", "pattern", "dir", "backup"] {
        assert_eq!(field_privacy_class(name), PrivacyClass::Sensitive, "{name}");
    }
}
