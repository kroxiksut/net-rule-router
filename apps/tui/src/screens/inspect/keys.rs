//! Locale keys of the trace, cache and diagnostics screens. The GUI's wording
//! is reused wherever the GUI says the same thing; only terminal-only text is
//! `tui.*`. Keys built from a service slug (`diag.conn-trace.egress.<slug>`)
//! are looked up with `Texts::dynamic` and are the GUI's own.

use crate::i18n::{key, Key};

// ── Lists, typing, questions ─────────────────────────────────────────────────

pub const PAGE: Key = key("tui.list.page", "Rows {from}–{to} of {total}.");
pub const PAGE_MORE: Key = key(
    "tui.list.more-on-service",
    "The service has more: going past the last row asks for them.",
);
pub const HELP_PAGES: Key = key(
    "tui.list.help-pages",
    "PageUp and PageDown: previous and next page; Home and End: first and last row",
);
pub const PLAIN_PAGES: Key = key(
    "tui.list.plain-pages",
    "n: next page (more)   p: previous page (back)",
);
pub const HELP_REFRESH: Key = key(
    "tui.list.help-refresh",
    "r: read again from the service. Lists do not refresh by themselves, so nothing moves while you read.",
);
pub const TYPING_HINT: Key = key("tui.list.typing-hint", "Enter: done   Esc: cancel");
pub const YES_NO: Key = key("tui.list.yes-no", "y: yes   n: no");
pub const YES: Key = key("label.yes", "Yes");
pub const NO: Key = key("label.no", "No");
pub const PRIMARY: Key = key("label.primary", "Primary");
pub const SECONDARY: Key = key("label.secondary", "Additional");

// ── Connection trace ─────────────────────────────────────────────────────────

pub const TRACE_LIST: Key = key("tui.trace.list-title", "Connections");
pub const TRACE_DETAIL: Key = key("tui.trace.detail-title", "Selected connection");
pub const TRACE_SHOWN: Key = key("tui.trace.shown", "Shown: {shown} of {total}.");
pub const TRACE_SEARCH: Key = key("tui.trace.search", "Search: {text}");
pub const TRACE_PATH: Key = key("tui.trace.path", "Path: {path}");
pub const TRACE_SUBTITLE: Key = key(
    "diag.conn-trace.subtitle",
    "Recently-observed outbound connections and which interface they actually left through.",
);
pub const TRACE_VERDICT_NOTE: Key = key(
    "diag.conn-trace.verdict-note",
    "\"Blocked\" means the connection was dropped by a Windows filter — this can be Windows Firewall or your antivirus, not necessarily NetRuleRouter.",
);
pub const TRACE_LOADING: Key = key("diag.conn-trace.entries-loading", "Loading connections...");
pub const TRACE_EMPTY: Key = key(
    "diag.conn-trace.entries-empty",
    "No connections observed yet",
);
pub const TRACE_NOT_OBSERVING: Key = key(
    "diag.conn-trace.observer-unavailable",
    "The service is not observing connections right now, so this list stays empty. The service log says why.",
);
pub const TRACE_STREAM_OFF: Key = key(
    "diag.conn-trace.gui-stream-off",
    "Showing the connection trace is switched off in Settings → Diagnostics and logs. Observation itself keeps running.",
);
pub const TRACE_NO_MATCH: Key = key(
    "diag.conn-trace.entries-no-match",
    "No connections match the current filters",
);
pub const TRACE_FAILED: Key = key(
    "diag.conn-trace.entries-failed",
    "Failed to load connection trace: ",
);
pub const TRACE_SHOW_BLOCKED: Key = key("diag.conn-trace.show-blocked", "Show blocked");
pub const TRACE_SHOW_LOCAL: Key = key("diag.conn-trace.show-local", "Show local connections");
pub const TRACE_ONLY_IPV6: Key = key("diag.conn-trace.only-ipv6", "IPv6 only");
pub const TRACE_SEARCH_LABEL: Key = key(
    "diag.conn-trace.entries-search-placeholder",
    "Search all fields…",
);
pub const TRACE_BLOCK_BY_NRR: Key = key(
    "diag.conn-trace.verdict.block-by-nrr",
    "Blocked (NetRuleRouter)",
);
pub const TRACE_BLOCK_BY_OTHER: Key = key(
    "diag.conn-trace.verdict.block-by-other",
    "Blocked (another program)",
);
pub const TRACE_FROM: Key = key("diag.conn-trace.entries-from", "from");
pub const TRACE_RELAY_FOR: Key = key("diag.conn-trace.relay-for", "relay for %1");
pub const TRACE_HOST_OTHERS: Key = key("diag.conn-trace.remote-host-others", "%1 (+%2)");
pub const TRACE_FAKE_IP: Key = key("diag.conn-trace.fake-ip", "fake-IP");
pub const TRACE_VIA_FAKE_IP: Key = key(
    "diag.conn-trace.via-fake-ip",
    "Via fake-IP: a virtual address the service gave this name.",
);
pub const TRACE_NAMES: Key = key(
    "diag.conn-trace.remote-hosts-tip",
    "Names this address was answered for (%1):",
);
pub const TRACE_LEAK: Key = key(
    "diag.conn-trace.leak-mismatch-tip",
    "Mismatch: this address belongs to a rule routed to the additional adapter, but the connection was allowed out over the PRIMARY link — a leak indicator.",
);
pub const TRACE_WHY: Key = key("diag.conn-trace.why-this-route", "Why this route?");
pub const COL_PROCESS: Key = key("diag.conn-trace.col-process", "Process");
pub const COL_REMOTE: Key = key("diag.conn-trace.col-remote", "Remote");
pub const COL_EGRESS: Key = key("diag.conn-trace.col-egress", "Egress");
pub const COL_VERDICT: Key = key("diag.conn-trace.col-verdict", "Verdict");

pub const TRACE_HELP_EXPLAIN: Key = key(
    "tui.trace.help-explain",
    "Enter: why the chosen connection took its route (opens Diagnostics)",
);
pub const TRACE_HELP_SEARCH: Key = key(
    "tui.trace.help-search",
    "/: search all fields; Enter applies the search, Esc cancels",
);
pub const TRACE_HELP_FILTERS: Key = key(
    "tui.trace.help-filters",
    "b: show or hide blocked   l: show or hide local connections   v: IPv6 only on or off",
);
pub const TRACE_PLAIN_DETAILS: Key = key(
    "tui.trace.plain-details",
    "d and a row number: show that connection, for example d 3",
);
pub const TRACE_PLAIN_EXPLAIN: Key = key(
    "tui.trace.plain-explain",
    "e and a row number: why that connection took its route, for example e 3",
);
pub const TRACE_PLAIN_SEARCH: Key = key(
    "tui.trace.plain-search",
    "/ and text: search all fields, for example /example; / on its own clears the search",
);

// ── Cache ────────────────────────────────────────────────────────────────────

pub const CACHE_LIST: Key = key("diag.cache.entries-title", "Cache entries");
pub const CACHE_DETAIL: Key = key("tui.cache.detail-title", "Selected entry");
pub const CACHE_TOTAL: Key = key("tui.cache.total", "Entries on the service: {total}.");
pub const CACHE_SEARCH: Key = key("tui.cache.search", "Search: {text}");
pub const CACHE_SEARCH_LABEL: Key = key(
    "diag.cache.entries-search-placeholder",
    "Exact name or IP; *.google.com — subdomains; *google* — any match",
);
pub const CACHE_LOADING: Key = key("diag.cache.entries-loading", "Loading cache entries...");
pub const CACHE_EMPTY: Key = key("diag.cache.entries-empty", "No cache entries");
pub const CACHE_NO_MATCH: Key = key(
    "diag.cache.entries-no-match",
    "No entries match your search",
);
pub const CACHE_FAILED: Key = key(
    "diag.cache.entries-failed",
    "Failed to load cache entries: ",
);
pub const CACHE_REDACTED: Key = key(
    "diag.cache.entries-redacted-notice",
    "Hostnames and IPs are reduced for privacy. Enable Extended diagnostics for full detail.",
);
pub const COL_HOST: Key = key("diag.cache.col-hostname", "Host");
pub const COL_IP: Key = key("diag.cache.col-ip", "IP");
pub const COL_SOURCE: Key = key("diag.cache.col-source", "Source");
pub const COL_ROUTE: Key = key("diag.cache.col-route", "Route");
pub const COL_FRESHNESS: Key = key("diag.cache.col-freshness", "Freshness");
pub const COL_FAKE_IP: Key = key("diag.cache.col-fake-ip", "Fake-IP");
pub const CACHE_RESOLVED: Key = key("diag.cache.entries-resolved", "resolved");
pub const CACHE_EXPIRES: Key = key("diag.cache.entries-expires", "expires");
pub const CACHE_CLEAR_APP: Key = key("diag.cache.clear-app-button", "Clear app cache");
pub const CACHE_CLEAR_OS: Key = key("diag.cache.clear-os-dns-button", "Clear OS DNS cache");
pub const CACHE_CLEAR_APP_QUESTION: Key = key(
    "tui.cache.clear-app-question",
    "Clear the app cache? Names are resolved again as programs use them.",
);
pub const CACHE_CLEAR_OS_QUESTION: Key = key(
    "tui.cache.clear-os-question",
    "Flush the operating system's DNS cache?",
);
pub const CACHE_CLEARING: Key = key("tui.cache.clearing", "Clearing…");
pub const CACHE_CLEARED: Key = key(
    "status.cache-cleared",
    "Cache cleared: {count} resolution(s) removed.",
);
pub const CACHE_CLEAR_FAILED: Key = key("status.cache-cleared-failed", "Failed to clear cache: ");
pub const CACHE_OS_FLUSHED: Key = key("diag.cache.os-flush-ok", "OS DNS cache flushed.");
pub const CACHE_OS_NOT_FLUSHED: Key = key(
    "diag.cache.os-flush-failed",
    "Could not flush the OS DNS cache.",
);
pub const CACHE_NO_RULE: Key = key("diag.cache.route-filter.none", "No rule");

pub const CACHE_HELP_SEARCH: Key = key(
    "tui.cache.help-search",
    "/: search the cache on the service; Enter applies the search, Esc cancels",
);
pub const CACHE_HELP_CLEAR: Key = key(
    "tui.cache.help-clear",
    "c: clear the app cache   o: flush the operating system's DNS cache (each asks first)",
);
pub const CACHE_PLAIN_DETAILS: Key = key(
    "tui.cache.plain-details",
    "d and a row number: show that entry, for example d 3",
);
pub const CACHE_PLAIN_SEARCH: Key = key(
    "tui.cache.plain-search",
    "/ and text: search the cache on the service, for example /example.com; / on its own clears the search",
);

// ── Diagnostics ──────────────────────────────────────────────────────────────

pub const SERVICE: Key = key("label.service", "Service");
pub const SERVICE_RUNNING: Key = key("diag.status.service-running", "Service running");
pub const SERVICE_DEGRADED: Key = key("diag.status.service-degraded", "Service degraded");
pub const SERVICE_STARTING: Key = key("diag.status.service-starting", "Service starting...");
pub const SERVICE_RECOVERY: Key = key(
    "diag.status.service-recovery-required",
    "Service requires recovery action",
);
pub const SERVICE_UNAVAILABLE: Key = key("diag.status.service-unavailable", "Service unavailable");
pub const REVISION: Key = key("diag.service.revision-label", "Active revision");
pub const PENDING: Key = key("diag.service.pending-changes-label", "Pending changes");
pub const STARTED_AFTER: Key = key(
    "diag.service.started-after-sign-in",
    "The service started %1 s after this boot reached the sign-in screen.",
);
pub const STARTED_BEFORE: Key = key(
    "diag.service.started-before-sign-in",
    "The service started %1 s before this boot reached the sign-in screen.",
);
pub const STALE: Key = key(
    "diag.status.stale-data-warning",
    "Status data may be outdated",
);
pub const NO_DATA: Key = key("diag.status.no-data", "No data from the service yet");
pub const LOADING: Key = key("logs.pagination.loading", "Loading...");
pub const CACHE_HEALTHY: Key = key("diag.status.cache-healthy", "Cache healthy");
pub const CACHE_STALE: Key = key("diag.status.cache-stale", "Cache entries stale");
pub const CACHE_ENTRIES: Key = key("diag.cache.entry-count", "Entries");
pub const LOG_FILES: Key = key("diag.storage-health.log-files", "{count} log file(s)");
pub const LOG_DROPPED: Key = key(
    "diag.storage-health.dropped-events",
    "{count} event(s) dropped",
);
pub const LOG_DIR_NOT_WRITABLE: Key = key(
    "diag.storage-health.dir-not-writable",
    "Log directory is not writable",
);

pub const AUDIT: Key = key("diag.audit.title", "Audit trail");
pub const AUDIT_BROKEN: Key = key(
    "diag.status.audit-chain-mismatch",
    "Audit chain mismatch detected",
);
pub const AUDIT_OK: Key = key("diag.status.audit-chain-ok", "Audit chain intact");
pub const ALERTS_UNREAD: Key = key(
    "diag.alert.unread-prefix",
    "Security alerts requiring attention:",
);
pub const ALERTS_UNREADABLE: Key = key(
    "diag.alert.unreadable",
    "The service could not read its security alerts, so this list may be incomplete or out of date.",
);
pub const ALERTS_NONE: Key = key("diag.alert.no-active-alerts", "No active alerts");
pub const ALERT_ACTIVE: Key = key("diag.alert.title-active", "Active security alert");
pub const ALERT_ACKNOWLEDGED: Key = key("diag.alert.title-acknowledged", "Acknowledged alert");
pub const ALERT_ACK: Key = key("diag.alert.action-acknowledge", "Acknowledge");
pub const ALERT_ACK_DONE: Key = key("diag.alert.ack-completed", "Security alert acknowledged.");
pub const ALERT_ACK_FAILED: Key = key("diag.alert.ack-failed", "Failed to acknowledge alert: ");
pub const ALERT_ACKING: Key = key("tui.diagnostics.acknowledging", "Acknowledging…");
pub const REVIEW_TITLE: Key = key("diag.alert.review.title", "Acknowledge security alert");
pub const REVIEW_EMPTY: Key = key(
    "diag.alert.review.body-empty",
    "No rule set needs to be trusted. Acknowledging only closes the alert.",
);
pub const REVIEW_KEY_RESET: Key = key(
    "diag.alert.review.body-key-reset",
    "The integrity key was recreated, so the stored rule sets below can no longer be verified. Acknowledging trusts them as listed.",
);
pub const REVIEW_TAMPER: Key = key(
    "diag.alert.review.body-tamper",
    "The rule set below was changed outside the app. Acknowledging trusts its contents as listed.",
);
pub const REVIEW_BASELINE: Key = key("diag.alert.review.scope-baseline", "shared baseline");
pub const REVIEW_USER: Key = key("diag.alert.review.scope-user", "user rules");
pub const REVIEW_POINTER: Key = key(
    "diag.alert.review.row-pointer",
    "Which rule set is active ({scope}), set {when}",
);
pub const REVIEW_RULES: Key = key("diag.alert.review.rule-count", "{count} rules");
pub const REVIEW_IN_USE: Key = key("diag.alert.review.status-active", "in use");

pub const EXPLAIN: Key = key("diag.explain.title", "Explain sample");
pub const EXPLAIN_SUBTITLE: Key = key(
    "diag.explain.subtitle",
    "Enter a hostname or IP to simulate the routing decision against the active rule set.",
);
pub const EXPLAIN_INPUT: Key = key("diag.explain.probe-placeholder", "hostname or IP");
pub const EXPLAIN_PROBING: Key = key("diag.explain.probing", "Probing...");
pub const EXPLAIN_EMPTY: Key = key(
    "diag.explain.empty",
    "No probe has been run yet. Enter a query above and click Probe.",
);
pub const EXPLAIN_REQUIRED: Key = key(
    "diag.explain.input-required",
    "Enter a hostname or IP to probe",
);
pub const ROUTE_NONE: Key = key("diag.explain.route.none", "no route");
pub const ROUTE_BLOCKED: Key = key("diag.explain.route.blocked", "blocked");
pub const ROUTE_PRIMARY: Key = key("diag.explain.route.primary", "primary route");
pub const ROUTE_SECONDARY: Key = key("diag.explain.route.secondary", "additional route");
pub const VERDICT_BLOCK: Key = key("diag.conn-trace.verdict.block", "Blocked");
pub const VERDICT_PERMIT: Key = key("diag.conn-trace.verdict.permit", "Allowed");

pub const ARCHIVE: Key = key("diag.archive.title", "Diagnostic archive export");
pub const ARCHIVE_NOTE: Key = key(
    "diag.archive.service-owned-note",
    "The archive is saved in the service archives directory (per-user).",
);
pub const ARCHIVE_READY: Key = key("diag.archive.state-ready", "Ready");
pub const ARCHIVE_BUSY: Key = key("diag.archive.state-exporting", "Exporting...");
pub const ARCHIVE_FAILED: Key = key("diag.archive.state-failed", "Export failed");
pub const ARCHIVE_SAVED: Key = key(
    "diag.archive.state-saved-with-size",
    "Archive saved: {path} ({size})",
);
pub const ARCHIVE_UNREADABLE: Key = key(
    "tui.diagnostics.archive-unreadable",
    "The service wrote the archive, but this account cannot open it.",
);

pub const LOGS: Key = key("diag.logs.title", "Operational logs");
pub const LOGS_EMPTY: Key = key("diag.logs.empty", "No log entries");
pub const LOGS_FAILED: Key = key("logs.pagination.error-prefix", "Load failed");
pub const LOGS_LEVEL: Key = key("diag.logs.filter-level", "Level");
pub const LOGS_ALL_LEVELS: Key = key("diag.logs.filter-all-levels", "All levels");
pub const LOGS_KIND: Key = key("diag.logs.filter-kind", "Event type");
pub const LOGS_KIND_ANY: Key = key("tui.diagnostics.kind-any", "any");
pub const LOGS_RANGE: Key = key("diag.logs.filter-time-range", "Time range");
pub const LOGS_SESSION: Key = key("diag.logs.range-current-session", "Current session");
pub const LOGS_ALL: Key = key("diag.logs.range-all", "All history");

pub const DIAG_HELP_SWITCH: Key = key(
    "tui.diagnostics.help-switch",
    "l: switch between diagnostics and the log",
);
pub const DIAG_HELP_ACK: Key = key(
    "tui.diagnostics.help-ack",
    "Up and Down: choose an alert; a: acknowledge it",
);
pub const DIAG_HELP_EXPLAIN: Key = key(
    "tui.diagnostics.help-explain",
    "e: type a host name or address and see which rule decides it",
);
pub const DIAG_HELP_EXPORT: Key = key(
    "tui.diagnostics.help-export",
    "x: export a diagnostic archive; the service writes it and the path is shown here",
);
pub const DIAG_HELP_LOG_FILTERS: Key = key(
    "tui.diagnostics.help-log-filters",
    "In the log: v changes the lowest level shown, / filters by event type, s switches between this session and all history",
);
pub const DIAG_PLAIN_ACK: Key = key(
    "tui.diagnostics.plain-ack",
    "a and an alert number: acknowledge it, for example a 1",
);
pub const DIAG_PLAIN_EXPLAIN: Key = key(
    "tui.diagnostics.plain-explain",
    "e and a host or address: which rule decides it, for example e example.com",
);
pub const DIAG_PLAIN_EXPORT: Key = key(
    "tui.diagnostics.plain-export",
    "x: export a diagnostic archive",
);
pub const DIAG_PLAIN_LOG_FILTERS: Key = key(
    "tui.diagnostics.plain-log-filters",
    "In the log: v next level, / and text filter by event type (/ on its own clears), s this session or all history",
);

/// Every `tui.*` and fixed GUI key above, for the test that holds both locale
/// files to them.
#[cfg(test)]
pub const ALL: &[Key] = &[
    PAGE,
    PAGE_MORE,
    HELP_PAGES,
    PLAIN_PAGES,
    HELP_REFRESH,
    TYPING_HINT,
    YES_NO,
    YES,
    NO,
    PRIMARY,
    SECONDARY,
    TRACE_LIST,
    TRACE_DETAIL,
    TRACE_SHOWN,
    TRACE_SEARCH,
    TRACE_PATH,
    TRACE_SUBTITLE,
    TRACE_VERDICT_NOTE,
    TRACE_LOADING,
    TRACE_EMPTY,
    TRACE_NOT_OBSERVING,
    TRACE_STREAM_OFF,
    TRACE_NO_MATCH,
    TRACE_FAILED,
    TRACE_SHOW_BLOCKED,
    TRACE_SHOW_LOCAL,
    TRACE_ONLY_IPV6,
    TRACE_SEARCH_LABEL,
    TRACE_BLOCK_BY_NRR,
    TRACE_BLOCK_BY_OTHER,
    TRACE_FROM,
    TRACE_RELAY_FOR,
    TRACE_HOST_OTHERS,
    TRACE_FAKE_IP,
    TRACE_VIA_FAKE_IP,
    TRACE_NAMES,
    TRACE_LEAK,
    TRACE_WHY,
    COL_PROCESS,
    COL_REMOTE,
    COL_EGRESS,
    COL_VERDICT,
    TRACE_HELP_EXPLAIN,
    TRACE_HELP_SEARCH,
    TRACE_HELP_FILTERS,
    TRACE_PLAIN_DETAILS,
    TRACE_PLAIN_EXPLAIN,
    TRACE_PLAIN_SEARCH,
    CACHE_LIST,
    CACHE_DETAIL,
    CACHE_TOTAL,
    CACHE_SEARCH,
    CACHE_SEARCH_LABEL,
    CACHE_LOADING,
    CACHE_EMPTY,
    CACHE_NO_MATCH,
    CACHE_FAILED,
    CACHE_REDACTED,
    COL_HOST,
    COL_IP,
    COL_SOURCE,
    COL_ROUTE,
    COL_FRESHNESS,
    COL_FAKE_IP,
    CACHE_RESOLVED,
    CACHE_EXPIRES,
    CACHE_CLEAR_APP,
    CACHE_CLEAR_OS,
    CACHE_CLEAR_APP_QUESTION,
    CACHE_CLEAR_OS_QUESTION,
    CACHE_CLEARING,
    CACHE_CLEARED,
    CACHE_CLEAR_FAILED,
    CACHE_OS_FLUSHED,
    CACHE_OS_NOT_FLUSHED,
    CACHE_NO_RULE,
    CACHE_HELP_SEARCH,
    CACHE_HELP_CLEAR,
    CACHE_PLAIN_DETAILS,
    CACHE_PLAIN_SEARCH,
    SERVICE,
    SERVICE_RUNNING,
    SERVICE_DEGRADED,
    SERVICE_STARTING,
    SERVICE_RECOVERY,
    SERVICE_UNAVAILABLE,
    REVISION,
    PENDING,
    STARTED_AFTER,
    STARTED_BEFORE,
    STALE,
    NO_DATA,
    LOADING,
    CACHE_HEALTHY,
    CACHE_STALE,
    CACHE_ENTRIES,
    LOG_FILES,
    LOG_DROPPED,
    LOG_DIR_NOT_WRITABLE,
    AUDIT,
    AUDIT_BROKEN,
    AUDIT_OK,
    ALERTS_UNREAD,
    ALERTS_UNREADABLE,
    ALERTS_NONE,
    ALERT_ACTIVE,
    ALERT_ACKNOWLEDGED,
    ALERT_ACK,
    ALERT_ACK_DONE,
    ALERT_ACK_FAILED,
    ALERT_ACKING,
    REVIEW_TITLE,
    REVIEW_EMPTY,
    REVIEW_KEY_RESET,
    REVIEW_TAMPER,
    REVIEW_BASELINE,
    REVIEW_USER,
    REVIEW_POINTER,
    REVIEW_RULES,
    REVIEW_IN_USE,
    EXPLAIN,
    EXPLAIN_SUBTITLE,
    EXPLAIN_INPUT,
    EXPLAIN_PROBING,
    EXPLAIN_EMPTY,
    EXPLAIN_REQUIRED,
    ROUTE_NONE,
    ROUTE_BLOCKED,
    ROUTE_PRIMARY,
    ROUTE_SECONDARY,
    VERDICT_BLOCK,
    VERDICT_PERMIT,
    ARCHIVE,
    ARCHIVE_NOTE,
    ARCHIVE_READY,
    ARCHIVE_BUSY,
    ARCHIVE_FAILED,
    ARCHIVE_SAVED,
    ARCHIVE_UNREADABLE,
    LOGS,
    LOGS_EMPTY,
    LOGS_FAILED,
    LOGS_LEVEL,
    LOGS_ALL_LEVELS,
    LOGS_KIND,
    LOGS_KIND_ANY,
    LOGS_RANGE,
    LOGS_SESSION,
    LOGS_ALL,
    DIAG_HELP_SWITCH,
    DIAG_HELP_ACK,
    DIAG_HELP_EXPLAIN,
    DIAG_HELP_EXPORT,
    DIAG_HELP_LOG_FILTERS,
    DIAG_PLAIN_ACK,
    DIAG_PLAIN_EXPLAIN,
    DIAG_PLAIN_EXPORT,
    DIAG_PLAIN_LOG_FILTERS,
];

#[cfg(test)]
mod tests {
    use super::ALL;
    use serde_json::Value;

    fn locale(language: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../locales")
            .join(format!("{language}.json"));
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        serde_json::from_str(raw.trim_start_matches('\u{feff}'))
            .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
    }

    #[test]
    fn every_key_is_in_both_locale_files() {
        for language in ["en", "ru"] {
            let root = locale(language);
            let missing: Vec<_> = ALL
                .iter()
                .filter(|k| {
                    k.id.split('.')
                        .try_fold(&root, |node, part| node.get(part))
                        .and_then(Value::as_str)
                        .is_none()
                })
                .map(|k| k.id)
                .collect();
            assert!(missing.is_empty(), "{language}.json lacks {missing:?}");
        }
    }
}
