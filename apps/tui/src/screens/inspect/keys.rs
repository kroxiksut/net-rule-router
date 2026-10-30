//! Locale keys of the trace, cache and diagnostics screens. The GUI's wording
//! is reused wherever the GUI says the same thing; only terminal-only text is
//! `tui.*`. Keys built from a service slug (`diag.conn-trace.egress.<slug>`)
//! are looked up with `Texts::dynamic` and are the GUI's own.

use crate::i18n::{key, Key, Plural};

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
pub const PRIMARY: Key = key("label.primary", "Main");
pub const SECONDARY: Key = key("label.secondary", "Additional");

// ── Connection trace ─────────────────────────────────────────────────────────

pub const TRACE_LIST: Key = key("tui.trace.list-title", "Connections");
pub const TRACE_DETAIL: Key = key("tui.trace.detail-title", "Selected connection");
pub const TRACE_SHOWN: Key = key("tui.trace.shown", "Shown: {shown} of {total}.");
pub const TRACE_SEARCH: Key = key("tui.trace.search", "Search: {text}");
pub const TRACE_PATH: Key = key("tui.trace.path", "Path: {path}");
pub const TRACE_SUBTITLE: Key = key(
    "diag.conn-trace.subtitle",
    "Recently-observed outbound connections and which connection they actually left through (main or additional).",
);
pub const TRACE_VERDICT_NOTE: Key = key(
    "diag.conn-trace.verdict-note",
    "\"Blocked\" means some filter in the system dropped the connection, such as a firewall or an antivirus. \"Blocked (NetRuleRouter)\" means NetRuleRouter stopped it: a deny rule, or leak protection while the additional connection is not working. Apart from that, NetRuleRouter does not block traffic on your main connection.",
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
pub const TRACE_LEARNED_ROUTE: Key = key(
    "diag.conn-trace.learned-route",
    "First connection held at %1 while the address was being learned, then sent over the additional connection",
);
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
    "Mismatch: this address belongs to a rule routed to the additional adapter, but the connection was allowed out over the MAIN connection — a leak indicator.",
);
pub const TRACE_WHY: Key = key("diag.conn-trace.why-this-route", "Why this connection?");
pub const COL_PROCESS: Key = key("diag.conn-trace.col-process", "Process");
pub const COL_REMOTE: Key = key("diag.conn-trace.col-remote", "Remote");
pub const COL_EGRESS: Key = key("diag.conn-trace.col-egress", "Egress");
pub const COL_VERDICT: Key = key("diag.conn-trace.col-verdict", "Verdict");

pub const TRACE_HELP_EXPLAIN: Key = key(
    "tui.trace.help-explain",
    "Enter: why the chosen connection went where it did (opens Diagnostics)",
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
    "e and a row number: why that connection went where it did, for example e 3",
);
pub const TRACE_PLAIN_SEARCH: Key = key(
    "tui.trace.plain-search",
    "/ and text: search all fields, for example /example; / on its own clears the search",
);
pub const TRACE_HELP_OUTAGE: Key = key(
    "tui.trace.help-outage",
    "o: what was blocked while the additional connection was down",
);
pub const TRACE_HELP_HISTORY: Key = key(
    "tui.trace.help-history",
    "h: the latest connections or your kept history   t: the history's period — last hour, today, last 7 days",
);
pub const TRACE_PLAIN_HISTORY: Key = key(
    "tui.trace.plain-history",
    "h hour, h today or h week: your kept history of that period; h now: back to the latest connections; t: the next period",
);
pub const TRACE_HELP_GROUPING: Key = key(
    "tui.trace.help-grouping",
    "g: group the list — no grouping, by program, by folder   f: a rule for the folder of the chosen group (opens Rules)",
);
pub const TRACE_PLAIN_GROUPING: Key = key(
    "tui.trace.plain-grouping",
    "g: the next grouping; g none, g program or g folder: that grouping; f and a row number: a rule for that row's folder, for example f 3",
);
pub const TRACE_HELP_RULE: Key = key(
    "tui.trace.help-rule",
    "i: a rule for the address of the chosen connection   a: a rule for its program (both open Rules)",
);
pub const TRACE_PLAIN_RULE: Key = key(
    "tui.trace.plain-rule",
    "i and a row number: a rule for that connection's address, for example i 3; a and a row number: a rule for its program",
);

// ── Grouping ─────────────────────────────────────────────────────────────────

pub const TRACE_GROUP_BY: Key = key("diag.conn-trace.group-by", "Group");
pub const TRACE_GROUP_NONE: Key = key("diag.conn-trace.group-none", "No grouping");
pub const TRACE_GROUP_PROGRAM: Key = key("diag.conn-trace.group-program", "By program");
pub const TRACE_GROUP_FOLDER: Key = key("diag.conn-trace.group-folder", "By folder");
pub const TRACE_GROUP_CONNECTIONS: Plural = Plural {
    stem: "diag.conn-trace.group-connections.",
    one: "{count} connection",
    other: "{count} connections",
};
pub const TRACE_GROUP_PROGRAMS: Plural = Plural {
    stem: "diag.conn-trace.group-programs.",
    one: "{count} program",
    other: "{count} programs",
};
pub const TRACE_GROUP_NO_PATH: Key = key(
    "diag.conn-trace.group-no-path",
    "Programs without a known path",
);
pub const TRACE_RULE_FOR_FOLDER: Key =
    key("diag.conn-trace.rule-for-folder", "Rule for this folder…");
pub const TRACE_GROUPING_NOT_SAVED: Key = key(
    "tui.settings.terminal.save-failed",
    "Could not save the setting: {error}",
);

// ── The kept connection history ──────────────────────────────────────────────

pub const HISTORY_MODE: Key = key("diag.conn-history.mode-history", "History");
pub const HISTORY_HOUR: Key = key("diag.conn-history.period-hour", "Last hour");
pub const HISTORY_TODAY: Key = key("diag.conn-history.period-today", "Today");
pub const HISTORY_WEEK: Key = key("diag.conn-history.period-week", "Last 7 days");
pub const HISTORY_EMPTY: Key = key("diag.conn-history.empty", "No connections in this period");
pub const HISTORY_OFF: Key = key(
    "diag.conn-history.off",
    "Your connection history is switched off in Settings → Diagnostics and logs.",
);
pub const HISTORY_UNAVAILABLE: Key = key(
    "diag.conn-history.unavailable",
    "The connection history cannot be kept right now. The service log says why.",
);
pub const HISTORY_REMOVED: Key = key(
    "diag.conn-history.removed",
    "%1 older entries were removed to keep the history within its size limit, so it may cover less than the period you chose.",
);
pub const HISTORY_SKIPPED: Key = key(
    "diag.conn-history.skipped",
    "%1 connections came too fast to be recorded and are missing from the history.",
);
pub const HISTORY_ROW_DETAIL: Key = key("diag.conn-history.row-detail", "%1 times  ·  %2 – %3");
pub const HISTORY_FAILED: Key = key(
    "diag.conn-history.load-failed",
    "Failed to load the connection history: ",
);

// ── Blocked while the route was down ─────────────────────────────────────────

pub const OUTAGE_INTRO: Key = key(
    "diag.outage-blocks.intro",
    "What leak protection held back while the additional connection was down. Your rules send these addresses there, so they were blocked instead of leaving through the main connection.",
);
pub const OUTAGE_ACTIVE: Key = key(
    "diag.outage-blocks.episode-active",
    "The additional connection has been down since {since}.",
);
pub const OUTAGE_ENDED: Key = key(
    "diag.outage-blocks.episode-ended",
    "The last outage lasted from {since} to {until}.",
);
pub const OUTAGE_NONE: Key = key(
    "diag.outage-blocks.no-episode",
    "The additional connection has not been down since the service started.",
);
pub const OUTAGE_EMPTY: Key = key(
    "diag.outage-blocks.empty",
    "Nothing was blocked during this outage.",
);
pub const OUTAGE_OMITTED: Key = key(
    "diag.outage-blocks.omitted",
    "{count} older entries did not fit in the list.",
);
pub const OUTAGE_OBSERVER_OFF: Key = key(
    "diag.outage-blocks.observer-off",
    "On this system NetRuleRouter cannot tell which connections an outage blocked, so this list stays empty.",
);
pub const OUTAGE_FAILED: Key = key("diag.outage-blocks.failed", "Could not load the list: ");
pub const OUTAGE_OPEN_ROUTES: Key = key("diag.outage-blocks.open-routes", "Open Connections");
pub const COL_ATTEMPTS: Key = key("diag.outage-blocks.col-attempts", "Attempts");
pub const COL_FIRST: Key = key("diag.outage-blocks.col-first", "First");
pub const COL_LAST: Key = key("diag.outage-blocks.col-last", "Last");
pub const OUTAGE_UNRESOLVED: Key = key("diag.outage-blocks.unresolved", "did not resolve");
pub const OUTAGE_UNRESOLVED_NOTE: Key = key(
    "diag.outage-blocks.unresolved-note",
    "Names marked “did not resolve” got no address, so the program could not even start a connection.",
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
pub const COL_ROUTE: Key = key("diag.cache.col-route", "Connection");
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
pub const CACHE_HELP_FILTERS: Key = key(
    "tui.cache.help-filters",
    "f: freshness, t: source, w: connection; each press shows the next choice of that filter",
);
pub const CACHE_HELP_SEED: Key = key(
    "tui.cache.help-seed",
    "b: seed the cache from browser history (only names that match your rules)",
);
pub const CACHE_FILTERS: Key = key(
    "tui.cache.filters",
    "Shown: {source} · {freshness} · {route}",
);
pub const CACHE_SOURCE_ALL: Key = key("diag.cache.source-filter.all", "All sources");
pub const CACHE_FRESH_ALL: Key = key("diag.cache.freshness-filter.all", "Any freshness");
pub const CACHE_FRESH_FRESH: Key = key("diag.cache.freshness-filter.fresh", "Fresh");
pub const CACHE_FRESH_STALE: Key = key("diag.cache.freshness-filter.stale", "Stale");
pub const CACHE_ROUTE_ALL: Key = key("diag.cache.route-filter.all", "All connections");
pub const CACHE_ROUTE_NONE: Key = key("diag.cache.route-filter.none", "No rule");
pub const CACHE_SEED_STARTED: Key = key(
    "diag.cache.seed-browser-history.started",
    "Import started — hosts matching your rules will appear in the cache.",
);
pub const CACHE_SEED_RUNNING: Key = key("diag.cache.seed-browser-history.already-running", "Your previous import is still running — hosts matching your rules will appear in the cache when it finishes.");
pub const CACHE_SEED_UNAVAILABLE: Key = key(
    "diag.cache.seed-browser-history.unavailable",
    "This feature is unavailable.",
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
pub const DNS_NOT_RESTORED: Key = key(
    "tui.service.dns-not-restored",
    "System DNS could not be restored. Run nrr-cli reset-network as administrator.",
);
pub const RULES_BOOK_UNREADABLE: Key = key(
    "diag.service.rules-book-unreadable",
    "The service could not read saved rules. The rules applied last stay in force until it can.",
);
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
pub const AUDIT_EMPTY: Key = key("diag.audit.empty", "No audit entries");
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

pub const EXPLAIN: Key = key("diag.explain.title", "Which rule applies to a site");
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
pub const ROUTE_NONE: Key = key("diag.explain.route.none", "no connection");
pub const ROUTE_BLOCKED: Key = key("diag.explain.route.blocked", "blocked");
pub const ROUTE_PRIMARY: Key = key("diag.explain.route.primary", "main connection");
pub const ROUTE_SECONDARY: Key = key("diag.explain.route.secondary", "additional connection");
pub const VERDICT_BLOCK: Key = key("diag.conn-trace.verdict.block", "Blocked");
pub const VERDICT_PERMIT: Key = key("diag.conn-trace.verdict.permit", "Allowed");

pub const SITE_CHECK: Key = key("diag.site-check.title", "Check a site");
pub const SITE_SUBTITLE: Key = key(
    "diag.site-check.subtitle",
    "Is it the network or the site? The site's names are checked over your connections: their address, the connection your rules give them, and whether they answer there. Runs only when you ask.",
);
pub const SITE_INPUT: Key = key("diag.site-check.placeholder", "site name, e.g. example.com");
pub const SITE_RUNNING: Key = key("diag.site-check.running", "Checking {host}…");
pub const SITE_REQUIRED: Key = key(
    "diag.site-check.input-required",
    "Enter a site name to check",
);
pub const SITE_FAILED: Key = key("diag.site-check.failed", "Could not check the site: ");
pub const SITE_NO_ADDRESS: Key = key(
    "diag.site-check.no-address",
    "address not known: not opened lately",
);
pub const SITE_STATUS: Key = key("diag.site-check.status", "answer {code}");
pub const SITE_REDIRECTS: Key = key("diag.site-check.redirects", "sends on to {hosts}");
pub const SITE_COOKIES: Key = key(
    "diag.site-check.cookies.title",
    "If the site still loops or will not let you sign in, delete its cookies in the browser:",
);
pub const SITE_COOKIES_CHROME: Key = key("diag.site-check.cookies.chrome", "Chrome");
pub const SITE_COOKIES_EDGE: Key = key("diag.site-check.cookies.edge", "Edge");
pub const SITE_COOKIES_FIREFOX: Key = key("diag.site-check.cookies.firefox", "Firefox");
pub const SITE_COOKIES_NOTE: Key = key(
    "diag.site-check.cookies.note",
    "NetRuleRouter never reads or changes browser data.",
);
pub const SITE_MOVE: Key = key(
    "tui.diagnostics.site-move",
    "m: move the sign-in names to the site's connection (Rules opens with them, and you confirm)",
);
pub const SITE_TRACE: Key = key(
    "tui.diagnostics.site-trace",
    "t: open the connection trace to see what the site's connections did",
);
pub const ROUTE_DENIED: Key = key("label.block", "Denied");
pub const DIAG_HELP_SITE: Key = key(
    "tui.diagnostics.help-site-check",
    "c: type a site name and check whether the network or the site is at fault",
);
pub const DIAG_PLAIN_SITE: Key = key(
    "tui.diagnostics.plain-site-check",
    "c and a site name: check it, for example c example.com; m: move the sign-in names the check found to the site's connection",
);
pub const TRACE_HELP_CHECK: Key = key(
    "tui.trace.help-check-site",
    "c: check the chosen connection's site, to tell whether the network or the site is at fault (opens Diagnostics)",
);
pub const TRACE_PLAIN_CHECK: Key = key(
    "tui.trace.plain-check-site",
    "c and a row number: check that connection's site, for example c 3",
);

pub const MISSING_HEADING: Key = key("platform.missing.heading", "Not available on this computer");
pub const DNS_TAMPER_HEADING: Key = key(
    "diag.dns-tamper.heading",
    "Your provider changes some DNS answers",
);
pub const DNS_TAMPER_BODY: Key = key(
    "diag.dns-tamper.body",
    "For {count} sites the provider's name lookup gave an unusable answer. NetRuleRouter asked another resolver and routes those sites correctly anyway.",
);
pub const DNS_TAMPER_EXAMPLES: Key = key("diag.dns-tamper.examples", "For example: {names}");
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
    "l: switch between diagnostics, the log and the audit trail",
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
pub const AUDIT_RESTART_OPEN: Key = key("diag.audit.restart.open", "Restart audit chain…");
pub const AUDIT_RESTART_TITLE: Key = key("diag.audit.restart.title", "Restart audit chain");
pub const AUDIT_RESTART_LOADING: Key =
    key("diag.audit.restart.loading", "Checking the audit trail…");
pub const AUDIT_RESTART_ROW_LINE: Key =
    key("diag.audit.restart.row-line", "{file}, line {line}: {kind}");
pub const AUDIT_RESTART_ROW_FILE: Key = key("diag.audit.restart.row-file", "{file}: {kind}");
pub const AUDIT_RESTART_TRUNCATED: Key = key(
    "diag.audit.restart.list-truncated",
    "Only the first {shown} are listed.",
);
pub const AUDIT_RESTART_EXPLAIN: Key = key("diag.audit.restart.explain", "Confirming does not erase these breaks: they stay recorded in the audit trail, and checking continues from this point. A new break will be reported again.");
pub const AUDIT_RESTART_CHANGED: Key = key(
    "diag.audit.restart.changed",
    "The audit trail changed while this list was open. Review the updated list and confirm again.",
);
pub const AUDIT_RESTART_COMPLETED: Key = key(
    "diag.audit.restart.completed",
    "Audit chain restarted. Checking continues from this point.",
);
pub const AUDIT_RESTART_FAILED: Key = key(
    "diag.audit.restart.failed",
    "Could not restart the audit chain: ",
);
pub const AUDIT_RESTART_SUMMARY: Plural = Plural {
    stem: "diag.audit.restart.summary.",
    one: "The audit trail fails verification in {count} place:",
    other: "The audit trail fails verification in {count} places:",
};
pub const DIAG_PLAIN_LOG_FILTERS: Key = key(
    "tui.diagnostics.plain-log-filters",
    "In the log: v next level, / and text filter by event type (/ on its own clears), s this session or all history",
);
pub const LOGS_CATEGORY: Key = key("diag.logs.filter-category", "Category");
pub const COLUMN_TIME: Key = key("logs.column.time", "Time");
pub const COLUMN_LEVEL: Key = key("logs.column.level", "Level");
pub const COLUMN_CATEGORY: Key = key("logs.column.category", "Category");
pub const COLUMN_KIND: Key = key("logs.column.kind", "Event type");
pub const COLUMN_SEQ: Key = key("audit.column.seq", "Seq");
pub const COLUMN_AUDIT_KIND: Key = key("audit.column.kind", "Kind");
pub const COLUMN_RESULT: Key = key("audit.column.result", "Result");
pub const COLUMN_REASON: Key = key("audit.column.reason", "Reason");
pub const COLUMN_REVISION: Key = key("audit.column.revision", "Revision");
pub const SORT: Key = key("tui.diagnostics.sort", "Sorted by {column}, {direction}");
pub const SORT_ASCENDING: Key = key("tui.diagnostics.sort-ascending", "ascending");
pub const SORT_DESCENDING: Key = key("tui.diagnostics.sort-descending", "descending");
pub const DIAG_HELP_LOG_SORT: Key = key(
    "tui.diagnostics.help-log-sort",
    "In the log: c filters by category. In the log and the audit trail: o sorts by the next column, d reverses the order",
);
pub const DIAG_PLAIN_LOG_SORT: Key = key(
    "tui.diagnostics.plain-log-sort",
    "In the log: c and text filter by category (c on its own clears). In the log and the audit trail: o next sort column, d reverse order",
);
pub const ARCHIVE_LEVEL: Key = key("diag.archive.level.label", "Detail level");
pub const ARCHIVE_LEVEL_STANDARD: Key =
    key("diag.archive.level.standard", "Standard (recommended)");
pub const ARCHIVE_LEVEL_FULL: Key = key("diag.archive.level.diagnostics", "Full diagnostics");
pub const ARCHIVE_LEVEL_CAPTION: Key = key(
    "diag.archive.level.caption",
    "Full diagnostics adds extra cache, storage and decision detail and is less redacted. Only share it with support.",
);
pub const ARCHIVE_SESSION_ONLY: Key = key(
    "diag.archive.session-only",
    "Only logs from the current session",
);
pub const ARCHIVE_BUDGET: Key = key(
    "diag.archive.log-budget.label",
    "Log size limit in the archive",
);
pub const ARCHIVE_BUDGET_UNLIMITED: Key = key("diag.archive.log-budget.unlimited", "Unlimited");
pub const ARCHIVE_OPTIONS_HELP: Key = key(
    "tui.diagnostics.archive-options",
    "d: change the detail level, o: only this session's logs or all of them, b: change the log size limit",
);

/// Every `tui.*` and fixed GUI key above, for the test that holds both locale
/// files to them.
#[cfg(test)]
pub const ALL: &[Key] = &[
    LOGS_CATEGORY,
    COLUMN_TIME,
    COLUMN_LEVEL,
    COLUMN_CATEGORY,
    COLUMN_KIND,
    COLUMN_SEQ,
    COLUMN_AUDIT_KIND,
    COLUMN_RESULT,
    COLUMN_REASON,
    COLUMN_REVISION,
    SORT,
    SORT_ASCENDING,
    SORT_DESCENDING,
    DIAG_HELP_LOG_SORT,
    DIAG_PLAIN_LOG_SORT,
    ARCHIVE_LEVEL,
    ARCHIVE_LEVEL_STANDARD,
    ARCHIVE_LEVEL_FULL,
    ARCHIVE_LEVEL_CAPTION,
    ARCHIVE_SESSION_ONLY,
    ARCHIVE_BUDGET,
    ARCHIVE_BUDGET_UNLIMITED,
    ARCHIVE_OPTIONS_HELP,
    PAGE,
    PAGE_MORE,
    HELP_PAGES,
    PLAIN_PAGES,
    HELP_REFRESH,
    TYPING_HINT,
    YES_NO,
    AUDIT_RESTART_OPEN,
    AUDIT_RESTART_TITLE,
    AUDIT_RESTART_LOADING,
    AUDIT_RESTART_ROW_LINE,
    AUDIT_RESTART_ROW_FILE,
    AUDIT_RESTART_TRUNCATED,
    AUDIT_RESTART_EXPLAIN,
    AUDIT_RESTART_CHANGED,
    AUDIT_RESTART_COMPLETED,
    AUDIT_RESTART_FAILED,
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
    TRACE_LEARNED_ROUTE,
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
    TRACE_HELP_OUTAGE,
    TRACE_HELP_HISTORY,
    TRACE_PLAIN_HISTORY,
    TRACE_HELP_GROUPING,
    TRACE_PLAIN_GROUPING,
    TRACE_HELP_RULE,
    TRACE_PLAIN_RULE,
    TRACE_GROUP_BY,
    TRACE_GROUP_NONE,
    TRACE_GROUP_PROGRAM,
    TRACE_GROUP_FOLDER,
    TRACE_GROUP_NO_PATH,
    TRACE_RULE_FOR_FOLDER,
    TRACE_GROUPING_NOT_SAVED,
    HISTORY_MODE,
    HISTORY_HOUR,
    HISTORY_TODAY,
    HISTORY_WEEK,
    HISTORY_EMPTY,
    HISTORY_OFF,
    HISTORY_UNAVAILABLE,
    HISTORY_REMOVED,
    HISTORY_SKIPPED,
    HISTORY_ROW_DETAIL,
    HISTORY_FAILED,
    OUTAGE_INTRO,
    OUTAGE_ACTIVE,
    OUTAGE_ENDED,
    OUTAGE_NONE,
    OUTAGE_EMPTY,
    OUTAGE_OMITTED,
    OUTAGE_OBSERVER_OFF,
    OUTAGE_FAILED,
    OUTAGE_OPEN_ROUTES,
    COL_ATTEMPTS,
    COL_FIRST,
    COL_LAST,
    OUTAGE_UNRESOLVED,
    OUTAGE_UNRESOLVED_NOTE,
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
    CACHE_HELP_FILTERS,
    CACHE_HELP_SEED,
    CACHE_FILTERS,
    CACHE_SOURCE_ALL,
    CACHE_FRESH_ALL,
    CACHE_FRESH_FRESH,
    CACHE_FRESH_STALE,
    CACHE_ROUTE_ALL,
    CACHE_ROUTE_NONE,
    CACHE_SEED_STARTED,
    CACHE_SEED_RUNNING,
    CACHE_SEED_UNAVAILABLE,
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
    DNS_NOT_RESTORED,
    RULES_BOOK_UNREADABLE,
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
    AUDIT_EMPTY,
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
    MISSING_HEADING,
    DNS_TAMPER_HEADING,
    DNS_TAMPER_BODY,
    DNS_TAMPER_EXAMPLES,
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
    SITE_CHECK,
    SITE_SUBTITLE,
    SITE_INPUT,
    SITE_RUNNING,
    SITE_REQUIRED,
    SITE_FAILED,
    SITE_NO_ADDRESS,
    SITE_STATUS,
    SITE_REDIRECTS,
    SITE_COOKIES,
    SITE_COOKIES_CHROME,
    SITE_COOKIES_EDGE,
    SITE_COOKIES_FIREFOX,
    SITE_COOKIES_NOTE,
    SITE_MOVE,
    SITE_TRACE,
    ROUTE_DENIED,
    DIAG_HELP_SITE,
    DIAG_PLAIN_SITE,
    TRACE_HELP_CHECK,
    TRACE_PLAIN_CHECK,
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
    fn plural_families_are_in_both_locale_files() {
        for language in ["en", "ru"] {
            let root = locale(language);
            for plural in [
                super::TRACE_GROUP_CONNECTIONS,
                super::TRACE_GROUP_PROGRAMS,
                super::AUDIT_RESTART_SUMMARY,
            ] {
                for id in plural.required_ids() {
                    let found = id
                        .split('.')
                        .try_fold(&root, |node, part| node.get(part))
                        .and_then(Value::as_str)
                        .is_some();
                    assert!(found, "{language}.json lacks {id}");
                }
            }
        }
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
