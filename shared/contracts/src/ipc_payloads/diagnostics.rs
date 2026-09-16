use super::*;

// ── ExplainGet ────────────────────────────────────────────────────────────

/// Explain query request. Two phases:
/// - Historical: caller passes a `decision-id` previously emitted by the
///   service into the audit/log trail.
/// - Synthetic: caller passes an `input-sample`; the service simulates a
///   decision against the active rule set without writing audit.
///
/// `detail-level` selects the redaction policy:
/// - `compact-ui` — minimum surface (default GUI view)
/// - `diagnostics` — adds IPs, full match metadata, cache TTLs
/// - `developer-trace` — adds internal trace fields (developer / support)
///
/// At most one of `decision-id` / `input-sample` must be `Some`. Both
/// `None` is a malformed request; both `Some` is also malformed (the
/// service uses the first non-empty in defensive parsing but rejects on
/// ambiguity).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct ExplainGetRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_sample: Option<ExplainInputSampleDto>,
    /// Defaults to `compact-ui` server-side when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail_level: Option<String>,
}

/// Wire form of `nrr_diagnostics::explain::query::RuntimeInputSample`.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct ExplainInputSampleDto {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
}

/// Explain response envelope. Carries a flat compact view
/// for the existing `DiagnosticsSection.qml` 3-line display PLUS the
/// full structured `nrr_diagnostics::explain::response::ExplainResponse`
/// passthrough for future detail surfaces.
///
/// The compact view uses pre-localised plaintext keys; the full payload
/// uses `snake_case` fields (mirrors the producer's serde shape — the
/// service does NOT rewrite to kebab-case here to keep the cross-module
/// invariant that the explain response is owned by `nrr-diagnostics`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ExplainGetResponse {
    pub compact: ExplainCompactViewDto,
    /// Passthrough of `nrr_diagnostics::ExplainResponse` (snake_case
    /// fields preserved). May be `null` when the underlying explain is
    /// `Unavailable` and the service decides to short-circuit.
    pub full: serde_json::Value,
    /// Audit-log diagnostic-id correlations enriched by the service
    /// AFTER the engine produced the outcome. Empty for synthetic
    /// queries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostic_ids: Vec<String>,
}

/// Compact 3-field view rendered today by `DiagnosticsSection.qml`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ExplainCompactViewDto {
    /// Display label for the input — hostname, IP, or process name
    /// depending on what was the primary lookup key.
    pub input: String,
    /// Route role applied: `"primary"`, `"secondary"`, `"none"`,
    /// `"blocked"`. Matches `ExplainFinalActionSection::route_role` +
    /// "blocked" when fail-closed.
    pub route: String,
    /// Localisation key for the reason. The GUI resolves via `tr(key)`.
    pub reason_key: String,
    /// Kill-switch ENFORCEMENT verdict on top of the rule
    /// verdict, so the probe stops saying "primary" for a host the armed
    /// block-all would in fact drop. Slug, empty
    /// when nothing applies: `blocked-unknown-under-block-all` (coverage =
    /// fail-closed-unknown, kill-switch on, hostname absent from the FQDN
    /// cache → no permit compiles while armed) |
    /// `fail-closed-when-secondary-down` (secondary-routed host under an
    /// enabled fail-closed kill-switch). Also covers the shared-IP
    /// collateral slugs: `collateral-blocked-strict` (strict policy — the
    /// host's census-shared IPs stay pinned, so it is cut whenever the
    /// secondary is down) | `collateral-smart-exempt` (smart policy — shared
    /// IPs exempted; host works, secondary traffic on them unprotected) |
    /// `collateral-risk-subdomain-rules` (host un-cached but rule-cached
    /// subdomains exist under it — same-front-end collateral likely).
    /// Additive; the GUI renders it via
    /// `tr("diag.explain.enforcement.<slug>")`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub enforcement: String,
    /// For the collateral slugs: how many of the probe host's cached
    /// IPs the shared-IP census flags. `0` otherwise. Wire key:
    /// `enforcement-shared-ips`.
    #[serde(default)]
    pub enforcement_shared_ips: u32,
    /// For the collateral slugs: the probe host's total cached IP
    /// count (the "M" in "N of M IPs are shared"). `0` otherwise. Wire key:
    /// `enforcement-total-ips`.
    #[serde(default)]
    pub enforcement_total_ips: u32,
    /// The VIRTUAL (fake) IPv4 address currently
    /// answering for the probe host when fake-IP is active, empty otherwise.
    /// Shown next to the real route verdict so "why does this host resolve to
    /// 198.18.x.x" is answered in place. Wire key: `fake-ip`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fake_ip: String,
}

// ── DiagnosticsExportArchive ─────────────────────────────────────────────────

/// Archive export request. Service writes a zip into the
/// per-user `archives/` directory and returns its path. Inclusion flags
/// let the operator slim down the archive when only a specific category
/// is needed for support; all default to `true` for the canonical
/// support snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DiagnosticsExportArchiveRequest {
    #[serde(default = "default_true")]
    pub include_logs: bool,
    #[serde(default = "default_true")]
    pub include_audit_summary: bool,
    #[serde(default = "default_true")]
    pub include_troubleshooting_playbooks: bool,
    /// How much detail to export:
    /// `"standard"` (default — redacted, the sections a normal bug report
    /// needs) or `"diagnostics"` (adds `cache_health.json`,
    /// `storage_health.json`, `explain_samples.json` and relaxes redaction to
    /// the diagnostics tier). An unknown/absent value falls back to
    /// `"standard"` — the export never fails on a bad level. Older clients that
    /// omit the field get exactly today's behavior.
    #[serde(default)]
    pub redaction_level: Option<String>,
    /// "Current session only" log trimming. When set,
    /// `logs.ndjson` drops entries older than this UTC-ms instant. The GUI
    /// passes the local-midnight floor of its session start,
    /// so yesterday's rotated segments stay out of a routine support archive
    /// while an app or service restart mid-day cannot silently drop the same
    /// day's earlier history from the bundle. Absent → full log history as
    /// before (additive; older clients are unaffected).
    #[serde(default)]
    pub logs_from_ms: Option<i64>,
    /// Byte cap for the RAW service-log section (`service-logs.ndjson`), the
    /// lines as written. Mirrors the user's "archive log budget" preference;
    /// `0` (and absence) means the preset default. The section used to be
    /// attached by the launcher reading the service's log directory, which is
    /// why the cap lived there — the service builds it now, so the cap travels
    /// with the request. Additive: an older service ignores it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_log_budget_bytes: Option<u64>,
}

impl Default for DiagnosticsExportArchiveRequest {
    fn default() -> Self {
        Self {
            include_logs: true,
            include_audit_summary: true,
            include_troubleshooting_playbooks: true,
            redaction_level: None,
            logs_from_ms: None,
            raw_log_budget_bytes: None,
        }
    }
}

/// Wire request for `LogsClear`. Maps 1:1 to
/// `nrr_diagnostics::facade::dto::ClearLogsRequest`. Audit trail is
/// never deleted — see the design invariant in
/// `core/diagnostics/src/facade/service.rs:11`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LogsClearRequest {
    /// When `true`, also remove archived diagnostics-export zips. The
    /// GUI never sets this today (we only expose the rotating-log
    /// cleanup); kept on the wire for parity with the facade.
    #[serde(default)]
    pub include_archives: bool,
    /// When `true`, report what would be deleted without acting.
    #[serde(default)]
    pub dry_run: bool,
}

/// Wire response for `LogsClear`. Lets the GUI
/// echo back a friendly toast (`files_deleted` rotated NDJSON files
/// freed `bytes_freed` bytes).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LogsClearResponse {
    pub files_deleted: u64,
    pub bytes_freed: u64,
    pub dry_run: bool,
}

/// Wire request for `CacheClear`. Clears the rebuildable
/// FQDN/IP resolution cache (`nrr_fqdn_ip_cache.db`) on explicit user
/// request. The audit / service-state DBs are never touched.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CacheClearRequest {
    /// When `true`, report the row counts that would be deleted without
    /// acting (routes to a stats read instead of the delete).
    #[serde(default)]
    pub dry_run: bool,
    /// When `true`, ALSO flush the OS resolver cache
    /// (`DnsFlushResolverCache` via `DnsCacheControlPort`). The GUI splits
    /// "Clear cache" into two buttons: the app's SQLite FQDN/IP cache (this
    /// request with `flush_os_cache = false`, the historic behaviour) and the
    /// OS DNS cache (`clear_app_cache = false`, `flush_os_cache = true`).
    /// `#[serde(default)]` = `false` keeps it additive — an older GUI that
    /// omits it gets the app-cache-only behaviour unchanged.
    #[serde(default)]
    pub flush_os_cache: bool,
    /// When `false`, DO NOT touch the app's SQLite cache (used by
    /// the OS-DNS-only button). Defaults to `true` (via `clear_app_cache_default`)
    /// so an older GUI that omits it keeps clearing the app cache — the
    /// original single-button behaviour.
    #[serde(default = "clear_app_cache_default")]
    pub clear_app_cache: bool,
}

/// Wire default for [`CacheClearRequest::clear_app_cache`]: `true` — an
/// omitting GUI must keep clearing the app cache.
fn clear_app_cache_default() -> bool {
    true
}

impl Default for CacheClearRequest {
    /// Matches the serde defaults (NOT the derived all-`false`): the app cache
    /// is cleared, the OS cache is not — the original single-button behaviour.
    fn default() -> Self {
        Self {
            dry_run: false,
            flush_os_cache: false,
            clear_app_cache: true,
        }
    }
}

/// Wire response for `CacheClear`. Lets the GUI echo a
/// friendly toast and re-pull the cache-health card.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CacheClearResponse {
    /// Hostname→IP resolution rows removed (or that would be removed on a
    /// dry run).
    pub resolutions_removed: u64,
    /// Negative-cache entries removed (or that would be removed).
    pub negative_cache_removed: u64,
    /// Echoes the request's `dry-run` flag.
    pub dry_run: bool,
    /// Outcome of the OS-resolver-cache flush: `Some(true)` flushed,
    /// `Some(false)` requested but failed (or no port wired), `None` not
    /// requested. `#[serde(default)]` keeps it additive for older peers.
    #[serde(default)]
    pub os_cache_flushed: Option<bool>,
}

/// Wire request for `CacheEntriesList`. Read-only, paginated
/// view of the FQDN/IP resolution cache. Offset-based paging is carried
/// through the shared [`PaginationParams`] cursor (the handler encodes the
/// next offset in the cursor); the cache is bounded so offset paging is
/// cheap and stable.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CacheEntriesListRequest {
    #[serde(default)]
    pub pagination: PaginationParams,
    /// Optional server-side search term. When non-empty the
    /// service filters the cache by a case-insensitive substring match on the
    /// canonical host and IP (WHERE LIKE) so a large cache is searched in SQLite
    /// instead of being drained page-by-page into the GUI (the search freeze).
    /// Empty = no filter (full listing).
    #[serde(default)]
    pub query: String,
}

/// One row in the read-only cache-entries viewer. Field naming
/// stays snake_case (matching [`crate::diagnostics_dto::LogEntryDto`], which
/// also flows through [`PageResult`]).
///
/// `hostname` / `ip` are already redaction-processed by the service before
/// serialisation: in the compact tier `hostname` is the registrable domain
/// (eTLD+1) and `ip` is a `<private-ipv4>` / `<public-ipv4>` marker; in the
/// diagnostics tier both are the full values. `freshness` and `source` are
/// stable backend slugs (`fresh`, `stale_usable`, `dns`,
/// `observed_from_traffic`, …) — the GUI wraps them with `tr()`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheEntryDto {
    pub hostname: String,
    pub ip: String,
    /// Freshness-state slug (`fresh`, `stale_usable`, `stale_not_usable`,
    /// `conflicting`, `negative_cached`).
    pub freshness: String,
    /// Resolution-source slug (`dns`, `observed_from_traffic`,
    /// `manual_refresh`, `imported_seed`, `cache_rebuild`).
    pub source: String,
    /// When the mapping was resolved (UTC ms).
    pub resolved_at_ms: i64,
    /// When the mapping expires (UTC ms).
    pub expires_at_ms: i64,
    /// Where routing policy would send this host: `secondary`
    /// (matches a secondary rule by name, or its IP is owned by a secondary
    /// rule — the shared-IP collateral case), `primary` (matches a primary
    /// rule), or empty (no rule expectation derived). Stamped at read time by
    /// the handler, mirroring [`ConnTraceEntryDto::expected_route`]; the GUI
    /// renders it via the same route labels.
    #[serde(default)]
    pub expected_route: String,
    /// Kind of the strongest address rule covering this
    /// entry: `exact-fqdn`, `subdomain`, `zone`, `exact-ip`, or empty (no
    /// address rule matched). Stamped at read time alongside
    /// `expected_route`; the cache viewer sorts direct rule matches above
    /// zone-derived entries.
    #[serde(default)]
    pub rule_match_kind: String,
    /// The VIRTUAL (fake) IPv4 address currently
    /// bound to this hostname when fake-IP is active, empty otherwise. Shown
    /// next to the real cached address in the cache viewer. Stamped at read
    /// time from the live allocator (not persisted in the cache DB).
    #[serde(default)]
    pub fake_ip: String,
}

/// Wire response for `CacheEntriesList`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CacheEntriesListResponse {
    /// One page of `(hostname, ip)` entries plus the offset cursor for the
    /// next page (`next_cursor == None` on the last page).
    pub page: PageResult<CacheEntryDto>,
    /// `true` when the compact redaction tier is active (values are reduced
    /// for privacy). Lets the GUI show a "enable diagnostic mode for full
    /// detail" notice.
    pub redacted: bool,
}

/// Wire request for `ConnTraceEntriesList`. Read-only,
/// paginated view of recently-observed outbound connections. Offset paging via
/// the shared [`PaginationParams`] cursor (the handler encodes the next offset).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConnTraceEntriesListRequest {
    #[serde(default)]
    pub pagination: PaginationParams,
}

/// One row in the connection-trace viewer. Field naming
/// stays snake_case (like [`CacheEntryDto`]). `remote` / `local` are
/// redaction-processed by the service (the IP is masked in the compact tier);
/// `process` is the executable name only. `proto`, `egress_role` and `verdict`
/// are stable backend slugs the GUI wraps with `tr()`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnTraceEntryDto {
    /// Executable name (e.g. `chrome.exe`), or `?` when unknown.
    pub process: String,
    /// Full executable path (device/NT path) for the hover tooltip, or empty
    /// when unknown. Only populated for the local
    /// own-machine viewer (not redacted away), matching the cache viewer.
    #[serde(default)]
    pub process_path: String,
    /// Transport slug (`tcp`, `udp`, `other`).
    pub proto: String,
    /// Local socket `ip:port` (IP masked in the compact tier).
    pub local: String,
    /// Remote socket `ip:port` (IP masked in the compact tier).
    pub remote: String,
    /// Egress-role slug (`primary`, `secondary`, `other`, `unknown`).
    pub egress_role: String,
    /// Egress interface index (0 when unresolved).
    pub egress_ifindex: u32,
    /// Verdict slug (`permit`, `block`, `unknown`).
    pub verdict: String,
    /// Drop attribution slug: `netrulerouter` (an NRR filter dropped it),
    /// `other` (Windows Firewall / antivirus / another WFP filter), or empty
    /// (an allow, or the owner could not be resolved), so the trace never
    /// blames NRR for a foreign drop. GUI wraps with tr().
    #[serde(default)]
    pub blocked_by: String,
    /// Which of our filters dropped it — a `BlockReason` slug
    /// (`route-unavailable`, `not-covered-by-rules`, `blocked-by-rule`,
    /// `ipv6-blocked`, `dns-lockdown`, `unattributed`); empty for anything that
    /// is not our drop. The GUI words it the way the block notice does.
    #[serde(default)]
    pub block_reason: String,
    /// Where routing policy EXPECTS this remote to egress:
    /// `secondary` (the remote IP belongs to a secondary rule per the current
    /// rule book + FQDN cache) or empty (no expectation derived). Stamped at
    /// read time by the handler. The GUI flags `expected_route == "secondary"`
    /// with `egress_role == "primary"` on a permitted flow as a LEAK indicator
    /// (decision-vs-actual mismatch).
    #[serde(default)]
    pub expected_route: String,
    /// When the connection was observed (UTC ms), or 0 when unknown.
    pub observed_at_ms: i64,
    /// The hostname this flow was dialled ON BEHALF OF, when the
    /// service itself opened it as the fake-IP relay: the application talks to
    /// a virtual address and the service carries the traffic to the real one.
    /// Empty for every ordinary flow. Without it the relay reads as the service
    /// going out to the internet on its own account.
    #[serde(default)]
    pub relay_for: String,
    /// The secondary-rule host this remote address belongs to, when the service
    /// knows one — so "which rule decides this row" can be asked by name: a
    /// domain rule cannot match a bare address.
    #[serde(default)]
    pub rule_host: String,
}

/// Wire response for `ConnTraceEntriesList`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConnTraceEntriesListResponse {
    /// One page of connection-trace rows plus the offset cursor for the next
    /// page (`next_cursor == None` on the last page).
    pub page: PageResult<ConnTraceEntryDto>,
    /// `true` when the compact redaction tier is active (IPs masked).
    pub redacted: bool,
    /// `false` when no observation source is running, so an empty page means
    /// "not watching" rather than "nothing happened yet" — the two states the
    /// GUI must not present as one. Defaults to `true` for a service that
    /// predates the field: silence is the safer read than a false alarm.
    #[serde(default = "default_true")]
    pub observer_active: bool,
    /// `false` when the user has switched the GUI trace off in Settings. The
    /// page is then empty BY REQUEST — a third silence, distinct from both
    /// "nothing happened" and "not watching". Read per request, so the switch
    /// takes effect without restarting the service.
    #[serde(default = "default_true")]
    pub gui_stream_enabled: bool,
}

/// Wire request for `DiagnosticModeSet`. The response
/// is the fresh [`crate::diagnostics_dto::DiagnosticModeStateDto`] — an
/// authoritative echo of the resulting session state.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DiagnosticModeSetRequest {
    /// Enable (true) or disable (false) extended diagnostics. Absent → false
    /// (a bare payload is a disable request).
    #[serde(default)]
    pub enabled: bool,
    /// TTL in milliseconds (clamped service-side to 4h). Ignored when
    /// `enabled = false` or `until_restart = true`.
    #[serde(default)]
    pub duration_ms: Option<i64>,
    /// No expiry — active until the service restarts. Overrides `duration_ms`.
    #[serde(default)]
    pub until_restart: bool,
    /// Scope slug (`all` by default).
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DiagnosticsExportArchiveResponse {
    /// Absolute path to the freshly-written zip. Lives under the
    /// service's per-user `archives/` directory and inherits the
    /// `Users:RX` ACL applied to that directory.
    pub archive_path: String,
    /// Size of the archive in bytes. Surface in the GUI confirmation
    /// toast so the operator knows roughly what was produced.
    pub size_bytes: u64,
    /// UTC milliseconds when the archive was finalised. Allows the GUI
    /// to format a friendly timestamp without a second IPC roundtrip.
    pub generated_at_ms: i64,
    /// The log cutoff the service ACTUALLY applied. For a
    /// session-only export the service narrows the request's midnight-floor
    /// cutoff to the start of the current service session — the latest
    /// service start that followed at least thirty minutes of downtime —
    /// and echoes the result here so the launcher trims its raw log
    /// attachments to the same window. `None` = full-history export
    /// (additive; older peers are unaffected).
    #[serde(default)]
    pub logs_from_ms_effective: Option<i64>,
}
