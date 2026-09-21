//! IPC handlers for the diagnostics operations
//! (`ExplainGet`, `DiagnosticsExportArchive`).
//!
//! Both handlers consume the production `DiagnosticsFacade` trait
//! object wired in `runtime_deps.rs`. The facade itself is shared
//! across multiple handlers (snapshot + logs + audit + alerts) — see
//! `IpcHandlerDeps.diagnostics`.
//!
//! ## ExplainGetHandler
//!
//! Maps wire `ExplainGetRequest` (decision_id OR input_sample +
//! optional detail_level) into the in-process `ExplainQuery` /
//! `ExplainDetailLevel` types, calls `DiagnosticsFacade::get_explain`,
//! and projects the resulting `ExplainResponse` into the wire
//! `ExplainGetResponse` shape (compact view + full passthrough).
//!
//! Both-fields-set or neither-set requests are rejected at the
//! handler boundary as `MalformedRequest` so the facade only sees
//! exactly one variant.
//!
//! ## DiagnosticsExportArchiveHandler
//!
//! Builds a zip archive via `nrr_diagnostics::archive::ArchiveBuilder`
//! using data collected from the facade (health snapshot, log + audit
//! pages). Writes the result to the per-user `archives/` directory
//! (sibling of `logs/` and `audit/`, closed to ordinary users like the rest
//! of the tree — the finished file is then handed to its requester through
//! `FileHandoffPort`).
//! Returns the absolute path so the GUI can open the containing folder
//! in Explorer.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use nrr_diagnostics::archive::{
    builder::{ArchiveBuilder, ArchiveInput, AttachedLog},
    request::DiagnosticArchiveRequest,
};
use nrr_diagnostics::explain::{ExplainQuery, ExplainResponse, RuntimeInputSample};
use nrr_diagnostics::facade::dto::{
    ClearLogsRequest, DiagnosticArchiveHealthEnrichmentDto, SetDiagnosticModeRequest,
};
use nrr_diagnostics::facade::pagination::{PaginationParams, MAX_PAGE_SIZE};
use nrr_diagnostics::facade::service::DiagnosticsFacade;
use nrr_diagnostics::privacy::mode::RedactionMode;
use nrr_diagnostics::privacy::redact::{redact_hostname, redact_ipv4_str};
use nrr_diagnostics::redaction::ExplainDetailLevel;
use nrr_domain::decision_explain::DecisionId;
use nrr_shared::ipc_payloads::{
    CacheClearRequest, CacheClearResponse, CacheEntriesListRequest, CacheEntriesListResponse,
    CacheEntryDto, ConnTraceEntriesListRequest, ConnTraceEntriesListResponse, ConnTraceEntryDto,
    DiagnosticModeSetRequest, DiagnosticsExportArchiveRequest, DiagnosticsExportArchiveResponse,
    ExplainCompactViewDto, ExplainGetRequest, ExplainGetResponse, LogsClearRequest,
    LogsClearResponse,
};
use nrr_shared::pagination::{PageCursor, PageResult};
use nrr_storage::dto::CacheResetReason;
use nrr_storage::repository::CacheRepository;

use crate::conn_observation_consumer::{proto_str, role_str, verdict_str, ConnectionTraceRing};
use crate::dns_observation_consumer::{
    build_secondary_ip_owners, rule_set_match_kind, rule_set_matches, ActiveSidFn,
};
use crate::fqdn_cache_lookup::FqdnCacheLookup;
use crate::ipc_handlers::providers::{
    AdaptersSnapshotProvider, RoutePolicyProvider, ServiceStabilityConfigProvider,
};
use crate::per_sid_orchestrator::RulesProvider;

/// Inputs for the conn-trace `expected_route` stamp: the active
/// user's rule book + the FQDN cache + the routing-active-SID resolver.
pub type ConnTraceExpectation = (
    Arc<dyn RulesProvider>,
    Arc<dyn FqdnCacheLookup>,
    ActiveSidFn,
);

use crate::ipc::DiagnosticsAudience;
use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};

fn malformed(op: &'static str, e: serde_json::Error) -> IpcError {
    IpcError {
        code: IpcErrorCode::MalformedRequest,
        message: format!("{op} payload invalid: {e}"),
        diagnostics_id: None,
    }
}

fn malformed_msg(op: &'static str, msg: impl Into<String>) -> IpcError {
    IpcError {
        code: IpcErrorCode::MalformedRequest,
        message: format!("{op}: {}", msg.into()),
        diagnostics_id: None,
    }
}

fn internal(op: &'static str, msg: impl Into<String>) -> IpcError {
    IpcError {
        code: IpcErrorCode::Internal,
        message: format!("{op}: {}", msg.into()),
        diagnostics_id: None,
    }
}

fn serialise(op: &'static str, value: impl serde::Serialize) -> HandlerOutcome {
    serde_json::to_value(value).map_err(|e| internal(op, format!("response serialisation: {e}")))
}

fn millis_since_epoch() -> i64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn system_time_to_ms(t: SystemTime) -> i64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ── ExplainGetHandler ────────────────────────────────────────────────────────

/// Dependency triple for the kill-switch enforcement
/// verdict: per-SID policy reader + FQDN-cache presence + active SID.
pub type ExplainEnforcementDeps = (
    Arc<dyn crate::ipc_handlers::providers::RoutePolicyProvider>,
    Arc<dyn crate::fqdn_cache_lookup::FqdnCacheLookup>,
    crate::dns_observation_consumer::ActiveSidFn,
);

pub struct ExplainGetHandler {
    diagnostics: Arc<dyn DiagnosticsFacade>,
    /// Optional inputs for the kill-switch enforcement
    /// verdict stamped onto the compact view. All-or-nothing: absent deps
    /// leave `compact.enforcement` empty (rule verdict only), matching every
    /// existing test/mock construction.
    enforcement: Option<ExplainEnforcementDeps>,
    /// Read-only view of the live hostname → fake-address (fake-IP)
    /// map so a synthetic hostname probe shows the virtual address the
    /// resolver is answering with. `None` (default) leaves the field empty.
    fake_ip: Option<crate::fake_ip::FakeIpBindingView>,
}

impl ExplainGetHandler {
    pub fn new(diagnostics: Arc<dyn DiagnosticsFacade>) -> Self {
        Self {
            diagnostics,
            enforcement: None,
            fake_ip: None,
        }
    }

    /// Enable the enforcement verdict (see the field doc).
    pub fn with_enforcement_verdict(
        mut self,
        policy: Arc<dyn crate::ipc_handlers::providers::RoutePolicyProvider>,
        fqdn: Arc<dyn crate::fqdn_cache_lookup::FqdnCacheLookup>,
        active_sid: crate::dns_observation_consumer::ActiveSidFn,
    ) -> Self {
        self.enforcement = Some((policy, fqdn, active_sid));
        self
    }

    /// Enable the fake-address (fake-IP) stamp (see the field doc).
    pub fn with_fake_ip_bindings(mut self, view: crate::fake_ip::FakeIpBindingView) -> Self {
        self.fake_ip = Some(view);
        self
    }

    /// The kill-switch verdict for a SYNTHETIC hostname probe, on top of the
    /// rule verdict (`route`). Config-based — deliberately independent of the
    /// live armed/disarmed runtime state, so the answer explains what the
    /// CURRENT SETTINGS do to this host whenever the switch arms:
    /// - kill-switch ON + coverage `fail-closed-unknown` (block-all) + the
    ///   hostname has NO cached IPs → no permit can compile → while armed the
    ///   catch-all drops it, even though the rule verdict says primary/none;
    /// - secondary-routed host + kill-switch ON → while the secondary is down
    ///   the fail-closed block holds it (never leaks via primary);
    /// - a primary/default host whose cached IPs the shared-IP census flags
    ///   (shared with secondary rules): under the strict policy those IPs are
    ///   pinned/blocked, under smart they are exempted (host works, leak
    ///   possible). Returns `(slug, shared_ip_count, total_ip_count)`; the
    ///   counts are non-zero only for the collateral slugs.
    fn enforcement_verdict(&self, hostname: &str, route: &str) -> (String, u32, u32) {
        let none = (String::new(), 0, 0);
        let Some((policy, fqdn, active_sid)) = self.enforcement.as_ref() else {
            return none;
        };
        if hostname.is_empty() {
            return none;
        }
        let Some(sid) = active_sid() else {
            return none;
        };
        let Some(dto) = policy.get_for_sid(&sid) else {
            return none;
        };
        if !dto.kill_switch_enabled {
            return none;
        }
        if route == "secondary" {
            return ("fail-closed-when-secondary-down".to_string(), 0, 0);
        }
        let cached_ips = fqdn.ips_for_hostname(hostname);
        let block_all_unknown = dto.mode_a_coverage_strategy == "fail-closed-unknown";
        if block_all_unknown && cached_ips.is_empty() {
            return ("blocked-unknown-under-block-all".to_string(), 0, 0);
        }
        // Shared-IP collateral for a primary/default host. The census
        // holds exactly the IPs that are BOTH secondary-owned and seen on a
        // direct host, so an intersection with this host's cached IPs is the
        // collateral set.
        if !cached_ips.is_empty() {
            let census = fqdn.shared_direct_ips();
            let shared = cached_ips
                .iter()
                .filter_map(|ip| match ip {
                    std::net::IpAddr::V4(v4) => Some(v4),
                    std::net::IpAddr::V6(_) => None,
                })
                .filter(|ip| census.contains(ip))
                .count() as u32;
            if shared > 0 {
                let slug = if dto.kill_switch_strict_shared_ips {
                    // Strict: these IPs stay pinned → blocked whenever the
                    // secondary is down.
                    "collateral-blocked-strict"
                } else {
                    // Smart (default): exempted from the kill-switch → the
                    // host keeps working, at the cost of unprotected
                    // secondary-rule traffic on those IPs.
                    "collateral-smart-exempt"
                };
                return (slug.to_string(), shared, cached_ips.len() as u32);
            }
        } else if !fqdn
            .hostnames_under_suffix(hostname, RISK_SUBDOMAIN_PROBE_LIMIT)
            .is_empty()
        {
            // Host itself is un-cached (never matches a rule — e.g. bare
            // search.example), but rule-cached subdomains exist under it
            // (gemini.search.example). Same-front-end CDNs serve both from one IP
            // pool, so collateral is likely even before it is observed.
            return ("collateral-risk-subdomain-rules".to_string(), 0, 0);
        }
        none
    }
}

/// How many cached subdomains are enough to call a probe host
/// "collateral at risk" (1 suffices; the tiny cap keeps the probe cheap).
const RISK_SUBDOMAIN_PROBE_LIMIT: usize = 4;

impl IpcHandler for ExplainGetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        const OP: &str = "diagnostics.explain.get";
        let req: ExplainGetRequest =
            serde_json::from_value(request.payload.clone()).map_err(|e| malformed(OP, e))?;

        // Discriminate the two variants. Ambiguity is treated as
        // structural malformation — defensive boundary check before
        // the facade.
        let query = match (req.decision_id.as_deref(), req.input_sample.as_ref()) {
            (None, None) => {
                return Err(malformed_msg(
                    OP,
                    "request must carry exactly one of decision-id / input-sample",
                ));
            }
            (Some(_), Some(_)) => {
                return Err(malformed_msg(
                    OP,
                    "request must NOT set both decision-id and input-sample",
                ));
            }
            (Some(id), None) => {
                if id.is_empty() {
                    return Err(malformed_msg(OP, "decision-id must not be empty"));
                }
                ExplainQuery::HistoricalDecision {
                    decision_id: DecisionId(id.to_string()),
                }
            }
            (None, Some(sample)) => {
                let mut input = RuntimeInputSample::new();
                if let Some(h) = sample.hostname.clone() {
                    input = input.with_hostname(h);
                }
                if let Some(ip) = sample.observed_ip.clone() {
                    input = input.with_ip(ip);
                }
                if let Some(p) = sample.process_name.clone() {
                    input = input.with_process(p);
                }
                ExplainQuery::Synthetic {
                    input_sample: input,
                }
            }
        };

        let level = parse_detail_level(req.detail_level.as_deref());
        // Pass the caller SID so the synthetic probe applies that user's
        // per-SID behavior_mode.
        let response = self
            .diagnostics
            .get_explain(&query, level, ctx.caller_stored())
            .map_err(|e| internal(OP, format!("facade.get_explain: {e}")))?;

        let mut compact = compact_view(&response);
        // Synthetic hostname probes additionally carry the kill-switch
        // verdict, so "primary" never hides "but block-all will drop this".
        if let ExplainQuery::Synthetic { input_sample } = &query {
            if let Some(host) = input_sample.hostname.as_deref() {
                let (slug, shared, total) = self.enforcement_verdict(host, &compact.route);
                compact.enforcement = slug;
                compact.enforcement_shared_ips = shared;
                compact.enforcement_total_ips = total;
                // The virtual address the resolver currently answers for
                // this host (fake-IP active), so "why 198.18.x.x?" is
                // explained in place. Read-only lookup, empty when unmapped.
                compact.fake_ip = self
                    .fake_ip
                    .as_ref()
                    .and_then(|v| v.fake_v4_for(host))
                    .map(|ip| ip.to_string())
                    .unwrap_or_default();
            }
        }
        let full = serde_json::to_value(&response)
            .map_err(|e| internal(OP, format!("explain response serialise: {e}")))?;

        let wire = ExplainGetResponse {
            compact,
            full,
            // diagnostic_ids enrichment via audit-log lookup is not yet
            // wired. The wire field stays — empty vector serialises as an
            // omitted field thanks to `skip_serializing_if = "Vec::is_empty"`.
            diagnostic_ids: Vec::new(),
        };
        serialise(OP, &wire)
    }
}

fn parse_detail_level(slug: Option<&str>) -> ExplainDetailLevel {
    match slug {
        Some("diagnostics") => ExplainDetailLevel::Diagnostics,
        Some("developer-trace") | Some("developer_trace") => ExplainDetailLevel::DeveloperTrace,
        _ => ExplainDetailLevel::CompactUi,
    }
}

/// Project the full `ExplainResponse` into the 3-field compact view
/// the diagnostics section's "explain sample" widget renders today
/// (input → route + reason key). The full response is shipped
/// alongside for future detail surfaces.
fn compact_view(response: &ExplainResponse) -> ExplainCompactViewDto {
    let input = response
        .input
        .as_ref()
        .and_then(|i| {
            i.destination_hostname
                .clone()
                .or_else(|| i.destination_ip.clone())
                .or_else(|| i.process_name.clone())
        })
        .unwrap_or_else(|| "-".to_string());

    let route = response
        .final_action_section
        .as_ref()
        .map(|f| {
            f.route_role
                .clone()
                .unwrap_or_else(|| match f.action_key.as_str() {
                    k if k.contains("block") => "blocked".to_string(),
                    _ => "none".to_string(),
                })
        })
        .unwrap_or_else(|| "none".to_string());

    let reason_key = response
        .final_action_section
        .as_ref()
        .map(|f| f.reason_key.clone())
        .unwrap_or_else(|| response.summary.summary_key.clone());

    ExplainCompactViewDto {
        input,
        route,
        reason_key,
        // Stamped by the handler for synthetic hostname probes (needs the
        // policy/cache deps the pure projection does not have).
        enforcement: String::new(),
        enforcement_shared_ips: 0,
        enforcement_total_ips: 0,
        fake_ip: String::new(),
    }
}

// ── LogsClearHandler ─────────────────────────────────────────────────────────

/// Forwards the wire `LogsClearRequest` to
/// `DiagnosticsFacade::clear_logs`. Audit trail is NEVER affected —
/// the facade contract documents this invariant.
pub struct LogsClearHandler {
    diagnostics: Arc<dyn DiagnosticsFacade>,
}

impl LogsClearHandler {
    pub fn new(diagnostics: Arc<dyn DiagnosticsFacade>) -> Self {
        Self { diagnostics }
    }
}

impl IpcHandler for LogsClearHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        const OP: &str = "logs.clear";
        let req: LogsClearRequest =
            serde_json::from_value(request.payload.clone()).map_err(|e| malformed(OP, e))?;
        let facade_req = ClearLogsRequest {
            include_archives: req.include_archives,
            dry_run: req.dry_run,
        };
        let result = self
            .diagnostics
            .clear_logs(&facade_req)
            .map_err(|e| internal(OP, format!("facade.clear_logs: {e}")))?;
        let response = LogsClearResponse {
            files_deleted: u64::from(result.files_deleted),
            bytes_freed: result.bytes_freed,
            dry_run: result.dry_run,
        };
        serialise(OP, &response)
    }
}

// ── DiagnosticModeSetHandler ──────────────────────────────────────────────

/// Enable/disable extended diagnostics for a bounded
/// in-memory session. Forwards to `DiagnosticsFacade::set_diagnostic_mode`
/// and echoes back the resulting `diagnostic_mode` state so the panel
/// renders authoritative data. Enabling immediately unredacts the cache +
/// connection-trace viewers (they read the SAME shared facade). Facade
/// always present → no dep gate.
pub struct DiagnosticModeSetHandler {
    diagnostics: Arc<dyn DiagnosticsFacade>,
}

impl DiagnosticModeSetHandler {
    pub fn new(diagnostics: Arc<dyn DiagnosticsFacade>) -> Self {
        Self { diagnostics }
    }
}

impl IpcHandler for DiagnosticModeSetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        const OP: &str = "diagnostics.mode.set";
        let req: DiagnosticModeSetRequest = if request.payload.is_null() {
            DiagnosticModeSetRequest::default()
        } else {
            serde_json::from_value(request.payload.clone()).map_err(|e| malformed(OP, e))?
        };
        let facade_req = SetDiagnosticModeRequest {
            enabled: req.enabled,
            duration_ms: req.duration_ms,
            scope: req.scope,
            until_restart: req.until_restart,
        };
        self.diagnostics
            .set_diagnostic_mode(&facade_req)
            .map_err(|e| internal(OP, format!("facade.set_diagnostic_mode: {e}")))?;
        // Authoritative echo of the resulting session state.
        let state = self.diagnostics.get_status().diagnostic_mode;
        serialise(OP, &state)
    }
}

// ── CacheClearHandler ────────────────────────────────────────────────────────

/// Clears the rebuildable FQDN/IP resolution cache on
/// explicit user request by forwarding to `CacheRepository::clear_cache`
/// (`CacheResetReason::ManualUserReset`). The audit / service-state DBs are
/// never touched. A `dry-run` request routes to `get_cache_stats` and reports
/// the counts that WOULD be removed without deleting anything.
///
/// The GUI splits "Clear cache" into two buttons. The app's SQLite
/// cache is cleared only when `clear_app_cache` (default `true`); the OS
/// resolver cache is flushed only when `flush_os_cache` is set, via the
/// injected [`DnsCacheControlPort`] (the same mechanism the boot / block-all
/// edges use). A request may target either or both.
pub struct CacheClearHandler {
    cache: Arc<Mutex<dyn CacheRepository + Send>>,
    /// OS resolver-cache flush mechanism. `None` (no port wired,
    /// e.g. non-Windows or degraded boot) makes a `flush_os_cache` request
    /// report `os_cache_flushed = Some(false)` rather than error.
    dns_cache_control: Option<Arc<dyn nrr_platform_api::dns::DnsCacheControlPort>>,
}

impl CacheClearHandler {
    pub fn new(cache: Arc<Mutex<dyn CacheRepository + Send>>) -> Self {
        Self {
            cache,
            dns_cache_control: None,
        }
    }

    /// Attach the OS resolver-cache flush port so a `flush_os_cache`
    /// request actually flushes. Without it the flush branch reports failure.
    pub fn with_dns_cache_control(
        mut self,
        port: Arc<dyn nrr_platform_api::dns::DnsCacheControlPort>,
    ) -> Self {
        self.dns_cache_control = Some(port);
        self
    }
}

impl IpcHandler for CacheClearHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        const OP: &str = "cache.clear";
        let req: CacheClearRequest =
            serde_json::from_value(request.payload.clone()).map_err(|e| malformed(OP, e))?;

        // App SQLite cache — cleared / counted only when requested.
        let (resolutions_removed, negative_cache_removed) = if req.clear_app_cache {
            let cache = self
                .cache
                .lock()
                .map_err(|e| internal(OP, format!("cache mutex poisoned: {e}")))?;
            if req.dry_run {
                let stats = cache
                    .get_cache_stats()
                    .map_err(|e| internal(OP, format!("get_cache_stats: {e}")))?;
                (stats.resolution_count, stats.negative_cache_count)
            } else {
                let summary = cache
                    .clear_cache(CacheResetReason::ManualUserReset)
                    .map_err(|e| internal(OP, format!("clear_cache: {e}")))?;
                (summary.resolutions_removed, summary.negative_cache_removed)
            }
        } else {
            (0, 0)
        };

        // OS resolver cache — flushed only when requested and never on a dry
        // run. `Some(true)` flushed, `Some(false)` requested but no port / flush
        // failed, `None` not requested.
        let os_cache_flushed = if req.flush_os_cache && !req.dry_run {
            match self.dns_cache_control.as_ref() {
                Some(port) => Some(port.flush_resolver_cache().is_ok()),
                None => Some(false),
            }
        } else if req.flush_os_cache {
            // Dry run: report intent without acting.
            Some(false)
        } else {
            None
        };

        serialise(
            OP,
            &CacheClearResponse {
                resolutions_removed,
                negative_cache_removed,
                dry_run: req.dry_run,
                os_cache_flushed,
            },
        )
    }
}

// ── CacheEntriesListHandler ──────────────────────────────────────────────────

/// Read-only, paginated view of the FQDN/IP resolution cache
/// (Diagnostics → Cache → "Show cache entries"). Forwards to
/// `CacheRepository::list_resolutions` and projects the rows into
/// [`CacheEntryDto`]s.
///
/// **Redaction.** Detail is gated by the active diagnostic mode, read from
/// `DiagnosticsFacade::get_status().diagnostic_mode.active` — the same
/// signal that drives `DiagnosticRedactionLevel` elsewhere. When diagnostic
/// mode is OFF (the compact tier, `RedactionMode::Default`) hostnames are
/// reduced to their registrable domain (eTLD+1) and IPs are replaced with a
/// `<private-ipv4>` / `<public-ipv4>` marker via the shared `redact_*`
/// helpers — raw hostnames/IPs never leave the service. When diagnostic mode
/// is ON the full values are surfaced. The `redacted` response flag lets the
/// GUI show a "enable diagnostic mode for full detail" notice.
///
/// Offset paging is carried through the shared cursor: the handler decodes
/// the next offset from `pagination.cursor` and re-encodes `offset + limit`
/// into `next_cursor` when a further page exists (the storage query fetches
/// `limit + 1` rows so the presence of a next page is exact).
pub struct CacheEntriesListHandler {
    cache: Arc<Mutex<dyn CacheRepository + Send>>,
    /// Optional inputs for the `expected_route` stamp (same tuple
    /// as the conn-trace handler): the active user's rule book decides where
    /// each cached hostname WOULD be routed. All-or-nothing: absent deps
    /// leave the field empty.
    expectation: Option<ConnTraceExpectation>,
    /// Read-only view of the live hostname → fake-address (fake-IP)
    /// map, so each row can show the virtual address next to the real one.
    /// `None` (default) leaves the field empty (fake-IP not wired / off).
    fake_ip: Option<crate::fake_ip::FakeIpBindingView>,
}

impl CacheEntriesListHandler {
    pub fn new(cache: Arc<Mutex<dyn CacheRepository + Send>>) -> Self {
        Self {
            cache,
            expectation: None,
            fake_ip: None,
        }
    }

    /// Enable the expected-route stamp (see the struct field doc).
    pub fn with_route_expectation(
        mut self,
        rules: Arc<dyn RulesProvider>,
        fqdn: Arc<dyn FqdnCacheLookup>,
        active_sid: ActiveSidFn,
    ) -> Self {
        self.expectation = Some((rules, fqdn, active_sid));
        self
    }

    /// Enable the fake-address (fake-IP) stamp (see the field doc).
    pub fn with_fake_ip_bindings(mut self, view: crate::fake_ip::FakeIpBindingView) -> Self {
        self.fake_ip = Some(view);
        self
    }

    /// The active user's rule book plus the secondary-owned IPv4 set, or
    /// `None` when the expectation deps are absent / no user is
    /// routing-active. Built once per page request, never per row.
    ///
    /// NOTE: name matching uses the RAW rule book (no `include_subdomains`
    /// coverage expansion) — consistent with the conn-trace stamp; the
    /// IP-owner fallback catches shared-IP collateral either way.
    fn route_expectation(
        &self,
    ) -> Option<(
        crate::per_sid_orchestrator::ActiveRulesSnapshot,
        std::collections::HashSet<std::net::Ipv4Addr>,
    )> {
        let (rules, fqdn, active_sid) = self.expectation.as_ref()?;
        let sid = active_sid()?;
        let snapshot = rules.active_rules_for(&sid)?;
        let owned = build_secondary_ip_owners(&snapshot.rule_book.secondary, fqdn.as_ref())
            .into_keys()
            .collect();
        Some((snapshot, owned))
    }
}

impl IpcHandler for CacheEntriesListHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        const OP: &str = "cache.entries.list";
        let req: CacheEntriesListRequest = if request.payload.is_null() {
            CacheEntriesListRequest::default()
        } else {
            serde_json::from_value(request.payload.clone()).map_err(|e| malformed(OP, e))?
        };

        // The cache viewer is a LOCAL, on-screen inspector of the
        // user's OWN machine — it shows the real resolved hostnames and IPs so
        // the user can see exactly what is cached and SEARCH by IP. (The compact
        // redaction tier still governs diagnostics EXPORTS / archives, which are
        // a separate code path.)
        let mode = RedactionMode::Diagnostics;

        let limit = req.pagination.effective_page_size();
        let offset = req
            .pagination
            .cursor
            .as_ref()
            .and_then(|c| c.parse())
            .map(|(o, _)| o.max(0) as u32)
            .unwrap_or(0);

        let (rows, total_count) = {
            let cache = self
                .cache
                .lock()
                .map_err(|e| internal(OP, format!("cache mutex poisoned: {e}")))?;
            let rows = cache
                .list_resolutions(offset, limit, req.query.trim())
                .map_err(|e| internal(OP, format!("list_resolutions: {e}")))?;
            // Live total so the GUI count reflects the REAL service cache, not a
            // frozen cold-start snapshot (the mock backend reported a fixed 24
            // when the GUI started before the service was up).
            let total = cache.get_cache_stats().map(|s| s.resolution_count).ok();
            (rows, total)
        };

        // Rule-book + secondary-owned IPv4 set, built ONCE per page.
        // Stamps each row with where policy WOULD route the host: a secondary
        // name-match (or secondary-owned IP — shared-IP collateral) wins over
        // a primary name-match; no match leaves the field empty.
        let expectation = self.route_expectation();
        let expected_route = |hostname: &str, ip: &str| -> String {
            let Some((snapshot, owned)) = expectation.as_ref() else {
                return String::new();
            };
            if rule_set_matches(hostname, &snapshot.rule_book.secondary) {
                return "secondary".to_string();
            }
            if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
                if owned.contains(&v4) {
                    return "secondary".to_string();
                }
            }
            if rule_set_matches(hostname, &snapshot.rule_book.primary) {
                return "primary".to_string();
            }
            String::new()
        };
        // Match-kind stamp for the cache viewer's
        // "direct rules above zones" ordering. Secondary set wins ties with
        // primary (mirrors `expected_route` above); the shared-IP collateral
        // path carries no address rule and stays empty by design.
        let rule_match_kind = |hostname: &str, ip: &str| -> String {
            let Some((snapshot, _)) = expectation.as_ref() else {
                return String::new();
            };
            let v4 = ip.parse::<std::net::Ipv4Addr>().ok();
            rule_set_match_kind(hostname, v4, &snapshot.rule_book.secondary)
                .or_else(|| rule_set_match_kind(hostname, v4, &snapshot.rule_book.primary))
                .unwrap_or_default()
                .to_string()
        };

        // The storage layer fetched `limit + 1` rows; the extra row (if
        // present) means another page exists. Keep only `limit` for display.
        let has_more = rows.len() as u32 > limit;
        let items: Vec<CacheEntryDto> = rows
            .into_iter()
            .take(limit as usize)
            .map(|row| CacheEntryDto {
                // Stamp from the RAW values (pre-redaction) so the expectation
                // is derived from the real hostname/IP.
                expected_route: expected_route(&row.canonical_hostname, &row.canonical_ip),
                rule_match_kind: rule_match_kind(&row.canonical_hostname, &row.canonical_ip),
                // The virtual address currently answering for this
                // host (fake-IP), empty when off/unmapped. Read-only lookup.
                fake_ip: self
                    .fake_ip
                    .as_ref()
                    .and_then(|v| v.fake_v4_for(&row.canonical_hostname))
                    .map(|ip| ip.to_string())
                    .unwrap_or_default(),
                hostname: redact_hostname(&row.canonical_hostname, mode).display_or_marker(),
                ip: redact_ipv4_str(&row.canonical_ip, mode).display_or_marker(),
                freshness: row.freshness_state,
                source: row.source,
                resolved_at_ms: system_time_to_ms(row.resolved_at),
                expires_at_ms: system_time_to_ms(row.expires_at),
            })
            .collect();

        let next_cursor = if has_more {
            Some(PageCursor::from_position(
                i64::from(offset) + i64::from(limit),
                "cache",
            ))
        } else {
            None
        };

        let response = CacheEntriesListResponse {
            page: PageResult {
                items,
                next_cursor,
                total_count,
                stale: false,
            },
            redacted: false,
        };
        serialise(OP, &response)
    }
}

// ── ConnTraceEntriesListHandler ───────────────────────────────────────────

/// Read-only, paginated view of the connection-trace ring the
/// connection-observer feeds. Mirrors [`CacheEntriesListHandler`]: same
/// pagination cursor. The local own-machine viewer is never redacted (real
/// remote/local IPs + full exe path), so it does not need the diagnostics
/// facade for a redaction tier.
pub struct ConnTraceEntriesListHandler {
    ring: Arc<ConnectionTraceRing>,
    /// Machine settings, consulted per request so the "show the trace in the
    /// GUI" switch acts at once instead of at the next service start. It gates
    /// the ANSWER, never the observer: app-routing, FCrDNS learning and the
    /// VPN learners read the same observation stream and must keep running.
    gui_stream: Option<Arc<dyn ServiceStabilityConfigProvider>>,
    /// Optional inputs for the `expected_route` stamp: the active
    /// user's rule book + the FQDN cache yield the set of IPv4s a secondary
    /// rule currently owns, so each trace row can carry where policy EXPECTS
    /// it to egress. All-or-nothing: absent deps simply leave the field empty.
    expectation: Option<ConnTraceExpectation>,
}

impl ConnTraceEntriesListHandler {
    pub fn new(ring: Arc<ConnectionTraceRing>) -> Self {
        Self {
            ring,
            gui_stream: None,
            expectation: None,
        }
    }

    /// Honour the user's "show connection trace in the GUI" switch. Without
    /// this the viewer answers regardless of the setting.
    pub fn with_gui_stream_gate(
        mut self,
        settings: Arc<dyn ServiceStabilityConfigProvider>,
    ) -> Self {
        self.gui_stream = Some(settings);
        self
    }

    /// Whether the viewer may answer at all. An absent provider means the
    /// deployment has no settings DB — answering is then the useful default.
    fn gui_stream_enabled(&self) -> bool {
        self.gui_stream
            .as_ref()
            .map(|s| s.get().conn_trace_gui)
            .unwrap_or(true)
    }

    /// Enable the expected-route stamp (see the struct field doc).
    pub fn with_route_expectation(
        mut self,
        rules: Arc<dyn RulesProvider>,
        fqdn: Arc<dyn FqdnCacheLookup>,
        active_sid: ActiveSidFn,
    ) -> Self {
        self.expectation = Some((rules, fqdn, active_sid));
        self
    }

    /// The secondary-owned IPv4 set for the active user, or `None` when the
    /// expectation deps are absent / no user is routing-active. Built once per
    /// page request (bounded by the owners fan-out cap), never per row.
    fn secondary_owned_ips(&self) -> Option<std::collections::HashMap<std::net::Ipv4Addr, String>> {
        let (rules, fqdn, active_sid) = self.expectation.as_ref()?;
        let sid = active_sid()?;
        let snapshot = rules.active_rules_for(&sid)?;
        Some(build_secondary_ip_owners(
            &snapshot.rule_book.secondary,
            fqdn.as_ref(),
        ))
    }
}

/// True when the trace row belongs to our own service process. The fake-IP
/// relay dials the real destination from here, so such a row is traffic carried
/// for an application, not the service's own errand.
fn is_own_service(process: &str) -> bool {
    let service = nrr_shared::product_identity::BinaryRole::Service;
    [service.windows_file_name(), service.unix_file_name()]
        .iter()
        .any(|name| process.eq_ignore_ascii_case(name))
}

/// Executable name from a device/NT path (`\device\…\chrome.exe` → `chrome.exe`).
fn exe_name(path: Option<&str>) -> String {
    match path {
        Some(p) => p
            .rsplit(['\\', '/'])
            .find(|s| !s.is_empty())
            .unwrap_or(p)
            .to_string(),
        None => "?".to_string(),
    }
}

impl IpcHandler for ConnTraceEntriesListHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        const OP: &str = "conn-trace.entries.list";
        let req: ConnTraceEntriesListRequest = if request.payload.is_null() {
            ConnTraceEntriesListRequest::default()
        } else {
            serde_json::from_value(request.payload.clone()).map_err(|e| malformed(OP, e))?
        };

        // The switch is off: answer with an empty page and say why, rather
        // than with rows the user asked not to be shown.
        if !self.gui_stream_enabled() {
            return serialise(
                OP,
                &ConnTraceEntriesListResponse {
                    page: PageResult {
                        items: Vec::new(),
                        next_cursor: None,
                        total_count: None,
                        stale: false,
                    },
                    redacted: false,
                    observer_active: self.ring.observer_active(),
                    gui_stream_enabled: false,
                },
            );
        }

        // This is the user's own-machine connection viewer (per-SID,
        // DACL-protected local pipe), so show real remote/local IPs and the
        // full exe path, exactly like the cache viewer. The user needs to see
        // WHICH IP an app reached; masking it to `<public-ipv4>` defeats the
        // panel. Not gated on a diagnostic session for the same reason the
        // cache viewer is not.
        let mode = RedactionMode::Diagnostics;

        let limit = req.pagination.effective_page_size();
        let offset = req
            .pagination
            .cursor
            .as_ref()
            .and_then(|c| c.parse())
            .map(|(o, _)| o.max(0) as u32)
            .unwrap_or(0);

        // Newest-first; fetch `limit + 1` so the extra row signals another page.
        let (rows, _total) = self.ring.snapshot(offset as usize, limit as usize + 1);
        let has_more = rows.len() as u32 > limit;

        let fmt_addr = |sa: &std::net::SocketAddr| -> String {
            let ip = redact_ipv4_str(&sa.ip().to_string(), mode).display_or_marker();
            format!("{ip}:{}", sa.port())
        };

        // The secondary-owned IPv4 set, built ONCE per page. A row
        // whose remote is in this set is EXPECTED to egress the secondary link;
        // the GUI flags expected=secondary + egress=primary permits as leaks.
        let secondary_owned = self.secondary_owned_ips();
        // The same map answers both questions: whether policy expects this
        // remote on the secondary link, and — for a flow the service itself
        // opened — whose traffic it is carrying.
        let owner_of = |remote: &std::net::SocketAddr| -> Option<&String> {
            match (remote.ip(), secondary_owned.as_ref()) {
                (std::net::IpAddr::V4(v4), Some(owned)) => owned.get(&v4),
                _ => None,
            }
        };
        let expected_route = |remote: &std::net::SocketAddr| -> String {
            match owner_of(remote) {
                Some(_) => "secondary".to_string(),
                // An IPv6 remote is not "no rule covers it" — no rule CAN, the
                // family is not routed in this edition. Say which of the two it
                // is instead of letting the row read as an uncovered host.
                None if remote.is_ipv6() => "ipv6".to_string(),
                None => String::new(),
            }
        };

        let items: Vec<ConnTraceEntryDto> = rows
            .into_iter()
            .take(limit as usize)
            .map(|r| ConnTraceEntryDto {
                relay_for: match owner_of(&r.remote) {
                    Some(host) if is_own_service(&exe_name(r.process_path.as_deref())) => {
                        host.clone()
                    }
                    _ => String::new(),
                },
                process: exe_name(r.process_path.as_deref()),
                process_path: r.process_path.clone().unwrap_or_default(),
                proto: proto_str(r.protocol).to_string(),
                local: fmt_addr(&r.local),
                remote: fmt_addr(&r.remote),
                egress_role: role_str(r.egress.role).to_string(),
                egress_ifindex: r.egress.ifindex,
                verdict: verdict_str(r.verdict).to_string(),
                blocked_by: match r.blocked_by_nrr {
                    Some(true) => "netrulerouter".to_string(),
                    Some(false) => "other".to_string(),
                    None => String::new(),
                },
                block_reason: r.nrr_block_reason.unwrap_or_default().to_string(),
                rule_host: owner_of(&r.remote).cloned().unwrap_or_default(),
                expected_route: expected_route(&r.remote),
                observed_at_ms: r.observed_unix_ms.map(|v| v as i64).unwrap_or(0),
            })
            .collect();

        let next_cursor = if has_more {
            Some(PageCursor::from_position(
                i64::from(offset) + i64::from(limit),
                "conn-trace",
            ))
        } else {
            None
        };

        let response = ConnTraceEntriesListResponse {
            page: PageResult {
                items,
                next_cursor,
                total_count: None,
                stale: false,
            },
            // Never redacted: local own-machine viewer
            // shows real addresses (see the mode note above). The GUI's
            // "addresses masked" notice therefore stays hidden.
            redacted: false,
            observer_active: self.ring.observer_active(),
            gui_stream_enabled: true,
        };
        serialise(OP, &response)
    }
}

// ── DiagnosticsExportArchiveHandler ──────────────────────────────────────────

/// How many historical
/// decisions `explain_samples.json` samples, most-recently-observed first.
const MAX_EXPLAIN_SAMPLES: usize = 20;

pub struct DiagnosticsExportArchiveHandler {
    diagnostics: Arc<dyn DiagnosticsFacade>,
    /// Per-user destination directory for the zip archives. Sibling
    /// of `logs/` and `audit/`, and closed to ordinary users like the rest of
    /// the tree; `file_handoff` opens the finished file to its requester.
    archives_dir: PathBuf,
    /// App version string baked into the archive manifest.
    app_version: String,
    /// Host system info for `system_info.json`. Collected
    /// once at the composition root; `None` writes a minimal section.
    system_info: Option<nrr_shared::system_info::SystemInfo>,
    /// Adapters snapshot provider for `health.json`'s `adapters_snapshot`
    /// field. Same provider the `SnapshotInterfacesGet` handler uses.
    adapters: Arc<dyn AdaptersSnapshotProvider>,
    /// Per-SID route policy provider for `health.json`'s `behavior_mode`
    /// field.
    route_policy: Arc<dyn RoutePolicyProvider>,
    /// `nrr_service_state.db` schema version, read once at the composition
    /// root. `None` when the state DB connection was unavailable at startup
    /// (degraded boot).
    state_schema_version: Option<u32>,
    /// Grants the requesting principal read on the archive that was just
    /// written. The service's own tree is closed to ordinary users, so without
    /// this the export is a file its requester cannot open.
    file_handoff: Arc<dyn nrr_platform_api::file_handoff::FileHandoffPort>,
}

impl DiagnosticsExportArchiveHandler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        diagnostics: Arc<dyn DiagnosticsFacade>,
        archives_dir: PathBuf,
        app_version: String,
        system_info: Option<nrr_shared::system_info::SystemInfo>,
        adapters: Arc<dyn AdaptersSnapshotProvider>,
        route_policy: Arc<dyn RoutePolicyProvider>,
        state_schema_version: Option<u32>,
        file_handoff: Arc<dyn nrr_platform_api::file_handoff::FileHandoffPort>,
    ) -> Self {
        Self {
            diagnostics,
            archives_dir,
            app_version,
            system_info,
            adapters,
            route_policy,
            state_schema_version,
            file_handoff,
        }
    }

    /// Best-effort discovery of recent decision ids to seed
    /// `explain_samples.json`.
    ///
    /// Decision-id correlation is carried on operational LOG events
    /// (`EventCorrelation::decision_id`, surfaced as a `"decision:<id>"`
    /// token in `LogEntryDto.correlation_summary`) — the audit trail
    /// (`AuditEntryDto`) carries no decision correlation. Fetched
    /// independently of the wire request's `include_logs` flag (that flag
    /// only controls whether `logs.ndjson` ships in the archive; explain
    /// sampling is an internal need of the `explain_samples.json` section).
    ///
    /// `recent_log_entries` returns entries newest-first, so decision ids are
    /// already discovered most-recent-first — no tail walk needed. Bounded to
    /// the freshest [`MAX_PAGE_SIZE`] entries, so sampling stays on the most
    /// recent decisions rather than the stalest ones in the store. Never
    /// fails the caller — an unreadable log store yields an empty list.
    fn recent_decision_ids(&self, limit: usize, audience: &DiagnosticsAudience) -> Vec<String> {
        let entries = match self.diagnostics.recent_log_entries(
            &Default::default(),
            MAX_PAGE_SIZE as usize,
            audience,
        ) {
            Ok(items) => items,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::diagnostics",
                    error = %e,
                    "diagnostics.export-archive: recent_decision_ids: recent_log_entries failed",
                );
                return Vec::new();
            }
        };
        let mut ids: Vec<String> = Vec::new();
        for entry in entries.iter() {
            for token in &entry.correlation_summary {
                if let Some(id) = token.strip_prefix("decision:") {
                    if ids.len() >= limit {
                        return ids;
                    }
                    if !ids.iter().any(|existing| existing == id) {
                        ids.push(id.to_string());
                    }
                }
            }
        }
        ids
    }

    /// Real explain payloads for `explain_samples.json`. Runs
    /// `ExplainQuery::HistoricalDecision` through the SAME facade the
    /// `ExplainGet` IPC op uses, so the archive reflects whatever the facade
    /// actually knows about each decision (currently `DecisionNotFound` until
    /// a historical-replay snapshot store lands — see
    /// `ProductionDiagnosticsFacade::get_explain` — but the wiring itself is
    /// real, not a hardcoded stub). A facade error on one decision is skipped
    /// (logged), never aborts the whole archive.
    fn collect_explain_samples(
        &self,
        level: ExplainDetailLevel,
        caller_sid: &str,
        audience: &DiagnosticsAudience,
    ) -> Vec<ExplainResponse> {
        self.recent_decision_ids(MAX_EXPLAIN_SAMPLES, audience)
            .into_iter()
            .filter_map(|decision_id| {
                let query = ExplainQuery::HistoricalDecision {
                    decision_id: DecisionId(decision_id.clone()),
                };
                match self.diagnostics.get_explain(&query, level, caller_sid) {
                    Ok(response) => Some(response),
                    Err(e) => {
                        tracing::warn!(
                            target: "nrr::diagnostics",
                            decision_id = %decision_id,
                            error = %e,
                            "diagnostics.export-archive: skipping explain sample (facade error)",
                        );
                        None
                    }
                }
            })
            .collect()
    }

    /// The tail of a file in the service's log directory, or `None` when it is
    /// absent or unreadable. For what no structured log line stands in for: the
    /// captured stderr, where a panic lands on the way down, and the elevation
    /// broker's log.
    fn read_log_tail(&self, file_name: &str) -> Option<String> {
        /// Enough for a panic and its backtrace; the file is bounded by the
        /// capture itself, this only guards a pathological one.
        const MAX_BYTES: u64 = 256 * 1024;
        let logs_dir = self
            .archives_dir
            .parent()
            .map(|root| root.join("logs"))
            .unwrap_or_else(|| self.archives_dir.join("logs"));

        // Seek to the tail rather than reading the file and trimming after: a
        // cap enforced only after the whole file is in memory is no cap at all,
        // and this runs inside the service.
        use std::io::{Read, Seek, SeekFrom};
        let mut file = std::fs::File::open(logs_dir.join(file_name)).ok()?;
        let len = file.metadata().ok()?.len();
        if len > MAX_BYTES {
            file.seek(SeekFrom::Start(len - MAX_BYTES)).ok()?;
        }
        let mut bytes = Vec::with_capacity(MAX_BYTES.min(len) as usize);
        file.take(MAX_BYTES).read_to_end(&mut bytes).ok()?;

        // The seek can land mid-character; drop the partial head.
        let text = match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(e) => {
                let bytes = e.into_bytes();
                let start = bytes
                    .iter()
                    .position(|b| (*b as i8) >= -0x40)
                    .unwrap_or(bytes.len());
                String::from_utf8_lossy(&bytes[start..]).into_owned()
            }
        };
        Some(text)
    }

    /// `health.json` fields beyond the live status snapshot. Best-effort: a
    /// value that cannot be sourced at this call site stays `None` rather
    /// than being fabricated.
    fn collect_health_enrichment(&self, caller_sid: &str) -> DiagnosticArchiveHealthEnrichmentDto {
        let behavior_mode = self
            .route_policy
            .get_for_sid(caller_sid)
            .and_then(|policy| serde_json::to_value(policy.mode).ok())
            .and_then(|v| v.as_str().map(str::to_string));
        // `force_refresh = false` — the archive reads the adapter monitor's
        // current cached snapshot rather than forcing a synchronous
        // re-enumeration, keeping export latency independent of adapter
        // enumeration cost.
        let adapters_snapshot = Some(self.adapters.adapters_snapshot(false));
        DiagnosticArchiveHealthEnrichmentDto {
            behavior_mode,
            state_schema_version: self.state_schema_version,
            adapters_snapshot,
        }
    }
}

impl IpcHandler for DiagnosticsExportArchiveHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        const OP: &str = "diagnostics.export-archive";
        let req: DiagnosticsExportArchiveRequest =
            serde_json::from_value(request.payload.clone()).map_err(|e| malformed(OP, e))?;

        // Collect data. We always include status; logs / audit are
        // gated on the request flags. Playbook inclusion lands as
        // optional sections inside `DiagnosticArchiveRequest`.
        let health = self.diagnostics.get_status();

        // Build the diagnostic-archive request object FIRST — it carries the
        // log entry ceiling + byte budget that bound the log fetch below.
        //
        // The optional `troubleshooting_playbooks` section flag in our wire
        // DTO doesn't directly map to `DiagnosticArchiveRequest`'s sections
        // (the playbooks markdown is always emitted by the builder). Honoring
        // the GUI flag is a follow-up; for now we always emit playbooks (low
        // cost, high signal for support).
        //
        // The redaction level picks the section set + redaction tier:
        // "diagnostics" ships the extra cache/storage/explain sections;
        // anything else (incl. absent / unknown) stays at the redacted
        // "standard" default. Fail-safe: a bad level never errors.
        let wants_diagnostics_detail =
            matches!(req.redaction_level.as_deref(), Some("diagnostics"));
        let mut archive_request = if wants_diagnostics_detail {
            DiagnosticArchiveRequest::diagnostics_export(self.app_version.clone())
        } else {
            DiagnosticArchiveRequest::default_export(self.app_version.clone())
        };
        // The one inclusion flag with no consumer until now: the wire promised
        // a choice the builder never read, so an operator who unticked it still
        // got the file.
        archive_request.include_troubleshooting = req.include_troubleshooting_playbooks;
        // "Current session only": the builder drops
        // `logs.ndjson` entries older than this cutoff (see the wire DTO doc).
        // The GUI sends its day floor; narrow it to the current service
        // session (latest start after >=30 min of downtime) so an evening
        // export does not carry the morning's unrelated runs. The refined
        // value is echoed in the response so the launcher trims its raw log
        // attachments to the identical window. Fails open to the day floor.
        let effective_logs_from_ms = req.logs_from_ms.map(|requested| {
            let logs_dir = self
                .archives_dir
                .parent()
                .map(|root| root.join("logs"))
                .unwrap_or_else(|| self.archives_dir.join("logs"));
            nrr_diagnostics::logs::session_window::refine_session_cutoff_ms(&logs_dir, requested)
        });
        archive_request.logs_from_ms = effective_logs_from_ms;

        // The archive answers to the same audience as the panels: an export is
        // not a way around the scoping, and the person exporting it is usually
        // about to send it to somebody else.
        let audience = ctx.diagnostics_audience();
        // The lines are scoped like everything else, so the log directory does
        // not need to be readable by every account. The user's cap applies;
        // `0` means UNLIMITED, as the preference promises, and the real bounds
        // are retention and the export's own window.
        let raw_log_budget = match req.raw_log_budget_bytes {
            Some(bytes) if bytes > 0 => bytes as usize,
            _ => usize::MAX,
        };
        let raw_log_files = if req.include_logs {
            self.diagnostics
                .recent_log_files_raw(raw_log_budget, effective_logs_from_ms, &audience)
                .map_err(|e| internal(OP, format!("recent_log_files_raw: {e}")))?
        } else {
            Vec::new()
        };
        // Beside the raw files the builder leaves `logs.ndjson` out, so there is
        // nothing to fetch. Otherwise the NEWEST entries, newest-first, trimmed
        // by the builder to `max_log_bytes`.
        let log_entries = if req.include_logs && raw_log_files.is_empty() {
            self.diagnostics
                .recent_log_entries(
                    &Default::default(),
                    archive_request.max_log_entries as usize,
                    &audience,
                )
                .map_err(|e| internal(OP, format!("recent_log_entries: {e}")))?
        } else {
            Vec::new()
        };
        let audit_entries = if req.include_audit_summary {
            // One newest-first page; the builder keeps its first `max_audit_entries`.
            let audit_page = PaginationParams {
                cursor: None,
                page_size: MAX_PAGE_SIZE,
            };
            self.diagnostics
                .list_audit_entries(&Default::default(), &audit_page, &audience)
                .map_err(|e| internal(OP, format!("list_audit_entries: {e}")))?
                .items
        } else {
            Vec::new()
        };
        // Raw, tamper-verifiable audit chain (audit_chain.ndjson) — ONLY in a
        // diagnostics-tier export, where raw payload_summary_json is permitted.
        // `AuditChain` is in the diagnostics_export section set but NOT the
        // default set, so the redaction gate and the section gate agree.
        // The RAW chain is machine-wide by construction: its value is that the
        // hashes link every event, and a subset cannot be verified. So it ships
        // only for a caller who may see the whole trail; everyone else gets the
        // scoped summary above and no chain, rather than a chain that would
        // fail its own verification.
        let audit_chain_lines = if wants_diagnostics_detail
            && req.include_audit_summary
            && audience.is_machine_wide()
        {
            self.diagnostics
                .recent_audit_chain_lines(archive_request.max_audit_chain_bytes as usize)
                .map_err(|e| internal(OP, format!("recent_audit_chain_lines: {e}")))?
        } else {
            Vec::new()
        };

        let caller_sid = ctx.caller_stored();
        // Only pay for decision-id discovery + N facade calls when the archive will
        // actually carry `explain_samples.json` (diagnostics-tier export).
        let explain_level = if wants_diagnostics_detail {
            ExplainDetailLevel::Diagnostics
        } else {
            ExplainDetailLevel::CompactUi
        };
        let explain_samples = if wants_diagnostics_detail {
            self.collect_explain_samples(explain_level, caller_sid, &audience)
        } else {
            Vec::new()
        };
        let health_enrichment = self.collect_health_enrichment(caller_sid);

        let now_ms = millis_since_epoch();
        std::fs::create_dir_all(&self.archives_dir)
            .map_err(|e| internal(OP, format!("create archives dir: {e}")))?;
        // Archive filename: app version + UTC timestamp + sub-second millis, made
        // unique against an existing file. The version lets a triager tell
        // builds apart before opening the zip.
        let dest_path = unique_archive_path(&self.archives_dir, &self.app_version, now_ms);

        let input = ArchiveInput {
            health,
            health_enrichment,
            log_entries,
            audit_entries,
            audit_chain_lines,
            raw_log_files,
            explain_samples,
            system_info: self.system_info.clone(),
            service_stderr: self.read_log_tail("nrr_service_stderr.log"),
            broker_logs: [
                nrr_platform_api::paths::BROKER_LOG_FILE,
                nrr_platform_api::paths::BROKER_PREVIOUS_LOG_FILE,
            ]
            .into_iter()
            .filter_map(|name| {
                self.read_log_tail(name).map(|text| AttachedLog {
                    name: name.to_string(),
                    text,
                })
            })
            .collect(),
            request: archive_request,
        };
        let result = ArchiveBuilder::build(input, &dest_path)
            .map_err(|e| internal(OP, format!("archive build: {e}")))?;

        // Hand the finished file to the caller. The service tree is closed to
        // ordinary users — deliberately, it holds every principal's rules and
        // the audit trail — so without this the archive the user just asked for
        // is one they cannot open, and the GUI reports a path that only an
        // administrator can reach. The grant is per FILE: another principal's
        // export in the same directory stays theirs.
        //
        // Best-effort: an export that succeeded is not failed over the handoff.
        // The caller finds out by the copy failing, which reports its own
        // reason, rather than by losing the archive that was already built.
        let caller = ctx.caller_stored();
        if !caller.is_empty() {
            if let Err(e) = self.file_handoff.grant_read(&result.path, caller) {
                tracing::warn!(
                    target: "nrr::diagnostics",
                    error = %e,
                    "diagnostics.export-archive: could not hand the archive to its requester",
                );
            }
        }

        // Retention: the service dir is not
        // user-deletable (ProgramData needs elevation), so without a cap old
        // archives accumulate forever. Keep the most recent
        // [`ARCHIVE_RETENTION_KEEP`]; the user-owned copy the launcher makes
        // in %TEMP%\NetRuleRouter is theirs to manage. Best-effort — a prune
        // failure never fails the export that just succeeded.
        prune_old_archives(&self.archives_dir, ARCHIVE_RETENTION_KEEP);

        let response = DiagnosticsExportArchiveResponse {
            archive_path: result.path.to_string_lossy().into_owned(),
            size_bytes: result.size_bytes,
            generated_at_ms: now_ms,
            logs_from_ms_effective: effective_logs_from_ms,
        };
        serialise(OP, &response)
    }
}

/// How many finished archives the service
/// keeps in its own `archives/` dir. Newest-first by modification time.
const ARCHIVE_RETENTION_KEEP: usize = 5;

/// Delete all but the newest `keep` `nrr-diagnostics-*.zip` files in `dir`.
/// Only files matching our own naming prefix are ever touched; anything else
/// in the directory is left alone. Best-effort (I/O errors are logged and
/// swallowed — retention must never break an export).
fn prune_old_archives(dir: &std::path::Path, keep: usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut archives: Vec<(std::time::SystemTime, PathBuf)> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if !(name.starts_with("nrr-diagnostics-") && name.ends_with(".zip")) {
                return None;
            }
            let modified = e.metadata().and_then(|m| m.modified()).ok()?;
            Some((modified, e.path()))
        })
        .collect();
    if archives.len() <= keep {
        return;
    }
    // Newest first; everything past `keep` goes.
    archives.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, path) in archives.drain(keep..) {
        match std::fs::remove_file(&path) {
            Ok(()) => tracing::info!(
                target: "nrr::diagnostics",
                path = %path.display(),
                "archive retention: pruned old diagnostic archive",
            ),
            Err(e) => tracing::warn!(
                target: "nrr::diagnostics",
                path = %path.display(),
                error = %e,
                "archive retention: failed to prune old archive",
            ),
        }
    }
}

/// Build a UNIQUE archive path:
/// `nrr-diagnostics-v<version>-<YYYYMMDD-HHMMSS>-<mmm>.zip`, where `<mmm>` is
/// the sub-second millisecond. If a file with that name already exists (two
/// exports within the same millisecond), a `-<n>` counter is appended until a
/// free name is found. Embedding the app version lets a triager tell builds
/// apart from the filename alone.
fn unique_archive_path(dir: &std::path::Path, app_version: &str, now_ms: i64) -> PathBuf {
    let ver = sanitize_for_filename(app_version);
    let ts = format_timestamp_for_filename(now_ms);
    let millis = now_ms.rem_euclid(1_000);
    let base = format!("nrr-diagnostics-v{ver}-{ts}-{millis:03}");
    let mut path = dir.join(format!("{base}.zip"));
    let mut n: u32 = 1;
    while path.exists() {
        path = dir.join(format!("{base}-{n}.zip"));
        n = n.saturating_add(1);
    }
    path
}

/// Reduce a version string to a filename-safe token (ASCII alphanumerics plus
/// `.`, `-`, `_`); every other character becomes `-`. Never empty.
fn sanitize_for_filename(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '-'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "unknown".to_string()
    } else {
        cleaned
    }
}

/// Format `now_ms` as `YYYYMMDD-HHMMSS` for use in the archive
/// filename. Uses simple UTC date arithmetic — pulling `chrono` for
/// this single call site would inflate the dependency graph
/// (workspace policy: avoid optional deps that only one module uses).
fn format_timestamp_for_filename(now_ms: i64) -> String {
    // Decompose ms → seconds, then days + time-of-day.
    let secs = now_ms / 1_000;
    let days_since_epoch = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let hour = (secs_of_day / 3600) as u32;
    let minute = ((secs_of_day % 3600) / 60) as u32;
    let second = (secs_of_day % 60) as u32;
    // Civil calendar conversion (Howard Hinnant). Public domain;
    // converts days-since-1970-01-01 into (year, month, day).
    let z = days_since_epoch + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe as i64 - (365 * yoe as i64 + yoe as i64 / 4 - yoe as i64 / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        year, m, d, hour, minute, second
    )
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
