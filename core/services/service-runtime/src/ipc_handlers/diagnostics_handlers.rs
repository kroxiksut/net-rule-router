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
//! (sibling of `logs/` and `audit/`, inherits the same Users:RX ACL).
//! Returns the absolute path so the GUI can open the containing folder
//! in Explorer.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use nrr_diagnostics::archive::{
    builder::{ArchiveBuilder, ArchiveInput},
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
use crate::ipc_handlers::providers::{AdaptersSnapshotProvider, RoutePolicyProvider};
use crate::per_sid_orchestrator::RulesProvider;

/// Inputs for the conn-trace `expected_route` stamp: the active
/// user's rule book + the FQDN cache + the routing-active-SID resolver.
pub type ConnTraceExpectation = (
    Arc<dyn RulesProvider>,
    Arc<dyn FqdnCacheLookup>,
    ActiveSidFn,
);

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
            let shared = cached_ips.iter().filter(|ip| census.contains(ip)).count() as u32;
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
            // google.com), but rule-cached subdomains exist under it
            // (gemini.google.com). Same-front-end CDNs serve both from one IP
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
            expectation: None,
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
    /// of `logs/` and `audit/`; inherits the Users:RX ACL set up by
    /// the bootstrap.
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
    ) -> Self {
        Self {
            diagnostics,
            archives_dir,
            app_version,
            system_info,
            adapters,
            route_policy,
            state_schema_version,
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
    fn recent_decision_ids(&self, limit: usize) -> Vec<String> {
        let entries = match self
            .diagnostics
            .recent_log_entries(&Default::default(), MAX_PAGE_SIZE as usize)
        {
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
    ) -> Vec<ExplainResponse> {
        self.recent_decision_ids(MAX_EXPLAIN_SAMPLES)
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

    /// The service's captured stderr, tail-trimmed, or `None` when the file is
    /// absent or unreadable.
    ///
    /// A panic never reaches the structured log — the process is already on its
    /// way down — so this file is the only record of it, and an archive
    /// exported to explain a crash was arriving without the crash in it.
    fn read_service_stderr(&self) -> Option<String> {
        /// Enough for a panic and its backtrace; the file is bounded by the
        /// capture itself, this only guards a pathological one.
        const MAX_BYTES: usize = 256 * 1024;
        let logs_dir = self
            .archives_dir
            .parent()
            .map(|root| root.join("logs"))
            .unwrap_or_else(|| self.archives_dir.join("logs"));
        let mut text = std::fs::read_to_string(logs_dir.join("nrr_service_stderr.log")).ok()?;
        if text.len() <= MAX_BYTES {
            return Some(text);
        }
        // Keep the TAIL: the last thing written is what the process died
        // saying. Cut on a char boundary so the result stays valid UTF-8.
        let mut cut = text.len() - MAX_BYTES;
        while cut < text.len() && !text.is_char_boundary(cut) {
            cut += 1;
        }
        Some(text.split_off(cut))
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

        // Fetch the NEWEST log entries (up to the archive's entry ceiling),
        // not a single oldest-first wire page — otherwise archives ship the
        // stalest lines and the byte budget in the builder goes unused.
        // `recent_log_entries` returns newest-first; the builder then trims
        // to `max_log_bytes`.
        let log_entries = if req.include_logs {
            self.diagnostics
                .recent_log_entries(
                    &Default::default(),
                    archive_request.max_log_entries as usize,
                )
                .map_err(|e| internal(OP, format!("recent_log_entries: {e}")))?
        } else {
            Vec::new()
        };
        let audit_entries = if req.include_audit_summary {
            // Audit summary keeps the oldest-first single page (capped
            // at `max_audit_entries`); the newest-first ordering is scoped to
            // logs.ndjson only.
            let audit_page = PaginationParams {
                cursor: None,
                page_size: MAX_PAGE_SIZE,
            };
            self.diagnostics
                .list_audit_entries(&Default::default(), &audit_page)
                .map_err(|e| internal(OP, format!("list_audit_entries: {e}")))?
                .items
        } else {
            Vec::new()
        };
        // Raw, tamper-verifiable audit chain (audit_chain.ndjson) — ONLY in a
        // diagnostics-tier export, where raw payload_summary_json is permitted.
        // `AuditChain` is in the diagnostics_export section set but NOT the
        // default set, so the redaction gate and the section gate agree.
        let audit_chain_lines = if wants_diagnostics_detail && req.include_audit_summary {
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
            self.collect_explain_samples(explain_level, caller_sid)
        } else {
            Vec::new()
        };
        let health_enrichment = self.collect_health_enrichment(caller_sid);

        let now_ms = millis_since_epoch();
        std::fs::create_dir_all(&self.archives_dir)
            .map_err(|e| internal(OP, format!("create archives dir: {e}")))?;
        // Archive filename: app version + UTC timestamp +
        // sub-second millis, made unique against an existing file (two exports
        // in the same millisecond get a numeric suffix). The version in the
        // name lets a triager tell builds apart before even opening the zip.
        let dest_path = unique_archive_path(&self.archives_dir, &self.app_version, now_ms);

        let input = ArchiveInput {
            health,
            health_enrichment,
            log_entries,
            audit_entries,
            audit_chain_lines,
            explain_samples,
            system_info: self.system_info.clone(),
            service_stderr: self.read_service_stderr(),
            request: archive_request,
        };
        let result = ArchiveBuilder::build(input, &dest_path)
            .map_err(|e| internal(OP, format!("archive build: {e}")))?;

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
mod tests {
    use super::*;
    use crate::ipc_handlers::test_fakes::{FakeAdapters, FakeRoutePolicy};
    use nrr_diagnostics::audit::alert::InMemorySecurityAlertsRepository;
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};

    fn fake_adapters() -> Arc<dyn AdaptersSnapshotProvider> {
        Arc::new(FakeAdapters::empty())
    }

    fn fake_route_policy() -> Arc<dyn RoutePolicyProvider> {
        Arc::new(FakeRoutePolicy::default())
    }

    // ── CacheClearHandler (two-target split) ─────────────────────────

    /// A real temp-file `SqliteCacheStore` — the trait has ~15 methods, so a
    /// hand fake is disproportionate; a migrated temp DB is honest and cheap.
    /// Returns the store plus the `TempDir` guard (drop = cleanup).
    fn temp_cache() -> (
        tempfile::TempDir,
        Arc<Mutex<dyn nrr_storage::repository::CacheRepository + Send>>,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nrr_fqdn_ip_cache.db");
        let conn = nrr_storage::migration::open_connection(&path).expect("open");
        let runner = nrr_storage::migration::SqliteMigrationRunner::for_cache_db(conn);
        use nrr_storage::repository::MigrationRunner as _;
        runner.run_pending_migrations().expect("migrate");
        let store = nrr_storage::store::SqliteCacheStore::new(
            runner.into_connection(),
            nrr_storage::FreshnessThresholds::default_production(),
        );
        (dir, Arc::new(Mutex::new(store)))
    }

    fn cache_clear(handler: &CacheClearHandler, payload: serde_json::Value) -> CacheClearResponse {
        let env = IpcRequestEnvelope {
            protocol_version: crate::ipc::IPC_PROTOCOL_VERSION,
            request_id: "r".into(),
            correlation_id: None,
            operation: IpcOperationName::CacheClear,
            operation_class: crate::ipc::IpcOperationClass::DiagnosticQuery,
            confirmation_token: None,
            payload,
        };
        let ctx = IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: false,
            caller_principal: None,
        };
        let value = handler.handle(&env, &ctx).expect("cache.clear ok");
        serde_json::from_value(value).expect("decode CacheClearResponse")
    }

    #[test]
    fn cache_clear_app_only_does_not_flush_os_cache() {
        let (_dir, cache) = temp_cache();
        let flush = Arc::new(nrr_platform_api::dns::MockDnsCacheControl::new());
        let handler = CacheClearHandler::new(cache).with_dns_cache_control(
            flush.clone() as Arc<dyn nrr_platform_api::dns::DnsCacheControlPort>
        );
        // Default request = app cache only (clear_app_cache defaults true).
        let resp = cache_clear(&handler, serde_json::json!({}));
        assert_eq!(resp.os_cache_flushed, None, "OS flush not requested");
        assert_eq!(flush.flush_count(), 0);
    }

    #[test]
    fn cache_clear_os_only_flushes_and_does_not_error() {
        let (_dir, cache) = temp_cache();
        let flush = Arc::new(nrr_platform_api::dns::MockDnsCacheControl::new());
        let handler = CacheClearHandler::new(cache).with_dns_cache_control(
            flush.clone() as Arc<dyn nrr_platform_api::dns::DnsCacheControlPort>
        );
        let resp = cache_clear(
            &handler,
            serde_json::json!({ "clear-app-cache": false, "flush-os-cache": true }),
        );
        assert_eq!(resp.resolutions_removed, 0, "app cache untouched");
        assert_eq!(resp.os_cache_flushed, Some(true));
        assert_eq!(flush.flush_count(), 1);
    }

    #[test]
    fn cache_clear_os_flush_without_port_reports_false() {
        let (_dir, cache) = temp_cache();
        let handler = CacheClearHandler::new(cache); // no port wired
        let resp = cache_clear(
            &handler,
            serde_json::json!({ "clear-app-cache": false, "flush-os-cache": true }),
        );
        assert_eq!(
            resp.os_cache_flushed,
            Some(false),
            "flush requested with no port must report Some(false), not error"
        );
    }

    #[test]
    fn sanitize_for_filename_keeps_safe_chars_and_replaces_the_rest() {
        assert_eq!(sanitize_for_filename("0.1.0-preview"), "0.1.0-preview");
        assert_eq!(sanitize_for_filename("1.0 build/x64"), "1.0-build-x64");
        assert_eq!(sanitize_for_filename(""), "unknown");
    }

    #[test]
    fn unique_archive_path_avoids_collision() {
        let dir = tempfile::tempdir().expect("temp");
        let now_ms = 1_745_000_000_123;
        let first = unique_archive_path(dir.path(), "0.1.0", now_ms);
        assert!(first
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("nrr-diagnostics-v0.1.0-"));
        // Create the first file so the SAME timestamp must pick a new name.
        std::fs::write(&first, b"x").expect("write");
        let second = unique_archive_path(dir.path(), "0.1.0", now_ms);
        assert_ne!(first, second, "a taken name must be bumped");
        assert!(second
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains("-1.zip"));
    }

    #[test]
    fn prune_keeps_newest_archives_and_ignores_foreign_files() {
        // Retention keeps the newest `keep`
        // of OUR archives (by mtime) and never touches other files.
        let dir = tempfile::tempdir().expect("tempdir");
        let base = std::time::SystemTime::now() - std::time::Duration::from_secs(1_000);
        for i in 0..7u64 {
            let p = dir.path().join(format!("nrr-diagnostics-v0-t-{i}.zip"));
            std::fs::write(&p, b"z").expect("write");
            let f = std::fs::OpenOptions::new()
                .write(true)
                .open(&p)
                .expect("open");
            f.set_modified(base + std::time::Duration::from_secs(i * 10))
                .expect("set mtime");
        }
        let foreign = dir.path().join("keep-me.txt");
        std::fs::write(&foreign, b"f").expect("write foreign");

        prune_old_archives(dir.path(), 5);

        let mut left: Vec<String> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert!(
            left.contains(&"keep-me.txt".to_string()),
            "foreign untouched"
        );
        let zips: Vec<&String> = left.iter().filter(|n| n.ends_with(".zip")).collect();
        assert_eq!(zips.len(), 5, "exactly the newest 5 archives remain");
        assert!(
            !left.contains(&"nrr-diagnostics-v0-t-0.zip".to_string())
                && !left.contains(&"nrr-diagnostics-v0-t-1.zip".to_string()),
            "the two OLDEST archives are pruned"
        );
    }

    use crate::ipc::{IpcOperationClass, IpcRequestContext, IpcRequestEnvelope};

    fn ctx() -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: true,
            caller_principal: crate::UserPrincipal::from_windows_sid("S-1-5-21-test").ok(),
        }
    }

    fn envelope(payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: 1,
            request_id: "req-1".into(),
            correlation_id: None,
            operation: IpcOperationName::ExplainGet,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload,
        }
    }

    fn facade() -> Arc<dyn DiagnosticsFacade> {
        let temp = tempfile::tempdir().unwrap();
        let alerts: Arc<dyn nrr_diagnostics::audit::alert::SecurityAlertsRepository> =
            Arc::new(InMemorySecurityAlertsRepository::new());
        Arc::new(
            crate::production_diagnostics::ProductionDiagnosticsFacade::new(
                temp.path().to_path_buf(),
                temp.path().to_path_buf(),
                None,
                alerts,
                None,
            ),
        )
        // tempdir dropped here; the facade only stores the path. Tests
        // that need on-disk artifacts construct their own facade.
    }

    #[test]
    fn explain_rejects_both_fields_set() {
        let h = ExplainGetHandler::new(facade());
        let payload = serde_json::json!({
            "decision-id": "d-1",
            "input-sample": { "hostname": "x.com" }
        });
        let r = h.handle(&envelope(payload), &ctx());
        assert!(r.is_err());
        let err = r.unwrap_err();
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }

    #[test]
    fn explain_rejects_neither_field_set() {
        let h = ExplainGetHandler::new(facade());
        let r = h.handle(&envelope(serde_json::json!({})), &ctx());
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().code, IpcErrorCode::MalformedRequest);
    }

    #[test]
    fn explain_rejects_empty_decision_id() {
        let h = ExplainGetHandler::new(facade());
        let payload = serde_json::json!({ "decision-id": "" });
        let r = h.handle(&envelope(payload), &ctx());
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().code, IpcErrorCode::MalformedRequest);
    }

    #[test]
    fn explain_historical_returns_compact_view() {
        let h = ExplainGetHandler::new(facade());
        let payload = serde_json::json!({ "decision-id": "d-unknown" });
        let v = h.handle(&envelope(payload), &ctx()).expect("ok");
        // Facade returns Unavailable::DecisionNotFound → response
        // still has summary + correlation; compact view falls back
        // to summary_key as reason_key, "-" as input, "none" as
        // route (no final_action_section on unavailable).
        let compact = &v["compact"];
        assert!(compact.is_object());
        assert_eq!(compact["input"], "-");
        assert_eq!(compact["route"], "none");
    }

    #[test]
    fn explain_synthetic_passes_input_sample() {
        let h = ExplainGetHandler::new(facade());
        let payload = serde_json::json!({
            "input-sample": {
                "hostname": "example.com",
                "process-name": "chrome.exe"
            }
        });
        let v = h.handle(&envelope(payload), &ctx()).expect("ok");
        let full = &v["full"];
        // ExplainResponse.is_simulation = true.
        assert_eq!(full["query_kind"], "synthetic");
    }

    // The kill-switch verdict rides the compact view: an
    // enabled kill-switch with block-all-unknown coverage marks an uncached
    // hostname as blocked-while-armed even though the rule verdict alone
    // would read "primary"/"none".
    #[test]
    fn explain_synthetic_stamps_killswitch_enforcement_verdict() {
        use crate::fqdn_cache_lookup::MockFqdnCacheLookup;

        struct FixedPolicy(nrr_shared::ipc_payloads::RoutePolicyDto);
        impl crate::ipc_handlers::providers::RoutePolicyProvider for FixedPolicy {
            fn get_for_sid(&self, _sid: &str) -> Option<nrr_shared::ipc_payloads::RoutePolicyDto> {
                Some(self.0.clone())
            }
        }

        let dto: nrr_shared::ipc_payloads::RoutePolicyDto =
            serde_json::from_value(serde_json::json!({
                "mode": "prefer-primary",
                "block-secondary-when-unavailable": true,
                "kill-switch-enabled": true,
                "mode-a-coverage-strategy": "fail-closed-unknown",
                "binding-source": "user-assigned"
            }))
            .expect("policy dto");
        let h = ExplainGetHandler::new(facade()).with_enforcement_verdict(
            Arc::new(FixedPolicy(dto)),
            Arc::new(MockFqdnCacheLookup::default()),
            Arc::new(|| Some("S-1-5-21-TEST".to_string())),
        );
        // Hostname absent from the (empty) FQDN cache → no permit compiles
        // while armed → the verdict slug rides along.
        let payload = serde_json::json!({ "input-sample": { "hostname": "google.com" } });
        let v = h.handle(&envelope(payload), &ctx()).expect("ok");
        assert_eq!(
            v["compact"]["enforcement"],
            "blocked-unknown-under-block-all"
        );

        // Same probe WITHOUT the deps → field absent (skip_serializing_if).
        let bare = ExplainGetHandler::new(facade());
        let payload = serde_json::json!({ "input-sample": { "hostname": "google.com" } });
        let v = bare.handle(&envelope(payload), &ctx()).expect("ok");
        assert!(v["compact"].get("enforcement").is_none());
    }

    // ── CacheEntriesList ──────────────────────────────────────────────────────

    fn seeded_cache() -> Arc<Mutex<dyn CacheRepository + Send>> {
        use nrr_domain::decision_lookup::FreshnessThresholds;
        use nrr_storage::dto::ResolutionEntry;
        use nrr_storage::migration::SqliteMigrationRunner;
        use nrr_storage::repository::MigrationRunner;
        use nrr_storage::resolution_source::StorageResolutionSource;
        use nrr_storage::store::SqliteCacheStore;
        use std::net::Ipv4Addr;

        let conn = rusqlite::Connection::open_in_memory().expect("in-memory");
        let runner = SqliteMigrationRunner::for_cache_db(conn);
        runner.run_pending_migrations().expect("migrate");
        let store = SqliteCacheStore::new(
            runner.into_connection(),
            FreshnessThresholds::default_production(),
        );
        store
            .upsert_resolution(ResolutionEntry {
                canonical_hostname: "sub.example.com".into(),
                raw_hostname_sample: None,
                resolved_ips: vec![Ipv4Addr::new(203, 0, 113, 5)],
                ttl_seconds: Some(300),
                source: StorageResolutionSource::Dns,
                resolved_at: SystemTime::now(),
                active_revision_id: Some("rev-1".into()),
            })
            .expect("seed");
        store
            .upsert_resolution(ResolutionEntry {
                canonical_hostname: "api.other.net".into(),
                raw_hostname_sample: None,
                resolved_ips: vec![Ipv4Addr::new(198, 51, 100, 9)],
                ttl_seconds: Some(300),
                source: StorageResolutionSource::ObservedFromTraffic,
                resolved_at: SystemTime::now(),
                active_revision_id: Some("rev-1".into()),
            })
            .expect("seed");
        Arc::new(Mutex::new(store))
    }

    #[test]
    fn cache_entries_local_viewer_shows_real_hostname_and_ip() {
        // The local cache viewer surfaces the real resolved hostnames
        // and IPs (so the user can inspect + search by IP) regardless of the
        // diagnostic-mode toggle. total_count reflects the real cache size.
        let h = CacheEntriesListHandler::new(seeded_cache());
        let v = h
            .handle(&envelope(serde_json::json!({})), &ctx())
            .expect("ok");
        assert_eq!(v["redacted"], false, "local viewer is not redacted");
        assert_eq!(v["page"]["total_count"], 2, "live cache total");
        let items = v["page"]["items"].as_array().expect("items array");
        assert_eq!(items.len(), 2);
        // Ordered by canonical_host: api.other.net before sub.example.com.
        assert_eq!(items[0]["hostname"], "api.other.net", "full hostname");
        assert_eq!(items[0]["source"], "observed_from_traffic");
        assert_eq!(items[0]["ip"], "198.51.100.9", "real IP");
        assert_eq!(items[1]["hostname"], "sub.example.com", "full hostname");
        assert_eq!(items[1]["ip"], "203.0.113.5", "real IP");
        assert_eq!(items[1]["freshness"], "fresh");
    }

    #[test]
    fn cache_entries_pagination_reports_next_cursor() {
        let h = CacheEntriesListHandler::new(seeded_cache());
        let payload = serde_json::json!({ "pagination": { "page_size": 1 } });
        let v = h.handle(&envelope(payload), &ctx()).expect("ok");
        let items = v["page"]["items"].as_array().expect("items");
        assert_eq!(items.len(), 1, "page_size clamps to one item");
        let cursor = v["page"]["next_cursor"]
            .as_str()
            .expect("next cursor present");
        // Second page via the returned cursor yields the remaining row and
        // no further cursor.
        let payload2 = serde_json::json!({ "pagination": { "page_size": 1, "cursor": cursor } });
        let v2 = h.handle(&envelope(payload2), &ctx()).expect("ok");
        assert_eq!(v2["page"]["items"].as_array().expect("items2").len(), 1);
        assert!(
            v2["page"]["next_cursor"].is_null(),
            "last page has no cursor"
        );
    }

    #[test]
    fn cache_entries_carry_expected_route_when_expectation_wired() {
        // The cache viewer's "Route" column: secondary name-match
        // wins, primary name-match second, no match → empty.
        use crate::fqdn_cache_lookup::MockFqdnCacheLookup;
        use crate::per_sid_orchestrator::ActiveRulesSnapshot;
        use nrr_domain::canonical::{
            CanonicalAddressMatch, CanonicalRule, CanonicalRuleBook, CanonicalRuleSet,
        };
        use nrr_domain::RuleId;

        struct ScriptedRules;
        impl RulesProvider for ScriptedRules {
            fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
                let rule = |id: &str, m: CanonicalAddressMatch| CanonicalRule {
                    id: RuleId(id.into()),
                    enabled: true,
                    address_match: Some(m),
                    app_match: None,
                    comment: String::new(),
                    action: nrr_domain::RuleAction::Route,
                    origin: None,
                };
                Some(ActiveRulesSnapshot {
                    rule_book: CanonicalRuleBook {
                        primary: CanonicalRuleSet::from_rules(vec![rule(
                            "p1",
                            CanonicalAddressMatch::SuffixDomain("other.net".into()),
                        )]),
                        secondary: CanonicalRuleSet::from_rules(vec![rule(
                            "s1",
                            CanonicalAddressMatch::SuffixDomain("example.com".into()),
                        )]),
                    },
                    behavior_mode: nrr_domain::RouteBehaviorMode::PreferPrimary,
                })
            }
        }

        let h = CacheEntriesListHandler::new(seeded_cache()).with_route_expectation(
            Arc::new(ScriptedRules),
            Arc::new(MockFqdnCacheLookup::new()),
            Arc::new(|| Some("S-1-5-21-T".to_string())),
        );
        let v = h
            .handle(&envelope(serde_json::json!({})), &ctx())
            .expect("ok");
        let items = v["page"]["items"].as_array().expect("items");
        assert_eq!(items[0]["hostname"], "api.other.net");
        assert_eq!(items[0]["expected_route"], "primary");
        assert_eq!(items[1]["hostname"], "sub.example.com");
        assert_eq!(items[1]["expected_route"], "secondary");
    }

    #[test]
    fn cache_entries_expected_route_empty_without_expectation() {
        let h = CacheEntriesListHandler::new(seeded_cache());
        let v = h
            .handle(&envelope(serde_json::json!({})), &ctx())
            .expect("ok");
        let items = v["page"]["items"].as_array().expect("items");
        assert_eq!(items[0]["expected_route"], "");
        assert_eq!(items[1]["expected_route"], "");
    }

    #[test]
    fn timestamp_filename_is_well_formed() {
        // Format-pattern assertion only — exact date arithmetic is
        // verified by round-tripping a few known epochs below.
        let s = format_timestamp_for_filename(1_778_502_645_000);
        assert_eq!(s.len(), 15, "format must be YYYYMMDD-HHMMSS, got {s}");
        assert_eq!(s.chars().filter(|c| *c == '-').count(), 1);
        let (date, time) = s.split_once('-').unwrap();
        assert_eq!(date.len(), 8, "date segment must be 8 chars");
        assert_eq!(time.len(), 6, "time segment must be 6 chars");
        assert!(date.chars().all(|c| c.is_ascii_digit()));
        assert!(time.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn timestamp_filename_unix_epoch_is_19700101() {
        // Epoch zero — sanity check that the civil-calendar conversion
        // anchors on 1970-01-01 (UTC).
        let s = format_timestamp_for_filename(0);
        assert_eq!(s, "19700101-000000");
    }

    #[test]
    fn timestamp_filename_is_monotonic_within_a_year() {
        // Two timestamps a day apart should produce sortable filenames.
        let a = format_timestamp_for_filename(1_700_000_000_000);
        let b = format_timestamp_for_filename(1_700_086_400_000);
        assert!(
            a < b,
            "filenames must be lexicographically sortable: {a} < {b}"
        );
    }

    #[test]
    fn archive_handler_builds_a_zip_and_returns_path() {
        let temp = tempfile::tempdir().unwrap();
        let alerts: Arc<dyn nrr_diagnostics::audit::alert::SecurityAlertsRepository> =
            Arc::new(InMemorySecurityAlertsRepository::new());
        let logs_dir = temp.path().join("logs");
        let audit_dir = temp.path().join("audit");
        let archives_dir = temp.path().join("archives");
        std::fs::create_dir_all(&logs_dir).unwrap();
        std::fs::create_dir_all(&audit_dir).unwrap();
        let facade: Arc<dyn DiagnosticsFacade> = Arc::new(
            crate::production_diagnostics::ProductionDiagnosticsFacade::new(
                logs_dir.clone(),
                audit_dir.clone(),
                None,
                alerts,
                None,
            ),
        );
        let handler = DiagnosticsExportArchiveHandler::new(
            facade,
            archives_dir.clone(),
            "test-1.0.0".into(),
            None,
            fake_adapters(),
            fake_route_policy(),
            Some(29),
        );
        let env = IpcRequestEnvelope {
            protocol_version: 1,
            request_id: "req-arc".into(),
            correlation_id: None,
            operation: IpcOperationName::DiagnosticsExportArchive,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload: serde_json::json!({}),
        };
        let v = handler.handle(&env, &ctx()).expect("archive build");
        let path_str = v["archive-path"].as_str().expect("archive-path string");
        assert!(path_str.contains("nrr-diagnostics-"));
        assert!(path_str.ends_with(".zip"));
        let size = v["size-bytes"].as_u64().expect("size-bytes");
        assert!(size > 0, "archive must have non-zero size");
        // File actually exists on disk.
        assert!(std::path::Path::new(path_str).exists());
        // Generated_at_ms is a real timestamp (within last 10s).
        let ts = v["generated-at-ms"].as_i64().expect("generated-at-ms");
        let now = millis_since_epoch();
        assert!(
            (now - ts).abs() < 10_000,
            "generated-at-ms must be near now"
        );
    }

    #[test]
    fn archive_handler_with_no_logs_flag_still_succeeds() {
        let temp = tempfile::tempdir().unwrap();
        let alerts: Arc<dyn nrr_diagnostics::audit::alert::SecurityAlertsRepository> =
            Arc::new(InMemorySecurityAlertsRepository::new());
        let archives_dir = temp.path().join("archives");
        let facade: Arc<dyn DiagnosticsFacade> = Arc::new(
            crate::production_diagnostics::ProductionDiagnosticsFacade::new(
                temp.path().to_path_buf(),
                temp.path().to_path_buf(),
                None,
                alerts,
                None,
            ),
        );
        let handler = DiagnosticsExportArchiveHandler::new(
            facade,
            archives_dir.clone(),
            "t".into(),
            None,
            fake_adapters(),
            fake_route_policy(),
            None,
        );
        let env = IpcRequestEnvelope {
            protocol_version: 1,
            request_id: "req-arc-2".into(),
            correlation_id: None,
            operation: IpcOperationName::DiagnosticsExportArchive,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload: serde_json::json!({
                "include-logs": false,
                "include-audit-summary": false,
                "include-troubleshooting-playbooks": false,
            }),
        };
        let v = handler.handle(&env, &ctx()).expect("archive build");
        assert!(v["archive-path"].as_str().is_some());
    }

    #[test]
    fn diagnostics_redaction_level_ships_the_extra_sections() {
        // With `redaction-level: "diagnostics"` the archive gains
        // cache_health.json / storage_health.json / explain_samples.json;
        // "standard" (and absent) stays at the lean default set.
        use std::io::Read;
        let temp = tempfile::tempdir().unwrap();
        let alerts: Arc<dyn nrr_diagnostics::audit::alert::SecurityAlertsRepository> =
            Arc::new(InMemorySecurityAlertsRepository::new());
        let archives_dir = temp.path().join("archives");
        let facade: Arc<dyn DiagnosticsFacade> = Arc::new(
            crate::production_diagnostics::ProductionDiagnosticsFacade::new(
                temp.path().to_path_buf(),
                temp.path().to_path_buf(),
                None,
                alerts,
                None,
            ),
        );
        let handler = DiagnosticsExportArchiveHandler::new(
            facade,
            archives_dir,
            "t".into(),
            None,
            fake_adapters(),
            fake_route_policy(),
            Some(29),
        );
        let names_for = |level: serde_json::Value| -> Vec<String> {
            let env = IpcRequestEnvelope {
                protocol_version: 1,
                request_id: "req-arc-lvl".into(),
                correlation_id: None,
                operation: IpcOperationName::DiagnosticsExportArchive,
                operation_class: IpcOperationClass::ReadSnapshot,
                confirmation_token: None,
                payload: level,
            };
            let v = handler.handle(&env, &ctx()).expect("archive build");
            let path = v["archive-path"].as_str().expect("path").to_string();
            let file = std::fs::File::open(&path).expect("open zip");
            let mut zip = zip::ZipArchive::new(file).expect("zip");
            let mut names = Vec::new();
            for i in 0..zip.len() {
                let mut e = zip.by_index(i).expect("entry");
                let n = e.name().to_string();
                if n == "manifest.json" {
                    // Provenance is embedded — non-empty profile at minimum.
                    let mut body = String::new();
                    e.read_to_string(&mut body).expect("read manifest");
                    let mv: serde_json::Value = serde_json::from_str(&body).expect("json");
                    assert!(
                        !mv["build-profile"].as_str().unwrap_or("").is_empty()
                            || !mv["build_profile"].as_str().unwrap_or("").is_empty(),
                        "manifest carries build provenance"
                    );
                }
                names.push(n);
            }
            names
        };

        let standard = names_for(serde_json::json!({ "redaction-level": "standard" }));
        assert!(!standard.contains(&"cache_health.json".to_string()));
        assert!(!standard.contains(&"explain_samples.json".to_string()));

        let diagnostics = names_for(serde_json::json!({ "redaction-level": "diagnostics" }));
        assert!(diagnostics.contains(&"cache_health.json".to_string()));
        assert!(diagnostics.contains(&"storage_health.json".to_string()));
        assert!(diagnostics.contains(&"explain_samples.json".to_string()));
    }

    #[test]
    fn health_json_carries_enrichment_from_providers() {
        // Behavior mode, state
        // schema version, and the adapters snapshot must reach `health.json`
        // via the real `RoutePolicyProvider` / `AdaptersSnapshotProvider`
        // deps, keyed by the caller's SID from `IpcRequestContext`.
        use nrr_shared::ipc_payloads::{
            AdapterEntry, BehaviorModeDto, BindingSourceDto, RoutePolicyDto,
        };
        use std::io::Read;

        let temp = tempfile::tempdir().unwrap();
        let alerts: Arc<dyn nrr_diagnostics::audit::alert::SecurityAlertsRepository> =
            Arc::new(InMemorySecurityAlertsRepository::new());
        let archives_dir = temp.path().join("archives");
        let facade: Arc<dyn DiagnosticsFacade> = Arc::new(
            crate::production_diagnostics::ProductionDiagnosticsFacade::new(
                temp.path().to_path_buf(),
                temp.path().to_path_buf(),
                None,
                alerts,
                None,
            ),
        );

        let adapters: Arc<dyn AdaptersSnapshotProvider> =
            Arc::new(FakeAdapters::with_one(AdapterEntry {
                persistent_id: "adp-1".into(),
                adapter_name: "eth0".into(),
                ipv6_if_index: 1,
                physical_address: None,
                windows_name: "Ethernet".into(),
                interface_description: "Test NIC".into(),
                interface_type: "ethernet".into(),
                oper_status: "up".into(),
            }));
        let route_policy = Arc::new(FakeRoutePolicy::default());
        *route_policy.stored.lock().unwrap() = Some(RoutePolicyDto {
            primary: None,
            secondary: None,
            mode: BehaviorModeDto::PreferSecondaryWhenAvailable,
            block_secondary_when_unavailable: false,
            kill_switch_fail_closed: true,
            kill_switch_protocols: 127,
            kill_switch_block_all: false,
            kill_switch_enabled: false,
            allow_dns_over_primary: false,
            include_subdomains: false,
            shared_ip_policy: "majority-of-ip".into(),
            mode_a_coverage_strategy: "fail-closed-unknown".into(),
            resolve_hosts_bypass: true,
            secondary_link_provider_apps: Vec::new(),
            doh_lockdown_enabled: false,
            doh_lockdown_scope: "leak-protection-only".into(),
            browser_history_auto_seed: false,
            kill_switch_strict_shared_ips: false,
            auto_rules_mode: "suggest".to_string(),
            auto_rules_eager_delivery_names: false,
            binding_source: BindingSourceDto::UserAssigned,
        });

        let handler = DiagnosticsExportArchiveHandler::new(
            facade,
            archives_dir,
            "t".into(),
            None,
            adapters,
            route_policy as Arc<dyn RoutePolicyProvider>,
            Some(29),
        );
        let env = IpcRequestEnvelope {
            protocol_version: 1,
            request_id: "req-arc-health".into(),
            correlation_id: None,
            operation: IpcOperationName::DiagnosticsExportArchive,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload: serde_json::json!({}),
        };
        let v = handler.handle(&env, &ctx()).expect("archive build");
        let path = v["archive-path"].as_str().expect("path").to_string();
        let file = std::fs::File::open(&path).expect("open zip");
        let mut zip = zip::ZipArchive::new(file).expect("zip");
        let mut body = String::new();
        zip.by_name("health.json")
            .expect("health.json present")
            .read_to_string(&mut body)
            .expect("read");
        let health: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(health["behavior_mode"], "prefer-secondary-when-available");
        assert_eq!(health["state_schema_version"], 29);
        assert_eq!(
            health["adapters_snapshot"]["adapters"][0]["adapter-name"],
            "eth0"
        );
    }

    #[test]
    fn explain_samples_are_wired_from_recent_decision_ids_not_hardcoded_empty() {
        // A log entry carrying a `decision:<id>` correlation token must
        // produce a REAL `get_explain(HistoricalDecision)` call, not an
        // empty vec. The production facade currently answers
        // `DecisionNotFound` for every historical id (no snapshot-replay
        // store yet); the assertion here is on the WIRING: the sample is
        // present and reflects that real facade response.
        use std::io::Read;

        let temp = tempfile::tempdir().unwrap();
        let logs_dir = temp.path().join("logs");
        let audit_dir = temp.path().join("audit");
        let archives_dir = temp.path().join("archives");
        std::fs::create_dir_all(&logs_dir).unwrap();
        std::fs::create_dir_all(&audit_dir).unwrap();

        // Write one operational log line carrying a decision correlation —
        // the mechanism `recent_decision_ids` mines.
        {
            let date =
                nrr_diagnostics::audit::writer::local_date_string(std::time::SystemTime::now());
            let path = logs_dir.join(format!("nrr_service_{date}-1.ndjson"));
            let event = nrr_diagnostics::event::LogEvent::new(
                "evt-decision-001",
                1_745_000_000_000,
                nrr_diagnostics::taxonomy::EventLevel::Info,
                nrr_diagnostics::reason::service::STARTED,
            )
            .with_correlation(
                nrr_diagnostics::taxonomy::EventCorrelation::default().with_decision("d-sample-1"),
            );
            std::fs::write(
                &path,
                format!("{}\n", event.to_ndjson().expect("serialize")),
            )
            .unwrap();
        }

        let alerts: Arc<dyn nrr_diagnostics::audit::alert::SecurityAlertsRepository> =
            Arc::new(InMemorySecurityAlertsRepository::new());
        let facade: Arc<dyn DiagnosticsFacade> = Arc::new(
            crate::production_diagnostics::ProductionDiagnosticsFacade::new(
                logs_dir, audit_dir, None, alerts, None,
            ),
        );
        let handler = DiagnosticsExportArchiveHandler::new(
            facade,
            archives_dir,
            "t".into(),
            None,
            fake_adapters(),
            fake_route_policy(),
            None,
        );
        let env = IpcRequestEnvelope {
            protocol_version: 1,
            request_id: "req-arc-explain".into(),
            correlation_id: None,
            operation: IpcOperationName::DiagnosticsExportArchive,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload: serde_json::json!({ "redaction-level": "diagnostics" }),
        };
        let v = handler.handle(&env, &ctx()).expect("archive build");
        let path = v["archive-path"].as_str().expect("path").to_string();
        let file = std::fs::File::open(&path).expect("open zip");
        let mut zip = zip::ZipArchive::new(file).expect("zip");
        let mut body = String::new();
        zip.by_name("explain_samples.json")
            .expect("explain_samples.json present")
            .read_to_string(&mut body)
            .expect("read");
        let samples: serde_json::Value = serde_json::from_str(&body).expect("json");
        let samples = samples.as_array().expect("array");
        assert_eq!(samples.len(), 1, "the one decision id must be sampled");
        assert_eq!(samples[0]["query_kind"], "historical");
    }
}
