//! Reading and clearing what the service remembers about names and addresses,
//! and the log/diagnostic-mode switches beside it.
//!
//! Split out of `diagnostics_handlers`; the code is unchanged.

use super::*;

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
