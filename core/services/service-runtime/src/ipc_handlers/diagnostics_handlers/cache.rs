//! Reading and clearing what the service remembers about names and addresses,
//! and clearing the operational logs beside it.
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

impl CheckedIpcHandler for LogsClearHandler {
    type Checked = LogsClearRequest;

    fn precheck(
        &self,
        request: &IpcRequestEnvelope,
        _ctx: &IpcRequestContext,
    ) -> Result<Self::Checked, IpcError> {
        serde_json::from_value(request.payload.clone()).map_err(|e| malformed("logs.clear", e))
    }

    fn execute(
        &self,
        req: Prechecked<Self::Checked>,
        _request: &IpcRequestEnvelope,
        _ctx: &IpcRequestContext,
    ) -> HandlerOutcome {
        const OP: &str = "logs.clear";
        let req = req.into_inner();
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

impl CheckedIpcHandler for CacheClearHandler {
    type Checked = CacheClearRequest;

    fn precheck(
        &self,
        request: &IpcRequestEnvelope,
        _ctx: &IpcRequestContext,
    ) -> Result<Self::Checked, IpcError> {
        serde_json::from_value(request.payload.clone()).map_err(|e| malformed("cache.clear", e))
    }

    fn execute(
        &self,
        req: Prechecked<Self::Checked>,
        _request: &IpcRequestEnvelope,
        _ctx: &IpcRequestContext,
    ) -> HandlerOutcome {
        const OP: &str = "cache.clear";
        let req = req.into_inner();

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
/// **Redaction.** None: this is an on-screen inspector of the user's own
/// machine, so full hostnames and addresses are shown and `redacted` is
/// always `false`. Exports and archives keep their own redaction tier.
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

    /// The viewer's rule book plus the secondary-owned IPv4 set, or `None`
    /// when the expectation deps are absent or nobody can be named. The viewer
    /// is the caller; a caller with no identity is judged by the routing user's
    /// book. Built once per page request, never per row.
    ///
    /// NOTE: name matching uses the RAW rule book (no `include_subdomains`
    /// coverage expansion) — consistent with the conn-trace stamp; the
    /// IP-owner fallback catches shared-IP collateral either way.
    fn route_expectation(
        &self,
        viewer: &str,
    ) -> Option<(
        crate::per_sid_orchestrator::ActiveRulesSnapshot,
        std::collections::HashSet<std::net::Ipv4Addr>,
    )> {
        let (rules, fqdn, active_sid) = self.expectation.as_ref()?;
        let sid = if viewer.is_empty() {
            active_sid()?
        } else {
            viewer.to_owned()
        };
        let snapshot = rules.active_rules_for(&sid)?;
        let owned = build_secondary_ip_owners(&snapshot.rule_book.secondary, fqdn.as_ref())
            .into_keys()
            .collect();
        Some((snapshot, owned))
    }
}

impl IpcHandler for CacheEntriesListHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
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

        // Rule-book + secondary-owned IPv4 set, built ONCE per page, from the
        // CALLER's book: another user's rules would call their own sites leaks.
        let expectation = self.route_expectation(ctx.caller_stored());
        // The names on this machine are everybody's: an administrator sees
        // them all, anyone else only the names their own rules cover.
        let scoped = !ctx.caller_is_elevated;

        let (rows, total_count, scoped_next) = {
            let cache = self
                .cache
                .lock()
                .map_err(|e| internal(OP, format!("cache mutex poisoned: {e}")))?;
            if scoped {
                let book = expectation
                    .as_ref()
                    .filter(|_| !ctx.caller_stored().is_empty())
                    .map(|(snapshot, _)| &snapshot.rule_book);
                let (rows, next) = own_rows_page(&*cache, book, offset, limit, req.query.trim())
                    .map_err(|e| internal(OP, format!("list_resolutions: {e}")))?;
                (rows, None, next)
            } else {
                let rows = cache
                    .list_resolutions(offset, limit, req.query.trim())
                    .map_err(|e| internal(OP, format!("list_resolutions: {e}")))?;
                // Live total so the GUI count reflects the REAL service cache,
                // not a frozen cold-start snapshot.
                let total = cache.get_cache_stats().map(|s| s.resolution_count).ok();
                (rows, total, None)
            }
        };
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
        let has_more = scoped_next.is_some() || (!scoped && rows.len() as u32 > limit);
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
                ip: viewer_ip_str(&row.canonical_ip, mode),
                freshness: row.freshness_state,
                source: row.source,
                resolved_at_ms: system_time_to_ms(row.resolved_at),
                expires_at_ms: system_time_to_ms(row.expires_at),
            })
            .collect();

        let next_cursor = match scoped_next {
            Some(position) => Some(PageCursor::from_position(i64::from(position), "cache")),
            None if has_more => Some(PageCursor::from_position(
                i64::from(offset) + i64::from(limit),
                "cache",
            )),
            None => None,
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

/// A stored address as the viewer shows it; one that does not parse stays masked.
fn viewer_ip_str(ip: &str, mode: RedactionMode) -> String {
    ip.parse().map_or_else(
        |_| redact_ipv4_str(ip, mode).display_or_marker(),
        |ip| viewer_ip(ip, mode),
    )
}

/// Rows read per storage query while looking for a caller's own names.
const OWN_ROWS_CHUNK: u32 = 512;
/// Rows looked at for one page of a caller's own names: past it the page is
/// cut short and the cursor resumes from there.
const OWN_ROWS_SCAN_CAP: u32 = 20_000;

/// One page of the cached names `book` covers, from position `offset` on, and
/// where the next page starts (`None` when nothing is left). Without a book
/// nothing is the caller's, so the page is empty.
fn own_rows_page(
    cache: &(dyn CacheRepository + Send),
    book: Option<&nrr_domain::canonical::CanonicalRuleBook>,
    offset: u32,
    limit: u32,
    query: &str,
) -> nrr_storage::error::StorageResult<(Vec<nrr_storage::dto::CacheEntryRow>, Option<u32>)> {
    let Some(book) = book else {
        return Ok((Vec::new(), None));
    };
    let covered = |row: &nrr_storage::dto::CacheEntryRow| {
        let v4 = row.canonical_ip.parse::<std::net::Ipv4Addr>().ok();
        rule_set_match_kind(&row.canonical_hostname, v4, &book.secondary).is_some()
            || rule_set_match_kind(&row.canonical_hostname, v4, &book.primary).is_some()
    };
    let mut page = Vec::new();
    let mut position = offset;
    let end = offset.saturating_add(OWN_ROWS_SCAN_CAP);
    while position < end {
        let rows = cache.list_resolutions(position, OWN_ROWS_CHUNK, query)?;
        let exhausted = rows.len() as u32 <= OWN_ROWS_CHUNK;
        for row in rows.into_iter().take(OWN_ROWS_CHUNK as usize) {
            if !covered(&row) {
                position += 1;
                continue;
            }
            if page.len() as u32 == limit {
                return Ok((page, Some(position)));
            }
            page.push(row);
            position += 1;
        }
        if exhausted {
            return Ok((page, None));
        }
    }
    Ok((page, Some(position)))
}
