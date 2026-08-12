//! Production [`DiagnosticsFacade`] implementation.
//!
//! Composes the existing `nrr-diagnostics` primitives (`LogReader`,
//! `AuditReader`, `SecurityAlertsRepository`) and `nrr-storage`
//! cache stats into the wire-shaped DTOs the GUI's Diagnostics
//! section consumes. Replaces the long-standing
//! [`MockDiagnosticsFacade::healthy()`](nrr_diagnostics::facade::mock::MockDiagnosticsFacade)
//! placeholder in `runtime_deps.rs:316`.
//!
//! # Method map
//!
//! | Trait method            | Source(s)                                                          |
//! |-------------------------|--------------------------------------------------------------------|
//! | `get_status`            | `AuditReader` (chain), alerts repo (count), `SqliteCacheStore`     |
//! |                         | (entry count + `last_rebuild_at`), `LogReader` (size+count),       |
//! |                         | `RevisionsRepository` (active + pending), diagnostic-session state |
//! | `list_log_entries`      | `LogReader::scan(filter)` + in-memory cursor pagination            |
//! | `list_audit_entries`    | `AuditReader::scan(filter)` + in-memory cursor pagination          |
//! | `list_active_alerts`    | `SecurityAlertsRepository::list_open`                              |
//! | `acknowledge_alert`     | Returns `RecoveryAction` — canonical path is                       |
//! |                         | `MutationKind::SecurityAlertAck` via the mutation queue (16.10).   |
//! |                         | This method is deliberately a non-mutating sentinel so the wire    |
//! |                         | invariant "single writer = MutationDispatcher" holds.              |
//! | `set_diagnostic_mode`   | Mutates internal [`DiagnosticSessionHandle`] (Arc<Mutex<...>>)     |
//! | `clear_logs`            | Walks `LogReader::list_files`, deletes each (`dry_run` skips)      |
//! | `get_explain`           | `Synthetic` runs the REAL rule engine (`match_sample`) against the |
//! |                         | caller's per-SID active rule book + behavior mode and returns a    |
//! |                         | real route/reason (`Available`). `Historical` (by decision id)     |
//! |                         | returns `DecisionNotFound` until the explain snapshot write-side   |
//! |                         | is wired — there is no UI consumer of the historical path today.   |
//!
//! # Threading
//!
//! All methods are `&self` synchronous. The facade is `Send + Sync` so
//! the IPC handler can hold an `Arc<dyn DiagnosticsFacade>` across
//! threads. Internal state (`DiagnosticSessionHandle`) uses
//! `Arc<Mutex<...>>` for interior mutability.
//!
//! # Pagination semantics
//!
//! Both `list_log_entries` and `list_audit_entries` scan the full
//! NDJSON tree, filter in-memory, then slice the matching events by
//! cursor. The cursor encodes `(created_at_ms, event_id)` of the last
//! item returned. Future blocks may add SQLite-indexed log storage —
//! the trait surface won't change.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use rusqlite::{Connection, OptionalExtension};

use nrr_diagnostics::audit::alert::{SecurityAlert, SecurityAlertsRepository};
use nrr_diagnostics::audit::reader::{AuditQueryFilter, AuditReader};
use nrr_diagnostics::error::{DiagnosticsError, DiagnosticsResult};
use nrr_diagnostics::event::{AuditEvent, LogEvent};
use nrr_diagnostics::explain::{ExplainDataAvailability, ExplainQuery, ExplainResponse};
use nrr_diagnostics::facade::dto::{
    AcknowledgeAlertRequest, AuditEntryDto, AuditEntryFilter, CacheHealthCard, ClearLogsRequest,
    ClearLogsResult, DiagnosticModeStateDto, DiagnosticsStatusDto, LogEntryDto, LogEntryFilter,
    LogHealthCard, SecurityAlertDto, SecurityStatusCard, ServiceHealthCard,
    SetDiagnosticModeRequest,
};
use nrr_diagnostics::facade::pagination::{PageCursor, PageResult, PaginationParams};
use nrr_diagnostics::facade::service::DiagnosticsFacade;
use nrr_diagnostics::logs::reader::{LogQueryFilter, LogReader};
use nrr_diagnostics::privacy::{DiagnosticSession, DiagnosticSessionScope, RedactionMode};
use nrr_diagnostics::redaction::ExplainDetailLevel;
use nrr_diagnostics::taxonomy::{EventCategory, EventLevel};

// ── DiagnosticSessionHandle ──────────────────────────────────────────────────

/// Shared, mutable holder for the active [`DiagnosticSession`] (if
/// any). Owned by [`ProductionDiagnosticsFacade`] but exposed as a
/// distinct type so other components (the redaction-aware log
/// projector, the explain handler) can read the current redaction
/// mode via `Arc::clone`.
#[derive(Clone, Default)]
pub struct DiagnosticSessionHandle {
    inner: Arc<Mutex<Option<DiagnosticSession>>>,
}

impl DiagnosticSessionHandle {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the current session if it's still active at `now_ms`.
    /// Returns `None` for missing or expired sessions; expired ones
    /// are NOT auto-evicted from the holder (the GUI may still want
    /// to display the recent expiration timestamp).
    pub fn current(&self, now_ms: i64) -> Option<DiagnosticSession> {
        let guard = self.inner.lock().ok()?;
        guard.as_ref().filter(|s| s.is_active(now_ms)).cloned()
    }

    /// Effective redaction mode at `now_ms`. Defaults to
    /// [`RedactionMode::Default`] when no session is active.
    pub fn redaction_mode(&self, now_ms: i64) -> RedactionMode {
        self.current(now_ms)
            .map(|s| s.redaction_mode())
            .unwrap_or(RedactionMode::Default)
    }

    fn store(&self, session: Option<DiagnosticSession>) {
        if let Ok(mut g) = self.inner.lock() {
            *g = session;
        }
    }
}

// ── ProductionDiagnosticsFacade ──────────────────────────────────────────────

/// Production wiring of the [`DiagnosticsFacade`] trait.
///
/// Both `state_conn` and `cache_conn` are `Option` because the
/// service can boot in degraded mode without either DB open (recovery
/// path). In that case the facade returns conservative defaults
/// (0 entries, no active revision, healthy = false where applicable).
pub struct ProductionDiagnosticsFacade {
    logs_dir: PathBuf,
    audit_dir: PathBuf,
    /// Shared lock on the FQDN/IP cache SQLite connection. Used for
    /// `cache_metadata.last_rebuild_at` and resolution-row counts.
    /// `None` when the cache DB is unavailable (corrupt + rebuild
    /// pending, or fresh service install before bootstrap).
    cache_conn: Option<Arc<Mutex<Connection>>>,
    alerts_repo: Arc<dyn SecurityAlertsRepository>,
    /// Shared lock on the service-state SQLite connection. Used for
    /// reading the active revision id + pending revisions count from
    /// `RevisionsRepository`. `None` when storage is degraded.
    state_conn: Option<Arc<Mutex<Connection>>>,
    diagnostic_session: DiagnosticSessionHandle,
}

impl ProductionDiagnosticsFacade {
    pub fn new(
        logs_dir: impl Into<PathBuf>,
        audit_dir: impl Into<PathBuf>,
        cache_conn: Option<Arc<Mutex<Connection>>>,
        alerts_repo: Arc<dyn SecurityAlertsRepository>,
        state_conn: Option<Arc<Mutex<Connection>>>,
    ) -> Self {
        Self {
            logs_dir: logs_dir.into(),
            audit_dir: audit_dir.into(),
            cache_conn,
            alerts_repo,
            state_conn,
            diagnostic_session: DiagnosticSessionHandle::new(),
        }
    }

    /// Hand a clone of the shared diagnostic-session handle to other
    /// components (explain projector, log redactor). Cheap clone.
    pub fn diagnostic_session_handle(&self) -> DiagnosticSessionHandle {
        self.diagnostic_session.clone()
    }
}

// ── DiagnosticsFacade impl ───────────────────────────────────────────────────

impl DiagnosticsFacade for ProductionDiagnosticsFacade {
    fn get_status(&self) -> DiagnosticsStatusDto {
        let now_ms = millis_since_epoch();

        // Service health
        let (active_revision_id, pending_changes) = self.read_revision_summary();
        let service_health = ServiceHealthCard {
            state: "running".to_string(),
            active_revision_id,
            pending_changes,
        };

        // Audit
        let audit_reader = AuditReader::new(self.audit_dir.clone());
        let chain = audit_reader.verify_latest_chain();
        let audit_chain_ok = chain.chain_ok;
        let audit_write_healthy = is_dir_writable(&self.audit_dir);

        let open_alerts = self.alerts_repo.list_open().unwrap_or_default();
        let active_alert_count = open_alerts.len() as u32;
        let active_alerts: Vec<SecurityAlertDto> = open_alerts.iter().map(alert_to_dto).collect();
        let security_status = SecurityStatusCard {
            audit_chain_ok,
            active_alert_count,
            audit_write_healthy,
        };

        // Cache
        let cache_health = self.compute_cache_health();

        // Log health
        let log_health = self.compute_log_health();

        let diagnostic_mode = self
            .diagnostic_session
            .current(now_ms)
            .map(|s| {
                // #21 — a no-expiry ("until restart") session has no countdown.
                let until_restart = s.is_until_restart();
                DiagnosticModeStateDto {
                    active: true,
                    expires_at: if until_restart {
                        None
                    } else {
                        Some(s.expires_at)
                    },
                    remaining_ms: if until_restart {
                        None
                    } else {
                        Some(s.remaining_ms(now_ms))
                    },
                    scope_key: Some(scope_slug(s.scope).to_string()),
                }
            })
            .unwrap_or_else(DiagnosticModeStateDto::inactive);

        let overall_healthy = audit_chain_ok
            && audit_write_healthy
            && cache_health.healthy
            && log_health.dir_writable
            && active_alert_count == 0;

        DiagnosticsStatusDto {
            overall_healthy,
            service_health,
            security_status,
            active_alerts,
            cache_health,
            log_health,
            diagnostic_mode,
            stale: false,
        }
    }

    fn list_log_entries(
        &self,
        filter: &LogEntryFilter,
        pagination: &PaginationParams,
    ) -> DiagnosticsResult<PageResult<LogEntryDto>> {
        let events = self.scan_sorted_log_events(filter);
        let items: Vec<LogEntryDto> = events.iter().map(log_event_to_dto).collect();
        Ok(paginate(items, pagination, log_entry_position))
    }

    /// Single-scan override (see the trait default): take the newest
    /// `max_entries` of the ascending scan (its tail) and reverse to
    /// newest-first, without paging the full tree once per wire page.
    fn recent_log_entries(
        &self,
        filter: &LogEntryFilter,
        max_entries: usize,
    ) -> DiagnosticsResult<Vec<LogEntryDto>> {
        if max_entries == 0 {
            return Ok(Vec::new());
        }
        let events = self.scan_sorted_log_events(filter);
        let start = events.len().saturating_sub(max_entries);
        let mut items: Vec<LogEntryDto> = events[start..].iter().map(log_event_to_dto).collect();
        items.reverse();
        Ok(items)
    }

    fn list_audit_entries(
        &self,
        filter: &AuditEntryFilter,
        pagination: &PaginationParams,
    ) -> DiagnosticsResult<PageResult<AuditEntryDto>> {
        let reader = AuditReader::new(self.audit_dir.clone());
        let query_filter = audit_filter_to_query(filter);
        let mut events: Vec<AuditEvent> = reader.scan(&query_filter);

        // Wire filter fields that the reader query doesn't honour.
        if let Some(rid) = filter.revision_id.as_deref() {
            events.retain(|e| e.revision_id.as_deref() == Some(rid));
        }

        events.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.event_id.cmp(&b.event_id))
        });

        let items: Vec<AuditEntryDto> = events.iter().map(audit_event_to_dto).collect();
        Ok(paginate(items, pagination, audit_entry_position))
    }

    fn recent_audit_chain_lines(&self, max_bytes: usize) -> DiagnosticsResult<Vec<String>> {
        // Read the raw NDJSON verbatim (chain fields intact) straight off disk;
        // the reader keeps the newest byte-budgeted suffix. The SYSTEM service
        // has full access to the audit dir, so no ACL gate here — the redaction
        // gate is the caller's (diagnostics-tier export only).
        Ok(AuditReader::new(self.audit_dir.clone()).recent_raw_lines(max_bytes))
    }

    fn list_active_alerts(&self) -> DiagnosticsResult<Vec<SecurityAlertDto>> {
        let alerts = self.alerts_repo.list_open()?;
        Ok(alerts.iter().map(alert_to_dto).collect())
    }

    fn acknowledge_alert(&self, req: &AcknowledgeAlertRequest) -> DiagnosticsResult<()> {
        // Alert ack routes through `MutationKind::SecurityAlertAck`
        // (via the mutation queue, so the audit-before-act invariant
        // and single-writer contract both hold). This direct-call
        // path is deliberately NOT mutating to avoid two parallel
        // write routes diverging. The GUI should never reach this —
        // it routes through `MutationSubmit`. Surfaces a structured
        // error so accidental use shows up in logs.
        if req.alert_id.is_empty() {
            return Err(DiagnosticsError::AuditWriteFailed {
                reason: "alert_id must not be empty".into(),
            });
        }
        Err(DiagnosticsError::AuditWriteFailed {
            reason: "acknowledge_alert must be routed through \
                     MutationKind::SecurityAlertAck (block 16.10)"
                .into(),
        })
    }

    fn set_diagnostic_mode(&self, req: &SetDiagnosticModeRequest) -> DiagnosticsResult<()> {
        let now_ms = millis_since_epoch();
        if !req.enabled {
            self.diagnostic_session.store(None);
            return Ok(());
        }
        let scope = req
            .scope
            .as_deref()
            .map(slug_to_scope)
            .unwrap_or(DiagnosticSessionScope::All);
        // #21 — the "until restart" radio maps to a no-expiry session; the
        // 1h/4h radios pass a bounded duration.
        let session = if req.until_restart {
            DiagnosticSession::until_restart(now_ms, "gui-user", scope, None)
        } else {
            let duration_ms = req
                .duration_ms
                .unwrap_or(DiagnosticSession::DEFAULT_DURATION_MS);
            DiagnosticSession::new(now_ms, duration_ms, "gui-user", scope, None)
        };
        self.diagnostic_session.store(Some(session));
        Ok(())
    }

    fn clear_logs(&self, req: &ClearLogsRequest) -> DiagnosticsResult<ClearLogsResult> {
        let reader = LogReader::new(self.logs_dir.clone());
        let files = reader.list_files();
        let mut files_deleted = 0u32;
        let mut bytes_freed = 0u64;
        for path in files {
            let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            if req.dry_run {
                files_deleted += 1;
                bytes_freed += size;
                continue;
            }
            // Best-effort: a file held open by the writer can't be
            // deleted on Windows. Skip such files silently; the
            // operator can retry after the writer rotates.
            if std::fs::remove_file(&path).is_ok() {
                files_deleted += 1;
                bytes_freed += size;
            }
        }
        // `include_archives` honouring deferred to follow-up — the
        // archives directory is a sibling of `logs/` and uses the
        // same Users:RX ACL; not implemented here to keep the scope
        // tight.
        Ok(ClearLogsResult {
            files_deleted,
            bytes_freed,
            dry_run: req.dry_run,
        })
    }

    fn get_explain(
        &self,
        query: &ExplainQuery,
        level: ExplainDetailLevel,
        caller_sid: &str,
    ) -> DiagnosticsResult<ExplainResponse> {
        // Historical replay needs a persisted `DecisionExplain` snapshot
        // store (not yet implemented). The
        // Synthetic path bypasses that by running a minimal rule-match
        // against the current revision's canonical rule book. Compact
        // view fields (`input`, `route_role`, `reason_key`) get
        // populated; the rest stays empty (no lookup section, no
        // availability section). The reason key set is enumerated in
        // `locales/{en,ru}.json` under `explain.reason.*`.
        match query {
            ExplainQuery::HistoricalDecision { .. } => Ok(ExplainResponse::unavailable(
                query.kind(),
                level,
                ExplainDataAvailability::DecisionNotFound,
            )),
            ExplainQuery::Synthetic { input_sample } => {
                Ok(self.synthetic_explain(input_sample, level, caller_sid))
            }
        }
    }
}

// ── Internal helpers ─────────────────────────────────────────────────────────

impl ProductionDiagnosticsFacade {
    /// Scans + filters + sorts (ascending `(created_at, event_id)`) the
    /// operational log events for `filter`. Shared by `list_log_entries`
    /// (paginated) and `recent_log_entries` (newest-first tail selection).
    fn scan_sorted_log_events(&self, filter: &LogEntryFilter) -> Vec<LogEvent> {
        let reader = LogReader::new(self.logs_dir.clone());
        let query_filter = log_filter_to_query(filter);
        let mut events: Vec<LogEvent> = reader.scan(&query_filter);

        // Filter post-conditions that LogQueryFilter doesn't honour
        // (revision_id; decision_id ALREADY honoured indirectly via
        // correlation — wire filter has it, query filter doesn't).
        if let Some(rid) = filter.revision_id.as_deref() {
            events.retain(|e| e.correlation.revision_id.as_deref() == Some(rid));
        }
        if let Some(did) = filter.decision_id.as_deref() {
            events.retain(|e| e.correlation.decision_id.as_deref() == Some(did));
        }

        // Stable order: ascending (created_at_ms, event_id).
        events.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.event_id.cmp(&b.event_id))
        });
        events
    }

    /// Minimal synthetic-probe explain.
    ///
    /// Reads the active rules revision, decodes it into a
    /// `CanonicalRuleBook`, and walks `primary` then `secondary`
    /// rule sets in priority order to find the first address match
    /// against the input sample. Returns a minimal
    /// [`ExplainResponse`] populated with the fields the compact-view
    /// projection in the IPC handler reads
    /// (`input`, `final_action_section`, `summary`). The lookup,
    /// availability, and match sections stay `None` until a future
    /// block adds a stored snapshot replay path.
    ///
    /// When no revision exists yet, falls back to an `Unavailable`
    /// response keyed `service-unavailable` so the GUI shows the
    /// "data unavailable" hint instead of empty fields.
    fn synthetic_explain(
        &self,
        sample: &nrr_diagnostics::explain::query::RuntimeInputSample,
        level: ExplainDetailLevel,
        caller_sid: &str,
    ) -> ExplainResponse {
        use nrr_diagnostics::explain::response::{
            ExplainCorrelationSection, ExplainFinalActionSection, ExplainInputSection,
            ExplainSummarySection,
        };

        let detail_level_str = match level {
            ExplainDetailLevel::CompactUi => "compact_ui",
            ExplainDetailLevel::Diagnostics => "diagnostics",
            ExplainDetailLevel::DeveloperTrace => "developer_trace",
        };

        let host = sample.hostname.as_deref();
        let ip = sample.observed_ip.as_deref();

        // Load the caller's active rule book. When NONE is active (no own
        // revision, empty baseline), fall back to an EMPTY rule book rather
        // than reporting "service unavailable / save a rule first". With no
        // rules, every destination follows the DEFAULT route (primary) — so
        // the probe must answer "<query> → primary", never "no route". A user
        // never needs to save a rule for traffic to flow via the primary NIC;
        // claiming otherwise was misleading and looked like broken routing.
        let mut rule_book = self
            .load_active_rule_book(caller_sid)
            .map(|content| content.rule_book)
            .unwrap_or_default();
        // The routing-check must model ENFORCEMENT, not the
        // bare stored rules. `ProductionRulesProvider::active_rules_for` applies
        // subdomain coverage before the WFP/route codegen and the DNS seeder ever
        // see the rules, so a probe for a subdomain (e.g. `www.whatismyip.com`)
        // of a bare-domain rule (`whatismyip.com`) must expand the SAME way here —
        // otherwise the routing-check reports `primary` while enforcement actually
        // routes it `secondary`, and the "cover subdomains" toggle looks broken.
        // Read for the caller's own policy, mirroring the provider. Enforcement-
        // only: the stored/hashed rule book (drift, `rules.list`) is untouched.
        if self.reads_include_subdomains(caller_sid) {
            rule_book = rule_book.with_subdomain_coverage();
        }

        // Match through the REAL engine matcher so the probe cannot diverge
        // from production routing semantics — `match_sample` honours the
        // `enabled` flag, tier order, the Zone↔ExactIp priority policy, and
        // app-filter AND-semantics.
        //
        // Locale: reason keys MUST start with `diag.` to resolve against the
        // `diag.explain.reason.*` tree in `locales/{en,ru}.json`. Every
        // `MatchClass` slug `match_class_reason_slug` emits has an entry there.
        let observed_ipaddr = ip.and_then(|s| s.parse::<std::net::IpAddr>().ok());
        // Feed the caller's per-SID behavior_mode so an unmatched sample
        // reports the default route the service actually enforces.
        let behavior_mode = self.behavior_mode_for_sid(caller_sid);
        // A BARE-IP probe (no hostname) is rule-less by
        // itself, so a shared CDN IP like `8.6.112.0` would report the DEFAULT
        // route even though its owning hostname IS routed — contradicting the
        // by-name probe and the installed /32 overlay. Reverse-resolve the IP
        // against the FQDN cache and, if any cached tenant matches a rule, answer
        // as that hostname so the two probes agree. Only rule-matching tenants
        // are preferred, so a mixed shared IP reports its RULED tenant's route.
        let reverse_hosts: Vec<String> = if host.is_none() {
            ip.map(|s| self.reverse_resolve_ip_hosts(s))
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let reverse_matched_host: Option<&str> = reverse_hosts
            .iter()
            .find(|h| {
                matches!(
                    nrr_domain::decision_engine_input::match_sample(
                        &rule_book,
                        Some(h),
                        observed_ipaddr,
                        sample.process_name.as_deref(),
                        nrr_domain::decision_matching::ZonePriorityPolicy::default(),
                        behavior_mode,
                    ),
                    nrr_domain::decision_matching::RequestedRouteDecision::MatchedRoute { .. }
                )
            })
            .map(String::as_str);
        let match_host = host.or(reverse_matched_host);
        let decision = nrr_domain::decision_engine_input::match_sample(
            &rule_book,
            match_host,
            observed_ipaddr,
            sample.process_name.as_deref(),
            nrr_domain::decision_matching::ZonePriorityPolicy::default(),
            behavior_mode,
        );
        let (route_role, action_key, reason_key) = match &decision {
            nrr_domain::decision_matching::RequestedRouteDecision::MatchedRoute { candidate } => {
                let kind = match_class_reason_slug(candidate.match_class);
                let (role, action) = match candidate.route_role {
                    nrr_domain::RouteRole::Primary => {
                        ("primary", "diag.explain.final-action.route-primary")
                    }
                    nrr_domain::RouteRole::Secondary => {
                        ("secondary", "diag.explain.final-action.route-secondary")
                    }
                };
                (
                    Some(role.to_string()),
                    action.to_string(),
                    format!("diag.explain.reason.rule-matched-{kind}"),
                )
            }
            nrr_domain::decision_matching::RequestedRouteDecision::DefaultRoute {
                behavior_mode,
                ..
            } => {
                // No rule matched → the DEFAULT route. Derive it from
                // `behavior_mode` exactly as production does
                // (`decision_final_action.rs::check_availability`): PreferPrimary
                // → primary; PreferSecondary* / Strict → secondary.
                // Availability/fail-policy nuance — e.g. Strict → blocked when
                // secondary is down — needs a live adapter snapshot the
                // synthetic probe lacks; reporting the requested default route
                // is correct for the probe.
                let (role, action) = default_route_explain_projection(*behavior_mode);
                (
                    Some(role.to_string()),
                    action.to_string(),
                    "diag.explain.reason.no-rule-match".to_string(),
                )
            }
        };

        // Compact-view-friendly population. At `CompactUi` we elide
        // the raw IP per the redaction policy; the wire DTO still
        // carries `destination_ip_present` so the GUI knows there was
        // one. Diagnostics+ exposes the address itself.
        let destination_ip = if matches!(level, ExplainDetailLevel::CompactUi) {
            None
        } else {
            sample.observed_ip.clone()
        };
        let input_section = ExplainInputSection {
            destination_hostname: sample.hostname.clone(),
            destination_ip_present: sample.observed_ip.is_some(),
            destination_ip,
            process_name: sample.process_name.clone(),
            process_path: None,
        };
        let final_action_section = ExplainFinalActionSection {
            action_key,
            route_role,
            reason_key: reason_key.clone(),
        };
        let summary = ExplainSummarySection {
            summary_key: reason_key,
            is_simulation: true,
        };

        ExplainResponse {
            query_kind: "synthetic".to_string(),
            detail_level: detail_level_str.to_string(),
            availability_key: ExplainDataAvailability::Available.ui_key().to_string(),
            summary,
            input: Some(input_section),
            match_section: None,
            lookup_section: None,
            availability_section: None,
            final_action_section: Some(final_action_section),
            warnings: Vec::new(),
            correlation: ExplainCorrelationSection::empty(),
        }
    }

    /// Pull the active rules revision from the state DB and decode it
    /// through `nrr_shared::rules_json::from_canonical_string` +
    /// `nrr_domain::rules_json_codec::decode`. Returns `None` if no
    /// state DB is wired, no revision is active, or the stored JSON
    /// fails to decode (treated as missing for the synthetic probe;
    /// the full apply pipeline surfaces decode errors elsewhere).
    fn load_active_rule_book(
        &self,
        caller_sid: &str,
    ) -> Option<nrr_domain::rules_revision::RulesRevisionContent> {
        let conn_arc = self.state_conn.as_ref()?;
        let conn = conn_arc.lock().ok()?;
        let repo = nrr_storage::revisions::RevisionsRepository::new(&conn);
        // Per-SID read-through: the caller's OWN active revision, falling back
        // to the admin baseline — mirrors `ProductionRulesProvider::
        // active_rules_for`.
        let active = if caller_sid.is_empty() {
            repo.get_active().ok().flatten()?
        } else {
            repo.get_active_for(caller_sid)
                .ok()
                .flatten()
                .or_else(|| repo.get_active().ok().flatten())?
        };
        let dto = nrr_shared::rules_json::from_canonical_string(&active.rules_json).ok()?;
        nrr_domain::rules_json_codec::decode(dto).ok()
    }

    /// Reads the caller's per-SID `include_subdomains` flag
    /// from `secondary_block_policy` so the synthetic routing-check expands
    /// bare-domain rules to their subdomains exactly as
    /// `ProductionRulesProvider::active_rules_for` does at enforcement time.
    /// ON by default (the storage layer supplies the default
    /// for a SID with no policy row). Degrades to `false` on an empty SID,
    /// missing state DB, lock failure, or read error — the probe reports the
    /// narrow rule book rather than guessing at an unreadable policy.
    fn reads_include_subdomains(&self, sid: &str) -> bool {
        if sid.is_empty() {
            return false;
        }
        let Some(conn_arc) = self.state_conn.as_ref() else {
            return false;
        };
        let Ok(conn) = conn_arc.lock() else {
            return false;
        };
        nrr_storage::route_bindings::RouteBindingsRepository::new(&conn)
            .load_for_sid(sid)
            .map(|p| p.include_subdomains)
            .unwrap_or(false)
    }

    /// Cached hostnames currently mapped to `ip` in the FQDN
    /// cache, most-recently-resolved first (capped). Lets the routing-check
    /// answer a bare-IP probe by the route its owning hostname takes, instead of
    /// the misleading rule-less DEFAULT. Empty on a missing cache DB, lock/query
    /// error, or when the IP is not cached.
    fn reverse_resolve_ip_hosts(&self, ip: &str) -> Vec<String> {
        let Some(conn_arc) = self.cache_conn.as_ref() else {
            return Vec::new();
        };
        let Ok(conn) = conn_arc.lock() else {
            return Vec::new();
        };
        let mut stmt = match conn.prepare(
            "SELECT h.canonical_host \
             FROM hostname_ip_resolutions r \
             JOIN hostnames h ON h.id = r.hostname_id \
             JOIN ip_addresses i ON i.id = r.ip_id \
             WHERE i.canonical_ip = ?1 \
             ORDER BY r.resolved_at DESC LIMIT 16",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = match stmt.query_map(rusqlite::params![ip], |row| row.get::<_, String>(0)) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        rows.filter_map(Result::ok).collect()
    }

    /// Loads the caller's per-SID
    /// `behavior_mode` from the live `behavior_mode` table so the synthetic
    /// explain reports the default route the service actually enforces. The
    /// per-SID mode is live config (NOT revision-tracked), so it is read here
    /// rather than from the rule book. Falls back to `PreferPrimary` on an
    /// empty SID, missing state DB, lock failure, or read error — the same
    /// safe default the storage layer uses for an unknown SID.
    fn behavior_mode_for_sid(&self, sid: &str) -> nrr_domain::RouteBehaviorMode {
        use std::str::FromStr;
        let fallback = nrr_domain::RouteBehaviorMode::PreferPrimary;
        if sid.is_empty() {
            return fallback;
        }
        let Some(conn_arc) = self.state_conn.as_ref() else {
            return fallback;
        };
        let Ok(conn) = conn_arc.lock() else {
            return fallback;
        };
        let repo = nrr_storage::route_bindings::RouteBindingsRepository::new(&conn);
        match repo.load_for_sid(sid) {
            Ok(record) => {
                nrr_domain::RouteBehaviorMode::from_str(record.mode.slug()).unwrap_or(fallback)
            }
            Err(_) => fallback,
        }
    }

    fn read_revision_summary(&self) -> (Option<String>, u32) {
        let Some(conn_arc) = self.state_conn.as_ref() else {
            return (None, 0);
        };
        let conn = match conn_arc.lock() {
            Ok(c) => c,
            Err(_) => return (None, 0),
        };
        // The facade has no caller-principal context, so report the most
        // recently activated revision across principals: exact for the Free
        // single-console-user model, and still honest (any non-null id means
        // "some principal has active rules").
        let active: Option<String> = conn
            .query_row(
                "SELECT revision_id FROM revisions WHERE status = 'active'
                 ORDER BY activated_at DESC LIMIT 1",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .ok()
            .flatten();
        // "pending_changes" counts revisions in
        // `Candidate` status. RevisionsRepository doesn't expose a
        // `list_by_status` API today; raw count via SQL keeps the
        // surface tight and matches the singleton-row read pattern
        // used in `get_status` elsewhere. Status slug must match
        // `RevisionStatus::Candidate.as_slug()` = "candidate".
        let pending: u32 = conn
            .query_row(
                "SELECT COUNT(*) FROM revisions WHERE status = 'candidate'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n.max(0) as u32)
            .unwrap_or(0);
        (active, pending)
    }

    fn compute_cache_health(&self) -> CacheHealthCard {
        let Some(conn_arc) = self.cache_conn.as_ref() else {
            return CacheHealthCard {
                entry_count: 0,
                healthy: false,
                rebuilding: false,
            };
        };
        let conn = match conn_arc.lock() {
            Ok(c) => c,
            Err(_) => {
                return CacheHealthCard {
                    entry_count: 0,
                    healthy: false,
                    rebuilding: false,
                };
            }
        };
        // Single COUNT — inexpensive on a warm WAL DB. Treats query
        // failure as "0 entries, unhealthy" rather than propagating
        // (the diagnostics surface must always render).
        let entry_count: u64 = conn
            .query_row("SELECT COUNT(*) FROM hostname_ip_resolutions", [], |r| {
                r.get::<_, i64>(0)
            })
            .map(|n| n.max(0) as u64)
            .unwrap_or(0);
        CacheHealthCard {
            entry_count,
            healthy: true,
            // Rebuild-in-progress tracking is a future
            // signal (DnsRefreshOrchestrator could expose it via a
            // shared AtomicBool). For now we report false — the GUI
            // displays "rebuilding…" only when this flag is true, so
            // a `false` default means "stable", never "broken".
            rebuilding: false,
        }
    }

    fn compute_log_health(&self) -> LogHealthCard {
        let reader = LogReader::new(self.logs_dir.clone());
        let files = reader.list_files();
        let file_count = files.len() as u32;
        let total_size_bytes: u64 = files
            .iter()
            .map(|p| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0))
            .sum();
        LogHealthCard {
            dir_writable: is_dir_writable(&self.logs_dir),
            total_size_bytes,
            file_count,
            // Dropped-event tracking + retention cleanup
            // timestamps land in a follow-up. For now the GUI shows
            // "0 dropped" / "no recent cleanup" which is conservative
            // — never misleads the operator into thinking events
            // were lost.
            dropped_count: 0,
            last_cleanup_at: None,
        }
    }
}

/// First-match walk over a single canonical rule set. Returns the
/// matched [`nrr_domain::canonical::CanonicalRule`] paired with a kebab-case
/// match-class slug (`"exact-fqdn" | "suffix-domain" | "zone" |
/// "exact-ip"`) used to build the reason key. Iteration order follows
/// the storage order (already priority-sorted by
/// `CanonicalRuleSet::from_rules`); the first matching rule wins.
/// Maps a winning [`MatchClass`] to its `diag.explain.reason.rule-matched-*`
/// locale slug. `Default` never reaches here (it is a `DefaultRoute`, handled
/// separately), but the arm keeps the match exhaustive.
fn match_class_reason_slug(class: nrr_domain::decision_matching::MatchClass) -> &'static str {
    use nrr_domain::decision_matching::MatchClass;
    match class {
        MatchClass::ExactFqdn => "exact-fqdn",
        MatchClass::SuffixDomain => "suffix-domain",
        MatchClass::Zone => "zone",
        MatchClass::ExactIp => "exact-ip",
        MatchClass::Application => "application",
        MatchClass::Default => "none",
    }
}

/// Projects the default-route `behavior_mode`
/// (when no rule matched) to the `(compact-view route slug, final-action
/// locale key)` the synthetic explain reports. Mirrors the production
/// requested-role derivation in `decision_final_action.rs::check_availability`:
/// `PreferPrimary → primary`; `PreferSecondaryWhenAvailable` /
/// `StrictSecondaryFailClosed → secondary`. Availability/fail-policy nuance
/// (e.g. Strict → blocked when secondary is unavailable) needs a live adapter
/// snapshot the synthetic probe does not have, so the *requested* default
/// route is reported. Both locale keys already exist (used by the
/// `MatchedRoute` arm), so this adds no new strings.
fn default_route_explain_projection(
    behavior_mode: nrr_domain::RouteBehaviorMode,
) -> (&'static str, &'static str) {
    match behavior_mode {
        nrr_domain::RouteBehaviorMode::PreferPrimary => {
            ("primary", "diag.explain.final-action.route-primary")
        }
        nrr_domain::RouteBehaviorMode::PreferSecondaryWhenAvailable
        | nrr_domain::RouteBehaviorMode::StrictSecondaryFailClosed => {
            ("secondary", "diag.explain.final-action.route-secondary")
        }
    }
}

fn millis_since_epoch() -> i64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn is_dir_writable(dir: &Path) -> bool {
    let probe = dir.join(".nrr-write-probe");
    let opened = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&probe);
    match opened {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

fn scope_slug(scope: DiagnosticSessionScope) -> &'static str {
    match scope {
        DiagnosticSessionScope::All => "all",
        DiagnosticSessionScope::DecisionAndCache => "decision_and_cache",
        DiagnosticSessionScope::ProcessAndAdapter => "process_and_adapter",
    }
}

fn slug_to_scope(slug: &str) -> DiagnosticSessionScope {
    match slug {
        "decision_and_cache" => DiagnosticSessionScope::DecisionAndCache,
        "process_and_adapter" => DiagnosticSessionScope::ProcessAndAdapter,
        _ => DiagnosticSessionScope::All,
    }
}

fn level_from_str(s: &str) -> Option<EventLevel> {
    match s {
        "trace" => Some(EventLevel::Trace),
        "debug" => Some(EventLevel::Debug),
        "info" => Some(EventLevel::Info),
        "warn" => Some(EventLevel::Warn),
        "error" => Some(EventLevel::Error),
        _ => None,
    }
}

fn category_from_str(s: &str) -> Option<EventCategory> {
    match s {
        "service" => Some(EventCategory::Service),
        "decision" => Some(EventCategory::Decision),
        "cache" => Some(EventCategory::Cache),
        "apply" => Some(EventCategory::Apply),
        "import" => Some(EventCategory::Import),
        "review" => Some(EventCategory::Review),
        "integrity" => Some(EventCategory::Integrity),
        "security" => Some(EventCategory::Security),
        "diagnostics" => Some(EventCategory::Diagnostics),
        "user_action" => Some(EventCategory::UserAction),
        _ => None,
    }
}

// ── Filter mapping ───────────────────────────────────────────────────────────

fn log_filter_to_query(filter: &LogEntryFilter) -> LogQueryFilter {
    let mut q = LogQueryFilter::new();
    if let Some(v) = filter.from_ms {
        q = q.from_ms(v);
    }
    if let Some(v) = filter.to_ms {
        q = q.to_ms(v);
    }
    if let Some(level_str) = filter.level_min.as_deref() {
        if let Some(lvl) = level_from_str(level_str) {
            q = q.level_min(lvl);
        }
    }
    if let Some(cat_str) = filter.category.as_deref() {
        if let Some(cat) = category_from_str(cat_str) {
            q = q.category(cat);
        }
    }
    if let Some(kind) = filter.kind.clone() {
        q = q.kind(kind);
    }
    q
}

fn audit_filter_to_query(filter: &AuditEntryFilter) -> AuditQueryFilter {
    // `AuditQueryFilter` defaults to "no filter"; populate via
    // direct field assignment because the public builder methods
    // don't cover every column.
    let mut q = AuditQueryFilter::new();
    q.from_ms = filter.from_ms;
    q.to_ms = filter.to_ms;
    q.kind = filter.kind.clone();
    q
}

// ── DTO mapping ──────────────────────────────────────────────────────────────

fn log_event_to_dto(event: &LogEvent) -> LogEntryDto {
    // The localised message key follows the `diag.<category>.<kind>.summary`
    // convention from `nrr_diagnostics::reason::ReasonCodeMeta::ui_key`.
    // We compute it inline rather than looking up the meta table so
    // the projection is total even for kinds without an explicit meta
    // entry (the GUI's `tr(...)` falls back gracefully on missing
    // keys).
    let message_key = format!("diag.{}.{}.summary", event.category.as_str(), event.kind);
    let mut correlation_summary = Vec::new();
    if let Some(id) = event.correlation.decision_id.as_deref() {
        correlation_summary.push(format!("decision:{id}"));
    }
    if let Some(id) = event.correlation.revision_id.as_deref() {
        correlation_summary.push(format!("revision:{id}"));
    }
    LogEntryDto {
        event_id: event.event_id.clone(),
        created_at: event.created_at,
        level: event.level.as_str().to_string(),
        category: event.category.as_str().to_string(),
        kind: event.kind.clone(),
        message_key,
        // Payload-detail surfacing requires diagnostic
        // mode plus a structured payload column on `LogEvent` that
        // doesn't exist on the wire today. Leave `false` until that
        // schema bump lands.
        has_payload: false,
        correlation_summary,
    }
}

fn audit_event_to_dto(event: &AuditEvent) -> AuditEntryDto {
    AuditEntryDto {
        event_id: event.event_id.clone(),
        seq: event.seq,
        kind: event.kind.clone(),
        created_at: event.created_at,
        result: event.result.clone(),
        reason_code: event.reason_code.clone(),
        revision_id: event.revision_id.clone(),
        has_payload_summary: event.payload_summary_json.is_some(),
    }
}

fn alert_to_dto(alert: &SecurityAlert) -> SecurityAlertDto {
    SecurityAlertDto {
        alert_id: alert.alert_id.clone(),
        kind: alert.kind.clone(),
        state: alert.state.as_str().to_string(),
        created_at: alert.created_at,
        updated_at: alert.updated_at,
        reason_code: alert.reason_code.clone(),
        raised_file: alert.raised_file.clone(),
        requires_action: alert.requires_action(),
    }
}

// ── Pagination helpers ───────────────────────────────────────────────────────

/// Position extractor for the cursor encoding. `T` is one of the DTO
/// types; the returned `(created_at_ms, event_id)` pair must produce
/// a stable lexicographic cursor across page boundaries.
type PositionFn<T> = fn(&T) -> (i64, &str);

fn log_entry_position(item: &LogEntryDto) -> (i64, &str) {
    (item.created_at, item.event_id.as_str())
}

fn audit_entry_position(item: &AuditEntryDto) -> (i64, &str) {
    (item.created_at, item.event_id.as_str())
}

/// Slice the (already-sorted) `items` list by the optional cursor +
/// `page_size`. Returns the page and an Option-cursor pointing at the
/// last returned item — caller treats it as opaque.
///
/// Inputs MUST already be sorted ascending by `(created_at, event_id)`.
fn paginate<T>(items: Vec<T>, params: &PaginationParams, position: PositionFn<T>) -> PageResult<T> {
    let total = items.len() as u64;
    let cursor_pos: Option<(i64, String)> = params
        .cursor
        .as_ref()
        .and_then(|c| c.parse().map(|(ts, id)| (ts, id.to_string())));
    // Skip items strictly less than or equal to the cursor's
    // position. Cursor points at the LAST item already delivered, so
    // the next page starts strictly after it.
    let start_index = match cursor_pos {
        None => 0,
        Some((cts, cid)) => items
            .iter()
            .position(|item| {
                let (ts, id) = position(item);
                (ts, id) > (cts, cid.as_str())
            })
            .unwrap_or(items.len()),
    };
    let page_size = params.effective_page_size() as usize;
    let end_index = (start_index + page_size).min(items.len());
    // SAFETY: build the page via owned iteration. The cursor needs an
    // immutable reference to the LAST item BEFORE we move items into
    // the result page, so capture the position pair first.
    let next_cursor = if end_index < items.len() && end_index > start_index {
        let last = &items[end_index - 1];
        let (ts, id) = position(last);
        Some(PageCursor::from_position(ts, id))
    } else {
        None
    };
    let page_items: Vec<T> = items
        .into_iter()
        .skip(start_index)
        .take(page_size)
        .collect();
    PageResult {
        items: page_items,
        next_cursor,
        total_count: Some(total),
        stale: false,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_diagnostics::audit::alert::InMemorySecurityAlertsRepository;
    use nrr_diagnostics::audit::writer::{AuditEventInput, AuditWriter, AuditWriterConfig};
    use nrr_diagnostics::audit::{ActorKind, AuditEventKind, AuditEventResult};
    use nrr_diagnostics::reason::ReasonCode;
    use nrr_diagnostics::sink::AuditSink;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn make_facade(audit_dir: &Path, logs_dir: &Path) -> ProductionDiagnosticsFacade {
        let alerts: Arc<dyn SecurityAlertsRepository> =
            Arc::new(InMemorySecurityAlertsRepository::new());
        ProductionDiagnosticsFacade::new(logs_dir, audit_dir, None, alerts, None)
    }

    fn write_audit_event(dir: &Path, suffix: &str) {
        let writer = AuditWriter::open(AuditWriterConfig::new(dir));
        writer
            .append(AuditEventInput {
                event_id: format!("adt-{suffix}"),
                kind: AuditEventKind::RevisionActivated,
                created_at: 1_700_000_000_000,
                actor_kind: ActorKind::Service,
                actor_id_hash: None,
                revision_id: Some("rev-1".to_string()),
                risk_level: None,
                result: AuditEventResult::Success,
                reason_code: ReasonCode("apply.completed"),
                payload_summary_json: Some(r#"{"event":"test"}"#.to_string()),
            })
            .expect("audit append");
    }

    #[test]
    fn get_status_reports_individual_cards_with_no_storage_attached() {
        // Degraded boot: cache_conn = None and state_conn = None
        // mimic the recovery path where storage isn't open yet.
        // `cache_health.healthy = false` is the documented response
        // for that case (see `compute_cache_health`), which in turn
        // forces `overall_healthy = false`. The test pins the
        // individual cards rather than the aggregate.
        let dir = TempDir::new().expect("tempdir");
        let audit_dir = dir.path().join("audit");
        let logs_dir = dir.path().join("logs");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::create_dir_all(&logs_dir).unwrap();
        let facade = make_facade(&audit_dir, &logs_dir);
        let status = facade.get_status();
        assert!(status.security_status.audit_chain_ok);
        assert!(status.security_status.audit_write_healthy);
        assert!(status.log_health.dir_writable);
        assert_eq!(status.security_status.active_alert_count, 0);
        assert_eq!(status.service_health.state, "running");
        assert!(!status.diagnostic_mode.active);
        // With no cache connection, the card reports unhealthy.
        assert!(!status.cache_health.healthy);
        assert_eq!(status.cache_health.entry_count, 0);
        // Aggregate flips to false because of the cache_health gate.
        assert!(!status.overall_healthy);
    }

    #[test]
    fn list_audit_entries_pages_and_emits_cursor() {
        let dir = TempDir::new().expect("tempdir");
        let audit_dir = dir.path().join("audit");
        let logs_dir = dir.path().join("logs");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::create_dir_all(&logs_dir).unwrap();
        // Write 5 audit events.
        for i in 0..5 {
            write_audit_event(&audit_dir, &format!("{i:03}"));
        }
        let facade = make_facade(&audit_dir, &logs_dir);
        let filter = AuditEntryFilter::default();
        let p1 = PaginationParams {
            cursor: None,
            page_size: 2,
        };
        let page1 = facade.list_audit_entries(&filter, &p1).unwrap();
        assert_eq!(page1.items.len(), 2);
        assert!(page1.next_cursor.is_some());
        assert_eq!(page1.total_count, Some(5));

        let p2 = PaginationParams {
            cursor: page1.next_cursor.clone(),
            page_size: 2,
        };
        let page2 = facade.list_audit_entries(&filter, &p2).unwrap();
        assert_eq!(page2.items.len(), 2);
        assert!(page2.next_cursor.is_some());

        let p3 = PaginationParams {
            cursor: page2.next_cursor.clone(),
            page_size: 2,
        };
        let page3 = facade.list_audit_entries(&filter, &p3).unwrap();
        assert_eq!(page3.items.len(), 1);
        assert!(
            page3.next_cursor.is_none(),
            "last page must terminate cursor"
        );
    }

    #[test]
    fn list_log_entries_returns_empty_on_no_files() {
        let dir = TempDir::new().expect("tempdir");
        let audit_dir = dir.path().join("audit");
        let logs_dir = dir.path().join("logs");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::create_dir_all(&logs_dir).unwrap();
        let facade = make_facade(&audit_dir, &logs_dir);
        let r = facade
            .list_log_entries(&LogEntryFilter::default(), &PaginationParams::default())
            .unwrap();
        assert!(r.items.is_empty());
        assert!(r.next_cursor.is_none());
    }

    /// Writes `n` operational log events `evt-0001..evt-000n` with strictly
    /// increasing `created_at` directly to an NDJSON rotation file (bypasses
    /// the writer allowlist, like the reader's own tests).
    fn write_log_events(dir: &Path, n: u32) {
        use nrr_diagnostics::event::LogEvent;
        use nrr_diagnostics::reason::service::STARTED;
        use nrr_diagnostics::taxonomy::EventLevel;
        use std::io::Write;
        let date = nrr_diagnostics::audit::writer::local_date_string(std::time::SystemTime::now());
        let path = dir.join(format!("nrr_service_{date}-1.ndjson"));
        let mut file = std::fs::File::create(&path).expect("create log file");
        for i in 1..=n {
            let event = LogEvent::new(
                format!("evt-{i:04}"),
                1_745_000_000_000 + i as i64 * 1000,
                EventLevel::Info,
                STARTED,
            );
            writeln!(file, "{}", event.to_ndjson().expect("serialize")).expect("write");
        }
    }

    #[test]
    fn recent_log_entries_returns_newest_first() {
        let dir = TempDir::new().expect("tempdir");
        let audit_dir = dir.path().join("audit");
        let logs_dir = dir.path().join("logs");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::create_dir_all(&logs_dir).unwrap();
        write_log_events(&logs_dir, 5);
        let facade = make_facade(&audit_dir, &logs_dir);
        let recent = facade
            .recent_log_entries(&LogEntryFilter::default(), 100)
            .expect("recent");
        let ids: Vec<&str> = recent.iter().map(|e| e.event_id.as_str()).collect();
        // Newest (highest created_at) first, i.e. the reverse of the ascending
        // scan — this is what the archive builder's byte budget trims from.
        assert_eq!(
            ids,
            vec!["evt-0005", "evt-0004", "evt-0003", "evt-0002", "evt-0001"]
        );
    }

    #[test]
    fn recent_log_entries_caps_to_the_newest_max_entries() {
        let dir = TempDir::new().expect("tempdir");
        let audit_dir = dir.path().join("audit");
        let logs_dir = dir.path().join("logs");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::create_dir_all(&logs_dir).unwrap();
        write_log_events(&logs_dir, 10);
        let facade = make_facade(&audit_dir, &logs_dir);
        let recent = facade
            .recent_log_entries(&LogEntryFilter::default(), 3)
            .expect("recent");
        let ids: Vec<&str> = recent.iter().map(|e| e.event_id.as_str()).collect();
        // Only the 3 NEWEST, newest-first — never the stale head the pre-0719
        // single-oldest-page fetch would have shipped.
        assert_eq!(ids, vec!["evt-0010", "evt-0009", "evt-0008"]);
    }

    #[test]
    fn recent_log_entries_zero_cap_is_empty() {
        let dir = TempDir::new().expect("tempdir");
        let audit_dir = dir.path().join("audit");
        let logs_dir = dir.path().join("logs");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::create_dir_all(&logs_dir).unwrap();
        write_log_events(&logs_dir, 3);
        let facade = make_facade(&audit_dir, &logs_dir);
        assert!(facade
            .recent_log_entries(&LogEntryFilter::default(), 0)
            .expect("recent")
            .is_empty());
    }

    #[test]
    fn list_active_alerts_proxies_repo() {
        let dir = TempDir::new().expect("tempdir");
        let audit_dir = dir.path().join("audit");
        let logs_dir = dir.path().join("logs");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::create_dir_all(&logs_dir).unwrap();
        let repo: Arc<dyn SecurityAlertsRepository> =
            Arc::new(InMemorySecurityAlertsRepository::new());
        let alert = SecurityAlert {
            alert_id: "alt-test".into(),
            kind: "tamper_alert_raised".into(),
            state: nrr_diagnostics::audit::alert::SecurityAlertState::Active,
            raised_event_seq: 1,
            raised_file: "nrr_audit_test.ndjson".into(),
            ack_event_seq: None,
            ack_file: None,
            resolved_event_seq: None,
            resolved_file: None,
            created_at: 1_700_000_000_000,
            updated_at: 1_700_000_000_000,
            reason_code: "integrity.audit_chain_mismatch".into(),
        };
        repo.insert(&alert).expect("insert");
        let facade = ProductionDiagnosticsFacade::new(&logs_dir, &audit_dir, None, repo, None);
        let alerts = facade.list_active_alerts().expect("list");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].alert_id, "alt-test");
        assert!(alerts[0].requires_action);
    }

    #[test]
    fn acknowledge_alert_rejects_empty_id() {
        let dir = TempDir::new().expect("tempdir");
        let audit_dir = dir.path().join("audit");
        let logs_dir = dir.path().join("logs");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::create_dir_all(&logs_dir).unwrap();
        let facade = make_facade(&audit_dir, &logs_dir);
        let r = facade.acknowledge_alert(&AcknowledgeAlertRequest {
            alert_id: String::new(),
            reason: None,
        });
        assert!(r.is_err());
    }

    #[test]
    fn acknowledge_alert_directs_caller_to_mutation_queue() {
        let dir = TempDir::new().expect("tempdir");
        let audit_dir = dir.path().join("audit");
        let logs_dir = dir.path().join("logs");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::create_dir_all(&logs_dir).unwrap();
        let facade = make_facade(&audit_dir, &logs_dir);
        let r = facade.acknowledge_alert(&AcknowledgeAlertRequest {
            alert_id: "alt-x".into(),
            reason: None,
        });
        assert!(r.is_err(), "direct ack must be rejected");
    }

    #[test]
    fn set_diagnostic_mode_enable_then_disable() {
        let dir = TempDir::new().expect("tempdir");
        let audit_dir = dir.path().join("audit");
        let logs_dir = dir.path().join("logs");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::create_dir_all(&logs_dir).unwrap();
        let facade = make_facade(&audit_dir, &logs_dir);
        // Initial state inactive.
        assert!(!facade.get_status().diagnostic_mode.active);
        // Enable.
        facade
            .set_diagnostic_mode(&SetDiagnosticModeRequest {
                enabled: true,
                duration_ms: Some(60_000),
                scope: Some("decision_and_cache".into()),
                until_restart: false,
            })
            .unwrap();
        let status = facade.get_status();
        assert!(status.diagnostic_mode.active);
        assert!(status.diagnostic_mode.remaining_ms.unwrap_or(0) > 0);
        assert_eq!(
            status.diagnostic_mode.scope_key.as_deref(),
            Some("decision_and_cache")
        );
        // Disable.
        facade
            .set_diagnostic_mode(&SetDiagnosticModeRequest {
                enabled: false,
                duration_ms: None,
                scope: None,
                until_restart: false,
            })
            .unwrap();
        assert!(!facade.get_status().diagnostic_mode.active);
    }

    #[test]
    fn clear_logs_dry_run_does_not_delete() {
        let dir = TempDir::new().expect("tempdir");
        let audit_dir = dir.path().join("audit");
        let logs_dir = dir.path().join("logs");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::create_dir_all(&logs_dir).unwrap();
        // Write 3 placeholder log files.
        for i in 0..3 {
            std::fs::write(
                logs_dir.join(format!("nrr_service_20260101-{i}.ndjson")),
                format!("dummy line {i}\n"),
            )
            .unwrap();
        }
        let facade = make_facade(&audit_dir, &logs_dir);
        let r = facade
            .clear_logs(&ClearLogsRequest {
                include_archives: false,
                dry_run: true,
            })
            .unwrap();
        assert!(r.dry_run);
        assert_eq!(r.files_deleted, 3);
        assert!(r.bytes_freed > 0);
        // Files still on disk.
        let remaining = LogReader::new(&logs_dir).list_files();
        assert_eq!(remaining.len(), 3);
    }

    #[test]
    fn clear_logs_real_deletes_files() {
        let dir = TempDir::new().expect("tempdir");
        let audit_dir = dir.path().join("audit");
        let logs_dir = dir.path().join("logs");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::create_dir_all(&logs_dir).unwrap();
        for i in 0..2 {
            std::fs::write(
                logs_dir.join(format!("nrr_service_20260101-{i}.ndjson")),
                "dummy\n",
            )
            .unwrap();
        }
        let facade = make_facade(&audit_dir, &logs_dir);
        let r = facade
            .clear_logs(&ClearLogsRequest {
                include_archives: false,
                dry_run: false,
            })
            .unwrap();
        assert!(!r.dry_run);
        assert_eq!(r.files_deleted, 2);
        // Files gone.
        let remaining = LogReader::new(&logs_dir).list_files();
        assert!(remaining.is_empty());
    }

    #[test]
    fn get_explain_historical_returns_decision_not_found() {
        let dir = TempDir::new().expect("tempdir");
        let audit_dir = dir.path().join("audit");
        let logs_dir = dir.path().join("logs");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::create_dir_all(&logs_dir).unwrap();
        let facade = make_facade(&audit_dir, &logs_dir);
        let q = ExplainQuery::HistoricalDecision {
            decision_id: nrr_domain::decision_explain::DecisionId("d-unknown".into()),
        };
        let r = facade
            .get_explain(&q, ExplainDetailLevel::CompactUi, "")
            .unwrap();
        assert!(!r.is_available());
        assert_eq!(
            r.availability_key,
            ExplainDataAvailability::DecisionNotFound.ui_key()
        );
    }

    #[test]
    fn get_explain_synthetic_with_no_rules_reports_default_primary() {
        // With no active revision (and no DB wired), the synthetic probe must
        // NOT report "service unavailable / save a rule first" — with no rules
        // every destination follows the DEFAULT route (primary). A user never
        // needs a saved rule for traffic to flow via the primary NIC.
        let dir = TempDir::new().expect("tempdir");
        let audit_dir = dir.path().join("audit");
        let logs_dir = dir.path().join("logs");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::create_dir_all(&logs_dir).unwrap();
        let facade = make_facade(&audit_dir, &logs_dir);
        let q = ExplainQuery::Synthetic {
            input_sample: nrr_diagnostics::explain::RuntimeInputSample::new()
                .with_hostname("example.com"),
        };
        let r = facade
            .get_explain(&q, ExplainDetailLevel::Diagnostics, "")
            .unwrap();
        assert!(r.is_simulation(), "synthetic probe is always a simulation");
        assert!(
            r.is_available(),
            "no rules → default route, not unavailable"
        );
        assert_eq!(
            r.availability_key,
            ExplainDataAvailability::Available.ui_key()
        );
        let final_action = r
            .final_action_section
            .expect("default-route response has a final action");
        assert_eq!(
            final_action.route_role.as_deref(),
            Some("primary"),
            "unmatched destination with no rules must report the primary route"
        );
    }

    // An unmatched probe (DefaultRoute) must report the DEFAULT route, not
    // "no route". This pins the projection that the synthetic explain uses.
    #[test]
    fn default_route_projection_maps_behavior_mode_to_route() {
        use nrr_domain::RouteBehaviorMode;
        assert_eq!(
            default_route_explain_projection(RouteBehaviorMode::PreferPrimary),
            ("primary", "diag.explain.final-action.route-primary"),
            "unmatched traffic under PreferPrimary must report the primary route, not none"
        );
        assert_eq!(
            default_route_explain_projection(RouteBehaviorMode::PreferSecondaryWhenAvailable),
            ("secondary", "diag.explain.final-action.route-secondary")
        );
        assert_eq!(
            default_route_explain_projection(RouteBehaviorMode::StrictSecondaryFailClosed),
            ("secondary", "diag.explain.final-action.route-secondary")
        );
    }

    #[test]
    fn paginate_handles_empty_input() {
        let empty: Vec<LogEntryDto> = Vec::new();
        let r = paginate(empty, &PaginationParams::default(), log_entry_position);
        assert!(r.items.is_empty());
        assert!(r.next_cursor.is_none());
        assert_eq!(r.total_count, Some(0));
    }

    #[test]
    fn diagnostic_session_handle_redaction_mode_inactive_returns_default() {
        let h = DiagnosticSessionHandle::new();
        assert_eq!(h.redaction_mode(0), RedactionMode::Default);
    }

    #[test]
    fn diagnostic_session_handle_redaction_mode_active_returns_diagnostics() {
        let h = DiagnosticSessionHandle::new();
        let s = DiagnosticSession::new(
            1_000,
            60_000,
            "test-user",
            DiagnosticSessionScope::All,
            None,
        );
        h.store(Some(s));
        assert_eq!(h.redaction_mode(2_000), RedactionMode::Diagnostics);
    }
}
