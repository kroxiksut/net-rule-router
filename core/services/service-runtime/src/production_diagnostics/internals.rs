//! What the facade does under each of its methods: health computation, log and
//! audit scans, explain projection, archive assembly.

use super::*;

// ── Internal helpers ─────────────────────────────────────────────────────────

impl ProductionDiagnosticsFacade {
    /// Scans + filters + sorts (ascending `(created_at, event_id)`) the
    /// operational log events for `filter`. Shared by `list_log_entries`
    /// (paginated) and `recent_log_entries` (newest-first tail selection).
    /// Scan, ordered, and narrowed to what `audience` may see.
    ///
    /// The operational log is ONE machine-wide stream: a line about routing
    /// carries the principal it was done for, everything else (boot, adapters,
    /// service lifecycle) belongs to the machine. So a principal-scoped reader
    /// keeps the machine lines and its own, and nothing of anybody else's.
    pub(super) fn scan_sorted_log_events_for(
        &self,
        filter: &LogEntryFilter,
        audience: &DiagnosticsAudience,
    ) -> Vec<LogEvent> {
        let reader = LogReader::new(self.logs_dir.clone());
        let query_filter = log_filter_to_query(filter);
        let mut events: Vec<LogEvent> = reader.scan(&query_filter);
        if let Some(principal) = audience.principal() {
            events.retain(|event| match event.principal.as_deref() {
                None => true,
                Some(owner) => owner == principal,
            });
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
    pub(super) fn synthetic_explain(
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
        let zone_policy = self.zone_policy_for_sid(caller_sid);
        // A BARE-IP probe (no hostname) is rule-less by
        // itself, so a shared CDN IP like `192.0.2.0` would report the DEFAULT
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
                        zone_policy,
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
            zone_policy,
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
        // The hostname went out in full at Compact while the IP beside it was
        // elided — the level gate protected one field of the pair and not the
        // other. Compact gets eTLD+1, which is what the redaction helper has
        // always produced for exactly this case.
        let destination_hostname = sample.hostname.as_deref().map(|hostname| {
            if matches!(level, ExplainDetailLevel::CompactUi) {
                redact_hostname(hostname, RedactionMode::Default).display_or_marker()
            } else {
                hostname.to_string()
            }
        });
        let input_section = ExplainInputSection {
            destination_hostname,
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
    /// The caller's Zone-vs-ExactIp order. The engine has always taken this as
    /// a parameter and both production callers passed the default, so the
    /// setting the rule model documents ("Exact IP wins by default;
    /// configurable") had no way to take effect.
    pub(super) fn zone_policy_for_sid(
        &self,
        sid: &str,
    ) -> nrr_domain::decision_matching::ZonePriorityPolicy {
        let prefer_ip = !self.reads_zone_priority_over_ip(sid);
        nrr_domain::decision_matching::ZonePriorityPolicy { prefer_ip }
    }

    fn reads_zone_priority_over_ip(&self, sid: &str) -> bool {
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
            .map(|p| p.zone_priority_over_ip)
            .unwrap_or(false)
    }

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

    pub(super) fn read_revision_summary(&self) -> (Option<String>, u32) {
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

    pub(super) fn compute_cache_health(&self) -> CacheHealthCard {
        let Some(conn_arc) = self.cache_conn.as_ref() else {
            return CacheHealthCard {
                entry_count: 0,
                healthy: false,
            };
        };
        let conn = match conn_arc.lock() {
            Ok(c) => c,
            Err(_) => {
                return CacheHealthCard {
                    entry_count: 0,
                    healthy: false,
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
        }
    }

    pub(super) fn compute_log_health(&self) -> LogHealthCard {
        let reader = LogReader::new(self.logs_dir.clone());
        let files = reader.list_files();
        let file_count = files.len() as u32;
        LogHealthCard {
            dir_writable: is_dir_writable(&self.logs_dir),
            total_size_bytes: total_bytes_of(&files),
            audit_size_bytes: total_bytes_of(
                &AuditReader::new(self.audit_dir.clone()).list_files(),
            ),
            file_count,
            // The writer's own counter, not a constant. A hardcoded zero was
            // described as conservative, but "0 dropped" is not a cautious
            // silence — it is a claim that nothing was lost, made by code that
            // never asked. With no writer attached the count is zero for the
            // honest reason: there is nothing writing to lose events.
            dropped_count: self
                .log_writer
                .as_ref()
                .map(|writer| writer.dropped_count())
                .unwrap_or(0),
            // TODO: retention has no completion timestamp to report yet; the
            // cleanup path would have to record when it last ran.
            last_cleanup_at: None,
        }
    }
}

/// Bytes on disk for a set of files. A file that cannot be stat'ed contributes
/// nothing: the number is a storage indicator, and a hole in it is better than
/// refusing to show any of it.
pub(super) fn total_bytes_of(files: &[std::path::PathBuf]) -> u64 {
    files
        .iter()
        .map(|p| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0))
        .sum()
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
pub(super) fn match_class_reason_slug(
    class: nrr_domain::decision_matching::MatchClass,
) -> &'static str {
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
pub(super) fn default_route_explain_projection(
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

pub(super) fn millis_since_epoch() -> i64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub(super) fn scope_slug(scope: DiagnosticSessionScope) -> &'static str {
    match scope {
        DiagnosticSessionScope::All => "all",
        DiagnosticSessionScope::DecisionAndCache => "decision_and_cache",
        DiagnosticSessionScope::ProcessAndAdapter => "process_and_adapter",
    }
}

pub(super) fn slug_to_scope(slug: &str) -> DiagnosticSessionScope {
    match slug {
        "decision_and_cache" => DiagnosticSessionScope::DecisionAndCache,
        "process_and_adapter" => DiagnosticSessionScope::ProcessAndAdapter,
        _ => DiagnosticSessionScope::All,
    }
}

pub(super) fn level_from_str(s: &str) -> Option<EventLevel> {
    match s {
        "trace" => Some(EventLevel::Trace),
        "debug" => Some(EventLevel::Debug),
        "info" => Some(EventLevel::Info),
        "warn" => Some(EventLevel::Warn),
        "error" => Some(EventLevel::Error),
        _ => None,
    }
}

pub(super) fn category_from_str(s: &str) -> Option<EventCategory> {
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
