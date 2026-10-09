//! What the facade does under each of its methods: health computation, log and
//! audit scans, explain projection, archive assembly.

use super::*;

// ── Internal helpers ─────────────────────────────────────────────────────────

impl ProductionDiagnosticsFacade {
    /// The newest `limit` log events before `before` that match `filter` and
    /// that `audience` may see, newest first.
    ///
    /// The operational log is ONE machine-wide stream: a line about routing
    /// carries the principal it was done for, everything else (boot, adapters,
    /// service lifecycle) belongs to the machine. So a principal-scoped reader
    /// keeps the machine lines and its own, and nothing of anybody else's.
    pub(super) fn log_page_for(
        &self,
        filter: &LogEntryFilter,
        audience: &DiagnosticsAudience,
        before: Option<(i64, &str)>,
        limit: usize,
    ) -> LogPage {
        let Some(query_filter) = log_filter_to_query(filter) else {
            return LogPage::default();
        };
        LogReader::new(self.logs_dir.clone()).page_newest_first(
            &query_filter,
            audience,
            before,
            limit,
            &self.log_index,
        )
    }

    /// Synthetic-probe explain: the caller's active rule book asked through the
    /// engine's own matcher. The match and lookup sections are filled when an
    /// address rule decided (a literal-IP Block, a network), so the GUI can
    /// name it.
    pub(super) fn synthetic_explain(
        &self,
        sample: &nrr_diagnostics::explain::query::RuntimeInputSample,
        level: ExplainDetailLevel,
        caller_sid: &str,
    ) -> ExplainResponse {
        use nrr_diagnostics::explain::response::{
            ExplainCorrelationSection, ExplainFinalActionSection, ExplainInputSection,
            ExplainLookupSection, ExplainMatchSection, ExplainSummarySection,
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
        // see the rules, so a probe for a subdomain (e.g. `www.site.example`)
        // of a bare-domain rule (`site.example`) must expand the SAME way here —
        // otherwise the routing-check reports `primary` while enforcement actually
        // routes it `secondary`, and the "cover subdomains" toggle looks broken.
        // Read for the caller's own policy, mirroring the provider. Enforcement-
        // only: the stored/hashed rule book (drift, `rules.list`) is untouched.
        rule_book = crate::verify_overlay::effective(&rule_book, caller_sid);
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
        let mut decision = nrr_domain::decision_engine_input::match_sample(
            &rule_book,
            match_host,
            observed_ipaddr,
            sample.process_name.as_deref(),
            zone_policy,
            behavior_mode,
        );
        // A name probed without an address: enforcement acts on the addresses
        // the name resolves to, so a literal-IP Block on any cached one of
        // them is the answer, whatever the name rules say.
        let mut blocking_ip = literal_block_ip(&decision, observed_ipaddr);
        // The cached address a network rule decided the name by, when it did.
        let mut network_ip = None;
        if let (Some(name), None) = (host, observed_ipaddr) {
            let cached = self.forward_resolve_host_ips(name);
            if let Some((ip, veto)) = literal_block_veto(
                &rule_book,
                name,
                &cached,
                sample.process_name.as_deref(),
                zone_policy,
                behavior_mode,
            ) {
                decision = veto;
                blocking_ip = Some(ip);
            } else if let Some((ip, by_network)) = network_decision(
                &rule_book,
                name,
                &cached,
                sample.process_name.as_deref(),
                zone_policy,
                behavior_mode,
            ) {
                decision = by_network;
                network_ip = Some(ip);
            }
        }
        let matched_network = match &decision {
            nrr_domain::decision_matching::RequestedRouteDecision::MatchedRoute { candidate }
                if candidate.match_class == nrr_domain::decision_matching::MatchClass::Subnet =>
            {
                network_rule_text(&rule_book, &candidate.rule_id)
            }
            _ => None,
        };
        // The engine's answer stands, but a winner enforcement skips for its
        // shape must not read as enforced.
        let shape_not_enforced = match &decision {
            nrr_domain::decision_matching::RequestedRouteDecision::MatchedRoute { candidate } => {
                rule_book
                    .primary
                    .rules()
                    .iter()
                    .chain(rule_book.secondary.rules())
                    .find(|r| r.id == candidate.rule_id)
                    .is_some_and(|r| !crate::wfp_codegen::rule_shape_enforced(r))
            }
            _ => false,
        };
        let (route_role, action_key, mut reason_key) = match &decision {
            nrr_domain::decision_matching::RequestedRouteDecision::MatchedRoute { candidate }
                if candidate.action == nrr_domain::RuleAction::Block =>
            {
                let reason = if blocking_ip.is_some() && host.is_some() {
                    "diag.explain.reason.blocked-by-ip-rule".to_string()
                } else if network_ip.is_some() {
                    "diag.explain.reason.blocked-by-network-rule".to_string()
                } else {
                    format!(
                        "diag.explain.reason.rule-matched-{}",
                        match_class_reason_slug(candidate.match_class)
                    )
                };
                (
                    None,
                    "diag.explain.final-action.blocked".to_string(),
                    reason,
                )
            }
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
        if shape_not_enforced {
            reason_key = "diag.explain.reason.rule-shape-not-enforced".to_string();
        }

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
            route_role: route_role.clone(),
            reason_key: reason_key.clone(),
        };
        let summary = ExplainSummarySection {
            summary_key: reason_key,
            is_simulation: true,
        };
        // Which rule blocked it, so the GUI can name the address from its own
        // rules list; the address itself only at Diagnostics+, as documented.
        let (match_section, lookup_section) = match (&decision, blocking_ip) {
            (
                nrr_domain::decision_matching::RequestedRouteDecision::MatchedRoute { candidate },
                Some(ip),
            ) => (
                Some(ExplainMatchSection {
                    outcome_key: "explain.match.rule_matched".to_string(),
                    matched_rule_id: Some(candidate.rule_id.as_str().to_string()),
                    match_class_label: Some("ExactIp".to_string()),
                    route_role: None,
                    conflict_resolved: false,
                    default_reason_key: None,
                    matched_network: None,
                }),
                Some(ExplainLookupSection {
                    cache_state_key: "explain.lookup.cache_hit".to_string(),
                    cache_hit: observed_ipaddr.is_none(),
                    has_errors: false,
                    selected_ip: (!matches!(level, ExplainDetailLevel::CompactUi))
                        .then(|| ip.to_string()),
                    is_multi_ip: false,
                    ttl_seconds: None,
                }),
            ),
            // A network rule decided: name the network, and the cached address
            // it was decided by when the probe gave none.
            (
                nrr_domain::decision_matching::RequestedRouteDecision::MatchedRoute { candidate },
                None,
            ) if matched_network.is_some() => (
                Some(ExplainMatchSection {
                    outcome_key: "explain.match.rule_matched".to_string(),
                    matched_rule_id: Some(candidate.rule_id.as_str().to_string()),
                    match_class_label: Some("Subnet".to_string()),
                    route_role: route_role.clone(),
                    conflict_resolved: false,
                    default_reason_key: None,
                    matched_network: matched_network.clone(),
                }),
                network_ip.map(|ip| ExplainLookupSection {
                    cache_state_key: "explain.lookup.cache_hit".to_string(),
                    cache_hit: true,
                    has_errors: false,
                    selected_ip: (!matches!(level, ExplainDetailLevel::CompactUi))
                        .then(|| ip.to_string()),
                    is_multi_ip: false,
                    ttl_seconds: None,
                }),
            ),
            _ => (None, None),
        };

        ExplainResponse {
            query_kind: "synthetic".to_string(),
            detail_level: detail_level_str.to_string(),
            availability_key: ExplainDataAvailability::Available.ui_key().to_string(),
            summary,
            input: Some(input_section),
            match_section,
            lookup_section,
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
        let dto = crate::production_rules_provider::read_stored_rules(
            &active.rules_json,
            &active.revision_id,
        )
        .ok()?;
        nrr_domain::rules_json_codec::decode(dto, nrr_domain::rules_file::HostPlatform::compiled())
            .ok()
    }

    /// The caller's Zone-vs-ExactIp order, as enforcement reads it.
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

    /// The caller's `include_subdomains` flag, so the probe expands bare-domain
    /// rules exactly as the rules provider does. `false` on any read failure:
    /// the narrow book beats a guess at an unreadable policy.
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

    /// The addresses the FQDN cache holds for `host`, newest first. Empty
    /// without a cache or on any read error: the probe then answers from the
    /// name rules alone, as it did before it looked.
    fn forward_resolve_host_ips(&self, host: &str) -> Vec<std::net::IpAddr> {
        let Some(conn_arc) = self.cache_conn.as_ref() else {
            return Vec::new();
        };
        let Ok(conn) = conn_arc.lock() else {
            return Vec::new();
        };
        let canonical = host.trim().trim_end_matches('.').to_ascii_lowercase();
        let Ok(mut stmt) = conn.prepare(
            "SELECT i.canonical_ip \
             FROM hostname_ip_resolutions r \
             JOIN hostnames h ON h.id = r.hostname_id \
             JOIN ip_addresses i ON i.id = r.ip_id \
             WHERE h.canonical_host = ?1 \
             ORDER BY r.resolved_at DESC LIMIT 16",
        ) else {
            return Vec::new();
        };
        let Ok(rows) = stmt.query_map(rusqlite::params![canonical], |row| row.get::<_, String>(0))
        else {
            return Vec::new();
        };
        rows.filter_map(Result::ok)
            .filter_map(|ip| ip.parse().ok())
            .collect()
    }

    /// Cached hostnames mapped to `ip`, newest first (capped), so a bare-IP
    /// probe answers by the route its owning hostname takes. Empty on any
    /// read failure.
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

    /// Whose revision `revision_id` is; `None` when the row or the store is gone.
    pub(super) fn principal_of_revision(&self, revision_id: &str) -> Option<String> {
        let conn = self.state_conn.as_ref()?.lock().ok()?;
        nrr_storage::revisions::RevisionsRepository::new(&conn)
            .principal_of(revision_id)
            .ok()
            .flatten()
    }

    /// The active revision id and the candidate count `audience` may see.
    ///
    /// A principal gets its own: its active revision, else the baseline it
    /// reads through to (what `service.health` answers too), and only its own
    /// candidates. The machine gets the latest activation and every candidate.
    pub(super) fn read_revision_summary(
        &self,
        audience: &DiagnosticsAudience,
    ) -> (Option<String>, u32) {
        let Some(Ok(conn)) = self.state_conn.as_ref().map(|c| c.lock()) else {
            return (None, 0);
        };
        match audience.principal() {
            Some(principal) => {
                let repo = nrr_storage::revisions::RevisionsRepository::new(&conn);
                let active = [principal, nrr_storage::BASELINE_PRINCIPAL]
                    .into_iter()
                    .find_map(|p| repo.active_identity_for(p).ok().flatten())
                    .map(|(revision_id, _)| revision_id);
                let pending = count_candidates(
                    &conn,
                    "SELECT COUNT(*) FROM revisions
                     WHERE status = 'candidate' AND principal = ?1",
                    rusqlite::params![principal],
                );
                (active, pending)
            }
            None => {
                let active = conn
                    .query_row(
                        "SELECT revision_id FROM revisions WHERE status = 'active'
                         ORDER BY activated_at DESC LIMIT 1",
                        [],
                        |r| r.get::<_, String>(0),
                    )
                    .optional()
                    .ok()
                    .flatten();
                let pending = count_candidates(
                    &conn,
                    "SELECT COUNT(*) FROM revisions WHERE status = 'candidate'",
                    [],
                );
                (active, pending)
            }
        }
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
            // Rebuild-in-progress tracking is not surfaced yet.
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

/// The first of `cached_ips` a literal-IP Block vetoes for `host`, with the
/// engine's answer for it. Goes through `match_sample`, so the probe cannot
/// disagree with the matcher about what a veto is.
pub(super) fn literal_block_veto(
    rule_book: &nrr_domain::canonical::CanonicalRuleBook,
    host: &str,
    cached_ips: &[std::net::IpAddr],
    process_name: Option<&str>,
    zone_policy: nrr_domain::decision_matching::ZonePriorityPolicy,
    behavior_mode: nrr_domain::RouteBehaviorMode,
) -> Option<(
    std::net::IpAddr,
    nrr_domain::decision_matching::RequestedRouteDecision,
)> {
    cached_ips.iter().find_map(|ip| {
        let decision = nrr_domain::decision_engine_input::match_sample(
            rule_book,
            Some(host),
            Some(*ip),
            process_name,
            zone_policy,
            behavior_mode,
        );
        literal_block_ip(&decision, Some(*ip)).map(|ip| (ip, decision))
    })
}

/// `ip` when `decision` is a literal-IP Block on it.
fn literal_block_ip(
    decision: &nrr_domain::decision_matching::RequestedRouteDecision,
    ip: Option<std::net::IpAddr>,
) -> Option<std::net::IpAddr> {
    use nrr_domain::decision_matching::{MatchClass, RequestedRouteDecision};
    match decision {
        RequestedRouteDecision::MatchedRoute { candidate }
            if candidate.action == nrr_domain::RuleAction::Block
                && candidate.match_class == MatchClass::ExactIp =>
        {
            ip
        }
        _ => None,
    }
}

/// The first of `cached_ips` a network rule decides `host` by, with the
/// engine's answer for it. A name rule narrower than the network still wins
/// inside `match_sample`, so only a host no name rule claims more closely is
/// answered here — what enforcement does to a connection to that address.
pub(super) fn network_decision(
    rule_book: &nrr_domain::canonical::CanonicalRuleBook,
    host: &str,
    cached_ips: &[std::net::IpAddr],
    process_name: Option<&str>,
    zone_policy: nrr_domain::decision_matching::ZonePriorityPolicy,
    behavior_mode: nrr_domain::RouteBehaviorMode,
) -> Option<(
    std::net::IpAddr,
    nrr_domain::decision_matching::RequestedRouteDecision,
)> {
    use nrr_domain::decision_matching::{MatchClass, RequestedRouteDecision};
    cached_ips.iter().find_map(|ip| {
        let decision = nrr_domain::decision_engine_input::match_sample(
            rule_book,
            Some(host),
            Some(*ip),
            process_name,
            zone_policy,
            behavior_mode,
        );
        matches!(
            &decision,
            RequestedRouteDecision::MatchedRoute { candidate }
                if candidate.match_class == MatchClass::Subnet
        )
        .then_some((*ip, decision))
    })
}

/// The network rule `rule_id` names, spelled as the rules list shows it.
pub(super) fn network_rule_text(
    rule_book: &nrr_domain::canonical::CanonicalRuleBook,
    rule_id: &nrr_domain::RuleId,
) -> Option<String> {
    let address = rule_book
        .primary
        .rules()
        .iter()
        .chain(rule_book.secondary.rules())
        .find(|r| r.id == *rule_id)?
        .address_match
        .as_ref()?;
    address
        .ip_blocks()
        .is_some()
        .then(|| address.to_display_string())
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
        MatchClass::Subnet => "subnet",
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

/// `COUNT(*)` of candidate revisions; the slug is `RevisionStatus::Candidate`'s.
fn count_candidates(conn: &Connection, sql: &str, params: impl rusqlite::Params) -> u32 {
    conn.query_row(sql, params, |r| r.get::<_, i64>(0))
        .map_or(0, |n| u32::try_from(n.max(0)).unwrap_or(u32::MAX))
}
