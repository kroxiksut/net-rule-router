//! Production implementations for the
//! remaining trait positions in `IpcHandlerDeps` that block
//! `register_production_handlers`. Most are thin wrappers around existing
//! repos / aggregators; the `MutationExecutor` slot is intentionally a
//! placeholder until the real revision-flow orchestrator lands.
//!
//! Modules covered:
//! - `ProductionRulesSnapshotProvider` — reads active revision id from
//!   `RevisionsRepository`; returns empty `rows` (the rule-row decoder
//!   needs the rule-engine wiring, which lands separately).
//! - `ProductionRoutePolicySource` — `PerSidApplyOrchestrator`-shaped
//!   per-SID policy reader.
//! - `ProductionRoutePolicyProvider` / `ProductionRoutePolicyWriter` —
//!   IPC-shaped per-SID readers/writers.
//! - `ProductionMigrationStatusProvider` /
//!   `ProductionMigrationCompletionWriter` — GUI migration ledger.
//! - `NoopMutationExecutor` — returns "not implemented" for now.

use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use nrr_storage::route_bindings::{
    BehaviorMode, BindingSource, LinkProviderAppRecord, RouteBindingRecord,
    RouteBindingsRepository, RoutePolicyRecord,
};

use crate::ipc_handlers::mutation_token_store::StoredMutation;
use crate::ipc_handlers::operation_status_store::OperationError;
use crate::ipc_handlers::payloads::{
    BehaviorModeDto, BindingSourceDto, FirstPolicyDto, LinkProviderAppDto,
    MigrationStatusGetResponse, MutationKind, PrincipalDataPurgeResponse, ReviewRiskLevel,
    ReviewSummaryResponse, RouteBindingDto, RoutePolicyDto, RoutePolicyUpdateRequest, RuleRowEntry,
    RulesListResponse, RulesRouteFilter, SnapshotInterfacesResponse,
};
use crate::ipc_handlers::providers::{
    AdaptersSnapshotProvider, LinkProviderWriter, MigrationCompletionRecord,
    MigrationCompletionWriter, MigrationStatusProvider, MutationExecutor, MutationOutcome,
    PrincipalDataPurger, RoutePolicyProvider, RoutePolicyWriteError, RoutePolicyWriter,
    RulesSnapshotProvider,
};
use crate::per_sid_orchestrator::{
    PerSidBehaviorMode, PerSidBinding, PerSidPolicySnapshot, RoutePolicySource,
};

fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ── ProductionRulesSnapshotProvider ──────────────────────────────────────────

/// Reads the active revision from `RevisionsRepository::get_active`,
/// decodes its canonical `rules_json`, and projects each rule into the
/// `RuleRowEntry` rows the GUI table renders.
///
/// Slug mapping mirrors what the GUI model already uses (the
/// `nrr_shared::preset_parser` 4-slug set `zone | domain | exact-ip |
/// application`): a suffix-domain renders as `*.suffix`, an exact-FQDN as
/// the bare FQDN — both as the `domain` type. `validation_status` is
/// recomputed with `validate_rule_value` so the refetched table colours
/// identically to the cold-start snapshot.
pub struct ProductionRulesSnapshotProvider {
    conn: Arc<Mutex<Connection>>,
    /// Read-only OS `hosts`-file reader used to annotate rows whose exact
    /// hostname is pinned by the resolver's `hosts` file.
    /// The service runs as LocalSystem and reads the world-readable file —
    /// no new privileged path.
    hosts: Arc<dyn nrr_platform_api::hosts_file::HostsFileReader>,
    /// What the user's last main-link check found for their rule addresses.
    /// `None` leaves every row unannotated, which is how the table read before
    /// the check existed.
    verdicts: Option<Arc<crate::main_route_verdicts::MainRouteVerdicts>>,
    /// Destinations each application rule currently holds. `None` leaves the
    /// rows unannotated — the table simply does not say what an application
    /// rule is holding, which is how it read before.
    app_observations: Option<Arc<crate::app_observation_lookup::AppObservationStore>>,
}

impl ProductionRulesSnapshotProvider {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self {
            conn,
            hosts: Arc::new(nrr_platform_api::hosts_file::OsHostsFileReader::new()),
            verdicts: None,
            app_observations: None,
        }
    }

    /// Wire the store the main-link check writes into.
    #[must_use]
    pub fn with_main_route_verdicts(
        mut self,
        verdicts: Arc<crate::main_route_verdicts::MainRouteVerdicts>,
    ) -> Self {
        self.verdicts = Some(verdicts);
        self
    }

    /// Wire the observed destination store so an application rule can show
    /// what it is holding.
    #[must_use]
    pub fn with_app_observations(
        mut self,
        store: Arc<crate::app_observation_lookup::AppObservationStore>,
    ) -> Self {
        self.app_observations = Some(store);
        self
    }

    /// Construct with an explicit `hosts` reader (tests inject a fixture).
    pub fn with_hosts_reader(
        conn: Arc<Mutex<Connection>>,
        hosts: Arc<dyn nrr_platform_api::hosts_file::HostsFileReader>,
    ) -> Self {
        Self {
            conn,
            hosts,
            verdicts: None,
            app_observations: None,
        }
    }

    /// Read the `hosts` map once and annotate every eligible row in `resp`.
    /// `principal` is empty for the baseline read, which has no owner and
    /// therefore no main-link verdicts of its own.
    fn annotate(&self, resp: &mut RulesListResponse, principal: &str) {
        if resp.rows.is_empty() {
            return;
        }
        let map = self.hosts.snapshot();
        annotate_hosts_overrides(resp, &map);
        if let Some(store) = self.verdicts.as_ref() {
            if !principal.is_empty() {
                resp.main_route_pending = store.pending(principal);
                let now = std::time::Instant::now();
                for row in &mut resp.rows {
                    if row.rule_type != "domain" && row.rule_type != "zone" {
                        continue;
                    }
                    row.main_route = store
                        .get(principal, &row.match_value, now)
                        .map(|v| v.slug().to_string());
                }
            }
        }
        // The caller's own observations, where they are kept per user.
        if let Some(store) = self
            .app_observations
            .as_ref()
            .and_then(|store| store.scope_for(Some(principal)))
        {
            for row in &mut resp.rows {
                // Only a rule that actually produces host routes: an
                // application rule bound to the additional link, showing what
                // it took. A blocked or main-link row holds nothing.
                if row.rule_type != "application" || row.target_route != "secondary" {
                    continue;
                }
                let mut held: Vec<String> =
                    crate::app_observation_lookup::AppObservationLookup::ips_for_app(
                        store.as_ref(),
                        &row.match_value,
                    )
                    .into_iter()
                    .map(|ip| ip.to_string())
                    .collect();
                if held.is_empty() {
                    continue;
                }
                // The list is the only unbounded part of this response, and the
                // whole response has to fit one frame.
                let total = held.len();
                held.truncate(nrr_shared::ipc_payloads::MAX_PINNED_DESTINATIONS_PER_ROW);
                row.pinned_destinations = Some(held);
                row.pinned_destinations_total = Some(total);
            }
        }
    }
}

impl ProductionRulesSnapshotProvider {
    /// The rows of the book `principal` is under, read as the rules provider
    /// resolves it (a revision mid-activation, their own, then the baseline).
    /// Shared by the baseline-only `rules_snapshot` and the per-principal
    /// `rules_snapshot_for`.
    fn snapshot_in_force(
        &self,
        principal: &str,
        route_filter: RulesRouteFilter,
    ) -> RulesListResponse {
        let empty = |base_revision: Option<String>| RulesListResponse {
            rows: Vec::new(),
            supported_rule_types: rule_type_slugs(),
            active_revision_id: None,
            unrecognized: 0,
            main_route_pending: 0,
            base_revision,
        };
        let Ok(conn) = self.conn.lock() else {
            return empty(None);
        };
        match crate::production_rules_provider::book_in_force_for(&conn, principal) {
            Ok(Some(book)) => Self::project(&book, route_filter),
            Ok(None) => empty(Some(crate::production_rules_provider::base_revision_of(
                None,
            ))),
            Err(_) => empty(None),
        }
    }

    /// Project the book in force into the GUI rows.
    fn project(
        book: &crate::production_rules_provider::BookInForce,
        route_filter: RulesRouteFilter,
    ) -> RulesListResponse {
        let active_revision_id = book.revision_id.clone();
        let base_revision = Some(crate::production_rules_provider::base_revision_of(Some(
            book,
        )));
        // The stored JSON was validated on the write path; a decode
        // failure here means stale/corrupt data — surface the revision id
        // with no rows rather than erroring the whole read. Nothing to build
        // a write on, though.
        let Ok(dto) =
            crate::production_rules_provider::read_stored_rules(&book.rules_json, book.origin())
        else {
            return RulesListResponse {
                rows: Vec::new(),
                supported_rule_types: rule_type_slugs(),
                active_revision_id,
                unrecognized: 0,
                main_route_pending: 0,
                base_revision: None,
            };
        };

        let want_primary = matches!(
            route_filter,
            RulesRouteFilter::Primary | RulesRouteFilter::All
        );
        let want_secondary = matches!(
            route_filter,
            RulesRouteFilter::Secondary | RulesRouteFilter::All
        );
        // A rule this build cannot read is kept for a newer one, not shown:
        // a client would send it back rewritten as a rule it understands.
        let readable = |d: &&nrr_shared::rules_json::RuleDto| !d.is_unrecognized();
        let mut rows: Vec<RuleRowEntry> = Vec::new();
        let mut unrecognized = 0usize;
        if want_primary {
            unrecognized += dto.primary.iter().filter(|d| d.is_unrecognized()).count();
            rows.extend(
                dto.primary
                    .iter()
                    .filter(readable)
                    .map(|d| rule_dto_to_row(d, "primary")),
            );
        }
        if want_secondary {
            unrecognized += dto.secondary.iter().filter(|d| d.is_unrecognized()).count();
            rows.extend(
                dto.secondary
                    .iter()
                    .filter(readable)
                    .map(|d| rule_dto_to_row(d, "secondary")),
            );
        }
        RulesListResponse {
            rows,
            supported_rule_types: rule_type_slugs(),
            active_revision_id,
            unrecognized: u32::try_from(unrecognized).unwrap_or(u32::MAX),
            main_route_pending: 0,
            base_revision,
        }
    }
}

impl RulesSnapshotProvider for ProductionRulesSnapshotProvider {
    fn rules_snapshot(&self, route_filter: RulesRouteFilter) -> RulesListResponse {
        let mut resp = self.snapshot_in_force(nrr_storage::BASELINE_PRINCIPAL, route_filter);
        // The `hosts` read is file I/O, done with the DB lock released.
        self.annotate(&mut resp, "");
        resp
    }

    /// The caller's book, read through to the shared baseline while they have
    /// not diverged.
    fn rules_snapshot_for(
        &self,
        route_filter: RulesRouteFilter,
        principal: &str,
    ) -> RulesListResponse {
        let mut resp = self.snapshot_in_force(principal, route_filter);
        // The `hosts` read is file I/O, done with the DB lock released.
        self.annotate(&mut resp, principal);
        resp
    }

    fn recent_changes_for(
        &self,
        principal: &str,
        since: i64,
        now: i64,
    ) -> Result<nrr_shared::ipc_payloads::RulesRecentChangesResponse, String> {
        crate::recent_rule_changes::read_for(&self.conn, principal, since, now)
    }
}

/// Project one canonical `RuleDto` into a GUI `RuleRowEntry`. Prefers the
/// address-side match for the displayed type/value (an AND rule with both
/// an address and an app match shows the address; an app-only rule falls
/// back to the application pattern).
pub(crate) fn rule_dto_to_row(dto: &nrr_shared::rules_json::RuleDto, route: &str) -> RuleRowEntry {
    let (rule_type, mut match_value) = nrr_domain::rule_value_validation::wire_rule_values(dto)
        .next()
        .unwrap_or(("application", String::new()));
    let rule_type = rule_type.to_string();
    // The requests ride the value as the rules file writes them, so a table or
    // a file built from these rows keeps them.
    if let Some(app) = dto
        .app_match
        .as_ref()
        .filter(|_| rule_type == "application")
    {
        for (asked, flag) in [
            (
                app.include_child_processes,
                nrr_shared::preset_parser::CHILDREN_FLAG,
            ),
            (
                app.override_requested,
                nrr_shared::preset_parser::OVERRIDE_FLAG,
            ),
        ] {
            if asked {
                match_value.push(' ');
                match_value.push_str(flag);
            }
        }
    }
    // A Block-action rule displays as the "block" route regardless of which
    // bucket it physically lives in — set membership is enforcement-irrelevant
    // for a blocked rule (the WFP codegen drops it). A `?` rule shows its own
    // set and the `verify` flag.
    let verify = dto.action == nrr_shared::rules_json::RuleAction::VerifyPrimary;
    let target_route = match &dto.action {
        nrr_shared::rules_json::RuleAction::Route
        | nrr_shared::rules_json::RuleAction::VerifyPrimary => route.to_string(),
        nrr_shared::rules_json::RuleAction::Block => "block".to_string(),
        // `project` leaves such a rule out; the slug says what it is if one
        // ever gets here.
        nrr_shared::rules_json::RuleAction::Unrecognized(slug) => slug.clone(),
    };
    // A stored rule on a protected program is not applied; the row says why.
    let validation = match nrr_domain::protected_places::RuleEffect::from_route_slug(&target_route)
    {
        Some(effect) => nrr_domain::rule_value_validation::validate_rule_value_in(
            &rule_type,
            &match_value,
            effect,
            crate::protected_rules::places(),
        ),
        None => nrr_domain::rule_value_validation::validate_rule_value(&rule_type, &match_value),
    };
    let message_key = validation.message_key();
    RuleRowEntry {
        id: dto.id.clone(),
        rule_type,
        match_value,
        target_route,
        verify,
        comment: if dto.comment.is_empty() {
            None
        } else {
            Some(dto.comment.clone())
        },
        enabled: dto.enabled,
        validation_status: validation.status_slug().to_string(),
        validation_message_key: if message_key.is_empty() {
            None
        } else {
            Some(message_key.to_string())
        },
        // Both filled after the whole row set is projected — the hosts map
        // and the probe verdicts are each read once per snapshot, not per row.
        main_route: None,
        hosts_override: None,
        // Provenance travels verbatim: the GUI marks an app-authored row and
        // names the site it was added for, and nothing else in the pipeline
        // branches on it.
        origin: dto.origin.clone(),
        // Filled with the other annotations, once per snapshot.
        pinned_destinations: None,
        pinned_destinations_total: None,
    }
}

/// Annotate domain rows with the OS `hosts`-file override that pins their
/// hostname, or for a `*.x` row a name under it, in either family.
///
/// The resolver applies `hosts` entries before any traffic reaches NRR, so
/// this is an informational badge. Only matching rows are annotated; the full
/// `hosts` list never crosses the wire. Rows with no match (or of another
/// type) are left untouched.
fn annotate_hosts_overrides(
    resp: &mut RulesListResponse,
    hosts: &std::collections::HashMap<String, nrr_platform_api::hosts_file::HostsPin>,
) {
    if hosts.is_empty() {
        return;
    }
    let dto =
        |pin: &nrr_platform_api::hosts_file::HostsPin| nrr_shared::ipc_payloads::HostsOverrideDto {
            ip: pin.ip.to_string(),
            blocking: pin.blocking,
        };
    // `*.x` rows by suffix; zones/IPs/apps are not resolver hostnames.
    let mut suffixes: std::collections::HashMap<String, Vec<usize>> =
        std::collections::HashMap::new();
    for (at, row) in resp.rows.iter_mut().enumerate() {
        if row.rule_type != "domain" {
            continue;
        }
        let value = row.match_value.trim_start();
        if let Some(suffix) = value.strip_prefix("*.") {
            let key = nrr_platform_api::hosts_file::normalize_hostname(suffix);
            if !key.is_empty() {
                suffixes.entry(key).or_default().push(at);
            }
            continue;
        }
        let key = nrr_platform_api::hosts_file::normalize_hostname(value);
        if let Some(pin) = hosts.get(&key).filter(|_| !key.is_empty()) {
            row.hosts_override = Some(dto(pin));
        }
    }
    if suffixes.is_empty() {
        return;
    }
    // One pass over the file, each name walked up its own labels: a scan per
    // suffix row would cost the whole file once per rule. The first name in
    // name order speaks for the rule, so the badge does not change between reads.
    let mut first: std::collections::HashMap<
        &str,
        (&str, &nrr_platform_api::hosts_file::HostsPin),
    > = std::collections::HashMap::new();
    for (name, pin) in hosts {
        let mut tail = name.as_str();
        loop {
            if let Some((key, _)) = suffixes.get_key_value(tail) {
                let slot = first.entry(key.as_str()).or_insert((name.as_str(), pin));
                if name.as_str() < slot.0 {
                    *slot = (name.as_str(), pin);
                }
            }
            match tail.split_once('.') {
                Some((_, rest)) if !rest.is_empty() => tail = rest,
                _ => break,
            }
        }
    }
    for (suffix, rows) in &suffixes {
        if let Some((_, pin)) = first.get(suffix.as_str()) {
            for &at in rows {
                resp.rows[at].hosts_override = Some(dto(pin));
            }
        }
    }
}

fn rule_type_slugs() -> Vec<String> {
    vec![
        "zone".into(),
        "domain".into(),
        "exact-ip".into(),
        "application".into(),
    ]
}

// ── Per-SID policy source ────────────────────────────────────────────────────

/// Wraps `RouteBindingsRepository::load_for_sid` and shapes the result
/// for the per-SID apply orchestrator. Empty binding rows produce an
/// empty `PerSidPolicySnapshot` (the orchestrator treats it as
/// "no filters to install").
pub struct ProductionRoutePolicySource {
    conn: Arc<Mutex<Connection>>,
    /// Optional FQDN cache so DoH-resolver-list HOST entries (`resolver.example`)
    /// resolve for the lockdown. Host entries contribute nothing without it;
    /// the seed carries literal addresses, so the lockdown still works by IP.
    fqdn_cache: Option<Arc<dyn crate::fqdn_cache_lookup::FqdnCacheLookup>>,
    /// Set where the platform has no other way to turn browser DoH off.
    doh_lockdown_forced: bool,
    /// Users whose last read failed, with the reason. A failed read answers
    /// like an absent policy; this keeps the two apart.
    failed: Mutex<std::collections::HashMap<String, String>>,
}

impl ProductionRoutePolicySource {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self {
            conn,
            fqdn_cache: None,
            doh_lockdown_forced: false,
            failed: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Blocks DoH for every principal regardless of their toggle. For a
    /// platform whose service does not answer DNS itself: there the canary that
    /// switches browser DoH off is never served, and a browser resolving over
    /// HTTPS hides every subdomain a wildcard rule has to learn.
    pub fn with_doh_lockdown_forced(mut self) -> Self {
        self.doh_lockdown_forced = true;
        self
    }

    /// Wires the FQDN cache so DoH-resolver HOST entries resolve.
    pub fn with_fqdn_cache(
        mut self,
        fqdn_cache: Arc<dyn crate::fqdn_cache_lookup::FqdnCacheLookup>,
    ) -> Self {
        self.fqdn_cache = Some(fqdn_cache);
        self
    }

    /// Resolves the ENABLED DoH-resolver-list entries to the addresses the
    /// lockdown blocks: literal entries as-is, host entries through the FQDN
    /// cache with their AAAA answers kept — a dual-stack browser reaches the
    /// resolver over either family. An un-cached host yields nothing.
    fn resolve_doh_resolver_ips(&self, conn: &Connection) -> Vec<std::net::IpAddr> {
        use nrr_storage::doh_lockdown::{DohResolverEntriesRepository, DohTarget};
        let entries = match DohResolverEntriesRepository::new(conn).load_all() {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };
        let mut ips: Vec<std::net::IpAddr> = Vec::new();
        for entry in entries.into_iter().filter(|e| e.enabled) {
            match entry.target {
                DohTarget::Ip(ip) => ips.push(ip),
                DohTarget::Host(host) => {
                    if let Some(cache) = self.fqdn_cache.as_ref() {
                        ips.extend(cache.ips_for_hostname(&host));
                    }
                }
            }
        }
        ips.sort_unstable();
        ips.dedup();
        ips
    }
}

impl ProductionRoutePolicySource {
    fn note_read(&self, sid: &str, failure: Option<String>) {
        let mut failed = self.failed.lock().unwrap_or_else(|p| p.into_inner());
        match failure {
            Some(reason) => {
                if failed.insert(sid.to_owned(), reason.clone()).is_none() {
                    tracing::warn!(
                        target: "nrr::enforcement",
                        principal = sid,
                        reason = %reason,
                        "the routing policy could not be read: what is applied stays in force",
                    );
                }
            }
            None => {
                failed.remove(sid);
            }
        }
    }
}

impl RoutePolicySource for ProductionRoutePolicySource {
    fn read_failure_for(&self, sid: &str) -> Option<String> {
        self.failed
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .cloned()
    }

    fn load_for_sid(&self, sid: &str) -> Option<PerSidPolicySnapshot> {
        let Ok(conn) = self.conn.lock() else {
            self.note_read(sid, Some("state DB mutex poisoned".to_owned()));
            return None;
        };
        let repo = RouteBindingsRepository::new(&conn);
        let record = match repo.load_for_sid(sid) {
            Ok(record) => record,
            Err(e) => {
                self.note_read(sid, Some(e.to_string()));
                return None;
            }
        };
        self.note_read(sid, None);
        // Empty record → return None so orchestrator treats SID as
        // unbound. Records with at least one slot bound become a
        // populated snapshot.
        if record.primary.is_none() && record.secondary.is_none() {
            return None;
        }
        // Best-effort: a provider-set read failure must not
        // hide the policy (the exemption just stays glob-only that pass).
        let link_provider_exe_paths = repo
            .load_link_provider_apps(sid, "secondary")
            .unwrap_or_default()
            .into_iter()
            .map(|a| a.exe_path)
            .collect();
        let doh_lockdown_enabled = record.doh_lockdown_enabled || self.doh_lockdown_forced;
        let doh_lockdown_scope = if self.doh_lockdown_forced {
            nrr_storage::doh_lockdown::DohLockdownScope::Always
        } else {
            record.doh_lockdown_scope
        };
        // Forced is on for everyone; automatic is decided by the planner from
        // the rule book, so the list is resolved for it too.
        let doh_lockdown_auto = record.doh_lockdown_auto && !self.doh_lockdown_forced;
        // Resolve the DoH-resolver list only when the lockdown can be
        // on (avoid the list read + cache lookups otherwise).
        let doh_resolver_ips = if doh_lockdown_enabled || doh_lockdown_auto {
            self.resolve_doh_resolver_ips(&conn)
        } else {
            Vec::new()
        };
        let secondary_unset_blocks = secondary_unset_blocks(&conn, &record);
        let mut snapshot = PerSidPolicySnapshot {
            primary: record.primary.map(record_binding_to_per_sid),
            secondary: record.secondary.map(record_binding_to_per_sid),
            mode: behavior_mode_to_per_sid(record.mode),
            leak_protection: record.leak_protection,
            kill_switch_protocols: record.kill_switch_protocols,
            allow_dns_over_primary: record.allow_dns_over_primary,
            shared_ip_policy: record.shared_ip_policy,
            kill_switch_strict_shared_ips: record.kill_switch_strict_shared_ips,
            link_provider_exe_paths,
            doh_lockdown_enabled,
            doh_lockdown_scope,
            doh_lockdown_auto,
            doh_resolver_ips,
            auto_rules_mode: record.auto_rules_mode,
            primary_probe_auto: record.primary_probe_auto,
            primary_probe_timeout_ms: record.primary_probe_timeout_ms,
            primary_probe_max_targets: record.primary_probe_max_targets,
            primary_probe_repeat_secs: record.primary_probe_repeat_secs,
            local_networks_auto_accept: record.local_networks_auto_accept,
            zone_priority_over_ip: record.zone_priority_over_ip,
            app_rules_take_all_addresses: record.app_rules_take_all_addresses,
            guard_forwarded_traffic: record.forwarded_outage != "unprotected",
        };
        if secondary_unset_blocks {
            refuse_unbound_secondary_rules(&mut snapshot);
        }
        Some(snapshot)
    }
}

/// The administrator's install-time answer for additional-route rules while
/// no additional connection is bound: `block` refuses them. Only once a main
/// connection is bound — before that nothing at all is enforced. A policy that
/// cannot be read refuses too: the safe reading of an unknown Fail-Closed.
fn secondary_unset_blocks(conn: &Connection, record: &RoutePolicyRecord) -> bool {
    use nrr_storage::install_policy::{InstallPolicyRepository, SecondaryUnset};
    if record.primary.is_none() || record.secondary.is_some() {
        return false;
    }
    match InstallPolicyRepository::new(conn).get() {
        Ok(policy) => policy.secondary_unset == SecondaryUnset::Block,
        Err(_) => true,
    }
}

/// Leak protection in its narrowest form, `sites`: the addresses the
/// additional-route rules name are blocked, everything else goes out as it
/// would. Protection the user already turned on keeps their own choice.
fn refuse_unbound_secondary_rules(snapshot: &mut PerSidPolicySnapshot) {
    if snapshot.leak_protection.is_on() {
        return;
    }
    snapshot.leak_protection = nrr_domain::LeakProtection::Sites;
    // Without an additional connection there is nothing to prefer, and `sites`
    // is offered only under the main connection.
    snapshot.mode = PerSidBehaviorMode::PreferPrimary;
}

/// Production DoH resolver baseline store over the state DB.
pub struct ProductionDohResolverListStore {
    conn: Arc<Mutex<Connection>>,
}

impl ProductionDohResolverListStore {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

impl crate::ipc_handlers::doh_resolvers::DohResolverListStore for ProductionDohResolverListStore {
    fn get_all(
        &self,
    ) -> Result<Vec<nrr_shared::ipc_payloads::DohResolverEntryDto>, RoutePolicyWriteError> {
        use nrr_storage::doh_lockdown::DohResolverEntriesRepository;
        let conn = self
            .conn
            .lock()
            .map_err(|_| RoutePolicyWriteError::Storage("connection mutex poisoned".into()))?;
        let entries = DohResolverEntriesRepository::new(&conn)
            .load_all()
            .map_err(|e| RoutePolicyWriteError::Storage(format!("{e:?}")))?;
        Ok(entries.into_iter().map(doh_entry_to_dto).collect())
    }

    fn replace_all(
        &self,
        entries: &[nrr_shared::ipc_payloads::DohResolverEntryDto],
    ) -> Result<Vec<nrr_shared::ipc_payloads::DohResolverEntryDto>, RoutePolicyWriteError> {
        use nrr_storage::doh_lockdown::{
            DohResolverEntriesRepository, DohResolverEntry, DohTarget,
        };
        // Map DTOs → domain entries (validation already done in the handler;
        // skip any that still fail to parse, defensively).
        let domain: Vec<DohResolverEntry> = entries
            .iter()
            .filter_map(|e| {
                DohTarget::parse(&e.target_kind, &e.target).map(|target| DohResolverEntry {
                    target,
                    comment: e.comment.clone(),
                    enabled: e.enabled,
                })
            })
            .collect();
        let conn = self
            .conn
            .lock()
            .map_err(|_| RoutePolicyWriteError::Storage("connection mutex poisoned".into()))?;
        let repo = DohResolverEntriesRepository::new(&conn);
        repo.replace_all(&domain, now_secs())
            .map_err(|e| RoutePolicyWriteError::Storage(format!("{e:?}")))?;
        let stored = repo
            .load_all()
            .map_err(|e| RoutePolicyWriteError::Storage(format!("{e:?}")))?;
        Ok(stored.into_iter().map(doh_entry_to_dto).collect())
    }
}

fn doh_entry_to_dto(
    e: nrr_storage::doh_lockdown::DohResolverEntry,
) -> nrr_shared::ipc_payloads::DohResolverEntryDto {
    nrr_shared::ipc_payloads::DohResolverEntryDto {
        target_kind: e.target.kind_str().to_string(),
        target: e.target.value_str(),
        comment: e.comment,
        enabled: e.enabled,
    }
}

fn record_binding_to_per_sid(rec: RouteBindingRecord) -> PerSidBinding {
    PerSidBinding {
        stable_id: rec.stable_id,
        display_name: rec.display_name,
        user_confirmed: rec.user_confirmed,
        known_stable_ids: rec.known_stable_ids,
    }
}

fn behavior_mode_to_per_sid(mode: BehaviorMode) -> PerSidBehaviorMode {
    match mode {
        BehaviorMode::PreferPrimary => PerSidBehaviorMode::PreferPrimary,
        BehaviorMode::PreferSecondaryWhenAvailable => {
            PerSidBehaviorMode::PreferSecondaryWhenAvailable
        }
    }
}

// ── IPC-shaped route policy provider/writer ──────────────────────────────────

/// Returns the caller's per-SID `RoutePolicyDto`; `None` only for a SID that
/// never stored a policy.
pub struct ProductionRoutePolicyProvider {
    conn: Arc<Mutex<Connection>>,
}

impl ProductionRoutePolicyProvider {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

impl RoutePolicyProvider for ProductionRoutePolicyProvider {
    fn get_for_sid(&self, sid: &str) -> Option<RoutePolicyDto> {
        stored_policy(&self.conn, sid)
    }

    /// What [`apply_install_default_mode`] makes of a first save that names
    /// no route and no protection.
    fn first_policy(&self) -> Option<FirstPolicyDto> {
        let guard = self.conn.lock().ok()?;
        let policy = nrr_storage::install_policy::InstallPolicyRepository::new(&guard)
            .get()
            .ok()?;
        let mode = policy
            .default_route_mode
            .unwrap_or(BehaviorMode::PreferPrimary);
        Some(FirstPolicyDto {
            mode: storage_mode_to_dto(mode),
            leak_protection_at_least: policy
                .default_leak_protection
                .effective(storage_mode_to_domain(mode))
                .into(),
        })
    }
}

/// The caller's stored policy as the wire carries it.
fn stored_policy(conn: &Arc<Mutex<Connection>>, sid: &str) -> Option<RoutePolicyDto> {
    let (record, providers) = {
        let guard = conn.lock().ok()?;
        let repo = RouteBindingsRepository::new(&guard);
        // A policy with no adapter bound yet is still the user's: hiding it
        // made every client rebuild the next full write from defaults, so
        // binding an adapter after choosing the protections switched them off.
        if !repo.has_policy_for_sid(sid).ok()? {
            return None;
        }
        let record = repo.load_for_sid(sid).ok()?;
        // Best-effort — a provider-set read failure must not hide the policy.
        let providers = repo
            .load_link_provider_apps(sid, "secondary")
            .unwrap_or_default();
        (record, providers)
    };
    // Read after the lock is released: the rules provider takes it itself.
    let rules_need_names = rules_need_names_for(conn, sid, record.mode);
    Some(record_to_dto(record, providers, rules_need_names))
}

/// Whether the caller's rules need to see site names, read through the one
/// rules provider the service reads rules by.
fn rules_need_names_for(conn: &Arc<Mutex<Connection>>, sid: &str, mode: BehaviorMode) -> bool {
    use crate::per_sid_orchestrator::RulesProvider;
    crate::production_rules_provider::ProductionRulesProvider::new(Arc::clone(conn))
        .active_rules_for(sid)
        .is_some_and(|snapshot| {
            crate::rule_book_facts::needs_names_seen(
                &snapshot.rule_book,
                mode == BehaviorMode::PreferSecondaryWhenAvailable,
            )
        })
}

pub struct ProductionRoutePolicyWriter {
    conn: Arc<Mutex<Connection>>,
}

impl ProductionRoutePolicyWriter {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

impl RoutePolicyWriter for ProductionRoutePolicyWriter {
    fn stored_for_sid(&self, sid: &str) -> Option<RoutePolicyDto> {
        stored_policy(&self.conn, sid)
    }

    fn update_for_sid(
        &self,
        sid: &str,
        request: &RoutePolicyUpdateRequest,
    ) -> Result<RoutePolicyDto, RoutePolicyWriteError> {
        if sid.is_empty() {
            return Err(RoutePolicyWriteError::EmptySid);
        }
        let short_name_suffix = match request.short_name_suffix.trim() {
            "" => String::new(),
            raw => nrr_domain::rule_value_validation::normalize_network_domain(raw)
                .ok_or(RoutePolicyWriteError::InvalidNetworkDomain)?,
        };
        let mut record = RoutePolicyRecord {
            primary: request.primary.as_ref().map(dto_binding_to_record),
            secondary: request.secondary.as_ref().map(dto_binding_to_record),
            mode: dto_mode_to_storage(request.mode),
            leak_protection: request.leak_protection.into(),
            kill_switch_protocols: request.kill_switch_protocols,
            allow_dns_over_primary: request.allow_dns_over_primary,
            include_subdomains: request.include_subdomains,
            // Unknown slug (older/other peer) → the balanced default; never
            // silently widen routing beyond what the user picked.
            shared_ip_policy: nrr_domain::shared_ip::SharedIpPolicy::from_slug(
                &request.shared_ip_policy,
            )
            .unwrap_or_default(),
            resolve_hosts_bypass: request.resolve_hosts_bypass,
            // DoH-lockdown toggle + scope. Unknown scope slug
            // (older peer) → the default (leak-protection-only); never silently
            // widen the lockdown beyond the pick.
            doh_lockdown_enabled: request.doh_lockdown_enabled,
            doh_lockdown_scope: nrr_storage::doh_lockdown::DohLockdownScope::from_slug(
                &request.doh_lockdown_scope,
            )
            .unwrap_or_default(),
            doh_lockdown_auto: request.doh_lockdown_auto,
            browser_history_auto_seed: request.browser_history_auto_seed,
            kill_switch_strict_shared_ips: request.kill_switch_strict_shared_ips,
            // Auto-rules mode. Unknown slug (older/other peer) →
            // the default ("suggest"); never silently promote a user to having
            // rules applied unattended, and never silently switch discovery off.
            auto_rules_mode: nrr_storage::auto_rules::AutoRulesMode::from_slug(
                &request.auto_rules_mode,
            )
            .unwrap_or_default(),
            auto_rules_eager_delivery_names: request.auto_rules_eager_delivery_names,
            primary_probe_auto: request.primary_probe_auto,
            primary_probe_timeout_ms: request.primary_probe_timeout_ms,
            primary_probe_max_targets: request.primary_probe_max_targets,
            primary_probe_repeat_secs: request.primary_probe_repeat_secs,
            local_networks_auto_accept: request.local_networks_auto_accept,
            zone_priority_over_ip: request.zone_priority_over_ip,
            short_name_completion: request.short_name_completion,
            short_name_suffix,
            app_rules_take_all_addresses: request.app_rules_take_all_addresses,
            forwarded_outage: request.forwarded_outage.clone(),
            external_address_auto_check: request.external_address_auto_check,
            binding_source: dto_source_to_storage(request.binding_source),
        };
        let (written, providers) = {
            let conn = self
                .conn
                .lock()
                .map_err(|_| RoutePolicyWriteError::Storage("connection mutex poisoned".into()))?;
            apply_install_default_mode(&conn, sid, &mut record);
            let repo = RouteBindingsRepository::new(&conn);
            repo.update_for_sid(sid, &record, now_secs())
                .map_err(|e| RoutePolicyWriteError::Storage(format!("{e:?}")))?;
            let written = repo
                .load_for_sid(sid)
                .map_err(|e| RoutePolicyWriteError::Storage(format!("{e:?}")))?;
            crate::short_name_suffixes::global_user_short_name_suffixes().publish(sid, &written);
            let providers = repo
                .load_link_provider_apps(sid, "secondary")
                .unwrap_or_default();
            (written, providers)
        };
        // After the lock is released: the rules provider takes it itself.
        let rules_need_names = rules_need_names_for(&self.conn, sid, written.mode);
        Ok(record_to_dto(written, providers, rules_need_names))
    }
}

/// A user's first saved policy starts from the administrator's install-time
/// choices: their default route unless the request names another one, and
/// leak protection never below their floor. Under the additional default route
/// `sites` means `everything`, so the protection follows the mode.
fn apply_install_default_mode(conn: &Connection, sid: &str, record: &mut RoutePolicyRecord) {
    if RouteBindingsRepository::new(conn)
        .has_policy_for_sid(sid)
        .unwrap_or(true)
    {
        return;
    }
    let Ok(policy) = nrr_storage::install_policy::InstallPolicyRepository::new(conn).get() else {
        return;
    };
    if record.mode == BehaviorMode::PreferPrimary {
        if let Some(mode) = policy.default_route_mode {
            record.mode = mode;
        }
    }
    record.leak_protection = record
        .leak_protection
        .at_least(policy.default_leak_protection)
        .effective(storage_mode_to_domain(record.mode));
}

impl LinkProviderWriter for ProductionRoutePolicyWriter {
    fn set_for_sid(
        &self,
        sid: &str,
        role: &str,
        apps: &[LinkProviderAppDto],
    ) -> Result<Vec<LinkProviderAppDto>, RoutePolicyWriteError> {
        if sid.is_empty() {
            return Err(RoutePolicyWriteError::EmptySid);
        }
        let records: Vec<LinkProviderAppRecord> = apps
            .iter()
            .map(|a| LinkProviderAppRecord {
                exe_path: a.exe_path.clone(),
                display_name: a.display_name.clone(),
            })
            .collect();
        let conn = self
            .conn
            .lock()
            .map_err(|_| RoutePolicyWriteError::Storage("connection mutex poisoned".into()))?;
        let repo = RouteBindingsRepository::new(&conn);
        repo.set_link_provider_apps(sid, role, &records, now_secs())
            .map_err(|e| RoutePolicyWriteError::Storage(format!("{e:?}")))?;
        let stored = repo
            .load_link_provider_apps(sid, role)
            .map_err(|e| RoutePolicyWriteError::Storage(format!("{e:?}")))?;
        Ok(stored.into_iter().map(provider_record_to_dto).collect())
    }
}

// ── ProductionPrincipalDataPurger ────────────────────────────────────────────

/// Full-reset auxiliary-state purge, state-DB-backed. Shares the same
/// `Arc<Mutex<Connection>>` as the other per-SID writers in this module.
pub struct ProductionPrincipalDataPurger {
    conn: Arc<Mutex<Connection>>,
    /// Where each user's connection history hangs: a record of where a person
    /// went is part of what a full reset erases.
    trace_ring: Option<Arc<crate::conn_observation_consumer::ConnectionTraceRing>>,
}

impl ProductionPrincipalDataPurger {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self {
            conn,
            trace_ring: None,
        }
    }

    /// Erase the connection history the ring carries along with the rest.
    #[must_use]
    pub fn with_conn_history(
        mut self,
        ring: Arc<crate::conn_observation_consumer::ConnectionTraceRing>,
    ) -> Self {
        self.trace_ring = Some(ring);
        self
    }

    /// `None` erases every user's. A history that cannot be reached is said in
    /// the log and never fails the reset: the rest of it has already happened.
    fn forget_history(&self, sid: Option<&str>) {
        let Some(history) = self.trace_ring.as_ref().and_then(|r| r.history()) else {
            return;
        };
        let outcome = match sid {
            Some(sid) => history.forget(sid),
            None => history.forget_all(),
        };
        if let Err(e) = outcome {
            tracing::warn!(
                target: "nrr::conn-history",
                msg_key = "conn-history-reset-failed",
                error = %e,
                "full reset could not erase the connection history; the rest of the reset went ahead",
            );
        }
    }
}

impl PrincipalDataPurger for ProductionPrincipalDataPurger {
    fn purge_for_sid(
        &self,
        sid: &str,
        include_rules_history: bool,
    ) -> Result<PrincipalDataPurgeResponse, RoutePolicyWriteError> {
        if sid.is_empty() {
            return Err(RoutePolicyWriteError::EmptySid);
        }
        // Before the rows go, so no holder writes them back; again after, for a
        // tick that ran in between.
        crate::principal_reset::forget_principal(sid);
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| RoutePolicyWriteError::Storage("connection mutex poisoned".into()))?;
        let summary = nrr_storage::purge_principal_data(&mut conn, sid)
            .map_err(|e| RoutePolicyWriteError::Storage(format!("{e:?}")))?;
        crate::short_name_suffixes::global_user_short_name_suffixes().forget(sid);
        let rules_rows_deleted = if include_rules_history {
            nrr_storage::purge_principal_rules(&mut conn, sid)
                .map_err(|e| RoutePolicyWriteError::Storage(format!("{e:?}")))?
        } else {
            0
        };
        drop(conn);
        crate::principal_reset::forget_principal(sid);
        self.forget_history(Some(sid));
        crate::override_grants::forget_principal(sid);
        Ok(PrincipalDataPurgeResponse {
            rows_deleted: summary.rows_deleted,
            tables_touched: summary.tables_touched as u32,
            rules_rows_deleted,
            principals_purged: 1,
        })
    }

    fn purge_all_principals(
        &self,
        include_rules_history: bool,
    ) -> Result<PrincipalDataPurgeResponse, RoutePolicyWriteError> {
        crate::principal_reset::forget_everyone();
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| RoutePolicyWriteError::Storage("connection mutex poisoned".into()))?;
        let principals = nrr_storage::principals_with_state(&conn)
            .map_err(|e| RoutePolicyWriteError::Storage(format!("{e:?}")))?;
        let mut total = PrincipalDataPurgeResponse::default();
        for principal in &principals {
            let summary = nrr_storage::purge_principal_data(&mut conn, principal)
                .map_err(|e| RoutePolicyWriteError::Storage(format!("{e:?}")))?;
            crate::short_name_suffixes::global_user_short_name_suffixes().forget(principal);
            total.rows_deleted += summary.rows_deleted;
            total.tables_touched = total.tables_touched.max(summary.tables_touched as u32);
            if include_rules_history {
                total.rules_rows_deleted +=
                    nrr_storage::purge_principal_rules(&mut conn, principal)
                        .map_err(|e| RoutePolicyWriteError::Storage(format!("{e:?}")))?;
            }
        }
        total.rows_deleted += nrr_storage::purge_machine_traces(&mut conn)
            .map_err(|e| RoutePolicyWriteError::Storage(format!("{e:?}")))?;
        total.principals_purged = principals.len() as u32;
        drop(conn);
        crate::principal_reset::forget_everyone();
        self.forget_history(None);
        for principal in &principals {
            crate::override_grants::forget_principal(principal);
        }
        Ok(total)
    }

    fn other_principal_count(&self, sid: &str) -> Result<u32, RoutePolicyWriteError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| RoutePolicyWriteError::Storage("connection mutex poisoned".into()))?;
        let principals = nrr_storage::principals_with_state(&conn)
            .map_err(|e| RoutePolicyWriteError::Storage(format!("{e:?}")))?;
        Ok(principals.iter().filter(|p| p.as_str() != sid).count() as u32)
    }
}

fn provider_record_to_dto(rec: LinkProviderAppRecord) -> LinkProviderAppDto {
    LinkProviderAppDto {
        exe_path: rec.exe_path,
        display_name: rec.display_name,
    }
}

fn record_to_dto(
    rec: RoutePolicyRecord,
    secondary_link_providers: Vec<LinkProviderAppRecord>,
    rules_need_names: bool,
) -> RoutePolicyDto {
    let doh_lockdown_effective = crate::doh_lockdown_policy::doh_lockdown_active(
        rec.doh_lockdown_auto,
        rec.doh_lockdown_enabled,
        rec.doh_lockdown_scope,
        rec.leak_protection.is_on(),
        rules_need_names,
    );
    RoutePolicyDto {
        primary: rec.primary.map(record_binding_to_dto),
        secondary: rec.secondary.map(record_binding_to_dto),
        mode: storage_mode_to_dto(rec.mode),
        leak_protection: rec.leak_protection.into(),
        kill_switch_protocols: rec.kill_switch_protocols,
        allow_dns_over_primary: rec.allow_dns_over_primary,
        include_subdomains: rec.include_subdomains,
        shared_ip_policy: rec.shared_ip_policy.as_slug().to_string(),
        resolve_hosts_bypass: rec.resolve_hosts_bypass,
        secondary_link_provider_apps: secondary_link_providers
            .into_iter()
            .map(provider_record_to_dto)
            .collect(),
        doh_lockdown_enabled: rec.doh_lockdown_enabled,
        doh_lockdown_scope: rec.doh_lockdown_scope.as_slug().to_string(),
        doh_lockdown_auto: rec.doh_lockdown_auto,
        doh_lockdown_effective,
        browser_history_auto_seed: rec.browser_history_auto_seed,
        kill_switch_strict_shared_ips: rec.kill_switch_strict_shared_ips,
        auto_rules_mode: rec.auto_rules_mode.as_slug().to_string(),
        auto_rules_eager_delivery_names: rec.auto_rules_eager_delivery_names,
        primary_probe_auto: rec.primary_probe_auto,
        primary_probe_timeout_ms: rec.primary_probe_timeout_ms,
        primary_probe_max_targets: rec.primary_probe_max_targets,
        primary_probe_repeat_secs: rec.primary_probe_repeat_secs,
        local_networks_auto_accept: rec.local_networks_auto_accept,
        zone_priority_over_ip: rec.zone_priority_over_ip,
        short_name_completion: rec.short_name_completion,
        short_name_suffix: rec.short_name_suffix,
        app_rules_take_all_addresses: rec.app_rules_take_all_addresses,
        forwarded_outage: rec.forwarded_outage,
        external_address_auto_check: rec.external_address_auto_check,
        binding_source: storage_source_to_dto(rec.binding_source),
    }
}

fn record_binding_to_dto(rec: RouteBindingRecord) -> RouteBindingDto {
    let known_stable_ids = rec
        .known_stable_ids
        .into_iter()
        .filter(|id| !id.eq_ignore_ascii_case(&rec.stable_id))
        .collect();
    RouteBindingDto {
        stable_id: rec.stable_id,
        display_name: rec.display_name,
        user_confirmed: rec.user_confirmed,
        known_stable_ids,
    }
}

fn dto_binding_to_record(b: &RouteBindingDto) -> RouteBindingRecord {
    RouteBindingRecord {
        stable_id: b.stable_id.clone(),
        display_name: b.display_name.clone(),
        user_confirmed: b.user_confirmed,
        // Ignored on write: the DB owns the healed-id history.
        known_stable_ids: Vec::new(),
    }
}

fn storage_mode_to_dto(mode: BehaviorMode) -> BehaviorModeDto {
    match mode {
        BehaviorMode::PreferPrimary => BehaviorModeDto::PreferPrimary,
        BehaviorMode::PreferSecondaryWhenAvailable => BehaviorModeDto::PreferSecondaryWhenAvailable,
    }
}

fn dto_mode_to_storage(mode: BehaviorModeDto) -> BehaviorMode {
    match mode {
        BehaviorModeDto::PreferPrimary => BehaviorMode::PreferPrimary,
        BehaviorModeDto::PreferSecondaryWhenAvailable => BehaviorMode::PreferSecondaryWhenAvailable,
    }
}

fn storage_mode_to_domain(mode: BehaviorMode) -> nrr_domain::RouteBehaviorMode {
    match mode {
        BehaviorMode::PreferPrimary => nrr_domain::RouteBehaviorMode::PreferPrimary,
        BehaviorMode::PreferSecondaryWhenAvailable => {
            nrr_domain::RouteBehaviorMode::PreferSecondaryWhenAvailable
        }
    }
}

fn storage_source_to_dto(source: BindingSource) -> BindingSourceDto {
    match source {
        BindingSource::UserAssigned => BindingSourceDto::UserAssigned,
        BindingSource::MigratedFromPreferences => BindingSourceDto::MigratedFromPreferences,
        BindingSource::Recovery => BindingSourceDto::Recovery,
    }
}

fn dto_source_to_storage(source: BindingSourceDto) -> BindingSource {
    match source {
        BindingSourceDto::UserAssigned => BindingSource::UserAssigned,
        BindingSourceDto::MigratedFromPreferences => BindingSource::MigratedFromPreferences,
        BindingSourceDto::Recovery => BindingSource::Recovery,
    }
}

// ── Migration ledger ─────────────────────────────────────────────────────────

pub struct ProductionMigrationStatusProvider {
    conn: Arc<Mutex<Connection>>,
}

impl ProductionMigrationStatusProvider {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

impl MigrationStatusProvider for ProductionMigrationStatusProvider {
    fn migration_status(&self, sid: &str, migration_id: &str) -> MigrationStatusGetResponse {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => {
                return MigrationStatusGetResponse {
                    completed: false,
                    completed_at: None,
                    detail_json: None,
                };
            }
        };
        let repo = RouteBindingsRepository::new(&conn);
        match repo.migration_status(sid, migration_id) {
            Ok(Some(status)) => MigrationStatusGetResponse {
                completed: true,
                completed_at: Some(status.completed_at as u64),
                detail_json: status.detail_json,
            },
            _ => MigrationStatusGetResponse {
                completed: false,
                completed_at: None,
                detail_json: None,
            },
        }
    }
}

pub struct ProductionMigrationCompletionWriter {
    conn: Arc<Mutex<Connection>>,
}

impl ProductionMigrationCompletionWriter {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

impl MigrationCompletionWriter for ProductionMigrationCompletionWriter {
    fn mark_migration_complete(
        &self,
        sid: &str,
        migration_id: &str,
        detail_json: Option<&str>,
    ) -> Result<MigrationCompletionRecord, RoutePolicyWriteError> {
        if sid.is_empty() {
            return Err(RoutePolicyWriteError::EmptySid);
        }
        let conn = self
            .conn
            .lock()
            .map_err(|_| RoutePolicyWriteError::Storage("connection mutex poisoned".into()))?;
        let repo = RouteBindingsRepository::new(&conn);
        // INSERT OR IGNORE in storage means we don't get a "was inserted"
        // signal back. Read first to detect the idempotent path; the
        // subsequent mark is a no-op when the row already exists.
        let prior = repo
            .migration_status(sid, migration_id)
            .map_err(|e| RoutePolicyWriteError::Storage(format!("{e:?}")))?;
        let now = now_secs();
        repo.mark_migration_complete(sid, migration_id, detail_json, now)
            .map_err(|e| RoutePolicyWriteError::Storage(format!("{e:?}")))?;
        let completed_at = match &prior {
            Some(rec) => rec.completed_at as u64,
            None => now as u64,
        };
        Ok(MigrationCompletionRecord {
            recorded: prior.is_none(),
            completed_at,
        })
    }
}

// ── NoopMutationExecutor ─────────────────────────────────────────────────────

/// Refusing executor for platforms where the revision flow has no backend
/// yet: every mutation fails and `preview` returns an empty summary, so a
/// caller is told nothing happened rather than shown a success it did not
/// get. Settings operations have their own thin handlers and do not travel
/// this trait, so they are unaffected.
pub struct NoopMutationExecutor;

impl MutationExecutor for NoopMutationExecutor {
    fn preview(
        &self,
        _kind: MutationKind,
        _payload: &serde_json::Value,
        _principal: &str,
    ) -> ReviewSummaryResponse {
        ReviewSummaryResponse {
            diff_summary:
                "preview is unavailable: the revision flow has no backend on this platform".into(),
            provenance: "service".into(),
            risk_level: ReviewRiskLevel::Low,
            requires_review: true,
            changed_fields: Vec::new(),
            risk_signals: Vec::new(),
            rules_added: Vec::new(),
            rules_removed: Vec::new(),
            rules_modified: Vec::new(),
            rules_retargeted: Vec::new(),
            cross_set_duplicates: Vec::new(),
        }
    }

    fn execute(&self, _payload: StoredMutation, _principal: &str) -> MutationOutcome {
        MutationOutcome::Failed(OperationError {
            args: Default::default(),
            code: "not-implemented".into(),
            message: "revision mutations are not available on this platform".into(),
        })
    }

    fn rollback(&self, _principal: &str, _target_revision_id: Option<&str>) -> MutationOutcome {
        MutationOutcome::Failed(OperationError {
            args: Default::default(),
            code: "not-implemented".into(),
            message: "rollback is not available on this platform".into(),
        })
    }

    fn rollback_target(
        &self,
        _principal: &str,
        _target_revision_id: Option<&str>,
    ) -> Result<Option<nrr_shared::ipc_payloads::RollbackTargetDto>, OperationError> {
        Err(OperationError {
            args: Default::default(),
            code: "not-implemented".into(),
            message: "rollback is not available on this platform".into(),
        })
    }

    fn safe_disable(
        &self,
        _principal: &str,
        _reason: &str,
        _term: nrr_shared::ipc_payloads::SafeDisableTerm,
    ) -> MutationOutcome {
        MutationOutcome::Failed(OperationError {
            args: Default::default(),
            code: "not-implemented".into(),
            message: "safe disable is not available on this platform".into(),
        })
    }
}

// ── MonitoredAdaptersSnapshotProvider ─────────────────────────────────────────

/// Narrow persistence seam for a per-adapter
/// (local_ip, external_ip) observation. Kept as a trait (rather than a direct
/// `TrafficSampler` handle) so `MonitoredAdaptersSnapshotProvider` — which
/// has no other reason to know about the traffic-stats DB — depends on only
/// this one method; the composition root wires the real implementation
/// (`production_traffic::SamplerAdapterAddressRecorder`) so both the routine
/// sampler tick and this write path share the sampler's single connection to
/// `nrr_traffic_stats.db` (never a second connection to the same file).
pub trait AdapterAddressRecorder: Send + Sync {
    fn record(&self, adapter_key: &str, local_ip: &str, external_ip: &str, observed_at_ms: i64);

    /// The LOCAL address stored alongside the remembered external one, or
    /// `None` when nothing is stored for this adapter.
    ///
    /// Read, not just written, because the in-memory copy of the same pair is
    /// empty after a service restart — and "the service restarted and the
    /// adapter was renamed meanwhile" is exactly the case that hands one
    /// adapter's external address to another.
    fn remembered_local_ip(&self, adapter_key: &str) -> Option<String>;

    /// Drop the remembered external address, keeping `local_ip` as what this
    /// adapter shows now.
    fn forget_external(&self, adapter_key: &str, local_ip: &str, observed_at_ms: i64);
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// The adapter ids `sid` has bound (current and earlier ones); empty when
/// nothing is bound yet, `None` when the store could not say.
pub type CallerBindings = Arc<dyn Fn(&str) -> Option<Vec<String>> + Send + Sync>;

type RowFilter = dyn Fn(&nrr_platform_api::InterfaceRouteRow) -> bool;

/// Sends the external-address probe for the rows the filter picks.
type ExternalProbe = fn(
    &mut [nrr_platform_api::InterfaceRouteRow],
    &dyn Fn(&nrr_platform_api::InterfaceRouteRow) -> bool,
);

pub struct MonitoredAdaptersSnapshotProvider {
    api: Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
    interface_rows: Arc<dyn nrr_platform_api::InterfaceRowsPort>,
    /// Last externally-observed address per adapter, keyed by the adapter's
    /// persistent id (adapter name when the id is empty). Snapshots are
    /// whole-table replacements, and a snapshot that did not probe carries no
    /// external address of its own — without this carry-forward, every
    /// adapters-changed rebuild (a VPN flap, an unrelated NIC event) visually
    /// wipes an address the user just obtained for an adapter whose
    /// connectivity never changed. An entry is only replayed while
    /// the adapter keeps the same local IPv4; a changed local address drops
    /// it, since the reflexive address it produced is no longer evidence.
    last_external: Mutex<std::collections::HashMap<String, CachedExternalAddress>>,
    /// Optional persistence sink for a FRESH external-IP
    /// resolution (never for a replayed/cached one — see
    /// [`Self::fold_cached_external`]). `None` keeps `new()` a pure
    /// preview-safe constructor that never touches the traffic DB.
    address_recorder: Option<Arc<dyn AdapterAddressRecorder>>,
    /// Whose connections a user's external-address check may leave by.
    caller_bindings: Option<CallerBindings>,
    external_probe: ExternalProbe,
}

struct CachedExternalAddress {
    external_ip: String,
    local_ip: String,
    /// Whose check obtained it: another user is not shown it.
    probed_by: String,
}

/// [`CallerBindings`] over the stored route bindings.
pub fn stored_caller_bindings(conn: Arc<Mutex<Connection>>) -> CallerBindings {
    Arc::new(move |sid: &str| {
        if sid.is_empty() {
            return Some(Vec::new());
        }
        let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
        let policy = RouteBindingsRepository::new(&guard)
            .load_for_sid(sid)
            .ok()?;
        Some(
            policy
                .primary
                .into_iter()
                .chain(policy.secondary)
                .flat_map(|b| std::iter::once(b.stable_id).chain(b.known_stable_ids))
                .collect(),
        )
    })
}

/// Whether `row` is the adapter a binding id names: the GUI binds by the
/// row's persistent id, or by its name where the OS reports no id.
fn row_is_bound(row: &nrr_platform_api::InterfaceRouteRow, ids: &[String]) -> bool {
    ids.iter().any(|id| {
        !id.is_empty()
            && [&row.persistent_id, &row.adapter_name, &row.name]
                .iter()
                .any(|own| !own.is_empty() && own.eq_ignore_ascii_case(id))
    })
}

/// The adapter's persistent id, or its name where the OS reports no id.
fn external_cache_key(row: &nrr_platform_api::InterfaceRouteRow) -> &str {
    if row.persistent_id.is_empty() {
        &row.adapter_name
    } else {
        &row.persistent_id
    }
}

impl MonitoredAdaptersSnapshotProvider {
    pub fn new(
        api: Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
        interface_rows: Arc<dyn nrr_platform_api::InterfaceRowsPort>,
    ) -> Self {
        Self {
            api,
            interface_rows,
            last_external: Mutex::new(std::collections::HashMap::new()),
            address_recorder: None,
            caller_bindings: None,
            external_probe: nrr_platform_api::interface_rows::apply_external_ip_probes_where,
        }
    }

    /// Wires the reader of each user's bindings, so a user's check probes only
    /// the connections they bound. Unwired, every adapter is probed.
    pub fn with_caller_bindings(mut self, bindings: CallerBindings) -> Self {
        self.caller_bindings = Some(bindings);
        self
    }

    #[cfg(test)]
    fn with_external_probe(mut self, probe: ExternalProbe) -> Self {
        self.external_probe = probe;
        self
    }

    /// Which rows `caller`'s check may probe: their bound connections, every
    /// connection while they have bound none, nothing when the store cannot
    /// say whose they are.
    fn probe_filter(&self, caller: &str) -> Box<RowFilter> {
        let Some(bindings) = self.caller_bindings.as_ref() else {
            return Box::new(|_: &nrr_platform_api::InterfaceRouteRow| true);
        };
        match bindings(caller) {
            None => Box::new(|_: &nrr_platform_api::InterfaceRouteRow| false),
            Some(ids) if ids.is_empty() => Box::new(|_: &nrr_platform_api::InterfaceRouteRow| true),
            Some(ids) => {
                Box::new(move |row: &nrr_platform_api::InterfaceRouteRow| row_is_bound(row, &ids))
            }
        }
    }

    /// Wires the persistence path: a FRESH external-IP
    /// resolution (from a user-requested probe) is recorded through this
    /// sink. The composition root (`runtime_deps`) passes a recorder backed
    /// by the same `TrafficSampler` connection the routine sampler tick
    /// already owns.
    pub fn with_address_recorder(mut self, recorder: Arc<dyn AdapterAddressRecorder>) -> Self {
        self.address_recorder = Some(recorder);
        self
    }

    /// Learn fresh probe results and replay remembered ones into rows that
    /// have no external address of their own. The replayed note says so —
    /// the row never claims a fresh observation it did not make.
    ///
    /// A link that is down, or gone from a `live` enumeration, loses what was
    /// remembered for it: a tunnel that comes back may leave by another exit,
    /// so its address is shown again only once it is checked again.
    #[cfg(test)]
    fn fold_cached_external(&self, rows: &mut [nrr_platform_api::InterfaceRouteRow], live: bool) {
        self.fold_cached_external_for(rows, live, None);
    }

    /// [`Self::fold_cached_external`] for `viewer`: a fresh result is filed
    /// under them, and only what their own check obtained is replayed. No
    /// viewer is the machine's view.
    fn fold_cached_external_for(
        &self,
        rows: &mut [nrr_platform_api::InterfaceRouteRow],
        live: bool,
        viewer: Option<&str>,
    ) {
        let Ok(mut cache) = self.last_external.lock() else {
            return;
        };
        if live {
            cache.retain(|key, _| rows.iter().any(|row| external_cache_key(row) == key));
        }
        for row in rows {
            if row.availability_status == nrr_platform_api::BasicAvailabilityStatus::Unavailable
                && row.observed_facts.external_ip.is_none()
            {
                cache.remove(external_cache_key(row));
                continue;
            }
            let key = external_cache_key(row).to_owned();
            if let Some(ip) = row.observed_facts.external_ip.clone() {
                cache.insert(
                    key,
                    CachedExternalAddress {
                        external_ip: ip.clone(),
                        local_ip: row.local_ip.clone(),
                        probed_by: viewer.unwrap_or_default().to_owned(),
                    },
                );
                // Only a FRESH resolution is persisted. Keyed by `row.name`,
                // the OS friendly name the traffic ledger also keys on, never
                // by `adapter_name` (a GUID on Windows); a rename race between
                // the two enumerations leaves the row unannotated this round.
                if let Some(recorder) = &self.address_recorder {
                    if !row.name.is_empty() && !row.local_ip.is_empty() {
                        recorder.record(&row.name, &row.local_ip, &ip, now_ms());
                    }
                }
                continue;
            }
            // The pair on DISK is what feeds the traffic screen, and it
            // outlives this process. A stored local address that no longer
            // matches the adapter under this name means the row belongs to
            // some other adapter — a rename, or a reinstall that took the name
            // back — so the external half must go before anything prints it as
            // this adapter's. Only the external half: the local one is a fact
            // about the adapter in front of us.
            if let Some(recorder) = &self.address_recorder {
                if !row.name.is_empty() && !row.local_ip.is_empty() {
                    if let Some(stored_local) = recorder.remembered_local_ip(&row.name) {
                        if stored_local != row.local_ip {
                            recorder.forget_external(&row.name, &row.local_ip, now_ms());
                        }
                    }
                }
            }
            match cache.get(&key) {
                Some(entry) if entry.local_ip == row.local_ip => {
                    if viewer.is_some_and(|viewer| viewer != entry.probed_by) {
                        continue;
                    }
                    row.observed_facts.external_ip = Some(entry.external_ip.clone());
                    row.observed_facts.external_probe_note =
                        "Last observed external address from an earlier probe; \
                         this snapshot did not obtain a fresh one."
                            .to_string();
                }
                Some(_) => {
                    cache.remove(&key);
                }
                None => {}
            }
        }
    }

    /// `probe_for`: whose check runs with this snapshot, if any. `viewer`:
    /// who reads it, `None` for the machine's view.
    fn snapshot(
        &self,
        probe_for: Option<&str>,
        viewer: Option<&str>,
    ) -> SnapshotInterfacesResponse {
        let adapters = match self.api.get_adapter_infos() {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::adapters",
                    msg_key = "prodmisc-adapter-infos-failed",
                    error = %format!("{e:?}"),
                    "get_adapter_infos failed; returning empty snapshot",
                );
                Vec::new()
            }
        };
        // A fresh enumeration on every snapshot, so a plain "Refresh
        // interfaces" shows adapters that appeared at runtime (VPN up, USB
        // dongle, VM NIC). The external-address probe runs only when the user
        // asked for it.
        let (source, mut rich_rows) = self.interface_rows.collect_rows(false);
        // Placeholder rows are offline by contract: nothing behind them to ask.
        if let Some(caller) = probe_for.filter(|_| source.is_live()) {
            let wanted = self.probe_filter(caller);
            (self.external_probe)(&mut rich_rows, &*wanted);
        }
        // Report the provenance the enumeration actually reached, not the one
        // this path hopes for. The rows are a deterministic PLACEHOLDER
        // whenever the live enumeration came back empty, and a placeholder
        // announced as `windows-live` is how invented adapters reach a user
        // about to bind a route to one.
        if !source.is_live() {
            tracing::warn!(
                target: "nrr::snapshot-interfaces",
                msg_key = "prodmisc-adapter-enum-empty-placeholder",
                data_source = source.title(),
                rows = rich_rows.len(),
                "live adapter enumeration produced nothing — answering with the deterministic placeholder dataset, marked as such",
            );
        }
        self.fold_cached_external_for(&mut rich_rows, source.is_live(), viewer);
        // After the fold: a remembered external address is part of the score.
        nrr_platform_api::interface_rows::assign_recommendations(&mut rich_rows);
        let rows = rich_rows
            .iter()
            .map(nrr_shared::ipc_payloads::InterfaceRowDto::from)
            .collect::<Vec<_>>();
        SnapshotInterfacesResponse {
            data_source: source.title().into(),
            adapters: adapters.into_iter().map(adapter_to_entry).collect(),
            // Secondary route state — population by the
            // policy manager for the Fail-Closed
            // banner is not wired here. For now we report `None` and the GUI hides
            // the banner.
            secondary: None,
            rows,
        }
    }
}

impl AdaptersSnapshotProvider for MonitoredAdaptersSnapshotProvider {
    fn adapters_snapshot(&self, _force_refresh: bool) -> SnapshotInterfacesResponse {
        self.snapshot(None, None)
    }

    fn adapters_snapshot_probing_external_ip(&self) -> SnapshotInterfacesResponse {
        self.snapshot(Some(""), None)
    }

    fn adapters_snapshot_for(
        &self,
        _force_refresh: bool,
        caller: &str,
    ) -> SnapshotInterfacesResponse {
        self.snapshot(None, Some(caller))
    }

    fn adapters_snapshot_probing_external_ip_for(
        &self,
        caller: &str,
    ) -> SnapshotInterfacesResponse {
        self.snapshot(Some(caller), Some(caller))
    }
}

// ── ProductionFailClosedProbe ─────────────────────────────────────────────────

/// Production [`FailClosedStateProbe`] backed by per-SID `route_bindings`,
/// `behavior_mode`, and `secondary_block_policy`. Reads the policy on
/// every call (no caching) — snapshots are infrequent (GUI-triggered,
/// not on a tight loop) and policy changes must be reflected promptly.
///
/// Emits a single `nrr::stability` info event per transition
/// (false→true or true→false). The transition state lives in an
/// internal `Mutex<Option<bool>>` — operator-visible logging of policy
/// changes is the goal, not a stable signalling primitive.
pub struct ProductionFailClosedProbe {
    state_conn: Arc<Mutex<Connection>>,
    last_emitted: Mutex<Option<bool>>,
}

impl ProductionFailClosedProbe {
    pub fn new(state_conn: Arc<Mutex<Connection>>) -> Self {
        Self {
            state_conn,
            last_emitted: Mutex::new(None),
        }
    }

    fn emit_transition_if_changed(&self, new_state: bool) {
        let mut guard = match self.last_emitted.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let changed = guard.map(|prev| prev != new_state).unwrap_or(true);
        if changed {
            tracing::info!(
                target: "nrr::stability",
                msg_key = "prodmisc-failclosed-state",
                fail_closed_active = new_state,
                "leak protection blocking traffic for the additional route",
            );
            *guard = Some(new_state);
        }
    }
}

impl crate::ipc_handlers::providers::FailClosedStateProbe for ProductionFailClosedProbe {
    fn probe(
        &self,
        caller_sid: &str,
        adapters: &[crate::ipc_handlers::payloads::AdapterEntry],
    ) -> Option<crate::ipc_handlers::payloads::SecondaryRouteStateDto> {
        if caller_sid.is_empty() {
            return None;
        }
        let guard = self.state_conn.lock().ok()?;
        let repo = RouteBindingsRepository::new(&guard);
        let policy = match repo.load_for_sid(caller_sid) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::stability",
                    msg_key = "prodmisc-route-bindings-load-failed",
                    error = %e,
                    "could not load route bindings; suppressing the leak protection banner",
                );
                return None;
            }
        };
        let secondary = match policy.secondary {
            Some(b) => b,
            None => {
                // No secondary bound → no fail-closed concept.
                return Some(crate::ipc_handlers::payloads::SecondaryRouteStateDto {
                    fail_closed_active: false,
                });
            }
        };
        // Locate the adapter with this stable_id in the already-
        // enumerated wire list. Missing entirely counts as offline.
        //
        // The binding stores the GUI persistent-id scheme
        // (`win-adapter:{name}` etc. — see
        // `route_coordinator::adapter_binding_matches`), which never equals
        // the wire `AdapterEntry::persistent_id` (populated from the
        // low-level `AdapterInfo::stable_id()`). A raw `==` compare here
        // always misses, which makes `secondary_offline` permanently
        // `true` — reuse the same matching rules the route coordinator
        // uses for the live adapter list.
        // The coordinator's own check, prior ids and IPv4 included: the banner
        // must say what the service does.
        let secondary_offline = !crate::route_coordinator::bound_adapter_usable(
            adapters,
            &secondary.stable_id,
            &secondary.known_stable_ids,
        );
        // The banner mirrors the actual blocking: with protection off nothing
        // blocks, and the ordinary secondary-down notice is the warning.
        let fail_closed_active = policy.leak_protection.is_on() && secondary_offline;
        self.emit_transition_if_changed(fail_closed_active);
        Some(crate::ipc_handlers::payloads::SecondaryRouteStateDto { fail_closed_active })
    }
}

fn adapter_to_entry(
    info: nrr_platform_api::adapters::AdapterInfo,
) -> nrr_shared::ipc_payloads::AdapterEntry {
    let mac_hex = info.mac.map(|m| {
        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        )
    });
    let stable_id = info.stable_id();
    let usable = crate::route_coordinator::BoundCandidate::usable(&info);
    nrr_shared::ipc_payloads::AdapterEntry {
        persistent_id: stable_id,
        adapter_name: info.adapter_name.clone(),
        ipv6_if_index: info.index,
        physical_address: mac_hex,
        name: info.adapter_name,
        interface_description: info.description,
        interface_type: format!("{:?}", info.interface_type),
        oper_status: format!("{:?}", info.oper_status),
        usable,
    }
}

#[cfg(test)]
mod adapters_snapshot_tests;

#[cfg(test)]
#[allow(clippy::expect_used)]
mod principal_purge_history_tests {
    use super::*;
    use crate::conn_history::{ConnHistory, HistoryRead};
    use crate::conn_observation_consumer::{ConnectionTraceRecord, ConnectionTraceRing};
    use nrr_platform_api::conn_observe::egress::{EgressInterface, EgressRole};
    use nrr_platform_api::conn_observe::{ConnectionVerdict, TransportProtocol};
    use nrr_storage::repository::MigrationRunner;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    const ALICE: &str = "S-1-5-21-1-2-3-1001";
    const BOB: &str = "S-1-5-21-1-2-3-1002";
    const T0: u64 = 1_700_000_000_000;

    fn state() -> Arc<Mutex<Connection>> {
        let runner = nrr_storage::migration::SqliteMigrationRunner::for_state_db(
            Connection::open_in_memory().expect("in-memory"),
        );
        runner.run_pending_migrations().expect("migrate");
        Arc::new(Mutex::new(runner.into_connection()))
    }

    fn row(owner: &str) -> ConnectionTraceRecord {
        ConnectionTraceRecord {
            process_path: Some("/usr/bin/browser".into()),
            user_sid: Some(owner.into()),
            protocol: TransportProtocol::Tcp,
            local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 5)), 50_000),
            remote: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 443),
            egress: EgressInterface {
                ifindex: 2,
                role: EgressRole::Primary,
            },
            verdict: ConnectionVerdict::Permit,
            blocked_by_nrr: None,
            nrr_drop_spec_id: None,
            nrr_block_reason: None,
            observed_unix_ms: Some(T0),
            remote_names: None,
        }
    }

    fn rows_of(history: &ConnHistory, sid: &str) -> usize {
        let read = HistoryRead {
            principal: Some(sid),
            to_ms: T0 * 2,
            limit: 100,
            ..HistoryRead::default()
        };
        history.read(&read, T0).expect("read").0.len()
    }

    #[test]
    fn a_full_reset_erases_the_callers_history_and_no_one_elses() {
        let dir = tempfile::tempdir().expect("temp dir");
        let ring = Arc::new(ConnectionTraceRing::new(8));
        ring.attach_history(Arc::new(ConnHistory::open(
            dir.path().join("nrr_conn_history.db"),
        )));
        ring.push(row(ALICE));
        ring.push(row(BOB));
        let history = Arc::clone(ring.history().expect("attached"));
        history.flush(T0);
        let purger = ProductionPrincipalDataPurger::new(state()).with_conn_history(ring);

        purger.purge_for_sid(ALICE, false).expect("reset");
        assert_eq!(rows_of(&history, ALICE), 0);
        assert_eq!(rows_of(&history, BOB), 1);

        purger.purge_all_principals(false).expect("reset everyone");
        assert_eq!(rows_of(&history, BOB), 0);
    }

    #[test]
    fn a_history_out_of_reach_never_fails_the_reset() {
        let ring = Arc::new(ConnectionTraceRing::new(8));
        ring.attach_history(Arc::new(ConnHistory::new(None, None)));
        let purger = ProductionPrincipalDataPurger::new(state()).with_conn_history(ring);
        purger
            .purge_for_sid(ALICE, true)
            .expect("the reset goes on");
        purger
            .purge_all_principals(true)
            .expect("the reset goes on");
    }
}

// ── hosts-override annotation tests ───────────────────────────────────────────

#[cfg(test)]
mod hosts_override_tests;

// ── ProductionFailClosedProbe tests ───────────────────────────────────────────

#[cfg(test)]
mod fail_closed_probe_tests;

#[cfg(test)]
mod rule_row_flag_tests {
    use super::*;
    use nrr_shared::rules_json::{AppMatchDto, AppPatternDto, RuleAction, RuleDto};

    /// `+children` written in a file reaches the book; the row a table and a
    /// rewritten file are built from must carry it back, or the next apply or
    /// file write drops the flag the user wrote.
    #[test]
    fn a_programs_flags_ride_its_row_as_the_file_writes_them() {
        let dto = RuleDto {
            id: "r-0001".into(),
            enabled: true,
            address_match: None,
            app_match: Some(AppMatchDto {
                pattern: AppPatternDto::Exact {
                    value: "tool.exe".into(),
                },
                include_child_processes: true,
                override_requested: true,
            }),
            comment: String::new(),
            action: RuleAction::Route,
            origin: None,
        };
        assert_eq!(
            rule_dto_to_row(&dto, "secondary").match_value,
            "tool.exe +children +override"
        );
    }
}

#[cfg(test)]
mod route_binding_dto_tests {
    use super::*;

    #[test]
    fn the_snapshot_names_the_ids_a_binding_was_healed_from_but_not_its_current_one() {
        let dto = record_binding_to_dto(RouteBindingRecord {
            stable_id: "win-adapter:{new}".into(),
            display_name: "Tunnel".into(),
            user_confirmed: true,
            known_stable_ids: vec!["WIN-ADAPTER:{NEW}".into(), "win-adapter:{old}".into()],
        });
        assert_eq!(dto.known_stable_ids, vec!["win-adapter:{old}".to_string()]);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn a_binding_that_was_never_healed_keeps_the_wire_shape_unchanged() {
        let dto = record_binding_to_dto(RouteBindingRecord {
            stable_id: "win-adapter:{a}".into(),
            display_name: "Tunnel".into(),
            user_confirmed: true,
            known_stable_ids: vec!["win-adapter:{a}".into()],
        });
        let wire = serde_json::to_value(&dto).expect("serializes");
        assert_eq!(wire["stable-id"], "win-adapter:{a}");
        assert!(wire.get("known-stable-ids").is_none());
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod route_policy_provider_tests {
    use super::*;
    use nrr_storage::repository::MigrationRunner;
    use nrr_storage::route_bindings::BindingSource;

    /// First run sends the protections before any adapter is bound; the
    /// binding write that follows is built on this read.
    #[test]
    fn protections_chosen_before_any_binding_are_read_back() {
        let runner = nrr_storage::migration::SqliteMigrationRunner::for_state_db(
            Connection::open_in_memory().expect("in-memory"),
        );
        runner.run_pending_migrations().expect("migrate");
        let conn = runner.into_connection();
        let mut policy = RoutePolicyRecord::empty(BindingSource::UserAssigned);
        policy.leak_protection = nrr_domain::LeakProtection::Everything;
        policy.doh_lockdown_enabled = true;
        RouteBindingsRepository::new(&conn)
            .update_for_sid("S-1-5-21-A", &policy, 0)
            .expect("write policy");
        let provider = ProductionRoutePolicyProvider::new(Arc::new(Mutex::new(conn)));

        let dto = provider.get_for_sid("S-1-5-21-A").expect("a stored policy");
        assert!(dto.primary.is_none() && dto.secondary.is_none());
        assert_eq!(
            dto.leak_protection,
            nrr_shared::ipc_payloads::LeakProtectionDto::Everything
        );
        assert!(dto.doh_lockdown_enabled);
        assert!(provider.get_for_sid("S-1-5-21-B").is_none());
    }

    /// A user with no policy yet is told what the install-time choices make
    /// of a first save, so the first-run choice is settled against them.
    #[test]
    fn the_first_policy_names_the_install_route_and_floor() {
        use nrr_shared::ipc_payloads::LeakProtectionDto;
        use nrr_storage::install_policy::{InstallPolicy, InstallPolicyRepository};
        let runner = nrr_storage::migration::SqliteMigrationRunner::for_state_db(
            Connection::open_in_memory().expect("in-memory"),
        );
        runner.run_pending_migrations().expect("migrate");
        let conn = Arc::new(Mutex::new(runner.into_connection()));
        let provider = ProductionRoutePolicyProvider::new(Arc::clone(&conn));
        assert_eq!(
            provider.first_policy(),
            Some(FirstPolicyDto {
                mode: BehaviorModeDto::PreferPrimary,
                leak_protection_at_least: LeakProtectionDto::Off,
            })
        );

        for (floor, at_least) in [
            (
                nrr_domain::LeakProtection::Sites,
                LeakProtectionDto::Everything,
            ),
            (
                nrr_domain::LeakProtection::Everything,
                LeakProtectionDto::Everything,
            ),
        ] {
            InstallPolicyRepository::new(&conn.lock().expect("conn"))
                .set(
                    &InstallPolicy {
                        default_route_mode: Some(BehaviorMode::PreferSecondaryWhenAvailable),
                        default_leak_protection: floor,
                        ..InstallPolicy::default()
                    },
                    1,
                )
                .expect("policy");
            assert_eq!(
                provider.first_policy(),
                Some(FirstPolicyDto {
                    mode: BehaviorModeDto::PreferSecondaryWhenAvailable,
                    leak_protection_at_least: at_least,
                }),
                "{floor}"
            );
        }
    }
}

#[cfg(test)]
mod doh_resolver_ip_tests {
    use super::*;
    use crate::fqdn_cache_lookup::MockFqdnCacheLookup;
    use nrr_storage::doh_lockdown::{DohResolverEntriesRepository, DohResolverEntry, DohTarget};
    use nrr_storage::repository::MigrationRunner;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// A host entry's AAAA answers are blocked too: the browser bootstraps its
    /// DoH hostname through the system resolver and may connect over either
    /// family.
    #[test]
    fn a_host_entry_contributes_both_families_from_the_cache() {
        let runner = nrr_storage::migration::SqliteMigrationRunner::for_state_db(
            Connection::open_in_memory().expect("in-memory"),
        );
        runner.run_pending_migrations().expect("migrate");
        let conn = runner.into_connection();
        let literal_v6: IpAddr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53).into();
        DohResolverEntriesRepository::new(&conn)
            .replace_all(
                &[
                    DohResolverEntry {
                        target: DohTarget::Host("doh.example".into()),
                        comment: String::new(),
                        enabled: true,
                    },
                    DohResolverEntry {
                        target: DohTarget::Ip(literal_v6),
                        comment: String::new(),
                        enabled: true,
                    },
                ],
                0,
            )
            .expect("write");
        let cached_v4: IpAddr = Ipv4Addr::new(192, 0, 2, 10).into();
        let cached_v6: IpAddr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10).into();
        let cache = Arc::new(MockFqdnCacheLookup::new());
        cache.set_addresses("doh.example", vec![cached_v4, cached_v6]);

        let source = ProductionRoutePolicySource::new(Arc::new(Mutex::new(
            Connection::open_in_memory().expect("unused"),
        )))
        .with_fqdn_cache(cache);
        let ips = source.resolve_doh_resolver_ips(&conn);
        for ip in [cached_v4, cached_v6, literal_v6] {
            assert!(ips.contains(&ip), "{ip} missing from {ips:?}");
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod rules_list_projection_tests {
    use super::*;
    use crate::production_rules_provider::BookInForce;
    use nrr_storage::repository::MigrationRunner;

    fn record(rules_json: &str) -> BookInForce {
        BookInForce {
            revision_id: Some("rev-1".into()),
            rules_json: rules_json.into(),
        }
    }

    /// A client would send such a rule back rewritten as one it understands.
    #[test]
    fn rules_this_build_cannot_read_are_not_listed() {
        let json = r#"{"primary":[{"address-match":{"kind":"exact-fqdn","value":"a.test"},"enabled":true,"id":"r-1"},{"address-match":{"from":1,"kind":"port-range"},"enabled":true,"id":"r-2"}],"schema-version":9,"secondary":[{"action":"throttle","address-match":{"kind":"zone","name":"test"},"enabled":true,"id":"r-3"}]}"#;
        let listed = ProductionRulesSnapshotProvider::project(&record(json), RulesRouteFilter::All);
        let ids: Vec<&str> = listed.rows.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["r-1"]);
        // Hidden, but counted, so the screen can say they do nothing here.
        assert_eq!(listed.unrecognized, 2);
        let primary_only =
            ProductionRulesSnapshotProvider::project(&record(json), RulesRouteFilter::Primary);
        assert_eq!(primary_only.unrecognized, 1);
    }

    fn state_conn() -> Arc<Mutex<Connection>> {
        let runner = nrr_storage::migration::SqliteMigrationRunner::for_state_db(
            Connection::open_in_memory().expect("in-memory"),
        );
        runner.run_pending_migrations().expect("migrate");
        Arc::new(Mutex::new(runner.into_connection()))
    }

    const BOOK: &str = r#"{"primary":[{"address-match":{"kind":"exact-fqdn","value":"a.test"},"enabled":true,"id":"r-1"}],"schema-version":1,"secondary":[]}"#;

    /// The list is the book in force: a revision mid-activation over the
    /// stored one, the baseline for a user who never diverged, and a name to
    /// build a write on that moves with it.
    #[test]
    fn the_list_is_the_book_in_force_and_names_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nrr_service_state.db");
        let runner = nrr_storage::migration::SqliteMigrationRunner::for_state_db(
            Connection::open(&path).expect("open"),
        );
        runner.run_pending_migrations().expect("migrate");
        let conn = runner.into_connection();
        conn.execute(
            "INSERT INTO revisions (principal, revision_id, content_hash, rules_json, status, \
             source, correlation_id, created_at, activated_at) \
             VALUES (?1, 'rev-b', 'h', ?2, 'active', 'gui-rules-edit', 'c', 1, 1)",
            rusqlite::params![nrr_storage::BASELINE_PRINCIPAL, BOOK],
        )
        .expect("seed baseline");
        let provider = ProductionRulesSnapshotProvider::new(Arc::new(Mutex::new(conn)));
        let user = "S-1-5-21-1-2-3-1001";

        let inherited = provider.rules_snapshot_for(RulesRouteFilter::All, user);
        assert_eq!(inherited.rows.len(), 1, "read through to the baseline");
        let base = inherited.base_revision.clone().expect("a base to build on");
        assert!(!base.is_empty());

        let applying = BOOK.replace("a.test", "b.test");
        let overlay = crate::applying_revision_overlay::publish(
            &Connection::open(&path).expect("open"),
            user,
            &applying,
        );
        let mid = provider.rules_snapshot_for(RulesRouteFilter::All, user);
        assert_eq!(
            mid.rows[0].match_value, "b.test",
            "the revision being applied"
        );
        assert_ne!(mid.base_revision.as_deref(), Some(base.as_str()));
        drop(overlay);

        let empty = ProductionRulesSnapshotProvider::new(state_conn())
            .rules_snapshot_for(RulesRouteFilter::All, user);
        assert_eq!(
            empty.base_revision.as_deref(),
            Some(""),
            "no rules is a base too"
        );
    }
}

#[cfg(test)]
mod install_policy_tests {
    use super::*;
    use nrr_storage::install_policy::{InstallPolicy, InstallPolicyRepository, SecondaryUnset};
    use nrr_storage::repository::MigrationRunner;

    fn conn() -> Arc<Mutex<Connection>> {
        let runner = nrr_storage::migration::SqliteMigrationRunner::for_state_db(
            Connection::open_in_memory().expect("in-memory"),
        );
        runner.run_pending_migrations().expect("migrate");
        Arc::new(Mutex::new(runner.into_connection()))
    }

    fn binding(id: &str) -> RouteBindingRecord {
        RouteBindingRecord {
            stable_id: id.into(),
            display_name: id.into(),
            user_confirmed: true,
            known_stable_ids: Vec::new(),
        }
    }

    fn store(conn: &Arc<Mutex<Connection>>, sid: &str, secondary: bool, unset: SecondaryUnset) {
        let guard = conn.lock().expect("conn");
        InstallPolicyRepository::new(&guard)
            .set(
                &InstallPolicy {
                    secondary_unset: unset,
                    ..InstallPolicy::default()
                },
                1,
            )
            .expect("policy");
        let mut record = RoutePolicyRecord::empty(BindingSource::UserAssigned);
        record.primary = Some(binding("main"));
        record.secondary = secondary.then(|| binding("tunnel"));
        RouteBindingsRepository::new(&guard)
            .update_for_sid(sid, &record, 1)
            .expect("bind");
    }

    #[test]
    fn nothing_is_planned_for_a_user_who_bound_nothing_whatever_the_install_policy() {
        let conn = conn();
        store(&conn, "S-1-5-21-other", false, SecondaryUnset::Block);
        let source = ProductionRoutePolicySource::new(Arc::clone(&conn));
        assert!(source.load_for_sid("S-1-5-21-new").is_none());
    }

    #[test]
    fn block_refuses_additional_route_rules_until_a_connection_is_bound() {
        let conn = conn();
        store(&conn, "S-1-5-21-1", false, SecondaryUnset::Block);
        let snapshot = ProductionRoutePolicySource::new(Arc::clone(&conn))
            .load_for_sid("S-1-5-21-1")
            .expect("policy");
        assert_eq!(
            snapshot.leak_protection,
            nrr_domain::LeakProtection::Sites,
            "only those rules, not everything"
        );
        assert_eq!(snapshot.mode, PerSidBehaviorMode::PreferPrimary);

        store(&conn, "S-1-5-21-1", true, SecondaryUnset::Block);
        let bound = ProductionRoutePolicySource::new(Arc::clone(&conn))
            .load_for_sid("S-1-5-21-1")
            .expect("policy");
        assert_eq!(
            bound.leak_protection,
            nrr_domain::LeakProtection::Off,
            "a bound connection ends the refusal"
        );
    }

    /// Protection the user chose stands; the refusal only raises `off`.
    #[test]
    fn block_keeps_a_protection_the_user_already_chose() {
        let conn = conn();
        store(&conn, "S-1-5-21-1", false, SecondaryUnset::Block);
        {
            let guard = conn.lock().expect("conn");
            let repo = RouteBindingsRepository::new(&guard);
            let mut record = repo.load_for_sid("S-1-5-21-1").expect("load");
            record.mode = BehaviorMode::PreferSecondaryWhenAvailable;
            record.leak_protection = nrr_domain::LeakProtection::Everything;
            repo.update_for_sid("S-1-5-21-1", &record, 2)
                .expect("write");
        }
        let snapshot = ProductionRoutePolicySource::new(conn)
            .load_for_sid("S-1-5-21-1")
            .expect("policy");
        assert_eq!(
            snapshot.leak_protection,
            nrr_domain::LeakProtection::Everything
        );
        assert_eq!(
            snapshot.mode,
            PerSidBehaviorMode::PreferSecondaryWhenAvailable
        );
    }

    #[test]
    fn direct_leaves_additional_route_rules_to_go_out_directly() {
        let conn = conn();
        store(&conn, "S-1-5-21-1", false, SecondaryUnset::Direct);
        let snapshot = ProductionRoutePolicySource::new(conn)
            .load_for_sid("S-1-5-21-1")
            .expect("policy");
        assert_eq!(snapshot.leak_protection, nrr_domain::LeakProtection::Off);
    }

    #[test]
    fn the_install_mode_seeds_only_a_first_write_that_names_none() {
        let conn = conn();
        let guard = conn.lock().expect("conn");
        InstallPolicyRepository::new(&guard)
            .set(
                &InstallPolicy {
                    secondary_unset: SecondaryUnset::Direct,
                    default_route_mode: Some(BehaviorMode::PreferSecondaryWhenAvailable),
                    ..InstallPolicy::default()
                },
                1,
            )
            .expect("policy");
        let mut first = RoutePolicyRecord::empty(BindingSource::UserAssigned);
        apply_install_default_mode(&guard, "S-1-5-21-1", &mut first);
        assert_eq!(first.mode, BehaviorMode::PreferSecondaryWhenAvailable);

        // `sites` is offered only under the main connection; the install mode
        // turning the route to the additional one widens it.
        let mut sites = RoutePolicyRecord::empty(BindingSource::UserAssigned);
        sites.leak_protection = nrr_domain::LeakProtection::Sites;
        apply_install_default_mode(&guard, "S-1-5-21-3", &mut sites);
        assert_eq!(
            sites.leak_protection,
            nrr_domain::LeakProtection::Everything
        );

        let mut stored = RoutePolicyRecord::empty(BindingSource::UserAssigned);
        stored.primary = Some(binding("main"));
        RouteBindingsRepository::new(&guard)
            .update_for_sid("S-1-5-21-2", &stored, 1)
            .expect("bind");
        let mut later = RoutePolicyRecord::empty(BindingSource::UserAssigned);
        apply_install_default_mode(&guard, "S-1-5-21-2", &mut later);
        assert_eq!(
            later.mode,
            BehaviorMode::PreferPrimary,
            "a stored policy is the user's"
        );
    }

    /// The install-time strict mode, as the migration folds it, still holds a
    /// new user's first write at everything, whichever route it names.
    #[test]
    fn the_install_floor_raises_a_first_write_and_only_the_first() {
        let conn = conn();
        {
            let guard = conn.lock().expect("conn");
            InstallPolicyRepository::new(&guard)
                .set(
                    &InstallPolicy {
                        secondary_unset: SecondaryUnset::Direct,
                        default_route_mode: Some(BehaviorMode::PreferSecondaryWhenAvailable),
                        default_leak_protection: nrr_domain::LeakProtection::Everything,
                    },
                    1,
                )
                .expect("policy");
        }
        use nrr_shared::ipc_payloads::LeakProtectionDto;
        let writer = ProductionRoutePolicyWriter::new(Arc::clone(&conn));
        for mode in [
            BehaviorModeDto::PreferPrimary,
            BehaviorModeDto::PreferSecondaryWhenAvailable,
        ] {
            let sid = format!("S-1-5-21-{mode:?}");
            let request: RoutePolicyUpdateRequest = serde_json::from_value(serde_json::json!({
                "mode": mode,
                "leak-protection": "off",
                "doh-lockdown-enabled": false,
                "kill-switch-strict-shared-ips": false,
                "binding-source": "user-assigned"
            }))
            .expect("request");
            let first = writer.update_for_sid(&sid, &request).expect("first write");
            assert_eq!(
                first.leak_protection,
                LeakProtectionDto::Everything,
                "{mode:?}"
            );
            assert_eq!(first.mode, BehaviorModeDto::PreferSecondaryWhenAvailable);

            // Lowering it afterwards is the user's own choice.
            let second = writer.update_for_sid(&sid, &request).expect("second write");
            assert_eq!(second.leak_protection, LeakProtectionDto::Off, "{mode:?}");
        }
    }
}
