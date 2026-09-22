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
    BehaviorModeDto, BindingSourceDto, LinkProviderAppDto, MigrationStatusGetResponse,
    MutationKind, PrincipalDataPurgeResponse, ReviewRiskLevel, ReviewSummaryResponse,
    RouteBindingDto, RoutePolicyDto, RoutePolicyUpdateRequest, RuleRowEntry, RulesListResponse,
    RulesRouteFilter, SnapshotInterfacesResponse,
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
        if let Some(store) = self.app_observations.as_ref() {
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
    /// Project a resolved active revision into the GUI rows. Shared by the
    /// baseline-only `rules_snapshot` and the per-principal
    /// `rules_snapshot_for`.
    fn project(
        active: nrr_storage::revisions::RevisionRecord,
        route_filter: RulesRouteFilter,
    ) -> RulesListResponse {
        let active_revision_id = Some(active.revision_id.clone());
        // The stored JSON was validated on the write path; a decode
        // failure here means stale/corrupt data — surface the revision id
        // with no rows rather than erroring the whole read.
        let Ok(dto) = nrr_shared::rules_json::from_canonical_string(&active.rules_json) else {
            return RulesListResponse {
                rows: Vec::new(),
                supported_rule_types: rule_type_slugs(),
                active_revision_id,
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
        let mut rows: Vec<RuleRowEntry> = Vec::new();
        if want_primary {
            rows.extend(dto.primary.iter().map(|d| rule_dto_to_row(d, "primary")));
        }
        if want_secondary {
            rows.extend(
                dto.secondary
                    .iter()
                    .map(|d| rule_dto_to_row(d, "secondary")),
            );
        }
        RulesListResponse {
            rows,
            supported_rule_types: rule_type_slugs(),
            active_revision_id,
        }
    }
}

impl RulesSnapshotProvider for ProductionRulesSnapshotProvider {
    fn rules_snapshot(&self, route_filter: RulesRouteFilter) -> RulesListResponse {
        let empty = RulesListResponse {
            rows: Vec::new(),
            supported_rule_types: rule_type_slugs(),
            active_revision_id: None,
        };
        let mut resp = {
            let Ok(conn) = self.conn.lock() else {
                return empty;
            };
            let repo = nrr_storage::revisions::RevisionsRepository::new(&conn);
            match repo.get_active() {
                Ok(Some(rec)) => Self::project(rec, route_filter),
                _ => return empty,
            }
        };
        // Annotate AFTER releasing the DB lock — the `hosts` read is file I/O.
        self.annotate(&mut resp, "");
        resp
    }

    /// The caller's per-principal active revision, with
    /// read-through to the shared baseline when the caller has not diverged
    /// yet (mirrors `ProductionRulesProvider::active_rules_for`).
    fn rules_snapshot_for(
        &self,
        route_filter: RulesRouteFilter,
        principal: &str,
    ) -> RulesListResponse {
        let empty = RulesListResponse {
            rows: Vec::new(),
            supported_rule_types: rule_type_slugs(),
            active_revision_id: None,
        };
        let mut resp = {
            let Ok(conn) = self.conn.lock() else {
                return empty;
            };
            let repo = nrr_storage::revisions::RevisionsRepository::new(&conn);
            // Caller's own active first; fall back to baseline read-through.
            if let Ok(Some(rec)) = repo.get_active_for(principal) {
                Self::project(rec, route_filter)
            } else if principal != nrr_storage::BASELINE_PRINCIPAL {
                match repo.get_active_for(nrr_storage::BASELINE_PRINCIPAL) {
                    Ok(Some(rec)) => Self::project(rec, route_filter),
                    _ => return empty,
                }
            } else {
                return empty;
            }
        };
        // Annotate AFTER releasing the DB lock — the `hosts` read is file I/O.
        self.annotate(&mut resp, principal);
        resp
    }
}

/// Project one canonical `RuleDto` into a GUI `RuleRowEntry`. Prefers the
/// address-side match for the displayed type/value (an AND rule with both
/// an address and an app match shows the address; an app-only rule falls
/// back to the application pattern).
fn rule_dto_to_row(dto: &nrr_shared::rules_json::RuleDto, route: &str) -> RuleRowEntry {
    use nrr_shared::rules_json::{AddressMatchDto, AppPatternDto};
    let (rule_type, match_value) = if let Some(addr) = &dto.address_match {
        match addr {
            AddressMatchDto::ExactFqdn { value } => ("domain".to_string(), value.clone()),
            AddressMatchDto::SuffixDomain { suffix } => {
                ("domain".to_string(), format!("*.{suffix}"))
            }
            AddressMatchDto::Zone { name } => ("zone".to_string(), name.clone()),
            AddressMatchDto::ExactIpv4 { address } | AddressMatchDto::ExactIpv6 { address } => {
                ("exact-ip".to_string(), address.clone())
            }
        }
    } else if let Some(app) = &dto.app_match {
        let value = match &app.pattern {
            AppPatternDto::Exact { value } => value.clone(),
            AppPatternDto::Glob { value } => value.clone(),
        };
        ("application".to_string(), value)
    } else {
        ("application".to_string(), String::new())
    };
    let validation =
        nrr_domain::rule_value_validation::validate_rule_value(&rule_type, &match_value);
    let message_key = validation.message_key();
    // A Block-action rule displays as the "block" route regardless of which
    // bucket it physically lives in — set membership is enforcement-irrelevant
    // for a blocked rule (the WFP codegen drops it). The QML list maps the
    // "block" slug back to «Блокировать».
    let target_route = if dto.action.is_route() {
        route.to_string()
    } else {
        "block".to_string()
    };
    RuleRowEntry {
        id: dto.id.clone(),
        rule_type,
        match_value,
        target_route,
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

/// Annotate exact-FQDN domain rows with the OS `hosts`-file override that
/// pins the same hostname.
///
/// Only rows whose match value is a bare hostname (`rule_type == "domain"`
/// and NOT a `*.suffix` wildcard) are considered: the resolver applies
/// `hosts` entries by exact name before any traffic reaches NRR, so this is
/// a purely informational badge. Each lookup is O(1) against the pre-read
/// map, so this scales trivially to huge ad-block `hosts` files — only
/// matching rows are annotated; the full `hosts` list never crosses the
/// wire. Rows with no match (or of another type) are left untouched.
fn annotate_hosts_overrides(
    resp: &mut RulesListResponse,
    hosts: &std::collections::HashMap<String, nrr_platform_api::hosts_file::HostsPin>,
) {
    if hosts.is_empty() {
        return;
    }
    for row in &mut resp.rows {
        // Exact-FQDN domain rules only. Suffix-domain rules render as
        // "*.suffix" (skip — a suffix would need an O(map) scan and is out
        // of MVP scope); zones/IPs/apps are not resolver hostnames.
        if row.rule_type != "domain" || row.match_value.trim_start().starts_with("*.") {
            continue;
        }
        let key = nrr_platform_api::hosts_file::normalize_hostname(&row.match_value);
        if key.is_empty() {
            continue;
        }
        if let Some(pin) = hosts.get(&key) {
            row.hosts_override = Some(nrr_shared::ipc_payloads::HostsOverrideDto {
                ip: pin.ip.to_string(),
                blocking: pin.blocking,
            });
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
    /// Optional FQDN cache so DoH-resolver-list HOST entries
    /// (`dns.google`) resolve to IPs for the lockdown. IP entries need no cache;
    /// host entries contribute nothing until this is wired (best-effort). The
    /// seed list carries an IP for every resolver, so the lockdown is fully
    /// functional by IP even without host resolution.
    fqdn_cache: Option<Arc<dyn crate::fqdn_cache_lookup::FqdnCacheLookup>>,
}

impl ProductionRoutePolicySource {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self {
            conn,
            fqdn_cache: None,
        }
    }

    /// Wires the FQDN cache so DoH-resolver HOST entries resolve.
    pub fn with_fqdn_cache(
        mut self,
        fqdn_cache: Arc<dyn crate::fqdn_cache_lookup::FqdnCacheLookup>,
    ) -> Self {
        self.fqdn_cache = Some(fqdn_cache);
        self
    }

    /// Resolves the ENABLED DoH-resolver-list entries to the IPv4s
    /// the lockdown blocks: literal IP entries as-is, host entries through the
    /// FQDN cache (best-effort — an un-cached host yields nothing). Reads the
    /// shared `doh_resolver_entries` baseline via the already-held state-DB conn.
    fn resolve_doh_resolver_ips(&self, conn: &Connection) -> Vec<std::net::Ipv4Addr> {
        use nrr_storage::doh_lockdown::{DohResolverEntriesRepository, DohTarget};
        let entries = match DohResolverEntriesRepository::new(conn).load_all() {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };
        let mut ips: Vec<std::net::Ipv4Addr> = Vec::new();
        for entry in entries.into_iter().filter(|e| e.enabled) {
            match entry.target {
                DohTarget::Ip(ip) => ips.push(ip),
                DohTarget::Host(host) => {
                    if let Some(cache) = self.fqdn_cache.as_ref() {
                        ips.extend(crate::dns_wire::only_v4(&cache.ips_for_hostname(&host)));
                    }
                }
            }
        }
        ips.sort_unstable();
        ips.dedup();
        ips
    }
}

impl RoutePolicySource for ProductionRoutePolicySource {
    fn load_for_sid(&self, sid: &str) -> Option<PerSidPolicySnapshot> {
        let conn = self.conn.lock().ok()?;
        let repo = RouteBindingsRepository::new(&conn);
        let record = repo.load_for_sid(sid).ok()?;
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
        // Resolve the DoH-resolver list only when the lockdown is
        // on (avoid the list read + cache lookups otherwise).
        let doh_resolver_ips = if record.doh_lockdown_enabled {
            self.resolve_doh_resolver_ips(&conn)
        } else {
            Vec::new()
        };
        Some(PerSidPolicySnapshot {
            primary: record.primary.map(record_binding_to_per_sid),
            secondary: record.secondary.map(record_binding_to_per_sid),
            mode: behavior_mode_to_per_sid(record.mode),
            block_secondary_when_unavailable: record.block_secondary_when_unavailable,
            kill_switch_fail_closed: record.kill_switch_fail_closed,
            kill_switch_protocols: record.kill_switch_protocols,
            kill_switch_block_all: record.kill_switch_block_all,
            kill_switch_enabled: record.kill_switch_enabled,
            allow_dns_over_primary: record.allow_dns_over_primary,
            shared_ip_policy: record.shared_ip_policy,
            kill_switch_strict_shared_ips: record.kill_switch_strict_shared_ips,
            mode_a_coverage_strategy: record.mode_a_coverage_strategy,
            link_provider_exe_paths,
            doh_lockdown_enabled: record.doh_lockdown_enabled,
            doh_lockdown_scope: record.doh_lockdown_scope,
            doh_resolver_ips,
            auto_rules_mode: record.auto_rules_mode,
            primary_probe_auto: record.primary_probe_auto,
            primary_probe_timeout_ms: record.primary_probe_timeout_ms,
            primary_probe_max_targets: record.primary_probe_max_targets,
            primary_probe_repeat_secs: record.primary_probe_repeat_secs,
            local_networks_auto_accept: record.local_networks_auto_accept,
            zone_priority_over_ip: record.zone_priority_over_ip,
        })
    }
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
        BehaviorMode::StrictSecondaryFailClosed => PerSidBehaviorMode::StrictSecondaryFailClosed,
    }
}

// ── IPC-shaped route policy provider/writer ──────────────────────────────────

/// Returns the caller's per-SID `RoutePolicyDto`. Empty rows produce
/// `None` (the documented "drive migration first" signal).
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
        let conn = self.conn.lock().ok()?;
        let repo = RouteBindingsRepository::new(&conn);
        let record = repo.load_for_sid(sid).ok()?;
        if record.primary.is_none() && record.secondary.is_none() {
            return None;
        }
        // Best-effort — a provider-set read failure must not hide the policy.
        let providers = repo
            .load_link_provider_apps(sid, "secondary")
            .unwrap_or_default();
        Some(record_to_dto(record, providers))
    }
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
    fn update_for_sid(
        &self,
        sid: &str,
        request: &RoutePolicyUpdateRequest,
    ) -> Result<RoutePolicyDto, RoutePolicyWriteError> {
        if sid.is_empty() {
            return Err(RoutePolicyWriteError::EmptySid);
        }
        let record = RoutePolicyRecord {
            primary: request.primary.as_ref().map(dto_binding_to_record),
            secondary: request.secondary.as_ref().map(dto_binding_to_record),
            mode: dto_mode_to_storage(request.mode),
            block_secondary_when_unavailable: request.block_secondary_when_unavailable,
            kill_switch_fail_closed: request.kill_switch_fail_closed,
            kill_switch_protocols: request.kill_switch_protocols,
            kill_switch_block_all: request.kill_switch_block_all,
            kill_switch_enabled: request.kill_switch_enabled,
            allow_dns_over_primary: request.allow_dns_over_primary,
            include_subdomains: request.include_subdomains,
            // Unknown slug (older/other peer) → the balanced default; never
            // silently widen routing beyond what the user picked.
            shared_ip_policy: nrr_domain::shared_ip::SharedIpPolicy::from_slug(
                &request.shared_ip_policy,
            )
            .unwrap_or_default(),
            // Mode-A coverage strategy + hosts-bypass. Unknown slug →
            // the default (fail-closed-unknown, the stricter, safe
            // direction); never silently change enforcement beyond the pick.
            mode_a_coverage_strategy:
                nrr_domain::mode_a_coverage::ModeACoverageStrategy::from_slug(
                    &request.mode_a_coverage_strategy,
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
            binding_source: dto_source_to_storage(request.binding_source),
        };
        let conn = self
            .conn
            .lock()
            .map_err(|_| RoutePolicyWriteError::Storage("connection mutex poisoned".into()))?;
        let repo = RouteBindingsRepository::new(&conn);
        repo.update_for_sid(sid, &record, now_secs())
            .map_err(|e| RoutePolicyWriteError::Storage(format!("{e:?}")))?;
        let written = repo
            .load_for_sid(sid)
            .map_err(|e| RoutePolicyWriteError::Storage(format!("{e:?}")))?;
        let providers = repo
            .load_link_provider_apps(sid, "secondary")
            .unwrap_or_default();
        Ok(record_to_dto(written, providers))
    }
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
}

impl ProductionPrincipalDataPurger {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
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
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| RoutePolicyWriteError::Storage("connection mutex poisoned".into()))?;
        let summary = nrr_storage::purge_principal_data(&mut conn, sid)
            .map_err(|e| RoutePolicyWriteError::Storage(format!("{e:?}")))?;
        let rules_rows_deleted = if include_rules_history {
            nrr_storage::purge_principal_rules(&mut conn, sid)
                .map_err(|e| RoutePolicyWriteError::Storage(format!("{e:?}")))?
        } else {
            0
        };
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
            total.rows_deleted += summary.rows_deleted;
            total.tables_touched = total.tables_touched.max(summary.tables_touched as u32);
            if include_rules_history {
                total.rules_rows_deleted +=
                    nrr_storage::purge_principal_rules(&mut conn, principal)
                        .map_err(|e| RoutePolicyWriteError::Storage(format!("{e:?}")))?;
            }
        }
        total.principals_purged = principals.len() as u32;
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
) -> RoutePolicyDto {
    RoutePolicyDto {
        primary: rec.primary.map(record_binding_to_dto),
        secondary: rec.secondary.map(record_binding_to_dto),
        mode: storage_mode_to_dto(rec.mode),
        block_secondary_when_unavailable: rec.block_secondary_when_unavailable,
        kill_switch_fail_closed: rec.kill_switch_fail_closed,
        kill_switch_protocols: rec.kill_switch_protocols,
        kill_switch_block_all: rec.kill_switch_block_all,
        kill_switch_enabled: rec.kill_switch_enabled,
        allow_dns_over_primary: rec.allow_dns_over_primary,
        include_subdomains: rec.include_subdomains,
        shared_ip_policy: rec.shared_ip_policy.as_slug().to_string(),
        mode_a_coverage_strategy: rec.mode_a_coverage_strategy.as_slug().to_string(),
        resolve_hosts_bypass: rec.resolve_hosts_bypass,
        secondary_link_provider_apps: secondary_link_providers
            .into_iter()
            .map(provider_record_to_dto)
            .collect(),
        doh_lockdown_enabled: rec.doh_lockdown_enabled,
        doh_lockdown_scope: rec.doh_lockdown_scope.as_slug().to_string(),
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
        BehaviorMode::StrictSecondaryFailClosed => BehaviorModeDto::StrictSecondaryFailClosed,
    }
}

fn dto_mode_to_storage(mode: BehaviorModeDto) -> BehaviorMode {
    match mode {
        BehaviorModeDto::PreferPrimary => BehaviorMode::PreferPrimary,
        BehaviorModeDto::PreferSecondaryWhenAvailable => BehaviorMode::PreferSecondaryWhenAvailable,
        BehaviorModeDto::StrictSecondaryFailClosed => BehaviorMode::StrictSecondaryFailClosed,
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
            extended_sections: Vec::new(),
            cross_set_duplicates: Vec::new(),
        }
    }

    fn execute(&self, _payload: StoredMutation, _principal: &str) -> MutationOutcome {
        MutationOutcome::Failed(OperationError {
            code: "not-implemented".into(),
            message: "revision mutations are not available on this platform".into(),
        })
    }

    fn rollback(&self, _principal: &str, _target_revision_id: Option<&str>) -> MutationOutcome {
        MutationOutcome::Failed(OperationError {
            code: "not-implemented".into(),
            message: "rollback is not available on this platform".into(),
        })
    }

    fn safe_disable(&self, _reason: &str) -> MutationOutcome {
        MutationOutcome::Failed(OperationError {
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

pub struct MonitoredAdaptersSnapshotProvider {
    api: Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
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
}

struct CachedExternalAddress {
    external_ip: String,
    local_ip: String,
}

impl MonitoredAdaptersSnapshotProvider {
    pub fn new(api: Arc<dyn nrr_platform_api::route_table::RouteTablePort>) -> Self {
        Self {
            api,
            last_external: Mutex::new(std::collections::HashMap::new()),
            address_recorder: None,
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
    fn fold_cached_external(&self, rows: &mut [nrr_platform_api::InterfaceRouteRow]) {
        let Ok(mut cache) = self.last_external.lock() else {
            return;
        };
        for row in rows {
            let key = if row.persistent_id.is_empty() {
                row.adapter_name.clone()
            } else {
                row.persistent_id.clone()
            };
            if let Some(ip) = row.observed_facts.external_ip.clone() {
                cache.insert(
                    key,
                    CachedExternalAddress {
                        external_ip: ip.clone(),
                        local_ip: row.local_ip.clone(),
                    },
                );
                // Persist a FRESH resolution only (this
                // branch is never reached for a replayed/cached one, which
                // takes the `Some(entry) if ...` arm below). The join key is
                // `row.windows_name` — the OS friendly interface name shown
                // in `resolve_windows_name` — NOT `row.adapter_name`, which
                // carries the low-level identity (a GUID on Windows, see
                // `interface_manager::collect_windows_adapters`) and never
                // matches the traffic ledger's key. The ledger keys on
                // `MIB_IF_ROW2.Alias` (`nrr_platform_windows::interface_traffic`),
                // which is the same OS-assigned friendly name `windows_name`
                // resolves to, so this is an exact match, not a best-effort
                // guess — in the rare case the two disagree (a rename race
                // between the two enumerations), the row simply gets no
                // address annotation this round rather than a wrong one.
                if let Some(recorder) = &self.address_recorder {
                    if !row.windows_name.is_empty() && !row.local_ip.is_empty() {
                        recorder.record(&row.windows_name, &row.local_ip, &ip, now_ms());
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
                if !row.windows_name.is_empty() && !row.local_ip.is_empty() {
                    if let Some(stored_local) = recorder.remembered_local_ip(&row.windows_name) {
                        if stored_local != row.local_ip {
                            recorder.forget_external(&row.windows_name, &row.local_ip, now_ms());
                        }
                    }
                }
            }
            match cache.get(&key) {
                Some(entry) if entry.local_ip == row.local_ip => {
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

    fn snapshot(&self, probe_external_ip: bool) -> SnapshotInterfacesResponse {
        let adapters = match self.api.get_adapter_infos() {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::adapters",
                    error = %format!("{e:?}"),
                    "get_adapter_infos failed; returning empty snapshot",
                );
                Vec::new()
            }
        };
        // Build the rich, GUI-shaped rows from a fresh live
        // enumeration so the GUI "Interfaces & routes" list reflects
        // runtime-appearing adapters (VPN up, USB dongle, VM NIC) on a
        // plain "Refresh interfaces" — the service is the single source
        // of truth for the adapter list. The external-address probe runs only
        // when `probe_external_ip` says the user asked for it; every other
        // snapshot path stays network-silent and returns immediately. The
        // enrichment is the same builder the GUI cold-start path uses, so
        // a refreshed row renders identically to a cold-start one.
        // Each OS enumerates its own links; the rows and every judgement on
        // them are the neutral ones. An OS with no enumeration of its own says
        // so with the placeholder set rather than inventing adapters.
        #[cfg(windows)]
        let (source, mut rich_rows) =
            nrr_platform_windows::interface_rows::collect_interfaces_rows(probe_external_ip);
        #[cfg(target_os = "linux")]
        let (source, mut rich_rows) =
            nrr_platform_linux::interface_rows::collect_interfaces_rows(probe_external_ip);
        #[cfg(not(any(windows, target_os = "linux")))]
        let (source, mut rich_rows) = {
            let _ = probe_external_ip;
            (
                nrr_platform_api::InterfacesDataSource::FallbackMock,
                nrr_platform_api::fallback_rows(),
            )
        };
        // Report the provenance the enumeration actually reached, not the one
        // this path hopes for. The rows are a deterministic PLACEHOLDER
        // whenever the live enumeration came back empty, and a placeholder
        // announced as `windows-live` is how invented adapters reach a user
        // about to bind a route to one.
        if !source.is_live() {
            tracing::warn!(
                target: "nrr::snapshot-interfaces",
                data_source = source.title(),
                rows = rich_rows.len(),
                "live adapter enumeration produced nothing — answering with the deterministic placeholder dataset, marked as such",
            );
        }
        self.fold_cached_external(&mut rich_rows);
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
        self.snapshot(false)
    }

    fn adapters_snapshot_probing_external_ip(&self) -> SnapshotInterfacesResponse {
        self.snapshot(true)
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

    /// Match the wire-formatted oper_status against the documented
    /// "up" marker. `adapter_to_entry` formats via `{:?}` on
    /// `IfOperStatus::Up` → "Up". Any other value (Down, Testing,
    /// Dormant, Unknown, NotPresent, …) is treated as offline for the
    /// purposes of fail-closed evaluation.
    fn adapter_is_up(entry: &crate::ipc_handlers::payloads::AdapterEntry) -> bool {
        entry.oper_status == "Up"
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
                fail_closed_active = new_state,
                "secondary route fail-closed state",
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
                    error = %e,
                    "RouteBindingsRepository::load_for_sid failed; suppressing Fail-Closed banner",
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
        let adapter = adapters.iter().find(|a| {
            crate::route_coordinator::adapter_entry_binding_matches(a, &secondary.stable_id)
        });
        let secondary_offline = match adapter {
            None => true,
            Some(a) => !Self::adapter_is_up(a),
        };
        // The banner mirrors the ACTUAL blocking posture. The
        // emergency block engages only when the MASTER kill-switch is enabled
        // (opt-in — mirror of per_sid_orchestrator.rs's `leak_guard_armed` gate)
        // AND the secondary is offline AND the posture is fail-closed (block). If
        // the kill-switch is OFF nothing blocks, so the banner stays clear; a
        // fail-open posture (`kill_switch_fail_closed == false`) likewise lets
        // traffic ride the primary, so it is not "fail-closed active".
        let fail_closed_active =
            policy.kill_switch_enabled && secondary_offline && policy.kill_switch_fail_closed;
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
    nrr_shared::ipc_payloads::AdapterEntry {
        persistent_id: stable_id,
        adapter_name: info.adapter_name.clone(),
        ipv6_if_index: info.index,
        physical_address: mac_hex,
        windows_name: info.adapter_name,
        interface_description: info.description,
        interface_type: format!("{:?}", info.interface_type),
        oper_status: format!("{:?}", info.oper_status),
    }
}

#[cfg(test)]
mod adapters_snapshot_tests;

// ── hosts-override annotation tests ───────────────────────────────────────────

#[cfg(test)]
mod hosts_override_tests;

// ── ProductionFailClosedProbe tests ───────────────────────────────────────────

#[cfg(test)]
mod fail_closed_probe_tests;

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
