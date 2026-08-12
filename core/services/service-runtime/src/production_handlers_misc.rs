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
}

impl ProductionRulesSnapshotProvider {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self {
            conn,
            hosts: Arc::new(nrr_platform_api::hosts_file::OsHostsFileReader::new()),
        }
    }

    /// Construct with an explicit `hosts` reader (tests inject a fixture).
    pub fn with_hosts_reader(
        conn: Arc<Mutex<Connection>>,
        hosts: Arc<dyn nrr_platform_api::hosts_file::HostsFileReader>,
    ) -> Self {
        Self { conn, hosts }
    }

    /// Read the `hosts` map once and annotate every eligible row in `resp`.
    fn annotate(&self, resp: &mut RulesListResponse) {
        if resp.rows.is_empty() {
            return;
        }
        let map = self.hosts.snapshot();
        annotate_hosts_overrides(resp, &map);
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
        self.annotate(&mut resp);
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
        self.annotate(&mut resp);
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
            AddressMatchDto::ExactIpv4 { address } => ("exact-ip".to_string(), address.clone()),
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
        // Filled later by `annotate_hosts_overrides` once the whole row set
        // is projected — the hosts map is read once per snapshot, not per row.
        hosts_override: None,
        // Provenance travels verbatim: the GUI marks an app-authored row and
        // names the site it was added for, and nothing else in the pipeline
        // branches on it.
        origin: dto.origin.clone(),
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
        Ok(PrincipalDataPurgeResponse {
            rows_deleted: summary.rows_deleted,
            tables_touched: summary.tables_touched as u32,
        })
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
        binding_source: storage_source_to_dto(rec.binding_source),
    }
}

fn record_binding_to_dto(rec: RouteBindingRecord) -> RouteBindingDto {
    RouteBindingDto {
        stable_id: rec.stable_id,
        display_name: rec.display_name,
        user_confirmed: rec.user_confirmed,
    }
}

fn dto_binding_to_record(b: &RouteBindingDto) -> RouteBindingRecord {
    RouteBindingRecord {
        stable_id: b.stable_id.clone(),
        display_name: b.display_name.clone(),
        user_confirmed: b.user_confirmed,
        // Ignored on write — `update_for_sid` derives known_stable_ids from the
        // DB (carry forward / reset) rather than trusting the GUI, which does
        // not track healed adapter identities.
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

// ── NoopMutationExecutor (placeholder until the real executor lands) ─────────

/// Placeholder. Returns an `OperationError::Internal` for
/// every execute call; preview returns a benign empty `ReviewSummary`;
/// rollback / safe_disable similarly fail. The settings-ops IPC flow
/// does NOT route through MutationExecutor (settings have their own
/// thin handlers) so this stub does not affect production
/// settings paths. A future revision-flow executor replaces this stub.
pub struct NoopMutationExecutor;

impl MutationExecutor for NoopMutationExecutor {
    fn preview(
        &self,
        _kind: MutationKind,
        _payload: &serde_json::Value,
        _principal: &str,
    ) -> ReviewSummaryResponse {
        ReviewSummaryResponse {
            diff_summary: "preview not implemented in phase 4a".into(),
            provenance: "service".into(),
            risk_level: ReviewRiskLevel::Low,
            requires_review: true,
            changed_fields: Vec::new(),
            risk_signals: Vec::new(),
            rules_added: Vec::new(),
            rules_removed: Vec::new(),
            rules_modified: Vec::new(),
            rules_retargeted: Vec::new(),
            pro_sections: Vec::new(),
        }
    }

    fn execute(&self, _payload: StoredMutation, _principal: &str) -> MutationOutcome {
        MutationOutcome::Failed(OperationError {
            code: "not-implemented".into(),
            message: "MutationExecutor not yet wired in phase 4a".into(),
        })
    }

    fn rollback(&self, _principal: &str, _target_revision_id: Option<&str>) -> MutationOutcome {
        MutationOutcome::Failed(OperationError {
            code: "not-implemented".into(),
            message: "rollback not yet wired in phase 4a".into(),
        })
    }

    fn safe_disable(&self, _reason: &str) -> MutationOutcome {
        MutationOutcome::Failed(OperationError {
            code: "not-implemented".into(),
            message: "safe_disable not yet wired in phase 4a".into(),
        })
    }
}

// ── NoopAdaptersSnapshotProvider ─────────────────────────────────────────────

/// Returns an empty adapters list. A future real adapter
/// wraps `AdapterMonitor::snapshot()` and maps to
/// `SnapshotInterfacesResponse`. Until then the GUI's interfaces panel
/// shows "no adapters detected".
pub struct NoopAdaptersSnapshotProvider;

impl AdaptersSnapshotProvider for NoopAdaptersSnapshotProvider {
    fn adapters_snapshot(&self, _force_refresh: bool) -> SnapshotInterfacesResponse {
        SnapshotInterfacesResponse {
            data_source: "noop-phase-4a".into(),
            adapters: Vec::new(),
            // Secondary route state — this noop has
            // no policy/adapter visibility, so we report `None`. The
            // GUI treats `None` as "no banner".
            secondary: None,
            // No enriched rows from the noop provider.
            rows: Vec::new(),
        }
    }
}

// ── MonitoredAdaptersSnapshotProvider ─────────────────────────────────────────

/// Production [`AdaptersSnapshotProvider`] backed by
/// [`WindowsApiPort::get_adapter_infos`]. Each call enumerates the
/// adapter list synchronously and projects every
/// [`AdapterInfo`](nrr_platform_api::adapters::AdapterInfo) into
/// the wire-shape [`AdapterEntry`](nrr_shared::ipc_payloads::AdapterEntry).
///
/// "Monitored" denotes the lifecycle relationship with the supervisor's
/// `adapter-monitor-tick`: the monitor keeps the
/// platform-side view warm via its 1-second debounce poll. The
/// snapshot path queries fresh on demand — `force_refresh` is honoured
/// implicitly because the underlying `GetAdaptersAddresses` call always
/// returns the current kernel state.
///
/// This is the one provider that can reach the network, and only through
/// `adapters_snapshot_probing_external_ip`: that variant additionally asks
/// each live adapter for the address the outside world sees behind it, which
/// costs a few seconds and sends packets to a third party. `adapters_snapshot`
/// itself never does.
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
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub struct MonitoredAdaptersSnapshotProvider {
    api: Arc<dyn nrr_platform_api::windows_api::WindowsApiPort>,
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
    pub fn new(api: Arc<dyn nrr_platform_api::windows_api::WindowsApiPort>) -> Self {
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
        // The live adapter enumeration is Windows-only; off
        // Windows the service returns the neutral deterministic fallback rows.
        #[cfg(windows)]
        let (_source, mut rich_rows) =
            nrr_platform_windows::interface_rows::collect_interfaces_rows(probe_external_ip);
        #[cfg(not(windows))]
        let (_source, mut rich_rows) = {
            let _ = probe_external_ip;
            (
                nrr_platform_api::InterfacesDataSource::FallbackMock,
                nrr_platform_api::fallback_rows(),
            )
        };
        self.fold_cached_external(&mut rich_rows);
        let rows = rich_rows
            .iter()
            .map(nrr_shared::ipc_payloads::InterfaceRowDto::from)
            .collect::<Vec<_>>();
        SnapshotInterfacesResponse {
            data_source: "windows-live".into(),
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
mod adapters_snapshot_tests {
    use super::*;
    use nrr_platform_api::adapters::{IfOperStatus, InterfaceType};
    use nrr_platform_api::windows_api::{MockWindowsApi, WindowsApiPort};
    use std::net::Ipv4Addr;

    #[test]
    fn empty_adapter_list_yields_empty_wire_response() {
        let api = Arc::new(MockWindowsApi::new());
        let provider = MonitoredAdaptersSnapshotProvider::new(api as Arc<dyn WindowsApiPort>);
        let resp = provider.adapters_snapshot(false);
        assert_eq!(resp.data_source, "windows-live");
        assert!(resp.adapters.is_empty());
    }

    #[test]
    fn projection_carries_mac_and_index() {
        use nrr_platform_api::adapters::AdapterInfo;
        let api = Arc::new(MockWindowsApi::new());
        api.set_adapter_infos(vec![AdapterInfo {
            index: 17,
            adapter_name: "{ABCD-EFGH}".into(),
            description: "Test Wi-Fi".into(),
            friendly_name: "Wi-Fi".into(),
            mac: Some([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]),
            interface_type: InterfaceType::Wireless,
            oper_status: IfOperStatus::Up,
            ipv4_addresses: vec![Ipv4Addr::new(192, 168, 1, 5)],
            gateways: vec![Ipv4Addr::new(192, 168, 1, 1)],
        }]);
        let provider = MonitoredAdaptersSnapshotProvider::new(api as Arc<dyn WindowsApiPort>);
        let resp = provider.adapters_snapshot(false);
        assert_eq!(resp.adapters.len(), 1);
        let entry = &resp.adapters[0];
        assert_eq!(entry.ipv6_if_index, 17);
        assert_eq!(entry.physical_address.as_deref(), Some("DE:AD:BE:EF:00:01"));
        assert_eq!(entry.persistent_id, "de:ad:be:ef:00:01");
        assert_eq!(entry.interface_description, "Test Wi-Fi");
    }

    // ── AdapterAddressRecorder wiring ─────────────────────────────────────────

    struct FakeAddressRecorder {
        calls: Mutex<Vec<(String, String, String)>>,
    }

    impl FakeAddressRecorder {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl AdapterAddressRecorder for FakeAddressRecorder {
        fn record(&self, adapter_key: &str, local_ip: &str, external_ip: &str, _ms: i64) {
            self.calls.lock().expect("lock").push((
                adapter_key.to_string(),
                local_ip.to_string(),
                external_ip.to_string(),
            ));
        }
    }

    #[test]
    fn fold_cached_external_persists_fresh_resolution_keyed_by_windows_name() {
        // `fallback_rows()`'s Ethernet entry ships a FRESH external-IP
        // resolution with `adapter_name` ("{FAKE-ETHERNET-ADAPTER}", a GUID)
        // deliberately distinct from `windows_name` ("Ethernet") — proves the
        // join key used is `windows_name`, matching the traffic ledger's
        // `Alias`-derived key, not the low-level identity GUID.
        let api = Arc::new(MockWindowsApi::new());
        let recorder = Arc::new(FakeAddressRecorder::new());
        let provider = MonitoredAdaptersSnapshotProvider::new(api as Arc<dyn WindowsApiPort>)
            .with_address_recorder(Arc::clone(&recorder) as Arc<dyn AdapterAddressRecorder>);

        let mut rows = nrr_platform_api::interface_rows::fallback_rows();
        provider.fold_cached_external(&mut rows);

        let calls = recorder.calls.lock().expect("lock");
        assert_eq!(
            calls.len(),
            1,
            "only the Ethernet row carries a fresh probe result"
        );
        assert_eq!(
            calls[0],
            (
                "Ethernet".to_string(),
                "192.168.1.20".to_string(),
                "203.0.113.10".to_string(),
            )
        );
    }

    #[test]
    fn fold_cached_external_does_not_persist_a_replayed_address() {
        // Second call: nothing in the fresh set has changed, so
        // `apply_external_ip_probes` was never re-run — simulate that by
        // clearing `external_ip` on a copy and folding again. The replay
        // path (carry-forward from `last_external`) must NOT call the
        // recorder — only a genuinely fresh resolution does.
        let api = Arc::new(MockWindowsApi::new());
        let recorder = Arc::new(FakeAddressRecorder::new());
        let provider = MonitoredAdaptersSnapshotProvider::new(api as Arc<dyn WindowsApiPort>)
            .with_address_recorder(Arc::clone(&recorder) as Arc<dyn AdapterAddressRecorder>);

        let mut first = nrr_platform_api::interface_rows::fallback_rows();
        provider.fold_cached_external(&mut first);
        assert_eq!(recorder.calls.lock().expect("lock").len(), 1);

        let mut second = nrr_platform_api::interface_rows::fallback_rows();
        for row in &mut second {
            row.observed_facts.external_ip = None;
        }
        provider.fold_cached_external(&mut second);
        assert_eq!(
            recorder.calls.lock().expect("lock").len(),
            1,
            "a replayed (cached) address must not be persisted again"
        );
    }

    #[test]
    fn without_a_recorder_fold_cached_external_is_a_noop_for_persistence() {
        let api = Arc::new(MockWindowsApi::new());
        let provider = MonitoredAdaptersSnapshotProvider::new(api as Arc<dyn WindowsApiPort>);
        let mut rows = nrr_platform_api::interface_rows::fallback_rows();
        // Must not panic without a recorder wired.
        provider.fold_cached_external(&mut rows);
    }
}

// ── hosts-override annotation tests ───────────────────────────────────────────

#[cfg(test)]
mod hosts_override_tests {
    use super::*;
    use nrr_platform_api::hosts_file::HostsPin;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    fn row(rule_type: &str, match_value: &str) -> RuleRowEntry {
        RuleRowEntry {
            id: "R-1".into(),
            rule_type: rule_type.into(),
            match_value: match_value.into(),
            target_route: "primary".into(),
            comment: None,
            enabled: true,
            validation_status: "ok".into(),
            validation_message_key: None,
            hosts_override: None,
            origin: None,
        }
    }

    fn resp(rows: Vec<RuleRowEntry>) -> RulesListResponse {
        RulesListResponse {
            rows,
            supported_rule_types: rule_type_slugs(),
            active_revision_id: Some("rev-1".into()),
        }
    }

    fn hosts_map() -> HashMap<String, HostsPin> {
        let mut m = HashMap::new();
        m.insert(
            "ads.example.com".into(),
            HostsPin {
                ip: Ipv4Addr::LOCALHOST,
                blocking: true,
            },
        );
        m.insert(
            "mirror.example.com".into(),
            HostsPin {
                ip: Ipv4Addr::new(203, 0, 113, 7),
                blocking: false,
            },
        );
        m
    }

    #[test]
    fn blocking_entry_annotates_domain_row() {
        let mut r = resp(vec![row("domain", "ads.example.com")]);
        annotate_hosts_overrides(&mut r, &hosts_map());
        let ov = r.rows[0].hosts_override.as_ref().expect("annotated");
        assert!(ov.blocking);
        assert_eq!(ov.ip, "127.0.0.1");
    }

    #[test]
    fn redirect_entry_carries_real_ip() {
        let mut r = resp(vec![row("domain", "mirror.example.com")]);
        annotate_hosts_overrides(&mut r, &hosts_map());
        let ov = r.rows[0].hosts_override.as_ref().expect("annotated");
        assert!(!ov.blocking);
        assert_eq!(ov.ip, "203.0.113.7");
    }

    #[test]
    fn matching_is_case_insensitive_and_dot_tolerant() {
        let mut r = resp(vec![row("domain", "ADS.Example.COM.")]);
        annotate_hosts_overrides(&mut r, &hosts_map());
        assert!(r.rows[0].hosts_override.is_some());
    }

    #[test]
    fn non_matching_and_non_domain_rows_are_untouched() {
        let mut r = resp(vec![
            row("domain", "not-in-hosts.example.com"), // no hosts entry
            row("domain", "*.example.com"),            // suffix wildcard — skipped
            row("zone", "ads.example.com"),            // zone type — skipped
            row("exact-ip", "127.0.0.1"),              // IP rule — skipped
            row("application", "browser.exe"),         // app rule — skipped
        ]);
        annotate_hosts_overrides(&mut r, &hosts_map());
        for row in &r.rows {
            assert!(
                row.hosts_override.is_none(),
                "row {} annotated",
                row.match_value
            );
        }
    }

    #[test]
    fn empty_hosts_map_is_a_noop() {
        let mut r = resp(vec![row("domain", "ads.example.com")]);
        annotate_hosts_overrides(&mut r, &HashMap::new());
        assert!(r.rows[0].hosts_override.is_none());
    }

    #[test]
    fn provider_annotate_uses_injected_reader() {
        use nrr_platform_api::hosts_file::StaticHostsFileReader;
        let reader = Arc::new(StaticHostsFileReader::from_pairs([(
            "ads.example.com",
            Ipv4Addr::LOCALHOST,
        )]));
        // The DB connection is never touched by `annotate`, so a throwaway
        // in-memory connection is fine for exercising the reader path.
        let conn = Arc::new(Mutex::new(
            rusqlite::Connection::open_in_memory().expect("open in-memory"),
        ));
        let provider = ProductionRulesSnapshotProvider::with_hosts_reader(conn, reader);
        let mut r = resp(vec![row("domain", "ads.example.com")]);
        provider.annotate(&mut r);
        assert!(
            r.rows[0]
                .hosts_override
                .as_ref()
                .expect("annotated")
                .blocking
        );
    }
}

// ── ProductionFailClosedProbe tests ───────────────────────────────────────────

#[cfg(test)]
mod fail_closed_probe_tests {
    use super::*;
    use crate::ipc_handlers::payloads::AdapterEntry;
    use crate::ipc_handlers::providers::FailClosedStateProbe;
    use nrr_storage::migration::{open_connection, SqliteMigrationRunner};
    use nrr_storage::repository::MigrationRunner;
    use nrr_storage::route_bindings::{
        BehaviorMode, BindingSource, RouteBindingRecord, RoutePolicyRecord,
    };

    const TEST_SID: &str = "S-1-5-21-test";
    const SECONDARY_ID: &str = "vpn-adapter-stable-id";

    fn open_state_db() -> (tempfile::TempDir, Arc<Mutex<Connection>>) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("state.db");
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        let conn = runner.into_connection();
        (dir, Arc::new(Mutex::new(conn)))
    }

    fn seed_policy(
        conn: &Arc<Mutex<Connection>>,
        mode: BehaviorMode,
        block_when_unavailable: bool,
    ) {
        // Default posture is fail-closed (block) — the common case.
        seed_policy_posture(conn, mode, block_when_unavailable, true);
    }

    fn seed_policy_posture(
        conn: &Arc<Mutex<Connection>>,
        mode: BehaviorMode,
        block_when_unavailable: bool,
        kill_switch_fail_closed: bool,
    ) {
        let guard = conn.lock().unwrap();
        let repo = RouteBindingsRepository::new(&guard);
        repo.update_for_sid(
            TEST_SID,
            &RoutePolicyRecord {
                primary: Some(RouteBindingRecord {
                    stable_id: "primary-id".into(),
                    display_name: "Primary".into(),
                    user_confirmed: true,
                    known_stable_ids: vec![],
                }),
                secondary: Some(RouteBindingRecord {
                    stable_id: SECONDARY_ID.into(),
                    display_name: "Secondary VPN".into(),
                    user_confirmed: true,
                    known_stable_ids: vec![],
                }),
                mode,
                block_secondary_when_unavailable: block_when_unavailable,
                kill_switch_fail_closed,
                kill_switch_protocols: 0x7F,
                kill_switch_block_all: false,
                // This fixture drives fail-closed behaviour tests; keep
                // the master toggle ON so the armed path is exercised.
                kill_switch_enabled: true,
                allow_dns_over_primary: false,
                include_subdomains: false,
                shared_ip_policy: nrr_domain::shared_ip::SharedIpPolicy::default(),
                mode_a_coverage_strategy:
                    nrr_domain::mode_a_coverage::ModeACoverageStrategy::default(),
                resolve_hosts_bypass: true,
                doh_lockdown_enabled: false,
                doh_lockdown_scope: nrr_storage::doh_lockdown::DohLockdownScope::default(),
                browser_history_auto_seed: false,
                kill_switch_strict_shared_ips: false,
                auto_rules_mode: nrr_storage::auto_rules::AutoRulesMode::default(),
                auto_rules_eager_delivery_names: false,
                binding_source: BindingSource::UserAssigned,
            },
            100,
        )
        .expect("update_for_sid");
    }

    fn adapter(id: &str, oper_status: &str) -> AdapterEntry {
        AdapterEntry {
            persistent_id: id.into(),
            adapter_name: id.into(),
            ipv6_if_index: 0,
            physical_address: None,
            windows_name: id.into(),
            interface_description: String::new(),
            interface_type: "Ethernet".into(),
            oper_status: oper_status.into(),
        }
    }

    #[test]
    fn empty_sid_returns_none() {
        let (_d, conn) = open_state_db();
        let probe = ProductionFailClosedProbe::new(conn);
        assert!(probe.probe("", &[]).is_none());
    }

    #[test]
    fn no_secondary_bound_returns_inactive_state() {
        let (_d, conn) = open_state_db();
        // Caller has never sent a RoutePolicyUpdate — load_for_sid
        // returns the empty record (no secondary, PreferPrimary mode).
        let probe = ProductionFailClosedProbe::new(conn);
        let state = probe.probe(TEST_SID, &[]).expect("Some");
        assert!(!state.fail_closed_active);
    }

    #[test]
    fn secondary_offline_with_block_policy_on_yields_active() {
        let (_d, conn) = open_state_db();
        seed_policy(&conn, BehaviorMode::PreferPrimary, true);
        let probe = ProductionFailClosedProbe::new(conn);
        // Secondary adapter listed as Down → offline + block ON.
        let adapters = vec![adapter("primary-id", "Up"), adapter(SECONDARY_ID, "Down")];
        let state = probe.probe(TEST_SID, &adapters).expect("Some");
        assert!(state.fail_closed_active);
    }

    #[test]
    fn secondary_up_with_block_policy_on_yields_inactive() {
        let (_d, conn) = open_state_db();
        seed_policy(&conn, BehaviorMode::PreferPrimary, true);
        let probe = ProductionFailClosedProbe::new(conn);
        let adapters = vec![adapter(SECONDARY_ID, "Up")];
        let state = probe.probe(TEST_SID, &adapters).expect("Some");
        assert!(!state.fail_closed_active);
    }

    #[test]
    fn secondary_offline_with_block_toggle_off_still_yields_active() {
        // A bound secondary arms the leak-guard on
        // its own, so the opt-in `block_secondary_when_unavailable` toggle no
        // longer disables protection. An offline secondary with the default
        // fail-closed posture is therefore ACTIVE even with the toggle off.
        // The user's opt-out is the fail-OPEN posture, below.
        let (_d, conn) = open_state_db();
        seed_policy(&conn, BehaviorMode::PreferPrimary, false);
        let probe = ProductionFailClosedProbe::new(conn);
        let adapters = vec![adapter(SECONDARY_ID, "Down")];
        let state = probe.probe(TEST_SID, &adapters).expect("Some");
        assert!(state.fail_closed_active);
    }

    #[test]
    fn secondary_offline_with_fail_open_posture_yields_inactive() {
        // The way to let traffic ride the primary
        // when the secondary drops is the fail-OPEN posture
        // (kill_switch_fail_closed = false), NOT unticking the block toggle.
        let (_d, conn) = open_state_db();
        seed_policy_posture(&conn, BehaviorMode::PreferPrimary, false, false);
        let probe = ProductionFailClosedProbe::new(conn);
        let adapters = vec![adapter(SECONDARY_ID, "Down")];
        let state = probe.probe(TEST_SID, &adapters).expect("Some");
        assert!(!state.fail_closed_active);
    }

    #[test]
    fn strict_secondary_fail_closed_mode_triggers_without_explicit_block_flag() {
        let (_d, conn) = open_state_db();
        // StrictSecondaryFailClosed mode counts as block-when-unavailable
        // regardless of the explicit flag.
        seed_policy(&conn, BehaviorMode::StrictSecondaryFailClosed, false);
        let probe = ProductionFailClosedProbe::new(conn);
        let adapters = vec![adapter(SECONDARY_ID, "Down")];
        let state = probe.probe(TEST_SID, &adapters).expect("Some");
        assert!(state.fail_closed_active);
    }

    #[test]
    fn missing_secondary_adapter_in_snapshot_counts_as_offline() {
        let (_d, conn) = open_state_db();
        seed_policy(&conn, BehaviorMode::PreferPrimary, true);
        let probe = ProductionFailClosedProbe::new(conn);
        // Secondary stable_id NOT in the adapter list at all (e.g.
        // device unplugged) — must be treated as offline.
        let adapters = vec![adapter("primary-id", "Up")];
        let state = probe.probe(TEST_SID, &adapters).expect("Some");
        assert!(state.fail_closed_active);
    }

    // ── Regression: persistent-id scheme mismatch (GUID/MAC bindings) ──────

    const GUID_SECONDARY: &str = "{12AB34CD-0000-0000-0000-000000000001}";
    const MAC_SECONDARY: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    fn seed_policy_with_secondary_stable_id(
        conn: &Arc<Mutex<Connection>>,
        secondary_stable_id: &str,
    ) {
        let guard = conn.lock().unwrap();
        let repo = RouteBindingsRepository::new(&guard);
        repo.update_for_sid(
            TEST_SID,
            &RoutePolicyRecord {
                primary: Some(RouteBindingRecord {
                    stable_id: "primary-id".into(),
                    display_name: "Primary".into(),
                    user_confirmed: true,
                    known_stable_ids: vec![],
                }),
                secondary: Some(RouteBindingRecord {
                    stable_id: secondary_stable_id.into(),
                    display_name: "Secondary VPN".into(),
                    user_confirmed: true,
                    known_stable_ids: vec![],
                }),
                mode: BehaviorMode::PreferPrimary,
                block_secondary_when_unavailable: true,
                kill_switch_fail_closed: true,
                kill_switch_protocols: 0x7F,
                kill_switch_block_all: false,
                kill_switch_enabled: true,
                allow_dns_over_primary: false,
                include_subdomains: false,
                shared_ip_policy: nrr_domain::shared_ip::SharedIpPolicy::default(),
                mode_a_coverage_strategy:
                    nrr_domain::mode_a_coverage::ModeACoverageStrategy::default(),
                resolve_hosts_bypass: true,
                doh_lockdown_enabled: false,
                doh_lockdown_scope: nrr_storage::doh_lockdown::DohLockdownScope::default(),
                browser_history_auto_seed: false,
                kill_switch_strict_shared_ips: false,
                auto_rules_mode: nrr_storage::auto_rules::AutoRulesMode::default(),
                auto_rules_eager_delivery_names: false,
                binding_source: BindingSource::UserAssigned,
            },
            100,
        )
        .expect("update_for_sid");
    }

    /// Wire `AdapterEntry` as `adapter_to_entry` would produce it for a live
    /// adapter identified only by its GUID (no MAC).
    fn guid_adapter_entry(oper_status: &str) -> AdapterEntry {
        AdapterEntry {
            persistent_id: GUID_SECONDARY.into(),
            adapter_name: GUID_SECONDARY.into(),
            ipv6_if_index: 7,
            physical_address: None,
            windows_name: "VPN".into(),
            interface_description: String::new(),
            interface_type: "Ppp".into(),
            oper_status: oper_status.into(),
        }
    }

    fn mac_hex_colon(mac: [u8; 6]) -> String {
        mac.iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    #[test]
    fn win_adapter_scheme_binding_matches_live_guid_adapter_up() {
        // Regression for the persistent-id scheme mismatch: the binding
        // stores `win-adapter:{lowercased-guid}` (the GUI persistent-id
        // scheme), while the wire `AdapterEntry` this probe receives carries
        // `AdapterInfo::stable_id()` (bare GUID here, no MAC). A raw `==`
        // compare between the two schemes never matched, so a live,
        // working secondary was permanently reported offline.
        let (_d, conn) = open_state_db();
        let bound_id = format!("win-adapter:{}", GUID_SECONDARY.to_ascii_lowercase());
        seed_policy_with_secondary_stable_id(&conn, &bound_id);
        let probe = ProductionFailClosedProbe::new(conn);

        let adapters = vec![adapter("primary-id", "Up"), guid_adapter_entry("Up")];
        let state = probe.probe(TEST_SID, &adapters).expect("Some");
        assert!(
            !state.fail_closed_active,
            "a live win-adapter:-scheme secondary must not trip the Fail-Closed banner"
        );
    }

    #[test]
    fn win_adapter_scheme_binding_down_adapter_yields_active() {
        let (_d, conn) = open_state_db();
        let bound_id = format!("win-adapter:{}", GUID_SECONDARY.to_ascii_lowercase());
        seed_policy_with_secondary_stable_id(&conn, &bound_id);
        let probe = ProductionFailClosedProbe::new(conn);

        let adapters = vec![adapter("primary-id", "Up"), guid_adapter_entry("Down")];
        let state = probe.probe(TEST_SID, &adapters).expect("Some");
        assert!(
            state.fail_closed_active,
            "a resolved but Down secondary must still trip the banner"
        );
    }

    #[test]
    fn win_adapter_scheme_binding_absent_adapter_yields_active() {
        let (_d, conn) = open_state_db();
        let bound_id = format!("win-adapter:{}", GUID_SECONDARY.to_ascii_lowercase());
        seed_policy_with_secondary_stable_id(&conn, &bound_id);
        let probe = ProductionFailClosedProbe::new(conn);

        let adapters = vec![adapter("primary-id", "Up")];
        let state = probe.probe(TEST_SID, &adapters).expect("Some");
        assert!(
            state.fail_closed_active,
            "a genuinely absent secondary must trip the banner"
        );
    }

    #[test]
    fn win_ifindex_mac_scheme_binding_matches_live_mac_adapter() {
        // Same mismatch, MAC-fallback branch: the binding stores
        // `win-ifindex-mac:{index}:{dash-separated-MAC}` while the wire
        // `AdapterEntry::physical_address` is colon-separated hex.
        let (_d, conn) = open_state_db();
        let mac_dash = mac_hex_colon(MAC_SECONDARY).replace(':', "-");
        let bound_id = format!("win-ifindex-mac:9:{mac_dash}");
        seed_policy_with_secondary_stable_id(&conn, &bound_id);
        let probe = ProductionFailClosedProbe::new(conn);

        let mac_adapter = AdapterEntry {
            persistent_id: "irrelevant-low-level-id".into(),
            adapter_name: String::new(),
            ipv6_if_index: 9,
            physical_address: Some(mac_hex_colon(MAC_SECONDARY)),
            windows_name: "VPN".into(),
            interface_description: String::new(),
            interface_type: "Ppp".into(),
            oper_status: "Up".into(),
        };
        let adapters = vec![adapter("primary-id", "Up"), mac_adapter];
        let state = probe.probe(TEST_SID, &adapters).expect("Some");
        assert!(
            !state.fail_closed_active,
            "a live win-ifindex-mac:-scheme secondary must not trip the Fail-Closed banner"
        );
    }
}
