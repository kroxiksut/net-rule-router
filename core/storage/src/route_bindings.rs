//! `route_bindings` / `behavior_mode` / `secondary_block_policy` /
//! `migration_state` repository.
//!
//! All four tables are SID-keyed: each OS user owns an independent
//! (primary, secondary) binding pair, a behavior mode, a secondary-block
//! flag, and a migration ledger. The repository exposes a single atomic
//! `update_for_sid` method that writes all three policy tables in one
//! SQLite transaction so partial state is never observable.
//!
//! ## Lifecycle
//!
//! 1. `RoutePolicyUpdate` IPC handler constructs a
//!    `RoutePolicyRecord` from the request and calls `update_for_sid`.
//! 2. `SnapshotInitial` IPC handler reads back via `load_for_sid`.
//! 3. `MigrationStatusGet` / `MigrationMarkComplete` use
//!    `migration_status` / `mark_migration_complete`.
//!
//! ## Concurrency
//!
//! Synchronous (`rusqlite` blocking API). Callers in async contexts must
//! wrap in `tokio::task::spawn_blocking`. The state DB is single-writer
//! (one `Connection` shared via `Arc<Mutex<...>>` in service-runtime),
//! so the repository takes `&Connection` — no internal locking.
//!
//! ## SID validation
//!
//! The repository does **not** validate SID format — that is the
//! responsibility of `named_pipe_identity::classify_pipe_client` which
//! constructs the SID via `ConvertSidToStringSidW`. The repository
//! treats SID as an opaque identifier; it only enforces non-empty
//! through schema `NOT NULL` plus a Rust-side guard in `update_for_sid`.

use nrr_domain::mode_a_coverage::ModeACoverageStrategy;
use nrr_domain::shared_ip::SharedIpPolicy;

use crate::auto_rules::{AutoRulesMode, AUTO_RULES_EAGER_DELIVERY_NAMES_DEFAULT};
use crate::doh_lockdown::DohLockdownScope;
use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{StorageError, StorageResult};

// ── Domain types ─────────────────────────────────────────────────────────────

/// Source of a binding: where did it come from.
///
/// Stored as TEXT in `route_bindings.binding_source` with a CHECK constraint
/// (see `STATE_DB_V5_DDL`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingSource {
    /// User chose this binding through the GUI.
    UserAssigned,
    /// Migrated from `UiPreferences` legacy fields by GUI on first launch
    /// after upgrade.
    MigratedFromPreferences,
    /// Service auto-set during recovery (e.g. previously-bound adapter
    /// disappeared, fallback chosen by routing policy).
    Recovery,
}

impl BindingSource {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::UserAssigned => "user-assigned",
            Self::MigratedFromPreferences => "migrated-from-preferences",
            Self::Recovery => "recovery",
        }
    }

    pub fn from_slug(s: &str) -> Option<Self> {
        match s {
            "user-assigned" => Some(Self::UserAssigned),
            "migrated-from-preferences" => Some(Self::MigratedFromPreferences),
            "recovery" => Some(Self::Recovery),
            _ => None,
        }
    }
}

/// Behavior mode for the (primary, secondary) pair. Slugs match the
/// existing `nrr_shared::RouteBehaviorMode` so wire and storage agree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BehaviorMode {
    PreferPrimary,
    PreferSecondaryWhenAvailable,
    StrictSecondaryFailClosed,
}

impl BehaviorMode {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::PreferPrimary => "prefer-primary",
            Self::PreferSecondaryWhenAvailable => "prefer-secondary-when-available",
            Self::StrictSecondaryFailClosed => "strict-secondary-fail-closed",
        }
    }

    pub fn from_slug(s: &str) -> Option<Self> {
        match s {
            "prefer-primary" => Some(Self::PreferPrimary),
            "prefer-secondary-when-available" => Some(Self::PreferSecondaryWhenAvailable),
            "strict-secondary-fail-closed" => Some(Self::StrictSecondaryFailClosed),
            _ => None,
        }
    }
}

/// Single (primary, secondary, mode, block-flag) snapshot for one SID.
///
/// `primary` and `secondary` are independently optional — a user may have
/// bound only a primary, or neither. `update_for_sid` validates that
/// `mode == StrictSecondaryFailClosed` requires `secondary.is_some()`
/// before writing.
/// Bitmask of IP protocols the multi-protocol kill-switch blocks:
/// TCP=1, UDP=2, ICMP=4, IGMP=8, GRE=16, ESP=32, Other=64.
/// `0x7F` = all (the default and the v16 `kill_switch_protocols` column
/// default — a true kill-switch that also cuts ICMP/ping).
pub const KILL_SWITCH_PROTOCOLS_ALL: u16 = 0x7F;

/// Column defaults for the auto-probe knobs, mirrored from the schema DDL so a
/// value that cannot be represented falls back to what a fresh row would hold.
pub const DEFAULT_PRIMARY_PROBE_TIMEOUT_MS: u32 = 1500;
pub const DEFAULT_PRIMARY_PROBE_MAX_TARGETS: u32 = 8;
pub const DEFAULT_PRIMARY_PROBE_REPEAT_SECS: u32 = 300;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutePolicyRecord {
    pub primary: Option<RouteBindingRecord>,
    pub secondary: Option<RouteBindingRecord>,
    pub mode: BehaviorMode,
    pub block_secondary_when_unavailable: bool,
    /// Kill-switch failure posture. When `true` (the
    /// default), the kill-switch **fails closed**: if the secondary (VPN)
    /// interface cannot be resolved at apply time, matched/all traffic is
    /// blocked rather than leaking out the primary link. When `false` it
    /// **fails open** (traffic allowed; the GUI surfaces a warning banner).
    /// Only meaningful when `block_secondary_when_unavailable` is on.
    pub kill_switch_fail_closed: bool,
    /// Which IP protocols the emergency block cuts, as a
    /// bitmask ([`KILL_SWITCH_PROTOCOLS_ALL`] = all). Only meaningful when
    /// `block_secondary_when_unavailable` is on. Backfills to all protocols
    /// for rows written before the v16 migration.
    pub kill_switch_protocols: u16,
    /// When `true`, the split-mode
    /// ([`BehaviorMode::PreferPrimary`]) fail-closed emergency block covers ALL
    /// egress (catch-all) instead of only the enumerated secondary destination
    /// IPs, so ICMP/ping and rotating/un-cached IPs of secondary-rule hosts
    /// cannot leak to the primary while the secondary is down. Only meaningful in
    /// `PreferPrimary` + fail-closed — the other two modes already catch-all.
    /// Default `false` (the per-IP behaviour).
    pub kill_switch_block_all: bool,
    /// MASTER kill-switch toggle. `false` (the default) means
    /// the kill-switch is OFF, so NO fail-closed / leak-guard blocking arms at all
    /// (full opt-in — any leak while the secondary is down is then the user's
    /// explicit choice). The `kill_switch_fail_closed` / `kill_switch_block_all` /
    /// `kill_switch_protocols` fields above only take effect when this is `true`.
    pub kill_switch_enabled: bool,
    /// OPT-IN "allow name resolution over the primary link while
    /// the kill-switch block-all is engaged" (default `false` = strict; blocks DNS
    /// too). When `true`, a port-scoped DNS permit lets zones keep resolving while
    /// everything else is blocked. Only meaningful in the block-all path.
    pub allow_dns_over_primary: bool,
    /// May the service check "does this answer on the main link?" on its own,
    /// or only when the user presses Check? Default `false` — a probe is an
    /// outgoing connection, so doing it unasked is the user's decision.
    pub primary_probe_auto: bool,
    /// What one probing pass may cost. Kept as plain numbers here; the service
    /// clamps them into its allowed ranges on the way out, so a value from
    /// another build (or a hand-edited row) can never widen a pass.
    pub primary_probe_timeout_ms: u32,
    pub primary_probe_max_targets: u32,
    pub primary_probe_repeat_secs: u32,
    /// Record the permissive answer for a newly discovered local network
    /// instead of asking. Off by default - opening a segment unasked is the
    /// user's call. It suppresses the QUESTION, never the record: the network
    /// still appears in the list with a decision they can change.
    pub local_networks_auto_accept: bool,
    /// Evaluate `Zone` BEFORE `ExactIp` in tier 3. Default `false` — the more
    /// specific address wins, which is what the rule model documents. The
    /// engine has always taken this as a parameter; until now nothing supplied
    /// one, so the user-facing setting existed only in the documentation.
    pub zone_priority_over_ip: bool,
    /// "Treat a domain as `domain` + `*.domain`". When `true`, the
    /// enforcement layer expands every bare-domain (`ExactFqdn`) rule with a
    /// `SuffixDomain` sibling so it also covers subdomains (apex kept).
    /// Default `true`: a user who adds `mysite.com` expects
    /// `cdn.mysite.com` to take the same route, and the widening only ever adds
    /// coverage TOWARDS the route the rule already names — it cannot send
    /// anything to a route the user did not choose. Opting out is the toggle
    /// (or a narrower rule). Never affects the canonical/stored rule hash.
    pub include_subdomains: bool,
    /// How a SHARED secondary IP (an address a secondary rule
    /// routes but that other hostnames also resolve to) is treated. Default
    /// [`SharedIpPolicy::MajorityOfIp`] (balanced). Governs only genuinely
    /// shared addresses; single-tenant routing is unaffected.
    pub shared_ip_policy: SharedIpPolicy,
    /// How Mode A (`PreferPrimary`) treats a routed domain that resolves to
    /// an IP NOT in the seeded secondary-destination set. Default
    /// [`ModeACoverageStrategy::PerIp`] (the permissive posture installs no
    /// catch-all, so default/primary and zone→primary traffic is not
    /// blocked; `FailClosedUnknown` is the paranoid opt-in that can briefly
    /// block unmatched browsing while armed).
    pub mode_a_coverage_strategy: ModeACoverageStrategy,
    /// When `true` (the DEFAULT), rule-host name resolution BYPASSES the
    /// OS hosts / adblock file so a routed host gets its routable public IP
    /// instead of a `127.0.0.1` pin. `false` honours the hosts file.
    /// Enforced by the DNS resolver (Mode B) / cache seeder.
    pub resolve_hosts_bypass: bool,
    /// MASTER toggle for the DoH/DoT lockdown (blocks browser
    /// DNS-over-HTTPS/TLS so the observer sees plaintext DNS). Default
    /// `false` (OFF — explicit opt-in; DoH browsing is not broken out of the box).
    /// The resolver list itself is a separate shared baseline
    /// (`doh_resolver_entries`).
    pub doh_lockdown_enabled: bool,
    /// When the lockdown applies:
    /// [`DohLockdownScope::LeakProtectionOnly`] (default — only while the
    /// kill-switch / block-all is armed) or [`DohLockdownScope::Always`].
    pub doh_lockdown_scope: DohLockdownScope,
    /// Opt-in AUTOMATIC browser-history seed: when
    /// `true`, the service runs the (rule-gated) browser-history seed pass on
    /// its own at boot, without the manual button. Default `false` — browser
    /// history is privacy-sensitive, so the automatic read is an explicit
    /// per-SID opt-in. The manual seed op works regardless of this flag.
    pub browser_history_auto_seed: bool,
    /// Kill-switch shared-IP strictness. `false` (default, "smart"): an IP
    /// the shared-IP census has seen on a direct (non-rule) host is
    /// EXCLUDED from the kill-switch per-IP pin/block set, so blocking a
    /// secondary-routed CDN address cannot cut innocent co-tenant sites.
    /// `true` ("strict"): pin/block every secondary-destined IP regardless
    /// of sharing — no leak, accepts the collateral. Routing (`/32` via the
    /// secondary while it is up) is governed by `shared_ip_policy`, not
    /// this flag.
    pub kill_switch_strict_shared_ips: bool,
    /// What the service may do with the companion domains it
    /// discovers for a routed site (CDN/media hosts the rules do not cover).
    /// [`AutoRulesMode::Suggest`] (default) collects findings and offers them;
    /// nothing is applied without confirmation.
    pub auto_rules_mode: AutoRulesMode,
    /// Offer a delivery-shaped companion host (a CDN endpoint) on its first
    /// co-occurrence instead of making it earn the suggestion across two visits.
    /// `false` (default) keeps the wait — see
    /// [`crate::auto_rules::AUTO_RULES_EAGER_DELIVERY_NAMES_DEFAULT`].
    pub auto_rules_eager_delivery_names: bool,
    pub binding_source: BindingSource,
}

impl RoutePolicyRecord {
    /// Empty record — neither primary nor secondary bound, mode defaults
    /// to `PreferPrimary`, leak-guard ON (block-when-unavailable — the safe
    /// privacy default, "Защита от утечки"), kill-switch posture fail-closed,
    /// subdomain-coverage ON. Used as the default response for SIDs that have
    /// not yet sent a `RoutePolicyUpdate`.
    pub fn empty(binding_source: BindingSource) -> Self {
        Self {
            primary: None,
            secondary: None,
            mode: BehaviorMode::PreferPrimary,
            block_secondary_when_unavailable: true,
            kill_switch_fail_closed: true,
            kill_switch_protocols: KILL_SWITCH_PROTOCOLS_ALL,
            kill_switch_block_all: false,
            kill_switch_enabled: false,
            // Default ON: with DNS cut, an armed fail-closed block-all is a
            // total blackout (nothing resolves, the FQDN cache never fills,
            // known-primary hosts never earn permits). The strict toggle
            // remains for users who accept that. The SQL column DEFAULT
            // stays 0 (checksummed DDL, inert — upserts always bind every
            // column).
            allow_dns_over_primary: true,
            primary_probe_auto: false,
            primary_probe_timeout_ms: DEFAULT_PRIMARY_PROBE_TIMEOUT_MS,
            primary_probe_max_targets: DEFAULT_PRIMARY_PROBE_MAX_TARGETS,
            primary_probe_repeat_secs: DEFAULT_PRIMARY_PROBE_REPEAT_SECS,
            local_networks_auto_accept: false,
            zone_priority_over_ip: false,
            // Default ON: adding `mysite.com` and silently losing
            // `cdn.mysite.com` to the other route was the surprising outcome.
            // Widening only adds coverage towards the route the rule names, so
            // it cannot leak to an unintended route. The SQL column DEFAULT
            // stays 0 (checksummed DDL, inert — upserts bind every column).
            include_subdomains: true,
            shared_ip_policy: SharedIpPolicy::default(),
            mode_a_coverage_strategy: ModeACoverageStrategy::default(),
            resolve_hosts_bypass: true,
            doh_lockdown_enabled: false,
            doh_lockdown_scope: DohLockdownScope::default(),
            browser_history_auto_seed: false,
            kill_switch_strict_shared_ips: false,
            // Collect companion-domain findings and offer them; apply nothing
            // unattended until the discovery mechanism is field-verified.
            auto_rules_mode: AutoRulesMode::default(),
            auto_rules_eager_delivery_names: AUTO_RULES_EAGER_DELIVERY_NAMES_DEFAULT,
            binding_source,
        }
    }
}

/// One row of `route_bindings` translated to domain shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteBindingRecord {
    pub stable_id: String,
    pub display_name: String,
    pub user_confirmed: bool,
    /// Every stable adapter id this binding has been matched to (the
    /// current `stable_id` plus historical GUIDs the auto-heal folded
    /// in). The route coordinator matches a live adapter against ANY of these,
    /// so a secondary adapter whose GUID rotated across a reinstall/version
    /// bump is still recognised without waiting for a friendly-name heal. Populated on load;
    /// **ignored on write** — `update_for_sid` derives the set from the DB
    /// (carry forward on an unchanged binding, reset on a genuine re-bind) and
    /// [`RouteBindingsRepository::heal_binding_identity`] unions healed ids.
    pub known_stable_ids: Vec<String>,
}

/// One row of `route_link_provider_apps` — an executable the
/// user confirmed as establishing/maintaining the link of a `(sid, role)`
/// binding (a VPN client for the secondary role is the common case). The
/// service-side SSOT behind the VPN onboarding dialog; consumed by the
/// kill-switch link-provider exemption and the endpoint-learning matcher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkProviderAppRecord {
    /// User-facing Win32 path of the executable (`C:\...\client.exe`).
    pub exe_path: String,
    /// Display name shown in the GUI (basename or product name). May be empty.
    pub display_name: String,
}

// ── Errors ───────────────────────────────────────────────────────────────────

/// Validation failures surfaced by the repository's `update_for_sid`.
/// Distinct from `StorageError` because they are caller-input errors,
/// not platform/DB failures — the IPC handler maps them to
/// `IpcErrorCode::PreconditionFailed` rather than `Internal`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutePolicyValidationError {
    EmptySid,
    PrimaryEqualsSecondary,
    StrictModeRequiresSecondary,
}

impl std::fmt::Display for RoutePolicyValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptySid => write!(f, "caller SID is empty"),
            Self::PrimaryEqualsSecondary => {
                write!(f, "primary and secondary cannot reference the same adapter")
            }
            Self::StrictModeRequiresSecondary => write!(
                f,
                "strict-secondary-fail-closed mode requires a bound secondary"
            ),
        }
    }
}

impl std::error::Error for RoutePolicyValidationError {}

// ── Repository ───────────────────────────────────────────────────────────────

/// Synchronous repository for the four per-SID policy tables. Borrows an
/// open `Connection`. The connection must already have v5 schema applied
/// (`SqliteMigrationRunner` does so during bootstrap).
pub struct RouteBindingsRepository<'c> {
    conn: &'c Connection,
}

/// One decoded `secondary_block_policy` row (see
/// `RouteBindingsRepository::load_block_policy`). `Default` is the
/// never-configured answer, which is why the loader can hand a missing row
/// straight to it.
struct BlockPolicyRow {
    block_secondary_when_unavailable: bool,
    kill_switch_fail_closed: bool,
    kill_switch_protocols: u16,
    kill_switch_block_all: bool,
    kill_switch_enabled: bool,
    allow_dns_over_primary: bool,
    include_subdomains: bool,
    shared_ip_policy: SharedIpPolicy,
    mode_a_coverage_strategy: ModeACoverageStrategy,
    resolve_hosts_bypass: bool,
    doh_lockdown_enabled: bool,
    doh_lockdown_scope: DohLockdownScope,
    browser_history_auto_seed: bool,
    kill_switch_strict_shared_ips: bool,
    auto_rules_mode: AutoRulesMode,
    auto_rules_eager_delivery_names: bool,
    primary_probe_auto: bool,
    primary_probe_timeout_ms: u32,
    primary_probe_max_targets: u32,
    primary_probe_repeat_secs: u32,
    local_networks_auto_accept: bool,
    zone_priority_over_ip: bool,
}

impl Default for BlockPolicyRow {
    fn default() -> Self {
        Self {
            block_secondary_when_unavailable: true,
            kill_switch_fail_closed: true,
            kill_switch_protocols: KILL_SWITCH_PROTOCOLS_ALL,
            kill_switch_block_all: false,
            kill_switch_enabled: false,
            allow_dns_over_primary: true,
            include_subdomains: true,
            shared_ip_policy: SharedIpPolicy::default(),
            mode_a_coverage_strategy: ModeACoverageStrategy::default(),
            resolve_hosts_bypass: true,
            doh_lockdown_enabled: false,
            doh_lockdown_scope: DohLockdownScope::default(),
            browser_history_auto_seed: false,
            kill_switch_strict_shared_ips: false,
            auto_rules_mode: AutoRulesMode::default(),
            auto_rules_eager_delivery_names: AUTO_RULES_EAGER_DELIVERY_NAMES_DEFAULT,
            primary_probe_auto: false,
            primary_probe_timeout_ms: DEFAULT_PRIMARY_PROBE_TIMEOUT_MS,
            primary_probe_max_targets: DEFAULT_PRIMARY_PROBE_MAX_TARGETS,
            primary_probe_repeat_secs: DEFAULT_PRIMARY_PROBE_REPEAT_SECS,
            local_networks_auto_accept: false,
            zone_priority_over_ip: false,
        }
    }
}

impl<'c> RouteBindingsRepository<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    /// Atomically write `record` for `sid` across `route_bindings`,
    /// `behavior_mode`, and `secondary_block_policy`. The full set of
    /// previous bindings for this SID is replaced — sending only a
    /// `primary` (with `secondary == None`) deletes any prior secondary
    /// row, which is the documented "user cleared the secondary slot"
    /// semantics.
    ///
    /// `now_epoch_secs` is injected so deterministic tests can fix it;
    /// production callers pass `SystemTime::now().duration_since(UNIX_EPOCH)`.
    pub fn update_for_sid(
        &self,
        sid: &str,
        record: &RoutePolicyRecord,
        now_epoch_secs: i64,
    ) -> StorageResult<()> {
        if sid.is_empty() {
            return Err(StorageError::Internal(
                RoutePolicyValidationError::EmptySid.to_string(),
            ));
        }
        if let (Some(p), Some(s)) = (&record.primary, &record.secondary) {
            if p.stable_id == s.stable_id {
                return Err(StorageError::Internal(
                    RoutePolicyValidationError::PrimaryEqualsSecondary.to_string(),
                ));
            }
        }
        if record.mode == BehaviorMode::StrictSecondaryFailClosed && record.secondary.is_none() {
            return Err(StorageError::Internal(
                RoutePolicyValidationError::StrictModeRequiresSecondary.to_string(),
            ));
        }

        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| StorageError::Internal(format!("begin tx: {e}")))?;

        // Snapshot the existing per-role identity (stable_id + accumulated
        // known ids) BEFORE the replace, so the known-id set survives an
        // unrelated settings change on the same adapter and resets
        // only on a genuine re-bind. Read inside the tx for a consistent view.
        let existing_primary = read_binding_identity(&tx, sid, "primary")?;
        let existing_secondary = read_binding_identity(&tx, sid, "secondary")?;

        // Replace bindings: delete the SID's existing rows, then insert
        // the present ones. DELETE-then-INSERT keeps the schema simple
        // (no UPSERT with conditional column updates) and matches the
        // "full replacement" semantics callers expect.
        tx.execute("DELETE FROM route_bindings WHERE sid = ?1", params![sid])
            .map_err(|e| StorageError::Internal(format!("delete bindings: {e}")))?;

        if let Some(p) = &record.primary {
            let known = merged_known_ids(p, existing_primary.as_ref());
            insert_binding(
                &tx,
                sid,
                "primary",
                p,
                &known,
                record.binding_source,
                now_epoch_secs,
            )?;
        }
        if let Some(s) = &record.secondary {
            let known = merged_known_ids(s, existing_secondary.as_ref());
            insert_binding(
                &tx,
                sid,
                "secondary",
                s,
                &known,
                record.binding_source,
                now_epoch_secs,
            )?;
        }

        // Upsert behavior_mode.
        tx.execute(
            "INSERT INTO behavior_mode (sid, mode, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(sid) DO UPDATE SET
                mode = excluded.mode,
                updated_at = excluded.updated_at",
            params![sid, record.mode.slug(), now_epoch_secs],
        )
        .map_err(|e| StorageError::Internal(format!("upsert mode: {e}")))?;

        // Upsert secondary_block_policy.
        tx.execute(
            "INSERT INTO secondary_block_policy
                (sid, block_secondary_when_unavailable, kill_switch_fail_closed, \
                 kill_switch_protocols, kill_switch_block_all, kill_switch_enabled, \
                 allow_dns_over_primary, include_subdomains, shared_ip_policy, \
                 mode_a_coverage_strategy, resolve_hosts_bypass, \
                 doh_lockdown_enabled, doh_lockdown_scope, browser_history_auto_seed, \
                 kill_switch_strict_shared_ips, auto_rules_mode, \
                 auto_rules_eager_delivery_names, primary_probe_auto, \
                 primary_probe_timeout_ms, primary_probe_max_targets, \
                 primary_probe_repeat_secs, local_networks_auto_accept,                  zone_priority_over_ip, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, \
             ?18, ?19, ?20, ?21, ?22, ?23, ?24)
             ON CONFLICT(sid) DO UPDATE SET
                block_secondary_when_unavailable = excluded.block_secondary_when_unavailable,
                kill_switch_fail_closed = excluded.kill_switch_fail_closed,
                kill_switch_protocols = excluded.kill_switch_protocols,
                kill_switch_block_all = excluded.kill_switch_block_all,
                kill_switch_enabled = excluded.kill_switch_enabled,
                allow_dns_over_primary = excluded.allow_dns_over_primary,
                include_subdomains = excluded.include_subdomains,
                shared_ip_policy = excluded.shared_ip_policy,
                mode_a_coverage_strategy = excluded.mode_a_coverage_strategy,
                resolve_hosts_bypass = excluded.resolve_hosts_bypass,
                doh_lockdown_enabled = excluded.doh_lockdown_enabled,
                doh_lockdown_scope = excluded.doh_lockdown_scope,
                browser_history_auto_seed = excluded.browser_history_auto_seed,
                kill_switch_strict_shared_ips = excluded.kill_switch_strict_shared_ips,
                auto_rules_mode = excluded.auto_rules_mode,
                auto_rules_eager_delivery_names = excluded.auto_rules_eager_delivery_names,
                primary_probe_auto = excluded.primary_probe_auto,
                primary_probe_timeout_ms = excluded.primary_probe_timeout_ms,
                primary_probe_max_targets = excluded.primary_probe_max_targets,
                primary_probe_repeat_secs = excluded.primary_probe_repeat_secs,
                local_networks_auto_accept = excluded.local_networks_auto_accept,
                zone_priority_over_ip = excluded.zone_priority_over_ip,
                updated_at = excluded.updated_at",
            params![
                sid,
                record.block_secondary_when_unavailable as i64,
                record.kill_switch_fail_closed as i64,
                record.kill_switch_protocols as i64,
                record.kill_switch_block_all as i64,
                record.kill_switch_enabled as i64,
                record.allow_dns_over_primary as i64,
                record.include_subdomains as i64,
                record.shared_ip_policy.as_code(),
                record.mode_a_coverage_strategy.as_code(),
                record.resolve_hosts_bypass as i64,
                record.doh_lockdown_enabled as i64,
                record.doh_lockdown_scope.as_code(),
                record.browser_history_auto_seed as i64,
                record.kill_switch_strict_shared_ips as i64,
                record.auto_rules_mode.as_slug(),
                record.auto_rules_eager_delivery_names as i64,
                record.primary_probe_auto as i64,
                record.primary_probe_timeout_ms as i64,
                record.primary_probe_max_targets as i64,
                record.primary_probe_repeat_secs as i64,
                record.local_networks_auto_accept as i64,
                record.zone_priority_over_ip as i64,
                now_epoch_secs
            ],
        )
        .map_err(|e| StorageError::Internal(format!("upsert block policy: {e}")))?;

        tx.commit()
            .map_err(|e| StorageError::Internal(format!("commit: {e}")))?;
        Ok(())
    }

    /// Fold a newly auto-matched adapter id into the
    /// `(sid, role)` binding. Called by the route coordinator when it resolved
    /// the binding to a live adapter whose GUID differs from the stored
    /// `stable_id` (secondary adapter reinstall / version bump). Sets `stable_id` +
    /// `display_name` to the live adapter and UNIONS both the previous
    /// `stable_id` and the new one into `known_stable_ids`, so either identity
    /// is recognised next time without re-healing. No-op when the binding row
    /// is absent. Idempotent — re-running with the same id is a harmless
    /// rewrite. Unlike [`Self::update_for_sid`] it does NOT reset the known set,
    /// which is exactly why the heal path is separate from the user path.
    pub fn heal_binding_identity(
        &self,
        sid: &str,
        role: &str,
        healed_stable_id: &str,
        healed_display_name: &str,
        now_epoch_secs: i64,
    ) -> StorageResult<()> {
        let existing: Option<(String, String)> = self
            .conn
            .query_row(
                "SELECT stable_id, known_stable_ids
                 FROM route_bindings WHERE sid = ?1 AND role = ?2",
                params![sid, role],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("heal read binding: {e}")))?;
        let Some((old_stable_id, old_known_raw)) = existing else {
            // Nothing bound for this role — nothing to heal.
            return Ok(());
        };
        let known = union_known_ids(
            &parse_known_ids(&old_known_raw),
            &[old_stable_id.as_str(), healed_stable_id],
        );
        self.conn
            .execute(
                "UPDATE route_bindings
                 SET stable_id = ?1, display_name = ?2, known_stable_ids = ?3, updated_at = ?4
                 WHERE sid = ?5 AND role = ?6",
                params![
                    healed_stable_id,
                    healed_display_name,
                    serialize_known_ids(&known),
                    now_epoch_secs,
                    sid,
                    role
                ],
            )
            .map(|_| ())
            .map_err(|e| StorageError::Internal(format!("heal update binding: {e}")))
    }

    /// Remember one more identity for an existing `(sid, role)` binding without
    /// touching which adapter it currently points at.
    ///
    /// The heal path rewrites `stable_id` because the stored one went stale;
    /// this one is for an identity the binding gains while still resolving
    /// correctly — the MAC anchor of a physical adapter, learned the first time
    /// the binding resolves. Returns whether the set actually grew, so the
    /// caller can log once instead of every reconcile. No-op when the row is
    /// absent or the id is already known.
    pub fn remember_stable_id(
        &self,
        sid: &str,
        role: &str,
        extra_stable_id: &str,
        now_epoch_secs: i64,
    ) -> StorageResult<bool> {
        if extra_stable_id.trim().is_empty() {
            return Ok(false);
        }
        let existing: Option<String> = self
            .conn
            .query_row(
                "SELECT known_stable_ids FROM route_bindings WHERE sid = ?1 AND role = ?2",
                params![sid, role],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("anchor read binding: {e}")))?;
        let Some(known_raw) = existing else {
            return Ok(false);
        };
        let known = parse_known_ids(&known_raw);
        let grown = union_known_ids(&known, &[extra_stable_id]);
        if grown.len() == known.len() {
            return Ok(false);
        }
        self.conn
            .execute(
                "UPDATE route_bindings SET known_stable_ids = ?1, updated_at = ?2
                 WHERE sid = ?3 AND role = ?4",
                params![serialize_known_ids(&grown), now_epoch_secs, sid, role],
            )
            .map(|_| true)
            .map_err(|e| StorageError::Internal(format!("anchor update binding: {e}")))
    }

    /// Read the current policy snapshot for `sid`. Returns
    /// `RoutePolicyRecord::empty(...)` if the SID has no rows in any of
    /// the three tables (i.e. the user has never sent a `RoutePolicyUpdate`).
    /// `binding_source` of the empty result is `UserAssigned` by default.
    pub fn load_for_sid(&self, sid: &str) -> StorageResult<RoutePolicyRecord> {
        let primary = self.load_binding_for_sid(sid, "primary")?;
        let secondary = self.load_binding_for_sid(sid, "secondary")?;
        let (mode, binding_source) = self.load_mode_and_source(sid)?;
        let policy = self.load_block_policy(sid)?;
        Ok(RoutePolicyRecord {
            primary: primary.map(|(b, _)| b),
            secondary: secondary.map(|(b, _)| b),
            mode,
            block_secondary_when_unavailable: policy.block_secondary_when_unavailable,
            kill_switch_fail_closed: policy.kill_switch_fail_closed,
            kill_switch_protocols: policy.kill_switch_protocols,
            kill_switch_block_all: policy.kill_switch_block_all,
            kill_switch_enabled: policy.kill_switch_enabled,
            allow_dns_over_primary: policy.allow_dns_over_primary,
            include_subdomains: policy.include_subdomains,
            shared_ip_policy: policy.shared_ip_policy,
            mode_a_coverage_strategy: policy.mode_a_coverage_strategy,
            resolve_hosts_bypass: policy.resolve_hosts_bypass,
            doh_lockdown_enabled: policy.doh_lockdown_enabled,
            doh_lockdown_scope: policy.doh_lockdown_scope,
            browser_history_auto_seed: policy.browser_history_auto_seed,
            kill_switch_strict_shared_ips: policy.kill_switch_strict_shared_ips,
            auto_rules_mode: policy.auto_rules_mode,
            auto_rules_eager_delivery_names: policy.auto_rules_eager_delivery_names,
            primary_probe_auto: policy.primary_probe_auto,
            primary_probe_timeout_ms: policy.primary_probe_timeout_ms,
            primary_probe_max_targets: policy.primary_probe_max_targets,
            primary_probe_repeat_secs: policy.primary_probe_repeat_secs,
            local_networks_auto_accept: policy.local_networks_auto_accept,
            zone_priority_over_ip: policy.zone_priority_over_ip,
            binding_source,
        })
    }

    fn load_binding_for_sid(
        &self,
        sid: &str,
        role: &str,
    ) -> StorageResult<Option<(RouteBindingRecord, BindingSource)>> {
        self.conn
            .query_row(
                "SELECT stable_id, display_name, user_confirmed, binding_source, known_stable_ids
                 FROM route_bindings WHERE sid = ?1 AND role = ?2",
                params![sid, role],
                |row| {
                    let stable_id: String = row.get(0)?;
                    let display_name: String = row.get(1)?;
                    let user_confirmed: i64 = row.get(2)?;
                    let source_str: String = row.get(3)?;
                    let known_raw: String = row.get(4)?;
                    Ok((
                        RouteBindingRecord {
                            stable_id,
                            display_name,
                            user_confirmed: user_confirmed != 0,
                            known_stable_ids: parse_known_ids(&known_raw),
                        },
                        source_str,
                    ))
                },
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("load binding: {e}")))
            .and_then(|opt| match opt {
                None => Ok(None),
                Some((bind, source_str)) => BindingSource::from_slug(&source_str)
                    .ok_or_else(|| {
                        StorageError::Internal(format!(
                            "unknown binding_source slug in DB: {source_str}"
                        ))
                    })
                    .map(|src| Some((bind, src))),
            })
    }

    fn load_mode_and_source(&self, sid: &str) -> StorageResult<(BehaviorMode, BindingSource)> {
        // Mode lives in `behavior_mode`; we also fetch any binding's source
        // for the empty-record fallback consistency. If the SID has no
        // mode row, return defaults.
        let mode_str: Option<String> = self
            .conn
            .query_row(
                "SELECT mode FROM behavior_mode WHERE sid = ?1",
                params![sid],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("load mode: {e}")))?;
        let mode = match mode_str {
            None => BehaviorMode::PreferPrimary,
            Some(s) => BehaviorMode::from_slug(&s)
                .ok_or_else(|| StorageError::Internal(format!("unknown mode slug in DB: {s}")))?,
        };

        // Source: pick from any binding row; if none exist, default to UserAssigned.
        let source_str: Option<String> = self
            .conn
            .query_row(
                "SELECT binding_source FROM route_bindings
                 WHERE sid = ?1 LIMIT 1",
                params![sid],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("load source: {e}")))?;
        let source = match source_str {
            None => BindingSource::UserAssigned,
            Some(s) => BindingSource::from_slug(&s).ok_or_else(|| {
                StorageError::Internal(format!("unknown binding_source slug: {s}"))
            })?,
        };
        Ok((mode, source))
    }

    /// Load both `secondary_block_policy` flags for `sid`: the
    /// `block_secondary_when_unavailable` toggle and the
    /// `kill_switch_fail_closed` posture. A missing row returns
    /// `(true, true, ALL)` — leak-guard ON by default ("Защита от утечки"),
    /// fail-closed posture, all protocols, so an un-configured SID never
    /// leaks secondary-bound traffic to the primary link. An explicit
    /// stored `0` (the user unchecked it) still wins.
    #[allow(clippy::type_complexity)]
    /// One `secondary_block_policy` row, decoded. A struct rather than a tuple:
    /// with twenty fields a positional return is a bug waiting for the next
    /// column to be added in the wrong place.
    fn load_block_policy(&self, sid: &str) -> StorageResult<BlockPolicyRow> {
        let row: Option<BlockPolicyRow> = self
            .conn
            .query_row(
                "SELECT block_secondary_when_unavailable, kill_switch_fail_closed,                  kill_switch_protocols, kill_switch_block_all, kill_switch_enabled,                  allow_dns_over_primary, include_subdomains, shared_ip_policy,                  mode_a_coverage_strategy, resolve_hosts_bypass,                  doh_lockdown_enabled, doh_lockdown_scope, browser_history_auto_seed,                  kill_switch_strict_shared_ips, auto_rules_mode,                  auto_rules_eager_delivery_names, primary_probe_auto,                  primary_probe_timeout_ms, primary_probe_max_targets,                  primary_probe_repeat_secs,                  local_networks_auto_accept, zone_priority_over_ip
                 FROM secondary_block_policy WHERE sid = ?1",
                params![sid],
                |row| {
                    let auto_rules_mode: String = row.get(14)?;
                    Ok(BlockPolicyRow {
                        block_secondary_when_unavailable: row.get::<_, i64>(0)? != 0,
                        kill_switch_fail_closed: row.get::<_, i64>(1)? != 0,
                        kill_switch_protocols: row.get::<_, i64>(2)? as u16,
                        kill_switch_block_all: row.get::<_, i64>(3)? != 0,
                        kill_switch_enabled: row.get::<_, i64>(4)? != 0,
                        allow_dns_over_primary: row.get::<_, i64>(5)? != 0,
                        include_subdomains: row.get::<_, i64>(6)? != 0,
                        // Unknown code (shouldn't happen — CHECK-constrained) → default.
                        shared_ip_policy: SharedIpPolicy::from_code(row.get::<_, i64>(7)?)
                            .unwrap_or_default(),
                        mode_a_coverage_strategy: ModeACoverageStrategy::from_code(
                            row.get::<_, i64>(8)?,
                        )
                        .unwrap_or_default(),
                        resolve_hosts_bypass: row.get::<_, i64>(9)? != 0,
                        doh_lockdown_enabled: row.get::<_, i64>(10)? != 0,
                        doh_lockdown_scope: DohLockdownScope::from_code(row.get::<_, i64>(11)?)
                            .unwrap_or_default(),
                        browser_history_auto_seed: row.get::<_, i64>(12)? != 0,
                        kill_switch_strict_shared_ips: row.get::<_, i64>(13)? != 0,
                        // Unknown slug → the default; never silently promote to
                        // applying rules unattended.
                        auto_rules_mode: AutoRulesMode::from_slug(&auto_rules_mode)
                            .unwrap_or_default(),
                        auto_rules_eager_delivery_names: row.get::<_, i64>(15)? != 0,
                        primary_probe_auto: row.get::<_, i64>(16)? != 0,
                        // `as u32` wraps modulo 2^32, so a value the schema
                        // cannot reject (INTEGER, no CHECK) turned a huge
                        // timeout into a tiny one — a probe that gives up
                        // instantly reads as "the primary is down". Out of
                        // range falls back to the column default instead.
                        primary_probe_timeout_ms: u32::try_from(row.get::<_, i64>(17)?)
                            .unwrap_or(DEFAULT_PRIMARY_PROBE_TIMEOUT_MS),
                        primary_probe_max_targets: u32::try_from(row.get::<_, i64>(18)?)
                            .unwrap_or(DEFAULT_PRIMARY_PROBE_MAX_TARGETS),
                        primary_probe_repeat_secs: u32::try_from(row.get::<_, i64>(19)?)
                            .unwrap_or(DEFAULT_PRIMARY_PROBE_REPEAT_SECS),
                        local_networks_auto_accept: row.get::<_, i64>(20)? != 0,
                        zone_priority_over_ip: row.get::<_, i64>(21)? != 0,
                    })
                },
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("load block policy: {e}")))?;
        // A missing row means the user never sent a policy: leak-guard ON,
        // fail-closed, all protocols, block-all OFF (per-IP), DNS-over-primary
        // ON (a DNS-cut block-all would otherwise be a total blackout),
        // subdomain coverage ON, balanced shared-IP policy, Mode-A default
        // coverage, hosts-bypass ON, DoH lockdown OFF, history seed OFF,
        // findings offered but never applied unattended, and probing only when
        // asked for.
        Ok(row.unwrap_or_default())
    }

    // ── Link-provider apps ───────────────────────────────────────────────

    /// Replace the full link-provider app set of `(sid, role)` — the
    /// executables the user confirmed as establishing that link (VPN client
    /// et al.). Full-replacement semantics like `update_for_sid`: an empty
    /// `apps` slice clears the set ("I don't use a VPN"). Deliberately
    /// SEPARATE from `update_for_sid` — re-binding the secondary adapter must
    /// not wipe the configured provider apps (the client survives an adapter
    /// GUID rotation). Entries with an empty `exe_path` are rejected;
    /// duplicate paths (case-insensitive — Windows paths) are collapsed,
    /// first display name wins.
    pub fn set_link_provider_apps(
        &self,
        sid: &str,
        role: &str,
        apps: &[LinkProviderAppRecord],
        now_epoch_secs: i64,
    ) -> StorageResult<()> {
        if sid.is_empty() {
            return Err(StorageError::Internal(
                RoutePolicyValidationError::EmptySid.to_string(),
            ));
        }
        if apps.iter().any(|a| a.exe_path.trim().is_empty()) {
            return Err(StorageError::Internal(
                "link-provider app with empty exe_path".to_string(),
            ));
        }
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| StorageError::Internal(format!("begin tx: {e}")))?;
        tx.execute(
            "DELETE FROM route_link_provider_apps WHERE sid = ?1 AND role = ?2",
            params![sid, role],
        )
        .map_err(|e| StorageError::Internal(format!("delete link providers: {e}")))?;
        let mut seen: Vec<String> = Vec::new();
        for app in apps {
            let key = app.exe_path.to_ascii_lowercase();
            if seen.contains(&key) {
                continue;
            }
            seen.push(key);
            tx.execute(
                "INSERT INTO route_link_provider_apps
                    (sid, role, exe_path, display_name, source, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 'user-confirmed', ?5)",
                params![sid, role, app.exe_path, app.display_name, now_epoch_secs],
            )
            .map_err(|e| StorageError::Internal(format!("insert link provider: {e}")))?;
        }
        tx.commit()
            .map_err(|e| StorageError::Internal(format!("commit: {e}")))
    }

    /// Read the link-provider app set of `(sid, role)`, ordered by path for
    /// deterministic output. Empty when the user never configured one.
    pub fn load_link_provider_apps(
        &self,
        sid: &str,
        role: &str,
    ) -> StorageResult<Vec<LinkProviderAppRecord>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT exe_path, display_name FROM route_link_provider_apps
                 WHERE sid = ?1 AND role = ?2 ORDER BY exe_path ASC",
            )
            .map_err(|e| StorageError::Internal(format!("prepare link providers: {e}")))?;
        let rows = stmt
            .query_map(params![sid, role], |row| {
                Ok(LinkProviderAppRecord {
                    exe_path: row.get(0)?,
                    display_name: row.get(1)?,
                })
            })
            .map_err(|e| StorageError::Internal(format!("query link providers: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| StorageError::Internal(format!("row link provider: {e}")))?);
        }
        Ok(out)
    }

    // ── Migration ledger ────────────────────────────────────────────────

    /// Read a migration row for `(sid, migration_id)`. `None` if the
    /// migration has not been recorded yet (i.e. GUI must run it).
    pub fn migration_status(
        &self,
        sid: &str,
        migration_id: &str,
    ) -> StorageResult<Option<MigrationStatusRecord>> {
        self.conn
            .query_row(
                "SELECT completed_at, detail_json
                 FROM migration_state WHERE sid = ?1 AND migration_id = ?2",
                params![sid, migration_id],
                |row| {
                    let completed_at: i64 = row.get(0)?;
                    let detail: Option<String> = row.get(1)?;
                    Ok(MigrationStatusRecord {
                        completed_at,
                        detail_json: detail,
                    })
                },
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("load migration: {e}")))
    }

    /// Record completion of `(sid, migration_id)`. Idempotent — repeated
    /// calls with the same key leave the existing `completed_at`
    /// untouched (the first completion wins). The caller relies on this
    /// to safely retry on transient IPC failures.
    pub fn mark_migration_complete(
        &self,
        sid: &str,
        migration_id: &str,
        detail_json: Option<&str>,
        now_epoch_secs: i64,
    ) -> StorageResult<()> {
        if sid.is_empty() {
            return Err(StorageError::Internal(
                RoutePolicyValidationError::EmptySid.to_string(),
            ));
        }
        self.conn
            .execute(
                "INSERT OR IGNORE INTO migration_state
                    (sid, migration_id, completed_at, detail_json)
                 VALUES (?1, ?2, ?3, ?4)",
                params![sid, migration_id, now_epoch_secs, detail_json],
            )
            .map(|_| ())
            .map_err(|e| StorageError::Internal(format!("mark migration: {e}")))
    }
}

/// One row of `migration_state`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationStatusRecord {
    pub completed_at: i64,
    pub detail_json: Option<String>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn insert_binding(
    tx: &rusqlite::Transaction<'_>,
    sid: &str,
    role: &str,
    binding: &RouteBindingRecord,
    known_ids: &[String],
    source: BindingSource,
    now_epoch_secs: i64,
) -> StorageResult<()> {
    tx.execute(
        "INSERT INTO route_bindings
            (sid, role, stable_id, display_name, user_confirmed,
             updated_at, binding_source, known_stable_ids)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            sid,
            role,
            binding.stable_id,
            binding.display_name,
            binding.user_confirmed as i64,
            now_epoch_secs,
            source.slug(),
            serialize_known_ids(known_ids),
        ],
    )
    .map(|_| ())
    .map_err(|e| StorageError::Internal(format!("insert binding {role}: {e}")))
}

// ── known_stable_ids ──────────────────────────────────────────────────────────
//
// Stored as a newline-delimited TEXT set. Newline is a safe separator: adapter
// stable ids (`win-adapter:{guid}`, `win-ifindex[-mac]:...`) never contain one.

fn serialize_known_ids(ids: &[String]) -> String {
    ids.join("\n")
}

fn parse_known_ids(raw: &str) -> Vec<String> {
    raw.split('\n')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Append every id in `extra` not already present (case-insensitive),
/// preserving insertion order.
fn union_known_ids(base: &[String], extra: &[&str]) -> Vec<String> {
    let mut out = base.to_vec();
    for e in extra {
        if !e.is_empty() && !out.iter().any(|x| x.eq_ignore_ascii_case(e)) {
            out.push((*e).to_string());
        }
    }
    out
}

/// Snapshot the existing per-role identity `(stable_id, known_stable_ids)`
/// inside the update transaction, so the known-id set can be carried forward.
fn read_binding_identity(
    tx: &rusqlite::Transaction<'_>,
    sid: &str,
    role: &str,
) -> StorageResult<Option<(String, Vec<String>)>> {
    tx.query_row(
        "SELECT stable_id, known_stable_ids FROM route_bindings WHERE sid = ?1 AND role = ?2",
        params![sid, role],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    )
    .optional()
    .map(|o| o.map(|(id, raw)| (id, parse_known_ids(&raw))))
    .map_err(|e| StorageError::Internal(format!("read binding identity {role}: {e}")))
}

/// Known-id set for a freshly written binding: carry the accumulated set
/// forward when the adapter is unchanged (same `stable_id`), else start over at
/// just the new id (the user bound a genuinely different adapter). A binding
/// written for the first time (no existing row) starts at its own id.
fn merged_known_ids(
    new: &RouteBindingRecord,
    existing: Option<&(String, Vec<String>)>,
) -> Vec<String> {
    match existing {
        Some((old_id, old_known)) if old_id.eq_ignore_ascii_case(&new.stable_id) => {
            union_known_ids(old_known, &[new.stable_id.as_str()])
        }
        _ => vec![new.stable_id.clone()],
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
