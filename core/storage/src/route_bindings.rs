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
                 auto_rules_eager_delivery_names, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, \
             ?18)
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

    /// Read the current policy snapshot for `sid`. Returns
    /// `RoutePolicyRecord::empty(...)` if the SID has no rows in any of
    /// the three tables (i.e. the user has never sent a `RoutePolicyUpdate`).
    /// `binding_source` of the empty result is `UserAssigned` by default.
    pub fn load_for_sid(&self, sid: &str) -> StorageResult<RoutePolicyRecord> {
        let primary = self.load_binding_for_sid(sid, "primary")?;
        let secondary = self.load_binding_for_sid(sid, "secondary")?;
        let (mode, binding_source) = self.load_mode_and_source(sid)?;
        let (
            block,
            kill_switch_fail_closed,
            kill_switch_protocols,
            kill_switch_block_all,
            kill_switch_enabled,
            allow_dns_over_primary,
            include_subdomains,
            shared_ip_policy,
            mode_a_coverage_strategy,
            resolve_hosts_bypass,
            doh_lockdown_enabled,
            doh_lockdown_scope,
            browser_history_auto_seed,
            kill_switch_strict_shared_ips,
            auto_rules_mode,
            auto_rules_eager_delivery_names,
        ) = self.load_block_policy(sid)?;
        Ok(RoutePolicyRecord {
            primary: primary.map(|(b, _)| b),
            secondary: secondary.map(|(b, _)| b),
            mode,
            block_secondary_when_unavailable: block,
            kill_switch_fail_closed,
            kill_switch_protocols,
            kill_switch_block_all,
            kill_switch_enabled,
            allow_dns_over_primary,
            include_subdomains,
            shared_ip_policy,
            mode_a_coverage_strategy,
            resolve_hosts_bypass,
            doh_lockdown_enabled,
            doh_lockdown_scope,
            browser_history_auto_seed,
            kill_switch_strict_shared_ips,
            auto_rules_mode,
            auto_rules_eager_delivery_names,
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
    fn load_block_policy(
        &self,
        sid: &str,
    ) -> StorageResult<(
        bool,
        bool,
        u16,
        bool,
        bool,
        bool,
        bool,
        SharedIpPolicy,
        ModeACoverageStrategy,
        bool,
        bool,
        DohLockdownScope,
        bool,
        bool,
        AutoRulesMode,
        bool,
    )> {
        #[allow(clippy::type_complexity)]
        let row: Option<(
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
            String,
            i64,
        )> = self
            .conn
            .query_row(
                "SELECT block_secondary_when_unavailable, kill_switch_fail_closed, \
                 kill_switch_protocols, kill_switch_block_all, kill_switch_enabled, \
                 allow_dns_over_primary, include_subdomains, shared_ip_policy, \
                 mode_a_coverage_strategy, resolve_hosts_bypass, \
                 doh_lockdown_enabled, doh_lockdown_scope, browser_history_auto_seed, \
                 kill_switch_strict_shared_ips, auto_rules_mode, \
                 auto_rules_eager_delivery_names
                 FROM secondary_block_policy WHERE sid = ?1",
                params![sid],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                        row.get(11)?,
                        row.get(12)?,
                        row.get(13)?,
                        row.get(14)?,
                        row.get(15)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("load block policy: {e}")))?;
        match row {
            // A missing row means the user never sent a policy: leak-guard ON,
            // fail-closed, all protocols, block-all OFF (per-IP), DNS-over-
            // primary ON (a DNS-cut block-all would otherwise be a total
            // blackout), subdomain-coverage ON (a rule for a site covers that
            // site's subdomains; widening only ever adds coverage towards the
            // route the rule already names), the default shared-IP policy
            // (balanced majority-of-ip), Mode-A default coverage, and
            // hosts-bypass ON.
            None => Ok((
                true,
                true,
                KILL_SWITCH_PROTOCOLS_ALL,
                false,
                false,
                true,
                true,
                SharedIpPolicy::default(),
                ModeACoverageStrategy::default(),
                true,
                // DoH lockdown OFF by default (explicit opt-in), scope
                // leak-protection-only.
                false,
                DohLockdownScope::default(),
                // Automatic browser-history seed OFF by default (explicit
                // per-SID opt-in — privacy-sensitive read).
                false,
                // Kill-switch shared-IP strictness OFF by default ("smart":
                // census-shared IPs are not pinned/blocked).
                false,
                // Companion-domain findings are collected and offered, never
                // applied unattended by default.
                AutoRulesMode::default(),
                // A delivery-shaped host still earns its suggestion by
                // evidence unless the user asks for it sooner.
                AUTO_RULES_EAGER_DELIVERY_NAMES_DEFAULT,
            )),
            Some((
                block,
                fail_closed,
                protocols,
                block_all,
                kill_switch_enabled,
                allow_dns_over_primary,
                include_subdomains,
                shared_ip,
                mode_a,
                resolve_hosts_bypass,
                doh_enabled,
                doh_scope,
                browser_history_auto_seed,
                kill_switch_strict_shared_ips,
                auto_rules_mode,
                auto_rules_eager_delivery_names,
            )) => Ok((
                block != 0,
                fail_closed != 0,
                protocols as u16,
                block_all != 0,
                kill_switch_enabled != 0,
                allow_dns_over_primary != 0,
                include_subdomains != 0,
                // Unknown code (shouldn't happen — CHECK-constrained) → default.
                SharedIpPolicy::from_code(shared_ip).unwrap_or_default(),
                ModeACoverageStrategy::from_code(mode_a).unwrap_or_default(),
                resolve_hosts_bypass != 0,
                doh_enabled != 0,
                DohLockdownScope::from_code(doh_scope).unwrap_or_default(),
                browser_history_auto_seed != 0,
                kill_switch_strict_shared_ips != 0,
                // Unknown slug (shouldn't happen — CHECK-constrained) → the
                // default; never silently promote to applying rules unattended.
                AutoRulesMode::from_slug(&auto_rules_mode).unwrap_or_default(),
                auto_rules_eager_delivery_names != 0,
            )),
        }
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
mod tests {
    use super::*;
    use crate::migration::{open_connection, SqliteMigrationRunner};
    use crate::repository::MigrationRunner;
    use tempfile::TempDir;

    fn fresh_db() -> (TempDir, Connection) {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("nrr_service_state.db");
        let conn = open_connection(&path).expect("open conn");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("run migrations");
        runner.verify_schema().expect("verify schema");
        (dir, runner.into_connection())
    }

    #[test]
    fn link_provider_apps_roundtrip_replace_clear_and_dedupe() {
        let (_dir, conn) = fresh_db();
        let repo = RouteBindingsRepository::new(&conn);
        let sid = "S-1-5-21-A";

        // Empty until configured; independent of route bindings.
        assert!(repo
            .load_link_provider_apps(sid, "secondary")
            .expect("load empty")
            .is_empty());

        let apps = vec![
            LinkProviderAppRecord {
                exe_path: "C:\\VPN\\client.exe".into(),
                display_name: "client.exe".into(),
            },
            // Case-insensitive duplicate — collapsed, first display name wins.
            LinkProviderAppRecord {
                exe_path: "C:\\vpn\\CLIENT.EXE".into(),
                display_name: "dup".into(),
            },
            LinkProviderAppRecord {
                exe_path: "C:\\VPN\\helper.exe".into(),
                display_name: "helper".into(),
            },
        ];
        repo.set_link_provider_apps(sid, "secondary", &apps, 1)
            .expect("set");
        let loaded = repo
            .load_link_provider_apps(sid, "secondary")
            .expect("load");
        assert_eq!(loaded.len(), 2, "case-insensitive dup collapsed");
        assert_eq!(loaded[0].exe_path, "C:\\VPN\\client.exe");
        assert_eq!(loaded[0].display_name, "client.exe");
        assert_eq!(loaded[1].exe_path, "C:\\VPN\\helper.exe");

        // Other role and other SID are isolated.
        assert!(repo
            .load_link_provider_apps(sid, "primary")
            .expect("other role")
            .is_empty());
        assert!(repo
            .load_link_provider_apps("S-1-5-21-B", "secondary")
            .expect("other sid")
            .is_empty());

        // Full replacement, then clear.
        repo.set_link_provider_apps(
            sid,
            "secondary",
            &[LinkProviderAppRecord {
                exe_path: "C:\\Other\\wg.exe".into(),
                display_name: "wg".into(),
            }],
            2,
        )
        .expect("replace");
        let replaced = repo
            .load_link_provider_apps(sid, "secondary")
            .expect("load replaced");
        assert_eq!(replaced.len(), 1);
        assert_eq!(replaced[0].exe_path, "C:\\Other\\wg.exe");
        repo.set_link_provider_apps(sid, "secondary", &[], 3)
            .expect("clear");
        assert!(repo
            .load_link_provider_apps(sid, "secondary")
            .expect("load cleared")
            .is_empty());

        // Update of route bindings must NOT touch the provider set.
        repo.set_link_provider_apps(
            sid,
            "secondary",
            &[LinkProviderAppRecord {
                exe_path: "C:\\VPN\\client.exe".into(),
                display_name: "client.exe".into(),
            }],
            4,
        )
        .expect("set again");
        repo.update_for_sid(sid, &sample_record(BindingSource::UserAssigned), 5)
            .expect("update bindings");
        assert_eq!(
            repo.load_link_provider_apps(sid, "secondary")
                .expect("survives rebind")
                .len(),
            1,
            "re-binding adapters must not wipe configured provider apps"
        );

        // Validation: empty sid / empty exe_path rejected.
        assert!(repo
            .set_link_provider_apps("", "secondary", &[], 6)
            .is_err());
        assert!(repo
            .set_link_provider_apps(
                sid,
                "secondary",
                &[LinkProviderAppRecord {
                    exe_path: "  ".into(),
                    display_name: "x".into(),
                }],
                7,
            )
            .is_err());
    }

    fn sample_record(source: BindingSource) -> RoutePolicyRecord {
        RoutePolicyRecord {
            primary: Some(RouteBindingRecord {
                stable_id: "Wi-Fi".into(),
                display_name: "Wi-Fi".into(),
                user_confirmed: true,
                // update_for_sid seeds a first-time binding's known set to its
                // own id, so the round-trip expectation matches.
                known_stable_ids: vec!["Wi-Fi".into()],
            }),
            secondary: Some(RouteBindingRecord {
                stable_id: "TAP".into(),
                display_name: "OpenVPN TAP".into(),
                user_confirmed: false,
                known_stable_ids: vec!["TAP".into()],
            }),
            mode: BehaviorMode::StrictSecondaryFailClosed,
            block_secondary_when_unavailable: true,
            // Non-default (default is `true`) so the round-trip test proves
            // the v15 column actually persists rather than reading the default.
            kill_switch_fail_closed: false,
            // Non-default (default is all = 127) so the round-trip test proves
            // the v16 column persists rather than reading the default.
            kill_switch_protocols: 0x05, // TCP + ICMP only
            // Non-default (default is false) — proves the v23 column round-trips.
            kill_switch_block_all: true,
            // Non-default (default is `false`) — proves the v26 master-toggle
            // column persists rather than reading the default.
            kill_switch_enabled: true,
            // Non-default — proves the v27 DNS-over-primary column round-trips.
            allow_dns_over_primary: true,
            // Non-default (default is `true`) so the round-trip test proves
            // the v20 column persists rather than reading the default.
            include_subdomains: false,
            shared_ip_policy: SharedIpPolicy::MajorityOfRules,
            // Non-default (default is fail-closed-unknown) — proves the v28
            // Mode-A coverage column round-trips rather than reading the
            // default.
            mode_a_coverage_strategy: ModeACoverageStrategy::ZoneWidening,
            // Non-default (default is `true`) — proves the v28 hosts-bypass column
            // persists rather than reading the default.
            resolve_hosts_bypass: false,
            // Non-default (defaults are false / leak-protection-only) — proves the
            // v31 DoH-lockdown columns round-trip rather than reading the default.
            doh_lockdown_enabled: true,
            doh_lockdown_scope: DohLockdownScope::Always,
            // Non-default (default is `false`) — proves the v32 auto-seed column
            // round-trips rather than reading the default.
            browser_history_auto_seed: true,
            // Non-default (default is `false` = smart) — proves the v33
            // strict-shared-IPs column round-trips rather than reading the
            // default.
            kill_switch_strict_shared_ips: true,
            // Non-default (default is `suggest`) — proves the v42 auto-rules
            // column round-trips rather than reading the default.
            auto_rules_mode: AutoRulesMode::Auto,
            // Non-default (default is `false`) — proves the v46 eager
            // delivery-name column round-trips rather than reading the default.
            auto_rules_eager_delivery_names: true,
            binding_source: source,
        }
    }

    #[test]
    fn slugs_roundtrip_for_all_known_variants() {
        for src in [
            BindingSource::UserAssigned,
            BindingSource::MigratedFromPreferences,
            BindingSource::Recovery,
        ] {
            assert_eq!(BindingSource::from_slug(src.slug()), Some(src));
        }
        for m in [
            BehaviorMode::PreferPrimary,
            BehaviorMode::PreferSecondaryWhenAvailable,
            BehaviorMode::StrictSecondaryFailClosed,
        ] {
            assert_eq!(BehaviorMode::from_slug(m.slug()), Some(m));
        }
        assert_eq!(BindingSource::from_slug("garbage"), None);
        assert_eq!(BehaviorMode::from_slug("garbage"), None);
    }

    #[test]
    fn empty_sid_load_returns_default_record() {
        let (_dir, conn) = fresh_db();
        let repo = RouteBindingsRepository::new(&conn);
        let r = repo.load_for_sid("S-1-5-21-0").expect("load");
        assert!(r.primary.is_none());
        assert!(r.secondary.is_none());
        assert_eq!(r.mode, BehaviorMode::PreferPrimary);
        assert!(
            r.block_secondary_when_unavailable,
            "leak-guard must default ON (block 16.HW-0702) so an un-configured \
             SID never leaks secondary-bound traffic to the primary link"
        );
        assert!(
            r.kill_switch_fail_closed,
            "kill-switch posture must default to fail-closed"
        );
        assert!(
            r.allow_dns_over_primary,
            "DNS-over-primary must default ON (block 16.HW-0716 P1b) — a \
             DNS-cut block-all is a total blackout and the FQDN cache never fills"
        );
        assert_eq!(r.binding_source, BindingSource::UserAssigned);
    }

    #[test]
    fn update_then_load_round_trips_full_record() {
        let (_dir, conn) = fresh_db();
        let repo = RouteBindingsRepository::new(&conn);
        let rec = sample_record(BindingSource::UserAssigned);
        repo.update_for_sid("S-1-5-21-A", &rec, 1_700_000_000)
            .expect("update");
        let loaded = repo.load_for_sid("S-1-5-21-A").expect("load");
        assert_eq!(loaded, rec);
    }

    /// A setting the user turned on has to survive the service restart that
    /// closes and reopens the database, not merely the connection that wrote it.
    #[test]
    fn eager_delivery_names_survives_reopen_and_defaults_off() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("nrr_service_state.db");
        let sid = "S-1-5-21-A";
        {
            let conn = open_connection(&path).expect("open");
            let runner = SqliteMigrationRunner::for_state_db(conn);
            runner.run_pending_migrations().expect("migrate");
            let conn = runner.into_connection();
            let repo = RouteBindingsRepository::new(&conn);
            assert!(
                !repo
                    .load_for_sid(sid)
                    .expect("load")
                    .auto_rules_eager_delivery_names,
                "an un-configured principal must not get eager suggestions"
            );
            let mut rec = sample_record(BindingSource::UserAssigned);
            rec.auto_rules_eager_delivery_names = true;
            repo.update_for_sid(sid, &rec, 1_700_000_000)
                .expect("update");
        }

        let conn = open_connection(&path).expect("reopen");
        let repo = RouteBindingsRepository::new(&conn);
        assert!(
            repo.load_for_sid(sid)
                .expect("load after reopen")
                .auto_rules_eager_delivery_names
        );
    }

    #[test]
    fn update_isolates_state_per_sid() {
        let (_dir, conn) = fresh_db();
        let repo = RouteBindingsRepository::new(&conn);
        let a = sample_record(BindingSource::UserAssigned);
        let mut b = sample_record(BindingSource::MigratedFromPreferences);
        b.primary = Some(RouteBindingRecord {
            stable_id: "Ethernet".into(),
            display_name: "Wired".into(),
            user_confirmed: true,
            known_stable_ids: vec!["Ethernet".into()],
        });
        b.secondary = None;
        b.mode = BehaviorMode::PreferPrimary;
        b.block_secondary_when_unavailable = false;
        repo.update_for_sid("A", &a, 1).expect("a");
        repo.update_for_sid("B", &b, 2).expect("b");
        assert_eq!(repo.load_for_sid("A").unwrap(), a);
        assert_eq!(repo.load_for_sid("B").unwrap(), b);
    }

    #[test]
    fn update_rejects_primary_equals_secondary() {
        let (_dir, conn) = fresh_db();
        let repo = RouteBindingsRepository::new(&conn);
        let mut rec = sample_record(BindingSource::UserAssigned);
        rec.secondary = Some(RouteBindingRecord {
            stable_id: rec.primary.as_ref().unwrap().stable_id.clone(),
            display_name: "dup".into(),
            user_confirmed: true,
            known_stable_ids: vec![],
        });
        let err = repo.update_for_sid("S", &rec, 1).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("same adapter"), "msg = {msg}");
    }

    #[test]
    fn update_rejects_strict_mode_without_secondary() {
        let (_dir, conn) = fresh_db();
        let repo = RouteBindingsRepository::new(&conn);
        let mut rec = sample_record(BindingSource::UserAssigned);
        rec.secondary = None;
        rec.mode = BehaviorMode::StrictSecondaryFailClosed;
        let err = repo.update_for_sid("S", &rec, 1).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("strict"), "msg = {msg}");
    }

    #[test]
    fn update_rejects_empty_sid() {
        let (_dir, conn) = fresh_db();
        let repo = RouteBindingsRepository::new(&conn);
        let rec = sample_record(BindingSource::UserAssigned);
        let err = repo.update_for_sid("", &rec, 1).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("SID is empty"), "msg = {msg}");
    }

    #[test]
    fn second_update_replaces_secondary_when_omitted() {
        // Initial: primary + secondary. Second update: only primary, no
        // secondary. The repository must DELETE the old secondary row,
        // not leave it dangling.
        let (_dir, conn) = fresh_db();
        let repo = RouteBindingsRepository::new(&conn);
        let mut rec = sample_record(BindingSource::UserAssigned);
        repo.update_for_sid("S", &rec, 1).unwrap();
        rec.secondary = None;
        rec.mode = BehaviorMode::PreferPrimary;
        repo.update_for_sid("S", &rec, 2).unwrap();
        let loaded = repo.load_for_sid("S").unwrap();
        assert!(loaded.secondary.is_none());
        assert_eq!(loaded.primary.unwrap().stable_id, "Wi-Fi");
    }

    // ── known_stable_ids ────────────────────────────────────────────────────

    fn secondary_binding(stable: &str, name: &str) -> RouteBindingRecord {
        RouteBindingRecord {
            stable_id: stable.into(),
            display_name: name.into(),
            user_confirmed: true,
            known_stable_ids: vec![stable.into()],
        }
    }

    #[test]
    fn heal_binding_identity_unions_old_and_new_ids() {
        let (_dir, conn) = fresh_db();
        let repo = RouteBindingsRepository::new(&conn);
        let mut rec = sample_record(BindingSource::UserAssigned);
        rec.secondary = Some(secondary_binding(
            "win-adapter:{guid-a}",
            "hidemy.name VPN OpenVPN Adapter",
        ));
        repo.update_for_sid("S", &rec, 1).unwrap();

        // VPN reinstalled: new GUID + a version-bumped friendly name.
        repo.heal_binding_identity(
            "S",
            "secondary",
            "win-adapter:{guid-b}",
            "hidemy.name VPN 3.0 OpenVPN Adapter",
            2,
        )
        .unwrap();

        let s = repo.load_for_sid("S").unwrap().secondary.unwrap();
        assert_eq!(s.stable_id, "win-adapter:{guid-b}");
        assert_eq!(s.display_name, "hidemy.name VPN 3.0 OpenVPN Adapter");
        assert!(s
            .known_stable_ids
            .contains(&"win-adapter:{guid-a}".to_string()));
        assert!(s
            .known_stable_ids
            .contains(&"win-adapter:{guid-b}".to_string()));
    }

    #[test]
    fn update_preserves_known_ids_across_unrelated_change() {
        // guid-a bound, healed to guid-b (known = {a, b}). A later user save that
        // keeps the same (healed) secondary — e.g. toggling an unrelated policy —
        // must NOT drop the accumulated ids.
        let (_dir, conn) = fresh_db();
        let repo = RouteBindingsRepository::new(&conn);
        let mut rec = sample_record(BindingSource::UserAssigned);
        rec.secondary = Some(secondary_binding("win-adapter:{guid-a}", "VPN"));
        repo.update_for_sid("S", &rec, 1).unwrap();
        repo.heal_binding_identity("S", "secondary", "win-adapter:{guid-b}", "VPN", 2)
            .unwrap();

        // GUI reads back guid-b and re-saves the same binding on a settings change.
        let reloaded = repo.load_for_sid("S").unwrap();
        repo.update_for_sid("S", &reloaded, 3).unwrap();

        let s = repo.load_for_sid("S").unwrap().secondary.unwrap();
        assert!(
            s.known_stable_ids
                .contains(&"win-adapter:{guid-a}".to_string()),
            "known ids must survive an unrelated re-save: {:?}",
            s.known_stable_ids
        );
        assert!(s
            .known_stable_ids
            .contains(&"win-adapter:{guid-b}".to_string()));
    }

    #[test]
    fn update_resets_known_ids_on_genuine_rebind() {
        let (_dir, conn) = fresh_db();
        let repo = RouteBindingsRepository::new(&conn);
        let mut rec = sample_record(BindingSource::UserAssigned);
        rec.secondary = Some(secondary_binding("win-adapter:{guid-a}", "VPN A"));
        repo.update_for_sid("S", &rec, 1).unwrap();
        repo.heal_binding_identity("S", "secondary", "win-adapter:{guid-b}", "VPN A", 2)
            .unwrap();

        // User binds a genuinely different adapter.
        let mut rebind = sample_record(BindingSource::UserAssigned);
        rebind.secondary = Some(RouteBindingRecord {
            stable_id: "win-adapter:{guid-c}".into(),
            display_name: "Some Other VPN".into(),
            user_confirmed: true,
            known_stable_ids: vec![],
        });
        repo.update_for_sid("S", &rebind, 3).unwrap();

        let s = repo.load_for_sid("S").unwrap().secondary.unwrap();
        assert_eq!(
            s.known_stable_ids,
            vec!["win-adapter:{guid-c}".to_string()],
            "a genuine re-bind must reset the known-id set"
        );
    }

    #[test]
    fn heal_binding_identity_is_noop_when_absent() {
        let (_dir, conn) = fresh_db();
        let repo = RouteBindingsRepository::new(&conn);
        repo.heal_binding_identity("S", "secondary", "x", "y", 1)
            .unwrap();
        assert!(repo.load_for_sid("S").unwrap().secondary.is_none());
    }

    #[test]
    fn migration_status_returns_none_before_mark() {
        let (_dir, conn) = fresh_db();
        let repo = RouteBindingsRepository::new(&conn);
        let r = repo.migration_status("S", "legacy_preferences_v1").unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn mark_migration_then_status_returns_some() {
        let (_dir, conn) = fresh_db();
        let repo = RouteBindingsRepository::new(&conn);
        repo.mark_migration_complete("S", "legacy_preferences_v1", Some(r#"{"n":3}"#), 99)
            .unwrap();
        let r = repo
            .migration_status("S", "legacy_preferences_v1")
            .unwrap()
            .unwrap();
        assert_eq!(r.completed_at, 99);
        assert_eq!(r.detail_json.as_deref(), Some(r#"{"n":3}"#));
    }

    #[test]
    fn mark_migration_is_idempotent_keeps_first_timestamp() {
        let (_dir, conn) = fresh_db();
        let repo = RouteBindingsRepository::new(&conn);
        repo.mark_migration_complete("S", "id", None, 100).unwrap();
        // Second call with later timestamp must not overwrite.
        repo.mark_migration_complete("S", "id", Some("later"), 200)
            .unwrap();
        let r = repo.migration_status("S", "id").unwrap().unwrap();
        assert_eq!(r.completed_at, 100);
        assert_eq!(r.detail_json, None);
    }

    #[test]
    fn mark_migration_per_sid_is_independent() {
        let (_dir, conn) = fresh_db();
        let repo = RouteBindingsRepository::new(&conn);
        repo.mark_migration_complete("A", "id", None, 1).unwrap();
        let a = repo.migration_status("A", "id").unwrap();
        let b = repo.migration_status("B", "id").unwrap();
        assert!(a.is_some());
        assert!(b.is_none());
    }
}
