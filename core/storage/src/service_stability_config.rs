//! `service_stability_config` singleton.
//!
//! Persists the service-wide `ServiceStabilityConfig` chosen by the
//! administrator. The repository hands the activation/supervisor layer
//! a typed record (`ServiceStabilityConfigRecord`) which mirrors the
//! domain enum at `nrr_service_runtime::service_stability::IpcAcceptFailurePolicy`
//! while staying free of any service-runtime dependency.
//!
//! ## Encoding
//!
//! The `IpcAcceptFailurePolicy` enum is encoded as a discriminator
//! column (`ipc_accept_kind`) plus three nullable parameter columns
//! that are only meaningful when the kind is `recoverable`. The schema
//! enforces cross-field consistency via a CHECK clause — see
//! [`crate::schema::STATE_DB_V8_DDL`].
//!
//! The repository normalises this into [`IpcAcceptPolicyRecord`]:
//!
//! - `IpcAcceptPolicyRecord::Recoverable { ... }` ⇔ row with kind
//!   `"recoverable"` and all three params non-NULL.
//! - `IpcAcceptPolicyRecord::Critical` ⇔ row with kind `"critical"`
//!   and all three params NULL.
//!
//! Setting requires admin elevation (the IPC handler upstream marks
//! `ServiceStabilityConfigSet` as a strong mutation). Read is open to
//! every authenticated caller.

use nrr_domain::enforcement_mode::EnforcementMode;
use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{StorageError, StorageResult};

// ── Default constants ────────────────────────────────────────────────────────

/// Canonical defaults — mirror
/// `nrr_service_runtime::service_stability::DEFAULT_IPC_*`. Kept here so
/// the storage layer can populate the implicit default record without
/// taking a runtime dep on service-runtime. Drift between the two is
/// caught by the wire-shape tests that round-trip
/// `ServiceStabilityConfigDto` through real storage.
pub const DEFAULT_IPC_MAX_RESTARTS: u32 = 20;
pub const DEFAULT_IPC_BACKOFF_BASE_MS: u32 = 100;
pub const DEFAULT_IPC_BACKOFF_CAP_MS: u32 = 5_000;

/// Slug allow-list — keep in sync with
/// `nrr_service_runtime::service_stability::IpcAcceptFailurePolicy::slug`.
pub const KIND_RECOVERABLE: &str = "recoverable";
pub const KIND_CRITICAL: &str = "critical";

/// `routing_stop_policy` slug allow-list — mirrors the schema CHECK on
/// [`crate::schema::STATE_DB_V17_DDL`].
pub const ROUTING_STOP_POLICY_TEARDOWN: &str = "teardown";
pub const ROUTING_STOP_POLICY_PERSIST: &str = "persist";

// ── DTO ──────────────────────────────────────────────────────────────────────

/// What happens to NRR routing/filters when the Windows service stops.
///
/// Stored as a TEXT slug on the `service_stability_config` singleton (schema
/// v17). `Teardown` (return everything to the primary connection) is the
/// default — the intuitive "disable/stop = back to normal"; `Persist` is
/// opt-in for a work/corporate additional adapter. Governs BOTH pause
/// ("safe disable") and service stop.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RoutingStopPolicy {
    /// Full teardown: remove **every** NRR route AND strip all WFP filters on
    /// pause/stop, restoring pristine networking — the box returns to its pre-NRR
    /// channel (the additional adapter's own default if it installs one, else
    /// direct). This is the default.
    #[default]
    Teardown,
    /// Keep the NRR `/32` rule-routes on the additional adapter (matched hosts
    /// keep egressing it after pause/stop) and remove only NRR's overlays, so
    /// general traffic returns to the primary connection. Opt-in — useful for a
    /// work/corporate additional adapter so corporate resources stay reachable
    /// while general routing is paused. Strips all WFP filters (routing is
    /// route-table-based; a lingering block would be a lockout).
    Persist,
}

impl RoutingStopPolicy {
    /// Stable on-disk / wire slug.
    pub fn as_slug(self) -> &'static str {
        match self {
            RoutingStopPolicy::Teardown => ROUTING_STOP_POLICY_TEARDOWN,
            RoutingStopPolicy::Persist => ROUTING_STOP_POLICY_PERSIST,
        }
    }

    /// Parse a slug at a read boundary. Returns `Err(slug)` on any
    /// unrecognised value so a corrupted row surfaces loudly rather than
    /// silently defaulting (mirrors `ipc_accept_kind` decoding).
    pub fn from_slug(slug: &str) -> Result<Self, &str> {
        match slug {
            ROUTING_STOP_POLICY_TEARDOWN => Ok(RoutingStopPolicy::Teardown),
            ROUTING_STOP_POLICY_PERSIST => Ok(RoutingStopPolicy::Persist),
            other => Err(other),
        }
    }
}

/// Persisted IPC accept-failure policy. The schema's cross-field CHECK
/// guarantees the two variants stay consistent on disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpcAcceptPolicyRecord {
    Recoverable {
        max_restarts: u32,
        backoff_base_ms: u32,
        backoff_cap_ms: u32,
    },
    Critical,
}

/// Full persisted `ServiceStabilityConfig` record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceStabilityConfigRecord {
    pub ipc_accept_policy: IpcAcceptPolicyRecord,
    /// SID of the admin who last touched the row. `None` for the
    /// implicit default returned when no row exists.
    pub set_by_sid: Option<String>,
    /// UTC milliseconds. `0` for the implicit default record.
    pub updated_at: i64,
    /// When `true` the supervisor installs the
    /// `tracing_subscriber::EnvFilter` directive `"nrr=debug,info"`
    /// instead of the canonical `"nrr=info,info"`, so operational
    /// NDJSON captures `tracing::debug!` events. Persisted as INTEGER
    /// 0/1 on disk; default `false`.
    pub verbose_logging: bool,
    /// When `true` the opt-in connection-egress trace writes each observed
    /// connection to the operational NDJSON. Persisted as INTEGER 0/1;
    /// default `false`.
    pub conn_trace_ndjson: bool,
    /// When `true` the connection-egress trace streams to the GUI
    /// «Диагностика» panel. Independent of
    /// `conn_trace_ndjson` (either, both, or neither). Default `false`.
    pub conn_trace_gui: bool,
    /// Routing scope. When `true` (the default) the
    /// service enforces the active console user's routing policy continuously
    /// — even with no GUI/tray connected, from boot — until the service stops.
    /// When `false` the route table is only enforced while a tray is connected
    /// (cleared on disconnect). Parked on this singleton row to reuse its
    /// admin-gated (`ServiceStabilityConfigSet`) read-modify-write round-trip;
    /// it is a service-wide routing flag, not a stability/diagnostics one.
    /// Persisted as INTEGER 0/1; default `true` (service-driven).
    pub rule_scope_service_driven: bool,
    /// Persist-on-stop — what happens to NRR routing/filters when the service
    /// stops. `Persist` keeps the `/32` rule-routes on the secondary and
    /// removes only NRR's overlays, so rule-matched hosts keep egressing the
    /// secondary while general traffic returns to the OS/secondary default;
    /// `Teardown` fully removes every NRR route (restore pristine). Both always
    /// strip all WFP filters (a paused/stopped service can never lock the user
    /// out). Persisted as a TEXT slug (schema v17); default
    /// [`RoutingStopPolicy::Teardown`]. Governs pause AND service stop.
    pub routing_stop_policy: RoutingStopPolicy,
    /// User-configurable FQDN cache refresh cadence (seconds):
    /// how often a routed site's IPs are re-resolved. Persisted as INTEGER
    /// (schema v19, CHECK 60..86400); default
    /// [`nrr_domain::decision_lookup::CACHE_REFRESH_DEFAULT_SECS`] (5 min).
    /// Always clamped through
    /// [`nrr_domain::decision_lookup::clamp_cache_refresh_secs`] on read + write
    /// so an out-of-range value (older build / manual edit) can never slip past.
    pub cache_refresh_interval_secs: u32,
    /// Machine-wide traffic-enforcement MECHANISM.
    /// `Reactive` (the default) uses the existing reactive kill-switch (passive
    /// ETW/seeder learning); `Resolver` uses a local DNS resolver that installs
    /// enforcement synchronously before answering. Persisted as a small-int code
    /// (schema v24, CHECK 0..=1) that mirrors
    /// [`nrr_domain::enforcement_mode::EnforcementMode::as_code`]; an
    /// unrecognised code (older build / manual edit) decodes to
    /// [`EnforcementMode::default`] (Reactive) rather than being trusted. Global
    /// service setting (NOT per-SID).
    pub enforcement_mode: EnforcementMode,
    /// Secondary-tunnel liveness window (SECONDS): how long the
    /// tunnel next-hop must be continuously unreachable (active ICMP probe) before
    /// the kill-switch fail-closes. `0` (the default) DISABLES the probe entirely —
    /// the liveness window never fail-closes (safe default). Any non-zero value is
    /// clamped to `5..=3600` on both read and write (defense-in-depth), so an
    /// out-of-range value (older build / manual edit) can never slip past. Persisted
    /// as INTEGER (schema v25, CHECK 0..3600). Global service setting (NOT per-SID).
    pub secondary_liveness_window_secs: u32,
    /// Machine-wide fake-IP toggle: when `true` AND
    /// the enforcement mode is `Resolver`, scope hosts are answered with
    /// virtual addresses and relayed through the TUN adapter. Lives next to
    /// `enforcement_mode` because the feature is meaningful only on top of the
    /// Mode-B resolver and drives a machine-wide adapter/stack. Persisted as
    /// INTEGER 0/1 (schema v34, CHECK 0/1); default `false` (opt-in). Global
    /// service setting (NOT per-SID).
    pub fake_ip_enabled: bool,
    /// DNS-over-secondary — when `true` AND the secondary adapter
    /// is up, the service's own upstream DNS queries egress source-bound
    /// through the secondary link to public resolvers instead of the primary
    /// provider's resolver (which can stub/poison answers for pinned names).
    /// Falls back to the primary path whenever the secondary is unavailable.
    /// Persisted as INTEGER 0/1 (schema v36, CHECK 0/1); default `false`
    /// (opt-in). Global service setting (NOT per-SID).
    pub dns_via_secondary: bool,
    /// Fast DNS answers — when `true`, the Mode-B resolver
    /// answers a rule-host query immediately whenever every answered address
    /// is already known to the routable cache (routes installed or
    /// converging), holding the answer for the reconcile deadline ONLY when
    /// the answer introduces never-seen addresses (first contact — the one
    /// case where the app's first connect can race the route install).
    /// Persisted as INTEGER 0/1 (schema v38, CHECK 0/1); default `true`
    /// (measured: holding every answer stalled page loads app-wide). Global
    /// service setting (NOT per-SID).
    pub dns_fast_answers: bool,
    /// Fake-IP UDP relay — when `true`, the fake-IP pool permit
    /// for a user SID admits UDP (QUIC/HTTP-3) into the pool instead of
    /// hard-blocking it, so QUIC flows through the relay's TUN stack like TCP
    /// already does. Meaningful only when `fake_ip_enabled` is also `true`.
    /// Persisted as INTEGER 0/1 (schema v39, CHECK 0/1); default `false`
    /// (opt-in — the safe default keeps today's "QUIC dies at connect, browser
    /// falls back to TCP" behaviour). Global service setting (NOT per-SID).
    pub fake_ip_udp_relay: bool,
    /// Fake-IP instant reset — when `true`, a relay dial that
    /// fails because the source-address policy refused it (most commonly:
    /// the secondary adapter is unresolved during a VPN reconnect) resets the
    /// client immediately, same as today. When `false`, that ONE refusal
    /// class is held and retried for a bounded window instead of resetting
    /// the client outright; a genuine network error still fails fast either
    /// way. Persisted as INTEGER 0/1 (schema v40, CHECK 0/1); default `true`
    /// (today's behaviour). Global service setting (NOT per-SID).
    pub fake_ip_instant_rst: bool,
    /// Administrative rules lock. When `true` (the default) every user
    /// maintains their own rule set; when `false` rule authoring is frozen for
    /// non-elevated callers — they keep reading the administrator's baseline,
    /// but their own divergence is refused by the service, not merely hidden by
    /// the GUI. Machine-wide on purpose: a per-principal row would be writable
    /// by the very account the lock restricts. Persisted as INTEGER 0/1 (schema
    /// v45, CHECK 0/1); default `true`. Writing it requires elevation (the
    /// singleton's wire operation is admin-gated); reading is open.
    pub allow_user_rule_edits: bool,
}

/// Clamp a secondary-tunnel liveness window (seconds) to its valid range. `0` is
/// the DISABLED sentinel and passes through unchanged; any non-zero value is
/// coerced into `5..=3600`. Applied on both read and write so an out-of-range
/// value (older build / manual edit) can never be trusted.
pub fn clamp_liveness_window_secs(secs: u32) -> u32 {
    if secs == 0 {
        0
    } else {
        secs.clamp(5, 3600)
    }
}

impl ServiceStabilityConfigRecord {
    /// Canonical default: `Recoverable` with documented constants,
    /// no `set_by_sid`, `updated_at = 0`, `verbose_logging = false`.
    /// Returned by [`ServiceStabilityConfigRepository::get_or_default`]
    /// when the singleton row has never been written.
    pub fn default_record() -> Self {
        Self {
            ipc_accept_policy: IpcAcceptPolicyRecord::Recoverable {
                max_restarts: DEFAULT_IPC_MAX_RESTARTS,
                backoff_base_ms: DEFAULT_IPC_BACKOFF_BASE_MS,
                backoff_cap_ms: DEFAULT_IPC_BACKOFF_CAP_MS,
            },
            set_by_sid: None,
            updated_at: 0,
            verbose_logging: false,
            conn_trace_ndjson: false,
            // Showing the trace in the GUI costs nothing on disk and is what
            // makes the Diagnostics panel useful out of the box; the
            // privacy-sensitive half is the NDJSON sink above, which stays off.
            // This is the answer for a state DB that was never written — an
            // existing row keeps whatever it holds.
            conn_trace_gui: true,
            rule_scope_service_driven: true,
            routing_stop_policy: RoutingStopPolicy::Teardown,
            cache_refresh_interval_secs: nrr_domain::decision_lookup::CACHE_REFRESH_DEFAULT_SECS,
            // Mirrors `EnforcementMode::default()`. Naming the variant instead
            // of deriving it is deliberate — this row is what a wiped or
            // never-written state DB answers with, and that answer must be
            // reviewed as a product decision, not inherited silently.
            enforcement_mode: EnforcementMode::Resolver,
            secondary_liveness_window_secs: 0,
            fake_ip_enabled: false,
            dns_via_secondary: false,
            dns_fast_answers: true,
            fake_ip_udp_relay: false,
            fake_ip_instant_rst: true,
            allow_user_rule_edits: true,
        }
    }
}

// ── Repository ───────────────────────────────────────────────────────────────

/// Hand-off type for the policy variant when calling
/// [`ServiceStabilityConfigRepository::set`]. Decoupled from the
/// persisted shape so callers can build a value without naming the
/// row's `set_by_sid`/`updated_at` fields.
pub use IpcAcceptPolicyRecord as IpcAcceptPolicyWrite;

pub struct ServiceStabilityConfigRepository<'c> {
    conn: &'c Connection,
}

impl<'c> ServiceStabilityConfigRepository<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    /// Reads the singleton row. Returns the implicit canonical default
    /// (see [`ServiceStabilityConfigRecord::default_record`]) when no
    /// row has been written.
    ///
    /// Rejects schema-inconsistent rows with `StorageError::Internal`.
    /// The schema CHECK should make these unreachable, but the
    /// invariant is double-checked at the read boundary so any
    /// out-of-band corruption (manual SQL fix, restored backup with
    /// older schema) surfaces loudly instead of returning silently
    /// wrong defaults.
    pub fn get_or_default(&self) -> StorageResult<ServiceStabilityConfigRecord> {
        let row = self
            .conn
            .query_row(
                "SELECT ipc_accept_kind,
                        ipc_max_restarts,
                        ipc_backoff_base_ms,
                        ipc_backoff_cap_ms,
                        set_by_sid,
                        updated_at,
                        verbose_logging,
                        conn_trace_ndjson,
                        conn_trace_gui,
                        rule_scope_service_driven,
                        routing_stop_policy,
                        cache_refresh_interval_secs,
                        enforcement_mode,
                        secondary_liveness_window_secs,
                        fake_ip_enabled,
                        dns_via_secondary,
                        dns_fast_answers,
                        fake_ip_udp_relay,
                        fake_ip_instant_rst,
                        allow_user_rule_edits
                 FROM service_stability_config
                 WHERE id = 1",
                [],
                |row| {
                    let kind: String = row.get(0)?;
                    let max_restarts: Option<i64> = row.get(1)?;
                    let backoff_base_ms: Option<i64> = row.get(2)?;
                    let backoff_cap_ms: Option<i64> = row.get(3)?;
                    let set_by_sid: Option<String> = row.get(4)?;
                    let updated_at: i64 = row.get(5)?;
                    let verbose_logging: i64 = row.get(6)?;
                    let conn_trace_ndjson: i64 = row.get(7)?;
                    let conn_trace_gui: i64 = row.get(8)?;
                    let rule_scope_service_driven: i64 = row.get(9)?;
                    let routing_stop_policy: String = row.get(10)?;
                    let cache_refresh_interval_secs: i64 = row.get(11)?;
                    let enforcement_mode: i64 = row.get(12)?;
                    let secondary_liveness_window_secs: i64 = row.get(13)?;
                    let fake_ip_enabled: i64 = row.get(14)?;
                    let dns_via_secondary: i64 = row.get(15)?;
                    let dns_fast_answers: i64 = row.get(16)?;
                    let fake_ip_udp_relay: i64 = row.get(17)?;
                    let fake_ip_instant_rst: i64 = row.get(18)?;
                    let allow_user_rule_edits: i64 = row.get(19)?;
                    Ok((
                        kind,
                        max_restarts,
                        backoff_base_ms,
                        backoff_cap_ms,
                        set_by_sid,
                        updated_at,
                        verbose_logging,
                        conn_trace_ndjson,
                        conn_trace_gui,
                        rule_scope_service_driven,
                        routing_stop_policy,
                        cache_refresh_interval_secs,
                        enforcement_mode,
                        secondary_liveness_window_secs,
                        fake_ip_enabled,
                        dns_via_secondary,
                        dns_fast_answers,
                        fake_ip_udp_relay,
                        fake_ip_instant_rst,
                        allow_user_rule_edits,
                    ))
                },
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("service_stability_config get: {e}")))?;

        match row {
            None => Ok(ServiceStabilityConfigRecord::default_record()),
            Some((
                kind,
                max_r,
                base_ms,
                cap_ms,
                sid,
                updated,
                verbose,
                ct_ndjson,
                ct_gui,
                rule_scope,
                stop_policy_slug,
                cache_refresh,
                enforcement_code,
                liveness_window,
                fake_ip,
                dns_via_secondary,
                dns_fast_answers,
                fake_ip_udp_relay,
                fake_ip_instant_rst,
                allow_user_rule_edits,
            )) => {
                let policy = decode_policy(&kind, max_r, base_ms, cap_ms)?;
                let routing_stop_policy =
                    RoutingStopPolicy::from_slug(&stop_policy_slug).map_err(|other| {
                        StorageError::Internal(format!(
                            "service_stability_config: unknown routing_stop_policy {other:?}"
                        ))
                    })?;
                Ok(ServiceStabilityConfigRecord {
                    ipc_accept_policy: policy,
                    set_by_sid: sid,
                    updated_at: updated,
                    verbose_logging: verbose != 0,
                    conn_trace_ndjson: ct_ndjson != 0,
                    conn_trace_gui: ct_gui != 0,
                    rule_scope_service_driven: rule_scope != 0,
                    routing_stop_policy,
                    // Clamp on read: an out-of-range value from an older build /
                    // manual edit is coerced to the valid range, never trusted.
                    cache_refresh_interval_secs:
                        nrr_domain::decision_lookup::clamp_cache_refresh_secs(
                            cache_refresh.clamp(0, u32::MAX as i64) as u32,
                        ),
                    // Decode the enforcement-mode code. An unknown code (older
                    // build / manual edit) falls back to the safe default
                    // (Reactive) rather than being trusted — never silently
                    // switch modes.
                    enforcement_mode: EnforcementMode::from_code(enforcement_code)
                        .unwrap_or_default(),
                    // Clamp on read: 0 stays 0 (disabled); any non-zero out-of-range
                    // value from an older build / manual edit is coerced into
                    // 5..=3600, never trusted.
                    secondary_liveness_window_secs: clamp_liveness_window_secs(
                        liveness_window.clamp(0, u32::MAX as i64) as u32,
                    ),
                    fake_ip_enabled: fake_ip != 0,
                    dns_via_secondary: dns_via_secondary != 0,
                    dns_fast_answers: dns_fast_answers != 0,
                    fake_ip_udp_relay: fake_ip_udp_relay != 0,
                    fake_ip_instant_rst: fake_ip_instant_rst != 0,
                    allow_user_rule_edits: allow_user_rule_edits != 0,
                })
            }
        }
    }

    /// Inserts or replaces the singleton row. The schema's range
    /// CHECKs (see `STATE_DB_V8_DDL`) reject out-of-range params at
    /// the SQL boundary; callers that want a Rust-side error before
    /// hitting SQL can use [`validate_recoverable_params`] first.
    ///
    /// `verbose_logging` is persisted alongside the policy in the same
    /// row — both fields update together on every Save so callers don't
    /// have to coordinate two writes. Pass `false` to preserve the
    /// default.
    #[allow(clippy::too_many_arguments)]
    pub fn set(
        &self,
        policy: &IpcAcceptPolicyWrite,
        verbose_logging: bool,
        conn_trace_ndjson: bool,
        conn_trace_gui: bool,
        rule_scope_service_driven: bool,
        routing_stop_policy: RoutingStopPolicy,
        cache_refresh_interval_secs: u32,
        enforcement_mode: EnforcementMode,
        secondary_liveness_window_secs: u32,
        fake_ip_enabled: bool,
        dns_via_secondary: bool,
        dns_fast_answers: bool,
        fake_ip_udp_relay: bool,
        fake_ip_instant_rst: bool,
        allow_user_rule_edits: bool,
        set_by_sid: Option<&str>,
        now_ms: i64,
    ) -> StorageResult<()> {
        let (kind, max_r, base_ms, cap_ms) = match *policy {
            IpcAcceptPolicyWrite::Recoverable {
                max_restarts,
                backoff_base_ms,
                backoff_cap_ms,
            } => (
                KIND_RECOVERABLE,
                Some(max_restarts as i64),
                Some(backoff_base_ms as i64),
                Some(backoff_cap_ms as i64),
            ),
            IpcAcceptPolicyWrite::Critical => (KIND_CRITICAL, None, None, None),
        };
        let verbose_int: i64 = if verbose_logging { 1 } else { 0 };
        let ct_ndjson_int: i64 = if conn_trace_ndjson { 1 } else { 0 };
        let ct_gui_int: i64 = if conn_trace_gui { 1 } else { 0 };
        let rule_scope_int: i64 = if rule_scope_service_driven { 1 } else { 0 };
        let stop_policy_slug = routing_stop_policy.as_slug();
        // Clamp on write (defense-in-depth): never persist a value outside the
        // SSOT range, so the schema CHECK is never hit and callers that skipped
        // the GUI limit still land in-range.
        let cache_refresh_int: i64 =
            nrr_domain::decision_lookup::clamp_cache_refresh_secs(cache_refresh_interval_secs)
                as i64;
        let enforcement_code: i64 = enforcement_mode.as_code();
        // Clamp on write (defense-in-depth): 0 stays 0 (disabled); any non-zero
        // value is coerced into 5..=3600 so the schema CHECK is never hit and a
        // caller that skipped the GUI limit still lands in-range.
        let liveness_window_int: i64 =
            clamp_liveness_window_secs(secondary_liveness_window_secs) as i64;
        let fake_ip_int: i64 = if fake_ip_enabled { 1 } else { 0 };
        let dns_via_secondary_int: i64 = if dns_via_secondary { 1 } else { 0 };
        let dns_fast_answers_int: i64 = if dns_fast_answers { 1 } else { 0 };
        let fake_ip_udp_relay_int: i64 = if fake_ip_udp_relay { 1 } else { 0 };
        let fake_ip_instant_rst_int: i64 = if fake_ip_instant_rst { 1 } else { 0 };
        let allow_user_rule_edits_int: i64 = if allow_user_rule_edits { 1 } else { 0 };
        self.conn
            .execute(
                "INSERT INTO service_stability_config
                    (id, ipc_accept_kind,
                     ipc_max_restarts, ipc_backoff_base_ms, ipc_backoff_cap_ms,
                     set_by_sid, updated_at, verbose_logging,
                     conn_trace_ndjson, conn_trace_gui, rule_scope_service_driven,
                     routing_stop_policy, cache_refresh_interval_secs, enforcement_mode,
                     secondary_liveness_window_secs, fake_ip_enabled, dns_via_secondary,
                     dns_fast_answers, fake_ip_udp_relay, fake_ip_instant_rst,
                     allow_user_rule_edits)
                 VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                         ?17, ?18, ?19, ?20)
                 ON CONFLICT(id) DO UPDATE SET
                     ipc_accept_kind     = excluded.ipc_accept_kind,
                     ipc_max_restarts    = excluded.ipc_max_restarts,
                     ipc_backoff_base_ms = excluded.ipc_backoff_base_ms,
                     ipc_backoff_cap_ms  = excluded.ipc_backoff_cap_ms,
                     set_by_sid          = excluded.set_by_sid,
                     updated_at          = excluded.updated_at,
                     verbose_logging     = excluded.verbose_logging,
                     conn_trace_ndjson   = excluded.conn_trace_ndjson,
                     conn_trace_gui      = excluded.conn_trace_gui,
                     rule_scope_service_driven = excluded.rule_scope_service_driven,
                     routing_stop_policy = excluded.routing_stop_policy,
                     cache_refresh_interval_secs = excluded.cache_refresh_interval_secs,
                     enforcement_mode    = excluded.enforcement_mode,
                     secondary_liveness_window_secs = excluded.secondary_liveness_window_secs,
                     fake_ip_enabled     = excluded.fake_ip_enabled,
                     dns_via_secondary   = excluded.dns_via_secondary,
                     dns_fast_answers    = excluded.dns_fast_answers,
                     fake_ip_udp_relay   = excluded.fake_ip_udp_relay,
                     fake_ip_instant_rst = excluded.fake_ip_instant_rst,
                     allow_user_rule_edits = excluded.allow_user_rule_edits",
                params![
                    kind,
                    max_r,
                    base_ms,
                    cap_ms,
                    set_by_sid,
                    now_ms,
                    verbose_int,
                    ct_ndjson_int,
                    ct_gui_int,
                    rule_scope_int,
                    stop_policy_slug,
                    cache_refresh_int,
                    enforcement_code,
                    liveness_window_int,
                    fake_ip_int,
                    dns_via_secondary_int,
                    dns_fast_answers_int,
                    fake_ip_udp_relay_int,
                    fake_ip_instant_rst_int,
                    allow_user_rule_edits_int
                ],
            )
            .map_err(|e| StorageError::Internal(format!("service_stability_config set: {e}")))?;
        Ok(())
    }
}

/// Rust-side range validation matching the schema CHECKs. Returns an
/// `Err` describing the first out-of-range field so the IPC handler
/// can produce a `MalformedRequest` error without round-tripping
/// through SQLite.
pub fn validate_recoverable_params(
    max_restarts: u32,
    backoff_base_ms: u32,
    backoff_cap_ms: u32,
) -> Result<(), &'static str> {
    if !(1..=100).contains(&max_restarts) {
        return Err("max_restarts out of range (allowed: 1..=100)");
    }
    if !(50..=5_000).contains(&backoff_base_ms) {
        return Err("backoff_base_ms out of range (allowed: 50..=5000)");
    }
    if !(1_000..=60_000).contains(&backoff_cap_ms) {
        return Err("backoff_cap_ms out of range (allowed: 1000..=60000)");
    }
    if backoff_cap_ms < backoff_base_ms {
        return Err("backoff_cap_ms must be >= backoff_base_ms");
    }
    Ok(())
}

/// Standalone probe for the verbose-logging flag.
/// Called from the service binary entrypoint BEFORE `install_ndjson_tracing`
/// (so the right `EnvFilter` directive is picked at install time, not
/// later). Returns `false` on any error so a corrupted or missing row
/// degrades to the canonical info-only behaviour.
pub fn probe_verbose_logging(conn: &Connection) -> bool {
    ServiceStabilityConfigRepository::new(conn)
        .get_or_default()
        .map(|r| r.verbose_logging)
        .unwrap_or(false)
}

fn decode_policy(
    kind: &str,
    max_r: Option<i64>,
    base_ms: Option<i64>,
    cap_ms: Option<i64>,
) -> StorageResult<IpcAcceptPolicyRecord> {
    match kind {
        KIND_RECOVERABLE => match (max_r, base_ms, cap_ms) {
            (Some(m), Some(b), Some(c)) if m >= 0 && b >= 0 && c >= 0 => {
                Ok(IpcAcceptPolicyRecord::Recoverable {
                    max_restarts: m as u32,
                    backoff_base_ms: b as u32,
                    backoff_cap_ms: c as u32,
                })
            }
            _ => Err(StorageError::Internal(
                "service_stability_config: recoverable row missing or negative params".to_string(),
            )),
        },
        KIND_CRITICAL => match (max_r, base_ms, cap_ms) {
            (None, None, None) => Ok(IpcAcceptPolicyRecord::Critical),
            _ => Err(StorageError::Internal(
                "service_stability_config: critical row has non-NULL params".to_string(),
            )),
        },
        other => Err(StorageError::Internal(format!(
            "service_stability_config: unknown ipc_accept_kind {other:?}"
        ))),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
