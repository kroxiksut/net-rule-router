//! Opening the databases the boot needs, and reading what it needs out of them.
//!
//! One shape throughout: answer with a value the caller can act on, never an
//! error the caller has to interpret. A missing row, a failed open and a
//! corrupt value all resolve to the documented default here, because boot has
//! no one to ask. `pub(super)` for the same reason as its siblings — the
//! caller is `build_supervised_runtime_deps`.

use super::*;

/// Opens the FQDN/IP cache database and wraps it in an
/// `Arc<Mutex<dyn CacheRepository + Send>>` so multiple consumers can
/// share one connection serialised behind the mutex: the per-SID
/// orchestrator's [`SqliteFqdnCacheLookup`], the DNS refresh task, and
/// any future cache lookup port the engine consumes. `None` is returned
/// if migrations fail or the file cannot be opened — callers degrade to
/// a noop cache lookup + disable the DNS refresh task.
pub(super) fn open_cache_store(
    path: &std::path::Path,
    cache_refresh_secs: u32,
) -> Option<Arc<Mutex<dyn nrr_storage::repository::CacheRepository + Send>>> {
    use nrr_domain::decision_lookup::{clamp_cache_refresh_secs, FreshnessThresholds};
    use nrr_storage::migration::SqliteMigrationRunner;
    use nrr_storage::repository::MigrationRunner;
    use nrr_storage::store::SqliteCacheStore;

    let conn = match nrr_storage::migration::open_connection(path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                target: "nrr::runtime",
                error = %e,
                path = %path.display(),
                "failed to open FQDN cache connection; FQDN lookups + DNS refresh disabled",
            );
            return None;
        }
    };
    // Rebuildable cache DB — WAL for reader/writer concurrency (the leak-guard
    // reads while the DNS-refresh task writes), `synchronous = NORMAL` because a
    // corrupt cache is deleted + rebuilt anyway, so full fsync durability is
    // wasted overhead. Best-effort; on failure the connection keeps its defaults.
    let _: rusqlite::Result<()> = conn.execute_batch(
        "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = 5000;",
    );
    let runner = SqliteMigrationRunner::for_cache_db(conn);
    if let Err(e) = runner.run_pending_migrations() {
        tracing::warn!(
            target: "nrr::runtime",
            error = %e,
            path = %path.display(),
            "FQDN cache migration failed; FQDN lookups + DNS refresh disabled",
        );
        return None;
    }
    let store = SqliteCacheStore::new(
        runner.into_connection(),
        FreshnessThresholds {
            // The user-configured refresh interval is the cadence FLOOR.
            fallback_ttl_secs: clamp_cache_refresh_secs(cache_refresh_secs),
            ..FreshnessThresholds::default_production()
        },
    );
    // Fake-pool addresses are virtual; any cached as "real" resolutions (or
    // census rows) corrupt the routing model — sweep them on every open. The
    // ingestion paths filter the pool too, so this only ever removes rows
    // written by older builds. Best-effort: a failed sweep degrades heuristics,
    // not correctness.
    {
        use nrr_storage::repository::CacheRepository;
        let (lo, hi) = nrr_platform_api::fake_ip::FakeIpPoolConfig::default().v4_range();
        match store.purge_ip_range_v4(lo, hi) {
            Ok(0) => {}
            Ok(removed) => tracing::info!(
                target: "nrr::fake-ip",
                removed,
                "purged fake-pool addresses from the FQDN cache at open",
            ),
            Err(e) => tracing::warn!(
                target: "nrr::fake-ip",
                error = %e,
                "fake-pool FQDN-cache sweep failed at open",
            ),
        }
    }
    Some(Arc::new(Mutex::new(store))
        as Arc<
            Mutex<dyn nrr_storage::repository::CacheRepository + Send>,
        >)
}

/// Open the rebuildable `nrr_traffic_stats.db` and
/// build the [`TrafficSampler`] over the Windows octet-counter source, wrapped
/// in `Arc<Mutex<…>>` so the IPC provider (reads) and the sampling tick (writes)
/// share the one connection. `None` on any error — the traffic-stats IPC ops
/// then resolve to `UnimplementedHandler` and the GUI hides the surface.
pub(super) fn open_traffic_sampler(
    path: &std::path::Path,
) -> Option<Arc<Mutex<nrr_service_runtime::traffic_sampler::TrafficSampler>>> {
    use nrr_platform_windows::interface_traffic::WindowsInterfaceCounterSource;
    use nrr_service_runtime::traffic_sampler::TrafficSampler;
    use nrr_storage::SqliteTrafficStore;

    // Rebuildable ledger — a corrupt open (structural damage, stale migration
    // checksum) deletes the DB with its WAL sidecars and recreates it once
    // inside the storage helper. A DB from a newer build is refused instead of
    // rebuilt, so a downgrade keeps the ledger and only loses the counter.
    let opened = match nrr_storage::open_traffic_connection_or_rebuild(path) {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!(
                target: "nrr::runtime",
                error = %e,
                path = %path.display(),
                "traffic-stats DB migration failed; traffic counter disabled",
            );
            return None;
        }
    };
    if let Some(reason) = &opened.rebuilt_reason {
        tracing::info!(
            target: "nrr::runtime",
            path = %path.display(),
            reason = %reason,
            "traffic-stats DB was deleted and recreated after an open/migration failure",
        );
    }
    let store = SqliteTrafficStore::new(opened.connection);
    let source = Arc::new(WindowsInterfaceCounterSource::new())
        as Arc<dyn nrr_platform_api::InterfaceCounterSource>;
    match TrafficSampler::new(source, store) {
        Ok(sampler) => Some(Arc::new(Mutex::new(sampler))),
        Err(e) => {
            tracing::warn!(
                target: "nrr::runtime",
                error = %e,
                "failed to prime traffic sampler; traffic counter disabled",
            );
            None
        }
    }
}

/// Opens a separate connection to the state DB for settings providers.
/// `None` is returned on failure; callers must skip the partial-handler
/// registration in that case (the bootstrap path will already have
/// surfaced the failure as a Blocking phase).
pub(super) fn open_settings_connection(path: &std::path::Path) -> Option<Arc<Mutex<Connection>>> {
    if !path.exists() {
        return None;
    }
    // `open_connection` applies AND verifies the busy-timeout pragma rather
    // than setting it by hand and discarding the result — a failed pragma
    // would otherwise leave the connection with no timeout and nobody the
    // wiser.
    match nrr_storage::migration::open_connection(path) {
        Ok(conn) => Some(Arc::new(Mutex::new(conn))),
        Err(e) => {
            tracing::warn!(
                target: "nrr::runtime",
                error = %e,
                path = %path.display(),
                "failed to open settings connection; settings IPC ops will be unavailable",
            );
            None
        }
    }
}

/// Run the DB-MAC tamper bootstrap over the
/// state DB and return the row-MAC signing key (loaded or freshly
/// generated). On failure, returns `None` so the coordinator runs
/// unsigned (routing is unaffected). Alerts raised here land in the
/// same `security_alerts` table the IPC handlers read, so the GUI
/// surfaces them and the mutation gate engages until acknowledged.
///
/// This whole module is `#![cfg(target_os = "windows")]`, so the DPAPI
/// key store is always available here.
pub(super) fn run_db_mac_tamper_bootstrap(conn: &Arc<Mutex<Connection>>) -> Option<Vec<u8>> {
    use nrr_platform_windows::key_store::WindowsDpapiKeyStore;
    let key_store = WindowsDpapiKeyStore::default_systemprofile();
    let alerts_repo: Arc<dyn nrr_diagnostics::audit::alert::SecurityAlertsRepository> =
        Arc::new(ProductionSecurityAlertsRepository::new(Arc::clone(conn)));
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    match run_tamper_bootstrap(conn, &key_store, &alerts_repo, now_ms) {
        Ok(outcome) => {
            if outcome.raised_blocking_alert {
                tracing::warn!(
                    target: "nrr::tamper",
                    tampered = outcome.tampered_revision_ids.len(),
                    key_reset = outcome.key_was_reset,
                    backfilled = outcome.backfilled_rows,
                    "DB-MAC tamper bootstrap raised blocking alert(s); \
                     mutations gated until acknowledged",
                );
            } else {
                tracing::info!(
                    target: "nrr::tamper",
                    backfilled = outcome.backfilled_rows,
                    "DB-MAC tamper bootstrap clean",
                );
            }
            Some(outcome.signing_key)
        }
        Err(e) => {
            tracing::error!(
                target: "nrr::tamper",
                error = %e,
                "DB-MAC tamper bootstrap failed; coordinator will run unsigned",
            );
            None
        }
    }
}

/// Runs [`ActivationCoordinator::enforce_active_integrity_all`] and, for
/// every principal it rolled back or cleared, raises a (non-blocking)
/// `security_alerts` row so the GUI surfaces it — same dedup mechanism
/// as [`run_db_mac_tamper_bootstrap`]'s alerts, reused via
/// `tamper_bootstrap::emit_alert`. Best effort: a sweep failure is
/// logged and does not block startup, matching the tamper bootstrap's
/// own failure posture.
pub(super) fn run_active_integrity_enforcement(
    coordinator: &ActivationCoordinator,
    conn: &Arc<Mutex<Connection>>,
) {
    use nrr_service_runtime::activation_coordinator::ActiveIntegrityOutcome;
    use nrr_service_runtime::tamper_bootstrap::emit_alert;

    let outcomes = match coordinator.enforce_active_integrity_all("svc-boot-integrity-scan") {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(
                target: "nrr::tamper",
                error = ?e,
                "active-revision integrity sweep failed",
            );
            return;
        }
    };
    let rejected: Vec<_> = outcomes
        .into_iter()
        .filter(|(_, outcome)| {
            matches!(
                outcome,
                ActiveIntegrityOutcome::RolledBack { .. }
                    | ActiveIntegrityOutcome::ClearedNoTrustedFallback { .. }
            )
        })
        .collect();
    if rejected.is_empty() {
        return;
    }
    let alerts_repo: Arc<dyn nrr_diagnostics::audit::alert::SecurityAlertsRepository> =
        Arc::new(ProductionSecurityAlertsRepository::new(Arc::clone(conn)));
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    for (principal, outcome) in rejected {
        let rejected_revision_id = match &outcome {
            ActiveIntegrityOutcome::RolledBack {
                rejected_revision_id,
                ..
            }
            | ActiveIntegrityOutcome::ClearedNoTrustedFallback {
                rejected_revision_id,
                ..
            } => rejected_revision_id.clone(),
            _ => continue,
        };
        tracing::warn!(
            target: "nrr::tamper",
            principal = %principal,
            rejected_revision_id = %rejected_revision_id,
            outcome = ?outcome,
            "active revision failed the integrity gate; rolled back to last trusted revision",
        );
        if let Err(e) = emit_alert(
            &alerts_repo,
            format!("alt-revintegrity-{rejected_revision_id}"),
            nrr_diagnostics::audit::AuditEventKind::UntrustedRevisionRejected.as_str(),
            nrr_diagnostics::reason::integrity::UNTRUSTED_REVISION_REJECTED.as_str(),
            now_ms,
        ) {
            tracing::error!(
                target: "nrr::tamper",
                error = ?e,
                rejected_revision_id = %rejected_revision_id,
                "failed to raise untrusted-revision-rejected alert",
            );
        }
    }
}

/// Reads the persisted `service_stability_config` row
/// and converts it into the runtime-side `ServiceStabilityConfig` the
/// supervisor consumes. Returns `None` on any error so the caller can
/// fall back to `ServiceStabilityConfig::default()` (canonical
/// recoverable / 20 / 100ms / 5s — same as the GUI's default state).
///
/// The lock-acquire failure path uses `_ = ...` rather than `?` because
/// poisoning is non-fatal: a poisoned mutex around the settings
/// connection means another thread panicked mid-op; we still want the
/// supervisor to start with defaults rather than refuse to boot.
/// Read the persisted operational-log + audit
/// retention config so the cleanup tasks enforce the operator's saved caps.
/// `None` on lock/read failure → the caller falls back to documented defaults.
pub(super) fn read_log_retention_config(
    conn: &Arc<Mutex<Connection>>,
) -> Option<nrr_storage::LogRetentionConfig> {
    let guard = conn.lock().ok()?;
    let repo = nrr_storage::LogRetentionConfigRepository::new(&guard);
    match repo.get_or_default() {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            tracing::warn!(
                target: "nrr::runtime",
                error = %e,
                "log_retention_config read failed; using retention defaults",
            );
            None
        }
    }
}

pub(super) fn read_service_stability_config(
    conn: &Arc<Mutex<Connection>>,
) -> Option<nrr_service_runtime::service_stability::ServiceStabilityConfig> {
    use nrr_service_runtime::service_stability::{IpcAcceptFailurePolicy, ServiceStabilityConfig};
    use nrr_storage::service_stability_config::{
        IpcAcceptPolicyRecord, ServiceStabilityConfigRepository,
    };
    use std::time::Duration;

    let guard = conn.lock().ok()?;
    let repo = ServiceStabilityConfigRepository::new(&guard);
    let record = match repo.get_or_default() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                target: "nrr::runtime",
                error = %e,
                "service_stability_config read failed; using runtime defaults",
            );
            return None;
        }
    };
    let policy = match record.ipc_accept_policy {
        IpcAcceptPolicyRecord::Critical => {
            tracing::info!(
                target: "nrr::stability",
                kind = "critical",
                "service_stability_config loaded",
            );
            IpcAcceptFailurePolicy::Critical
        }
        IpcAcceptPolicyRecord::Recoverable {
            max_restarts,
            backoff_base_ms,
            backoff_cap_ms,
        } => {
            // Emit the loaded numbers so an operator who saves new
            // values in GUI Settings → Service stability can verify
            // via NDJSON that the supervisor picked them up after
            // restart. Without this, the only signal would be timing
            // between `task_failed` events — useless when IPC is
            // healthy.
            tracing::info!(
                target: "nrr::stability",
                kind = "recoverable",
                max_restarts,
                backoff_base_ms,
                backoff_cap_ms,
                "service_stability_config loaded",
            );
            IpcAcceptFailurePolicy::Recoverable {
                max_restarts,
                backoff_base: Duration::from_millis(u64::from(backoff_base_ms)),
                backoff_cap: Duration::from_millis(u64::from(backoff_cap_ms)),
            }
        }
    };
    Some(ServiceStabilityConfig {
        ipc_accept_policy: policy,
    })
}

/// Read the persisted `enforcement_mode` from
/// `service_stability_config`. Defaults to Reactive on any lock/read error or a
/// missing row (same fail-safe posture as `read_service_stability_config`). The
/// runtime `ServiceStabilityConfig` intentionally does not carry this field, so
/// it is read straight off the storage record here.
pub(super) fn read_enforcement_mode(
    conn: &Arc<Mutex<Connection>>,
) -> nrr_domain::enforcement_mode::EnforcementMode {
    use nrr_storage::service_stability_config::ServiceStabilityConfigRepository;
    let Ok(guard) = conn.lock() else {
        return nrr_domain::enforcement_mode::EnforcementMode::default();
    };
    let repo = ServiceStabilityConfigRepository::new(&guard);
    repo.get_or_default()
        .map(|record| record.enforcement_mode)
        .unwrap_or_default()
}

/// The ONE place the production fake-IP policy values come from: the scope
/// (broad coverage, no user host-exclusions yet) and the pool geometry. Shared
/// by the assembly (DNS answerer + relay) and the per-SID WFP context provider,
/// so the two sides can never disagree about what is fake-routed.
pub(super) fn fake_ip_policy() -> (
    nrr_platform_api::fake_ip::FakeIpScope,
    nrr_platform_api::fake_ip::FakeIpPoolConfig,
) {
    (
        nrr_platform_api::fake_ip::FakeIpScope::enabled(Vec::<String>::new()),
        nrr_platform_api::fake_ip::FakeIpPoolConfig::default(),
    )
}

/// The persisted machine-wide fake-IP toggle, read at boot
/// to reconcile the stack (mirrors [`read_enforcement_mode`]). Defaults to
/// `false` on any lock/read failure — the safe direction (feature off).
pub(super) fn read_fake_ip_enabled(conn: &Arc<Mutex<Connection>>) -> bool {
    use nrr_storage::service_stability_config::ServiceStabilityConfigRepository;
    let Ok(guard) = conn.lock() else {
        return false;
    };
    ServiceStabilityConfigRepository::new(&guard)
        .get_or_default()
        .map(|record| record.fake_ip_enabled)
        .unwrap_or(false)
}

/// The persisted DNS-over-secondary toggle, read at boot to seed the shared
/// live flag (mirrors [`read_fake_ip_enabled`]). Defaults to `false` on any
/// lock/read failure — the safe direction (feature off).
pub(super) fn read_dns_via_secondary(conn: &Arc<Mutex<Connection>>) -> bool {
    use nrr_storage::service_stability_config::ServiceStabilityConfigRepository;
    let Ok(guard) = conn.lock() else {
        return false;
    };
    ServiceStabilityConfigRepository::new(&guard)
        .get_or_default()
        .map(|record| record.dns_via_secondary)
        .unwrap_or(false)
}

/// The persisted fast-DNS-answers toggle, read at boot to seed the shared live
/// flag (mirrors [`read_dns_via_secondary`]). Defaults to `true` on any
/// lock/read failure — answering immediately is the safe direction (the hold
/// is the measured page-stall, not the protection).
pub(super) fn read_dns_fast_answers(conn: &Arc<Mutex<Connection>>) -> bool {
    use nrr_storage::service_stability_config::ServiceStabilityConfigRepository;
    let Ok(guard) = conn.lock() else {
        return true;
    };
    ServiceStabilityConfigRepository::new(&guard)
        .get_or_default()
        .map(|record| record.dns_fast_answers)
        .unwrap_or(true)
}

/// The persisted fake-IP UDP relay toggle, read at boot to seed the shared
/// live flag (mirrors [`read_dns_fast_answers`]). Defaults to `false` on any
/// lock/read failure — hard-blocking UDP into the pool is the safe direction
/// (today's "QUIC falls back to TCP" behaviour).
pub(super) fn read_fake_ip_udp_relay(conn: &Arc<Mutex<Connection>>) -> bool {
    use nrr_storage::service_stability_config::ServiceStabilityConfigRepository;
    let Ok(guard) = conn.lock() else {
        return false;
    };
    ServiceStabilityConfigRepository::new(&guard)
        .get_or_default()
        .map(|record| record.fake_ip_udp_relay)
        .unwrap_or(false)
}

/// The persisted fake-IP instant-reset toggle, read at boot to seed the
/// shared live flag (mirrors [`read_fake_ip_udp_relay`]). Defaults to `true`
/// on any lock/read failure — instant reset is today's behaviour and the
/// safe direction (never silently starts holding client connections).
pub(super) fn read_fake_ip_instant_rst(conn: &Arc<Mutex<Connection>>) -> bool {
    use nrr_storage::service_stability_config::ServiceStabilityConfigRepository;
    let Ok(guard) = conn.lock() else {
        return true;
    };
    ServiceStabilityConfigRepository::new(&guard)
        .get_or_default()
        .map(|record| record.fake_ip_instant_rst)
        .unwrap_or(true)
}
