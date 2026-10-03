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
                msg_key = "svc-boot-cache-open-failed",
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
            msg_key = "svc-boot-cache-migration-failed",
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
                msg_key = "svc-boot-fakeip-cache-purged",
                removed,
                "purged fake-pool addresses from the FQDN cache at open",
            ),
            Err(e) => tracing::warn!(
                target: "nrr::fake-ip",
                msg_key = "svc-boot-fakeip-cache-sweep-failed",
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
                msg_key = "svc-boot-traffic-db-migration-failed",
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
            msg_key = "svc-boot-traffic-db-rebuilt",
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
                msg_key = "svc-boot-traffic-sampler-prime-failed",
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
                msg_key = "svc-boot-settings-open-failed",
                error = %e,
                path = %path.display(),
                "failed to open settings connection; settings IPC ops will be unavailable",
            );
            None
        }
    }
}

/// The DB-MAC key store. This whole module is `#![cfg(target_os = "windows")]`,
/// so the DPAPI store is always available here.
pub(super) fn production_key_store() -> Arc<dyn nrr_platform_api::key_store::KeyStore> {
    Arc::new(nrr_platform_windows::key_store::WindowsDpapiKeyStore::default_systemprofile())
}

pub(super) use nrr_service_runtime::dns_stack::read_enforcement_mode;

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

/// Persist-on-stop — read the `routing_stop_policy` FRESH from
/// `service_stability_config`. Returns `true` only for the explicit `persist`
/// slug; any error, a missing row, or the default row all yield `false`
/// (teardown). Called from the graceful-stop hook at stop time (not a boot
/// snapshot) so a mid-session Save takes effect. Failing to `false` is the safe
/// posture: teardown always cleans up, so a corrupted row can never strand
/// routes or an orphaned block.
pub(super) fn read_routing_stop_persist(conn: &Arc<Mutex<Connection>>) -> bool {
    use nrr_storage::service_stability_config::{
        RoutingStopPolicy, ServiceStabilityConfigRepository,
    };
    let Ok(guard) = conn.lock() else {
        return false;
    };
    match ServiceStabilityConfigRepository::new(&guard).get_or_default() {
        Ok(r) => matches!(r.routing_stop_policy, RoutingStopPolicy::Persist),
        Err(_) => false,
    }
}
