//! Tasks that keep resolved addresses current: the refresh tick, the rule-host
//! seeder and the application-destination write-back.
//!
//! Split out of `service_tasks`; the code is unchanged.

use super::*;

// ── DNS refresh ───────────────────────────────────────────────────────────────

/// Periodic DNS refresh tick. Walks
/// [`CacheRepository::list_expired_resolutions`][nrr_storage::repository::CacheRepository::list_expired_resolutions]
/// hot-first, re-resolves each via [`DnsResolverPort`][nrr_platform_api::dns::DnsResolverPort],
/// and writes the outcome back. `Optional` class — DNS unavailability
/// degrades rule matching over time (stale IPs expire from the cache)
/// but never blocks routing policy enforcement.
///
/// The orchestrator is shared via `Arc` so other entry points (manual
/// cache refresh IPC handler, on-demand admin command) can drive the
/// same code path.
pub fn build_dns_refresh_task(
    orchestrator: Arc<crate::dns_refresh::DnsRefreshOrchestrator>,
    on_progress: Option<crate::supervised_runtime::RouteRecomputeHook>,
) -> ServiceTask {
    ServiceTask::periodic(
        TASK_ID_DNS_REFRESH,
        TaskClass::Optional,
        DNS_REFRESH_INTERVAL,
        0,
        move |_stop| {
            let summary = orchestrator.run_once(SystemTime::now(), DNS_REFRESH_BATCH);
            if summary.made_progress() {
                tracing::info!(
                    target: "nrr::dns",
                    msg_key = "dns-refresh-tick",
                    attempted = summary.attempted,
                    succeeded = summary.succeeded,
                    failed_authoritative = summary.failed_authoritative,
                    failed_transient = summary.failed_transient,
                    cache_errors = summary.cache_errors,
                    skipped = summary.skipped,
                    fake_intercepted = summary.fake_intercepted,
                    loopback_pinned = summary.loopback_pinned,
                    "DNS refresh tick"
                );
                // Recompute only when fresh IPs actually landed in the FQDN
                // cache (a domain/zone rule whose hosts were cold may now
                // produce routes). `made_progress` also counts pure attempts —
                // failures and skips land nothing, and recomputing on them
                // re-derived the full route + WFP set every refresh tick.
                if summary.succeeded > 0 {
                    if let Some(hook) = on_progress.as_ref() {
                        hook();
                    }
                }
            }
            TaskOutcome::Continue
        },
    )
}

/// Periodic task that resolves the active user's not-yet-cached
/// `ExactFqdn` rule hostnames into the FQDN cache, then (if
/// it seeded anything) recomputes the route table so the freshly-resolved
/// IPs become routes. Without this nothing ever populates the cache from
/// the rule book, so domain rules would never route.
///
/// `present` returns everyone whose rules are in force right now — one console
/// user on Windows, however many are logged in on Linux. Empty → nothing to
/// seed. Off the mutation path: DNS resolution runs on the supervisor's
/// background tick, never blocking an apply.
pub fn build_rule_hostname_seed_task(
    seeder: Arc<crate::rule_hostname_seeder::RuleHostnameSeeder>,
    present: PresentPrincipalsFn,
    on_progress: Option<crate::supervised_runtime::RouteRecomputeHook>,
) -> ServiceTask {
    ServiceTask::periodic(
        TASK_ID_RULE_HOSTNAME_SEED,
        TaskClass::Optional,
        RULE_HOSTNAME_SEED_INTERVAL,
        0,
        move |_stop| {
            let mut progressed = false;
            for sid in present() {
                let summary = seeder.seed_for_principal(&sid, SystemTime::now());
                if summary.made_progress() {
                    progressed = true;
                    tracing::info!(
                        target: "nrr::rule-seed",
                        sid = %sid,
                        resolved = summary.resolved,
                        already_cached = summary.already_cached,
                        failed = summary.failed,
                        apex_absent = summary.apex_absent,
                        "rule-hostname seed tick",
                    );
                }
            }
            // One recompute for the pass, not one per user: the pass installs
            // policy for everyone present anyway.
            if progressed {
                if let Some(hook) = on_progress.as_ref() {
                    hook();
                }
            }
            TaskOutcome::Continue
        },
    )
}

/// Everyone whose rules are in force at this moment.
///
/// A list rather than an Option because "the active user" is a Windows-shaped
/// idea: there is one console session there, and any number of logged-in users
/// on Linux. A task that seeds only the first of them leaves the others' domain
/// rules resolving to nothing.
pub type PresentPrincipalsFn = Arc<dyn Fn() -> Vec<String> + Send + Sync>;

/// Application-destination write-back.
///
/// Persists the destinations of the applications the active user routes over the
/// additional link, so the next session's routes exist before those applications
/// connect (see [`crate::app_destination_memory`]). Purely a memory refresh — it
/// installs nothing and never recomputes routes, so no progress hook.
pub fn build_app_destination_flush_task(
    memory: Arc<crate::app_destination_memory::AppDestinationMemory>,
) -> ServiceTask {
    ServiceTask::periodic(
        TASK_ID_APP_DESTINATION_FLUSH,
        TaskClass::Optional,
        APP_DESTINATION_FLUSH_INTERVAL,
        0,
        move |_stop| {
            let summary = memory.flush(SystemTime::now());
            if summary.made_progress() {
                tracing::debug!(
                    target: "nrr::app-routing",
                    apps = summary.apps,
                    destinations = summary.destinations,
                    "application-destination write-back tick",
                );
            }
            TaskOutcome::Continue
        },
    )
}
