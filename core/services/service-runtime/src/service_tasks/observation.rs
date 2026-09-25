//! Tasks that feed the service from live traffic: the DNS and connection
//! observation drains, the application-destination fold and the live-connection
//! refresh.
//!
//! Split out of `service_tasks`; the code is unchanged.

use super::*;

// ── DNS observation ──────────────────────────────────────────────────────────

/// How often observed resolutions are folded into the rule-driven cache.
///
/// Two seconds: a name is looked up immediately before it is connected to, so
/// the window between learning the address and needing it is what decides
/// whether the first connection goes the right way.
pub const DNS_OBSERVATION_INTERVAL: Duration = Duration::from_secs(2);
pub const TASK_ID_DNS_OBSERVATION: &str = "dns-observation-tick";

/// Applies a batch of observations on behalf of ONE principal. A resolution is
/// not owned by a user — the machine looked the name up — so the caller applies
/// it to every present user's rules rather than to a chosen one's.
pub type ConsumeObservationsFor =
    Arc<dyn Fn(&str, &[nrr_platform_api::dns_observe::DnsObservation]) + Send + Sync>;

/// What the DNS-observation tick needs.
#[derive(Clone)]
pub struct DnsObservationWiring {
    pub source: Arc<dyn nrr_platform_api::dns_observe::DnsObservationSource>,
    pub consume_for: ConsumeObservationsFor,
    /// Who is present right now.
    pub principals: Arc<dyn nrr_platform_api::active_principals::ActivePrincipalSource>,
}

/// Fold observed resolutions into the addresses domain rules enforce.
///
/// A rule naming a domain can only be enforced for addresses that are known, so
/// this is what makes `suffix` and zone rules follow a site that moves. The
/// batch is applied for each present principal: two users may have different
/// rules about the same name, and the machine resolved it once for both.
///
/// `Optional`: losing it costs domain rules their freshness, never the policy.
pub fn build_dns_observation_task(wiring: DnsObservationWiring) -> ServiceTask {
    ServiceTask::periodic(
        TASK_ID_DNS_OBSERVATION,
        TaskClass::Optional,
        DNS_OBSERVATION_INTERVAL,
        RECOVERABLE_DEFAULT_MAX_RESTARTS,
        move |_stop| {
            let observations = wiring.source.drain();
            if observations.is_empty() {
                return TaskOutcome::Continue;
            }
            match wiring.principals.active_principals() {
                Ok(principals) => {
                    for principal in principals {
                        (wiring.consume_for)(principal.as_stored(), &observations);
                    }
                }
                // "Could not ask" is not "nobody is here": dropping the batch is
                // the honest outcome, and the next resolution comes soon.
                Err(e) => tracing::debug!(
                    target: "nrr::dns-observe",
                    error = %e,
                    observations = observations.len(),
                    "could not determine who is present; this batch was not applied",
                ),
            }
            TaskOutcome::Continue
        },
    )
}

// ── App-destination observation ──────────────────────────────────────────────

/// How often observed connections are folded into the app-destination store.
///
/// Short, because a socket that opens and closes between two polls is invisible:
/// the poll interval IS the resolution of what an application rule can learn.
/// Cheap enough for that — the platform source reads a socket table, never
/// traffic.
pub const APP_OBSERVATION_INTERVAL: Duration = Duration::from_secs(2);
pub const TASK_ID_APP_OBSERVATION: &str = "app-observation-tick";

/// What the app-destination tick needs.
#[derive(Clone)]
pub struct AppObservationWiring {
    pub source: Arc<dyn nrr_platform_api::conn_observe::ConnectionObservationSource>,
    pub store: Arc<crate::app_observation_lookup::AppObservationStore>,
    /// Where this tick is the only drain of the source, the connection-trace
    /// panel reads the same batch through it.
    pub trace: Option<Arc<crate::conn_observation_consumer::ConnTraceTee>>,
}

/// Fold observed connections into the destinations application rules route.
///
/// An application rule cannot be expressed as a packet-filter condition on every
/// OS, so the destinations the program actually uses ARE the rule's expression:
/// the planner turns each remembered address into an ordinary host flow. That
/// makes this tick the whole mechanism behind app rules where the filter engine
/// has no app context, and a supporting one where it has.
///
/// A newly-learnt address re-drives policy at once rather than waiting for the
/// next pass: the point of learning it is that traffic to it is going the wrong
/// way right now.
///
/// `Optional`: losing it costs an app rule its freshness, never the rest of the
/// policy.
pub fn build_app_observation_task(
    wiring: AppObservationWiring,
    on_new_destination: Option<crate::supervised_runtime::RouteRecomputeHook>,
) -> ServiceTask {
    ServiceTask::periodic(
        TASK_ID_APP_OBSERVATION,
        TaskClass::Optional,
        APP_OBSERVATION_INTERVAL,
        RECOVERABLE_DEFAULT_MAX_RESTARTS,
        move |_stop| {
            let learnt = fold_observations(&wiring);
            if learnt > 0 {
                tracing::debug!(
                    target: "nrr::app-routing",
                    learnt,
                    "new application destinations observed; re-driving policy",
                );
                if let Some(hook) = on_new_destination.as_ref() {
                    hook();
                }
            }
            TaskOutcome::Continue
        },
    )
}

/// Drain the source into the store; returns how many destinations were NEW.
///
/// Separate from the task so the decision is testable without a supervisor: the
/// count is what decides whether policy is re-driven, and a count that can only
/// be read from a log is a decision nothing checks.
pub fn fold_observations(wiring: &AppObservationWiring) -> usize {
    let mut learnt = 0usize;
    let batch = wiring.source.drain();
    if let Some(trace) = wiring.trace.as_ref() {
        trace.record(&batch, crate::conn_observation_consumer::now_unix_ms());
    }
    for observation in batch {
        // Without a process there is nothing to attribute the address to, and an
        // address attributed to nobody would widen every app rule that happens
        // to be enabled.
        let Some(path) = observation.process_path.as_deref() else {
            continue;
        };
        if let std::net::IpAddr::V4(ip) = observation.remote.ip() {
            if wiring.store.record(path, ip) {
                learnt += 1;
            }
        }
    }
    learnt
}

// ── Live-connection refresh ──────────────────────────────────────────────────

/// How often destinations still held open are restamped. Far inside the
/// freshness window, so a held connection is never older than this when the
/// window is measured, and rare enough that reading the connection table costs
/// nothing noticeable.
pub const LIVE_CONNECTION_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);
pub const TASK_ID_LIVE_CONNECTION_REFRESH: &str = "live-connection-refresh-tick";

/// What the live-connection refresh needs: the open connections, and the store
/// whose destinations they keep fresh.
#[derive(Clone)]
pub struct LiveConnectionRefreshWiring {
    pub source: Arc<dyn nrr_platform_api::conn_observe::live::LiveConnectionSource>,
    pub store: Arc<crate::app_observation_lookup::AppObservationStore>,
}

/// Keep application destinations fresh while a program still holds a
/// connection to them.
///
/// Observation sees a connection when it opens, and the freshness window then
/// runs from that moment: a program holding one connection for hours had its
/// route withdrawn at the window's edge, under the live session. This tick
/// changes no policy by itself: a refreshed destination was already routed, and
/// staying routed is the point.
///
/// `Optional`: without it destinations age out as they did before.
pub fn build_live_connection_refresh_task(wiring: LiveConnectionRefreshWiring) -> ServiceTask {
    ServiceTask::periodic(
        TASK_ID_LIVE_CONNECTION_REFRESH,
        TaskClass::Optional,
        LIVE_CONNECTION_REFRESH_INTERVAL,
        RECOVERABLE_DEFAULT_MAX_RESTARTS,
        move |_stop| {
            let refreshed = refresh_live_destinations(&wiring);
            if refreshed > 0 {
                tracing::debug!(
                    target: "nrr::app-observations",
                    refreshed,
                    "destinations still held open were kept inside the freshness window",
                );
            }
            TaskOutcome::Continue
        },
    )
}

/// One refresh pass; returns how many destinations were restamped.
pub fn refresh_live_destinations(wiring: &LiveConnectionRefreshWiring) -> usize {
    wiring.store.refresh_live(&wiring.source.established())
}

/// Periodic pump that drains passively-observed DNS resolutions and
/// feeds them to the consumer, which caches the ones
/// matching an active suffix/zone/exact rule. When anything matched (so the
/// cache gained a new sub-hostname), recompute the route table — this is
/// how `*.example.com` / `.ru` rules become real routes. The DNS resolution
/// happens elsewhere (ETW observer); this task only matches + caches +
/// recomputes, so it never blocks on the network.
pub fn build_dns_observe_task(
    source: Arc<dyn nrr_platform_api::dns_observe::DnsObservationSource>,
    consumer: Arc<crate::dns_observation_consumer::DnsObservationConsumer>,
    on_progress: Option<crate::supervised_runtime::RouteRecomputeHook>,
) -> ServiceTask {
    // Seed the FQDN cache from the OS resolver cache on a SLOW cadence (every
    // SEED_EVERY_TICKS observe ticks ≈ 30 s at the 1 s observe interval) in
    // addition to the boot seed. Reading the whole OS cache + a cache-only
    // query per name is heavier than draining the ETW ring, so it must NOT
    // run at the observe cadence. This catches rule hosts that were served
    // from the OS cache (no wire query, so the observer missed them) after
    // boot. First tick (counter 0) seeds early.
    const SEED_EVERY_TICKS: u64 = 30;
    let seed_tick = std::sync::atomic::AtomicU64::new(0);
    ServiceTask::periodic(
        TASK_ID_DNS_OBSERVE,
        TaskClass::Optional,
        DNS_OBSERVE_INTERVAL,
        0,
        move |_stop| {
            let batch = source.drain();
            if !batch.is_empty() {
                let summary = consumer.consume(&batch, SystemTime::now());
                if summary.made_progress() {
                    tracing::info!(
                        target: "nrr::dns-observe",
                        matched = summary.matched,
                        refreshed = summary.refreshed,
                        ignored = summary.ignored,
                        collateral = summary.collateral,
                        "DNS observation tick cached new suffix/zone hosts",
                    );
                    if let Some(hook) = on_progress.as_ref() {
                        hook();
                    }
                }
            }
            let n = seed_tick.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if n.is_multiple_of(SEED_EVERY_TICKS) {
                let seeded = consumer.seed_from_os_cache(SystemTime::now());
                if seeded.made_progress() {
                    if let Some(hook) = on_progress.as_ref() {
                        hook();
                    }
                }
            }
            TaskOutcome::Continue
        },
    )
}

/// Periodic pump that drains passively-observed outbound connections and
/// feeds them to the consumer, which derives each
/// connection's egress interface and emits the trace. Opt-in: only spawned when
/// a connection-observation source + consumer are wired (off by default).
pub fn build_conn_observe_task(
    source: Arc<dyn nrr_platform_api::conn_observe::ConnectionObservationSource>,
    consumer: Arc<crate::conn_observation_consumer::ConnectionObservationConsumer>,
    on_progress: Option<crate::supervised_runtime::RouteRecomputeHook>,
) -> ServiceTask {
    ServiceTask::periodic(
        TASK_ID_CONN_OBSERVE,
        TaskClass::Optional,
        CONN_OBSERVE_INTERVAL,
        0,
        move |_stop| {
            let batch = source.drain();
            if !batch.is_empty() {
                let summary = consumer.consume(&batch, SystemTime::now());
                if summary.made_progress() {
                    tracing::info!(
                        target: "nrr::conn-trace",
                        msg_key = "conn-observation-tick",
                        total = summary.total,
                        primary = summary.primary,
                        secondary = summary.secondary,
                        loopback = summary.loopback,
                        other = summary.other,
                        unknown = summary.unknown,
                        app_ips_added = summary.app_ips_added,
                        app_ips_retracted = summary.app_ips_retracted,
                        vpn_endpoints_learned = summary.vpn_endpoints_learned,
                        vpn_client_apps_learned = summary.vpn_client_apps_learned,
                        blocked_nrr = summary.blocked_nrr,
                        blocked_foreign = summary.blocked_foreign,
                        // Scope-bug indicator; must stay ~0 (see
                        // `ConnConsumeSummary::killswitch_drops_live_secondary`).
                        // The app-pin half is split out separately below since
                        // it is expected first-contact behaviour, so this line
                        // shows at a glance whether the remainder is the
                        // actionable destination-scoped kind.
                        killswitch_drops_live_secondary = summary.killswitch_drops_live_secondary,
                        killswitch_drops_live_secondary_app_scope =
                            summary.killswitch_drops_live_secondary_app_scope,
                        "connection-observation tick",
                    );
                }
                // New app→IP pairs may give an `Application` rule new
                // destinations; recompute now so they route promptly instead
                // of waiting for the next apply. A newly-learned VPN
                // bootstrap endpoint must likewise arm its exemption before
                // the client's retry, so recompute on that too (not just the
                // 30 s safety tick) — same for a newly-learned VPN client app
                // arming its app-scoped exemption before the client's next
                // check.
                if summary.app_ips_added > 0
                    // A withdrawal has to reach the route table as promptly as
                    // an addition: until the recompute runs, the `/32` is still
                    // moving the process the withdrawal was for.
                    || summary.app_ips_retracted > 0
                    || summary.vpn_endpoints_learned > 0
                    || summary.vpn_client_apps_learned > 0
                {
                    if let Some(hook) = on_progress.as_ref() {
                        hook();
                    }
                }
            }
            TaskOutcome::Continue
        },
    )
}
