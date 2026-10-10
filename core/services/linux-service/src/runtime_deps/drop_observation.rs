//! The connections our own rules drop, read back from their NFLOG reports and
//! merged with the socket table into the neutral connection consumer — the one
//! the other platform feeds. That is what gives block notices, the outage list,
//! a reason on each trace row and the learners something to read.
//!
//! Without the reports (no `CAP_NET_ADMIN`, or another listener holds the
//! group) the socket table alone keeps feeding the trace and the application
//! rules, as it did before; the outage list then says it is not watching.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use nrr_platform_api::adapters::AdapterEventSource;
use nrr_platform_api::conn_observe::{
    ConnectionObservationSource, MergedConnectionObservationSource,
};
use nrr_platform_api::enforcement::{EgressBindingSource, PolicyEnforcer, UserPrincipal};
use nrr_platform_api::fake_ip::stale_flows::StaleFlowReset;
use nrr_platform_api::route_table::RouteTablePort;
use nrr_platform_api::PlatformError;
use nrr_platform_linux::drop_tag::{DropKind, DropTag};
use nrr_service_runtime::app_observation_lookup::AppObservationStore;
use nrr_service_runtime::block_notice_center::BlockNoticeCenter;
use nrr_service_runtime::conn_observation_consumer::{
    BlockNoticeSinkFn, ConnTraceTee, ConnectionObservationConsumer, ConnectionTraceRing,
    EgressIfindexesFn, KillswitchDropCheckFn, VpnEndpointLearnFn,
};
use nrr_service_runtime::service_tasks::AppObservationWiring;

/// What the drop consumer takes from the policy stack.
pub(crate) struct DropObservationParts {
    pub api: Arc<dyn RouteTablePort>,
    pub egress_of: EgressIfindexesFn,
    pub notice_sink: BlockNoticeSinkFn,
    pub vpn_endpoint_learner: VpnEndpointLearnFn,
    /// The trace's "write to the log" switch, shared with the settings writer.
    pub log_ndjson: Arc<AtomicBool>,
    pub stale_flow_reset: Option<Arc<dyn StaleFlowReset>>,
}

/// A principal's links as the consumer reads them: the secondary only while
/// the enforcer counts it usable, so a dead tunnel is an outage here too.
pub(crate) fn egress_of(
    enforcer: Arc<dyn PolicyEnforcer>,
    bindings: Arc<dyn EgressBindingSource>,
    adapters: Arc<dyn AdapterEventSource>,
) -> EgressIfindexesFn {
    Arc::new(move |owner: &str| {
        let Ok(principal) = UserPrincipal::from_stored(owner) else {
            return (None, None);
        };
        let binding = bindings.bindings_for(&principal);
        // Service accounts bind nothing: no link read for them.
        if binding.primary.is_none() && binding.secondary.is_none() {
            return (None, None);
        }
        let Ok(links) = adapters.enumerate_all() else {
            return (None, None);
        };
        let index_of = |name: Option<&str>| {
            let name = name?;
            links
                .iter()
                .find(|a| a.friendly_name == name || a.adapter_name == name)
                .map(|a| a.index)
        };
        let secondary = binding
            .secondary
            .as_deref()
            .filter(|_| enforcer.channel_availability(&principal).secondary);
        (index_of(binding.primary.as_deref()), index_of(secondary))
    })
}

/// Drops worth a notice go to the centre, which keeps each user's episodes
/// and mutes.
pub(crate) fn notice_sink(center: Arc<BlockNoticeCenter>) -> BlockNoticeSinkFn {
    Arc::new(move |sid: &str, attempt, seen_at| center.record_observed(sid, &attempt, seen_at))
}

/// A role check over our drop ids: the id names the role, so nothing is
/// published or looked up.
fn tag_check(role: fn(DropTag) -> bool) -> KillswitchDropCheckFn {
    Arc::new(move |id| DropTag::from_spec_id(id).is_some_and(role))
}

/// The consumer over our drops and the socket table.
pub(crate) fn drop_consumer(
    parts: DropObservationParts,
    ring: Arc<ConnectionTraceRing>,
    store: Arc<AppObservationStore>,
) -> ConnectionObservationConsumer {
    let recent = nrr_service_runtime::recent_rule_addresses::global_recent_rule_addresses();
    let consumer = ConnectionObservationConsumer::with_egress(
        parts.api,
        parts.egress_of,
        Arc::new(|| None),
        false,
    )
    .with_log_ndjson_flag(parts.log_ndjson)
    // Several users, each with links of their own.
    .with_owner_scoped_egress()
    // The socket table lists a dropped connection as one more socket.
    .with_drop_pairing()
    .with_app_observations(store)
    .with_trace_ring(ring)
    // System drops may teach a tunnel server, as on the other platform.
    .with_vpn_endpoint_learner(
        parts.vpn_endpoint_learner,
        tag_check(|tag| tag.kind.verifies_kill_switch()),
    )
    .with_ipv6_cut_drop_check(tag_check(|tag| tag.kind == DropKind::Ipv6Cut))
    .with_dns_lockdown_drop_check(tag_check(|tag| tag.kind == DropKind::DnsLockdown))
    .with_service_account_drop_check(tag_check(|tag| tag.system))
    .with_not_covered_drop_check(tag_check(|tag| tag.kind == DropKind::Default))
    .with_block_notice(Arc::new(move |ip| recent.lookup(ip)), parts.notice_sink);
    match parts.stale_flow_reset {
        Some(reset) => consumer.with_stale_flow_reset(reset),
        None => consumer,
    }
}

/// The app-destination tick's wiring: socket table and drop reports through
/// the consumer when the reports start, the socket table alone when not.
pub(crate) fn app_observation_wiring(
    socket_table: Arc<dyn ConnectionObservationSource>,
    start_drop_reports: impl FnOnce() -> Result<Arc<dyn ConnectionObservationSource>, PlatformError>,
    drops: Option<DropObservationParts>,
    tee: Option<Arc<ConnTraceTee>>,
    store: Arc<AppObservationStore>,
) -> AppObservationWiring {
    let started = match (drops, tee.as_ref()) {
        (Some(parts), Some(tee)) => match start_drop_reports() {
            Ok(reports) => Some((parts, tee.ring(), reports)),
            Err(error) => {
                tracing::info!(
                    target: "nrr::conn-trace",
                    msg_key = "linux-svc-drop-reports-unavailable",
                    error = %error,
                    "drop reports unavailable: blocks are enforced, but notices and the outage list stay empty",
                );
                None
            }
        },
        _ => None,
    };
    match started {
        Some((parts, ring, reports)) => {
            tracing::info!(
                target: "nrr::conn-trace",
                msg_key = "linux-svc-drop-reports-enabled",
                "drop reports enabled: notices and the outage list are fed",
            );
            let consumer = drop_consumer(parts, ring, Arc::clone(&store));
            AppObservationWiring {
                // Socket table first: a drop reported by the time the table is
                // read lands in the same batch as its socket row.
                source: Arc::new(MergedConnectionObservationSource::new(vec![
                    socket_table,
                    reports,
                ])),
                store,
                trace: None,
                consumer: Some(Arc::new(consumer)),
            }
        }
        None => AppObservationWiring {
            source: socket_table,
            store,
            trace: tee,
            consumer: None,
        },
    }
}

/// The NFLOG listener as the tick's second source.
pub(crate) fn start_nflog() -> Result<Arc<dyn ConnectionObservationSource>, PlatformError> {
    nrr_platform_linux::nflog::NflogDropObserver::start()
        .map(|observer| Arc::new(observer) as Arc<dyn ConnectionObservationSource>)
}

#[cfg(test)]
mod tests;
