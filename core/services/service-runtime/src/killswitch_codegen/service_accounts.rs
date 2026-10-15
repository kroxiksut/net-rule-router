//! The service accounts' and the forwarded traffic's share of the owner's
//! guard, as WFP filters.
//!
//! The same emitters as the owner's pins, re-scoped: only the ALE filters carry
//! a user condition, so only they are twinned — the transport-layer halves are
//! machine-wide and already the owner's.

use nrr_platform_api::types::SERVICE_ACCOUNTS_PRINCIPAL;

use crate::enforcement_planner::{ServiceAccountGuard, ServiceAccountPosture};

use super::*;

/// The id seed of `owner`'s service-account twins. Their own, so an owner
/// change retires one set and installs the other instead of two owners
/// claiming the same ids.
#[must_use]
pub fn service_account_seed(owner: &str) -> String {
    format!("{owner}|svc")
}

/// `guard` as filters scoped to the service accounts. A pin needs the tunnel's
/// LUID and fails open without one, like the owner's. `exempt_apps` — our own
/// executable and the tunnel clients — sit in the app-exemption band, above
/// every pin.
#[must_use]
pub fn service_account_filters(
    owner: &str,
    guard: &ServiceAccountGuard,
    secondary_luid: u64,
    protocols: KillSwitchProtocols,
    exempt_apps: &[String],
) -> Vec<WfpFilterSpec> {
    let seed = service_account_seed(owner);
    let mut out = match guard.posture {
        ServiceAccountPosture::Pin => {
            let mut out =
                kill_switch_filters(&seed, &guard.destinations, secondary_luid, protocols);
            out.extend(kill_switch_network_filters(
                &seed,
                &guard.holds,
                secondary_luid,
                protocols,
            ));
            out
        }
        ServiceAccountPosture::Block => {
            let mut out = fail_closed_block_destinations(&seed, &guard.destinations, protocols);
            out.extend(fail_closed_network_filters(&seed, &guard.holds, protocols));
            out
        }
    };
    out.extend(primary_app_exempt_filters(&seed, exempt_apps));
    out.retain(|spec| spec.layer.supports_ale_scoping());
    for spec in &mut out {
        spec.user_sid = Some(SERVICE_ACCOUNTS_PRINCIPAL.to_string());
    }
    out
}

/// The id seed of `owner`'s forwarded-traffic twins.
#[must_use]
pub fn forwarded_seed(owner: &str) -> String {
    format!("{owner}|fwd")
}

/// `guard` laid on the forwarding path, for what the machine routes for others
/// (WSL, Docker Desktop). A pin is the owner's pair keyed on the interface the
/// packet is forwarded out of, so it closes the instant the tunnel goes, as the
/// owner's does; without one the route table alone would carry these packets
/// out the main link until the next pass. Every protocol, as nothing narrower
/// is expressible there.
#[must_use]
pub fn forwarded_guard_filters(
    owner: &str,
    guard: &ServiceAccountGuard,
    secondary_luid: u64,
) -> Vec<WfpFilterSpec> {
    let seed = forwarded_seed(owner);
    let all = KillSwitchProtocols::ALL;
    let out = match guard.posture {
        ServiceAccountPosture::Pin => {
            let mut out = kill_switch_filters(&seed, &guard.destinations, secondary_luid, all);
            out.extend(kill_switch_network_filters(
                &seed,
                &guard.holds,
                secondary_luid,
                all,
            ));
            out
        }
        ServiceAccountPosture::Block => {
            let mut out = fail_closed_block_destinations(&seed, &guard.destinations, all);
            out.extend(fail_closed_network_filters(&seed, &guard.holds, all));
            out
        }
    };
    onto_forwarding_path(out)
}

/// The owner's blanket block, for what the machine forwards: the tunnel is gone
/// and the owner's traffic is held whole, so a guest's is too, save what the
/// blanket's own floor keeps open plus the main link's resolvers.
#[must_use]
pub fn forwarded_block_all_filters(
    owner: &str,
    exemptions: &FailClosedExemptions,
    primary_dns: &[IpAddr],
) -> Vec<WfpFilterSpec> {
    let mut exemptions = exemptions.clone();
    // A guest names its resolvers by address, and no port condition exists on
    // the forwarding path to keep the permit to port 53.
    exemptions.allow_dns_over_primary = false;
    exemptions
        .known_direct_ips
        .extend(
            exemptions
                .primary_dest_ips
                .iter()
                .copied()
                .chain(primary_dns.iter().filter_map(|ip| match ip {
                    IpAddr::V4(v4) => Some(*v4),
                    IpAddr::V6(_) => None,
                })),
        );
    exemptions.known_direct_ips.sort_unstable();
    exemptions.known_direct_ips.dedup();
    let seed = forwarded_seed(owner);
    onto_forwarding_path(fail_closed_block_all_filters(
        &seed,
        &exemptions,
        KillSwitchProtocols::ALL,
    ))
}

/// The connect half of each filter, moved onto the forwarding layers. The
/// layers below it repeat a destination per protocol, which the forwarding
/// path cannot tell apart; a port or user condition does not exist there.
fn onto_forwarding_path(mut out: Vec<WfpFilterSpec>) -> Vec<WfpFilterSpec> {
    out.retain(|spec| spec.layer.supports_ale_scoping());
    for spec in &mut out {
        spec.layer = if spec.layer.is_v6() {
            WfpLayerKey::IpForwardV6
        } else {
            WfpLayerKey::IpForwardV4
        };
        spec.user_sid = None;
        spec.ip_protocol = None;
        spec.remote_port = None;
    }
    let mut seen = std::collections::HashSet::new();
    out.retain(|spec| seen.insert(spec.id));
    out
}
