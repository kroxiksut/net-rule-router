//! The service accounts' and the forwarded traffic's share of the owner's
//! guard, as WFP filters.
//!
//! The same emitters as the owner's pins, re-scoped: only the ALE filters carry
//! a user condition, so only they are twinned — the transport-layer halves are
//! machine-wide and already the owner's.

use nrr_platform_api::types::{MAX_REMOTE_SUBNETS, SERVICE_ACCOUNTS_PRINCIPAL};
use nrr_shared::ip_block::IpBlock;

use crate::enforcement_planner::{ServiceAccountGuard, ServiceAccountPosture};
use crate::wfp_bands::{BASE_PRIMARY, NETWORK_HOLD_MAX};

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
/// every pin. `foreign` are the networks of somebody else's tunnels: a service
/// reaches its corporate network through that tunnel, as the owner does.
#[must_use]
pub fn service_account_filters(
    owner: &str,
    guard: &ServiceAccountGuard,
    secondary_luid: u64,
    protocols: KillSwitchProtocols,
    exempt_apps: &[String],
    foreign: &[ForeignTunnelNetwork],
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
    let permits = foreign_tunnel_permits(&seed, &out, foreign, secondary_luid);
    out.extend(permits);
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
    foreign: &[ForeignTunnelNetwork],
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
    let mut out = out;
    let permits = foreign_tunnel_permits(&seed, &out, foreign, secondary_luid);
    out.extend(permits);
    WfpFilterSpec::onto_forwarding_path(out)
}

/// The owner's blanket block, for what the machine forwards: the owner's
/// traffic is held whole, so a guest's is too, save what the blanket's own
/// floor keeps open plus the main link's resolvers and the networks its rules
/// route. `main_networks` are the pieces the owner's rule filters carry,
/// already carved around every narrower claim.
///
/// With the tunnel up (`exemptions.secondary_luid` set) what leaves through it
/// is let out as well, keyed on the interface the packet is forwarded out of:
/// the instant the tunnel goes, the same blanket holds the guest's traffic,
/// before any pass. The floor is the same in both states.
#[must_use]
pub fn forwarded_block_all_filters(
    owner: &str,
    exemptions: &FailClosedExemptions,
    primary_dns: &[IpAddr],
    main_networks: &[IpBlock],
) -> Vec<WfpFilterSpec> {
    let mut exemptions = exemptions.clone();
    // A guest names its resolvers by address, and no port condition exists on
    // the forwarding path to keep the permit to port 53.
    exemptions.allow_dns_over_primary = false;
    // Packed rather than one filter per host: every forwarded packet is judged
    // against this set, and the per-host form would double the standing count
    // the owner's own blanket carries.
    let open: Vec<Ipv4Addr> = std::mem::take(&mut exemptions.primary_dest_ips)
        .into_iter()
        .chain(primary_dns.iter().filter_map(|ip| match ip {
            IpAddr::V4(v4) => Some(*v4),
            IpAddr::V6(_) => None,
        }))
        .filter(|ip| !is_exempt_from_blocking(*ip))
        .take(KILLSWITCH_MAX_DESTINATIONS)
        .collect();
    let seed = forwarded_seed(owner);
    let mut out = fail_closed_block_all_filters(&seed, &exemptions, KillSwitchProtocols::ALL);
    // The IPv6 half already carries its own when the LUID is known.
    if exemptions.secondary_luid != 0 {
        out.push(exempt_egress(
            &seed,
            exemptions.secondary_luid,
            CATCHALL_EXEMPT_BASE,
        ));
    }
    // Over the floor alone, so the permits stacked above it keep their weights
    // whether the tunnel is up or gone.
    let above = out
        .iter()
        .filter(|spec| {
            spec.action == WfpAction::Permit
                && spec.layer.supports_ale_scoping()
                && spec.local_interface_luid.is_none()
        })
        .map(|spec| spec.weight)
        .fold(CATCHALL_EXEMPT_BASE, u64::max);
    let chunks = nrr_platform_api::wfp_slotting::pack_v4(open);
    let guests = guest_network_permits(&seed, &out, &exemptions, above + 1 + chunks.len() as u64);
    for (idx, chunk) in chunks.into_iter().enumerate() {
        out.push(WfpFilterSpec {
            layer: WfpLayerKey::AleAuthConnectV4,
            action: WfpAction::Permit,
            remote_ip: None,
            id: filter_id_for(&seed, KILLSWITCH_ROLE, "", "ks-fwd-open", &chunk.id_seg()),
            remote_ip_set: chunk.members,
            remote_ip_set_v6: Vec::new(),
            remote_port: None,
            weight: above + 1 + idx as u64,
            user_sid: None,
            app_pattern: None,
            local_interface_luid: None,
            remote_subnet: None,
            remote_subnet_v6: None,
            ip_protocol: None,
            remote_subnet_set: Vec::new(),
        });
    }
    out.extend(guests);
    out.extend(main_network_permits(&seed, main_networks));
    let permits = foreign_tunnel_permits(
        &seed,
        &out,
        &exemptions.foreign_tunnel_networks,
        exemptions.secondary_luid,
    );
    out.extend(permits);
    WfpFilterSpec::onto_forwarding_path(out)
}

/// Most guest networks the forwarded blanket opens, one permit each per family.
pub const GUEST_NETWORK_MAX: usize = 16;

/// One permit per guest network and per family the blanket blocks, for what is
/// forwarded out into that network: the replies a guest waits for. Keyed on the
/// interface the packet leaves by, and laid only on the forwarding layers,
/// which never see what the machine itself sends, so it cannot become a way
/// out for the computer's own traffic. The tunnel and a foreign tunnel are
/// never a guest network, whatever the caller passed: a permit through one
/// would carry guests past the narrowing their own permits keep.
fn guest_network_permits(
    seed: &str,
    blanket: &[WfpFilterSpec],
    exemptions: &FailClosedExemptions,
    weight: u64,
) -> Vec<WfpFilterSpec> {
    let mut luids: Vec<u64> = exemptions
        .guest_network_luids
        .iter()
        .copied()
        .filter(|luid| {
            *luid != 0
                && *luid != exemptions.secondary_luid
                && !exemptions.foreign_tunnel_luids.contains(luid)
        })
        .collect();
    luids.sort_unstable();
    luids.dedup();
    luids.truncate(GUEST_NETWORK_MAX);
    let mut out = Vec::new();
    for (layer, kind) in [
        (WfpLayerKey::AleAuthConnectV4, "ks-fwd-guest"),
        (WfpLayerKey::AleAuthConnectV6, "ks-fwd-guest-v6"),
    ] {
        let blocked = blanket
            .iter()
            .any(|spec| spec.layer == layer && spec.action == WfpAction::Block);
        if !blocked {
            continue;
        }
        for (idx, luid) in luids.iter().enumerate() {
            out.push(WfpFilterSpec {
                layer,
                action: WfpAction::Permit,
                remote_ip: None,
                remote_ip_set: Vec::new(),
                remote_ip_set_v6: Vec::new(),
                remote_port: None,
                weight: weight + idx as u64,
                id: filter_id_for(seed, KILLSWITCH_ROLE, "", kind, &permit_luid_seg(*luid)),
                user_sid: None,
                app_pattern: None,
                local_interface_luid: Some(*luid),
                remote_subnet: None,
                remote_subnet_v6: None,
                ip_protocol: None,
                remote_subnet_set: Vec::new(),
            });
        }
    }
    out
}

/// The main link's route networks as packed permits in the primary rule band:
/// above the blanket, as the owner's own rule filters are, and below every
/// fail-closed block, so a tunnel-bound address inside one stays held.
fn main_network_permits(seed: &str, networks: &[IpBlock]) -> Vec<WfpFilterSpec> {
    let mut out = Vec::new();
    for (layer, kind, v4) in [
        (WfpLayerKey::AleAuthConnectV4, "ks-fwd-net", true),
        (WfpLayerKey::AleAuthConnectV6, "ks-fwd-net-v6", false),
    ] {
        let mut family: Vec<(IpAddr, u8)> = networks
            .iter()
            .filter(|net| net.is_ipv4() == v4)
            .map(|net| (net.network(), net.prefix_len()))
            .collect();
        family.sort_unstable();
        family.dedup();
        family.truncate(NETWORK_HOLD_MAX);
        for (idx, chunk) in family.chunks(MAX_REMOTE_SUBNETS).enumerate() {
            let seg = chunk
                .iter()
                .map(|(net, prefix)| format!("{net}/{prefix}"))
                .collect::<Vec<_>>()
                .join(",");
            // One network keeps the single-subnet spelling; several are a set.
            let (remote_subnet, remote_subnet_v6, remote_subnet_set) = match chunk {
                [(IpAddr::V4(net), prefix)] => (Some((*net, *prefix)), None, Vec::new()),
                [(IpAddr::V6(net), prefix)] => (None, Some((*net, *prefix)), Vec::new()),
                _ => (None, None, chunk.to_vec()),
            };
            out.push(WfpFilterSpec {
                layer,
                action: WfpAction::Permit,
                remote_ip: None,
                remote_ip_set: Vec::new(),
                remote_ip_set_v6: Vec::new(),
                remote_port: None,
                weight: BASE_PRIMARY + idx as u64,
                id: filter_id_for(seed, KILLSWITCH_ROLE, "", kind, &seg),
                user_sid: None,
                app_pattern: None,
                local_interface_luid: None,
                remote_subnet,
                remote_subnet_v6,
                ip_protocol: None,
                remote_subnet_set,
            });
        }
    }
    out
}
