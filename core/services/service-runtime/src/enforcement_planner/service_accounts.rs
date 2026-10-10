//! What the machine's service accounts get from the route-table owner's leak
//! guard.
//!
//! System traffic belongs to no user, so a per-user guard never covered it: a
//! service reached a secondary-rule destination over the main link while the
//! tunnel was down, or by binding to the main adapter while it was up. It now
//! gets the owner's address pins, and only those — never a blanket block, which
//! would hand every service on the machine to one user's tunnel.

use std::net::IpAddr;
use std::sync::Mutex;

use nrr_shared::ip_block::IpBlock;

use super::*;

/// What the owner's guard does this pass, and so what the service accounts get.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceAccountPosture {
    /// The additional link resolves: permitted through it, blocked elsewhere.
    Pin,
    /// It does not, and the owner's guard blocks: blocked outright.
    Block,
}

/// The owner's guard, read as plain facts.
#[derive(Clone, Copy, Debug)]
pub struct ServiceAccountInput<'a> {
    /// Only the route-table owner's pass speaks for the service accounts.
    pub is_route_table_owner: bool,
    /// `None` while the owner's guard is off or fails open.
    pub posture: Option<ServiceAccountPosture>,
    /// The owner's pinned (or blocked) addresses.
    pub destinations: &'a [IpAddr],
    /// The owner's held networks; their cut-outs already spare the tunnel
    /// servers and the attached subnets.
    pub holds: &'a NetworkHolds,
    /// Tunnel servers, live and learned: the tunnel's own transport.
    pub tunnel_servers: &'a [IpAddr],
    /// The main link's attached subnets.
    pub local_subnets: &'a [IpBlock],
    /// DNS servers configured on the main link.
    pub primary_dns: &'a [IpAddr],
}

/// The service accounts' share of the guard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceAccountGuard {
    pub posture: ServiceAccountPosture,
    pub destinations: Vec<IpAddr>,
    pub holds: NetworkHolds,
    /// Main-link DNS servers a secondary rule names, left open: cutting them
    /// would take name resolution from every service on the machine.
    pub dns_spared: Vec<IpAddr>,
}

/// The guard the service accounts get, or `None` when they get nothing.
#[must_use]
pub fn service_account_guard(input: &ServiceAccountInput<'_>) -> Option<ServiceAccountGuard> {
    if !input.is_route_table_owner {
        return None;
    }
    let posture = input.posture?;
    let local = |ip: IpAddr| input.local_subnets.iter().any(|net| net.contains(ip));
    let mut dns_spared = Vec::new();
    let mut destinations = Vec::with_capacity(input.destinations.len());
    for ip in input.destinations.iter().copied() {
        if input.tunnel_servers.contains(&ip) || local(ip) {
            continue;
        }
        if input.primary_dns.contains(&ip) {
            dns_spared.push(ip);
            continue;
        }
        destinations.push(ip);
    }
    let holds = with_dns_cut_outs(input.holds, input.primary_dns, &mut dns_spared);
    dns_spared.sort_unstable();
    dns_spared.dedup();
    Some(ServiceAccountGuard {
        posture,
        destinations,
        holds,
        dns_spared,
    })
}

/// `holds` with a cut-out for each DNS server inside a held network. Past the
/// cut-out cap the server stays held: the cap is what keeps the set bounded.
fn with_dns_cut_outs(
    holds: &NetworkHolds,
    dns: &[IpAddr],
    spared: &mut Vec<IpAddr>,
) -> NetworkHolds {
    let mut out = holds.clone();
    for ip in dns.iter().copied() {
        let Some(host) = IpBlock::new(ip, if ip.is_ipv4() { 32 } else { 128 }) else {
            continue;
        };
        let held = out.held.iter().any(|net| net.covers(host));
        let open = out.cut_outs.iter().any(|cut| cut.covers(host));
        if !held || open || out.cut_outs.len() >= NETWORK_CUT_OUT_MAX {
            continue;
        }
        out.cut_outs.push(host);
        spared.push(ip);
    }
    out.cut_outs.sort_unstable();
    out
}

/// The guard as neutral flows, every one scoped to the service accounts.
///
/// Built from the owner's own planners so both scopes pin and block alike, then
/// narrowed to the connect decision: the packet-layer twins carry no user
/// condition on Windows and are already the owner's, and Linux judges every
/// packet in one hook anyway. `exempt_apps` are the tunnel clients that must
/// reach their servers whatever account runs them.
#[must_use]
pub fn plan_service_account_flows(
    owner: &str,
    guard: &ServiceAccountGuard,
    protocols: KillSwitchProtocols,
    exempt_apps: &[String],
) -> Vec<FlowRule> {
    let mut flows = match guard.posture {
        ServiceAccountPosture::Pin => {
            let mut flows = plan_kill_switch_destinations(owner, &guard.destinations, protocols);
            flows.extend(plan_kill_switch_networks(owner, &guard.holds, protocols));
            flows
        }
        ServiceAccountPosture::Block => {
            let mut flows = plan_fail_closed_destinations(owner, &guard.destinations, protocols);
            flows.extend(plan_fail_closed_networks(owner, &guard.holds, protocols));
            flows
        }
    };
    flows.extend(plan_primary_app_exempt(owner, exempt_apps));
    flows.retain(|flow| flow.coverage == Coverage::ConnectOnly);
    for flow in &mut flows {
        flow.principal = PrincipalScope::ServiceAccounts;
    }
    flows
}

/// Announces the spared DNS servers once per change, not once per pass.
#[derive(Default)]
pub struct ServiceAccountDnsLog {
    last: Mutex<Vec<IpAddr>>,
}

impl ServiceAccountDnsLog {
    pub fn note(&self, spared: &[IpAddr]) {
        let mut last = self.last.lock().unwrap_or_else(|p| p.into_inner());
        if last.as_slice() == spared {
            return;
        }
        *last = spared.to_vec();
        if spared.is_empty() {
            return;
        }
        let servers = spared
            .iter()
            .map(IpAddr::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        tracing::info!(
            target: "nrr::enforcement",
            msg_key = "persid-plan-service-dns-spared",
            count = spared.len(),
            servers = %servers,
            "additional-link rules name DNS servers of the main link; system services keep reaching them over the main link, since cutting them would break name resolution for the whole machine. Mode B moves name resolution to the service",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::enforcement::{EgressConstraint, Verdict};
    use std::net::Ipv4Addr;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn block(text: &str) -> IpBlock {
        IpBlock::parse(text).expect("block")
    }

    fn input<'a>(
        posture: Option<ServiceAccountPosture>,
        destinations: &'a [IpAddr],
        holds: &'a NetworkHolds,
    ) -> ServiceAccountInput<'a> {
        ServiceAccountInput {
            is_route_table_owner: true,
            posture,
            destinations,
            holds,
            tunnel_servers: &[],
            local_subnets: &[],
            primary_dns: &[],
        }
    }

    #[test]
    fn nothing_while_the_owners_guard_is_off_or_fails_open() {
        let holds = NetworkHolds::default();
        let dests = [v4(198, 51, 100, 1)];
        assert_eq!(service_account_guard(&input(None, &dests, &holds)), None);
    }

    #[test]
    fn only_the_route_table_owner_speaks_for_the_service_accounts() {
        let holds = NetworkHolds::default();
        let dests = [v4(198, 51, 100, 1)];
        let mut other = input(Some(ServiceAccountPosture::Pin), &dests, &holds);
        other.is_route_table_owner = false;
        assert_eq!(service_account_guard(&other), None);
        let owner = input(Some(ServiceAccountPosture::Pin), &dests, &holds);
        assert_eq!(
            service_account_guard(&owner).map(|g| g.destinations),
            Some(dests.to_vec())
        );
    }

    #[test]
    fn tunnel_servers_attached_subnets_and_main_link_dns_are_subtracted() {
        let holds = NetworkHolds::default();
        let server = v4(203, 0, 113, 9);
        let lan_host = v4(192, 0, 2, 20);
        let dns = v4(198, 51, 100, 53);
        let kept = v4(198, 51, 100, 1);
        let dests = [server, lan_host, dns, kept];
        let local = [block("192.0.2.0/24")];
        let mut facts = input(Some(ServiceAccountPosture::Block), &dests, &holds);
        facts.tunnel_servers = std::slice::from_ref(&server);
        facts.local_subnets = &local;
        let dns_list = [dns];
        facts.primary_dns = &dns_list;
        let guard = service_account_guard(&facts).expect("owner with a guard");
        assert_eq!(guard.destinations, vec![kept]);
        assert_eq!(guard.dns_spared, vec![dns]);
    }

    #[test]
    fn a_main_link_dns_server_inside_a_held_network_gets_a_cut_out() {
        let holds = NetworkHolds {
            held: vec![block("198.51.100.0/24")],
            ..NetworkHolds::default()
        };
        let dns = v4(198, 51, 100, 53);
        let mut facts = input(Some(ServiceAccountPosture::Pin), &[], &holds);
        let dns_list = [dns];
        facts.primary_dns = &dns_list;
        let guard = service_account_guard(&facts).expect("owner with a guard");
        assert_eq!(guard.holds.cut_outs, vec![block("198.51.100.53/32")]);
        assert_eq!(guard.dns_spared, vec![dns]);
    }

    #[test]
    fn the_flows_are_service_scoped_connect_only_and_never_block_everything() {
        let holds = NetworkHolds {
            held: vec![block("198.51.100.0/24")],
            ..NetworkHolds::default()
        };
        let dests = [v4(203, 0, 113, 5)];
        for posture in [ServiceAccountPosture::Pin, ServiceAccountPosture::Block] {
            let guard = service_account_guard(&input(Some(posture), &dests, &holds))
                .expect("owner with a guard");
            let flows = plan_service_account_flows(
                "S-1-5-21-1-2-3-1001",
                &guard,
                KillSwitchProtocols::ALL,
                &[r"C:\Program Files\ExampleVpn\client.exe".to_string()],
            );
            assert!(!flows.is_empty());
            for flow in &flows {
                assert_eq!(flow.principal, PrincipalScope::ServiceAccounts);
                assert_eq!(flow.coverage, Coverage::ConnectOnly);
                let blanket = matches!(
                    flow.flow.dst,
                    DstMatch::Any
                        | DstMatch::SubnetV4 { prefix: 0, .. }
                        | DstMatch::SubnetV6 { prefix: 0, .. }
                );
                assert!(
                    !(blanket && flow.verdict == Verdict::Block),
                    "a blanket block for the service accounts: {flow:?}"
                );
                assert!(
                    !(blanket && flow.app == AppScope::Any),
                    "a blanket flow names no destination and no program: {flow:?}"
                );
            }
            let pinned = flows
                .iter()
                .any(|f| matches!(f.egress, EgressConstraint::OnlyVia(_)));
            assert_eq!(pinned, posture == ServiceAccountPosture::Pin);
        }
    }

    /// The tunnel-default modes give the owner a blanket block; the service
    /// accounts still get nothing but the addresses.
    #[test]
    fn the_tunnel_default_modes_still_give_the_service_accounts_addresses_only() {
        let holds = NetworkHolds::default();
        let dests = [v4(203, 0, 113, 5), v4(203, 0, 113, 6)];
        let facts = input(Some(ServiceAccountPosture::Block), &dests, &holds);
        let guard = service_account_guard(&facts).expect("owner with a guard");
        let flows = plan_service_account_flows(
            "S-1-5-21-1-2-3-1001",
            &guard,
            KillSwitchProtocols::ALL,
            &[],
        );
        assert!(flows
            .iter()
            .all(|f| matches!(f.flow.dst, DstMatch::HostV4(_))));
    }

    /// The live Windows emitter and the neutral flows lowered by
    /// `lower_windows` install the same filters in the same order, so the
    /// shadow path stays a faithful copy of what enforces.
    #[cfg(windows)]
    #[test]
    fn the_neutral_flows_lower_to_the_live_filters() {
        use crate::killswitch_codegen::service_account_filters;
        use nrr_platform_api::enforcement::EnforcementPlan;
        use nrr_platform_api::wfp_behavioral::{
            arbitration_order_preserved, behaviorally_equivalent,
        };
        use nrr_platform_windows::lower_windows::{lower_catch_all_kill_switch, lower_kill_switch};

        let owner = "S-1-5-21-1-2-3-1001";
        let luid = 0x0001_0000_0000_0007_u64;
        let apps = vec![r"C:\Program Files\ExampleVpn\client.exe".to_string()];
        let holds = NetworkHolds::default();
        let dests = [v4(203, 0, 113, 5), v4(198, 51, 100, 8)];
        for posture in [ServiceAccountPosture::Pin, ServiceAccountPosture::Block] {
            let guard = service_account_guard(&input(Some(posture), &dests, &holds))
                .expect("owner with a guard");
            let live =
                service_account_filters(owner, &guard, luid, KillSwitchProtocols::ALL, &apps);
            let plan = EnforcementPlan {
                principal: UserPrincipal::from_windows_sid(owner).expect("valid sid"),
                flows: plan_service_account_flows(owner, &guard, KillSwitchProtocols::ALL, &apps),
                routes: Vec::new(),
                policy_rules: Vec::new(),
            };
            let mut lowered = lower_kill_switch(&plan, luid);
            lowered.extend(lower_catch_all_kill_switch(&plan, luid));
            assert!(!live.is_empty());
            assert!(
                behaviorally_equivalent(&live, &lowered),
                "{posture:?}: {live:?} vs {lowered:?}"
            );
            assert!(arbitration_order_preserved(&live, &lowered), "{posture:?}");
        }
    }
}
