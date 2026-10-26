//! Fail-closed planning and the per-application half of the kill-switch.
//!
//! Fail-closed is what the plan falls back to when the additional link cannot
//! be resolved: it blocks rather than leaks, and everything here exists to keep
//! the machine reachable while it does.

use super::*;

// ── Fail-closed + per-app kill-switch + primary-app exemption ──────────────────

/// A named-app scope carrying `pattern` as its `ALE_APP_ID` — the kill-switch app
/// filters put the pattern straight into `app_pattern` (no exe-path resolution),
/// so `exe_paths` holds the single pattern the Windows lowering reads.
fn app_scope(pattern: &str) -> AppScope {
    AppScope::Program {
        key: pattern.to_string(),
        exe_paths: vec![PathBuf::from(pattern)],
    }
}

/// Whether `ip` sits on a segment the main link is attached to. A rule host
/// there keeps its direct route (`NetworkRouteFacts::keeps_host_direct`), so
/// the leak-guard neither pins nor blocks it: the floor already opens the
/// segment, and a pin would only cut a device one hop away. Both engines ask.
#[must_use]
pub fn on_attached_segment(ip: IpAddr, v4: &[(Ipv4Addr, u8)], v6: &[(Ipv6Addr, u8)]) -> bool {
    let within = |net: IpAddr, len: u8| {
        nrr_shared::ip_block::IpBlock::new(net, len).is_some_and(|b| b.contains(ip))
    };
    match ip {
        IpAddr::V4(_) => v4.iter().any(|(net, len)| within(IpAddr::V4(*net), *len)),
        IpAddr::V6(_) => v6.iter().any(|(net, len)| within(IpAddr::V6(*net), *len)),
    }
}

/// Addresses a name under a rule never pulls into the tunnel, on either OS.
///
/// The tunnel's own servers: a pin or a route there seals its reconnect. The
/// main link's resolvers: pinned, the machine's DNS dies the moment the tunnel
/// drops — unless a rule names the address itself, which is the user's call.
/// An answer from somebody else's server under a zone rule could name either.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LinkInfrastructure {
    pub tunnel_servers: Vec<IpAddr>,
    pub link_resolvers: Vec<IpAddr>,
}

impl LinkInfrastructure {
    /// Whether the leak-guard leaves `ip` alone; `named_literally`: an enabled
    /// rule of the additional route names the address itself.
    #[must_use]
    pub fn spares(&self, ip: IpAddr, named_literally: bool) -> bool {
        self.tunnel_servers.contains(&ip) || (!named_literally && self.link_resolvers.contains(&ip))
    }
}

/// Whether an enabled rule of `rules` names `ip` as a literal address.
#[must_use]
pub fn names_address_literally(
    rules: &nrr_domain::canonical::CanonicalRuleSet,
    ip: IpAddr,
) -> bool {
    rules.rules().iter().any(|rule| {
        rule.enabled
            && matches!(
                rule.address_match,
                Some(nrr_domain::canonical::CanonicalAddressMatch::ExactIp(named)) if named == ip
            )
    })
}

/// The single ALE `ip_protocol` narrowing for a mask (neutral), mirroring
/// `KillSwitchProtocols::ale_protocol`: `None` when both or neither TCP/UDP are
/// selected (one proto-agnostic block covers both), else the one selected.
fn ale_protocol(p: KillSwitchProtocols) -> Option<L4Proto> {
    match (p.tcp, p.udp) {
        (true, true) | (false, false) => None,
        (true, false) => Some(L4Proto::Tcp),
        (false, true) => Some(L4Proto::Udp),
    }
}

/// Build one kill-switch / fail-closed [`FlowRule`].
#[allow(clippy::too_many_arguments)]
fn ks_flow(
    principal: &PrincipalScope,
    verdict: Verdict,
    class: PrecedenceClass,
    dst: DstMatch,
    app: AppScope,
    egress: EgressConstraint,
    protocol: Option<L4Proto>,
    coverage: Coverage,
    ordinal: u32,
) -> FlowRule {
    FlowRule {
        verdict,
        precedence: Precedence { class, ordinal },
        flow: FlowMatch {
            dst,
            dst_port: None,
            protocol,
        },
        principal: principal.clone(),
        app,
        egress,
        coverage,
        observed_by_program: false,
    }
}

/// Plan the **per-app kill-switch** — the leak-proof
/// `OnlyVia(Secondary)` pin over each protected app, keyed on `ALE_APP_ID` instead
/// of a remote IP. Neutral equivalent of `killswitch_codegen::app_kill_switch_filters`.
///
/// ALE-connect only (the packet layer has no app context) and protocol-agnostic,
/// so it emits nothing unless a TCP/UDP protocol is selected — like the codegen.
/// One [`PrecedenceClass::KillSwitchPermit`] flow per app; `lower_kill_switch`
/// expands each into the ALE permit(luid)+block pair. Zero-LUID fail-open is a
/// lowering concern.
///
/// Main-named addresses need no rescue flows: the lowered per-app block sits
/// below the primary rule band, so the primary rules' own permits carry every
/// address the main link names — uncapped, unlike the per-(app, address) rescue
/// permits that ordering replaced.
pub fn plan_app_kill_switch(
    sid: &str,
    app_patterns: &[String],
    protocols: KillSwitchProtocols,
) -> Vec<FlowRule> {
    plan_app_kill_switch_for(sid, app_patterns, protocols, false)
}

/// [`plan_app_kill_switch`] under the principal's
/// `app_rules_take_all_addresses`: with it on, the pin's block outranks the
/// main-link rule permits ([`PrecedenceClass::AppTakeover`]).
pub fn plan_app_kill_switch_for(
    sid: &str,
    app_patterns: &[String],
    protocols: KillSwitchProtocols,
    app_takeover: bool,
) -> Vec<FlowRule> {
    if !(protocols.tcp || protocols.udp) {
        return Vec::new();
    }
    let principal = principal_scope(sid);
    let mut flows = Vec::new();
    for (idx, pattern) in app_patterns
        .iter()
        .take(APP_KILLSWITCH_MAX_APPS)
        .enumerate()
    {
        for dst in BOTH_FAMILIES {
            flows.push(ks_flow(
                &principal,
                Verdict::Permit,
                app_class(idx, app_takeover, PrecedenceClass::KillSwitchPermit),
                dst,
                app_scope(pattern),
                EgressConstraint::OnlyVia(EgressRef::Secondary),
                None,
                Coverage::ConnectOnly,
                idx as u32,
            ));
        }
    }
    flows
}

/// The class of the `idx`-th app's pin or block: raised over the main-link
/// rules under the takeover setting while it fits that band, as
/// `killswitch_codegen::app_block_band` decides for the live filters.
fn app_class(idx: usize, app_takeover: bool, otherwise: PrecedenceClass) -> PrecedenceClass {
    if app_takeover && idx < crate::wfp_bands::APP_TAKEOVER_MAX_APPS {
        PrecedenceClass::AppTakeover
    } else {
        otherwise
    }
}

/// Every destination of either family: `Any` lowers to the v4 layer, the
/// v6 family catch-all `::/0` to the v6 one.
const BOTH_FAMILIES: [DstMatch; 2] = [
    DstMatch::Any,
    DstMatch::SubnetV6 {
        net: Ipv6Addr::UNSPECIFIED,
        prefix: 0,
    },
];

/// Plan the **primary-app kill-switch exemption** — one
/// unconditional ALE `Permit` per app pattern in the top exempt band, so a user's
/// deliberately primary-routed app (e.g. a VPN client bootstrapping over the
/// primary link) is never cut. Neutral equivalent of
/// `killswitch_codegen::primary_app_exempt_filters`.
///
/// A [`PrecedenceClass::CatchAllExempt`] flow with an [`AppScope::Program`] and no
/// egress condition; `lower_catch_all_kill_switch` maps it to the `APP_EXEMPT_BASE`
/// band. There is no block half — this is a pure exemption.
pub fn plan_primary_app_exempt(sid: &str, app_patterns: &[String]) -> Vec<FlowRule> {
    let principal = principal_scope(sid);
    // Both families, as `killswitch_codegen::primary_app_exempt_filters`: the
    // whole-v6 match is the family catch-all `::/0`.
    let families = [
        DstMatch::Any,
        DstMatch::SubnetV6 {
            net: Ipv6Addr::UNSPECIFIED,
            prefix: 0,
        },
    ];
    app_patterns
        .iter()
        .take(KILLSWITCH_MAX_DESTINATIONS)
        .enumerate()
        .flat_map(|(idx, pattern)| {
            let principal = &principal;
            families.into_iter().map(move |dst| {
                ks_flow(
                    principal,
                    Verdict::Permit,
                    PrecedenceClass::CatchAllExempt,
                    dst,
                    app_scope(pattern),
                    EgressConstraint::Any,
                    None,
                    Coverage::ConnectOnly,
                    idx as u32,
                )
            })
        })
        .collect()
}

/// Plan the **fail-closed per-destination block** — the secondary
/// is unresolvable, so block each protected IP outright (no egress permit). Neutral
/// equivalent of `killswitch_codegen::fail_closed_block_destinations`.
///
/// Per non-exempt, capped IP at index `idx`: an ALE block narrowed to the ALE
/// protocol ([`PrecedenceClass::KillSwitchBlock`], if TCP/UDP selected) plus the
/// packet-layer blocks (reproducing `packet_protocol_blocks`): with "Other", a
/// proto-agnostic block-all plus a lone permit per UN-selected protocol; else one
/// block per selected named protocol. Empty when no protocol is selected.
pub fn plan_fail_closed_destinations(
    sid: &str,
    protected_ips: &[IpAddr],
    protocols: KillSwitchProtocols,
) -> Vec<FlowRule> {
    let any_selected = protocols.tcp
        || protocols.udp
        || protocols.icmp
        || protocols.igmp
        || protocols.gre
        || protocols.esp
        || protocols.other;
    if !any_selected {
        return Vec::new();
    }
    let principal = principal_scope(sid);
    let ale_proto = ale_protocol(protocols);
    let mut flows = Vec::new();
    for (idx, ip) in protected_ips
        .iter()
        .copied()
        .filter(|ip| !nrr_platform_api::is_exempt_from_blocking(*ip))
        .take(KILLSWITCH_MAX_DESTINATIONS)
        .enumerate()
    {
        let idx = idx as u32;
        // ALE block (narrowed to the ALE protocol), if TCP/UDP selected.
        if protocols.tcp || protocols.udp {
            flows.push(ks_flow(
                &principal,
                Verdict::Block,
                PrecedenceClass::KillSwitchBlock,
                host_match(ip),
                AppScope::Any,
                EgressConstraint::Any,
                ale_proto,
                Coverage::ConnectOnly,
                idx,
            ));
        }
        // Packet-layer blocks (the `idx * 16` window) — one block per selected
        // NAMED protocol; the "Other" block-all is GONE. IPv4 only, for the
        // reason `plan_kill_switch_destinations` states.
        if ip.is_ipv6() {
            continue;
        }
        let base = idx * PACKET_SLOTS_PER_DEST;
        for (k, proto) in selected_packet_protocols(protocols).into_iter().enumerate() {
            flows.push(ks_flow(
                &principal,
                Verdict::Block,
                PrecedenceClass::KillSwitchBlock,
                host_match(ip),
                AppScope::Any,
                EgressConstraint::Any,
                Some(proto),
                Coverage::AllPackets,
                base + k as u32,
            ));
        }
    }
    flows
}

/// Plan the fail-closed block over the held networks: each blocked outright,
/// narrowed like [`plan_fail_closed_destinations`], with the cut-outs inside
/// them left open. Empty when no protocol is selected.
pub fn plan_fail_closed_networks(
    sid: &str,
    holds: &NetworkHolds,
    protocols: KillSwitchProtocols,
) -> Vec<FlowRule> {
    let any_selected = protocols.tcp
        || protocols.udp
        || protocols.icmp
        || protocols.igmp
        || protocols.gre
        || protocols.esp
        || protocols.other;
    if !any_selected {
        return Vec::new();
    }
    let principal = principal_scope(sid);
    let mut flows = Vec::new();
    for (i, net) in holds.held.iter().copied().enumerate() {
        let ordinal = NETWORK_ORDINAL_BASE + i as u32;
        let block = |protocol, coverage, ordinal| {
            ks_flow(
                &principal,
                Verdict::Block,
                PrecedenceClass::KillSwitchBlock,
                block_match(net),
                AppScope::Any,
                EgressConstraint::Any,
                protocol,
                coverage,
                ordinal,
            )
        };
        if protocols.tcp || protocols.udp {
            flows.push(block(
                ale_protocol(protocols),
                Coverage::ConnectOnly,
                ordinal,
            ));
        }
        if !net.is_ipv4() {
            continue;
        }
        let base = ordinal * PACKET_SLOTS_PER_DEST;
        for (k, proto) in selected_packet_protocols(protocols).into_iter().enumerate() {
            flows.push(block(Some(proto), Coverage::AllPackets, base + k as u32));
        }
    }
    flows.extend(plan_network_cut_outs(&principal, holds, protocols));
    flows
}

/// Plan the **fail-closed per-app block** — block each protected
/// app at the ALE layer (proto-agnostic, no egress permit). Neutral equivalent of
/// `killswitch_codegen::fail_closed_block_apps`. Emits nothing unless TCP/UDP is
/// selected (ALE only).
pub fn plan_fail_closed_apps(
    sid: &str,
    app_patterns: &[String],
    protocols: KillSwitchProtocols,
) -> Vec<FlowRule> {
    plan_fail_closed_apps_for(sid, app_patterns, protocols, false)
}

/// [`plan_fail_closed_apps`] under the principal's
/// `app_rules_take_all_addresses`, as [`plan_app_kill_switch_for`].
pub fn plan_fail_closed_apps_for(
    sid: &str,
    app_patterns: &[String],
    protocols: KillSwitchProtocols,
    app_takeover: bool,
) -> Vec<FlowRule> {
    if !(protocols.tcp || protocols.udp) {
        return Vec::new();
    }
    let principal = principal_scope(sid);
    app_patterns
        .iter()
        .take(APP_KILLSWITCH_MAX_APPS)
        .enumerate()
        .flat_map(|(idx, pattern)| {
            let principal = &principal;
            let class = app_class(idx, app_takeover, PrecedenceClass::KillSwitchBlock);
            BOTH_FAMILIES.into_iter().map(move |dst| {
                ks_flow(
                    principal,
                    Verdict::Block,
                    class,
                    dst,
                    app_scope(pattern),
                    EgressConstraint::Any,
                    None,
                    Coverage::ConnectOnly,
                    idx as u32,
                )
            })
        })
        .collect()
}

/// Plan the DoH/DoT lockdown blocks as neutral
/// [`FlowRule`]s — the neutral equivalent of
/// [`crate::killswitch_codegen::doh_dot_block_filters`]. Per resolver address of
/// either family: a [`PrecedenceClass::DohBlock`] `Block` on `443` for TCP then
/// UDP; then, when `block_dot`, a global `Block` on `853` for TCP then UDP.
/// The global cut is family-agnostic here: a backend whose filters are
/// per-family (WFP) lowers it once per family. IPv4 addresses come first, so a
/// v4-only list keeps the ordinals it had before the v6 half existed.
pub fn plan_doh_dot_block(sid: &str, resolver_ips: &[IpAddr], block_dot: bool) -> Vec<FlowRule> {
    let principal = principal_scope(sid);
    let mut flows = Vec::new();
    let mut ordinal = 0u32;
    let flow_for = |dst: DstMatch, port: u16, ordinal: u32| FlowRule {
        verdict: Verdict::Block,
        precedence: Precedence {
            class: PrecedenceClass::DohBlock,
            ordinal,
        },
        flow: FlowMatch {
            dst,
            dst_port: Some(port),
            protocol: None, // set per proto below
        },
        principal: principal.clone(),
        app: AppScope::Any,
        egress: EgressConstraint::Any,
        coverage: Coverage::ConnectOnly,
        observed_by_program: false,
    };
    let (v4, v6): (Vec<IpAddr>, Vec<IpAddr>) = resolver_ips
        .iter()
        .copied()
        .filter(|ip| !nrr_platform_api::is_exempt_from_blocking(*ip))
        .take(crate::killswitch_codegen::DOH_MAX_RESOLVER_IPS)
        .partition(IpAddr::is_ipv4);
    for ip in v4.into_iter().chain(v6) {
        for proto in [L4Proto::Tcp, L4Proto::Udp] {
            let mut f = flow_for(host_match(ip), 443, ordinal);
            f.flow.protocol = Some(proto);
            flows.push(f);
            ordinal += 1;
        }
    }
    if block_dot {
        for proto in [L4Proto::Tcp, L4Proto::Udp] {
            let mut f = flow_for(DstMatch::Any, 853, ordinal);
            f.flow.protocol = Some(proto);
            flows.push(f);
            ordinal += 1;
        }
    }
    flows
}

/// Plan the **fail-closed Mode-B block-all** — the secondary is
/// gone, so block ALL egress for this user except the safe exemptions. Neutral
/// equivalent of `killswitch_codegen::fail_closed_block_all_filters`.
///
/// Unlike [`plan_catch_all_kill_switch`] it arms WITHOUT a resolvable secondary
/// (there is none — so no egress-via-secondary permit) and WITHOUT requiring
/// server IPs. The exemptions are loopback / link-local / broadcast / servers /
/// liveness-probe targets / local subnets (ALE + packet mirror), plus opt-in
/// DNS-over-primary (port-53 UDP/TCP to each of `dns_servers`, the machine's
/// own resolvers, ALE only). The ALE catch-all block is narrowed to the ALE protocol and
/// emitted only when TCP/UDP is selected; the packet blocks reproduce
/// `packet_protocol_blocks`; the IPv6 cut always applies. Empty when no protocol is
/// selected.
// Mirrors `FailClosedExemptions` field-by-field as plain slices — the
// equivalence tests drive both sides from the same locals, and a struct here
// would just duplicate the codegen's. `open_hosts` has no codegen field: they
// are hosts no rule permit lets out, open at both layers — what the forwarded
// blanket states as its floor.
#[allow(clippy::too_many_arguments)]
pub fn plan_fail_closed_block_all(
    sid: &str,
    server_ips: &[Ipv4Addr],
    probe_target_ips: &[Ipv4Addr],
    local_subnets: &[(Ipv4Addr, u8)],
    primary_dest_ips: &[Ipv4Addr],
    open_hosts: &[Ipv4Addr],
    v6: Ipv6Exemptions<'_>,
    allow_dns_over_primary: bool,
    dns_servers: &[Ipv4Addr],
    protocols: KillSwitchProtocols,
) -> Vec<FlowRule> {
    let dns: Vec<IpAddr> = dns_servers.iter().copied().map(IpAddr::V4).collect();
    plan_fail_closed_block_all_with_dns(
        sid,
        server_ips,
        probe_target_ips,
        local_subnets,
        primary_dest_ips,
        open_hosts,
        v6,
        allow_dns_over_primary,
        &dns,
        protocols,
    )
}

/// [`plan_fail_closed_block_all`] with resolvers of either family: on a
/// network whose only resolvers are IPv6 the port-53 permit has to name them.
#[allow(clippy::too_many_arguments)]
pub fn plan_fail_closed_block_all_with_dns(
    sid: &str,
    server_ips: &[Ipv4Addr],
    probe_target_ips: &[Ipv4Addr],
    local_subnets: &[(Ipv4Addr, u8)],
    primary_dest_ips: &[Ipv4Addr],
    open_hosts: &[Ipv4Addr],
    v6: Ipv6Exemptions<'_>,
    allow_dns_over_primary: bool,
    dns_servers: &[IpAddr],
    protocols: KillSwitchProtocols,
) -> Vec<FlowRule> {
    let any_selected = protocols.tcp
        || protocols.udp
        || protocols.icmp
        || protocols.igmp
        || protocols.gre
        || protocols.esp
        || protocols.other;
    if !any_selected {
        return Vec::new();
    }
    // `other` does not activate the packet layer
    // (mirrors `KillSwitchProtocols::wants_packet_layer`).
    let wants_packet = protocols.icmp || protocols.igmp || protocols.gre || protocols.esp;
    let principal = principal_scope(sid);
    let mut flows = Vec::new();

    // ── ALE exemptions (+ packet mirror iff the packet layer is active), in
    //    codegen order — NO egress permit (the secondary is gone). ──
    let mut exemptions: Vec<(DstMatch, EgressConstraint)> = vec![
        (
            DstMatch::SubnetV4 {
                net: Ipv4Addr::new(127, 0, 0, 0),
                prefix: 8,
            },
            EgressConstraint::Any,
        ),
        (
            DstMatch::SubnetV4 {
                net: Ipv4Addr::new(169, 254, 0, 0),
                prefix: 16,
            },
            EgressConstraint::Any,
        ),
        (DstMatch::HostV4(Ipv4Addr::BROADCAST), EgressConstraint::Any),
        // Local network control block: mDNS/LLMNR/IGMP never leave the link.
        (
            DstMatch::SubnetV4 {
                net: Ipv4Addr::new(224, 0, 0, 0),
                prefix: 24,
            },
            EgressConstraint::Any,
        ),
    ];
    for ip in server_ips {
        exemptions.push((DstMatch::HostV4(*ip), EgressConstraint::Any));
    }
    // Liveness-probe targets — mirrors the codegen's placement between the
    // bootstrap servers and the local subnets.
    for ip in probe_target_ips {
        exemptions.push((DstMatch::HostV4(*ip), EgressConstraint::Any));
    }
    for (net, prefix) in local_subnets {
        exemptions.push((
            DstMatch::SubnetV4 {
                net: *net,
                prefix: *prefix,
            },
            EgressConstraint::Any,
        ));
    }
    let mut e = 0u32;
    for (dst, egress) in exemptions {
        flows.push(catch_all_flow(
            &principal,
            Verdict::Permit,
            PrecedenceClass::CatchAllExempt,
            dst,
            egress.clone(),
            None,
            Coverage::ConnectOnly,
            e,
        ));
        if wants_packet {
            flows.push(catch_all_flow(
                &principal,
                Verdict::Permit,
                PrecedenceClass::CatchAllExempt,
                dst,
                egress,
                None,
                Coverage::AllPackets,
                e,
            ));
        }
        e += 1;
    }
    // Open hosts: a connect-layer exempt now, the packet twin after the
    // known-primary permits below. No rule permit lets them out, so the
    // connect half is what keeps them reachable.
    for ip in open_hosts
        .iter()
        .copied()
        .filter(|ip| !nrr_platform_api::is_exempt_from_blocking(*ip))
        .take(KILLSWITCH_MAX_DESTINATIONS)
    {
        flows.push(catch_all_flow(
            &principal,
            Verdict::Permit,
            PrecedenceClass::CatchAllExempt,
            DstMatch::HostV4(ip),
            EgressConstraint::Any,
            None,
            Coverage::ConnectOnly,
            e,
        ));
        e += 1;
    }
    // Known-primary destinations get a
    // packet-ONLY proto-agnostic permit (no ALE mirror — TCP/UDP already escape
    // via the primary rule permit), so ping/ICMP to a whitelisted host survives
    // the packet block-all. Skip loopback/link-local, cap like every other
    // destination list. Mirrors `killswitch_codegen::packet_permit_primary_host`.
    if wants_packet {
        for ip in primary_dest_ips
            .iter()
            .copied()
            .filter(|ip| !nrr_platform_api::is_exempt_from_blocking(*ip))
            .take(KILLSWITCH_MAX_DESTINATIONS)
        {
            flows.push(catch_all_flow(
                &principal,
                Verdict::Permit,
                PrecedenceClass::CatchAllExempt,
                DstMatch::HostV4(ip),
                EgressConstraint::Any,
                None,
                Coverage::AllPackets,
                e,
            ));
            e += 1;
        }
        // Packet twin of the open-host exempt above.
        for ip in open_hosts
            .iter()
            .copied()
            .filter(|ip| !nrr_platform_api::is_exempt_from_blocking(*ip))
            .take(KILLSWITCH_MAX_DESTINATIONS)
        {
            flows.push(catch_all_flow(
                &principal,
                Verdict::Permit,
                PrecedenceClass::CatchAllExempt,
                DstMatch::HostV4(ip),
                EgressConstraint::Any,
                None,
                Coverage::AllPackets,
                e,
            ));
            e += 1;
        }
    }
    // Opt-in DNS-over-primary: port-53 UDP then TCP per system resolver, ALE
    // only (no packet mirror). Same order and cap as the codegen.
    if allow_dns_over_primary {
        for ip in dns_servers
            .iter()
            .filter(|ip| !nrr_platform_api::is_exempt_from_blocking(**ip))
            .take(crate::killswitch_codegen::MAX_DNS_SERVER_PERMITS)
        {
            let dst = match *ip {
                IpAddr::V4(v4) => DstMatch::HostV4(v4),
                IpAddr::V6(v6) => DstMatch::HostV6(v6),
            };
            for proto in [L4Proto::Udp, L4Proto::Tcp] {
                flows.push(FlowRule {
                    verdict: Verdict::Permit,
                    precedence: Precedence {
                        class: PrecedenceClass::CatchAllExempt,
                        ordinal: e,
                    },
                    flow: FlowMatch {
                        dst,
                        dst_port: Some(53),
                        protocol: Some(proto),
                    },
                    principal: principal.clone(),
                    app: AppScope::Any,
                    egress: EgressConstraint::Any,
                    coverage: Coverage::ConnectOnly,
                    observed_by_program: false,
                });
                e += 1;
            }
        }
    }

    // ── ALE catch-all block (narrowed to the ALE protocol), if TCP/UDP selected. ──
    if protocols.tcp || protocols.udp {
        flows.push(catch_all_flow(
            &principal,
            Verdict::Block,
            PrecedenceClass::CatchAllBlock,
            DstMatch::Any,
            EgressConstraint::Any,
            ale_protocol(protocols),
            Coverage::ConnectOnly,
            0,
        ));
    }

    // ── V4 packet blocks (iff the packet layer is active) — one block per
    //    selected NAMED protocol; the "Other" block-all is GONE. ──
    if wants_packet {
        for (k, proto) in selected_packet_protocols(protocols).into_iter().enumerate() {
            flows.push(catch_all_flow(
                &principal,
                Verdict::Block,
                PrecedenceClass::CatchAllBlock,
                DstMatch::Any,
                EgressConstraint::Any,
                Some(proto),
                Coverage::AllPackets,
                k as u32,
            ));
        }
    }

    // ── IPv6 cut (always). ──
    push_ipv6_cut(&principal, &mut flows, v6, protocols);

    flows
}

#[cfg(test)]
mod link_infrastructure_tests {
    use super::LinkInfrastructure;
    use std::net::{IpAddr, Ipv4Addr};

    const SERVER: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    const RESOLVER: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 53));
    const SITE: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 80));

    /// A name another party answers for can point at the main link's resolver;
    /// pinned to the tunnel, the machine's DNS dies when the tunnel drops. The
    /// user writing the address as a rule is a choice and is kept.
    #[test]
    fn a_resolver_is_spared_unless_a_rule_names_it_literally() {
        let infra = LinkInfrastructure {
            tunnel_servers: vec![SERVER],
            link_resolvers: vec![RESOLVER],
        };
        assert!(infra.spares(RESOLVER, false));
        assert!(!infra.spares(RESOLVER, true));
        assert!(
            infra.spares(SERVER, true),
            "the tunnel's server, whatever names it"
        );
        assert!(!infra.spares(SITE, false));
    }
}
