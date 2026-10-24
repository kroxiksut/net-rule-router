//! Planning the kill-switch: per-destination pins, the catch-all, and the IPv6
//! cut that travels with them.

use super::*;

mod network_holds;
pub use network_holds::*;

/// Plan the **per-destination kill-switch** for `sid` — the
/// leak-proof `OnlyVia(Secondary)` pins over each protected IP, across every
/// selected protocol.
///
/// Neutral equivalent of `killswitch_codegen::kill_switch_filters` (the ALE pair
/// plus `packet_egress_pairs`). For each non-exempt, capped protected IP at
/// post-filter index `idx` it emits:
///
/// - **ALE-connect pair** — iff any ALE protocol (TCP/UDP) is selected: one
///   proto-agnostic [`FlowRule`], [`Coverage::ConnectOnly`], `ordinal = idx`,
///   egress [`EgressConstraint::OnlyVia`]`(Secondary)`.
/// - **Packet-layer flows** — one 16-slot window per destination
///   (`ordinal = idx * `[`PACKET_SLOTS_PER_DEST`]` + slot`), reproducing
///   `packet_egress_pairs`. When "Other" is selected: a proto-agnostic egress
///   pair (`OnlyVia`, [`Coverage::AllPackets`], slot 0) that cuts every protocol,
///   plus one `EgressConstraint::Any` permit per UN-selected protocol (in
///   `killswitch_codegen::unselected_named` order) so it keeps flowing. Otherwise:
///   one `OnlyVia` egress pair per selected named protocol (ICMP/IGMP/GRE/ESP, in
///   `killswitch_codegen::packet_named` order).
///
/// `lower_windows::lower_kill_switch` expands each flow into its WFP filter(s)
/// keyed on `(egress, coverage)`. Exempt IPs
/// (`nrr_platform_api::is_exempt_from_blocking`) are filtered and the set is
/// capped exactly as the current codegen does, so every `ordinal` reproduces the
/// kill-switch weights. All protocol vocabulary is the neutral [`L4Proto`]; the
/// WFP `ip_protocol` number is a lowering-time detail.
pub fn plan_kill_switch_destinations(
    sid: &str,
    protected_ips: &[IpAddr],
    protocols: KillSwitchProtocols,
) -> Vec<FlowRule> {
    let principal = principal_scope(sid);
    let mut flows = Vec::new();
    for (idx, ip) in protected_ips
        .iter()
        .copied()
        .filter(|ip| !nrr_platform_api::is_exempt_from_blocking(*ip))
        .take(KILLSWITCH_MAX_DESTINATIONS)
        .enumerate()
    {
        let idx = idx as u32;
        // ALE-connect pair: a proto-agnostic egress-conditional pin at
        // ordinal = idx. Present iff any ALE protocol (TCP or UDP) is selected —
        // the ALE pair is protocol-agnostic, so either one selected covers both.
        if protocols.tcp || protocols.udp {
            flows.push(kill_switch_flow(
                &principal,
                host_match(ip),
                None,
                EgressConstraint::OnlyVia(EgressRef::Secondary),
                Coverage::ConnectOnly,
                idx,
            ));
        }
        // Packet-layer flows: one 16-slot window per destination — one
        // egress pair per selected NAMED packet protocol. By design the
        // proto-agnostic "Other" pair is GONE (see
        // `killswitch_codegen::KillSwitchProtocols::wants_packet_layer`).
        //
        // IPv4 only. The pairs need `FWPM_CONDITION_IP_PROTOCOL`, which lives
        // at the transport layer, and this build models no v6 transport layer.
        // A rule host's own traffic is TCP/UDP, which the ALE pair above covers
        // in both families.
        if ip.is_ipv6() {
            continue;
        }
        let base = idx * PACKET_SLOTS_PER_DEST;
        for (slot, proto) in selected_packet_protocols(protocols).into_iter().enumerate() {
            flows.push(kill_switch_flow(
                &principal,
                host_match(ip),
                Some(proto),
                EgressConstraint::OnlyVia(EgressRef::Secondary),
                Coverage::AllPackets,
                base + slot as u32,
            ));
        }
    }
    flows
}

/// Build one [`PrecedenceClass::KillSwitchPermit`] `Permit` flow over `dst`.
fn kill_switch_flow(
    principal: &PrincipalScope,
    dst: DstMatch,
    protocol: Option<L4Proto>,
    egress: EgressConstraint,
    coverage: Coverage,
    ordinal: u32,
) -> FlowRule {
    FlowRule {
        verdict: Verdict::Permit,
        precedence: Precedence {
            class: PrecedenceClass::KillSwitchPermit,
            ordinal,
        },
        flow: FlowMatch {
            dst,
            dst_port: None,
            protocol,
        },
        principal: principal.clone(),
        app: AppScope::Any,
        egress,
        coverage,
        observed_by_program: false,
    }
}

/// Plan the kill-switch over the additional link's held networks: the same
/// `OnlyVia(Secondary)` pin [`plan_kill_switch_destinations`] puts on an
/// address, once per held network, plus the cut-outs left open inside them.
/// Ordinals continue past the per-address pins, so the two never share a slot.
pub fn plan_kill_switch_networks(
    sid: &str,
    holds: &NetworkHolds,
    protocols: KillSwitchProtocols,
) -> Vec<FlowRule> {
    let principal = principal_scope(sid);
    let mut flows = Vec::new();
    for (i, net) in holds.held.iter().copied().enumerate() {
        let ordinal = NETWORK_ORDINAL_BASE + i as u32;
        if protocols.tcp || protocols.udp {
            flows.push(kill_switch_flow(
                &principal,
                block_match(net),
                None,
                EgressConstraint::OnlyVia(EgressRef::Secondary),
                Coverage::ConnectOnly,
                ordinal,
            ));
        }
        // IPv4 only, as for the per-address pin.
        if !net.is_ipv4() {
            continue;
        }
        let base = ordinal * PACKET_SLOTS_PER_DEST;
        for (slot, proto) in selected_packet_protocols(protocols).into_iter().enumerate() {
            flows.push(kill_switch_flow(
                &principal,
                block_match(net),
                Some(proto),
                EgressConstraint::OnlyVia(EgressRef::Secondary),
                Coverage::AllPackets,
                base + slot as u32,
            ));
        }
    }
    flows.extend(plan_network_cut_outs(&principal, holds, protocols));
    flows
}

/// The cut-outs inside held networks, as exemptions: their band outranks every
/// hold whatever the ordinals, so no lowering has to order holds against them.
pub(super) fn plan_network_cut_outs(
    principal: &PrincipalScope,
    holds: &NetworkHolds,
    protocols: KillSwitchProtocols,
) -> Vec<FlowRule> {
    let connect = protocols.tcp || protocols.udp;
    let packet = !selected_packet_protocols(protocols).is_empty();
    let mut flows = Vec::new();
    for (j, cut) in holds.cut_outs.iter().copied().enumerate() {
        let ordinal = NETWORK_ORDINAL_BASE + j as u32;
        let mut push = |coverage| {
            flows.push(catch_all_flow(
                principal,
                Verdict::Permit,
                PrecedenceClass::CatchAllExempt,
                block_match(cut),
                EgressConstraint::Any,
                None,
                coverage,
                ordinal,
            ));
        };
        if connect {
            push(Coverage::ConnectOnly);
        }
        if packet && cut.is_ipv4() {
            push(Coverage::AllPackets);
        }
    }
    flows
}

/// The named packet protocols (ICMP/IGMP/GRE/ESP) that ARE selected, in
/// `killswitch_codegen::packet_named` order — each gets its own egress pair.
pub(super) fn selected_packet_protocols(p: KillSwitchProtocols) -> Vec<L4Proto> {
    let mut v = Vec::new();
    if p.icmp {
        v.push(L4Proto::Icmp);
    }
    if p.igmp {
        v.push(L4Proto::Igmp);
    }
    if p.gre {
        v.push(L4Proto::Gre);
    }
    if p.esp {
        v.push(L4Proto::Esp);
    }
    v
}

/// Plan the **catch-all (Mode-B) kill-switch** for `sid` — the
/// blanket "block everything not exempted" for everything-via-secondary.
///
/// Neutral equivalent of `killswitch_codegen::catch_all_kill_switch_filters`. For
/// the selected `protocols` (with `server_ips` the tunnel-server host exemptions
/// and `local_subnets` the primary's connected subnets, both resolved by the
/// caller — the secondary LUID is a lowering-time concern) it emits, in the exact
/// codegen order so each `ordinal` reproduces the weight:
///
/// - **V4 exemptions** ([`PrecedenceClass::CatchAllExempt`], `ordinal = e`) — the
///   egress-via-secondary blanket permit, loopback `127/8`, link-local
///   `169.254/16`, limited broadcast, each server, each local subnet. Each is an
///   ALE flow ([`Coverage::ConnectOnly`]) plus, iff any packet protocol is
///   selected, a packet mirror ([`Coverage::AllPackets`]).
/// - **V4 ALE catch-all block** ([`PrecedenceClass::CatchAllBlock`],
///   [`Coverage::ConnectOnly`]) — proto-agnostic, always.
/// - **V4 packet blocks** (iff a packet protocol is selected) — reproducing
///   `packet_protocol_blocks`: with "Other", a proto-agnostic block-all plus a
///   lone permit per UN-selected protocol; otherwise one block per selected named
///   protocol.
/// - **IPv6 cut** (always) — loopback `::1/128` + link-local `fe80::/10`
///   exemptions over an `::/0` connect block-all, plus a per-protocol block
///   (ICMPv6, GRE, ESP) for each selected one, like the V4 packet blocks.
///
/// Returns empty when there is no server exemption (arming the blanket block
/// without one would trap the tunnel's own reconnect) or no protocol is selected
/// — the planner-side safety valves. The zero-LUID fail-open is a lowering
/// concern (`lower_windows::lower_catch_all_kill_switch`).
pub fn plan_catch_all_kill_switch(
    sid: &str,
    server_ips: &[Ipv4Addr],
    local_subnets: &[(Ipv4Addr, u8)],
    v6: Ipv6Exemptions<'_>,
    protocols: KillSwitchProtocols,
) -> Vec<FlowRule> {
    let any_selected = protocols.tcp
        || protocols.udp
        || protocols.icmp
        || protocols.igmp
        || protocols.gre
        || protocols.esp
        || protocols.other;
    if server_ips.is_empty() || !any_selected {
        return Vec::new();
    }
    // `other` does not activate the packet layer
    // (mirrors `KillSwitchProtocols::wants_packet_layer`).
    let wants_packet = protocols.icmp || protocols.igmp || protocols.gre || protocols.esp;
    let principal = principal_scope(sid);
    let mut flows = Vec::new();

    // ── V4 exemptions, in codegen order (egress, loopback, link-local, broadcast,
    //    servers, local subnets). Each: an ALE flow + a packet mirror iff the
    //    packet layer is active. ──
    let mut exemptions: Vec<(DstMatch, EgressConstraint)> = vec![
        (
            DstMatch::Any,
            EgressConstraint::OnlyVia(EgressRef::Secondary),
        ),
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
    for (net, prefix) in local_subnets {
        exemptions.push((
            DstMatch::SubnetV4 {
                net: *net,
                prefix: *prefix,
            },
            EgressConstraint::Any,
        ));
    }
    for (e, (dst, egress)) in exemptions.into_iter().enumerate() {
        flows.push(catch_all_flow(
            &principal,
            Verdict::Permit,
            PrecedenceClass::CatchAllExempt,
            dst,
            egress.clone(),
            None,
            Coverage::ConnectOnly,
            e as u32,
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
                e as u32,
            ));
        }
    }

    // ── V4 ALE catch-all block (proto-agnostic, always). ──
    flows.push(catch_all_flow(
        &principal,
        Verdict::Block,
        PrecedenceClass::CatchAllBlock,
        DstMatch::Any,
        EgressConstraint::Any,
        None,
        Coverage::ConnectOnly,
        0,
    ));

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

    // IPv6 leaving through the tunnel survives the cut below. Named per family:
    // the Windows lowering reads `Any` as IPv4.
    let v6_coverages: &[Coverage] = if selected_packet_protocols_v6(protocols).is_empty() {
        &[Coverage::ConnectOnly]
    } else {
        &[Coverage::ConnectOnly, Coverage::AllPackets]
    };
    for &coverage in v6_coverages {
        flows.push(catch_all_flow(
            &principal,
            Verdict::Permit,
            PrecedenceClass::CatchAllExempt,
            DstMatch::SubnetV6 {
                net: Ipv6Addr::UNSPECIFIED,
                prefix: 0,
            },
            EgressConstraint::OnlyVia(EgressRef::Secondary),
            None,
            coverage,
            CATCH_ALL_V6_EGRESS_ORDINAL,
        ));
    }
    // ── IPv6 cut (always): loopback + link-local + link-local-multicast
    //    exemptions over the ::/0 connect block and the per-protocol ones. ──
    push_ipv6_cut(&principal, &mut flows, v6, protocols);

    flows
}

/// Above the IPv6 exemption band, where `killswitch_codegen` weighs its egress
/// permit (`CATCHALL_EXEMPT_BASE + 100`).
const CATCH_ALL_V6_EGRESS_ORDINAL: u32 = 100;

/// First ordinal of the foreign-tunnel permits: past every exemption the
/// blanket postures number, so the two never share a slot.
const FOREIGN_TUNNEL_ORDINAL_BASE: u32 = nrr_platform_api::enforcement::FOREIGN_TUNNEL_ORDINAL_BASE;

/// Somebody else's tunnel: the link it runs on, by the name the egress pin
/// uses, and the networks its own routes carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForeignTunnelLink {
    pub name: String,
    pub networks: Vec<nrr_shared::ip_block::IpBlock>,
}

/// Plan the permits that keep somebody else's tunnels out of every block this
/// plan carries: egress through the tunnel to a network its own routes carry.
/// Empty when `flows` holds no posture block or pin to spare them from.
///
/// Never to any destination: a tunnel that also holds a default route would
/// then carry the protected traffic once ours is down. Past
/// `FOREIGN_TUNNEL_MAX_NETWORKS` per link and family (or
/// `FOREIGN_TUNNEL_MAX_TUNNELS` links) the rest stay cut. The user's own hard
/// blocks sit above this band and stay in force.
///
/// One flow per network by design: the Linux lowering folds the rules of a link
/// into a single anonymous set, so the chain pays one lookup per link.
pub fn plan_foreign_tunnel_permits(
    sid: &str,
    flows: &[FlowRule],
    links: &[ForeignTunnelLink],
) -> Vec<FlowRule> {
    plan_foreign_tunnel_permits_for(&principal_scope(sid), flows, links)
}

/// [`plan_foreign_tunnel_permits`] for any scope: the service accounts and the
/// forwarded traffic keep a corporate network the same way a user does.
pub fn plan_foreign_tunnel_permits_for(
    principal: &PrincipalScope,
    flows: &[FlowRule],
    links: &[ForeignTunnelLink],
) -> Vec<FlowRule> {
    use crate::wfp_bands::{FOREIGN_TUNNEL_MAX_NETWORKS, FOREIGN_TUNNEL_MAX_TUNNELS};
    let principal = principal.clone();
    if !holds_posture_block(&principal, flows) {
        return Vec::new();
    }
    // The cap is per link and family, the way the Windows lowering packs a
    // tunnel's networks into one filter per layer.
    let per_family = |v4: bool| {
        links
            .iter()
            .take(FOREIGN_TUNNEL_MAX_TUNNELS)
            .flat_map(move |link| {
                link.networks
                    .iter()
                    .filter(move |net| net.is_ipv4() == v4)
                    .take(FOREIGN_TUNNEL_MAX_NETWORKS)
                    .map(move |net| (link, *net))
            })
    };
    let kept: Vec<(&ForeignTunnelLink, nrr_shared::ip_block::IpBlock)> =
        per_family(true).chain(per_family(false)).collect();
    let vetoes = plan_foreign_pin_vetoes(&principal, flows, &kept);
    let permits = kept
        .iter()
        .enumerate()
        .map(|(n, &(link, net))| {
            let dst = match net.network() {
                IpAddr::V4(addr) => DstMatch::SubnetV4 {
                    net: addr,
                    prefix: net.prefix_len(),
                },
                IpAddr::V6(addr) => DstMatch::SubnetV6 {
                    net: addr,
                    prefix: net.prefix_len(),
                },
            };
            catch_all_flow(
                &principal,
                Verdict::Permit,
                PrecedenceClass::CatchAllExempt,
                dst,
                EgressConstraint::OnlyVia(EgressRef::Adapter(
                    nrr_platform_api::enforcement::AdapterId(link.name.clone()),
                )),
                None,
                Coverage::ConnectOnly,
                FOREIGN_TUNNEL_ORDINAL_BASE + n as u32,
            )
        })
        .collect::<Vec<_>>();
    let mut out = permits;
    out.extend(vetoes);
    out
}

/// Whether `flows` hold a block the guard placed for `principal`. A pin states
/// its guard as the drop that follows its permit, so it cuts like a block does.
pub(crate) fn holds_posture_block(principal: &PrincipalScope, flows: &[FlowRule]) -> bool {
    flows.iter().any(|f| {
        f.principal == *principal
            && f.precedence.class.rank() < PrecedenceClass::CatchAllExempt.rank()
            && (f.verdict == Verdict::Block
                || (matches!(f.egress, EgressConstraint::OnlyVia(_))
                    && f.flow.dst != DstMatch::Any))
    })
}

/// The DoH/DoT lockdown restated for each link `flows` holds a permit for, our
/// own tunnel's block-all egress included, and for IPsec-protected traffic when
/// they spare it: a copy of every lockdown block that drops only what leaves
/// that way, above the permits. The lockdown is the user's own protection, so
/// neither a resolver the corporate network routes nor one reached through our
/// tunnel is exempt from it. The lockdown keeps its own place for every other
/// egress.
#[must_use]
pub fn plan_doh_foreign_vetoes(sid: &str, doh: &[FlowRule], flows: &[FlowRule]) -> Vec<FlowRule> {
    use nrr_platform_api::enforcement::DOH_FOREIGN_VETO_ORDINAL_BASE;
    let principal = principal_scope(sid);
    let mut spared = flows.iter().filter(|f| {
        f.principal == principal
            && f.verdict == Verdict::Permit
            && f.precedence.class == PrecedenceClass::CatchAllExempt
            && (f.precedence.ordinal >= FOREIGN_TUNNEL_ORDINAL_BASE
                || (f.flow.dst == DstMatch::Any
                    && matches!(f.egress, EgressConstraint::OnlyVia(_))))
    });
    let mut links: Vec<&nrr_platform_api::enforcement::AdapterId> = spared
        .clone()
        .filter_map(|f| match &f.egress {
            EgressConstraint::OnlyVia(EgressRef::Adapter(link)) => Some(link),
            _ => None,
        })
        .collect();
    links.sort_by(|a, b| a.0.cmp(&b.0));
    links.dedup();
    let own = EgressConstraint::OnlyVia(EgressRef::Secondary);
    let mut egresses: Vec<EgressConstraint> = spared
        .clone()
        .any(|f| f.egress == own && f.flow.dst == DstMatch::Any)
        .then(|| own.clone())
        .into_iter()
        .chain(
            links
                .into_iter()
                .map(|link| EgressConstraint::OnlyVia(EgressRef::Adapter(link.clone()))),
        )
        .collect();
    if spared.any(|f| f.egress == EgressConstraint::UnderIpsecPolicy) {
        egresses.push(EgressConstraint::UnderIpsecPolicy);
    }
    let mut out = Vec::new();
    for egress in egresses {
        for block in doh.iter().filter(|f| {
            f.principal == principal
                && f.verdict == Verdict::Block
                && f.precedence.class == PrecedenceClass::DohBlock
        }) {
            let mut veto = block.clone();
            veto.precedence = Precedence {
                class: PrecedenceClass::HardBlock,
                ordinal: DOH_FOREIGN_VETO_ORDINAL_BASE.saturating_add(out.len() as u32),
            };
            veto.egress = egress.clone();
            out.push(veto);
        }
    }
    out
}

/// The narrower rule wins over the network: an address the guard pins to our
/// tunnel, or cuts while it is down, stays that way inside a corporate network
/// a foreign permit opens. Each is the guard's own flow re-stated above the
/// permits, so a pin still means "this address, our tunnel only".
fn plan_foreign_pin_vetoes(
    principal: &PrincipalScope,
    flows: &[FlowRule],
    permitted: &[(&ForeignTunnelLink, nrr_shared::ip_block::IpBlock)],
) -> Vec<FlowRule> {
    use nrr_platform_api::enforcement::FOREIGN_PIN_VETO_ORDINAL_BASE;
    let inside = |dst: DstMatch| {
        let addr = match dst {
            DstMatch::HostV4(a) => IpAddr::V4(a),
            DstMatch::HostV6(a) => IpAddr::V6(a),
            _ => return false,
        };
        permitted.iter().any(|(_, net)| net.contains(addr))
    };
    flows
        .iter()
        .filter(|f| {
            f.principal == *principal
                && f.app == AppScope::Any
                && f.flow.dst_port.is_none()
                && f.coverage == Coverage::ConnectOnly
                && inside(f.flow.dst)
                && match f.verdict {
                    Verdict::Permit => {
                        f.precedence.class == PrecedenceClass::KillSwitchPermit
                            && f.flow.protocol.is_none()
                            && f.egress == EgressConstraint::OnlyVia(EgressRef::Secondary)
                    }
                    Verdict::Block => f.precedence.class == PrecedenceClass::KillSwitchBlock,
                }
        })
        .enumerate()
        .map(|(n, f)| {
            let mut veto = f.clone();
            veto.precedence = Precedence {
                class: PrecedenceClass::HardBlock,
                ordinal: FOREIGN_PIN_VETO_ORDINAL_BASE.saturating_add(n as u32),
            };
            veto
        })
        .collect()
}

/// What a blanket block must not cut on the IPv6 side, beyond the link-scope
/// prefixes every posture exempts: the tunnel's own endpoints and the primary
/// link's attached prefixes. The v6 twin of the `server_ips` / `local_subnets`
/// pair the v4 half takes.
#[derive(Clone, Copy, Default)]
pub struct Ipv6Exemptions<'a> {
    pub server_ips: &'a [Ipv6Addr],
    pub local_subnets: &'a [(Ipv6Addr, u8)],
}

/// Append the IPv6 half of a blanket block — the link-scope exemptions, the
/// tunnel's endpoints and the local prefixes, over the principal's `::/0`
/// block-all on connect and, below it, a block per selected non-TCP/UDP
/// protocol (ICMPv6, GRE, ESP), the shape of the v4 half. Shared by the
/// catch-all and fail-closed block-all planners
/// (`killswitch_codegen::catch_all_v6_filters`).
///
/// No protocol-less block below connect: Windows cannot scope that layer to a
/// user, so it would cut the system's IKE to an IPv6 VPN server, and its drop
/// would name nobody to ask about the gateway.
pub(super) fn push_ipv6_cut(
    principal: &PrincipalScope,
    flows: &mut Vec<FlowRule>,
    v6: Ipv6Exemptions<'_>,
    protocols: KillSwitchProtocols,
) {
    let below_connect = selected_packet_protocols_v6(protocols);
    for (e, dst) in ipv6_exempt_matches(v6).into_iter().enumerate() {
        flows.push(catch_all_flow(
            principal,
            Verdict::Permit,
            PrecedenceClass::CatchAllExempt,
            dst,
            EgressConstraint::Any,
            None,
            Coverage::ConnectOnly,
            e as u32,
        ));
        if !below_connect.is_empty() {
            flows.push(catch_all_flow(
                principal,
                Verdict::Permit,
                PrecedenceClass::CatchAllExempt,
                dst,
                EgressConstraint::Any,
                None,
                Coverage::AllPackets,
                e as u32,
            ));
        }
    }
    let v6_all = DstMatch::SubnetV6 {
        net: Ipv6Addr::UNSPECIFIED,
        prefix: 0,
    };
    flows.push(catch_all_flow(
        principal,
        Verdict::Block,
        PrecedenceClass::CatchAllBlock,
        v6_all,
        EgressConstraint::Any,
        None,
        Coverage::ConnectOnly,
        0,
    ));
    for (k, proto) in below_connect.into_iter().enumerate() {
        flows.push(catch_all_flow(
            principal,
            Verdict::Block,
            PrecedenceClass::CatchAllBlock,
            v6_all,
            EgressConstraint::Any,
            Some(proto),
            Coverage::AllPackets,
            k as u32,
        ));
    }
}

/// [`selected_packet_protocols`] for IPv6: ICMP is ICMPv6, and IGMP has no v6
/// twin (its job is MLD, ICMPv6 to link scope).
pub(super) fn selected_packet_protocols_v6(p: KillSwitchProtocols) -> Vec<L4Proto> {
    selected_packet_protocols(p)
        .into_iter()
        .filter_map(|proto| match proto {
            L4Proto::Icmp => Some(L4Proto::IcmpV6),
            L4Proto::Igmp => None,
            other => Some(other),
        })
        .collect()
}

/// What any block over `::/0` must leave open, in order: the link-scope
/// prefixes every posture exempts, then the tunnel's endpoints and the local
/// prefixes. One list for both blanket postures.
pub(super) fn ipv6_exempt_matches(v6: Ipv6Exemptions<'_>) -> Vec<DstMatch> {
    let link_scope = [
        DstMatch::SubnetV6 {
            net: Ipv6Addr::LOCALHOST,
            prefix: 128,
        },
        DstMatch::SubnetV6 {
            net: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
            prefix: 10,
        },
        // Neighbour discovery, MLD, mDNS and DHCPv6 address the group, not
        // `fe80::` — cutting this scope breaks the link, leaks nothing.
        DstMatch::SubnetV6 {
            net: Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0),
            prefix: 16,
        },
    ];
    link_scope
        .into_iter()
        .chain(v6.server_ips.iter().map(|ip| DstMatch::SubnetV6 {
            net: *ip,
            prefix: 128,
        }))
        .chain(
            v6.local_subnets
                .iter()
                .map(|(net, prefix)| DstMatch::SubnetV6 {
                    net: *net,
                    prefix: *prefix,
                }),
        )
        .collect()
}

/// Build one catch-all [`FlowRule`], `app = Any`.
#[allow(clippy::too_many_arguments)]
pub(super) fn catch_all_flow(
    principal: &PrincipalScope,
    verdict: Verdict,
    class: PrecedenceClass,
    dst: DstMatch,
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
        app: AppScope::Any,
        egress,
        coverage,
        observed_by_program: false,
    }
}

#[cfg(test)]
mod network_tests;

#[cfg(test)]
mod foreign_tunnel_tests {
    use super::*;
    use nrr_shared::ip_block::IpBlock;

    const SID: &str = "1000";
    const CORP: &str = "tap-corp";

    fn corp() -> Vec<ForeignTunnelLink> {
        vec![ForeignTunnelLink {
            name: CORP.to_owned(),
            networks: vec![
                IpBlock::parse("10.77.0.0/16").expect("block"),
                IpBlock::parse("fd00:77::/48").expect("block"),
            ],
        }]
    }

    fn via_corp() -> EgressConstraint {
        EgressConstraint::OnlyVia(EgressRef::Adapter(
            nrr_platform_api::enforcement::AdapterId(CORP.to_owned()),
        ))
    }

    fn pins() -> Vec<FlowRule> {
        let pinned = [IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))];
        plan_kill_switch_destinations(SID, &pinned, KillSwitchProtocols::ALL)
    }

    /// Every posture block of the principal sits under a permit for each
    /// network the foreign link carries, by that link, and for nothing else.
    fn assert_spared(posture: &str, flows: Vec<FlowRule>) {
        let permits = plan_foreign_tunnel_permits(SID, &flows, &corp());
        let dsts: Vec<DstMatch> = permits.iter().map(|p| p.flow.dst).collect();
        assert_eq!(
            dsts,
            vec![
                DstMatch::SubnetV4 {
                    net: Ipv4Addr::new(10, 77, 0, 0),
                    prefix: 16
                },
                DstMatch::SubnetV6 {
                    net: Ipv6Addr::new(0xfd00, 0x77, 0, 0, 0, 0, 0, 0),
                    prefix: 48
                },
            ],
            "{posture}",
        );
        assert!(permits
            .iter()
            .all(|p| p.verdict == Verdict::Permit && p.egress == via_corp()));
        // Pins lower to an accept and a drop at their own rank, so ranking
        // the permit above every other class the posture uses is the proof.
        let permit_rank = PrecedenceClass::CatchAllExempt.rank();
        assert!(flows
            .iter()
            .all(|f| f.precedence.class.rank() <= permit_rank));
    }

    fn v6<'a>() -> Ipv6Exemptions<'a> {
        Ipv6Exemptions::default()
    }

    #[test]
    fn every_blocking_posture_spares_a_foreign_tunnels_networks() {
        let server = [Ipv4Addr::new(203, 0, 113, 7)];
        let pinned = [IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))];
        let all = KillSwitchProtocols::ALL;
        assert_spared("per-destination pins", pins());
        assert_spared(
            "prefer-secondary catch-all",
            plan_catch_all_kill_switch(SID, &server, &[], v6(), all),
        );
        assert_spared(
            "fail-closed per destination",
            plan_fail_closed_destinations(SID, &pinned, all),
        );
        assert_spared(
            "fail-closed block-all",
            plan_fail_closed_block_all(SID, &server, &[], &[], &[], &[], v6(), false, &[], all),
        );
    }

    /// A tunnel whose routes are only a default or a redirect pair carries no
    /// network of its own, so nothing is opened through it.
    #[test]
    fn a_tunnel_with_only_a_default_route_gets_no_permit() {
        let full_tunnel = [ForeignTunnelLink {
            name: CORP.to_owned(),
            networks: Vec::new(),
        }];
        assert!(plan_foreign_tunnel_permits(SID, &pins(), &full_tunnel).is_empty());
        assert!(plan_foreign_tunnel_permits(SID, &pins(), &corp())
            .iter()
            .all(|p| p.flow.dst != DstMatch::Any));
    }

    #[test]
    fn nothing_is_permitted_where_nothing_blocks_or_no_tunnel_is_foreign() {
        assert!(plan_foreign_tunnel_permits(SID, &pins(), &[]).is_empty());
        assert!(plan_foreign_tunnel_permits(SID, &[], &corp()).is_empty());

        let pinned = [IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))];
        let blocks = plan_fail_closed_destinations(SID, &pinned, KillSwitchProtocols::ALL);
        assert!(plan_foreign_tunnel_permits(SID, &blocks, &[]).is_empty());
    }

    /// The permit sits below the hard-block class, so a user's own Block on an
    /// address inside the tunnel's network keeps it cut.
    #[test]
    fn a_users_hard_block_outranks_the_foreign_permit() {
        let permits = plan_foreign_tunnel_permits(SID, &pins(), &corp());
        assert!(!permits.is_empty());
        let block = catch_all_flow(
            &principal_scope(SID),
            Verdict::Block,
            PrecedenceClass::HardBlock,
            DstMatch::HostV4(Ipv4Addr::new(10, 77, 0, 5)),
            EgressConstraint::Any,
            None,
            Coverage::ConnectOnly,
            0,
        );
        assert!(permits
            .iter()
            .all(|p| p.precedence.class.rank() < block.precedence.class.rank()));
    }

    /// A pin inside the tunnel's network is restated above the permit, so the
    /// address still goes through our tunnel only; one outside it is left alone.
    #[test]
    fn a_pin_inside_a_foreign_network_outranks_the_permit() {
        let inside = IpAddr::V4(Ipv4Addr::new(10, 77, 3, 4));
        let outside = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
        let flows =
            plan_kill_switch_destinations(SID, &[inside, outside], KillSwitchProtocols::ALL);
        let out = plan_foreign_tunnel_permits(SID, &flows, &corp());
        let vetoes: Vec<&FlowRule> = out
            .iter()
            .filter(|f| f.precedence.class == PrecedenceClass::HardBlock)
            .collect();
        assert_eq!(vetoes.len(), 1);
        let veto = vetoes[0];
        assert_eq!(veto.flow.dst, DstMatch::HostV4(Ipv4Addr::new(10, 77, 3, 4)));
        assert_eq!(veto.verdict, Verdict::Permit);
        assert_eq!(veto.egress, EgressConstraint::OnlyVia(EgressRef::Secondary));
        let permit_rank = PrecedenceClass::CatchAllExempt.rank();
        assert!(veto.precedence.class.rank() > permit_rank);
        assert!(
            veto.precedence.ordinal >= nrr_platform_api::enforcement::FOREIGN_PIN_VETO_ORDINAL_BASE
        );
    }

    #[test]
    fn a_fail_closed_block_inside_a_foreign_network_stays_cut() {
        let inside = [IpAddr::V4(Ipv4Addr::new(10, 77, 3, 4))];
        let flows = plan_fail_closed_destinations(SID, &inside, KillSwitchProtocols::ALL);
        let out = plan_foreign_tunnel_permits(SID, &flows, &corp());
        assert!(out.iter().any(|f| f.verdict == Verdict::Block
            && f.precedence.class == PrecedenceClass::HardBlock
            && f.flow.dst == DstMatch::HostV4(Ipv4Addr::new(10, 77, 3, 4))));
    }

    fn link_with(name: &str, count: usize) -> ForeignTunnelLink {
        ForeignTunnelLink {
            name: name.to_owned(),
            networks: (0..count)
                .map(|n| {
                    IpBlock::parse(&format!("10.{}.{}.0/24", n / 200 + 1, n % 200)).expect("block")
                })
                .collect(),
        }
    }

    #[test]
    fn past_the_cap_the_rest_of_a_links_family_stays_cut() {
        use crate::wfp_bands::FOREIGN_TUNNEL_MAX_NETWORKS;
        let many = [link_with(CORP, FOREIGN_TUNNEL_MAX_NETWORKS + 1)];
        assert_eq!(
            plan_foreign_tunnel_permits(SID, &pins(), &many).len(),
            FOREIGN_TUNNEL_MAX_NETWORKS
        );
    }

    /// The cap is per link: a second tunnel is not starved by the first.
    #[test]
    fn each_link_has_its_own_cap() {
        use crate::wfp_bands::FOREIGN_TUNNEL_MAX_NETWORKS;
        let two = [
            link_with(CORP, FOREIGN_TUNNEL_MAX_NETWORKS),
            link_with("tap-other", 3),
        ];
        let permits = plan_foreign_tunnel_permits(SID, &pins(), &two);
        assert_eq!(permits.len(), FOREIGN_TUNNEL_MAX_NETWORKS + 3);
        assert!(permits.iter().any(|p| p.egress
            == EgressConstraint::OnlyVia(EgressRef::Adapter(
                nrr_platform_api::enforcement::AdapterId("tap-other".to_owned())
            ))));
    }

    /// The lockdown outranks a corporate link's permit for what leaves through
    /// that link, and only there.
    #[test]
    fn the_lockdown_is_restated_above_a_foreign_permit_for_that_link_only() {
        use nrr_platform_api::enforcement::DOH_FOREIGN_VETO_ORDINAL_BASE;
        let resolver = [IpAddr::V4(Ipv4Addr::new(10, 77, 7, 7))];
        let doh = plan_doh_dot_block(SID, &resolver, true);
        let mut flows = pins();
        flows.extend(plan_foreign_tunnel_permits(SID, &flows, &corp()));
        let vetoes = plan_doh_foreign_vetoes(SID, &doh, &flows);
        assert_eq!(
            vetoes.len(),
            doh.len(),
            "one restatement per lockdown block"
        );
        let permit_rank = PrecedenceClass::CatchAllExempt.rank();
        for v in &vetoes {
            assert_eq!(v.verdict, Verdict::Block);
            assert_eq!(v.egress, via_corp());
            assert!(v.precedence.class.rank() > permit_rank);
            assert!(v.precedence.ordinal >= DOH_FOREIGN_VETO_ORDINAL_BASE);
        }
        assert!(doh.iter().all(|d| d.egress == EgressConstraint::Any));
        assert!(
            plan_doh_foreign_vetoes(SID, &doh, &pins()).is_empty(),
            "no permit for a foreign link, nothing to restate",
        );
    }
}
