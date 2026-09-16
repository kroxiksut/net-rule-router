//! Planning the kill-switch: per-destination pins, the catch-all, and the IPv6
//! cut that travels with them.

use super::*;

/// Plan the **per-destination kill-switch** (Sub-slices 4a + 4b) for `sid` — the
/// leak-proof `OnlyVia(Secondary)` pins over each protected IP, across every
/// selected protocol.
///
/// Neutral equivalent of `killswitch_codegen::kill_switch_filters` (the ALE pair
/// plus `packet_egress_pairs`). For each non-exempt, capped protected IP at
/// post-filter index `idx` it emits:
///
/// - **ALE-connect pair (4a)** — iff any ALE protocol (TCP/UDP) is selected: one
///   proto-agnostic [`FlowRule`], [`Coverage::ConnectOnly`], `ordinal = idx`,
///   egress [`EgressConstraint::OnlyVia`]`(Secondary)`.
/// - **Packet-layer flows (4b)** — one 16-slot window per destination
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
        // ALE-connect pair (4a): a proto-agnostic egress-conditional pin at
        // ordinal = idx. Present iff any ALE protocol (TCP or UDP) is selected —
        // the ALE pair is protocol-agnostic, so either one selected covers both.
        if protocols.tcp || protocols.udp {
            flows.push(kill_switch_flow(
                &principal,
                ip,
                None,
                EgressConstraint::OnlyVia(EgressRef::Secondary),
                Coverage::ConnectOnly,
                idx,
            ));
        }
        // Packet-layer flows (4b): one 16-slot window per destination — one
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
                ip,
                Some(proto),
                EgressConstraint::OnlyVia(EgressRef::Secondary),
                Coverage::AllPackets,
                base + slot as u32,
            ));
        }
    }
    flows
}

/// Build one [`PrecedenceClass::KillSwitchPermit`] `Permit` flow over `ip`.
fn kill_switch_flow(
    principal: &PrincipalScope,
    ip: IpAddr,
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
            dst: host_match(ip),
            dst_port: None,
            protocol,
        },
        principal: principal.clone(),
        app: AppScope::Any,
        egress,
        coverage,
    }
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

/// Plan the **catch-all (Mode-B) kill-switch** (Sub-slice 4c) for `sid` — the
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
///   exemptions over an `::/0` block-all, at BOTH V6 layers (Free's only IPv6
///   handling; independent of the V4 protocol mask).
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

    // ── IPv6 cut (always): loopback + link-local + link-local-multicast
    //    exemptions over an ::/0 block-all, at BOTH V6 layers (ALE + packet). ──
    push_ipv6_cut(&principal, &mut flows, v6);

    flows
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
/// tunnel's endpoints and the local prefixes, over an `::/0` block-all, at BOTH
/// V6 layers. Shared by the catch-all and fail-closed block-all planners
/// (`killswitch_codegen::catch_all_v6_filters`).
pub(super) fn push_ipv6_cut(
    principal: &PrincipalScope,
    flows: &mut Vec<FlowRule>,
    v6: Ipv6Exemptions<'_>,
) {
    let v6_exempts = [
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
    let scoped = v6
        .server_ips
        .iter()
        .map(|ip| DstMatch::SubnetV6 {
            net: *ip,
            prefix: 128,
        })
        .chain(
            v6.local_subnets
                .iter()
                .map(|(net, prefix)| DstMatch::SubnetV6 {
                    net: *net,
                    prefix: *prefix,
                }),
        );
    for (e, dst) in v6_exempts.into_iter().chain(scoped).enumerate() {
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
    flows.push(catch_all_flow(
        principal,
        Verdict::Block,
        PrecedenceClass::CatchAllBlock,
        v6_all,
        EgressConstraint::Any,
        None,
        Coverage::AllPackets,
        0,
    ));
}

/// Build one catch-all [`FlowRule`] (Sub-slices 4c/4d), `app = Any`.
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
    }
}
