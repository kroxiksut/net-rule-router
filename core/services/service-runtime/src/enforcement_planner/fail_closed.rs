//! Fail-closed planning and the per-application half of the kill-switch.
//!
//! Fail-closed is what the plan falls back to when the additional link cannot
//! be resolved: it blocks rather than leaks, and everything here exists to keep
//! the machine reachable while it does.

use super::*;

// ── Sub-slice 4d — fail-closed + per-app kill-switch + primary-app exemption ────

/// A named-app scope carrying `pattern` as its `ALE_APP_ID` — the kill-switch app
/// filters put the pattern straight into `app_pattern` (no exe-path resolution),
/// so `exe_paths` holds the single pattern the Windows lowering reads.
fn app_scope(pattern: &str) -> AppScope {
    AppScope::Program {
        key: pattern.to_string(),
        exe_paths: vec![PathBuf::from(pattern)],
    }
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

/// Build one kill-switch / fail-closed [`FlowRule`] (Sub-slice 4d).
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
    }
}

/// Plan the **per-app kill-switch** (Sub-slice 4d) — the leak-proof
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
        flows.push(ks_flow(
            &principal,
            Verdict::Permit,
            PrecedenceClass::KillSwitchPermit,
            DstMatch::Any,
            app_scope(pattern),
            EgressConstraint::OnlyVia(EgressRef::Secondary),
            None,
            Coverage::ConnectOnly,
            idx as u32,
        ));
    }
    flows
}

/// Plan the **primary-app kill-switch exemption** (Sub-slice 4d) — one
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
    app_patterns
        .iter()
        .take(KILLSWITCH_MAX_DESTINATIONS)
        .enumerate()
        .map(|(idx, pattern)| {
            ks_flow(
                &principal,
                Verdict::Permit,
                PrecedenceClass::CatchAllExempt,
                DstMatch::Any,
                app_scope(pattern),
                EgressConstraint::Any,
                None,
                Coverage::ConnectOnly,
                idx as u32,
            )
        })
        .collect()
}

/// Plan the **fail-closed per-destination block** (Sub-slice 4d) — the secondary
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

/// Plan the **fail-closed per-app block** (Sub-slice 4d) — block each protected
/// app at the ALE layer (proto-agnostic, no egress permit). Neutral equivalent of
/// `killswitch_codegen::fail_closed_block_apps`. Emits nothing unless TCP/UDP is
/// selected (ALE only).
pub fn plan_fail_closed_apps(
    sid: &str,
    app_patterns: &[String],
    protocols: KillSwitchProtocols,
) -> Vec<FlowRule> {
    if !(protocols.tcp || protocols.udp) {
        return Vec::new();
    }
    let principal = principal_scope(sid);
    app_patterns
        .iter()
        .take(APP_KILLSWITCH_MAX_APPS)
        .enumerate()
        .map(|(idx, pattern)| {
            ks_flow(
                &principal,
                Verdict::Block,
                PrecedenceClass::KillSwitchBlock,
                DstMatch::Any,
                app_scope(pattern),
                EgressConstraint::Any,
                None,
                Coverage::ConnectOnly,
                idx as u32,
            )
        })
        .collect()
}

/// Plan the DoH/DoT lockdown blocks as neutral
/// [`FlowRule`]s — the neutral equivalent of
/// [`crate::killswitch_codegen::doh_dot_block_filters`]. Per resolver IP: a
/// [`PrecedenceClass::DohBlock`] `Block` on `443` for TCP then UDP; then, when
/// `block_dot`, a global `Block` on `853` for TCP then UDP. Emission order fixes
/// the ascending `ordinal` so `lower_windows::lower_doh_dot_block` reproduces the
/// exact same arbitration order as the codegen.
pub fn plan_doh_dot_block(sid: &str, resolver_ips: &[Ipv4Addr], block_dot: bool) -> Vec<FlowRule> {
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
    };
    for ip in resolver_ips
        .iter()
        .copied()
        .filter(|ip| !nrr_platform_api::is_exempt_from_blocking(*ip))
        .take(crate::killswitch_codegen::DOH_MAX_RESOLVER_IPS)
    {
        for proto in [L4Proto::Tcp, L4Proto::Udp] {
            let mut f = flow_for(DstMatch::HostV4(ip), 443, ordinal);
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

/// Plan the **fail-closed Mode-B block-all** (Sub-slice 4d) — the secondary is
/// gone, so block ALL egress for this user except the safe exemptions. Neutral
/// equivalent of `killswitch_codegen::fail_closed_block_all_filters`.
///
/// Unlike [`plan_catch_all_kill_switch`] it arms WITHOUT a resolvable secondary
/// (there is none — so no egress-via-secondary permit) and WITHOUT requiring
/// server IPs. The exemptions are loopback / link-local / broadcast / servers /
/// liveness-probe targets / local subnets (ALE + packet mirror), plus opt-in
/// DNS-over-primary (port-53
/// UDP/TCP, ALE only). The ALE catch-all block is narrowed to the ALE protocol and
/// emitted only when TCP/UDP is selected; the packet blocks reproduce
/// `packet_protocol_blocks`; the IPv6 cut always applies. Empty when no protocol is
/// selected.
// Mirrors `FailClosedExemptions` field-by-field as plain slices — the
// equivalence tests drive both sides from the same locals, and a struct here
// would just duplicate the codegen's.
#[allow(clippy::too_many_arguments)]
pub fn plan_fail_closed_block_all(
    sid: &str,
    server_ips: &[Ipv4Addr],
    probe_target_ips: &[Ipv4Addr],
    local_subnets: &[(Ipv4Addr, u8)],
    primary_dest_ips: &[Ipv4Addr],
    known_direct_ips: &[Ipv4Addr],
    v6: Ipv6Exemptions<'_>,
    allow_dns_over_primary: bool,
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
    // Known-DIRECT destinations: an ALE exempt now (matching
    // the codegen's within-layer order: …, subnets, direct, dns-53, block); the
    // packet twin is emitted after the known-primary permits below. Unlike
    // known-primary these have NO rule permit at all, so the ALE half is what
    // keeps a plain primary-path site reachable under the block-all.
    // Mirrors `killswitch_codegen::exempt_direct_host`.
    for ip in known_direct_ips
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
        // Packet twin of the known-direct ALE exempt above, after the
        // known-primary permits (the codegen's packet-layer emission order).
        // Mirrors `killswitch_codegen::packet_permit_direct_host`.
        for ip in known_direct_ips
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
    // Opt-in DNS-over-primary: port-53 UDP then TCP, ALE only (no packet mirror).
    if allow_dns_over_primary {
        for proto in [L4Proto::Udp, L4Proto::Tcp] {
            flows.push(FlowRule {
                verdict: Verdict::Permit,
                precedence: Precedence {
                    class: PrecedenceClass::CatchAllExempt,
                    ordinal: e,
                },
                flow: FlowMatch {
                    dst: DstMatch::Any,
                    dst_port: Some(53),
                    protocol: Some(proto),
                },
                principal: principal.clone(),
                app: AppScope::Any,
                egress: EgressConstraint::Any,
                coverage: Coverage::ConnectOnly,
            });
            e += 1;
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
    push_ipv6_cut(&principal, &mut flows, v6);

    flows
}
