use super::*;

// ── Fail-closed: the failure posture ──────────────────────────────────────────

/// Exemptions for the fail-closed block-all path (mode B) when the secondary
/// is unresolvable. Loopback / link-local / broadcast are always exempt in the
/// codegen; these are the host-specific extras that keep the box manageable and
/// let the tunnel reconnect.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FailClosedExemptions {
    /// Known VPN server IPs to exempt so the tunnel can (re)establish even
    /// while everything else is blocked. May be empty (then reconnection
    /// requires toggling the emergency block off).
    pub bootstrap_server_ips: Vec<Ipv4Addr>,
    /// The tunnel's IPv6 endpoints, from the `/128` bootstrap routes. The v6
    /// block-all must let these out for the same reason the v4 one must: a
    /// tunnel that cannot dial its own server never comes back.
    pub bootstrap_server_ips_v6: Vec<Ipv6Addr>,
    /// Primary interface's connected subnets (LAN / DHCP unicast / local
    /// router / local DNS) to exempt so the machine stays reachable.
    pub local_subnets: Vec<(Ipv4Addr, u8)>,
    /// The primary link's directly-attached IPv6 prefixes — the v6 LAN, which
    /// a blanket family block cut along with everything else.
    pub local_subnets_v6: Vec<(Ipv6Addr, u8)>,
    /// known-primary destination IPs (hosts
    /// the user's PRIMARY rules resolved to). Under the block-all, TCP/UDP to
    /// these already escapes at the ALE layer via the rule permit, but the
    /// packet-layer named blocks (ICMP/…) are unconditional and would cut ping
    /// to a positively primary-routed host. Each earns a packet-layer
    /// proto-agnostic permit above the block band so "known-primary" is fully
    /// reachable while only "unknown" traffic is cut. The caller has already
    /// subtracted any IP that is also secondary-destined (those stay blocked
    /// while the secondary is down). Loopback/link-local are skipped here too.
    pub primary_dest_ips: Vec<Ipv4Addr>,
    /// OPT-IN "allow name resolution over the primary link
    /// while the catch-all block-all is engaged". `false` (default) = the strict
    /// posture blocks DNS too; `true` = add port-scoped permits (remote UDP/TCP
    /// port 53) so the Mode-B resolver's upstream queries — and plain DNS — keep
    /// working over the primary link while everything else is blocked. Narrowed to
    /// port 53 so it is NOT a full-host tunnel; it is still a deliberate
    /// DNS-over-primary leak, which is why it is opt-in and defaults off.
    pub allow_dns_over_primary: bool,
    /// destinations POSITIVELY established as DIRECT
    /// (non-rule) hosts (see [`crate::known_direct::KnownDirectRegistry`]): a
    /// Mode-B steered direct answer, or an FCrDNS forward-confirmed name that
    /// matches no rule. Unlike [`Self::primary_dest_ips`] these have NO rule
    /// permit at the ALE layer, so under the block-all each earns BOTH an ALE
    /// exempt and a packet-layer permit — otherwise a plain primary-path site
    /// (an unruled direct destination) dies with the tunnel it never used. The caller has
    /// already subtracted anything secondary-destined.
    pub known_direct_ips: Vec<Ipv4Addr>,
    /// LUID of the tunnel, so traffic leaving THROUGH it survives a cut. `0`
    /// when the tunnel is unresolved and there is no egress to permit. Carried
    /// here rather than passed alongside because it answers the same question
    /// as every other field: what may still leave.
    pub secondary_luid: u64,
    /// LUIDs of tunnels the USER runs that are none of our business — a
    /// corporate VPN beside our own additional route.
    ///
    /// Traffic leaving through one of these is not a leak: it goes into
    /// somebody else's encrypted tunnel, not out of the provider's door,
    /// which is the thing this block-all exists to stop. Cutting it makes the
    /// product the reason a working corporate connection dies, and the user
    /// cannot tell our block from their VPN failing.
    ///
    /// Permitted by EGRESS, never by destination: exempting the tunnel's
    /// address range instead would open that range on every link, including
    /// the primary — the hole the kill-switch is for.
    pub foreign_tunnel_luids: Vec<u64>,
    /// The secondary tunnel next-hop(s) the liveness probe pings. The probe's
    /// verdict is what DISARMS this very block-all, and its ICMP echo is
    /// kernel-originated — it carries no app-id, so no process exemption can
    /// cover it; only a destination permit can  HW diagnosis: the
    /// packet-layer ICMP block ate the probe's echo and the kill-switch stayed
    /// fail-closed until service stop, through every VPN reconnect). Each IP
    /// earns an ALE exempt plus a proto-agnostic packet-layer permit, both with
    /// their own id kind so a next-hop equal to a bootstrap server IP keeps
    /// distinct filter ids.
    pub probe_target_ips: Vec<Ipv4Addr>,
}

/// Fail-closed, mode A (selective). The secondary is unresolvable, so there is
/// no tunnel to permit through — emit a **block** over each protected secondary
/// destination, narrowed to the selected `protocols`. TCP/UDP are blocked at
/// the ALE connect layer; ICMP/IGMP/GRE/ESP (and, for "Other", every remaining
/// protocol) at the packet layer — the only place ICMP/ping is visible.
/// Loopback / link-local destinations are skipped. Returns empty when there is
/// nothing to protect or no protocol is selected.
pub fn fail_closed_block_destinations(
    sid: &str,
    protected_ips: &[IpAddr],
    protocols: KillSwitchProtocols,
) -> Vec<WfpFilterSpec> {
    if !protocols.any() {
        return Vec::new();
    }
    let chunks = pack_both(
        protected_ips
            .iter()
            .copied()
            .filter(|ip| !is_exempt_from_blocking(*ip))
            .take(KILLSWITCH_MAX_DESTINATIONS),
    );
    let mut out = Vec::new();
    for (idx, chunk) in chunks.iter().enumerate() {
        let idx = idx as u64;
        match chunk {
            FamilyChunk::V4(v4) => {
                let scope = DestScope::Chunk(v4);
                if protocols.wants_ale_block() {
                    out.push(ale_block(
                        sid,
                        scope,
                        protocols.ale_protocol(),
                        KILLSWITCH_BLOCK_BASE + idx,
                    ));
                }
                out.extend(packet_protocol_blocks(sid, scope, protocols, idx));
            }
            // The v6 half is the ALE block alone — same reasoning as the pin:
            // the protocol-narrowed layers below ALE have no v6 twin here.
            FamilyChunk::V6(_) => {
                if protocols.wants_ale_block() {
                    out.push(ale_block_v6(
                        sid,
                        chunk,
                        protocols.ale_protocol(),
                        KILLSWITCH_BLOCK_BASE + idx,
                    ));
                }
            }
        }
    }
    out
}

/// Fail-closed, mode A, per-**app**. The secondary is unresolvable, so there is
/// no tunnel to permit through — block each protected secondary application at
/// the ALE connect layer (TCP/UDP). ICMP from a specific process is not
/// matchable at the packet layer (no app context), so it is out of scope here —
/// the app's observed-destination `/32`s cover it via
/// [`fail_closed_block_destinations`]. Returns empty when no app is protected or
/// no ALE protocol is selected.
pub fn fail_closed_block_apps(
    sid: &str,
    app_patterns: &[String],
    protocols: KillSwitchProtocols,
) -> Vec<WfpFilterSpec> {
    if !protocols.wants_ale_block() {
        return Vec::new();
    }
    app_patterns
        .iter()
        .take(APP_KILLSWITCH_MAX_APPS)
        .enumerate()
        .map(|(idx, pattern)| ale_block_app(sid, pattern, APP_KILLSWITCH_BLOCK_BASE + idx as u64))
        .collect()
}

/// ALE-layer block keyed on an app id (mirrors [`ale_block`] for the per-app
/// fail-closed path). Protocol-agnostic (covers TCP+UDP). Sits below the
/// primary rule band ([`APP_KILLSWITCH_BLOCK_BASE`]) so main-named addresses
/// keep working for the app even with the tunnel unresolved; the id folds the
/// band tag for the same upgrade reason as [`block_app_off_secondary`].
fn ale_block_app(sid: &str, pattern: &str, weight: u64) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Block,
        remote_ip: None,
        remote_ip_set: Vec::new(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight,
        id: filter_id_for(
            sid,
            KILLSWITCH_ROLE,
            "sub-main-band",
            "ks-app-fc-block",
            pattern,
        ),
        user_sid: Some(sid.to_string()),
        app_pattern: Some(pattern.to_string()),
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

/// Fail-closed, mode B (everything-via-secondary). The secondary is gone, so
/// block **all** egress for this user except the safe exemptions. Unlike
/// [`catch_all_kill_switch_filters`] this arms WITHOUT a resolvable secondary adapter LUID
/// (there is none) and WITHOUT requiring server IPs — it is the last-resort
/// "the secondary adapter is gone, cut everything" path. The filter set, by weight
/// (high → low):
/// 1. exemption permits at [`CATCHALL_EXEMPT_BASE`] (loopback, link-local,
///    broadcast, any known VPN server, each primary local subnet);
/// 2. (rule-driven primary permits at `0x0020_0000` still escape — mode-B
///    exceptions routed via the primary link keep working);
/// 3. the catch-all `Block` at [`CATCHALL_BLOCK_WEIGHT`].
///
/// All filters are scoped to `sid` — it never blocks other users / the system.
pub fn fail_closed_block_all_filters(
    sid: &str,
    exemptions: &FailClosedExemptions,
    protocols: KillSwitchProtocols,
) -> Vec<WfpFilterSpec> {
    if !protocols.any() {
        return Vec::new();
    }
    let mut filters: Vec<WfpFilterSpec> = Vec::new();
    let mut weight = CATCHALL_EXEMPT_BASE;

    // Somebody else's tunnel keeps carrying what it was carrying. See
    // `FailClosedExemptions::foreign_tunnel_luids` for why this is not a hole:
    // the permit is on the EGRESS interface, so it covers only packets that
    // actually leave through that tunnel.
    for luid in &exemptions.foreign_tunnel_luids {
        if *luid != 0 && *luid != exemptions.secondary_luid {
            filters.push(exempt_egress(sid, *luid, weight));
            weight += 1;
        }
    }
    // ── ALE connect layer exemptions (TCP/UDP) ──
    filters.extend(base_ale_exemptions(
        sid,
        &exemptions.bootstrap_server_ips,
        &mut weight,
    ));
    // Liveness-probe target(s): the tunnel next-hop the probe must keep
    // reaching, or its DEAD verdict can never flip back and this block-all
    // never disarms (see `FailClosedExemptions::probe_target_ips`).
    for ip in &exemptions.probe_target_ips {
        filters.push(exempt_probe_target(sid, *ip, weight));
        weight += 1;
    }
    // Primary interface's connected subnets (LAN, DHCP unicast, local DNS).
    for (net, prefix) in &exemptions.local_subnets {
        filters.push(exempt_subnet(sid, *net, *prefix, weight));
        weight += 1;
    }
    // known-direct destinations. A direct host has no rule
    // permit at all, so without this the catch-all cuts plain primary-path
    // sites along with the leak it guards against. Distinct id kind from
    // `exempt_host`, so an IP that is also a VPN server keeps both filter ids.
    for ip in exemptions
        .known_direct_ips
        .iter()
        .copied()
        .filter(|ip| !is_exempt_from_blocking(*ip))
        .take(KILLSWITCH_MAX_DESTINATIONS)
    {
        filters.push(exempt_direct_host(sid, ip, weight));
        weight += 1;
    }
    // opt-in: keep name resolution working over the primary
    // link while blocked (port-scoped UDP/TCP 53). See `allow_dns_over_primary`.
    if exemptions.allow_dns_over_primary {
        filters.extend(exempt_dns_over_primary(sid, weight));
    }
    // The catch-all ALE block — TCP/UDP egress this user sends, narrowed to the
    // TCP/UDP selection. Skipped entirely when neither TCP nor UDP is selected.
    if protocols.wants_ale_block() {
        filters.push(ale_block(
            sid,
            DestScope::All,
            protocols.ale_protocol(),
            CATCHALL_BLOCK_WEIGHT,
        ));
    }

    // ── Transport layer (ICMP/IGMP/GRE/ESP — incl. ping) ──
    // the named-protocol blocks live at OUTBOUND_TRANSPORT_V4 (the
    // packet layer has no IP_PROTOCOL condition), so the layer needs its OWN
    // exemptions: the named blocks there would otherwise trap loopback/LAN/
    // DHCP/the tunnel server for those protocols.
    if protocols.wants_packet_layer() {
        const TR: WfpLayerKey = WfpLayerKey::OutboundTransportV4;
        let mut pw = PACKET_EXEMPT_BASE;
        filters.extend(base_packet_exemptions(
            sid,
            TR,
            &exemptions.bootstrap_server_ips,
            &mut pw,
        ));
        // Packet-layer twin of the probe-target ALE exempt above — this is the
        // layer whose named ICMP block would otherwise eat the probe's echo.
        for ip in &exemptions.probe_target_ips {
            filters.push(packet_permit_probe_target(sid, TR, *ip, pw));
            pw += 1;
        }
        for (net, prefix) in &exemptions.local_subnets {
            filters.push(packet_exempt_subnet(sid, TR, *net, *prefix, pw));
            pw += 1;
        }
        // known-primary destinations: a
        // proto-agnostic packet permit per IP so ping/ICMP to a positively
        // primary-routed host (e.g. ya.ru) escapes the named packet blocks
        // below, while genuinely-unknown traffic is still cut. TCP/UDP already
        // escaped at the ALE layer via the rule permit; this closes the
        // packet-layer gap that made ping to a whitelisted host fail. Caller
        // has subtracted secondary-destined IPs (those stay blocked while the
        // secondary is down). Loopback/link-local are skipped and the set is
        // capped like every other kill-switch destination list.
        for ip in exemptions
            .primary_dest_ips
            .iter()
            .copied()
            .filter(|ip| !is_exempt_from_blocking(*ip))
            .take(KILLSWITCH_MAX_DESTINATIONS)
        {
            filters.push(packet_permit_primary_host(sid, TR, ip, pw));
            pw += 1;
        }
        // packet-layer twin of the known-direct ALE exempt
        // above, so ICMP/ping to a learned direct host survives too.
        for ip in exemptions
            .known_direct_ips
            .iter()
            .copied()
            .filter(|ip| !is_exempt_from_blocking(*ip))
            .take(KILLSWITCH_MAX_DESTINATIONS)
        {
            filters.push(packet_permit_direct_host(sid, TR, ip, pw));
            pw += 1;
        }
        filters.extend(packet_protocol_blocks(sid, DestScope::All, protocols, 0));
    }

    // ── IPv6 ──
    // The secondary is gone, so the family goes with everything else — minus
    // what has to survive for the tunnel to come back and the LAN to answer.
    filters.extend(catch_all_v6_filters(
        sid,
        exemptions.secondary_luid,
        &exemptions.bootstrap_server_ips_v6,
        &exemptions.local_subnets_v6,
    ));

    filters
}
