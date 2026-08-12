//! leak-proof kill-switch WFP codegen.
//!
//! ## What the kill-switch guarantees
//!
//! When the user routes a set of destinations through a "secondary"
//! adapter (typically a VPN tunnel) and that adapter goes down, the OS
//! route table fails the traffic over to the primary adapter — so the
//! packets that were meant to be private leak out under the real IP.
//! The reactive Fail-Closed path (block 15.6,
//! [`nrr_platform_api::fail_closed`]) closes this by *detecting*
//! the adapter is unavailable and then installing block filters — but
//! between "secondary adapter dropped" and "block installed" there is a race window
//! where packets can still escape.
//!
//! The kill-switch removes the race entirely. Instead of reacting to
//! adapter state, it pins a **permanent, egress-conditional** pair of
//! WFP filters per protected destination:
//!
//! ```text
//!   Permit  remote_ip == X  AND  local_interface == secondary_luid   (high weight)
//!   Block   remote_ip == X                                           (lower weight)
//! ```
//!
//! - While the secondary adapter is up, the OS sends `X` out the tunnel, the connect
//!   egresses `secondary_luid`, the **Permit** matches (it outranks the
//!   Block) and the connection is allowed.
//! - The instant the secondary adapter drops, the route fails over to the primary
//!   interface, the connect no longer egresses `secondary_luid`, the
//!   **Permit stops matching**, and the lower-weight **Block** becomes
//!   the highest matching filter — the connection is dropped. No reactive
//!   reinstall, no polling, no race: the kernel arbitration does it on
//!   the very first packet.
//!
//! ## Weight bands
//!
//! The pair sits **above** every rule-driven band in
//! [`crate::wfp_codegen`] (`BASE_PRIMARY = 0x0020_0000`), so for a
//! protected destination the kill-switch always governs the verdict,
//! overriding the plain `Permit` the rule codegen emits for the same IP
//! (which carries no interface condition and would otherwise permit the
//! leak):
//!
//! | Filter | Weight | Conditions |
//! |--------|--------|------------|
//! | KS Permit | `0x0040_0000 + i` | `remote_ip`, `local_interface` |
//! | KS Block  | `0x0030_0000 + i` | `remote_ip` |
//! | rule Permit | `≤ 0x0020_xxxx` | `remote_ip` (no interface) |
//!
//! For each destination `i`: `KS Permit > KS Block > rule Permit`, which
//! is precisely the ordering the leak-proof guarantee needs.
//!
//! ## Scope and blast radius
//!
//! This is the **per-destination** kill-switch: it only ever touches the
//! enumerated `protected_ips`. Destinations outside the set are never
//! blocked — a deliberately bounded blast radius. (A catch-all "block
//! everything that isn't egressing the secondary adapter" variant, for the
//! "everything-via-secondary" mode B, reuses the same
//! [`condition_local_interface`](nrr_platform_api) FFI primitive but
//! a `remote_ip = None` scope; it carries a much higher blast radius and
//! is deferred to the wiring slice so it can be verified on hardware.)
//!
//! ## Safety valves
//!
//! - **Loopback / link-local are never blocked** — they back system
//!   services (mDNS, APIPA) and reuse
//!   [`nrr_platform_api::fail_closed::is_exempt_from_blocking`].
//! - **A zero/unknown LUID disables the kill-switch entirely** (returns
//!   no filters). A bad LUID would make the egress-conditional Permit
//!   never match, turning the Block into an unconditional black hole for
//!   the protected set. Failing *open* on a bad LUID is the safe default;
//!   the wiring layer must only pass a LUID it actually resolved.
//!
//! The function is pure: same inputs → identical filters and identical
//! filter ids.

use std::net::{Ipv4Addr, Ipv6Addr};

use nrr_platform_api::fail_closed::is_exempt_from_blocking;
use nrr_platform_api::types::{WfpAction, WfpFilterSpec, WfpLayerKey};

use crate::wfp_codegen::filter_id_for;

/// Everything the kill-switch needs to know about the secondary (VPN)
/// interface for a SID, resolved fresh on every apply (block 16.18.vpn).
///
/// The per-destination kill-switch (mode A) uses only `secondary_luid`.
/// The catch-all kill-switch (mode B) additionally needs the system
/// exemptions so its block-everything-off-tunnel never traps the tunnel
/// itself, DHCP, the local router/DNS, or the LAN.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct KillSwitchResolution {
    /// LUID of the secondary (VPN) interface — the egress condition.
    pub secondary_luid: u64,
    /// VPN server IPs (bootstrap host-route destinations) to exempt so the
    /// tunnel can (re)establish. Empty → the catch-all must NOT arm.
    pub bootstrap_server_ips: Vec<Ipv4Addr>,
    /// Primary interface's connected subnets to exempt (LAN/DHCP/local DNS).
    pub local_subnets: Vec<(Ipv4Addr, u8)>,
}

/// Base weight of the kill-switch **Permit** half. Above
/// `BASE_PRIMARY` (`0x0020_0000`) so the egress-conditional permit
/// outranks the plain rule permit for the same destination.
const KILLSWITCH_PERMIT_BASE: u64 = 0x0040_0000;
/// Base weight of the kill-switch **Block** half. Above the rule bands
/// but below the kill-switch permit, so the permit wins while the secondary
/// adapter is up and the block wins the instant it is not.
const KILLSWITCH_BLOCK_BASE: u64 = 0x0030_0000;

/// Maximum number of protected destinations a single kill-switch plan
/// will emit. The two weight bands are `0x0010_0000` apart, so the
/// per-destination offset must stay below that to avoid the permit band
/// overflowing into the block band. The practical destination set
/// (resolved rule IPs / FQDN-cache fan-out) is far smaller; anything
/// beyond the cap is dropped rather than allowed to collide weights.
pub const KILLSWITCH_MAX_DESTINATIONS: usize = 0x000F_FFFF;

/// The pseudo-`role` slug stamped into kill-switch filter ids so they
/// never collide with rule-driven filters (which use `primary` /
/// `secondary` / `default`).
const KILLSWITCH_ROLE: &str = "killswitch";

/// Block D (fake-IP, slice 5) — weight of the fake-pool permit. Inside the
/// kill-switch permit band, near its top and far above the per-destination
/// permits (`KILLSWITCH_PERMIT_BASE + idx`, `idx` a small sequential count), so
/// it never collides with them while staying below the band ceiling. Above the
/// catch-all block, so an application can always reach the pool (and the TUN)
/// even under block-all.
const FAKEIP_POOL_PERMIT_BASE: u64 = KILLSWITCH_PERMIT_BASE + 0x000E_0000;

// ── Multi-protocol kill-switch ─────────────────────────────────

/// IP protocol numbers (IANA) the kill-switch can target individually.
const PROTO_ICMP: u8 = 1;
const PROTO_IGMP: u8 = 2;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_GRE: u8 = 47;
const PROTO_ESP: u8 = 50;

/// Packet-layer (`FWPM_LAYER_OUTBOUND_IPPACKET_V4`) weight bands. This layer
/// arbitrates SEPARATELY from the ALE connect layer, so the numeric space can
/// be reused. Within the packet layer the ordering (high to low) is exemption
/// permits, then permit-unselected, then blocks — so loopback / LAN / the
/// tunnel server and any UN-selected protocol always escape the block.
///
/// Each per-destination filter takes a 16-slot window (`idx * 16 + k`, k < 16 —
/// see [`packet_egress_pairs`]). The bands are spaced by more than
/// `KILLSWITCH_MAX_DESTINATIONS * 16` so that window can never carry a block up
/// into the permit/exempt band (a `const` assertion below enforces it). At the
/// previous tight spacing (`0x0030/0x0048/0x0050`) a block weight crossed the
/// permit base past ~98 304 destinations — harmless while every packet filter is
/// IP-scoped (each matches a different connection), but a latent unique-weight
/// violation the adversarial review flagged. Widening the bands closes it with
/// zero behavioural change (packet weights are layer-local).
const PACKET_EXEMPT_BASE: u64 = 0x0250_0000;
const PACKET_PERMIT_BASE: u64 = 0x0140_0000;
const PACKET_BLOCK_BASE: u64 = 0x0030_0000;

// Compile-time guard: the per-destination weight window (`idx * 16`, idx up to
// KILLSWITCH_MAX_DESTINATIONS) must fit inside each packet band gap so a block
// can never reach the permit/exempt band. Widen the bands or cap the packet
// destination count if this ever fails.
const _: () = {
    let window = (KILLSWITCH_MAX_DESTINATIONS as u64) * 16;
    assert!(
        window <= PACKET_PERMIT_BASE - PACKET_BLOCK_BASE
            && window <= PACKET_EXEMPT_BASE - PACKET_PERMIT_BASE,
        "packet-layer per-destination weight window overflows a band gap — widen \
         the packet bands or cap the packet destination count"
    );
};

/// Decoded protocol selection for the emergency block (the v16
/// `kill_switch_protocols` bitmask: TCP=1, UDP=2, ICMP=4, IGMP=8, GRE=16,
/// ESP=32, Other=64). TCP/UDP are enforced at the ALE connect layer; the rest
/// at the packet layer (the only place ICMP/ping is visible). "Other" =
/// every IP protocol not individually listed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KillSwitchProtocols {
    pub tcp: bool,
    pub udp: bool,
    pub icmp: bool,
    pub igmp: bool,
    pub gre: bool,
    pub esp: bool,
    pub other: bool,
}

impl KillSwitchProtocols {
    /// Block every protocol — the default (v16 column default `127`).
    pub const ALL: Self = Self {
        tcp: true,
        udp: true,
        icmp: true,
        igmp: true,
        gre: true,
        esp: true,
        other: true,
    };

    /// Decode the v16 bitmask. Unknown high bits are ignored.
    pub fn from_bits(bits: u16) -> Self {
        Self {
            tcp: bits & 0x01 != 0,
            udp: bits & 0x02 != 0,
            icmp: bits & 0x04 != 0,
            igmp: bits & 0x08 != 0,
            gre: bits & 0x10 != 0,
            esp: bits & 0x20 != 0,
            other: bits & 0x40 != 0,
        }
    }

    /// `true` when at least one protocol is selected (else the block is inert).
    fn any(self) -> bool {
        self.tcp || self.udp || self.icmp || self.igmp || self.gre || self.esp || self.other
    }

    /// Any TCP/UDP selected → emit an ALE-layer block.
    fn wants_ale_block(self) -> bool {
        self.tcp || self.udp
    }

    /// The single `ip_protocol` to narrow the ALE block to, or `None` when
    /// both (one block covers TCP+UDP) or neither are selected.
    fn ale_protocol(self) -> Option<u8> {
        match (self.tcp, self.udp) {
            (true, true) | (false, false) => None,
            (true, false) => Some(PROTO_TCP),
            (false, true) => Some(PROTO_UDP),
        }
    }

    /// Any non-TCP/UDP protocol selected → emit packet-layer filters.
    ///
    /// `other` no longer counts — the
    /// packet layer emits ONLY per-protocol blocks for the named set
    /// (ICMP/IGMP/GRE/ESP), never a protocol-agnostic block-all. The old
    /// "Other → block-all" was a SYSTEM-WIDE proto-agnostic block that cut
    /// TCP/UDP at the packet layer ABOVE every ALE verdict, so primary-route
    /// rule permits, the DNS exemption, the app exemptions and the service's
    /// own Mode-B resolver upstream (SYSTEM raw UDP) were all dead letters
    /// whenever "Other" was in the mask — which is the DEFAULT (127). TCP/UDP
    /// are enforced exclusively at the ALE connect layer (SID-scoped and
    /// permit/app/DNS-aware); the packet layer owns only what ALE cannot see.
    /// Trade-off accepted by the user: an exotic IP protocol outside the
    /// named set passes. The GUI "Other" checkbox needs re-labeling (P2).
    fn wants_packet_layer(self) -> bool {
        self.icmp || self.igmp || self.gre || self.esp
    }

    /// Named packet-layer protocols (not TCP/UDP) that ARE selected.
    fn packet_named(self) -> Vec<u8> {
        let mut v = Vec::new();
        if self.icmp {
            v.push(PROTO_ICMP);
        }
        if self.igmp {
            v.push(PROTO_IGMP);
        }
        if self.gre {
            v.push(PROTO_GRE);
        }
        if self.esp {
            v.push(PROTO_ESP);
        }
        v
    }
}

/// Base weight of the
/// catch-all **exemption permits**. Above every rule band AND the
/// per-destination kill-switch bands, so an exemption (egress via secondary adapter,
/// loopback, link-local, VPN server, LAN, broadcast) always wins.
const CATCHALL_EXEMPT_BASE: u64 = 0x0050_0000;
/// base weight of the **primary-app kill-switch exemption**.
/// Above `CATCHALL_EXEMPT_BASE` so a user's primary-routed app permit outranks
/// every other filter (including the catch-all exemptions) and can never share
/// a weight with them. `+ idx` (idx < `KILLSWITCH_MAX_DESTINATIONS`) stays below
/// the next `0x0010_0000` band, so it cannot bleed into any other band.
const APP_EXEMPT_BASE: u64 = 0x0060_0000;
// Compile-time guard: the primary-app exempt band must sit above the catch-all
// exemption band so a user's primary-routed app permit outranks everything —
// blocks AND the other exemptions.
const _: () = assert!(APP_EXEMPT_BASE > CATCHALL_EXEMPT_BASE);
/// Weight of the catch-all **Block**. Deliberately BETWEEN the secondary
/// rule band (`0x0010_0000`) and the primary rule band (`0x0020_0000`):
///
/// - primary rules (mode-B exceptions routed via the primary NIC) outrank
///   it → they keep working even off-tunnel;
/// - secondary rule permits lose to it → their destinations are blocked
///   rather than leaking off-tunnel when the secondary adapter is down.
const CATCHALL_BLOCK_WEIGHT: u64 = 0x0018_0000;

// ── DoH/DoT lockdown ────────────────────────────────────────────────────────

/// DoH-lockdown weight band. BETWEEN the primary rule band (`BASE_PRIMARY =
/// 0x0020_0000`) and the kill-switch block band (`0x0030_0000`): a DoH/DoT block
/// OUTRANKS a rule permit for the same resolver IP (so a zone/suffix rule that
/// happens to cover a resolver's hostname cannot let encrypted DNS through), but
/// stays BELOW the kill-switch permit / exemption bands (loopback, LAN, the VPN
/// server, primary-routed apps), so it never breaks the tunnel or an app the user
/// deliberately routes. Its own band, disjoint from the kill-switch blocks, so
/// the two never collide on a weight.
const DOH_BLOCK_BASE: u64 = 0x0028_0000;
/// Standard DoH (HTTPS) service port — a DoH endpoint is an HTTPS server.
const DOH_PORT: u16 = 443;
/// Standard DoT (DNS-over-TLS) / DoQ (DNS-over-QUIC) service port.
const DOT_PORT: u16 = 853;
/// Max resolver IPs the DoH lockdown will pin. Each IP takes 2 slots (TCP+UDP);
/// the band window (`0x0028..0x0030` = `0x0008_0000`) has ample room, this is a
/// runaway backstop.
pub const DOH_MAX_RESOLVER_IPS: usize = 0x0003_0000;

/// Build the DoH/DoT lockdown block filters for `sid`:
/// - per resolver IP: a `Block` on `443` for TCP and UDP (kills DoH / DoH-over-HTTP3
///   to that resolver without touching the resolver's plain DNS on 53 or general
///   web traffic to other hosts);
/// - when `block_dot`: a global `Block` on `853` for TCP and UDP (DoT / DoQ).
///
/// All filters are ALE-connect, SID-scoped, at [`DOH_BLOCK_BASE`]. Loopback /
/// link-local resolver IPs are skipped (never blocked). Emission order (per IP:
/// TCP then UDP; then the global DoT pair) fixes the ascending weights so the
/// neutral planner mirror reproduces the same arbitration order.
pub fn doh_dot_block_filters(
    sid: &str,
    resolver_ips: &[Ipv4Addr],
    block_dot: bool,
) -> Vec<WfpFilterSpec> {
    let mut filters = Vec::new();
    let mut weight = DOH_BLOCK_BASE;
    for ip in resolver_ips
        .iter()
        .copied()
        .filter(|ip| !is_exempt_from_blocking(*ip))
        .take(DOH_MAX_RESOLVER_IPS)
    {
        for proto in [PROTO_TCP, PROTO_UDP] {
            filters.push(doh_port_block(sid, Some(ip), DOH_PORT, proto, weight));
            weight += 1;
        }
    }
    if block_dot {
        for proto in [PROTO_TCP, PROTO_UDP] {
            filters.push(doh_port_block(sid, None, DOT_PORT, proto, weight));
            weight += 1;
        }
    }
    filters
}

/// One DoH/DoT block: ALE-connect `Block` narrowed to `(remote_ip?, port, proto)`.
fn doh_port_block(
    sid: &str,
    ip: Option<Ipv4Addr>,
    port: u16,
    proto: u8,
    weight: u64,
) -> WfpFilterSpec {
    let host_seg = ip
        .map(|i| i.to_string())
        .unwrap_or_else(|| "any".to_string());
    let tag = format!("{host_seg}-{port}-{proto}");
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Block,
        remote_ip: ip,
        remote_port: Some(port),
        weight,
        id: filter_id_for(sid, KILLSWITCH_ROLE, "", "ks-doh", &tag),
        user_sid: Some(sid.to_string()),
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: Some(proto),
    }
}

/// Build the leak-proof kill-switch filter pair for every protected
/// destination.
///
/// - `sid`: the user SID the filters are scoped to (stamped into
///   `user_sid` so `FWPM_CONDITION_ALE_USER_ID` matches only this
///   user's connections, exactly like the rule codegen).
/// - `protected_ips`: the destinations that must never leak off the
///   secondary interface. The caller (wiring slice) supplies the
///   resolved secondary-route IP set — *not* primary-exception IPs,
///   which are meant to use the primary adapter and must not be killed.
/// - `secondary_luid`: the LUID of the secondary (VPN) interface. A
///   value of `0` disables the kill-switch (see module "Safety valves").
///
/// Returns the filters in emission order: for each non-exempt
/// destination, its `Permit` then its `Block`. Loopback / link-local
/// destinations are skipped. Returns an empty vector when there is
/// nothing to protect or the LUID is unusable.
pub fn kill_switch_filters(
    sid: &str,
    protected_ips: &[Ipv4Addr],
    secondary_luid: u64,
    protocols: KillSwitchProtocols,
) -> Vec<WfpFilterSpec> {
    // Fail OPEN on an unusable LUID — a Block with a never-matching
    // egress-conditional Permit would black-hole the protected set.
    if secondary_luid == 0 {
        return Vec::new();
    }

    let mut filters = Vec::new();
    for (idx, ip) in protected_ips
        .iter()
        .copied()
        .filter(|ip| !is_exempt_from_blocking(*ip))
        .take(KILLSWITCH_MAX_DESTINATIONS)
        .enumerate()
    {
        let idx = idx as u64;
        // ALE pair (TCP/UDP at the connect layer) — only when TCP or UDP is
        // selected. (The pair is protocol-agnostic, so selecting just one of
        // TCP/UDP still blocks both — a minor over-block in a rare config.)
        if protocols.wants_ale_block() {
            filters.push(permit_via_secondary(sid, ip, secondary_luid, idx));
            filters.push(block_off_secondary(sid, ip, idx));
        }
        // 2a — packet-layer egress-conditional pairs so ICMP and
        // the other selected packet protocols are killed the instant the secondary
        // adapter drops (the ALE pair above only sees TCP/UDP). Scoped to this /32.
        filters.extend(packet_egress_pairs(
            sid,
            Some(ip),
            protocols,
            secondary_luid,
            idx,
        ));
    }
    filters
}

/// id segment folding the egress LUID into an
/// egress-conditional **permit's** filter id. A WFP filter is immutable by key
/// and the id → filterKey GUID is a pure function of the id, so without the LUID
/// in the id a secondary adapter reconnect (new LUID) mints a permit whose id/GUID collides
/// with the stale old-LUID permit — the add-only install then swallows it as a
/// duplicate and the dead-LUID permit sticks (legit secondary-adapter traffic blocked, fail-
/// safe). Folding the LUID in mints a fresh id per LUID so the reconcile
/// installs the new permit and reaps the old. **Block** ids deliberately omit
/// this (they carry no LUID) so they stay stable and keep the guard armed
/// through the make-before-break swap.
fn permit_luid_seg(luid: u64) -> String {
    format!("luid-{luid:016x}")
}

/// `Permit` half: allow `ip` **only while** the flow egresses
/// `secondary_luid`.
fn permit_via_secondary(sid: &str, ip: Ipv4Addr, secondary_luid: u64, idx: u64) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Permit,
        remote_ip: Some(ip),
        remote_port: None,
        weight: KILLSWITCH_PERMIT_BASE + idx,
        id: filter_id_for(
            sid,
            KILLSWITCH_ROLE,
            &permit_luid_seg(secondary_luid),
            "ks-permit",
            &ip.to_string(),
        ),
        user_sid: Some(sid.to_string()),
        app_pattern: None,
        local_interface_luid: Some(secondary_luid),
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

/// `Block` half: drop `ip` whenever the egress-conditional permit does
/// not match (i.e. the secondary adapter is down and the route fell back elsewhere).
fn block_off_secondary(sid: &str, ip: Ipv4Addr, idx: u64) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Block,
        remote_ip: Some(ip),
        remote_port: None,
        weight: KILLSWITCH_BLOCK_BASE + idx,
        id: filter_id_for(sid, KILLSWITCH_ROLE, "", "ks-block", &ip.to_string()),
        user_sid: Some(sid.to_string()),
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

// ── Per-app kill-switch ────────────────────────────────────────

/// Per-**app** leak-proof kill-switch. A secondary-routed application rule
/// installs an unconditional per-process Permit (wfp_codegen slot 0, no
/// interface condition) that routes ALL the app's traffic via the secondary.
/// Its *observed* destination `/32`s already get per-destination kill-switch
/// pairs, but the app's UN-observed destinations would still egress the primary
/// NIC if the secondary adapter dropped. This pins each protected app to the secondary LUID
/// with the same egress-conditional Permit/Block pair the per-destination
/// kill-switch uses — keyed on the app id (`ALE_APP_ID`) instead of a remote IP.
///
/// ALE connect layer only: `ALE_APP_ID` is not exposed at the packet layer, so
/// ICMP from a specific process cannot be egress-gated per-app (the app's
/// observed-destination `/32`s carry their own packet-layer pairs). Fails OPEN
/// on a zero LUID, exactly like [`kill_switch_filters`]. Emits nothing unless a
/// TCP/UDP protocol is selected (the ALE pair is protocol-agnostic).
pub fn app_kill_switch_filters(
    sid: &str,
    app_patterns: &[String],
    secondary_luid: u64,
    protocols: KillSwitchProtocols,
) -> Vec<WfpFilterSpec> {
    if secondary_luid == 0 || !protocols.wants_ale_block() {
        return Vec::new();
    }
    let mut filters = Vec::new();
    for (idx, pattern) in app_patterns
        .iter()
        .take(KILLSWITCH_MAX_DESTINATIONS)
        .enumerate()
    {
        let idx = idx as u64;
        filters.push(permit_app_via_secondary(sid, pattern, secondary_luid, idx));
        filters.push(block_app_off_secondary(sid, pattern, idx));
    }
    filters
}

/// Per-app `Permit` half: allow `pattern`'s process **only while** its flow
/// egresses `secondary_luid`. Sits in the same weight band as the
/// per-destination permit, above the unconditional per-process Permit
/// wfp_codegen emits (secondary band), so it governs the verdict.
fn permit_app_via_secondary(
    sid: &str,
    pattern: &str,
    secondary_luid: u64,
    idx: u64,
) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Permit,
        remote_ip: None,
        remote_port: None,
        weight: KILLSWITCH_PERMIT_BASE + idx,
        id: filter_id_for(
            sid,
            KILLSWITCH_ROLE,
            &permit_luid_seg(secondary_luid),
            "ks-app-permit",
            pattern,
        ),
        user_sid: Some(sid.to_string()),
        app_pattern: Some(pattern.to_string()),
        local_interface_luid: Some(secondary_luid),
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

/// Per-app `Block` half: drop `pattern`'s process whenever its egress-
/// conditional permit does not match (secondary adapter down / off-tunnel fallback). Above
/// the per-process Permit's secondary band, below the app permit.
fn block_app_off_secondary(sid: &str, pattern: &str, idx: u64) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Block,
        remote_ip: None,
        remote_port: None,
        weight: KILLSWITCH_BLOCK_BASE + idx,
        id: filter_id_for(sid, KILLSWITCH_ROLE, "", "ks-app-block", pattern),
        user_sid: Some(sid.to_string()),
        app_pattern: Some(pattern.to_string()),
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

// ── Primary-app kill-switch exemption (HW-0712 C4) ──────────────────────────

/// Built-in default VPN-client exemption patterns, always applied on the primary
/// adapter (HW-0712 C4, user request). A VPN client must reach its server over
/// the physical/primary link to bring the tunnel up; if the kill-switch blocks
/// that handshake the tunnel never comes up and the secondary stays down —
/// a fail-closed deadlock. Exempting common VPN clients out of the box prevents
/// it with zero configuration; the user can add their own via primary app rules.
///
/// Patterns are OS-neutral case-insensitive globs (matched by the platform app
/// resolver's `glob_match`). `*vpn*` covers most branded clients (NordVPN,
/// ProtonVPN, ExpressVPN, hidemy.name VPN, …); the rest name clients that lack
/// "vpn" in their executable. This is neutral policy DATA co-located with the
/// emitter — the OS-specific `.exe` handling lives in the Windows resolver.
///
/// these are GLOBS, and the WFP `ALE_APP_ID` condition
/// keys on a real on-disk file path (`FwpmGetAppIdFromFileName0`), NOT a glob.
/// A glob stamped verbatim into a filter's `app_pattern` is therefore silently
/// dropped by the apply layer and NO permit installs — which used to trap a VPN
/// under its own kill-switch. They must be RESOLVED to concrete exe paths through
/// the injected `AppPathResolver` (`wfp_codegen::generate_filters` →
/// `CodegenOutput::vpn_default_exempt_paths`) before reaching
/// [`primary_app_exempt_filters`]. Never pass these raw to the enforcement layer.
pub const DEFAULT_VPN_EXEMPT_PATTERNS: &[&str] = &[
    "*vpn*",
    "openvpn*",
    "wireguard*",
    "wg",
    "mullvad*",
    "openconnect",
    "softether*",
    "tunnelbear*",
    "windscribe*",
    "hide.me*",
    "hidemy.name*",
    "amnezia*",
    "outline*",
    "warp-svc",
    "cloudflare warp",
    "tailscale*",
    "zerotier*",
];

/// Kill-switch EXEMPTION for apps the user routed to the **primary** adapter.
///
/// Emits one unconditional ALE `Permit` per app pattern at the exempt weight
/// band ([`APP_EXEMPT_BASE`]), so it OUTRANKS every kill-switch / fail-closed /
/// block-all filter. The permit carries no remote-IP and no interface condition,
/// so the app's TCP/UDP egress is allowed over ANY link — crucially the primary —
/// even while the secondary adapter is down and the block is engaged.
///
/// Rationale: fail-closed exists to stop LEAKS over the unprotected path; an app
/// the user *deliberately* routes to the primary adapter is not a leak, so the
/// kill-switch must never cut it. This is the VPN-bootstrap fix — put the VPN
/// client on the primary adapter and its handshake to its server is never
/// blocked, so the tunnel can come up (no fail-closed deadlock).
///
/// ALE connect layer only: `ALE_APP_ID` is not exposed at the packet layer, so a
/// per-app ICMP exemption is not possible (VPN bootstrap is TCP/UDP, so this is
/// sufficient). There is no `Block` half — this is a pure exemption.
pub fn primary_app_exempt_filters(sid: &str, app_patterns: &[String]) -> Vec<WfpFilterSpec> {
    app_patterns
        .iter()
        .take(KILLSWITCH_MAX_DESTINATIONS)
        .enumerate()
        .map(|(idx, pattern)| exempt_primary_app(sid, pattern, idx as u64))
        .collect()
}

fn exempt_primary_app(sid: &str, pattern: &str, idx: u64) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Permit,
        remote_ip: None,
        remote_port: None,
        weight: APP_EXEMPT_BASE + idx,
        id: filter_id_for(sid, KILLSWITCH_ROLE, "", "ks-app-exempt", pattern),
        user_sid: Some(sid.to_string()),
        app_pattern: Some(pattern.to_string()),
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

// ── Catch-all kill-switch (mode B) ──────────────────────────────────────────

/// Build the **catch-all** kill-switch filter set for mode B
/// (everything-via-secondary). When the secondary adapter is up, all traffic egresses the
/// tunnel and is permitted; when it drops, the catch-all block drops
/// everything that isn't an exemption — with no race.
///
/// The ALE connect layer (TCP/UDP) filter set is, by weight (high → low):
/// 1. exemption permits at [`CATCHALL_EXEMPT_BASE`] (egress via secondary adapter,
///    loopback `127.0.0.0/8`, link-local `169.254.0.0/16`, limited
///    broadcast, each VPN server, each primary local subnet);
/// 2. (the rule codegen's primary-rule permits at `0x0020_0000` — the
///    mode-B exceptions — sit above the block and so still escape);
/// 3. the catch-all `Block` at [`CATCHALL_BLOCK_WEIGHT`];
/// 4. (the rule codegen's secondary-rule permits at `0x0010_0000` lose
///    to the block).
///
/// the ALE layer only sees TCP/UDP connects, so ICMP
/// (ping) would leak past it. When the protocol mask selects any packet-layer
/// protocol a mirror set at `OUTBOUND_IPPACKET_V4` is appended — an egress-via-
/// secondary permit, the same exemptions, and the protocol-narrowed block — so ping
/// is caught too. Packet-layer filters carry `user_sid = None` (that layer has
/// no `ALE_USER_ID`); the ALE filters remain scoped to `sid`.
///
/// Fails **open** (returns no filters) when the LUID is unusable, there are no
/// VPN server IPs to exempt (arming a block-everything filter without a server
/// exemption would trap the tunnel's own reconnection), *or* the protocol mask
/// is empty.
pub fn catch_all_kill_switch_filters(
    sid: &str,
    resolution: &KillSwitchResolution,
    protocols: KillSwitchProtocols,
) -> Vec<WfpFilterSpec> {
    if resolution.secondary_luid == 0
        || resolution.bootstrap_server_ips.is_empty()
        || !protocols.any()
    {
        return Vec::new();
    }

    let mut filters: Vec<WfpFilterSpec> = Vec::new();
    let mut weight = CATCHALL_EXEMPT_BASE;

    // #1 — permit everything that egresses via the secondary adapter.
    filters.push(exempt_egress(sid, resolution.secondary_luid, weight));
    weight += 1;
    // #2 — loopback (local IPC, the GUI↔service pipe, DNS stub resolvers).
    filters.push(exempt_subnet(sid, Ipv4Addr::new(127, 0, 0, 0), 8, weight));
    weight += 1;
    // #3 — link-local / APIPA.
    filters.push(exempt_subnet(
        sid,
        Ipv4Addr::new(169, 254, 0, 0),
        16,
        weight,
    ));
    weight += 1;
    // #6 — limited broadcast (DHCP discover/request).
    filters.push(exempt_host(sid, Ipv4Addr::BROADCAST, weight));
    weight += 1;
    // #4 — the VPN server(s), so the tunnel can (re)establish.
    for ip in &resolution.bootstrap_server_ips {
        filters.push(exempt_host(sid, *ip, weight));
        weight += 1;
    }
    // #5 — the primary interface's connected subnets (LAN, DHCP unicast,
    // local router/DNS).
    for (net, prefix) in &resolution.local_subnets {
        filters.push(exempt_subnet(sid, *net, *prefix, weight));
        weight += 1;
    }
    // The catch-all block — everything else this user sends off-tunnel.
    filters.push(catch_all_block(sid));

    // ── Transport layer (ICMP/IGMP/GRE/ESP — incl. ping) ──
    // The ALE catch-all above only sees TCP/UDP
    // connects; ICMP/ping is invisible there and would leak out the primary
    // when the secondary adapter drops. HW-0718: the named-protocol blocks
    // (and therefore the whole mirrored exemption set that shields them) live
    // at OUTBOUND_TRANSPORT_V4 — the packet layer has no IP_PROTOCOL
    // condition, so the previous packet-layer set silently never installed
    // its blocks. Topped by an egress-conditional permit so anything leaving
    // the tunnel is allowed while the secondary adapter is up and the block
    // bites the instant it drops. Skipped when the user's protocol mask
    // selects no packet-layer protocol.
    if protocols.wants_packet_layer() {
        const TR: WfpLayerKey = WfpLayerKey::OutboundTransportV4;
        let mut pw = PACKET_EXEMPT_BASE;
        // Permit anything egressing the secondary adapter (protocol-agnostic), highest weight.
        filters.push(packet_egress_permit(
            sid,
            TR,
            None,
            None,
            resolution.secondary_luid,
            pw,
        ));
        pw += 1;
        filters.push(packet_exempt_subnet(
            sid,
            TR,
            Ipv4Addr::new(127, 0, 0, 0),
            8,
            pw,
        ));
        pw += 1;
        filters.push(packet_exempt_subnet(
            sid,
            TR,
            Ipv4Addr::new(169, 254, 0, 0),
            16,
            pw,
        ));
        pw += 1;
        filters.push(packet_exempt_host(sid, TR, Ipv4Addr::BROADCAST, pw));
        pw += 1;
        for ip in &resolution.bootstrap_server_ips {
            filters.push(packet_exempt_host(sid, TR, *ip, pw));
            pw += 1;
        }
        for (net, prefix) in &resolution.local_subnets {
            filters.push(packet_exempt_subnet(sid, TR, *net, *prefix, pw));
            pw += 1;
        }
        filters.extend(packet_protocol_blocks(sid, None, protocols, 0));
    }

    // ── IPv6 (Free's only IPv6 handling) ──
    // Whenever the catch-all arms, cut ALL outbound IPv6 too (except loopback +
    // link-local), independent of the V4 protocol mask above. Selective per-IP
    // V6 needs AAAA (Pro); the catch-all just closes the IPv6 leak entirely.
    filters.extend(catch_all_v6_filters(sid));

    filters
}

/// Exemption permit: allow any flow egressing the secondary adapter interface.
fn exempt_egress(sid: &str, secondary_luid: u64, weight: u64) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Permit,
        remote_ip: None,
        remote_port: None,
        weight,
        id: filter_id_for(
            sid,
            KILLSWITCH_ROLE,
            &permit_luid_seg(secondary_luid),
            "ks-ca-egress",
            "secondary",
        ),
        user_sid: Some(sid.to_string()),
        app_pattern: None,
        local_interface_luid: Some(secondary_luid),
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

/// Exemption permit for a remote subnet (loopback / link-local / LAN).
fn exempt_subnet(sid: &str, net: Ipv4Addr, prefix_len: u8, weight: u64) -> WfpFilterSpec {
    let target = format!("{net}/{prefix_len}");
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Permit,
        remote_ip: None,
        remote_port: None,
        weight,
        id: filter_id_for(sid, KILLSWITCH_ROLE, "", "ks-ca-subnet", &target),
        user_sid: Some(sid.to_string()),
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: Some((net, prefix_len)),
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

/// Block D (fake-IP, slice 5) — permit the user's connections into the fake pool.
///
/// When fake-IP is on, an application reaches a scope host by connecting to its
/// FAKE address (out of the pool), which the OS routes into the TUN. Under a
/// catch-all block-all the pool is just another "unknown" destination, so
/// without this the app could never reach the TUN. This permit — in the
/// kill-switch permit band, above the catch-all block — carves the whole pool
/// open for the user SID. Emit it only while fake-IP is enabled.
///
/// Per-user-SID like every kill-switch filter, and the pool is non-routable
/// (RFC 2544 / ULA) terminating at our own TUN, so it widens nothing real.
/// Returns the v4 permit, plus the v6 permit when the pool has a v6 range,
/// plus the pool-wide UDP block pair when `udp_relay_enabled` is `false`
/// (the default).
#[must_use]
pub fn fake_ip_pool_permit_filters(
    sid: &str,
    pool: &nrr_platform_api::fake_ip::FakeIpPoolConfig,
    udp_relay_enabled: bool,
) -> Vec<WfpFilterSpec> {
    let mut filters = vec![WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Permit,
        remote_ip: None,
        remote_port: None,
        weight: FAKEIP_POOL_PERMIT_BASE,
        id: filter_id_for(sid, KILLSWITCH_ROLE, "", "ks-fakeip-pool", "v4"),
        user_sid: Some(sid.to_string()),
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: Some((pool.v4_base, pool.v4_prefix_len)),
        remote_subnet_v6: None,
        ip_protocol: None,
    }];
    if let Some(v6_base) = pool.v6_base {
        filters.push(WfpFilterSpec {
            layer: WfpLayerKey::AleAuthConnectV6,
            action: WfpAction::Permit,
            remote_ip: None,
            remote_port: None,
            weight: FAKEIP_POOL_PERMIT_BASE + 1,
            id: filter_id_for(sid, KILLSWITCH_ROLE, "", "ks-fakeip-pool", "v6"),
            user_sid: Some(sid.to_string()),
            app_pattern: None,
            local_interface_luid: None,
            remote_subnet: None,
            remote_subnet_v6: Some((v6_base, pool.v6_prefix_len)),
            ip_protocol: None,
        });
    }
    // While the UDP relay setting is off (the default), hard-block UDP into
    // the pool so a QUIC attempt dies at connect time and the browser falls
    // straight back to TCP, instead of handshaking against a stack that reads
    // and drops datagrams until the protocol times out. The block's hard veto
    // outranks the pool permit above by design. When the user turns the
    // setting on, these blocks are omitted and QUIC/HTTP-3 rides the relay's
    // TUN stack the same way TCP already does.
    if !udp_relay_enabled {
        filters.push(WfpFilterSpec {
            layer: WfpLayerKey::AleAuthConnectV4,
            action: WfpAction::Block,
            remote_ip: None,
            remote_port: None,
            weight: FAKEIP_POOL_PERMIT_BASE + 2,
            id: filter_id_for(sid, KILLSWITCH_ROLE, "", "ks-fakeip-pool", "udp4"),
            user_sid: Some(sid.to_string()),
            app_pattern: None,
            local_interface_luid: None,
            remote_subnet: Some((pool.v4_base, pool.v4_prefix_len)),
            remote_subnet_v6: None,
            ip_protocol: Some(PROTO_UDP),
        });
        if let Some(v6_base) = pool.v6_base {
            filters.push(WfpFilterSpec {
                layer: WfpLayerKey::AleAuthConnectV6,
                action: WfpAction::Block,
                remote_ip: None,
                remote_port: None,
                weight: FAKEIP_POOL_PERMIT_BASE + 3,
                id: filter_id_for(sid, KILLSWITCH_ROLE, "", "ks-fakeip-pool", "udp6"),
                user_sid: Some(sid.to_string()),
                app_pattern: None,
                local_interface_luid: None,
                remote_subnet: None,
                remote_subnet_v6: Some((v6_base, pool.v6_prefix_len)),
                ip_protocol: Some(PROTO_UDP),
            });
        }
    }
    filters
}

/// Exemption permit for an exact remote host (VPN server / broadcast).
fn exempt_host(sid: &str, ip: Ipv4Addr, weight: u64) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Permit,
        remote_ip: Some(ip),
        remote_port: None,
        weight,
        id: filter_id_for(sid, KILLSWITCH_ROLE, "", "ks-ca-host", &ip.to_string()),
        user_sid: Some(sid.to_string()),
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

/// ALE exempt for a KNOWN-DIRECT destination under the
/// catch-all block-all (see [`FailClosedExemptions::known_direct_ips`]).
/// Distinct id kind from [`exempt_host`] so an IP that is also a bootstrap
/// VPN server does not collide filter ids in one desired set.
fn exempt_direct_host(sid: &str, ip: Ipv4Addr, weight: u64) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Permit,
        remote_ip: Some(ip),
        remote_port: None,
        weight,
        id: filter_id_for(
            sid,
            KILLSWITCH_ROLE,
            "",
            "ks-ca-direct-host",
            &ip.to_string(),
        ),
        user_sid: Some(sid.to_string()),
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

/// ALE exempt for a liveness-probe target (the secondary tunnel's next-hop) —
/// see [`FailClosedExemptions::probe_target_ips`]. Distinct id kind from
/// [`exempt_host`] / [`exempt_direct_host`] so overlapping IPs keep distinct
/// filter ids in one desired set.
fn exempt_probe_target(sid: &str, ip: Ipv4Addr, weight: u64) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Permit,
        remote_ip: Some(ip),
        remote_port: None,
        weight,
        id: filter_id_for(
            sid,
            KILLSWITCH_ROLE,
            "",
            "ks-ca-probe-host",
            &ip.to_string(),
        ),
        user_sid: Some(sid.to_string()),
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

/// port-scoped exemption permits for outbound DNS (remote port
/// 53, UDP + TCP) at the ALE connect layer, so name resolution keeps working over
/// the PRIMARY link while the catch-all block-all is engaged. Opt-in only (see
/// [`FailClosedExemptions::allow_dns_over_primary`]); narrowed to port 53 so it is
/// not a full-host tunnel. Returns two specs (UDP then TCP).
fn exempt_dns_over_primary(sid: &str, base_weight: u64) -> Vec<WfpFilterSpec> {
    const IP_PROTO_UDP: u8 = 17;
    const IP_PROTO_TCP: u8 = 6;
    [(IP_PROTO_UDP, "udp53"), (IP_PROTO_TCP, "tcp53")]
        .into_iter()
        .enumerate()
        .map(|(i, (proto, tag))| WfpFilterSpec {
            layer: WfpLayerKey::AleAuthConnectV4,
            action: WfpAction::Permit,
            remote_ip: None,
            remote_port: Some(53),
            weight: base_weight + i as u64,
            id: filter_id_for(sid, KILLSWITCH_ROLE, "", "ks-ca-dns", tag),
            user_sid: Some(sid.to_string()),
            app_pattern: None,
            local_interface_luid: None,
            remote_subnet: None,
            remote_subnet_v6: None,
            ip_protocol: Some(proto),
        })
        .collect()
}

/// The catch-all block: drop every off-tunnel flow this user makes that no
/// higher-weight exemption or primary-rule permit covered.
fn catch_all_block(sid: &str) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Block,
        remote_ip: None,
        remote_port: None,
        weight: CATCHALL_BLOCK_WEIGHT,
        id: filter_id_for(sid, KILLSWITCH_ROLE, "", "ks-ca-block", "block-all"),
        user_sid: Some(sid.to_string()),
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

// ── IPv6 catch-all coverage (Free's only IPv6 handling) ─────────────────────
//
// Free does no IPv6 routing (selective per-destination V6 needs AAAA — a Pro
// feature), so the only IPv6 the product ever touches is this: whenever a
// catch-all block arms, ALL outbound IPv6 is cut too, except loopback
// (`::1/128`) and link-local (`fe80::/10`). It mirrors the V4
// exemption-permit-over-block-all pattern at the two IPv6 WFP layers (ALE
// connect for TCP/UDP, packet for ICMPv6/etc.). The exemption/block weight
// bands are reused from V4 — the V6 layers arbitrate SEPARATELY, so there is no
// cross-layer weight collision.

/// IPv6 loopback `::1/128` — exempt (local IPC / stub resolvers over v6).
const V6_LOOPBACK: Ipv6Addr = Ipv6Addr::LOCALHOST;
/// IPv6 link-local base `fe80::` (paired with `/10`) — exempt (SLAAC/NDP/mDNS).
const V6_LINK_LOCAL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0);

/// Emit the IPv6 half of a catch-all block: loopback + link-local exemption
/// permits over an unconditional block-all, at BOTH the V6 ALE-connect and V6
/// packet layers. ALE-layer filters are scoped to `sid` (the V6 ALE layer
/// exposes `ALE_USER_ID`); packet-layer filters carry `user_sid = None` (no ALE
/// id there — the same caveat as the V4 packet layer). Distinct id seeds per
/// (layer, target) so every filter gets a unique UUID.
fn catch_all_v6_filters(sid: &str) -> Vec<WfpFilterSpec> {
    vec![
        // ── V6 ALE connect layer (TCP/UDP over IPv6) ──
        exempt_subnet_v6(
            sid,
            WfpLayerKey::AleAuthConnectV6,
            V6_LOOPBACK,
            128,
            CATCHALL_EXEMPT_BASE,
        ),
        exempt_subnet_v6(
            sid,
            WfpLayerKey::AleAuthConnectV6,
            V6_LINK_LOCAL,
            10,
            CATCHALL_EXEMPT_BASE + 1,
        ),
        block_all_v6(sid, WfpLayerKey::AleAuthConnectV6),
        // ── V6 packet layer (ICMPv6 / everything else) ──
        exempt_subnet_v6(
            sid,
            WfpLayerKey::OutboundIpPacketV6,
            V6_LOOPBACK,
            128,
            PACKET_EXEMPT_BASE,
        ),
        exempt_subnet_v6(
            sid,
            WfpLayerKey::OutboundIpPacketV6,
            V6_LINK_LOCAL,
            10,
            PACKET_EXEMPT_BASE + 1,
        ),
        block_all_v6(sid, WfpLayerKey::OutboundIpPacketV6),
    ]
}

/// IPv6 exemption permit for a remote subnet (loopback / link-local) at the
/// given V6 layer. Packet-layer filters carry `user_sid = None`.
fn exempt_subnet_v6(
    sid: &str,
    layer: WfpLayerKey,
    net: Ipv6Addr,
    prefix_len: u8,
    weight: u64,
) -> WfpFilterSpec {
    let is_packet = matches!(layer, WfpLayerKey::OutboundIpPacketV6);
    // The filter id seed excludes the layer, so the ALE and packet twins MUST
    // use distinct kind tags or their UUIDs collide (add-only install would
    // swallow one as a duplicate).
    let kind = if is_packet {
        "ks-ca-subnet-v6-pkt"
    } else {
        "ks-ca-subnet-v6-ale"
    };
    WfpFilterSpec {
        layer,
        action: WfpAction::Permit,
        remote_ip: None,
        remote_port: None,
        weight,
        id: filter_id_for(
            sid,
            KILLSWITCH_ROLE,
            "",
            kind,
            &format!("{net}/{prefix_len}"),
        ),
        user_sid: if is_packet {
            None
        } else {
            Some(sid.to_string())
        },
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: Some((net, prefix_len)),
        ip_protocol: None,
    }
}

/// IPv6 catch-all block-all (no conditions) at the given V6 layer. Its weight
/// mirrors the V4 block band for that layer. Packet-layer filters carry
/// `user_sid = None`.
fn block_all_v6(sid: &str, layer: WfpLayerKey) -> WfpFilterSpec {
    let is_packet = matches!(layer, WfpLayerKey::OutboundIpPacketV6);
    let (weight, kind) = if is_packet {
        (PACKET_BLOCK_BASE, "ks-ca-block-v6-pkt")
    } else {
        (CATCHALL_BLOCK_WEIGHT, "ks-ca-block-v6-ale")
    };
    WfpFilterSpec {
        layer,
        action: WfpAction::Block,
        remote_ip: None,
        remote_port: None,
        weight,
        id: filter_id_for(sid, KILLSWITCH_ROLE, "", kind, "block-all"),
        user_sid: if is_packet {
            None
        } else {
            Some(sid.to_string())
        },
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

// ── Fail-closed (block 16.18.vpn — failure posture) ─────────────────────────

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
    /// Primary interface's connected subnets (LAN / DHCP unicast / local
    /// router / local DNS) to exempt so the machine stays reachable.
    pub local_subnets: Vec<(Ipv4Addr, u8)>,
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
    /// (habr.com, HW-0721) dies with the tunnel it never used. The caller has
    /// already subtracted anything secondary-destined.
    pub known_direct_ips: Vec<Ipv4Addr>,
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
    protected_ips: &[Ipv4Addr],
    protocols: KillSwitchProtocols,
) -> Vec<WfpFilterSpec> {
    if !protocols.any() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (idx, ip) in protected_ips
        .iter()
        .copied()
        .filter(|ip| !is_exempt_from_blocking(*ip))
        .take(KILLSWITCH_MAX_DESTINATIONS)
        .enumerate()
    {
        let idx = idx as u64;
        if protocols.wants_ale_block() {
            out.push(ale_block(
                sid,
                Some(ip),
                protocols.ale_protocol(),
                KILLSWITCH_BLOCK_BASE + idx,
            ));
        }
        out.extend(packet_protocol_blocks(sid, Some(ip), protocols, idx));
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
        .take(KILLSWITCH_MAX_DESTINATIONS)
        .enumerate()
        .map(|(idx, pattern)| ale_block_app(sid, pattern, KILLSWITCH_BLOCK_BASE + idx as u64))
        .collect()
}

/// ALE-layer block keyed on an app id (mirrors [`ale_block`] for the per-app
/// fail-closed path). Protocol-agnostic (covers TCP+UDP).
fn ale_block_app(sid: &str, pattern: &str, weight: u64) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Block,
        remote_ip: None,
        remote_port: None,
        weight,
        id: filter_id_for(sid, KILLSWITCH_ROLE, "", "ks-app-fc-block", pattern),
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

    // ── ALE connect layer exemptions (TCP/UDP) ──
    // Loopback (local IPC, the GUI↔service pipe, DNS stub resolvers).
    filters.push(exempt_subnet(sid, Ipv4Addr::new(127, 0, 0, 0), 8, weight));
    weight += 1;
    // Link-local / APIPA.
    filters.push(exempt_subnet(
        sid,
        Ipv4Addr::new(169, 254, 0, 0),
        16,
        weight,
    ));
    weight += 1;
    // Limited broadcast (DHCP discover/request).
    filters.push(exempt_host(sid, Ipv4Addr::BROADCAST, weight));
    weight += 1;
    // Known VPN server(s), so the tunnel can (re)establish.
    for ip in &exemptions.bootstrap_server_ips {
        filters.push(exempt_host(sid, *ip, weight));
        weight += 1;
    }
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
            None,
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
        filters.push(packet_exempt_subnet(
            sid,
            TR,
            Ipv4Addr::new(127, 0, 0, 0),
            8,
            pw,
        ));
        pw += 1;
        filters.push(packet_exempt_subnet(
            sid,
            TR,
            Ipv4Addr::new(169, 254, 0, 0),
            16,
            pw,
        ));
        pw += 1;
        filters.push(packet_exempt_host(sid, TR, Ipv4Addr::BROADCAST, pw));
        pw += 1;
        for ip in &exemptions.bootstrap_server_ips {
            filters.push(packet_exempt_host(sid, TR, *ip, pw));
            pw += 1;
        }
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
        filters.extend(packet_protocol_blocks(sid, None, protocols, 0));
    }

    // ── IPv6 (Free's only IPv6 handling) ──
    // The secondary is gone, so cut ALL outbound IPv6 too (except loopback +
    // link-local), independent of the V4 protocol mask above.
    filters.extend(catch_all_v6_filters(sid));

    filters
}

// ── Protocol-aware filter builders (multi-protocol kill-switch) ──────────────

/// Build a scope/protocol key for a packet- or ALE-layer filter id.
/// `scope = None` → "all"; `proto = None` → "any".
fn proto_scope_key(scope: Option<Ipv4Addr>, proto: Option<u8>) -> String {
    let s = scope.map(|i| i.to_string()).unwrap_or_else(|| "all".into());
    let p = proto.map(|p| p.to_string()).unwrap_or_else(|| "any".into());
    format!("{s}-{p}")
}

/// ALE-layer block, optionally narrowed to one IP protocol (TCP/UDP). Scoped to
/// `sid` (ALE exposes `ALE_USER_ID`). `scope = None` blocks all destinations.
fn ale_block(sid: &str, scope: Option<Ipv4Addr>, proto: Option<u8>, weight: u64) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Block,
        remote_ip: scope,
        remote_port: None,
        weight,
        id: filter_id_for(
            sid,
            KILLSWITCH_ROLE,
            "",
            "ks-ale-block",
            &proto_scope_key(scope, proto),
        ),
        user_sid: Some(sid.to_string()),
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: proto,
    }
}

/// Below-ALE block at `layer`. ⚠ Neither the packet layer nor the transport
/// layer exposes `ALE_USER_ID`, so `user_sid` MUST be `None` (system-wide);
/// the id is still seeded with `sid` for uniqueness + cleanup tracking.
///
/// a protocol-narrowed block (`proto = Some`) MUST target
/// [`WfpLayerKey::OutboundTransportV4`] — the IPPACKET layers have no
/// `FWPM_CONDITION_IP_PROTOCOL` and `FwpmFilterAdd0` rejects the filter with
/// `FWP_E_CONDITION_NOT_FOUND` (every named-protocol kill-switch block
/// silently failed to install from  until this fix). The kind tag
/// is layer-specific so a transport filter never collides UUIDs with a
/// historically-installed packet-layer twin.
fn packet_block(
    sid: &str,
    layer: WfpLayerKey,
    scope: Option<Ipv4Addr>,
    proto: Option<u8>,
    weight: u64,
) -> WfpFilterSpec {
    let kind = if layer == WfpLayerKey::OutboundTransportV4 {
        "ks-tr-block"
    } else {
        "ks-pkt-block"
    };
    WfpFilterSpec {
        layer,
        action: WfpAction::Block,
        remote_ip: scope,
        remote_port: None,
        weight,
        id: filter_id_for(
            sid,
            KILLSWITCH_ROLE,
            "",
            kind,
            &proto_scope_key(scope, proto),
        ),
        user_sid: None,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: proto,
    }
}

/// Below-ALE exemption permit for a remote subnet (loopback / link-local /
/// LAN) at `layer`. Protocol-agnostic. `user_sid = None` (no ALE ids below
/// the ALE layers). Layer-specific kind tag — see [`packet_block`].
fn packet_exempt_subnet(
    sid: &str,
    layer: WfpLayerKey,
    net: Ipv4Addr,
    prefix_len: u8,
    weight: u64,
) -> WfpFilterSpec {
    let kind = if layer == WfpLayerKey::OutboundTransportV4 {
        "ks-tr-exempt-net"
    } else {
        "ks-pkt-exempt-net"
    };
    WfpFilterSpec {
        layer,
        action: WfpAction::Permit,
        remote_ip: None,
        remote_port: None,
        weight,
        id: filter_id_for(
            sid,
            KILLSWITCH_ROLE,
            "",
            kind,
            &format!("{net}/{prefix_len}"),
        ),
        user_sid: None,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: Some((net, prefix_len)),
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

/// Below-ALE exemption permit for an exact remote host (VPN server /
/// broadcast) at `layer`. Protocol-agnostic. `user_sid = None` (no ALE ids
/// below the ALE layers). Layer-specific kind tag — see [`packet_block`].
fn packet_exempt_host(sid: &str, layer: WfpLayerKey, ip: Ipv4Addr, weight: u64) -> WfpFilterSpec {
    let kind = if layer == WfpLayerKey::OutboundTransportV4 {
        "ks-tr-exempt-host"
    } else {
        "ks-pkt-exempt-host"
    };
    WfpFilterSpec {
        layer,
        action: WfpAction::Permit,
        remote_ip: Some(ip),
        remote_port: None,
        weight,
        id: filter_id_for(sid, KILLSWITCH_ROLE, "", kind, &ip.to_string()),
        user_sid: None,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

/// below-ALE proto-agnostic permit for a
/// known-primary destination host under a fail-closed block-all, at `layer`.
/// Distinct id kind from [`packet_exempt_host`] so a primary IP that happens
/// to equal a VPN-server IP does not collide filter ids. `user_sid = None`
/// (no ALE ids below the ALE layers). Layer-specific kind tag — see
/// [`packet_block`].
fn packet_permit_primary_host(
    sid: &str,
    layer: WfpLayerKey,
    ip: Ipv4Addr,
    weight: u64,
) -> WfpFilterSpec {
    let kind = if layer == WfpLayerKey::OutboundTransportV4 {
        "ks-tr-primary-host"
    } else {
        "ks-pkt-primary-host"
    };
    packet_permit_host_with_kind(sid, layer, ip, weight, kind)
}

/// packet-layer permit for a KNOWN-DIRECT destination.
/// Same shape as [`packet_permit_primary_host`] with its own id kind so a
/// destination that is both known-primary and known-direct keeps distinct ids.
fn packet_permit_direct_host(
    sid: &str,
    layer: WfpLayerKey,
    ip: Ipv4Addr,
    weight: u64,
) -> WfpFilterSpec {
    let kind = if layer == WfpLayerKey::OutboundTransportV4 {
        "ks-tr-direct-host"
    } else {
        "ks-pkt-direct-host"
    };
    packet_permit_host_with_kind(sid, layer, ip, weight, kind)
}

/// Packet-layer proto-agnostic permit for a liveness-probe target — the twin
/// of [`exempt_probe_target`] at the layer where the ICMP echo is actually
/// classified (the ALE block is TCP/UDP-narrowed; the named packet blocks are
/// what eat ICMP). Own id kind so overlapping IPs keep distinct ids.
fn packet_permit_probe_target(
    sid: &str,
    layer: WfpLayerKey,
    ip: Ipv4Addr,
    weight: u64,
) -> WfpFilterSpec {
    let kind = if layer == WfpLayerKey::OutboundTransportV4 {
        "ks-tr-probe-host"
    } else {
        "ks-pkt-probe-host"
    };
    packet_permit_host_with_kind(sid, layer, ip, weight, kind)
}

fn packet_permit_host_with_kind(
    sid: &str,
    layer: WfpLayerKey,
    ip: Ipv4Addr,
    weight: u64,
    kind: &str,
) -> WfpFilterSpec {
    WfpFilterSpec {
        layer,
        action: WfpAction::Permit,
        remote_ip: Some(ip),
        remote_port: None,
        weight,
        id: filter_id_for(sid, KILLSWITCH_ROLE, "", kind, &ip.to_string()),
        user_sid: None,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

/// The named-protocol block set for one scope (`Some(ip)` = a /32 in mode A;
/// `None` = block-all in mode B), narrowed to `protocols`: one block per
/// selected named packet protocol (ICMP/IGMP/GRE/ESP). `idx` offsets weights
/// so per-destination sets in mode A never collide.
///
/// these blocks live at `OUTBOUND_TRANSPORT_V4`, NOT the packet
/// layer: the IPPACKET layers have no `FWPM_CONDITION_IP_PROTOCOL`, so every
/// protocol-narrowed packet-layer filter failed `FwpmFilterAdd0` with
/// `FWP_E_CONDITION_NOT_FOUND` since  (3 020 skips per HW run).
/// Known transport-layer gap (accepted): stack-originated IGMP and
/// kernel-injected GRE/ESP tunnels bypass the transport stack — user-space
/// ICMP (ping) and raw-socket sends are classified there.
///
/// the protocol-agnostic "Other"
/// block-all is GONE (see [`KillSwitchProtocols::wants_packet_layer`]): it was
/// system-wide and cut TCP/UDP above every ALE permit/exemption.
fn packet_protocol_blocks(
    sid: &str,
    scope: Option<Ipv4Addr>,
    protocols: KillSwitchProtocols,
    idx: u64,
) -> Vec<WfpFilterSpec> {
    let mut out = Vec::new();
    for (k, p) in protocols.packet_named().into_iter().enumerate() {
        out.push(packet_block(
            sid,
            WfpLayerKey::OutboundTransportV4,
            scope,
            Some(p),
            PACKET_BLOCK_BASE + idx * 16 + k as u64,
        ));
    }
    out
}

/// Below-ALE egress-conditional Permit for the leak-proof pair at `layer`:
/// allow a flow **while it egresses `luid`** (the secondary adapter).
/// `user_sid = None` (no ALE ids below the ALE layers). Mirrors
/// [`permit_via_secondary`], optionally narrowed to one IP protocol —
/// protocol narrowing REQUIRES the transport layer (HW-0718, see
/// [`packet_block`]). Layer-specific kind tag.
fn packet_egress_permit(
    sid: &str,
    layer: WfpLayerKey,
    scope: Option<Ipv4Addr>,
    proto: Option<u8>,
    luid: u64,
    weight: u64,
) -> WfpFilterSpec {
    let kind = if layer == WfpLayerKey::OutboundTransportV4 {
        "ks-tr-egress"
    } else {
        "ks-pkt-egress"
    };
    WfpFilterSpec {
        layer,
        action: WfpAction::Permit,
        remote_ip: scope,
        remote_port: None,
        weight,
        id: filter_id_for(
            sid,
            KILLSWITCH_ROLE,
            &permit_luid_seg(luid),
            kind,
            &proto_scope_key(scope, proto),
        ),
        user_sid: None,
        app_pattern: None,
        local_interface_luid: Some(luid),
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: proto,
    }
}

/// The below-ALE leak-proof pairs for one scope, narrowed to `protocols`:
/// an egress-conditional Permit (allow while egressing the secondary adapter)
/// over a Block (fires the instant the secondary adapter drops), per selected
/// named packet protocol (ICMP/IGMP/GRE/ESP). Empty when no packet protocol
/// is selected. HW-0718: the pairs live at `OUTBOUND_TRANSPORT_V4` — see
/// [`packet_protocol_blocks`] for why the packet layer cannot host them.
///
/// the protocol-agnostic "Other" pair
/// is GONE (see [`KillSwitchProtocols::wants_packet_layer`]).
fn packet_egress_pairs(
    sid: &str,
    scope: Option<Ipv4Addr>,
    protocols: KillSwitchProtocols,
    luid: u64,
    idx: u64,
) -> Vec<WfpFilterSpec> {
    let mut out = Vec::new();
    for (k, p) in protocols.packet_named().into_iter().enumerate() {
        out.push(packet_egress_permit(
            sid,
            WfpLayerKey::OutboundTransportV4,
            scope,
            Some(p),
            luid,
            PACKET_EXEMPT_BASE + idx * 16 + k as u64,
        ));
        out.push(packet_block(
            sid,
            WfpLayerKey::OutboundTransportV4,
            scope,
            Some(p),
            PACKET_BLOCK_BASE + idx * 16 + k as u64,
        ));
    }
    out
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Weight of the top rule band in [`crate::wfp_codegen`]
    /// (`BASE_PRIMARY`). The kill-switch must outrank it.
    const RULE_PRIMARY_BAND: u64 = 0x0020_0000;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    const LUID: u64 = 0x0001_0000_0000_0007;

    #[test]
    fn fake_ip_pool_permit_carves_both_families_above_the_block() {
        use nrr_platform_api::fake_ip::FakeIpPoolConfig;
        let filters =
            fake_ip_pool_permit_filters("S-1-5-21-7", &FakeIpPoolConfig::default(), false);
        assert_eq!(
            filters.len(),
            4,
            "v4 + v6 permits plus the v4 + v6 UDP blocks for the dual-stack pool"
        );

        let v4 = &filters[0];
        assert_eq!(v4.action, WfpAction::Permit);
        assert_eq!(v4.layer, WfpLayerKey::AleAuthConnectV4);
        assert_eq!(v4.remote_subnet, Some((Ipv4Addr::new(198, 18, 0, 0), 15)));
        assert_eq!(v4.user_sid.as_deref(), Some("S-1-5-21-7"));
        // Above the catch-all block so the app can always reach the pool → TUN.
        assert!(v4.weight > CATCHALL_BLOCK_WEIGHT);
        // Protocol-agnostic: TCP flows into the pool must pass.
        assert_eq!(v4.ip_protocol, None);

        let v6 = &filters[1];
        assert_eq!(v6.layer, WfpLayerKey::AleAuthConnectV6);
        assert!(v6.remote_subnet_v6.is_some());
        assert_ne!(v4.weight, v6.weight, "distinct weights, no collision");
    }

    #[test]
    fn fake_ip_pool_udp_is_blocked_by_default() {
        use nrr_platform_api::fake_ip::FakeIpPoolConfig;
        let filters =
            fake_ip_pool_permit_filters("S-1-5-21-7", &FakeIpPoolConfig::default(), false);
        let udp_blocks: Vec<_> = filters
            .iter()
            .filter(|f| f.action == WfpAction::Block)
            .collect();
        assert_eq!(udp_blocks.len(), 2, "one UDP block per address family");
        for block in &udp_blocks {
            assert_eq!(
                block.ip_protocol,
                Some(PROTO_UDP),
                "the block must be UDP-narrowed — TCP into the pool stays permitted"
            );
            assert_eq!(block.user_sid.as_deref(), Some("S-1-5-21-7"));
        }
        assert!(
            udp_blocks
                .iter()
                .any(|f| f.remote_subnet == Some((Ipv4Addr::new(198, 18, 0, 0), 15))),
            "the v4 block covers the whole pool subnet"
        );
        let ids: std::collections::HashSet<_> = filters.iter().map(|f| &f.id).collect();
        assert_eq!(ids.len(), filters.len(), "distinct filter ids");
    }

    #[test]
    fn fake_ip_pool_udp_is_permitted_when_relay_enabled() {
        use nrr_platform_api::fake_ip::FakeIpPoolConfig;
        let filters = fake_ip_pool_permit_filters("S-1-5-21-7", &FakeIpPoolConfig::default(), true);
        assert_eq!(
            filters.len(),
            2,
            "only the v4 + v6 permits — no UDP blocks once the relay carries UDP"
        );
        assert!(
            filters.iter().all(|f| f.action == WfpAction::Permit),
            "no Block filters when udp_relay_enabled is true"
        );
        assert!(
            filters.iter().all(|f| f.ip_protocol.is_none()),
            "the permits stay protocol-agnostic — UDP now rides the same permit as TCP"
        );
    }

    #[test]
    fn fake_ip_pool_permit_is_v4_only_for_a_v4_only_pool() {
        use nrr_platform_api::fake_ip::FakeIpPoolConfig;
        let filters = fake_ip_pool_permit_filters("S", &FakeIpPoolConfig::v4_only(), false);
        assert_eq!(filters.len(), 2, "the v4 permit plus its UDP block");
        assert!(filters.iter().all(|f| f.remote_subnet_v6.is_none()));
        assert_eq!(filters[0].action, WfpAction::Permit);
        assert_eq!(filters[1].action, WfpAction::Block);
        assert_eq!(filters[1].ip_protocol, Some(PROTO_UDP));
    }

    #[test]
    fn fake_ip_pool_permit_is_v4_only_permit_when_relay_enabled_for_v4_only_pool() {
        use nrr_platform_api::fake_ip::FakeIpPoolConfig;
        let filters = fake_ip_pool_permit_filters("S", &FakeIpPoolConfig::v4_only(), true);
        assert_eq!(filters.len(), 1, "just the v4 permit — no UDP block");
        assert_eq!(filters[0].action, WfpAction::Permit);
        assert_eq!(filters[0].ip_protocol, None);
    }

    #[test]
    fn empty_destinations_yield_no_filters() {
        assert!(kill_switch_filters("S", &[], LUID, KillSwitchProtocols::ALL).is_empty());
    }

    #[test]
    fn zero_luid_disables_kill_switch() {
        // A bad LUID must fail OPEN — never emit a black-hole Block.
        let out = kill_switch_filters("S", &[ip(203, 0, 113, 5)], 0, KillSwitchProtocols::ALL);
        assert!(out.is_empty(), "zero LUID must produce no filters");
    }

    #[test]
    fn single_destination_emits_ale_pair_plus_packet_pair() {
        // All protocols: 1 dest → ALE permit+block (TCP/UDP) + one packet
        // egress-permit + block per NAMED packet protocol (ICMP/IGMP/GRE/ESP;
        // 16.HW-0716: "Other" no longer adds an agnostic pair) = 2 + 4×2 = 10.
        let out = kill_switch_filters("S", &[ip(203, 0, 113, 5)], LUID, KillSwitchProtocols::ALL);
        assert_eq!(out.len(), 10);
        let permit = &out[0];
        let block = &out[1];
        assert_eq!(permit.action, WfpAction::Permit);
        assert_eq!(permit.layer, WfpLayerKey::AleAuthConnectV4);
        assert_eq!(permit.remote_ip, Some(ip(203, 0, 113, 5)));
        assert_eq!(
            permit.local_interface_luid,
            Some(LUID),
            "ALE permit half carries the egress-interface condition"
        );
        assert_eq!(block.action, WfpAction::Block);
        assert_eq!(
            block.local_interface_luid, None,
            "ALE block is unconditional"
        );
        // The packet pair: an egress-conditional permit (carries the LUID) and
        // an unconditional packet block, both at the packet layer.
        let pkt: Vec<_> = out
            .iter()
            .filter(|f| f.layer == WfpLayerKey::OutboundTransportV4)
            .collect();
        assert_eq!(
            pkt.len(),
            8,
            "one egress-permit + block pair per named protocol"
        );
        assert!(pkt
            .iter()
            .any(|f| f.action == WfpAction::Permit && f.local_interface_luid == Some(LUID)));
        assert!(pkt.iter().any(|f| f.action == WfpAction::Block));
        // 16.HW-0716 — every packet filter is narrowed to a named protocol;
        // the protocol-agnostic block-all is gone.
        assert!(pkt.iter().all(|f| f.ip_protocol.is_some()));
    }

    #[test]
    fn icmp_only_emits_packet_pair_no_ale() {
        // Only ICMP: no ALE pair (no TCP/UDP), one packet egress-permit + block.
        let protos = KillSwitchProtocols {
            tcp: false,
            udp: false,
            icmp: true,
            igmp: false,
            gre: false,
            esp: false,
            other: false,
        };
        let out = kill_switch_filters("S", &[ip(8, 8, 8, 8)], LUID, protos);
        // No ALE pair (no TCP/UDP selected) — only the ICMP packet pair.
        assert_eq!(out.len(), 2);
        assert!(out
            .iter()
            .all(|f| f.layer == WfpLayerKey::OutboundTransportV4));
        assert!(out
            .iter()
            .any(|f| f.action == WfpAction::Block && f.ip_protocol == Some(1)));
        assert!(out.iter().any(|f| f.action == WfpAction::Permit
            && f.local_interface_luid == Some(LUID)
            && f.ip_protocol == Some(1)));
    }

    #[test]
    fn ale_permit_outranks_ale_block_outranks_rule_band() {
        let out = kill_switch_filters("S", &[ip(8, 8, 8, 8)], LUID, KillSwitchProtocols::ALL);
        let permit = &out[0];
        let block = &out[1];
        assert!(permit.weight > block.weight, "permit must outrank block");
        assert!(
            block.weight > RULE_PRIMARY_BAND,
            "kill-switch block must outrank the rule primary band"
        );
    }

    // ── Per-app kill-switch ────────────────────────────────────

    #[test]
    fn app_kill_switch_emits_ale_pair_pinned_to_app_and_luid() {
        let out = app_kill_switch_filters(
            "S",
            &["C:\\Games\\game.exe".to_string()],
            LUID,
            KillSwitchProtocols::ALL,
        );
        // ALE only (no per-app packet layer): exactly one permit + one block.
        assert_eq!(out.len(), 2);
        let permit = &out[0];
        let block = &out[1];
        assert_eq!(permit.action, WfpAction::Permit);
        assert_eq!(permit.layer, WfpLayerKey::AleAuthConnectV4);
        assert_eq!(permit.app_pattern.as_deref(), Some("C:\\Games\\game.exe"));
        assert_eq!(
            permit.local_interface_luid,
            Some(LUID),
            "app permit is egress-conditional on the secondary LUID"
        );
        assert_eq!(
            permit.remote_ip, None,
            "the app pair is keyed on app id, not IP"
        );
        assert_eq!(block.action, WfpAction::Block);
        assert_eq!(block.app_pattern.as_deref(), Some("C:\\Games\\game.exe"));
        assert_eq!(
            block.local_interface_luid, None,
            "app block is unconditional so it fires the instant the secondary adapter drops"
        );
        assert!(permit.weight > block.weight, "permit must outrank block");
        assert!(
            block.weight > RULE_PRIMARY_BAND,
            "app block must outrank the rule bands (and the per-process Permit)"
        );
    }

    #[test]
    fn primary_app_exempt_emits_unconditional_permit_above_all_bands() {
        // a primary-routed app must be EXEMPT from the kill-switch:
        // one unconditional ALE Permit per pattern, at the exempt band, outranking
        // every block. No interface/IP condition so it permits egress over the
        // primary even while the secondary adapter is down and block-all is engaged.
        let out = primary_app_exempt_filters(
            "S",
            &["hidemy.name VPN 3.0.exe".to_string(), "*vpn*".to_string()],
        );
        assert_eq!(out.len(), 2, "one exempt permit per pattern, no block half");
        for f in &out {
            assert_eq!(f.action, WfpAction::Permit);
            assert_eq!(f.layer, WfpLayerKey::AleAuthConnectV4);
            assert_eq!(
                f.local_interface_luid, None,
                "unconditional — allowed over any link, incl. primary"
            );
            assert_eq!(f.remote_ip, None, "keyed on app id, not IP");
            assert!(f.app_pattern.is_some());
            assert!(
                f.weight >= APP_EXEMPT_BASE,
                "exempt permit must sit in the top exempt band"
            );
        }
        assert_eq!(
            out[0].app_pattern.as_deref(),
            Some("hidemy.name VPN 3.0.exe")
        );
        assert_eq!(out[1].app_pattern.as_deref(), Some("*vpn*"));
    }

    #[test]
    fn primary_app_exempt_empty_input_emits_nothing() {
        assert!(primary_app_exempt_filters("S", &[]).is_empty());
    }

    #[test]
    fn default_vpn_exempt_patterns_present_and_each_emits_an_exempt_permit() {
        // The built-in defaults must include the broad glob and each must produce
        // a well-formed unconditional exempt permit (HW-0712 C4, out-of-the-box
        // VPN-bootstrap protection).
        assert!(DEFAULT_VPN_EXEMPT_PATTERNS.contains(&"*vpn*"));
        let pats: Vec<String> = DEFAULT_VPN_EXEMPT_PATTERNS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let out = primary_app_exempt_filters("S", &pats);
        assert_eq!(out.len(), DEFAULT_VPN_EXEMPT_PATTERNS.len());
        assert!(out.iter().all(|f| f.action == WfpAction::Permit
            && f.layer == WfpLayerKey::AleAuthConnectV4
            && f.local_interface_luid.is_none()
            && f.remote_ip.is_none()));
    }

    #[test]
    fn app_kill_switch_never_touches_packet_layer() {
        // ALE_APP_ID is not available at the packet layer — a per-app ICMP gate
        // is impossible, so nothing must land there.
        let out =
            app_kill_switch_filters("S", &["a.exe".to_string()], LUID, KillSwitchProtocols::ALL);
        assert!(out.iter().all(|f| f.layer == WfpLayerKey::AleAuthConnectV4));
    }

    #[test]
    fn app_kill_switch_zero_luid_fails_open() {
        let out = app_kill_switch_filters("S", &["a.exe".to_string()], 0, KillSwitchProtocols::ALL);
        assert!(
            out.is_empty(),
            "zero LUID must fail open (no per-app filters)"
        );
    }

    #[test]
    fn app_kill_switch_icmp_only_emits_nothing() {
        let protos = KillSwitchProtocols {
            tcp: false,
            udp: false,
            icmp: true,
            igmp: false,
            gre: false,
            esp: false,
            other: false,
        };
        let out = app_kill_switch_filters("S", &["a.exe".to_string()], LUID, protos);
        assert!(
            out.is_empty(),
            "no TCP/UDP selected → the ALE-only app kill-switch emits nothing"
        );
    }

    #[test]
    fn fail_closed_block_apps_blocks_each_protected_app() {
        let out = fail_closed_block_apps(
            "S",
            &["a.exe".to_string(), "b.exe".to_string()],
            KillSwitchProtocols::ALL,
        );
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|f| f.action == WfpAction::Block
            && f.layer == WfpLayerKey::AleAuthConnectV4
            && f.app_pattern.is_some()));
    }

    #[test]
    fn fail_closed_block_apps_icmp_only_emits_nothing() {
        let protos = KillSwitchProtocols {
            tcp: false,
            udp: false,
            icmp: true,
            igmp: false,
            gre: false,
            esp: false,
            other: false,
        };
        let out = fail_closed_block_apps("S", &["a.exe".to_string()], protos);
        assert!(out.is_empty());
    }

    #[test]
    fn loopback_and_link_local_are_exempt() {
        let out = kill_switch_filters(
            "S",
            &[ip(127, 0, 0, 1), ip(169, 254, 1, 1)],
            LUID,
            KillSwitchProtocols::ALL,
        );
        assert!(
            out.is_empty(),
            "loopback and link-local must never be kill-switched"
        );
    }

    #[test]
    fn exempt_ips_are_skipped_while_others_are_kept() {
        let out = kill_switch_filters(
            "S",
            &[ip(127, 0, 0, 1), ip(203, 0, 113, 5), ip(169, 254, 0, 9)],
            LUID,
            KillSwitchProtocols::ALL,
        );
        // The one non-exempt IP → ALE pair + 4 named packet pairs = 10 filters
        // (16.HW-0716: named-only packet layer), all for it.
        assert_eq!(out.len(), 10);
        for f in &out {
            assert_eq!(f.remote_ip, Some(ip(203, 0, 113, 5)));
        }
    }

    #[test]
    fn ale_filters_carry_sid_packet_filters_do_not() {
        let out = kill_switch_filters(
            "S-1-5-21-XYZ",
            &[ip(1, 1, 1, 1), ip(2, 2, 2, 2)],
            LUID,
            KillSwitchProtocols::ALL,
        );
        assert_eq!(out.len(), 20); // 2 dests × (2 ALE + 4×2 named transport)
        for f in &out {
            match f.layer {
                WfpLayerKey::AleAuthConnectV4 | WfpLayerKey::AleAuthConnectV6 => {
                    assert_eq!(f.user_sid.as_deref(), Some("S-1-5-21-XYZ"))
                }
                WfpLayerKey::OutboundIpPacketV4
                | WfpLayerKey::OutboundIpPacketV6
                | WfpLayerKey::OutboundTransportV4 => {
                    assert_eq!(f.user_sid, None, "no ALE_USER_ID below the ALE layers")
                }
            }
        }
    }

    #[test]
    fn weights_do_not_collide_within_each_layer() {
        let out = kill_switch_filters(
            "S",
            &[ip(1, 1, 1, 1), ip(2, 2, 2, 2), ip(3, 3, 3, 3)],
            LUID,
            KillSwitchProtocols::ALL,
        );
        // Weights only need to be distinct WITHIN a layer (WFP arbitrates per
        // layer); the packet bands deliberately reuse the ALE numeric space.
        for layer in [
            WfpLayerKey::AleAuthConnectV4,
            WfpLayerKey::OutboundTransportV4,
        ] {
            let weights: Vec<u64> = out
                .iter()
                .filter(|f| f.layer == layer)
                .map(|f| f.weight)
                .collect();
            let unique: std::collections::HashSet<u64> = weights.iter().copied().collect();
            assert_eq!(
                unique.len(),
                weights.len(),
                "weights distinct within {layer:?}"
            );
        }
    }

    #[test]
    fn filter_ids_are_deterministic_and_distinct() {
        let a = kill_switch_filters(
            "S",
            &[ip(1, 1, 1, 1), ip(2, 2, 2, 2)],
            LUID,
            KillSwitchProtocols::ALL,
        );
        let b = kill_switch_filters(
            "S",
            &[ip(1, 1, 1, 1), ip(2, 2, 2, 2)],
            LUID,
            KillSwitchProtocols::ALL,
        );
        let ids_a: Vec<u64> = a.iter().map(|f| f.id.raw).collect();
        let ids_b: Vec<u64> = b.iter().map(|f| f.id.raw).collect();
        assert_eq!(ids_a, ids_b, "same inputs must yield identical filter ids");
        let unique: std::collections::HashSet<u64> = ids_a.iter().copied().collect();
        assert_eq!(unique.len(), ids_a.len(), "all ids must differ");
    }

    #[test]
    fn different_sids_produce_different_filter_ids() {
        let a = kill_switch_filters(
            "S-1-5-21-A",
            &[ip(1, 1, 1, 1)],
            LUID,
            KillSwitchProtocols::ALL,
        );
        let b = kill_switch_filters(
            "S-1-5-21-B",
            &[ip(1, 1, 1, 1)],
            LUID,
            KillSwitchProtocols::ALL,
        );
        assert_ne!(a[0].id.raw, b[0].id.raw);
        assert_ne!(a[1].id.raw, b[1].id.raw);
    }

    #[test]
    fn filters_span_ale_and_packet_layers() {
        let out = kill_switch_filters("S", &[ip(9, 9, 9, 9)], LUID, KillSwitchProtocols::ALL);
        assert!(out.iter().any(|f| f.layer == WfpLayerKey::AleAuthConnectV4));
        assert!(out
            .iter()
            .any(|f| f.layer == WfpLayerKey::OutboundTransportV4));
    }

    // ── Catch-all kill-switch (mode B) ──────────────────────────────────────

    fn full_resolution() -> KillSwitchResolution {
        KillSwitchResolution {
            secondary_luid: LUID,
            bootstrap_server_ips: vec![ip(203, 0, 113, 7)],
            local_subnets: vec![(ip(192, 168, 1, 0), 24)],
        }
    }

    /// regression gate. `FwpmFilterAdd0` rejects a condition the
    /// target layer does not expose (`FWP_E_CONDITION_NOT_FOUND`) — 3 020
    /// kill-switch filters per HW run silently never installed because the
    /// packet layer has no `FWPM_CONDITION_IP_PROTOCOL` and the mock engine
    /// accepted them anyway. Every public emitter must produce specs whose
    /// conditions are expressible at their layer (the mock now enforces the
    /// same rule at add time; this test pins it at the codegen source).
    #[test]
    fn every_emitted_filter_is_expressible_at_its_layer() {
        let sid = "S-1-5-21-REG";
        let ips = [ip(203, 0, 113, 5), ip(198, 51, 100, 7)];
        let apps = ["C:\\Apps\\tunnel.exe".to_string()];
        let exemptions = FailClosedExemptions {
            bootstrap_server_ips: vec![ip(203, 0, 113, 7)],
            local_subnets: vec![(ip(192, 168, 1, 0), 24)],
            primary_dest_ips: vec![ip(198, 51, 100, 200)],
            allow_dns_over_primary: true,
            known_direct_ips: vec![ip(178, 248, 237, 68)],
            probe_target_ips: vec![ip(10, 91, 192, 1)],
        };
        let mut all = Vec::new();
        all.extend(kill_switch_filters(
            sid,
            &ips,
            LUID,
            KillSwitchProtocols::ALL,
        ));
        all.extend(app_kill_switch_filters(
            sid,
            &apps,
            LUID,
            KillSwitchProtocols::ALL,
        ));
        all.extend(catch_all_kill_switch_filters(
            sid,
            &full_resolution(),
            KillSwitchProtocols::ALL,
        ));
        all.extend(fail_closed_block_destinations(
            sid,
            &ips,
            KillSwitchProtocols::ALL,
        ));
        all.extend(fail_closed_block_apps(sid, &apps, KillSwitchProtocols::ALL));
        all.extend(fail_closed_block_all_filters(
            sid,
            &exemptions,
            KillSwitchProtocols::ALL,
        ));
        assert!(!all.is_empty());
        for f in &all {
            assert!(
                f.validate_layer_conditions().is_ok(),
                "filter has a condition its layer cannot express: {f:?}"
            );
        }
    }

    #[test]
    fn catch_all_disabled_on_zero_luid() {
        let mut r = full_resolution();
        r.secondary_luid = 0;
        assert!(catch_all_kill_switch_filters("S", &r, KillSwitchProtocols::ALL).is_empty());
    }

    #[test]
    fn catch_all_not_armed_without_server_ips() {
        let mut r = full_resolution();
        r.bootstrap_server_ips.clear();
        assert!(
            catch_all_kill_switch_filters("S", &r, KillSwitchProtocols::ALL).is_empty(),
            "no server exemption → don't arm (avoid trapping the tunnel's reconnect)"
        );
    }

    #[test]
    fn catch_all_disabled_when_no_protocol_selected() {
        let empty = KillSwitchProtocols::from_bits(0);
        assert!(
            catch_all_kill_switch_filters("S", &full_resolution(), empty).is_empty(),
            "an empty protocol mask arms no block"
        );
    }

    #[test]
    fn catch_all_emits_exemptions_and_block() {
        let out = catch_all_kill_switch_filters("S", &full_resolution(), KillSwitchProtocols::ALL);
        // ALE layer: egress + loopback + link-local + broadcast + 1 server
        //   + 1 subnet + block = 7.
        let ale: Vec<_> = out
            .iter()
            .filter(|f| f.layer == WfpLayerKey::AleAuthConnectV4)
            .collect();
        assert_eq!(ale.len(), 7, "ALE: 6 exemptions + 1 catch-all block");
        assert_eq!(
            ale.iter()
                .filter(|f| f.local_interface_luid == Some(LUID))
                .count(),
            1,
            "exactly one egress-via-secondary permit at the ALE layer"
        );
        assert_eq!(
            ale.iter().filter(|f| f.remote_subnet.is_some()).count(),
            3,
            "loopback + link-local + LAN subnet"
        );
        assert_eq!(
            ale.iter().filter(|f| f.remote_ip.is_some()).count(),
            2,
            "VPN server + broadcast hosts"
        );
        assert_eq!(
            ale.iter().filter(|f| f.action == WfpAction::Block).count(),
            1,
            "exactly one ALE catch-all block"
        );
        // Packet layer (P2): egress + loopback + link-local + broadcast
        //   + 1 server + 1 subnet + 4 named protocol blocks = 10
        //   (16.HW-0716: one block per ICMP/IGMP/GRE/ESP, no agnostic block-all).
        let pkt: Vec<_> = out
            .iter()
            .filter(|f| f.layer == WfpLayerKey::OutboundTransportV4)
            .collect();
        assert_eq!(
            pkt.len(),
            10,
            "packet layer mirrors the ALE exemptions + named blocks"
        );
        assert_eq!(
            pkt.iter()
                .filter(|f| f.local_interface_luid == Some(LUID))
                .count(),
            1,
            "exactly one egress-via-secondary permit at the packet layer"
        );
        assert_eq!(
            pkt.iter().filter(|f| f.action == WfpAction::Block).count(),
            4,
            "one packet block per named protocol (ICMP/IGMP/GRE/ESP)"
        );
        assert!(
            pkt.iter()
                .filter(|f| f.action == WfpAction::Block)
                .all(|f| f.ip_protocol.is_some()),
            "16.HW-0716: no protocol-agnostic packet block-all"
        );
    }

    #[test]
    fn catch_all_covers_icmp_at_packet_layer() {
        let out = catch_all_kill_switch_filters("S", &full_resolution(), KillSwitchProtocols::ALL);
        // A packet-layer block with no destination scope drops ICMP/ping the
        // instant the secondary adapter drops; a packet-layer egress permit keeps it flowing
        // while the tunnel is up. This is the 0704 P2 fix for the mode-B ping
        // leak.
        let has_packet_block = out
            .iter()
            .any(|f| f.layer == WfpLayerKey::OutboundTransportV4 && f.action == WfpAction::Block);
        let has_packet_egress = out.iter().any(|f| {
            f.layer == WfpLayerKey::OutboundTransportV4
                && f.action == WfpAction::Permit
                && f.local_interface_luid == Some(LUID)
        });
        assert!(
            has_packet_block,
            "ping must be blockable at the packet layer"
        );
        assert!(
            has_packet_egress,
            "packets egressing the secondary adapter stay permitted"
        );
    }

    #[test]
    fn catch_all_no_packet_layer_when_only_tcp_udp_selected() {
        let tcp_udp = KillSwitchProtocols::from_bits(0x03); // tcp + udp only
        let out = catch_all_kill_switch_filters("S", &full_resolution(), tcp_udp);
        assert!(
            out.iter()
                .all(|f| f.layer != WfpLayerKey::OutboundTransportV4),
            "no V4 packet-layer filters when the mask selects only TCP/UDP \
             (the IPv6 catch-all coverage is orthogonal to the V4 protocol mask)"
        );
    }

    #[test]
    fn catch_all_block_weight_sits_between_secondary_and_primary_bands() {
        let out = catch_all_kill_switch_filters("S", &full_resolution(), KillSwitchProtocols::ALL);
        let ale: Vec<_> = out
            .iter()
            .filter(|f| f.layer == WfpLayerKey::AleAuthConnectV4)
            .collect();
        let block = ale.iter().find(|f| f.action == WfpAction::Block).unwrap();
        assert!(
            block.weight > 0x0010_0000 && block.weight < 0x0020_0000,
            "block {:#x} must sit between the secondary and primary rule bands so \
             primary exceptions escape and secondary destinations get killed",
            block.weight
        );
        for permit in ale.iter().filter(|f| f.action == WfpAction::Permit) {
            assert!(
                permit.weight > block.weight,
                "every ALE exemption permit must outrank the catch-all block"
            );
        }
    }

    #[test]
    fn catch_all_block_is_unconditional_on_destination() {
        let out = catch_all_kill_switch_filters("S", &full_resolution(), KillSwitchProtocols::ALL);
        let block = out
            .iter()
            .find(|f| f.action == WfpAction::Block && f.layer == WfpLayerKey::AleAuthConnectV4)
            .unwrap();
        assert!(block.remote_ip.is_none());
        assert!(block.remote_subnet.is_none());
        assert!(block.local_interface_luid.is_none());
        assert_eq!(
            block.user_sid.as_deref(),
            Some("S"),
            "still scoped to the user — never blocks other users / system"
        );
    }

    #[test]
    fn catch_all_user_sid_stamped_on_ale_filters_only() {
        let out = catch_all_kill_switch_filters(
            "S-1-5-21-Z",
            &full_resolution(),
            KillSwitchProtocols::ALL,
        );
        for f in &out {
            match f.layer {
                WfpLayerKey::AleAuthConnectV4 | WfpLayerKey::AleAuthConnectV6 => {
                    assert_eq!(f.user_sid.as_deref(), Some("S-1-5-21-Z"))
                }
                WfpLayerKey::OutboundIpPacketV4
                | WfpLayerKey::OutboundIpPacketV6
                | WfpLayerKey::OutboundTransportV4 => {
                    assert_eq!(f.user_sid, None, "no ALE_USER_ID below the ALE layers")
                }
            }
        }
    }

    #[test]
    fn catch_all_ids_deterministic_and_distinct() {
        let a = catch_all_kill_switch_filters("S", &full_resolution(), KillSwitchProtocols::ALL);
        let b = catch_all_kill_switch_filters("S", &full_resolution(), KillSwitchProtocols::ALL);
        let ids_a: Vec<u64> = a.iter().map(|f| f.id.raw).collect();
        let ids_b: Vec<u64> = b.iter().map(|f| f.id.raw).collect();
        assert_eq!(ids_a, ids_b, "same inputs → identical ids");
        let unique: std::collections::HashSet<u64> = ids_a.iter().copied().collect();
        assert_eq!(unique.len(), ids_a.len(), "all catch-all ids must differ");
    }

    // ── Fail-closed posture ─────────────────────────────────────────────────

    #[test]
    fn fail_closed_mode_a_blocks_each_protected_dest_at_both_layers() {
        // All protocols: per dest → 1 ALE block (TCP/UDP) + 4 named packet
        // blocks (16.HW-0716: ICMP/IGMP/GRE/ESP, no agnostic block-all).
        let out = fail_closed_block_destinations(
            "S",
            &[ip(203, 0, 113, 5), ip(8, 8, 8, 8)],
            KillSwitchProtocols::ALL,
        );
        assert_eq!(out.len(), 10);
        for f in &out {
            assert_eq!(f.action, WfpAction::Block);
            assert_eq!(
                f.local_interface_luid, None,
                "fail-closed block has no egress condition — the secondary adapter is gone"
            );
        }
        let ale = out
            .iter()
            .filter(|f| f.layer == WfpLayerKey::AleAuthConnectV4)
            .count();
        let pkt = out
            .iter()
            .filter(|f| f.layer == WfpLayerKey::OutboundTransportV4)
            .count();
        assert_eq!((ale, pkt), (2, 8));
        // ALE blocks are per-SID; packet blocks are system-wide (no ALE_USER_ID).
        for f in out
            .iter()
            .filter(|f| f.layer == WfpLayerKey::AleAuthConnectV4)
        {
            assert_eq!(f.user_sid.as_deref(), Some("S"));
        }
        for f in out
            .iter()
            .filter(|f| f.layer == WfpLayerKey::OutboundTransportV4)
        {
            assert_eq!(f.user_sid, None, "packet layer has no ALE_USER_ID");
        }
        assert!(out.iter().any(|f| f.remote_ip == Some(ip(203, 0, 113, 5))));
        assert!(out.iter().any(|f| f.remote_ip == Some(ip(8, 8, 8, 8))));
    }

    #[test]
    fn fail_closed_mode_a_outranks_rule_band_and_skips_loopback() {
        let out = fail_closed_block_destinations(
            "S",
            &[ip(127, 0, 0, 1), ip(203, 0, 113, 5)],
            KillSwitchProtocols::ALL,
        );
        // loopback skipped; the one real dest → ALE block + 4 named packet blocks.
        assert_eq!(out.len(), 5, "loopback is never blocked");
        assert!(out.iter().all(|f| f.remote_ip == Some(ip(203, 0, 113, 5))));
        let ale = out
            .iter()
            .find(|f| f.layer == WfpLayerKey::AleAuthConnectV4)
            .unwrap();
        assert!(
            ale.weight > RULE_PRIMARY_BAND,
            "fail-closed ALE block {:#x} must outrank the rule permit it overrides",
            ale.weight
        );
    }

    #[test]
    fn fail_closed_mode_a_icmp_only_emits_single_packet_block() {
        // Only ICMP selected: no ALE block (no TCP/UDP), one packet block proto=1.
        let protos = KillSwitchProtocols {
            tcp: false,
            udp: false,
            icmp: true,
            igmp: false,
            gre: false,
            esp: false,
            other: false,
        };
        let out = fail_closed_block_destinations("S", &[ip(203, 0, 113, 5)], protos);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].layer, WfpLayerKey::OutboundTransportV4);
        assert_eq!(out[0].action, WfpAction::Block);
        assert_eq!(out[0].ip_protocol, Some(PROTO_ICMP));
        assert_eq!(out[0].remote_ip, Some(ip(203, 0, 113, 5)));
    }

    #[test]
    fn fail_closed_no_protocols_yields_no_filters() {
        let none = KillSwitchProtocols {
            tcp: false,
            udp: false,
            icmp: false,
            igmp: false,
            gre: false,
            esp: false,
            other: false,
        };
        assert!(fail_closed_block_destinations("S", &[ip(8, 8, 8, 8)], none).is_empty());
        assert!(
            fail_closed_block_all_filters("S", &FailClosedExemptions::default(), none).is_empty()
        );
    }

    #[test]
    fn fail_closed_allow_dns_over_primary_adds_port_scoped_dns_permits() {
        // opt-in: with `allow_dns_over_primary` the block-all set
        // gains port-scoped (remote UDP/TCP 53) ALE permits so name resolution keeps
        // working over the primary link; off (the strict default) it must not.
        let strict = fail_closed_block_all_filters(
            "S",
            &FailClosedExemptions::default(),
            KillSwitchProtocols::ALL,
        );
        assert!(
            !strict.iter().any(|f| f.remote_port == Some(53)),
            "strict block-all must NOT permit DNS over the primary link"
        );

        let ex = FailClosedExemptions {
            allow_dns_over_primary: true,
            ..FailClosedExemptions::default()
        };
        let out = fail_closed_block_all_filters("S", &ex, KillSwitchProtocols::ALL);
        let dns: Vec<_> = out
            .iter()
            .filter(|f| {
                f.action == WfpAction::Permit
                    && f.layer == WfpLayerKey::AleAuthConnectV4
                    && f.remote_port == Some(53)
            })
            .collect();
        assert_eq!(dns.len(), 2, "expected exactly UDP-53 + TCP-53 permits");
        assert!(dns.iter().any(|f| f.ip_protocol == Some(17)), "UDP permit");
        assert!(dns.iter().any(|f| f.ip_protocol == Some(6)), "TCP permit");
        // Port-scoped, not a full-host tunnel: no remote_ip pin.
        assert!(dns.iter().all(|f| f.remote_ip.is_none()));
    }

    #[test]
    fn fail_closed_block_all_permits_known_primary_at_packet_layer_above_block() {
        // a known-primary host earns a
        // packet-layer proto-agnostic permit that outranks the named packet
        // blocks, so ping/ICMP to it survives the block-all (the ya.ru case).
        let primary = ip(203, 0, 113, 50);
        let ex = FailClosedExemptions {
            primary_dest_ips: vec![primary, ip(127, 0, 0, 1)], // loopback filtered
            ..FailClosedExemptions::default()
        };
        let out = fail_closed_block_all_filters("S", &ex, KillSwitchProtocols::ALL);
        let permit = out
            .iter()
            .find(|f| {
                f.layer == WfpLayerKey::OutboundTransportV4
                    && f.action == WfpAction::Permit
                    && f.remote_ip == Some(primary)
                    && f.ip_protocol.is_none() // proto-agnostic → covers ICMP
            })
            .expect("known-primary packet permit present");
        // Loopback in the primary set is filtered (is_exempt_from_blocking):
        // the only 127/8 permit is the standard subnet exempt, never a per-host
        // primary permit keyed on 127.0.0.1.
        assert!(
            !out.iter().any(|f| f.remote_ip == Some(ip(127, 0, 0, 1))),
            "loopback host is skipped — no per-host primary permit for it"
        );
        // The permit must outrank every packet-layer block so ICMP escapes.
        for blk in out
            .iter()
            .filter(|f| f.layer == WfpLayerKey::OutboundTransportV4 && f.action == WfpAction::Block)
        {
            assert!(
                permit.weight > blk.weight,
                "known-primary permit {:#x} must outrank packet block {:#x}",
                permit.weight,
                blk.weight
            );
        }
    }

    #[test]
    fn fail_closed_block_all_exempts_known_direct_at_both_layers() {
        // a known-DIRECT destination (habr.com case) has no
        // rule permit at all, so it needs BOTH an ALE exempt (TCP/UDP connects)
        // and a packet-layer permit (ICMP), each above its layer's block.
        let direct = ip(178, 248, 237, 68);
        let ex = FailClosedExemptions {
            known_direct_ips: vec![direct, ip(127, 0, 0, 1)], // loopback filtered
            ..FailClosedExemptions::default()
        };
        let out = fail_closed_block_all_filters("S", &ex, KillSwitchProtocols::ALL);
        let ale = out
            .iter()
            .find(|f| {
                f.layer == WfpLayerKey::AleAuthConnectV4
                    && f.action == WfpAction::Permit
                    && f.remote_ip == Some(direct)
            })
            .expect("known-direct ALE exempt present");
        let pkt = out
            .iter()
            .find(|f| {
                f.layer == WfpLayerKey::OutboundTransportV4
                    && f.action == WfpAction::Permit
                    && f.remote_ip == Some(direct)
                    && f.ip_protocol.is_none()
            })
            .expect("known-direct packet permit present");
        // Distinct id kinds — an IP that is also a VPN server / known-primary
        // must not collide filter ids in one desired set.
        let overlap = FailClosedExemptions {
            bootstrap_server_ips: vec![direct],
            primary_dest_ips: vec![direct],
            known_direct_ips: vec![direct],
            ..FailClosedExemptions::default()
        };
        let dup = fail_closed_block_all_filters("S", &overlap, KillSwitchProtocols::ALL);
        let ids: std::collections::HashSet<String> =
            dup.iter().map(|f| format!("{:?}", f.id)).collect();
        assert_eq!(
            ids.len(),
            dup.len(),
            "server/primary/direct twins keep distinct filter ids"
        );
        // Each permit outranks its own layer's block.
        let ale_block = out
            .iter()
            .find(|f| f.action == WfpAction::Block && f.layer == WfpLayerKey::AleAuthConnectV4)
            .expect("ALE block present");
        assert!(ale.weight > ale_block.weight);
        for blk in out
            .iter()
            .filter(|f| f.layer == WfpLayerKey::OutboundTransportV4 && f.action == WfpAction::Block)
        {
            assert!(pkt.weight > blk.weight);
        }
        // The loopback entry is filtered — no per-host permit keyed on it.
        assert!(
            !out.iter().any(|f| f.remote_ip == Some(ip(127, 0, 0, 1))),
            "loopback never earns a known-direct permit"
        );
        // ALE half carries the user-SID scope like every kill-switch ALE filter.
        assert_eq!(ale.user_sid.as_deref(), Some("S"));
    }

    #[test]
    fn fail_closed_block_all_exempts_liveness_probe_target_at_both_layers() {
        //  HW — the liveness probe's ICMP echo to the tunnel
        // next-hop is kernel-originated (no app-id): if the packet-layer ICMP
        // block eats it, the DEAD verdict can never recover and the block-all
        // never disarms. The probe target must earn an ALE exempt AND a
        // proto-agnostic packet permit, each above its layer's block.
        let next_hop = ip(10, 91, 192, 1);
        let ex = FailClosedExemptions {
            probe_target_ips: vec![next_hop],
            ..FailClosedExemptions::default()
        };
        let out = fail_closed_block_all_filters("S", &ex, KillSwitchProtocols::ALL);
        let ale = out
            .iter()
            .find(|f| {
                f.layer == WfpLayerKey::AleAuthConnectV4
                    && f.action == WfpAction::Permit
                    && f.remote_ip == Some(next_hop)
            })
            .expect("probe-target ALE exempt present");
        let pkt = out
            .iter()
            .find(|f| {
                f.layer == WfpLayerKey::OutboundTransportV4
                    && f.action == WfpAction::Permit
                    && f.remote_ip == Some(next_hop)
                    && f.ip_protocol.is_none() // proto-agnostic → covers ICMP
            })
            .expect("probe-target packet permit present");
        let ale_block = out
            .iter()
            .find(|f| f.action == WfpAction::Block && f.layer == WfpLayerKey::AleAuthConnectV4)
            .expect("ALE block present");
        assert!(ale.weight > ale_block.weight);
        for blk in out
            .iter()
            .filter(|f| f.layer == WfpLayerKey::OutboundTransportV4 && f.action == WfpAction::Block)
        {
            assert!(
                pkt.weight > blk.weight,
                "probe-target permit {:#x} must outrank packet block {:#x}",
                pkt.weight,
                blk.weight
            );
        }
        assert_eq!(ale.user_sid.as_deref(), Some("S"));
        // A next-hop that equals a bootstrap server IP keeps distinct ids.
        let overlap = FailClosedExemptions {
            bootstrap_server_ips: vec![next_hop],
            probe_target_ips: vec![next_hop],
            ..FailClosedExemptions::default()
        };
        let dup = fail_closed_block_all_filters("S", &overlap, KillSwitchProtocols::ALL);
        let ids: std::collections::HashSet<String> =
            dup.iter().map(|f| format!("{:?}", f.id)).collect();
        assert_eq!(
            ids.len(),
            dup.len(),
            "server/probe twins keep distinct filter ids"
        );
    }

    #[test]
    fn fail_closed_mode_b_blocks_all_except_exemptions() {
        let ex = FailClosedExemptions {
            bootstrap_server_ips: vec![ip(203, 0, 113, 7)],
            local_subnets: vec![(ip(192, 168, 1, 0), 24)],
            ..FailClosedExemptions::default()
        };
        let out = fail_closed_block_all_filters("S", &ex, KillSwitchProtocols::ALL);
        // ALE: loopback+link-local+broadcast+server+subnet + block-all = 6.
        // Packet: same 5 exemptions + 4 named protocol blocks = 9
        //   (16.HW-0716: ICMP/IGMP/GRE/ESP, no agnostic block-all).
        // IPv6: V6 ALE (loopback+link-local+block = 3) + V6 packet (3) = 6.
        // Total 21.
        assert_eq!(out.len(), 21);
        let ale_block = out
            .iter()
            .find(|f| f.action == WfpAction::Block && f.layer == WfpLayerKey::AleAuthConnectV4)
            .unwrap();
        assert!(ale_block.remote_ip.is_none() && ale_block.remote_subnet.is_none());
        assert!(
            ale_block.weight > 0x0010_0000 && ale_block.weight < 0x0020_0000,
            "ALE block weight {:#x} keeps primary exceptions escaping",
            ale_block.weight
        );
        let pkt_block = out
            .iter()
            .find(|f| f.action == WfpAction::Block && f.layer == WfpLayerKey::OutboundTransportV4)
            .unwrap();
        // Within each layer, every permit outranks that layer's block.
        for p in out
            .iter()
            .filter(|f| f.action == WfpAction::Permit && f.layer == WfpLayerKey::AleAuthConnectV4)
        {
            assert!(p.weight > ale_block.weight);
        }
        for p in out.iter().filter(|f| {
            f.action == WfpAction::Permit && f.layer == WfpLayerKey::OutboundTransportV4
        }) {
            assert!(p.weight > pkt_block.weight);
        }
        for f in out
            .iter()
            .filter(|f| f.layer == WfpLayerKey::AleAuthConnectV4)
        {
            assert_eq!(f.user_sid.as_deref(), Some("S"));
        }
        for f in out
            .iter()
            .filter(|f| f.layer == WfpLayerKey::OutboundTransportV4)
        {
            assert_eq!(f.user_sid, None);
        }
    }

    #[test]
    fn fail_closed_mode_b_other_off_emits_named_packet_blocks_no_permit_unselected() {
        // Everything except "Other": ALE block (TCP/UDP) + named packet blocks
        // (ICMP/IGMP/GRE/ESP). No block-all, so no permit-unselected.
        let protos = KillSwitchProtocols {
            other: false,
            ..KillSwitchProtocols::ALL
        };
        let out = fail_closed_block_all_filters("S", &FailClosedExemptions::default(), protos);
        let pkt_blocks: Vec<u8> = out
            .iter()
            .filter(|f| f.action == WfpAction::Block && f.layer == WfpLayerKey::OutboundTransportV4)
            .filter_map(|f| f.ip_protocol)
            .collect();
        assert_eq!(pkt_blocks.len(), 4, "ICMP/IGMP/GRE/ESP each get a block");
        assert!(pkt_blocks.contains(&PROTO_ICMP));
        assert!(pkt_blocks.contains(&PROTO_ESP));
        assert_eq!(
            out.iter()
                .filter(|f| f.action == WfpAction::Permit
                    && f.layer == WfpLayerKey::OutboundTransportV4)
                .filter(|f| f.ip_protocol.is_some())
                .count(),
            0,
            "no permit-unselected without a block-all"
        );
    }

    #[test]
    fn fail_closed_uncheck_icmp_leaves_icmp_unblocked() {
        // All except ICMP. The packet layer emits only named per-protocol
        // blocks — unchecking ICMP simply means NO ICMP
        // block exists (ping escapes because nothing matches it), and there is
        // never a protocol-agnostic block-all for a permit to outrank.
        let protos = KillSwitchProtocols {
            icmp: false,
            ..KillSwitchProtocols::ALL
        };
        let out = fail_closed_block_all_filters("S", &FailClosedExemptions::default(), protos);
        assert!(
            !out.iter().any(|f| {
                f.layer == WfpLayerKey::OutboundTransportV4
                    && f.action == WfpAction::Block
                    && f.ip_protocol.is_none()
            }),
            "no protocol-agnostic packet block-all (16.HW-0716)"
        );
        assert!(
            !out.iter().any(|f| {
                f.layer == WfpLayerKey::OutboundTransportV4 && f.ip_protocol == Some(PROTO_ICMP)
            }),
            "unchecked ICMP gets no packet filter at all — it simply flows"
        );
        // The other named protocols are still individually blocked.
        let named: Vec<u8> = out
            .iter()
            .filter(|f| f.action == WfpAction::Block && f.layer == WfpLayerKey::OutboundTransportV4)
            .filter_map(|f| f.ip_protocol)
            .collect();
        assert_eq!(named.len(), 3, "IGMP/GRE/ESP blocks remain");
    }

    #[test]
    fn fail_closed_mode_b_arms_without_server_ips() {
        // Unlike the catch-all, fail-closed must still cut everything even with
        // NO server exemption (reconnection then needs the user to toggle off).
        let out = fail_closed_block_all_filters(
            "S",
            &FailClosedExemptions::default(),
            KillSwitchProtocols::ALL,
        );
        // ALE: loopback+link-local+broadcast + block = 4. Packet: same 3
        // exemptions + 4 named protocol blocks = 7 (16.HW-0716). IPv6: V6 ALE
        // (loopback+link-local+block = 3) + V6 packet (3) = 6. Total 17.
        assert_eq!(out.len(), 17);
        assert_eq!(
            out.iter().filter(|f| f.action == WfpAction::Block).count(),
            7,
            "V4 ALE + 4 named V4 packet + V6 ALE + V6 packet block-all"
        );
    }

    // ── IPv6 catch-all coverage (Free's only IPv6 handling) ─────────────────

    /// Every V6 filter emitted by a catch-all: loopback + link-local exemption
    /// permits over a block-all, at BOTH V6 layers.
    fn v6_filters(out: &[WfpFilterSpec]) -> Vec<&WfpFilterSpec> {
        out.iter()
            .filter(|f| {
                matches!(
                    f.layer,
                    WfpLayerKey::AleAuthConnectV6 | WfpLayerKey::OutboundIpPacketV6
                )
            })
            .collect()
    }

    #[test]
    fn catch_all_emits_v6_exemptions_and_block_all_at_both_v6_layers() {
        let out = catch_all_kill_switch_filters("S", &full_resolution(), KillSwitchProtocols::ALL);
        for layer in [
            WfpLayerKey::AleAuthConnectV6,
            WfpLayerKey::OutboundIpPacketV6,
        ] {
            let at: Vec<_> = out.iter().filter(|f| f.layer == layer).collect();
            assert_eq!(
                at.len(),
                3,
                "{layer:?}: loopback + link-local exemptions + one block-all"
            );
            // ::1/128 and fe80::/10 exemptions.
            assert!(at.iter().any(|f| f.action == WfpAction::Permit
                && f.remote_subnet_v6 == Some((Ipv6Addr::LOCALHOST, 128))));
            assert!(at.iter().any(|f| f.action == WfpAction::Permit
                && f.remote_subnet_v6 == Some((Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10))));
            // One unconditional block-all.
            let block = at.iter().find(|f| f.action == WfpAction::Block).unwrap();
            assert!(block.remote_ip.is_none());
            assert!(block.remote_subnet.is_none());
            assert!(block.remote_subnet_v6.is_none());
            assert!(block.local_interface_luid.is_none());
            // Every V6 exemption permit must outrank the V6 block-all.
            for permit in at.iter().filter(|f| f.action == WfpAction::Permit) {
                assert!(
                    permit.weight > block.weight,
                    "V6 exemption must outrank the V6 block-all in {layer:?}"
                );
            }
        }
        // V6 ALE filters are per-SID; V6 packet filters are system-wide.
        for f in v6_filters(&out) {
            match f.layer {
                WfpLayerKey::AleAuthConnectV6 => assert_eq!(f.user_sid.as_deref(), Some("S")),
                WfpLayerKey::OutboundIpPacketV6 => {
                    assert_eq!(f.user_sid, None, "V6 packet layer has no ALE_USER_ID")
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn catch_all_v6_coverage_present_even_when_only_tcp_udp_selected() {
        // IPv6 coverage is orthogonal to the V4 protocol mask — the catch-all
        // cuts all IPv6 whenever it fires.
        let tcp_udp = KillSwitchProtocols::from_bits(0x03);
        let out = catch_all_kill_switch_filters("S", &full_resolution(), tcp_udp);
        assert_eq!(
            v6_filters(&out).len(),
            6,
            "6 V6 filters regardless of V4 mask"
        );
    }

    #[test]
    fn fail_closed_mode_b_emits_v6_coverage() {
        let out = fail_closed_block_all_filters(
            "S",
            &FailClosedExemptions::default(),
            KillSwitchProtocols::ALL,
        );
        assert_eq!(
            v6_filters(&out).len(),
            6,
            "V6 half present in fail-closed mode B"
        );
    }

    #[test]
    fn per_ip_paths_never_emit_v6() {
        // The per-destination / per-app fail-closed + kill-switch paths stay
        // IPv4-only (selective V6 needs AAAA — a Pro feature). None of them may
        // ever emit a V6-layer filter.
        assert!(v6_filters(&kill_switch_filters(
            "S",
            &[ip(203, 0, 113, 5)],
            LUID,
            KillSwitchProtocols::ALL
        ))
        .is_empty());
        assert!(v6_filters(&fail_closed_block_destinations(
            "S",
            &[ip(203, 0, 113, 5)],
            KillSwitchProtocols::ALL
        ))
        .is_empty());
        assert!(v6_filters(&app_kill_switch_filters(
            "S",
            &["a.exe".to_string()],
            LUID,
            KillSwitchProtocols::ALL
        ))
        .is_empty());
        assert!(v6_filters(&fail_closed_block_apps(
            "S",
            &["a.exe".to_string()],
            KillSwitchProtocols::ALL
        ))
        .is_empty());
    }

    #[test]
    fn v6_filter_ids_are_distinct_across_layers_and_targets() {
        // The id seed excludes the layer, so ALE/packet twins rely on distinct
        // kind tags. Assert every V6 filter id is unique within a catch-all.
        let out = catch_all_kill_switch_filters("S", &full_resolution(), KillSwitchProtocols::ALL);
        let ids: Vec<u64> = v6_filters(&out).iter().map(|f| f.id.raw).collect();
        let unique: std::collections::HashSet<u64> = ids.iter().copied().collect();
        assert_eq!(unique.len(), ids.len(), "all V6 filter ids must differ");
    }
}
