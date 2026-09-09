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
//! WFP filters per packed CHUNK of protected destinations
//! ([`nrr_platform_api::wfp_slotting`] — WFP ORs same-field conditions, so one
//! filter guards a whole set; the per-address form let the standing count grow
//! linearly into the thousands, which the BFE host does not survive for hours):
//!
//! ```text
//!   Permit  remote_ip ∈ chunk  AND  local_interface == secondary_luid   (high weight)
//!   Block   remote_ip ∈ chunk                                           (lower weight)
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
//! | KS Permit | `0x0040_0000 + i` | `remote_ip ∈ chunk i`, `local_interface` |
//! | KS Block  | `0x0030_0000 + i` | `remote_ip ∈ chunk i` |
//! | rule Permit | `≤ 0x0020_xxxx` | `remote_ip` (no interface) |
//!
//! A flow only matches the filters of its own address's chunk, and band over
//! band `KS Permit > KS Block > rule Permit` — precisely the ordering the
//! leak-proof guarantee needs (the exact `+ i` offsets never decide).
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

use std::net::Ipv4Addr;

use nrr_platform_api::fail_closed::is_exempt_from_blocking;
use nrr_platform_api::types::{WfpAction, WfpFilterSpec, WfpLayerKey};
use nrr_platform_api::wfp_slotting::{pack_v4, V4SlotChunk};
// Weight bands come from `wfp_bands`, which holds the complete order and
// asserts it. This file emits filters; it does not get to invent a band.
use crate::wfp_bands::{
    APP_EXEMPT_BASE, APP_KILLSWITCH_BLOCK_BASE, APP_KILLSWITCH_MAX_APPS, CATCHALL_BLOCK_WEIGHT,
    CATCHALL_EXEMPT_BASE, DOH_BLOCK_BASE, FAKEIP_POOL_PERMIT_BASE, KILLSWITCH_BLOCK_BASE,
    KILLSWITCH_MAX_DESTINATIONS, KILLSWITCH_PERMIT_BASE, PACKET_BLOCK_BASE, PACKET_EXEMPT_BASE,
};

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
    /// Tunnels the user runs beside ours — see
    /// [`FailClosedExemptions::foreign_tunnel_luids`].
    pub foreign_tunnel_luids: Vec<u64>,
}

/// The pseudo-`role` slug stamped into kill-switch filter ids so they
/// never collide with rule-driven filters (which use `primary` /
/// `secondary` / `default`).
pub(super) const KILLSWITCH_ROLE: &str = "killswitch";

// ── Multi-protocol kill-switch ─────────────────────────────────

/// IP protocol numbers (IANA) the kill-switch can target individually.
const PROTO_ICMP: u8 = 1;
const PROTO_IGMP: u8 = 2;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_GRE: u8 = 47;
const PROTO_ESP: u8 = 50;

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

    /// Any TCP/UDP selected → emit an ALE-layer block. `pub(crate)` — the
    /// orchestrator gates the app-covered pin exclusion on the app pair being
    /// armable at all.
    pub(crate) fn wants_ale_block(self) -> bool {
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

// ── DoH/DoT lockdown ────────────────────────────────────────────────────────

/// Standard DoH (HTTPS) service port — a DoH endpoint is an HTTPS server.
const DOH_PORT: u16 = 443;
/// Standard DoT (DNS-over-TLS) / DoQ (DNS-over-QUIC) service port.
const DOT_PORT: u16 = 853;
/// Max resolver IPs the DoH lockdown will pin. Each IP takes 2 slots (TCP+UDP);
/// the band window (`0x0028..0x0030` = `0x0008_0000`) has ample room, this is a
/// runaway backstop.
pub const DOH_MAX_RESOLVER_IPS: usize = 0x0003_0000;

/// Build the DoH/DoT lockdown block filters for `sid`:
/// - per packed resolver-IP chunk: a `Block` on `443` for TCP and UDP (kills
///   DoH / DoH-over-HTTP3 to those resolvers without touching their plain DNS
///   on 53 or general web traffic to other hosts);
/// - when `block_dot`: a global `Block` on `853` for TCP and UDP (DoT / DoQ).
///
/// All filters are ALE-connect, SID-scoped, at [`DOH_BLOCK_BASE`]. Loopback /
/// link-local resolver IPs are skipped (never blocked). Emission order (per
/// chunk: TCP then UDP; then the global DoT pair) fixes the ascending weights
/// so the neutral planner mirror reproduces the same arbitration order.
pub fn doh_dot_block_filters(
    sid: &str,
    resolver_ips: &[Ipv4Addr],
    block_dot: bool,
) -> Vec<WfpFilterSpec> {
    let mut filters = Vec::new();
    let mut weight = DOH_BLOCK_BASE;
    for chunk in pack_v4(
        resolver_ips
            .iter()
            .copied()
            .filter(|ip| !is_exempt_from_blocking(*ip))
            .take(DOH_MAX_RESOLVER_IPS),
    ) {
        for proto in [PROTO_TCP, PROTO_UDP] {
            filters.push(doh_port_block(sid, Some(&chunk), DOH_PORT, proto, weight));
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

/// One DoH/DoT block: ALE-connect `Block` narrowed to `(chunk?, port, proto)`.
fn doh_port_block(
    sid: &str,
    scope: Option<&V4SlotChunk>,
    port: u16,
    proto: u8,
    weight: u64,
) -> WfpFilterSpec {
    let host_seg = scope
        .map(V4SlotChunk::id_seg)
        .unwrap_or_else(|| "any".to_string());
    let tag = format!("{host_seg}-{port}-{proto}");
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Block,
        remote_ip: None,
        remote_ip_set: scope.map(|c| c.members.clone()).unwrap_or_default(),
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
/// Returns the filters in emission order: for each packed chunk of non-exempt
/// destinations, its `Permit` then its `Block`. Loopback / link-local
/// destinations are skipped before packing. Returns an empty vector when
/// there is nothing to protect or the LUID is unusable.
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

    let chunks = pack_v4(
        protected_ips
            .iter()
            .copied()
            .filter(|ip| !is_exempt_from_blocking(*ip))
            .take(KILLSWITCH_MAX_DESTINATIONS),
    );
    let mut filters = Vec::new();
    for (idx, chunk) in chunks.iter().enumerate() {
        let idx = idx as u64;
        // ALE pair (TCP/UDP at the connect layer) — only when TCP or UDP is
        // selected. (The pair is protocol-agnostic, so selecting just one of
        // TCP/UDP still blocks both — a minor over-block in a rare config.)
        if protocols.wants_ale_block() {
            filters.push(permit_via_secondary(sid, chunk, secondary_luid, idx));
            filters.push(block_off_secondary(sid, chunk, idx));
        }
        // 2a — packet-layer egress-conditional pairs so ICMP and
        // the other selected packet protocols are killed the instant the
        // secondary adapter drops (the ALE pair above only sees TCP/UDP).
        filters.extend(packet_egress_pairs(
            sid,
            DestScope::Chunk(chunk),
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
pub(super) fn permit_luid_seg(luid: u64) -> String {
    format!("luid-{luid:016x}")
}

/// `Permit` half: allow the chunk's destinations **only while** the flow
/// egresses `secondary_luid`. The chunk digest is in the id, so a membership
/// change mints a new id and the reconcile swaps the filter make-before-break.
fn permit_via_secondary(
    sid: &str,
    chunk: &V4SlotChunk,
    secondary_luid: u64,
    idx: u64,
) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Permit,
        remote_ip: None,
        remote_ip_set: chunk.members.clone(),
        remote_port: None,
        weight: KILLSWITCH_PERMIT_BASE + idx,
        id: filter_id_for(
            sid,
            KILLSWITCH_ROLE,
            &permit_luid_seg(secondary_luid),
            "ks-permit",
            &chunk.id_seg(),
        ),
        user_sid: Some(sid.to_string()),
        app_pattern: None,
        local_interface_luid: Some(secondary_luid),
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

/// `Block` half: drop the chunk's destinations whenever the egress-conditional
/// permit does not match (i.e. the secondary adapter is down and the route
/// fell back elsewhere).
fn block_off_secondary(sid: &str, chunk: &V4SlotChunk, idx: u64) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Block,
        remote_ip: None,
        remote_ip_set: chunk.members.clone(),
        remote_port: None,
        weight: KILLSWITCH_BLOCK_BASE + idx,
        id: filter_id_for(sid, KILLSWITCH_ROLE, "", "ks-block", &chunk.id_seg()),
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
/// This pins each protected app to the secondary LUID with the same
/// egress-conditional Permit/Block pair the per-destination kill-switch uses —
/// keyed on the app id (`ALE_APP_ID`) instead of a remote IP. The pair is the
/// app's WHOLE guard: its observed destinations deliberately get no
/// per-destination pairs of their own (~12 standing filters per address turned
/// hours of P2P peer churn into a thousands-strong BFE-resident set).
///
/// ALE connect layer only: `ALE_APP_ID` is not exposed at the packet layer, so
/// ICMP from a specific process cannot be egress-gated per-app — an accepted
/// gap: the app's own protocols are TCP/UDP, and another process's ICMP to an
/// observed address is not this rule's traffic. Fails OPEN on a zero LUID,
/// exactly like [`kill_switch_filters`]. Emits nothing unless a TCP/UDP
/// protocol is selected (the ALE pair is protocol-agnostic).
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
        .take(APP_KILLSWITCH_MAX_APPS)
        .enumerate()
    {
        let idx = idx as u64;
        filters.push(permit_app_via_secondary(sid, pattern, secondary_luid, idx));
        // An address a MAIN-LINK rule names is not this app's to cut: the block
        // sits BELOW the primary rule band, so the primary rules' own permits
        // outrank it for every address they name — uncapped, unlike the old
        // per-(app, address) rescue permits this ordering replaced.
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
        remote_ip_set: Vec::new(),
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
/// the per-process Permit's secondary band, below the primary rule band and the
/// app permit — see [`APP_KILLSWITCH_BLOCK_BASE`].
///
/// The id folds a band tag for the same reason the permit folds its LUID: a
/// WFP filter is immutable by key and the add-only install swallows a
/// duplicate id, so a weight change under the OLD id would leave the stale
/// higher-weight block alive across an upgrade.
fn block_app_off_secondary(sid: &str, pattern: &str, idx: u64) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Block,
        remote_ip: None,
        remote_ip_set: Vec::new(),
        remote_port: None,
        weight: APP_KILLSWITCH_BLOCK_BASE + idx,
        id: filter_id_for(
            sid,
            KILLSWITCH_ROLE,
            "sub-main-band",
            "ks-app-block",
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
/// ProtonVPN, ExpressVPN, swiftvpn VPN, …); the rest name clients that lack
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
    "swiftvpn*",
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
/// How many install-tree binaries the exemption is willing to admit in total,
/// across every recognised client. A ceiling, not a target: one product ships a
/// handful of executables, and a number this size only ever binds if something
/// unexpected resolved as a client.
pub const CLIENT_TREE_EXEMPT_CAP: usize = 24;

/// The OTHER executables of each recognised tunnel client, so the exemption
/// covers the process that actually performs the handshake.
///
/// A client is not one binary. `hidemy.name VPN 3.0.exe` is a window: its
/// transports are `OpenVPN\openvpn.exe` and `XRay\ExternalBinaries\xray.exe`,
/// each a separate process, and one of them — never the window — is what talks
/// to the server. Exempting only the resolved binary is why a 2026-09-08 outage
/// held: the user switched protocols for over an hour while every attempt ran
/// from a process no permit named. The bounded Program-Files walk had not found
/// the nested `openvpn.exe` either, and `xray.exe` matches no VPN pattern at
/// all, so neither the resolver nor the drop-driven learner could ever have
/// covered them.
///
/// `client_paths` must hold ONLY recognised clients — resolved built-in VPN
/// patterns, the user-confirmed link provider, drop-verified clients. An
/// ordinary primary-routed application must not reach here: the user routing
/// their mail client to the main link is not a reason to exempt everything
/// shipped beside it.
///
/// The residual hole is one product directory: a binary planted next to a
/// confirmed client is exempt too. That is narrower than it looks — writing
/// there already means being able to replace the client itself — but it is the
/// reason this takes recognised clients rather than any resolved app.
pub fn tunnel_client_tree_exempt_paths(
    resolver: &dyn nrr_platform_api::AppPathResolver,
    client_paths: &[String],
) -> Vec<String> {
    let mut seen: std::collections::HashSet<String> = client_paths
        .iter()
        .map(|p| p.to_ascii_lowercase())
        .collect();
    let mut out = Vec::new();
    for client in client_paths {
        for sibling in resolver.sibling_executables(std::path::Path::new(client)) {
            if out.len() >= CLIENT_TREE_EXEMPT_CAP {
                return out;
            }
            let path = sibling.to_string_lossy().into_owned();
            if seen.insert(path.to_ascii_lowercase()) {
                out.push(path);
            }
        }
    }
    out
}

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
        remote_ip_set: Vec::new(),
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
    exemptions: &FailClosedExemptions,
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
    // The floor both postures share.
    filters.extend(base_ale_exemptions(
        sid,
        &resolution.bootstrap_server_ips,
        &mut weight,
    ));
    // #5 — the primary interface's connected subnets (LAN, DHCP unicast,
    // local router/DNS).
    for (net, prefix) in &resolution.local_subnets {
        filters.push(exempt_subnet(sid, *net, *prefix, weight));
        weight += 1;
    }
    // Hosts known to be reached directly - in these modes those are the
    // main-link carve-outs. The fail-closed twin has always spared them; the
    // catch-all cut them, so a destination the user positively routed over the
    // main link died the moment the tunnel came UP.
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
    // The catch-all block — everything else this user sends off-tunnel.
    // Gated on the protocol mask exactly like its fail-closed twin: with both
    // TCP and UDP unticked this block used to install anyway and cut them,
    // so the checkboxes did nothing in mode B. Narrowed to the single selected
    // protocol when only one is ticked — the ALE layer carries a protocol
    // condition (the packet layers do not).
    if protocols.wants_ale_block() {
        filters.push(catch_all_block(sid, protocols.ale_protocol()));
    }

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
            DestScope::All,
            None,
            resolution.secondary_luid,
            pw,
        ));
        pw += 1;
        filters.extend(base_packet_exemptions(
            sid,
            TR,
            &resolution.bootstrap_server_ips,
            &mut pw,
        ));
        for (net, prefix) in &resolution.local_subnets {
            filters.push(packet_exempt_subnet(sid, TR, *net, *prefix, pw));
            pw += 1;
        }
        // Ping/ICMP to a host the main link's own rules name. TCP/UDP already
        // escapes at the ALE layer via the rule permit; without this the packet
        // layer cut ping to a destination the user explicitly carved out.
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

    // ── IPv6 (Free's only IPv6 handling) ──
    // Whenever the catch-all arms, cut ALL outbound IPv6 too (except loopback,
    // link-local and link-local multicast), independent of the V4 protocol
    // mask above. Selective per-IP
    // V6 needs AAAA, which is not done; the catch-all closes the IPv6 leak.
    filters.extend(catch_all_v6_filters(sid, exemptions.secondary_luid));

    filters
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
        remote_ip_set: Vec::new(),
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
            remote_ip_set: Vec::new(),
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
            remote_ip_set: Vec::new(),
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
                remote_ip_set: Vec::new(),
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

/// The catch-all block: drop every off-tunnel flow this user makes that no
/// higher-weight exemption or primary-rule permit covered.
fn catch_all_block(sid: &str, ip_protocol: Option<u8>) -> WfpFilterSpec {
    let proto_seg = match ip_protocol {
        Some(p) => format!("proto-{p}"),
        None => String::new(),
    };
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Block,
        remote_ip: None,
        remote_ip_set: Vec::new(),
        remote_port: None,
        weight: CATCHALL_BLOCK_WEIGHT,
        // The protocol is part of the id: a filter is immutable by key, and the
        // key is a pure function of the id, so a mask change must produce a
        // DIFFERENT filter rather than silently leave the old one installed.
        id: filter_id_for(sid, KILLSWITCH_ROLE, &proto_seg, "ks-ca-block", "block-all"),
        user_sid: Some(sid.to_string()),
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol,
    }
}

// ── IPv6 catch-all coverage (Free's only IPv6 handling) ─────────────────────
//
// There is no IPv6 routing (selective per-destination V6 needs AAAA, which is
// not done), so the only IPv6 the product ever touches is this: whenever a
// catch-all block arms, ALL outbound IPv6 is cut too, except loopback
// (`::1/128`), link-local (`fe80::/10`) and link-local multicast
// (`ff02::/16`). It mirrors the V4
// exemption-permit-over-block-all pattern at the two IPv6 WFP layers (ALE
// connect for TCP/UDP, packet for ICMPv6/etc.). The exemption/block weight
// bands are reused from V4 — the V6 layers arbitrate SEPARATELY, so there is no
// cross-layer weight collision.

/// IPv4 local network control block `224.0.0.0/24` — exempt. The v4 twin of
/// `ff02::/16`: mDNS (`224.0.0.251`), LLMNR (`.252`), IGMP membership (`.22`)
/// and the router/all-hosts groups live here, routers never forward it, so
/// cutting it breaks the link's own upkeep and leaks nothing. Wider multicast
/// (SSDP's `239.255.255.250`, any global-scope group) is NOT exempt — its scope
/// does leave the link.
const V4_LOCAL_NETWORK_CONTROL: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 0);

// The IPv6 half lives in `killswitch_codegen::v6`; it is re-exported here so
// the emitter stays one name to its callers.
// Everything the cut must not take with it lives in
// `killswitch_codegen::exemptions`.
mod exemptions;

pub use exemptions::default_block_exemptions;
use exemptions::{
    base_ale_exemptions, base_packet_exemptions, exempt_direct_host, exempt_dns_over_primary,
    exempt_egress, exempt_probe_target, exempt_subnet,
};

mod v6;

pub use v6::catch_all_v6_filters;

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
    protected_ips: &[Ipv4Addr],
    protocols: KillSwitchProtocols,
) -> Vec<WfpFilterSpec> {
    if !protocols.any() {
        return Vec::new();
    }
    let chunks = pack_v4(
        protected_ips
            .iter()
            .copied()
            .filter(|ip| !is_exempt_from_blocking(*ip))
            .take(KILLSWITCH_MAX_DESTINATIONS),
    );
    let mut out = Vec::new();
    for (idx, chunk) in chunks.iter().enumerate() {
        let idx = idx as u64;
        let scope = DestScope::Chunk(chunk);
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

    // ── IPv6 (Free's only IPv6 handling) ──
    // The secondary is gone, so cut ALL outbound IPv6 too (except loopback,
    // link-local and link-local multicast), independent of the V4 protocol
    // mask above.
    filters.extend(catch_all_v6_filters(sid, exemptions.secondary_luid));

    filters
}

// ── Protocol-aware filter builders (multi-protocol kill-switch) ──────────────

/// Destination scope of a kill-switch filter: everything (the catch-all
/// forms) or one packed chunk of destinations. The single-address form is
/// gone deliberately — per-address filters are what grew the standing set
/// into the thousands.
#[derive(Clone, Copy)]
enum DestScope<'a> {
    All,
    Chunk(&'a V4SlotChunk),
}

impl DestScope<'_> {
    fn members(self) -> Vec<Ipv4Addr> {
        match self {
            DestScope::All => Vec::new(),
            DestScope::Chunk(c) => c.members.clone(),
        }
    }

    fn key(self) -> String {
        match self {
            DestScope::All => "all".into(),
            DestScope::Chunk(c) => c.id_seg(),
        }
    }
}

/// Build a scope/protocol key for a packet- or ALE-layer filter id.
/// [`DestScope::All`] → "all"; `proto = None` → "any".
fn proto_scope_key(scope: DestScope<'_>, proto: Option<u8>) -> String {
    let p = proto.map(|p| p.to_string()).unwrap_or_else(|| "any".into());
    format!("{}-{p}", scope.key())
}

/// ALE-layer block, optionally narrowed to one IP protocol (TCP/UDP). Scoped
/// to `sid` (ALE exposes `ALE_USER_ID`). [`DestScope::All`] blocks all
/// destinations.
fn ale_block(sid: &str, scope: DestScope<'_>, proto: Option<u8>, weight: u64) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Block,
        remote_ip: None,
        remote_ip_set: scope.members(),
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
    scope: DestScope<'_>,
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
        remote_ip: None,
        remote_ip_set: scope.members(),
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
        remote_ip_set: Vec::new(),
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
        remote_ip_set: Vec::new(),
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
        remote_ip_set: Vec::new(),
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
    scope: DestScope<'_>,
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
    scope: DestScope<'_>,
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
        remote_ip: None,
        remote_ip_set: scope.members(),
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
    scope: DestScope<'_>,
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
mod tests;
