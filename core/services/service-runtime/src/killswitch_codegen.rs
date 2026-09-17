//! leak-proof kill-switch WFP codegen.
//!
//! ## What the kill-switch guarantees
//!
//! When the user routes a set of destinations through a "secondary"
//! adapter (typically a VPN tunnel) and that adapter goes down, the OS
//! route table fails the traffic over to the primary adapter — so the
//! packets that were meant to be private leak out under the real IP.
//! The reactive Fail-Closed path ([`nrr_platform_api::fail_closed`]) closes
//! this by *detecting* the adapter is unavailable and then installing block
//! filters — but
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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nrr_platform_api::fail_closed::is_exempt_from_blocking;
use nrr_platform_api::types::{WfpAction, WfpFilterSpec, WfpLayerKey};
use nrr_platform_api::wfp_slotting::{pack_both, pack_v4, FamilyChunk, V4SlotChunk};
// Weight bands come from `wfp_bands`, which holds the complete order and
// asserts it. This file emits filters; it does not get to invent a band.
use crate::wfp_bands::{
    APP_EXEMPT_BASE, APP_KILLSWITCH_BLOCK_BASE, APP_KILLSWITCH_MAX_APPS, CATCHALL_BLOCK_WEIGHT,
    CATCHALL_EXEMPT_BASE, DOH_BLOCK_BASE, FAKEIP_POOL_PERMIT_BASE, KILLSWITCH_BLOCK_BASE,
    KILLSWITCH_MAX_DESTINATIONS, KILLSWITCH_PERMIT_BASE, PACKET_BLOCK_BASE, PACKET_EXEMPT_BASE,
};

use crate::wfp_codegen::filter_id_for;

/// Everything the kill-switch needs to know about the secondary (VPN)
/// interface for a SID, resolved fresh on every apply.
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
    /// The same endpoints reached over IPv6. Empty on a machine with no v6.
    pub bootstrap_server_ips_v6: Vec<Ipv6Addr>,
    /// Primary interface's connected subnets to exempt (LAN/DHCP/local DNS).
    pub local_subnets: Vec<(Ipv4Addr, u8)>,
    /// The primary link's directly-attached IPv6 prefixes.
    pub local_subnets_v6: Vec<(Ipv6Addr, u8)>,
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
    /// `other` never triggers a block: the packet layer emits ONLY
    /// per-protocol blocks for the named set (ICMP/IGMP/GRE/ESP), never a
    /// protocol-agnostic block-all. A proto-agnostic packet-layer block would
    /// sit ABOVE every ALE verdict and silently kill primary-route rule
    /// permits, the DNS exemption, the app exemptions and the service's own
    /// Mode-B resolver upstream (SYSTEM raw UDP) whenever "Other" is in the
    /// mask — which is the DEFAULT (127). TCP/UDP are enforced exclusively at
    /// the ALE connect layer (SID-scoped and permit/app/DNS-aware); the packet
    /// layer owns only what ALE cannot see. Trade-off accepted by the user: an
    /// exotic IP protocol outside the named set passes. The GUI "Other"
    /// checkbox needs re-labeling.
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
        remote_ip_set_v6: Vec::new(),
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
    protected_ips: &[IpAddr],
    secondary_luid: u64,
    protocols: KillSwitchProtocols,
) -> Vec<WfpFilterSpec> {
    // Fail OPEN on an unusable LUID — a Block with a never-matching
    // egress-conditional Permit would black-hole the protected set.
    if secondary_luid == 0 {
        return Vec::new();
    }

    let chunks = pack_both(
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
        //
        // IPv4 only: the pairs need `FWPM_CONDITION_IP_PROTOCOL`, which lives
        // at the transport layer, and the v6 transport layer is not modelled.
        // An accepted gap with the same shape as the per-app one — a rule
        // host's own traffic is TCP/UDP, which the ALE pair above covers in
        // both families, and ICMPv6 to it is not what the tunnel carries.
        if let FamilyChunk::V4(v4) = chunk {
            filters.extend(packet_egress_pairs(
                sid,
                DestScope::Chunk(v4),
                protocols,
                secondary_luid,
                idx,
            ));
        }
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
    chunk: &FamilyChunk,
    secondary_luid: u64,
    idx: u64,
) -> WfpFilterSpec {
    let id = filter_id_for(
        sid,
        KILLSWITCH_ROLE,
        &permit_luid_seg(secondary_luid),
        "ks-permit",
        &chunk.id_seg(),
    );
    let mut spec = crate::wfp_codegen::chunk_spec(
        chunk,
        crate::wfp_codegen::ale_layer(chunk),
        WfpAction::Permit,
        KILLSWITCH_PERMIT_BASE + idx,
        id,
    );
    spec.user_sid = Some(sid.to_string());
    spec.local_interface_luid = Some(secondary_luid);
    spec
}

/// `Block` half: drop the chunk's destinations whenever the egress-conditional
/// permit does not match (i.e. the secondary adapter is down and the route
/// fell back elsewhere).
/// The v6 twin of [`ale_block`] over a packed chunk: same band, same protocol
/// narrowing, the family's own layer.
fn ale_block_v6(sid: &str, chunk: &FamilyChunk, proto: Option<u8>, weight: u64) -> WfpFilterSpec {
    let id = filter_id_for(
        sid,
        KILLSWITCH_ROLE,
        "",
        "ks-ale-block",
        &format!(
            "{}-{}",
            chunk.id_seg(),
            proto.map_or("any".into(), |p| p.to_string())
        ),
    );
    let mut spec = crate::wfp_codegen::chunk_spec(
        chunk,
        crate::wfp_codegen::ale_layer(chunk),
        WfpAction::Block,
        weight,
        id,
    );
    spec.user_sid = Some(sid.to_string());
    spec.ip_protocol = proto;
    spec
}

fn block_off_secondary(sid: &str, chunk: &FamilyChunk, idx: u64) -> WfpFilterSpec {
    let id = filter_id_for(sid, KILLSWITCH_ROLE, "", "ks-block", &chunk.id_seg());
    let mut spec = crate::wfp_codegen::chunk_spec(
        chunk,
        crate::wfp_codegen::ale_layer(chunk),
        WfpAction::Block,
        KILLSWITCH_BLOCK_BASE + idx,
        id,
    );
    spec.user_sid = Some(sid.to_string());
    spec
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
        remote_ip_set_v6: Vec::new(),
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
        remote_ip_set_v6: Vec::new(),
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

// ── Primary-app kill-switch exemption ────────────────────────────────────────

/// Built-in default VPN-client exemption patterns, always applied on the
/// primary adapter. A VPN client must reach its server over
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
/// These are GLOBS, and the WFP `ALE_APP_ID` condition
/// keys on a real on-disk file path (`FwpmGetAppIdFromFileName0`), NOT a glob.
/// A glob stamped verbatim into a filter's `app_pattern` is therefore silently
/// dropped by the apply layer and no permit installs, trapping the VPN under
/// its own kill-switch. They must be RESOLVED to concrete exe paths through
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
    "amnezia*",
    "outline*",
    "warp-svc",
    "cloudflare warp",
    "tailscale*",
    "zerotier*",
    // Corporate clients of the project's primary audience. None of them carries
    // "vpn" in its name — `*vpn*` does not reach "ViPNet" (v-i-p-n-e-t), and a
    // client that fail-closed cuts is a user who loses the corporate network
    // and has every reason to blame us.
    //
    // Shaped as exe-name globs, which is what the app resolver matches; the
    // adapter-side [`nrr_platform_api::vpn_discovery::VPN_CORPORATE_KEYWORDS`]
    // is a substring list over DISPLAY names too, so the two cannot be derived
    // from one another (several of its entries contain spaces). A client whose
    // binary is named differently still needs the user's own primary-app rule.
    "*vipnet*",
    "*s-terra*",
    "*sterra*",
    // Prefix, not substring: as a substring "continent" is an ordinary word,
    // which is why the adapter-side list leaves it out. An executable that
    // BEGINS with it is a different matter.
    "continent*",
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
/// A client is not one binary. `swiftvpn 3.0.exe` is a window: its
/// transports are `OpenVPN\openvpn.exe` and `XRay\ExternalBinaries\xray.exe`,
/// each a separate process, and one of them — never the window — is what talks
/// to the server. Exempting only the resolved binary is why one observed outage
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
        remote_ip_set_v6: Vec::new(),
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
    // Hosts known to be reached directly — in these modes, the main-link
    // carve-outs. Without this exemption the catch-all would kill a
    // destination the user positively routed over the main link the moment
    // the tunnel came up, even though the fail-closed twin spares the same
    // hosts.
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
    // Gated on the protocol mask exactly like its fail-closed twin, so
    // unticking both TCP and UDP keeps the checkboxes meaningful in mode B.
    // Narrowed to the single selected protocol when only one is ticked — the
    // ALE layer carries a protocol condition (the packet layers do not).
    if protocols.wants_ale_block() {
        filters.push(catch_all_block(sid, protocols.ale_protocol()));
    }

    // ── Transport layer (ICMP/IGMP/GRE/ESP — incl. ping) ──
    // The ALE catch-all above only sees TCP/UDP connects; ICMP/ping is
    // invisible there and would leak out the primary when the secondary
    // adapter drops. The named-protocol blocks (and the mirrored exemption set
    // that shields them) must live at OUTBOUND_TRANSPORT_V4 — no other layer
    // exposes an IP_PROTOCOL condition. Topped by an egress-conditional permit
    // so anything leaving the tunnel is allowed while the secondary adapter is
    // up and the block bites the instant it drops. Skipped when the user's
    // protocol mask selects no packet-layer protocol.
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

    // ── IPv6 ──
    // The blanket posture means "nothing leaves except through the tunnel", and
    // that has to hold for both families or the block is a v4 block wearing a
    // catch-all's name. Same exemption list as the v4 half, in v6 spelling.
    filters.extend(catch_all_v6_filters(
        sid,
        exemptions.secondary_luid,
        &exemptions.bootstrap_server_ips_v6,
        &exemptions.local_subnets_v6,
    ));

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
        remote_ip_set_v6: Vec::new(),
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
            remote_ip_set_v6: Vec::new(),
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
            remote_ip_set_v6: Vec::new(),
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
                remote_ip_set_v6: Vec::new(),
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
        remote_ip_set_v6: Vec::new(),
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

mod fail_closed;
pub use fail_closed::*;
mod filters;
use filters::*;
// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
