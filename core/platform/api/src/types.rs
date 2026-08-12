//! Neutral platform-level network value types.
//!
//! These types represent the platform's view of the routing/packet-filter state
//! — they are **not** business-domain types. `CanonicalProfile` (from
//! `nrr-domain`) is converted to `ApplyActionPlan` by the service layer before
//! being handed to the OS apply engine (e.g. the Windows WFP `WindowsApplyEngine`).
//! Per the policy/mechanism seam these DEFINITIONS live in the neutral
//! `nrr-platform-api`; each OS backend consumes them and implements the ports.
//!
//! IPv6 routing is out-of-scope for the Free tier: per-destination V6 needs
//! AAAA resolution (a Pro feature), so an IPv6 destination in an ordinary rule
//! is silently skipped by the apply layer with an audit note "skipped: IPv6
//! destination not supported". The one exception is the **catch-all
//! kill-switch**, which blocks ALL outbound IPv6 (except loopback + link-local)
//! whenever it fires — see [`WfpLayerKey::AleAuthConnectV6`] /
//! [`WfpFilterSpec::remote_subnet_v6`]. Everything else uses
//! `std::net::Ipv4Addr`.

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::enforcement::RouteTableRef;

// ── WFP identity ────────────────────────────────────────────────────────────
//
// Stable byte-array identifiers for NetRuleRouter's own WFP provider/sub-layer.
// They are pure data (`[u8; 16]`), so they live in the neutral crate alongside
// the WFP value-types and the `snapshot` hashing logic that references them; the
// Windows backend re-exports them and converts to `windows::core::GUID`.

/// NetRuleRouter WFP provider GUID `{B4E0D8A2-3F7C-4E1B-9D5F-6C2A8B0E1F3D}`.
pub const WFP_PROVIDER_GUID: [u8; 16] = [
    0xB4, 0xE0, 0xD8, 0xA2, // Data1
    0x3F, 0x7C, // Data2
    0x4E, 0x1B, // Data3
    0x9D, 0x5F, 0x6C, 0x2A, 0x8B, 0x0E, 0x1F, 0x3D, // Data4
];

/// NetRuleRouter WFP sub-layer GUID `{C1D2E3F4-5A6B-7C8D-9E0F-1A2B3C4D5E6F}`.
pub const WFP_SUBLAYER_GUID: [u8; 16] = [
    0xC1, 0xD2, 0xE3, 0xF4, // Data1
    0x5A, 0x6B, // Data2
    0x7C, 0x8D, // Data3
    0x9E, 0x0F, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, // Data4
];

/// Base weight for individual WFP filters within our sub-layer; each filter's
/// weight = `FILTER_WEIGHT_BASE + canonical_position_index` for deterministic
/// evaluation order. Neutral numeric constant so the `fail_closed` planning
/// logic can reference it.
pub const FILTER_WEIGHT_BASE: u64 = 0x0010_0000;

// ── Route table ───────────────────────────────────────────────────────────────

/// One IPv4 route entry in the Windows forwarding table.
/// Mirrors the relevant fields of `MIB_IPFORWARDROW2`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteEntry {
    /// Destination network address (IPv4 only — see module doc).
    pub destination: Ipv4Addr,
    /// CIDR prefix length (0–32).
    pub prefix_length: u8,
    /// Next-hop gateway address.
    pub next_hop: Ipv4Addr,
    /// Interface index (`IfIndex`).
    pub interface_index: u32,
    /// Route metric. Lower = preferred.
    pub metric: u32,
    /// `true` when this entry was added by our apply layer.
    /// Used to distinguish our routes from system/DHCP/VPN routes.
    pub is_ours: bool,
    /// Which routing table this entry belongs to.
    /// Defaults to [`RouteTableRef::Main`]; the Windows lowering only ever
    /// produces `Main` and ignores the rest. `#[serde(skip)]` keeps the
    /// persisted / hashed RouteEntry shape unchanged (Windows snapshot + IPC
    /// are untouched), so no state-DB wipe is needed. The Linux lowering
    /// populates `Principal` / `Tagged`.
    #[serde(skip)]
    pub table: RouteTableRef,
}

// ── WFP types ─────────────────────────────────────────────────────────────────

/// Opaque token representing an open packet-filter engine session.
///
/// Created by `WindowsApiPort::wfp_engine_open`. Must be closed via
/// `WindowsApiPort::wfp_engine_close`. In the Windows backend this wraps the raw
/// `HFWPENGINE` handle as a `u64`; in tests it is an opaque integer.
///
/// Design rule: no raw `HANDLE`/`HFWPENGINE` TYPE crosses the public
/// API — only the `u64` handle VALUE, which the OS backend that opened it turns
/// back into its native handle. `raw` is `pub` so the OS backend crate can
/// still build and read the token.
#[derive(Debug, Serialize, Deserialize)]
pub struct WfpEngineToken {
    /// Raw handle value. `u64` covers both 32-bit and 64-bit Windows.
    pub raw: u64,
}

/// Stable identifier for a WFP filter managed by this product.
///
/// Generated as UUIDv5(`PROVIDER_GUID || rule_id || layer_key`) so that
/// re-applying the same rule produces the same `WfpFilterId` —
/// enabling idempotency without enumerating existing filters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WfpFilterId {
    pub raw: u64,
}

impl WfpFilterId {
    /// Construct from a precomputed `u64` seed. Used by the per-SID decision
    /// runner to derive deterministic ids from a `(sid, role, stable_id)`
    /// triple.
    pub const fn from_raw(raw: u64) -> Self {
        Self { raw }
    }
}

/// The WFP layer a filter belongs to.
///
/// `AleAuthConnectV4` is used for outbound TCP/UDP blocking.
/// Packet-layer and IPv6 layers are out-of-scope (see module doc).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WfpLayerKey {
    /// `FWPM_LAYER_ALE_AUTH_CONNECT_V4` — outbound per-flow IPv4 (TCP connect
    /// + first UDP send). Does NOT classify ICMP/IGMP/GRE/ESP.
    AleAuthConnectV4,
    /// `FWPM_LAYER_OUTBOUND_IPPACKET_V4` — outbound IPv4 packet layer. Sees
    /// every outbound IP packet (incl. ICMP/IGMP/GRE/ESP), used by the
    /// multi-protocol kill-switch to block protocols the ALE connect layer
    /// can't see (e.g. ping). ⚠ This layer does NOT expose `ALE_USER_ID` or
    /// `ALE_APP_ID`: a filter here MUST have `user_sid = None` and
    /// `app_pattern = None`, or `FwpmFilterAdd0` fails `FWP_E_CONDITION_NOT_FOUND`.
    OutboundIpPacketV4,
    /// `FWPM_LAYER_ALE_AUTH_CONNECT_V6` — outbound per-flow IPv6 (TCP connect
    /// and first UDP send). The IPv6 twin of [`AleAuthConnectV4`]; does NOT
    /// classify ICMPv6 or other non-TCP/UDP protocols (that is the V6 packet
    /// layer's job). Used by the catch-all kill-switch to cut all outbound
    /// IPv6 TCP/UDP off-tunnel.
    AleAuthConnectV6,
    /// `FWPM_LAYER_OUTBOUND_IPPACKET_V6` — outbound IPv6 packet layer. Sees
    /// every outbound IPv6 packet (incl. ICMPv6/etc.), the IPv6 twin of
    /// [`OutboundIpPacketV4`] and where the catch-all kill-switch cuts IPv6
    /// protocols the ALE connect layer can't see. ⚠ Like the V4 packet layer,
    /// it does NOT expose `ALE_USER_ID` or `ALE_APP_ID`: a filter here MUST
    /// have `user_sid = None` and `app_pattern = None`, or `FwpmFilterAdd0`
    /// fails `FWP_E_CONDITION_NOT_FOUND`.
    OutboundIpPacketV6,
    /// `FWPM_LAYER_OUTBOUND_TRANSPORT_V4` — outbound IPv4 transport layer.
    /// Sits below ALE, above the packet layer; classifies every outbound
    /// transport-protocol send (TCP/UDP/ICMP and raw-socket protocols) and —
    /// unlike the packet layer — DOES expose `FWPM_CONDITION_IP_PROTOCOL`,
    /// so it is the only place a protocol-narrowed block with no ALE context
    /// can live. Caveats: stack-originated IGMP and kernel-injected
    /// GRE/ESP tunnels bypass this layer (they never traverse the transport
    /// stack), and like the packet layer it has NO `ALE_USER_ID` / `ALE_APP_ID`
    /// — `user_sid` and `app_pattern` MUST be `None` here.
    OutboundTransportV4,
}

impl WfpLayerKey {
    /// Whether `FWPM_CONDITION_IP_PROTOCOL` is a valid condition at this
    /// layer. Per the Win32 "Filtering conditions available at each filtering
    /// layer" reference: the ALE connect and transport layers expose it; the
    /// IPPACKET layers do NOT — a protocol-narrowed filter at the
    /// packet layer fails `FwpmFilterAdd0` with `FWP_E_CONDITION_NOT_FOUND`,
    /// silently voiding the multi-protocol kill-switch.
    pub fn supports_ip_protocol(self) -> bool {
        !matches!(
            self,
            WfpLayerKey::OutboundIpPacketV4 | WfpLayerKey::OutboundIpPacketV6
        )
    }

    /// Whether `FWPM_CONDITION_ALE_USER_ID` / `FWPM_CONDITION_ALE_APP_ID` are
    /// valid conditions at this layer (ALE layers only).
    pub fn supports_ale_scoping(self) -> bool {
        matches!(
            self,
            WfpLayerKey::AleAuthConnectV4 | WfpLayerKey::AleAuthConnectV6
        )
    }
}

/// Action a WFP filter takes when its conditions match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WfpAction {
    /// `FWP_ACTION_BLOCK` — drop the connection.
    Block,
    /// `FWP_ACTION_PERMIT` — allow the connection.
    Permit,
}

/// Specification for a WFP filter to be added.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WfpFilterSpec {
    /// Which layer this filter belongs to.
    pub layer: WfpLayerKey,
    /// What to do when conditions match.
    pub action: WfpAction,
    /// Match condition: specific remote IPv4 address (None = any).
    pub remote_ip: Option<Ipv4Addr>,
    /// Match condition: specific remote port (None = any).
    pub remote_port: Option<u16>,
    /// Filter weight within our sub-layer.
    /// Deterministic: `BASE_WEIGHT + canonical_position_index`.
    pub weight: u64,
    /// Stable identifier seed — used to compute the filter's UUID key via
    /// UUIDv5. The same seed always produces the same UUID, enabling
    /// idempotent applies without enumerating existing filters.
    pub id: WfpFilterId,
    /// Match condition: connection's user SID
    /// (`FWPM_CONDITION_ALE_USER_ID`). `None` = any user (system-wide
    /// filter). `Some(sid)` = filter only matches connections from
    /// processes whose token user SID equals `sid`. Multi-active per-
    /// user routing sets one filter per (user-SID, decision) pair so
    /// concurrent users have independent routing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_sid: Option<String>,
    /// Match condition: process executable
    /// (`FWPM_CONDITION_ALE_APP_ID`). `None` = any process.
    /// `Some(path)` = filter only matches connections initiated by the
    /// given executable. The path is the user-facing Win32 path
    /// (`C:\Path\app.exe`); the production apply layer converts it to
    /// the NT-format byte blob via `FwpmGetAppIdFromFileName0` before
    /// adding the filter. The `Application` rule kind uses this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_pattern: Option<String>,
    /// Match condition: the
    /// connection's **egress local interface**
    /// (`FWPM_CONDITION_IP_LOCAL_INTERFACE`, `FWP_UINT64` interface
    /// LUID). `None` = any interface (the default for every rule-driven
    /// filter). `Some(luid)` = the filter only matches connections the
    /// OS route lookup would send out the interface with this LUID.
    ///
    /// This is the primitive behind the leak-proof kill-switch: a
    /// `Permit` filter carrying `local_interface_luid = Some(secondary_luid)`
    /// over a lower-weight `Block` filter for the same destination means
    /// "permit only while the route egresses the secondary adapter; the instant the
    /// secondary adapter drops and traffic would fall back to another interface the
    /// permit stops matching and the block fires — with no reactive
    /// route reinstall and no race window".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_interface_luid: Option<u64>,
    /// Match condition: a
    /// remote IPv4 **subnet** as `(network, prefix_len)`, mapped to
    /// `FWPM_CONDITION_IP_REMOTE_ADDRESS_V4` with an `FWP_V4_ADDR_AND_MASK`
    /// value. `None` = no subnet condition. Mutually exclusive with
    /// `remote_ip` (an exact host is a /32 — use `remote_ip` for that).
    ///
    /// The catch-all kill-switch uses this to carve the system exemptions
    /// the block must never cover: loopback `127.0.0.0/8`, link-local
    /// `169.254.0.0/16`, and the user's local subnet (so DHCP, the local
    /// router/DNS, and LAN keep working while everything else is blocked
    /// off-tunnel).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_subnet: Option<(Ipv4Addr, u8)>,
    /// IPv6 catch-all kill-switch (Free's only IPv6 handling) — match
    /// condition: a remote IPv6 **subnet** as `(network, prefix_len)`, mapped
    /// to `FWPM_CONDITION_IP_REMOTE_ADDRESS_V6` with an `FWP_V6_ADDR_AND_MASK`
    /// value. `None` = no subnet condition. The IPv6 twin of [`remote_subnet`].
    ///
    /// The catch-all kill-switch uses this to carve the IPv6 system exemptions
    /// its block-everything must never cover: loopback `::1/128` and link-local
    /// `fe80::/10`. The per-IP fail-closed path stays IPv4-only — selective V6
    /// destinations need AAAA resolution, a Pro feature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_subnet_v6: Option<(Ipv6Addr, u8)>,
    /// Match condition (multi-protocol kill-switch): IP protocol
    /// number (`FWPM_CONDITION_IP_PROTOCOL`, `FWP_UINT8`). Common values:
    /// ICMP=1, IGMP=2, TCP=6, UDP=17, GRE=47, ESP=50. `None` = any protocol.
    /// ⚠ Only valid at layers where
    /// [`WfpLayerKey::supports_ip_protocol`] is true (ALE connect, transport).
    /// The IPPACKET layers do NOT expose this condition — a protocol-narrowed
    /// packet-layer filter fails `FwpmFilterAdd0` with
    /// `FWP_E_CONDITION_NOT_FOUND`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_protocol: Option<u8>,
}

impl WfpFilterSpec {
    /// Validate that every condition this spec carries is expressible at its
    /// layer. Returns the human-readable reason of the first
    /// violation. The real `FwpmFilterAdd0` rejects such filters with
    /// `FWP_E_CONDITION_NOT_FOUND` at apply time — catching it here turns a
    /// silent per-filter skip in production (and a false green in tests,
    /// where the mock engine accepts anything) into a structured error.
    pub fn validate_layer_conditions(&self) -> Result<(), &'static str> {
        if self.ip_protocol.is_some() && !self.layer.supports_ip_protocol() {
            return Err("FWPM_CONDITION_IP_PROTOCOL is not available at the IPPACKET layers");
        }
        if !self.layer.supports_ale_scoping() {
            if self.user_sid.is_some() {
                return Err("FWPM_CONDITION_ALE_USER_ID is only available at the ALE layers");
            }
            if self.app_pattern.is_some() {
                return Err("FWPM_CONDITION_ALE_APP_ID is only available at the ALE layers");
            }
        }
        Ok(())
    }
}

/// A WFP filter as returned by enumeration (existing filter in the system).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WfpFilterRecord {
    pub id: WfpFilterId,
    pub layer: WfpLayerKey,
    pub action: WfpAction,
    pub remote_ip: Option<Ipv4Addr>,
    pub remote_port: Option<u16>,
    pub weight: u64,
    /// `FWPM_CONDITION_ALE_USER_ID` value when the
    /// filter was added with a per-user condition. Production
    /// enumeration reads this from the live WFP filter; the mock
    /// `MockWindowsApi` carries through whatever `WfpFilterSpec.user_sid`
    /// the caller passed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_sid: Option<String>,
    /// `FWPM_CONDITION_ALE_APP_ID` source path the
    /// filter was added with. Mirrors `WfpFilterSpec::app_pattern`.
    /// Production enumeration cannot reverse the NT-format byte blob
    /// back to a user-facing path; live WFP records carry `None` and
    /// the apply layer cross-references against persisted state. Mock
    /// enumeration round-trips through `WfpFilterSpec::app_pattern`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_pattern: Option<String>,
    /// `FWPM_CONDITION_IP_LOCAL_INTERFACE`
    /// LUID the filter was added with. Mirrors
    /// `WfpFilterSpec::local_interface_luid`. Unlike `app_pattern` /
    /// `user_sid`, the LUID is a plain `FWP_UINT64` the enumeration path
    /// *can* recover, so live WFP records carry it back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_interface_luid: Option<u64>,
    /// The remote IPv4
    /// subnet `(network, prefix_len)` the filter was added with. Mirrors
    /// `WfpFilterSpec::remote_subnet`. The enumeration path *can* recover
    /// it from the `FWP_V4_ADDR_AND_MASK` condition value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_subnet: Option<(Ipv4Addr, u8)>,
    /// IPv6 catch-all kill-switch — the remote IPv6 subnet `(network,
    /// prefix_len)` the filter was added with. Mirrors
    /// `WfpFilterSpec::remote_subnet_v6`. The enumeration path recovers it
    /// from the `FWP_V6_ADDR_AND_MASK` condition value, so rollback re-adds the
    /// IPv6 exemption permits with their subnet condition intact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_subnet_v6: Option<(Ipv6Addr, u8)>,
    /// Multi-protocol kill-switch: `FWPM_CONDITION_IP_PROTOCOL`
    /// (`FWP_UINT8`) value the filter was added with. The enumeration path
    /// recovers it, so rollback re-adds packet-layer kill-switch filters with
    /// their protocol narrowing intact. Mirrors `WfpFilterSpec::ip_protocol`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_protocol: Option<u8>,
}

// ── Apply action plan ─────────────────────────────────────────────────────────

/// Concrete actions to execute in one apply transaction.
///
/// Computed by `compute_action_plan(snapshot, candidate_profile)`.
/// The types here are intentionally platform-level — no
/// `CanonicalProfile` or domain types, just concrete route/filter mutations.
#[derive(Clone, Debug, Default)]
pub struct ApplyActionPlan {
    pub routing_actions: Vec<RoutingAction>,
    pub wfp_actions: Vec<WfpFilterAction>,
}

impl ApplyActionPlan {
    pub fn is_empty(&self) -> bool {
        self.routing_actions.is_empty() && self.wfp_actions.is_empty()
    }
}

/// A single routing table mutation.
#[derive(Clone, Debug)]
pub enum RoutingAction {
    AddRoute(RouteEntry),
    DeleteRoute(RouteEntry),
    UpdateRoute { old: RouteEntry, new: RouteEntry },
}

/// A single WFP filter mutation.
#[derive(Clone, Debug)]
pub enum WfpFilterAction {
    AddFilter(WfpFilterSpec),
    DeleteFilter(WfpFilterId),
}
