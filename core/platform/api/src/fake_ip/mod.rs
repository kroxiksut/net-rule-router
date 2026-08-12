//! Fake-IP — the neutral contract.
//!
//! Fake-IP hands every rule-host its **own** address out of a reserved pool
//! instead of the provider's real answer, so routing and the kill-switch become
//! exactly per-hostname. That removes the collateral damage of shared CDN
//! addresses (`chatgpt.com` and unrelated hosts share one Google front-end IP,
//! so pinning the IP either over- or under-blocks) and removes the
//! dependency on the provider's DNS being honest — without terminating TLS.
//!
//! The mechanism is a TUN adapter plus a userspace TCP/IP stack: the adapter
//! receives raw IP packets addressed to a fake address, the stack reassembles
//! them into TCP/UDP flows, looks the fake address up in the allocator to learn
//! the hostname, and relays the flow to the real destination over the route that
//! hostname's rule selected. No MITM: the client's own TLS/QUIC bytes are
//! spliced through untouched.
//!
//! ## What lives here (and what does not)
//!
//! Per the policy/mechanism seam this module holds ONLY the neutral
//! half, all of it pure and testable on every OS:
//!
//! - [`allocator`] — the address pool (RFC 2544 `198.18.0.0/15` + `fc00::/18`)
//!   and the bidirectional hostname <-> fake-address map.
//! - [`scope`] — which hostnames get a fake address at all. Fake-IP is
//!   opt-in (default off) and, once on, applies broadly EXCEPT for the
//!   peer-to-peer/crypto application groups, which keep real addresses.
//! - [`tun`] — the [`TunAdapterPort`] trait: open an L3 adapter, read/write
//!   packets, MTU. This is the one genuinely OS-specific piece.
//!
//! The OS MECHANISM behind [`TunAdapterPort`] lives in each backend crate:
//! **Windows** binds the redistributable Wintun driver (WireGuard LLC — the only
//! platform needing a third-party driver, which is why its attribution is a
//! release requirement), **Linux** opens the native `/dev/net/tun`, **macOS** the
//! native `utun`. The userspace stack and the relay on top of the port are
//! neutral and shared.

pub mod allocator;
pub mod flow_owner;
pub mod scope;
pub mod stale_flows;
pub mod tun;

pub use allocator::{
    BindingChange, BindingChangeSink, FakeIpAllocator, FakeIpBinding, FakeIpError,
    FakeIpPoolConfig, LocalSubnet, PoolCollision, FAKE_IP_FIRST_HOST_INDEX, FAKE_IP_GATEWAY_INDEX,
    FAKE_IP_V4_BASE, FAKE_IP_V4_PREFIX_LEN, FAKE_IP_V6_BASE, FAKE_IP_V6_PREFIX_LEN,
};
pub use flow_owner::{FlowOwnerLookup, MockFlowOwnerLookup, NoopFlowOwnerLookup};
pub use scope::{FakeIpScope, FakeIpVerdict, RealIpReason};
pub use stale_flows::{MockStaleFlowReset, NoopStaleFlowReset, StaleFlowReset, StaleFlowSweep};
pub use tun::{
    MockTunAdapter, MockTunState, NoopTunAdapter, TunAdapterConfig, TunAdapterPort, TunControl,
    TunDevice, DEFAULT_TUN_MTU, DEFAULT_TUN_RING_CAPACITY_BYTES,
};
