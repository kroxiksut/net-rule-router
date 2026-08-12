//! The neutral fake-IP relay.
//!
//! The adapter (slice 2) delivers raw IP packets addressed to the pool, and the
//! allocator (slice 1) knows which hostname each fake address stands for. This
//! module is what sits between them and the real internet:
//!
//! - [`flow`] — parse a packet far enough to identify its flow and spot the
//!   segment that opens one;
//! - [`relay`] — decide what each flow is (which hostname, which real address,
//!   which route) and remember the flows already decided;
//! - [`dialer`] — open the real connection and move bytes, behind a trait so
//!   the decision logic is testable without a network and so per-OS route
//!   binding never leaks into it;
//! - [`stack`] — the userspace TCP/IP stack (`smoltcp`) that terminates a
//!   flow addressed to a fake address and splices it to the dialer's upstream.
//!
//! Everything here is OS-neutral and lives in `service-runtime` on purpose:
//! these are policy decisions about the user's traffic, and the policy/
//! mechanism seam keeps the policy neutral while only the mechanism (the TUN
//! adapter itself) is per-OS.
//!
//! The decision layer ([`relay`]) is deliberately finished and tested before
//! the byte-moving stack — a wrong verdict there would send a user's traffic to
//! the wrong host, and that must be provable without any network at all. The
//! [`stack`] on top is the mechanism: TCP and UDP/QUIC are both complete;
//! production port adapters remain hardware-gated work. UDP
//! reaching the pool at all is gated by [`global_udp_relay_enabled`] — see
//! `killswitch_codegen::fake_ip_pool_permit_filters`.

use std::sync::Arc;

pub mod dialer;
pub mod direct;
pub mod enforcement;
pub mod flow;
pub mod health;
pub mod lifecycle;
pub mod production_ports;
pub mod relay;
pub mod self_heal;
pub mod stack;
pub mod vpn_client_bypass;

pub use dialer::{
    MockRelayDialer, RelayDatagram, RelayDialer, RelayError, RelayNameResolver, RelaySourceAddrs,
    RelaySplit, RelayStream, RelayWriteHalf, SourceBindDecision, StaticSourceAddrs,
    SystemRelayDialer, UpstreamTarget, UPSTREAM_CONNECT_TIMEOUT,
};
pub use direct::{
    ArmedDirectFakeIpAnswerer, DirectAwareUpstreamResolver, DirectRealIpMap, DIRECT_MAP_CAPACITY,
};
pub use enforcement::{
    augment_codegen_for_fake_ip, plan_fake_ip_enforcement, FakeIpAugmentation,
    FakeIpEnforcementContext, FakeIpEnforcementPlan, NoSharedIps, SharedIpCensus,
};
pub use flow::{parse_packet, FlowKey, FlowProtocol, ParsedPacket};
pub use health::FakeIpHealth;
pub use lifecycle::{
    FakeIpAssembly, FakeIpBindingView, FakeIpController, FakeIpDatapathStatus, FakeIpStackFactory,
};
pub use production_ports::{
    CacheUpstreamResolver, CompositeFlowObserver, ConfirmedNameResolver, FlowActivityObserver,
    RuleBookRouteSelector,
};
pub use relay::{
    FixedRouteSelector, RelayCore, RelayDecision, RelaySession, RouteSelector, SessionTable,
    StaticUpstreamResolver, UpstreamAddressResolver, DEFAULT_SESSION_CAPACITY,
    DEFAULT_SESSION_IDLE_MS,
};
pub use self_heal::{
    probe_and_heal, HealPersistFn, HealVerdict, RuntimeHostExclusions, VpnSelfHealObserver,
};
pub use stack::{
    FakeIpStack, FlowObserver, NoopFlowObserver, StackWaker, TunPhyDevice,
    DEFAULT_SOCKET_BUFFER_BYTES,
};
pub use vpn_client_bypass::{
    NoVpnClientBypass, OwnerLookupVpnClientBypass, VpnClientFlowBypass, DEFAULT_MIN_PROBE_INTERVAL,
};

/// Process-wide live gate for the fake-IP UDP relay toggle:
/// `true` admits UDP (QUIC/HTTP-3) into the pool permit instead of hard-
/// blocking it — see [`crate::killswitch_codegen::fake_ip_pool_permit_filters`].
/// Read fresh on every per-SID codegen compute
/// ([`crate::per_sid_orchestrator`]) and written by
/// `ProductionServiceStability::set` on a settings save, mirroring
/// [`crate::dns_resolver::global_dns_fast_answers`]. A single process-wide
/// atomic (not per-SID) because the underlying setting is a global service
/// setting, and the two call sites (boot seed, live write) are composed in
/// different scopes — a process singleton keeps them on one value by
/// construction. Defaults to `false` (hard-block UDP, today's behaviour); the
/// boot path overwrites it with the persisted setting before the first
/// per-SID compute.
pub fn global_udp_relay_enabled() -> Arc<std::sync::atomic::AtomicBool> {
    static FLAG: std::sync::OnceLock<Arc<std::sync::atomic::AtomicBool>> =
        std::sync::OnceLock::new();
    Arc::clone(FLAG.get_or_init(|| Arc::new(std::sync::atomic::AtomicBool::new(false))))
}

/// Process-wide live gate for the fake-IP instant-reset toggle:
/// `true` (default) keeps the base behaviour — a relay dial refused by
/// source-address policy alone (most commonly: the secondary adapter is
/// unresolved during a VPN reconnect) resets the client immediately. `false`
/// holds and retries that ONE refusal class for a bounded window instead —
/// see [`stack`]'s dial-worker hold-and-retry path. Read fresh on every TCP
/// dial and written by `ProductionServiceStability::set` on a settings save,
/// mirroring [`global_udp_relay_enabled`]. Unlike that flag, this one never
/// feeds WFP filter generation — it only selects which branch a failed dial
/// takes — so production hands it to [`stack::FakeIpStack::with_instant_rst`]
/// at construction and no replan is needed on a live flip. The boot path
/// overwrites the default with the persisted setting before the stack first
/// starts.
pub fn global_instant_rst_enabled() -> Arc<std::sync::atomic::AtomicBool> {
    static FLAG: std::sync::OnceLock<Arc<std::sync::atomic::AtomicBool>> =
        std::sync::OnceLock::new();
    Arc::clone(FLAG.get_or_init(|| Arc::new(std::sync::atomic::AtomicBool::new(true))))
}
