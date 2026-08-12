//! Fake-IP datapath health — the "answers vs. packets" pulse.
//!
//! Under an armed block-all the relay is the machine's single escape hatch:
//! every direct host is answered with a virtual address and carried by the
//! stack. A wedged TUN datapath (driver interference, session stall) is then
//! indistinguishable from a healthy idle one *unless* someone correlates the
//! two facts the service already produces independently:
//!
//! - the DNS side keeps handing out virtual addresses ([`record_answer`]);
//! - the packet side stops seeing ANY inbound packets ([`record_ingress`]).
//!
//! Sustained "answers without ingress" is the wedge signature — a client that
//! resolved a name connects to it within milliseconds, so a healthy datapath
//! shows ingress in the same observation window as the answers. The
//! [`FakeIpController`](super::FakeIpController) watchdog consumes these
//! counters and rebuilds the stack when the signature holds for several
//! consecutive ticks.
//!
//! [`record_answer`]: FakeIpHealth::record_answer
//! [`record_ingress`]: FakeIpHealth::record_ingress

use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonic counters shared between the DNS answerers (writers), the packet
/// stack (writer) and the controller watchdog (reader). Cheap enough to bump
/// on every packet.
///
/// The TCP/UDP relay-flow and dial-outcome counters below are bumped once
/// PER FLOW (a dial attempted), never once per byte or per packet, so they
/// carry the same "cheap enough" guarantee as `answers`/`ingress`. They give
/// visibility into the UDP relay's behaviour without per-connection log
/// events —
/// [`FakeIpController::watchdog_tick`](super::lifecycle::FakeIpController::watchdog_tick)
/// logs their deltas periodically.
#[derive(Default)]
pub struct FakeIpHealth {
    /// Virtual addresses handed out to clients (rule-host + direct answerers).
    answers: AtomicU64,
    /// Inbound packets the stack read off the TUN device — any packet counts:
    /// liveness of the path is what is being measured, not flow accounting.
    ingress: AtomicU64,
    /// TCP relay flows opened (a dial was attempted) since the process started.
    tcp_relay_flows_opened: AtomicU64,
    /// TCP upstream dial outcomes since the process started.
    tcp_dial_ok: AtomicU64,
    /// TCP dials that failed specifically because source-address policy
    /// refused them (instant or held — see `fake_ip_instant_rst`).
    tcp_dial_refused: AtomicU64,
    /// TCP dials that failed for any other reason (genuine network error).
    tcp_dial_failed: AtomicU64,
    /// UDP relay client flows opened (a dial was attempted) since the process
    /// started.
    udp_relay_flows_opened: AtomicU64,
    /// UDP upstream dial outcomes since the process started.
    udp_dial_ok: AtomicU64,
    /// UDP dials that failed specifically because source-address policy
    /// refused them. UDP dials run inline on the poll thread and are never
    /// held (see `fake_ip::stack::udp_forward_upstream`).
    udp_dial_refused: AtomicU64,
    /// UDP dials that failed for any other reason (genuine network error).
    udp_dial_failed: AtomicU64,
    /// ICMP port-unreachable replies the stack sent because a datagram it had
    /// already taken off a bound fake endpoint could not be relayed. The signal
    /// that a client was told to fall back immediately rather than being left to
    /// time out — a nonzero count next to `udp_dial_refused` is the expected
    /// pairing, a nonzero count without one means an upstream died mid-flow.
    udp_unreachable_sent: AtomicU64,
}

impl FakeIpHealth {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A virtual address was just handed to a client.
    pub fn record_answer(&self) {
        self.answers.fetch_add(1, Ordering::Relaxed);
    }

    /// The stack read at least one packet off the TUN device.
    pub fn record_ingress(&self) {
        self.ingress.fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub fn answers(&self) -> u64 {
        self.answers.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn ingress(&self) -> u64 {
        self.ingress.load(Ordering::Relaxed)
    }

    /// A TCP relay flow was opened — a dial was attempted (outcome unknown yet).
    pub fn record_tcp_relay_flow_opened(&self) {
        self.tcp_relay_flows_opened.fetch_add(1, Ordering::Relaxed);
    }

    /// A TCP dial completed successfully.
    pub fn record_tcp_dial_ok(&self) {
        self.tcp_dial_ok.fetch_add(1, Ordering::Relaxed);
    }

    /// A TCP dial failed on source-address policy alone.
    pub fn record_tcp_dial_refused(&self) {
        self.tcp_dial_refused.fetch_add(1, Ordering::Relaxed);
    }

    /// A TCP dial failed for a genuine network reason.
    pub fn record_tcp_dial_failed(&self) {
        self.tcp_dial_failed.fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub fn tcp_relay_flows_opened(&self) -> u64 {
        self.tcp_relay_flows_opened.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn tcp_dial_ok(&self) -> u64 {
        self.tcp_dial_ok.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn tcp_dial_refused(&self) -> u64 {
        self.tcp_dial_refused.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn tcp_dial_failed(&self) -> u64 {
        self.tcp_dial_failed.load(Ordering::Relaxed)
    }

    /// A UDP relay client flow was opened — a dial was attempted.
    pub fn record_udp_relay_flow_opened(&self) {
        self.udp_relay_flows_opened.fetch_add(1, Ordering::Relaxed);
    }

    /// A UDP dial completed successfully.
    pub fn record_udp_dial_ok(&self) {
        self.udp_dial_ok.fetch_add(1, Ordering::Relaxed);
    }

    /// A UDP dial failed on source-address policy alone.
    pub fn record_udp_dial_refused(&self) {
        self.udp_dial_refused.fetch_add(1, Ordering::Relaxed);
    }

    /// A UDP dial failed for a genuine network reason.
    pub fn record_udp_dial_failed(&self) {
        self.udp_dial_failed.fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub fn udp_relay_flows_opened(&self) -> u64 {
        self.udp_relay_flows_opened.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn udp_dial_ok(&self) -> u64 {
        self.udp_dial_ok.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn udp_dial_refused(&self) -> u64 {
        self.udp_dial_refused.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn udp_dial_failed(&self) -> u64 {
        self.udp_dial_failed.load(Ordering::Relaxed)
    }

    /// A client was told its fake endpoint's port is unreachable.
    pub fn record_udp_unreachable_sent(&self) {
        self.udp_unreachable_sent.fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub fn udp_unreachable_sent(&self) -> u64 {
        self.udp_unreachable_sent.load(Ordering::Relaxed)
    }
}
