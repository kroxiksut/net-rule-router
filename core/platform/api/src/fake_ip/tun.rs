//! TUN adapter port — the one OS-specific piece of fake-IP.
//!
//! A TUN adapter is a layer-3 network interface with no wire behind it: the OS
//! routes packets into it and NetRuleRouter reads them as raw IP datagrams,
//! writes replies back the same way. That is what lets the userspace stack
//! terminate a flow addressed to a fake address, learn the hostname from
//! [`crate::fake_ip::FakeIpAllocator`], and relay it over the route that
//! hostname's rule selected — for TCP, UDP/QUIC, and virtual-machine traffic
//! alike, without a filter driver of our own and without touching TLS.
//!
//! Only the PORT is neutral. The backends:
//!
//! - **Windows** — the redistributable Wintun adapter (WireGuard LLC). Windows
//!   is the only platform that needs a third-party driver, which is why shipping
//!   it carries attribution obligations.
//! - **Linux** — the native `/dev/net/tun`; no third-party driver exists or is
//!   needed.
//! - **macOS** — the native `utun` interface; likewise no kext.
//!
//! Where a platform has no adapter available (or the build excludes it),
//! [`NoopTunAdapter`] reports `is_available() == false` so the GUI degrades to
//! "fake-IP unavailable on this system" instead of failing at activation time.

use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use crate::error::PlatformError;
use crate::fake_ip::allocator::FakeIpPoolConfig;

/// Default MTU of the fake-IP adapter. 1500 keeps the OS from fragmenting on the
/// way in; the relay re-segments onto the real path anyway.
pub const DEFAULT_TUN_MTU: u16 = 1500;
/// Default receive-ring size in bytes (2 MiB). Must be a power of two — a
/// requirement of the Windows backend that costs the others nothing.
pub const DEFAULT_TUN_RING_CAPACITY_BYTES: u32 = 2 * 1024 * 1024;

const MIN_TUN_MTU: u16 = 576;
const MAX_TUN_MTU: u16 = 9000;
const MIN_RING_CAPACITY_BYTES: u32 = 128 * 1024;
const MAX_RING_CAPACITY_BYTES: u32 = 64 * 1024 * 1024;

/// How the fake-IP adapter should be created. Neutral: every field maps onto
/// each backend's own creation call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunAdapterConfig {
    /// Interface name shown by the OS (`ipconfig`, `ip link`, `ifconfig`).
    pub adapter_name: String,
    /// Address the adapter itself carries — the next hop for the whole fake
    /// range, i.e. [`FakeIpPoolConfig::gateway_v4`].
    pub v4_address: Ipv4Addr,
    /// Prefix length of the fake range routed into the adapter.
    pub v4_prefix_len: u8,
    /// IPv6 counterpart, when the pool has a v6 range.
    pub v6_address: Option<Ipv6Addr>,
    /// Prefix length of the v6 fake range.
    pub v6_prefix_len: u8,
    /// Interface MTU.
    pub mtu: u16,
    /// Receive-ring size in bytes (power of two).
    pub ring_capacity_bytes: u32,
}

impl TunAdapterConfig {
    /// The adapter configuration that serves `pool` — the addresses and prefix
    /// lengths are derived from the pool, so the two can never disagree.
    #[must_use]
    pub fn for_pool(adapter_name: impl Into<String>, pool: &FakeIpPoolConfig) -> Self {
        Self {
            adapter_name: adapter_name.into(),
            v4_address: pool.gateway_v4(),
            v4_prefix_len: pool.v4_prefix_len,
            v6_address: pool.gateway_v6(),
            v6_prefix_len: pool.v6_prefix_len,
            mtu: DEFAULT_TUN_MTU,
            ring_capacity_bytes: DEFAULT_TUN_RING_CAPACITY_BYTES,
        }
    }

    /// Reject a configuration no backend could honour, before any OS call is
    /// made — the validation is identical everywhere, so it belongs here.
    pub fn validate(&self) -> Result<(), PlatformError> {
        if self.adapter_name.trim().is_empty() {
            return Err(PlatformError::NotSupported {
                reason: "TUN adapter name must not be empty",
            });
        }
        if !(MIN_TUN_MTU..=MAX_TUN_MTU).contains(&self.mtu) {
            return Err(PlatformError::NotSupported {
                reason: "TUN MTU is outside the supported 576..=9000 range",
            });
        }
        if self.v4_prefix_len > 32 {
            return Err(PlatformError::NotSupported {
                reason: "IPv4 prefix length must be 0..=32",
            });
        }
        if self.v6_address.is_some() && self.v6_prefix_len > 128 {
            return Err(PlatformError::NotSupported {
                reason: "IPv6 prefix length must be 0..=128",
            });
        }
        if !(MIN_RING_CAPACITY_BYTES..=MAX_RING_CAPACITY_BYTES).contains(&self.ring_capacity_bytes)
            || !self.ring_capacity_bytes.is_power_of_two()
        {
            return Err(PlatformError::NotSupported {
                reason: "TUN ring capacity must be a power of two in 128 KiB..=64 MiB",
            });
        }
        Ok(())
    }
}

impl Default for TunAdapterConfig {
    fn default() -> Self {
        Self::for_pool("NetRuleRouter", &FakeIpPoolConfig::default())
    }
}

/// Create the fake-IP adapter. One implementation per OS.
pub trait TunAdapterPort: Send + Sync {
    /// Whether this system can provide a TUN adapter right now (driver present,
    /// permissions sufficient). Checked before offering the feature, so an
    /// unavailable adapter is a greyed-out checkbox, not a failed activation.
    fn is_available(&self) -> bool;

    /// Create and bring up the adapter. Idempotent per name: opening an adapter
    /// this process already owns replaces the previous session.
    fn open(&self, config: &TunAdapterConfig) -> Result<Box<dyn TunDevice>, PlatformError>;
}

/// An open adapter: raw IP packets in and out. Owned by the reader thread, hence
/// `&mut self` on the I/O calls; use [`TunDevice::control`] to unblock a reader
/// from another thread.
pub trait TunDevice: Send {
    /// Negotiated MTU — the largest packet [`Self::read_packet`] can return and
    /// [`Self::write_packet`] will accept.
    fn mtu(&self) -> u16;

    /// Read one IP packet into `buf`, blocking until one arrives. Returns the
    /// packet length, or `Ok(0)` once the device has been shut down — the
    /// reader loop's exit condition.
    fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, PlatformError>;

    /// Write one IP packet to the adapter (a reply travelling back to the
    /// client). Returns the number of bytes accepted.
    fn write_packet(&mut self, packet: &[u8]) -> Result<usize, PlatformError>;

    /// Register a hint the device fires when a packet becomes readable, so a
    /// caller parked between polls can wake immediately instead of sleeping
    /// out its idle interval. Optional: a device with no readiness signal
    /// ignores it and the caller's periodic poll still drains every packet —
    /// the hint only removes idle-park latency, never correctness.
    fn set_readable_waker(&mut self, _waker: Arc<dyn Fn() + Send + Sync>) {}

    /// A shareable handle whose only job is to unblock and tear down the device
    /// from another thread (service stop, feature turned off).
    fn control(&self) -> Arc<dyn TunControl>;
}

/// Cross-thread shutdown handle for an open [`TunDevice`].
pub trait TunControl: Send + Sync {
    /// Unblock any in-flight [`TunDevice::read_packet`] and tear the adapter
    /// down. Idempotent.
    fn shutdown(&self) -> Result<(), PlatformError>;
}

/// Off-platform / feature-disabled default: no adapter, and it says so up front.
#[derive(Debug, Default)]
pub struct NoopTunAdapter;

impl TunAdapterPort for NoopTunAdapter {
    fn is_available(&self) -> bool {
        false
    }

    fn open(&self, _config: &TunAdapterConfig) -> Result<Box<dyn TunDevice>, PlatformError> {
        Err(PlatformError::NotSupported {
            reason: "no TUN adapter backend on this platform build",
        })
    }
}

/// Shared state of a [`MockTunAdapter`]: packets queued for the device to read
/// and packets the device has written. Always compiled (not `#[cfg(test)]`) so
/// dependent crates can drive the neutral stack in their own tests.
#[derive(Debug, Default)]
pub struct MockTunState {
    inbound: Mutex<VecDeque<Vec<u8>>>,
    outbound: Mutex<Vec<Vec<u8>>>,
    shutdown: Mutex<bool>,
}

// Test double: lock-poisoning `expect()` is acceptable scaffolding.
#[allow(clippy::expect_used)]
impl MockTunState {
    /// Queue a packet for the device to return from `read_packet`.
    pub fn push_inbound(&self, packet: Vec<u8>) {
        self.inbound
            .lock()
            .expect("mock tun mutex")
            .push_back(packet);
    }

    /// Every packet written to the device, in order.
    #[must_use]
    pub fn written_packets(&self) -> Vec<Vec<u8>> {
        self.outbound.lock().expect("mock tun mutex").clone()
    }

    /// Whether [`TunControl::shutdown`] has been called.
    #[must_use]
    pub fn is_shut_down(&self) -> bool {
        *self.shutdown.lock().expect("mock tun mutex")
    }

    fn pop_inbound(&self) -> Option<Vec<u8>> {
        self.inbound.lock().expect("mock tun mutex").pop_front()
    }

    fn record_written(&self, packet: &[u8]) {
        self.outbound
            .lock()
            .expect("mock tun mutex")
            .push(packet.to_vec());
    }

    fn mark_shut_down(&self) {
        *self.shutdown.lock().expect("mock tun mutex") = true;
    }
}

/// In-memory adapter for tests of the neutral stack: no OS involvement.
#[derive(Debug, Clone)]
pub struct MockTunAdapter {
    state: Arc<MockTunState>,
    available: bool,
}

impl MockTunAdapter {
    /// An available mock adapter plus the state handle to drive it with.
    #[must_use]
    pub fn new() -> (Self, Arc<MockTunState>) {
        let state = Arc::new(MockTunState::default());
        (
            Self {
                state: Arc::clone(&state),
                available: true,
            },
            state,
        )
    }

    /// A mock that reports the platform cannot provide an adapter.
    #[must_use]
    pub fn unavailable() -> Self {
        Self {
            state: Arc::new(MockTunState::default()),
            available: false,
        }
    }
}

impl TunAdapterPort for MockTunAdapter {
    fn is_available(&self) -> bool {
        self.available
    }

    fn open(&self, config: &TunAdapterConfig) -> Result<Box<dyn TunDevice>, PlatformError> {
        if !self.available {
            return Err(PlatformError::NotSupported {
                reason: "mock TUN adapter is configured as unavailable",
            });
        }
        config.validate()?;
        Ok(Box::new(MockTunDevice {
            state: Arc::clone(&self.state),
            mtu: config.mtu,
        }))
    }
}

#[derive(Debug)]
struct MockTunDevice {
    state: Arc<MockTunState>,
    mtu: u16,
}

impl TunDevice for MockTunDevice {
    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, PlatformError> {
        if self.state.is_shut_down() {
            return Ok(0);
        }
        // Non-blocking by design: a test drains what it queued, and an empty
        // queue reads as "nothing pending" rather than parking the thread.
        match self.state.pop_inbound() {
            Some(packet) => {
                let len = packet.len().min(buf.len());
                buf[..len].copy_from_slice(&packet[..len]);
                Ok(len)
            }
            None => Ok(0),
        }
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<usize, PlatformError> {
        if self.state.is_shut_down() {
            return Err(PlatformError::NotSupported {
                reason: "write to a shut-down TUN device",
            });
        }
        self.state.record_written(packet);
        Ok(packet.len())
    }

    fn control(&self) -> Arc<dyn TunControl> {
        Arc::new(MockTunControl {
            state: Arc::clone(&self.state),
        })
    }
}

#[derive(Debug)]
struct MockTunControl {
    state: Arc<MockTunState>,
}

impl TunControl for MockTunControl {
    fn shutdown(&self) -> Result<(), PlatformError> {
        self.state.mark_shut_down();
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn default_config_serves_the_default_pool() {
        let cfg = TunAdapterConfig::default();
        assert_eq!(cfg.adapter_name, "NetRuleRouter");
        assert_eq!(cfg.v4_address, Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(cfg.v4_prefix_len, 15);
        assert_eq!(cfg.v6_address, FakeIpPoolConfig::default().gateway_v6());
        assert_eq!(cfg.mtu, DEFAULT_TUN_MTU);
        cfg.validate().expect("default config is valid");
    }

    #[test]
    fn v4_only_pool_yields_a_v4_only_adapter() {
        let cfg = TunAdapterConfig::for_pool("NetRuleRouter", &FakeIpPoolConfig::v4_only());
        assert_eq!(cfg.v6_address, None);
        cfg.validate().expect("v4-only config is valid");
    }

    #[test]
    fn validate_rejects_impossible_configurations() {
        let base = TunAdapterConfig::default();
        let cases = [
            TunAdapterConfig {
                adapter_name: "  ".to_string(),
                ..base.clone()
            },
            TunAdapterConfig {
                mtu: 100,
                ..base.clone()
            },
            TunAdapterConfig {
                v4_prefix_len: 33,
                ..base.clone()
            },
            TunAdapterConfig {
                // Not a power of two.
                ring_capacity_bytes: 3 * 1024 * 1024,
                ..base.clone()
            },
            TunAdapterConfig {
                ring_capacity_bytes: 1024,
                ..base.clone()
            },
        ];
        for cfg in cases {
            assert!(cfg.validate().is_err(), "expected rejection for {cfg:?}");
        }
    }

    #[test]
    fn noop_adapter_reports_unavailable_and_refuses_to_open() {
        let adapter = NoopTunAdapter;
        assert!(!adapter.is_available());
        assert!(adapter.open(&TunAdapterConfig::default()).is_err());
    }

    #[test]
    fn mock_device_round_trips_packets() {
        let (adapter, state) = MockTunAdapter::new();
        assert!(adapter.is_available());
        let mut device = adapter
            .open(&TunAdapterConfig::default())
            .expect("mock open");
        assert_eq!(device.mtu(), DEFAULT_TUN_MTU);

        state.push_inbound(vec![0x45, 0x00, 0x00, 0x28]);
        let mut buf = [0u8; 64];
        let len = device.read_packet(&mut buf).expect("read");
        assert_eq!(&buf[..len], &[0x45, 0x00, 0x00, 0x28]);
        assert_eq!(
            device.read_packet(&mut buf).expect("read"),
            0,
            "queue drained"
        );

        device.write_packet(&[0x60, 0x00]).expect("write");
        assert_eq!(state.written_packets(), vec![vec![0x60, 0x00]]);
    }

    #[test]
    fn shutdown_ends_the_reader_loop_and_blocks_writes() {
        let (adapter, state) = MockTunAdapter::new();
        let mut device = adapter
            .open(&TunAdapterConfig::default())
            .expect("mock open");
        let control = device.control();

        state.push_inbound(vec![1, 2, 3]);
        control.shutdown().expect("shutdown");
        control.shutdown().expect("shutdown is idempotent");
        assert!(state.is_shut_down());

        let mut buf = [0u8; 8];
        assert_eq!(
            device.read_packet(&mut buf).expect("read after shutdown"),
            0,
            "0 is the reader loop's exit condition"
        );
        assert!(device.write_packet(&[1]).is_err());
    }

    #[test]
    fn unavailable_mock_refuses_to_open() {
        let adapter = MockTunAdapter::unavailable();
        assert!(!adapter.is_available());
        assert!(adapter.open(&TunAdapterConfig::default()).is_err());
    }
}
