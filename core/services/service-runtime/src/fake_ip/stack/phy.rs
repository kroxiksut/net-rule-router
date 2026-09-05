//! The TUN device presented to `smoltcp` as an IP-medium phy.
//!
//! A complete `smoltcp::phy::Device` implementation and its two tokens — the
//! only place in the fake-IP stack that speaks to the tunnel handle directly.
//! It moved out whole because it is exactly that: everything above the poll
//! loop, nothing from it.
//!
//! The one-packet lookahead is the part worth keeping in view: the poll loop
//! reads a packet, classifies it (to open a socket for a new flow BEFORE
//! `smoltcp` sees the SYN), then hands it back so the very next `poll` consumes
//! it. `smoltcp` pulls at most that one pending packet per poll, which keeps
//! "inspect, then deliver" a single step.
//!
//! Behaviour is unchanged: the same code, verbatim.

use std::sync::Arc;

use nrr_platform_api::error::PlatformError;
use nrr_platform_api::fake_ip::tun::{TunControl, TunDevice};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant as SmolInstant;

/// Presents the neutral [`TunDevice`] to `smoltcp` as an IP-medium phy device.
///
/// One-packet lookahead: the poll loop reads a packet, classifies it (to open a
/// socket for a new flow *before* `smoltcp` sees the SYN), then [`ingest`]s it
/// so the very next `poll` consumes it. `smoltcp` pulls at most that one pending
/// packet per poll, which keeps "inspect, then deliver" a single step.
///
/// [`ingest`]: TunPhyDevice::ingest
pub struct TunPhyDevice {
    device: Box<dyn TunDevice>,
    mtu: u16,
    pending_rx: Option<Vec<u8>>,
}

impl TunPhyDevice {
    #[must_use]
    pub fn new(device: Box<dyn TunDevice>) -> Self {
        let mtu = device.mtu();
        Self {
            device,
            mtu,
            pending_rx: None,
        }
    }

    /// Read one raw IP packet from the adapter into `buf`, returning its length,
    /// or `0` when nothing is pending / the device has shut down.
    pub fn read_raw(&mut self, buf: &mut [u8]) -> Result<usize, PlatformError> {
        self.device.read_packet(buf)
    }

    /// Hand `smoltcp` the packet the poll loop just read and classified.
    pub fn ingest(&mut self, packet: Vec<u8>) {
        self.pending_rx = Some(packet);
    }

    /// Write one client-bound IP packet the poll loop built itself, bypassing
    /// `smoltcp`. Used only for the ICMP unreachable that answers a datagram the
    /// relay accepted but cannot carry — a socket-less error reply has no
    /// `smoltcp` socket to emit it. Best-effort like [`TunTxToken::consume`]: a
    /// full ring drops the reply, which is never a reason to unwind the loop.
    pub fn write_client_packet(&mut self, packet: &[u8]) {
        let _ = self.device.write_packet(packet);
    }

    #[must_use]
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// A cross-thread handle that unblocks the reader and tears the adapter down
    /// — how the lifecycle controller stops the run loop.
    #[must_use]
    pub fn control(&self) -> Arc<dyn TunControl> {
        self.device.control()
    }
}

/// Received-packet token: owns the bytes, so it needs no borrow of the device.
pub struct TunRxToken(Vec<u8>);

impl RxToken for TunRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

/// Transmit token: borrows the device just long enough to write one reply.
pub struct TunTxToken<'a> {
    device: &'a mut dyn TunDevice,
}

impl TxToken for TunTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        // Best-effort: a full TUN ring drops the reply, which TCP treats as a
        // lost segment and retransmits — never a reason to unwind the loop.
        let _ = self.device.write_packet(&buf);
        result
    }
}

impl Device for TunPhyDevice {
    type RxToken<'a> = TunRxToken;
    type TxToken<'a> = TunTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.pending_rx.take()?;
        Some((
            TunRxToken(packet),
            TunTxToken {
                device: &mut *self.device,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TunTxToken {
            device: &mut *self.device,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        // `DeviceCapabilities` is `#[non_exhaustive]` upstream, so default +
        // field assignment is the only way to build it.
        #[allow(clippy::field_reassign_with_default)]
        {
            let mut caps = DeviceCapabilities::default();
            caps.medium = Medium::Ip;
            caps.max_transmission_unit = usize::from(self.mtu);
            caps
        }
    }
}
