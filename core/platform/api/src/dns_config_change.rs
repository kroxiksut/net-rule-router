//! "The machine's DNS configuration changed" — the neutral port.
//!
//! A connection can gain or lose its DNS suffix and servers without any link or
//! route moving: a DHCP lease renewed with a new domain, a VPN client pushing
//! its namespace after the tunnel is already up. The network-change feed stays
//! silent for those, so whoever caches the machine's DNS claims needs this one
//! beside it to avoid re-reading them on a timer.
//!
//! Same shape as [`crate::network_change`]: the callback does the minimum and
//! the caller coalesces.

use crate::error::PlatformError;
use crate::network_change::{NetworkChangeCallback, NetworkChangeSubscription};

/// Invokes `on_change` whenever the OS's DNS configuration may have changed.
/// A spurious call is allowed; a missed one is not. `Err` when the OS
/// registration fails, and the caller then keeps re-reading on its own.
pub trait DnsConfigChangeObserver: Send + Sync {
    fn subscribe(
        &self,
        on_change: NetworkChangeCallback,
    ) -> Result<NetworkChangeSubscription, PlatformError>;
}

/// For platforms whose DNS configuration only changes with the links the
/// network-change feed already reports.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopDnsConfigChangeObserver;

impl DnsConfigChangeObserver for NoopDnsConfigChangeObserver {
    fn subscribe(
        &self,
        _on_change: NetworkChangeCallback,
    ) -> Result<NetworkChangeSubscription, PlatformError> {
        Ok(NetworkChangeSubscription::inert())
    }
}
