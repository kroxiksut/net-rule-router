//! Blocked-connection notification emitter (skeleton).
//!
//! The full notification path — rate-limiting, ring buffer, and IPC
//! delivery — is not yet implemented.

use std::net::Ipv4Addr;

/// A single event emitted when the apply layer blocks a connection.
#[derive(Clone, Debug)]
pub struct BlockNotificationEvent {
    /// Wall-clock epoch seconds when the block occurred.
    pub blocked_at_epoch_secs: u64,
    /// Destination hostname (if known via FQDN cache).
    pub host: Option<String>,
    /// Destination IPv4 address.
    pub dest_ip: Ipv4Addr,
    /// Rule id that caused the block.
    pub rule_id: String,
    /// Human-readable reason key (locale key, not raw string).
    pub reason_key: &'static str,
}

/// Emits `BlockNotificationEvent`s to the service-runtime ring buffer.
///
/// TODO: implement rate-limiting (leaky bucket per
/// `(host, rule_id)`), ring buffer (capacity 50), IPC polling endpoint.
pub struct BlockNotificationEmitter;

impl BlockNotificationEmitter {
    pub fn new() -> Self {
        Self
    }

    /// Emit a block notification.
    /// TODO: real implementation.
    pub fn emit(&self, _event: BlockNotificationEvent) {
        // TODO: rate-limit, push to ring buffer, IPC delivery.
    }
}

impl Default for BlockNotificationEmitter {
    fn default() -> Self {
        Self::new()
    }
}
