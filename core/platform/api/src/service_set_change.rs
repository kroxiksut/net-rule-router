//! "The machine's set of services changed" — the neutral port.
//!
//! A service installed or removed after a user confirmed a rule over a
//! program's folder may run what the rule takes. The owner of that decision
//! re-checks on this event instead of on every enforcement pass. Windows: SCM
//! create/delete notifications; Linux: the systemd unit directories.
//!
//! Same shape as [`crate::network_change`]: the callback does the minimum and
//! the caller coalesces.

use crate::error::PlatformError;
use crate::network_change::{NetworkChangeCallback, NetworkChangeSubscription};

/// Invokes `on_change` whenever a service may have been added or removed. A
/// spurious call is allowed; a missed one is covered by the caller's slow
/// timer. `Err` when the OS registration fails.
pub trait ServiceSetChangeObserver: Send + Sync {
    fn subscribe(
        &self,
        on_change: NetworkChangeCallback,
    ) -> Result<NetworkChangeSubscription, PlatformError>;
}

/// For platforms without an event: only the caller's timer re-checks.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopServiceSetChangeObserver;

impl ServiceSetChangeObserver for NoopServiceSetChangeObserver {
    fn subscribe(
        &self,
        _on_change: NetworkChangeCallback,
    ) -> Result<NetworkChangeSubscription, PlatformError> {
        Ok(NetworkChangeSubscription::inert())
    }
}
