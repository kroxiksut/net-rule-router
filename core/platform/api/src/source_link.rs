//! The output interface of the service's own sockets. Probes can request the
//! link that owns a source address. DNS that requires a specific secondary
//! adapter must use the strict interface-index port and propagate its errors.

use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use crate::error::PlatformError;
use crate::own_traffic::{AsSocketHandle, SocketHandle};

/// Holds a socket to the link that owns `source`. Runs before the first packet.
pub trait SourceLinkPinner: Send + Sync {
    fn pin_to_source_link(
        &self,
        socket: SocketHandle<'_>,
        source: Ipv4Addr,
    ) -> Result<(), PlatformError>;
}

static PINNER: OnceLock<Box<dyn SourceLinkPinner>> = OnceLock::new();

/// Install the service's pinner, once, before any probe runs. `false` when one
/// is already installed.
pub fn install_source_link_pinner(pinner: Box<dyn SourceLinkPinner>) -> bool {
    PINNER.set(pinner).is_ok()
}

/// Hold `socket` to the link that owns `source`. Never fails the caller: an
/// unpinned probe still answers wherever routing already leaves by that link.
pub fn pin_to_source_link(socket: &impl AsSocketHandle, source: Ipv4Addr) {
    let Some(pinner) = PINNER.get() else {
        return;
    };
    if let Err(e) = pinner.pin_to_source_link(socket.socket_handle(), source) {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                target: "nrr::platform",
                msg_key = "source-link-pin-failed",
                error = %e,
                "the service could not hold a probe to its adapter: the answer may describe another link",
            );
        }
    }
}

/// Restrict an IPv4 socket to the current OS interface index before connecting
/// it. A successful call is required before the caller can send any bytes.
/// An index identifies the current adapter in this network namespace, not a
/// connection across reconnects. Resolve it afresh for a new attempt; an
/// adapter removed and replaced with the same index cannot be distinguished
/// from the old one by this socket option alone.
pub trait InterfacePinner: Send + Sync {
    fn pin_ipv4(&self, socket: SocketHandle<'_>, index: NonZeroU32) -> Result<(), PlatformError>;
}

static INTERFACE_PINNER: OnceLock<Box<dyn InterfacePinner>> = OnceLock::new();

/// Install the service's strict socket mechanism before DNS starts.
pub fn install_interface_pinner(pinner: Box<dyn InterfacePinner>) -> bool {
    INTERFACE_PINNER.set(pinner).is_ok()
}

/// An absent mechanism or a rejected socket option fails the DNS attempt.
pub fn pin_ipv4_to_interface(
    socket: SocketHandle<'_>,
    index: NonZeroU32,
) -> Result<(), PlatformError> {
    INTERFACE_PINNER
        .get()
        .ok_or(PlatformError::NotSupported {
            reason: "IPv4 socket interface binding is unavailable",
        })?
        .pin_ipv4(socket, index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_installed_pins_nothing_and_does_not_fail() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        pin_to_source_link(&socket, Ipv4Addr::LOCALHOST);
    }
}
