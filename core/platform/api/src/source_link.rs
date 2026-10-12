//! A probe socket held to the link that owns its source address.
//!
//! Binding to an adapter's address picks the way out on Windows. On Linux the
//! routing tables still choose, and a full-tunnel VPN rule sends the datagram
//! into the tunnel with a foreign source, where it is dropped. The service
//! installs a pinner where the OS needs one; with none installed the source
//! address alone decides.

use std::net::Ipv4Addr;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_installed_pins_nothing_and_does_not_fail() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        pin_to_source_link(&socket, Ipv4Addr::LOCALHOST);
    }
}
