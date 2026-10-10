//! The service's own outbound traffic, told apart from everyone else's.
//!
//! Machine-scope filters cover the service accounts the service itself runs
//! as, so its probes, DNS forwarding and relay would meet them too. Where the
//! OS can tag a socket, the service tags its own and the filters let the tag
//! through; where it cannot (Windows exempts by application id), nothing is
//! installed and marking is a no-op.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use crate::error::PlatformError;

/// The socket mark the service puts on its own outbound sockets so the
/// machine-scope filters let them through.
pub const OWN_TRAFFIC_MARK: u32 = 0x4e52_5200;

/// A borrowed OS socket, in the OS's own handle type.
#[cfg(unix)]
pub type SocketHandle<'a> = std::os::fd::BorrowedFd<'a>;
#[cfg(windows)]
pub type SocketHandle<'a> = std::os::windows::io::BorrowedSocket<'a>;

/// Anything that owns or borrows an OS socket.
pub trait AsSocketHandle {
    fn socket_handle(&self) -> SocketHandle<'_>;
}

#[cfg(unix)]
impl<T: std::os::fd::AsFd> AsSocketHandle for T {
    fn socket_handle(&self) -> SocketHandle<'_> {
        self.as_fd()
    }
}

#[cfg(windows)]
impl<T: std::os::windows::io::AsSocket> AsSocketHandle for T {
    fn socket_handle(&self) -> SocketHandle<'_> {
        self.as_socket()
    }
}

/// Puts [`OWN_TRAFFIC_MARK`] on a socket. Must run before the socket's first
/// packet: a TCP handshake sent unmarked meets the filters unmarked.
pub trait OwnTrafficMarker: Send + Sync {
    fn mark_own_socket(&self, socket: SocketHandle<'_>) -> Result<(), PlatformError>;
}

/// The marker where the OS exempts the service another way.
pub struct UnmarkedOwnTraffic;

impl OwnTrafficMarker for UnmarkedOwnTraffic {
    fn mark_own_socket(&self, _socket: SocketHandle<'_>) -> Result<(), PlatformError> {
        Ok(())
    }
}

static MARKER: OnceLock<Box<dyn OwnTrafficMarker>> = OnceLock::new();

/// Install the service's marker, once, before it opens any outbound socket.
/// `false` when one is already installed. Nothing installed means no marking,
/// which is what tests and the clients get.
pub fn install_own_traffic_marker(marker: Box<dyn OwnTrafficMarker>) -> bool {
    MARKER.set(marker).is_ok()
}

/// Mark `socket` as the service's own. Never fails the caller: an unmarked
/// socket still works wherever the machine-scope filters are not armed, so a
/// refusal is logged once rather than turned into a failed probe or lookup.
pub fn mark_own_socket(socket: &impl AsSocketHandle) {
    let Some(marker) = MARKER.get() else {
        return;
    };
    if let Err(e) = marker.mark_own_socket(socket.socket_handle()) {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                target: "nrr::platform",
                msg_key = "own-traffic-mark-failed",
                error = %e,
                "the service could not mark its own socket: machine-scope filters may hold its probes and lookups",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_installed_marks_nothing_and_does_not_fail() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        mark_own_socket(&socket);
    }

    #[test]
    fn the_unmarked_marker_accepts_any_socket() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        assert!(UnmarkedOwnTraffic
            .mark_own_socket(socket.socket_handle())
            .is_ok());
    }
}
