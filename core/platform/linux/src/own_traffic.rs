//! `SO_MARK` on the service's own sockets, the Linux half of
//! [`nrr_platform_api::own_traffic`]. Setting a mark needs `CAP_NET_ADMIN`,
//! which the daemon has as root.

#![cfg(target_os = "linux")]

use nrr_platform_api::error::PlatformError;
use nrr_platform_api::own_traffic::{OwnTrafficMarker, SocketHandle, OWN_TRAFFIC_MARK};

pub struct SoMarkOwnTraffic;

impl OwnTrafficMarker for SoMarkOwnTraffic {
    fn mark_own_socket(&self, socket: SocketHandle<'_>) -> Result<(), PlatformError> {
        socket2::SockRef::from(&socket)
            .set_mark(OWN_TRAFFIC_MARK)
            .map_err(|e| PlatformError::Errno {
                operation: "setsockopt(SO_MARK)",
                code: e.raw_os_error().unwrap_or(0),
                message: e.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::own_traffic::AsSocketHandle;
    use std::os::unix::fs::MetadataExt;

    fn running_as_root() -> bool {
        std::fs::metadata("/proc/self").is_ok_and(|m| m.uid() == 0)
    }

    #[test]
    fn the_mark_lands_on_the_socket_or_the_refusal_names_the_errno() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let marked = SoMarkOwnTraffic.mark_own_socket(socket.socket_handle());
        if running_as_root() {
            marked.expect("root may set SO_MARK");
            let read = socket2::SockRef::from(&socket).mark().expect("read back");
            assert_eq!(read, OWN_TRAFFIC_MARK);
        } else {
            assert!(
                matches!(&marked, Err(PlatformError::Errno { code, .. }) if *code == libc::EPERM),
                "{marked:?}"
            );
        }
    }
}
