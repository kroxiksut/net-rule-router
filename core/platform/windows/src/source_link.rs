//! Enforce the egress adapter selected for an IPv4 socket.

#![cfg(windows)]

use std::num::NonZeroU32;
use std::os::windows::io::AsRawSocket;

use nrr_platform_api::error::PlatformError;
use nrr_platform_api::own_traffic::SocketHandle;
use nrr_platform_api::source_link::InterfacePinner;
use windows::Win32::Networking::WinSock::{
    setsockopt, WSAGetLastError, IPPROTO_IP, IP_UNICAST_IF, SOCKET, SOCKET_ERROR,
};

pub struct UnicastInterface;

impl InterfacePinner for UnicastInterface {
    #[allow(unsafe_code)]
    fn pin_ipv4(&self, socket: SocketHandle<'_>, index: NonZeroU32) -> Result<(), PlatformError> {
        // Winsock distinguishes an index (0.x.x.x) from an IPv4 address.
        if index.get() > 0x00ff_ffff {
            return Err(PlatformError::Transient {
                operation: "IP_UNICAST_IF",
                detail: "IPv4 interface index exceeds 24 bits".to_owned(),
            });
        }
        let value = index.get().to_be_bytes();
        let handle = SOCKET(socket.as_raw_socket() as usize);
        // SAFETY: the socket remains borrowed through the call. The option
        // takes one DWORD in network byte order, supplied by the live array.
        if unsafe { setsockopt(handle, IPPROTO_IP.0, IP_UNICAST_IF, Some(&value)) } == SOCKET_ERROR {
            // SAFETY: WSAGetLastError reads this thread's socket error.
            let code = unsafe { WSAGetLastError() }.0;
            return Err(PlatformError::Win32 {
                operation: "setsockopt(IP_UNICAST_IF)",
                code: code as u32,
                message: std::io::Error::from_raw_os_error(code).to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::own_traffic::AsSocketHandle;
    use windows::core::PSTR;
    use windows::Win32::NetworkManagement::IpHelper::GetBestInterface;
    use windows::Win32::Networking::WinSock::getsockopt;

    /// A source-bound UDP socket can still use the default route until the
    /// kernel holds it to our link. Read back the chosen index in host order.
    #[test]
    #[allow(unsafe_code)]
    fn winsock_readback_confirms_the_selected_ipv4_interface() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind loopback");
        let mut index = 0;
        let loopback = u32::from_ne_bytes([127, 0, 0, 1]);
        // SAFETY: index is a writable ULONG and loopback is in network order.
        assert_eq!(unsafe { GetBestInterface(loopback, &mut index) }, 0);
        let index = NonZeroU32::new(index).expect("loopback has an interface index");
        UnicastInterface
            .pin_ipv4(socket.socket_handle(), index)
            .expect("pin to the loopback adapter");
        let mut actual = [0u8; 4];
        let mut len = actual.len() as i32;
        // SAFETY: the socket is live, and the buffer and length are writable
        // for the duration of the synchronous getsockopt call.
        let rc = unsafe {
            getsockopt(
                SOCKET(socket.as_raw_socket() as usize),
                IPPROTO_IP.0,
                IP_UNICAST_IF,
                PSTR(actual.as_mut_ptr()),
                &mut len,
            )
        };
        assert_eq!(rc, 0, "IP_UNICAST_IF readback failed");
        assert_eq!(len, 4);
        assert_eq!(u32::from_ne_bytes(actual), index.get());
    }
}
