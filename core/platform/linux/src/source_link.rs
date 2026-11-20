//! `SO_BINDTODEVICE` to the link owning a probe's source address, the Linux
//! half of [`nrr_platform_api::source_link`]. Needs `CAP_NET_RAW`, which the
//! daemon has as root.

#![cfg(target_os = "linux")]

use std::net::Ipv4Addr;
use std::num::NonZeroU32;

use nrr_platform_api::error::PlatformError;
use nrr_platform_api::own_traffic::SocketHandle;
use nrr_platform_api::source_link::{InterfacePinner, SourceLinkPinner};

use crate::adapters_addr::unicast_addresses_by_interface;

pub struct BindToSourceDevice;

impl InterfacePinner for BindToSourceDevice {
    fn pin_ipv4(&self, socket: SocketHandle<'_>, index: NonZeroU32) -> Result<(), PlatformError> {
        let socket = socket2::SockRef::from(&socket);
        match socket.bind_device_by_index_v4(Some(index)) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::ENOPROTOOPT) => {
                // Before Linux 5.1 install the same sk_bound_dev_if by name.
                let name = interface_name(index).map_err(|e| errno("if_indextoname", e))?;
                socket
                    .bind_device(Some(name.to_bytes()))
                    .map_err(|e| errno("SO_BINDTODEVICE", e))?;
            }
            Err(e) => return Err(errno("SO_BINDTOIFINDEX", e)),
        }
        // The index option accepts even a positive index that no longer
        // exists. Reading the bound device name also catches a rename/swap
        // during the legacy lookup, before this socket can send.
        let expected = interface_name(index).map_err(|e| errno("if_indextoname", e))?;
        let bound = socket.device().map_err(|e| errno("SO_BINDTODEVICE", e))?;
        if bound.as_deref() != Some(expected.to_bytes()) {
            return Err(errno(
                "verify socket interface",
                std::io::Error::from_raw_os_error(libc::ENODEV),
            ));
        }
        Ok(())
    }
}

fn errno(operation: &'static str, error: std::io::Error) -> PlatformError {
    PlatformError::Errno {
        operation,
        code: error.raw_os_error().unwrap_or(0),
        message: error.to_string(),
    }
}

#[allow(unsafe_code)]
fn interface_name(index: NonZeroU32) -> std::io::Result<std::ffi::CString> {
    let mut name = [0; libc::IF_NAMESIZE];
    // SAFETY: the writable buffer has IF_NAMESIZE bytes. On success libc
    // writes a NUL-terminated interface name into it.
    if unsafe { libc::if_indextoname(index.get(), name.as_mut_ptr()) }.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the lookup succeeded, and the buffer lives through the copy.
    Ok(unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }.to_owned())
}

impl SourceLinkPinner for BindToSourceDevice {
    fn pin_to_source_link(
        &self,
        socket: SocketHandle<'_>,
        source: Ipv4Addr,
    ) -> Result<(), PlatformError> {
        // An alias address is reported under its label (`eth0:1`); the device
        // is the part before the colon, which a device name cannot contain.
        let link = unicast_addresses_by_interface()
            .into_iter()
            .find_map(|(name, addresses)| addresses.v4.contains(&source).then_some(name))
            .map(|name| name.split(':').next().unwrap_or_default().to_owned())
            .ok_or_else(|| PlatformError::Transient {
                operation: "source-link lookup",
                detail: "no link holds the probe's source address".to_owned(),
            })?;
        socket2::SockRef::from(&socket)
            .bind_device(Some(link.as_bytes()))
            .map_err(|e| PlatformError::Errno {
                operation: "setsockopt(SO_BINDTODEVICE)",
                code: e.raw_os_error().unwrap_or(0),
                message: e.to_string(),
            })
    }
}
