//! `SO_BINDTODEVICE` to the link owning a probe's source address, the Linux
//! half of [`nrr_platform_api::source_link`]. Needs `CAP_NET_RAW`, which the
//! daemon has as root.

#![cfg(target_os = "linux")]

use std::net::Ipv4Addr;

use nrr_platform_api::error::PlatformError;
use nrr_platform_api::own_traffic::SocketHandle;
use nrr_platform_api::source_link::SourceLinkPinner;

use crate::adapters_addr::unicast_addresses_by_interface;

pub struct BindToSourceDevice;

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
