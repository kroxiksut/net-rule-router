//! Windows adapter enumeration source.
//!
//! The neutral value types (`IfOperStatus`, `InterfaceType`, `AdapterInfo`,
//! `AdapterAvailability`, …), the `AdapterEventSource` port, and the pure
//! classification + debounce logic (`AdapterMonitor`, `classify_availability`,
//! `is_virtual_adapter`, `MockAdapterEventSource`) live in `nrr-platform-api`;
//! re-export them so `nrr_platform_windows::adapters::*` paths keep resolving
//! byte-for-byte unchanged. The Windows MECHANISM — `WindowsApiAdapterSource`,
//! which enumerates via `WindowsApiPort::get_adapter_infos()` (Win32
//! `GetAdaptersAddresses`) — stays here.

use std::sync::Arc;

use crate::error::PlatformError;
use crate::windows_api::WindowsApiPort;

pub use nrr_platform_api::adapters::{
    classify_availability, is_virtual_adapter, AdapterAvailability, AdapterAvailabilityChange,
    AdapterAvailabilitySnapshot, AdapterEventSource, AdapterInfo, AdapterMonitor, IfOperStatus,
    InterfaceType, MockAdapterEventSource,
};

/// Production source: delegates to `WindowsApiPort::get_adapter_infos()`.
pub struct WindowsApiAdapterSource {
    api: Arc<dyn WindowsApiPort>,
}

impl WindowsApiAdapterSource {
    pub fn new(api: Arc<dyn WindowsApiPort>) -> Self {
        Self { api }
    }
}

impl AdapterEventSource for WindowsApiAdapterSource {
    fn enumerate_all(&self) -> Result<Vec<AdapterInfo>, PlatformError> {
        self.api.get_adapter_infos()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows_api::MockWindowsApi;
    use std::net::Ipv4Addr;

    #[test]
    fn windows_api_adapter_source_enumerates_via_port() {
        let api = Arc::new(MockWindowsApi::new());
        api.set_adapter_infos(vec![AdapterInfo {
            index: 5,
            adapter_name: "{5}".to_string(),
            description: "Intel Ethernet".to_string(),
            friendly_name: "Ethernet".to_string(),
            mac: Some([0xAA, 0xBB, 0xCC, 0, 0, 5]),
            interface_type: InterfaceType::Ethernet,
            oper_status: IfOperStatus::Up,
            ipv4_addresses: vec![Ipv4Addr::new(192, 168, 1, 5)],
            gateways: vec![Ipv4Addr::new(192, 168, 1, 1)],
        }]);
        let src = WindowsApiAdapterSource::new(Arc::clone(&api) as Arc<dyn WindowsApiPort>);
        let infos = src.enumerate_all().unwrap();
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].index, 5);
    }
}
