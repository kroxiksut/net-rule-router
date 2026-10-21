#![no_main]
//! An adapter name another program chose: telling our fake-IP adapter apart
//! never panics, and nothing but our name or our fixed identity reads as ours.

use libfuzzer_sys::fuzz_target;
use nrr_platform_api::adapters::{AdapterInfo, IfOperStatus, InterfaceType};
use nrr_platform_api::uplink::is_own_fake_ip_adapter;

/// Well above any name the OS reports for an adapter.
const MAX_INPUT: usize = 4096;

const OUR_GUID: &str = "{7A3E1C55-0B6D-4F82-9E14-2D6C8B0A5F31}";

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let name = String::from_utf8_lossy(data).into_owned();
    let info = AdapterInfo {
        index: 1,
        adapter_name: name.clone(),
        description: String::new(),
        friendly_name: String::new(),
        mac: None,
        interface_type: InterfaceType::Ethernet,
        oper_status: IfOperStatus::Up,
        ipv4_addresses: Vec::new(),
        ipv6_addresses: Vec::new(),
        gateways: Vec::new(),
    };
    if is_own_fake_ip_adapter(&info) {
        let id = name.trim();
        assert!(
            id.eq_ignore_ascii_case(OUR_GUID)
                || id == nrr_shared::product_identity::TUN_ADAPTER_NAME,
            "{name:?}"
        );
    }
});
