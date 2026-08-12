use nrr_shared::{
    AdapterIdentity, AdapterIdentityContract, AdapterIdentityField, AdapterSnapshotDataSource,
    AdapterSnapshotEntry, AdaptersSnapshot,
};

const STABLE_IDENTITY_FIELDS: [AdapterIdentityField; 3] = [
    AdapterIdentityField::AdapterName,
    AdapterIdentityField::Ipv6IfIndex,
    AdapterIdentityField::PhysicalAddress,
];

const DISPLAY_ONLY_FIELDS: [&str; 4] = [
    "windows_name",
    "interface_description",
    "interface_type",
    "oper_status",
];

const PERSISTENT_ID_POLICY: &str = "primary=AdapterName (normalized); fallback=ifindex+mac";

pub fn adapter_identity_contract() -> AdapterIdentityContract {
    AdapterIdentityContract {
        stable_fields: &STABLE_IDENTITY_FIELDS,
        display_only_fields: &DISPLAY_ONLY_FIELDS,
        persistent_id_policy: PERSISTENT_ID_POLICY,
    }
}

pub fn adapters_snapshot() -> AdaptersSnapshot {
    #[cfg(windows)]
    {
        if let Ok(adapters) = collect_windows_adapters() {
            if !adapters.is_empty() {
                return AdaptersSnapshot {
                    data_source: AdapterSnapshotDataSource::WindowsLive,
                    identity_contract: adapter_identity_contract(),
                    adapters,
                };
            }
        }
    }

    AdaptersSnapshot {
        data_source: AdapterSnapshotDataSource::FallbackMock,
        identity_contract: adapter_identity_contract(),
        adapters: fallback_adapters(),
    }
}

#[cfg(windows)]
fn collect_windows_adapters() -> Result<Vec<AdapterSnapshotEntry>, String> {
    let mut adapters = ipconfig::get_adapters()
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|adapter| {
            let adapter_name = adapter.adapter_name().trim().to_string();
            let normalized_adapter_name = normalize_adapter_name(&adapter_name);
            let physical_address = format_physical_address(adapter.physical_address());
            let persistent_id = build_persistent_id(
                &normalized_adapter_name,
                adapter.ipv6_if_index(),
                physical_address.as_deref(),
            );

            AdapterSnapshotEntry {
                identity: AdapterIdentity {
                    persistent_id,
                    adapter_name,
                    ipv6_if_index: adapter.ipv6_if_index(),
                    physical_address,
                },
                windows_name: resolve_windows_name(
                    adapter.friendly_name(),
                    adapter.adapter_name().trim(),
                ),
                interface_description: adapter.description().to_string(),
                interface_type: format!("{:?}", adapter.if_type()),
                oper_status: format!("{:?}", adapter.oper_status()).to_ascii_lowercase(),
            }
        })
        .collect::<Vec<_>>();

    adapters.sort_by(|left, right| {
        left.windows_name
            .to_ascii_lowercase()
            .cmp(&right.windows_name.to_ascii_lowercase())
    });
    Ok(adapters)
}

fn fallback_adapters() -> Vec<AdapterSnapshotEntry> {
    vec![
        AdapterSnapshotEntry {
            identity: AdapterIdentity {
                persistent_id: "win-adapter:ethernet-fallback".to_string(),
                adapter_name: "{FAKE-ETHERNET-ADAPTER}".to_string(),
                ipv6_if_index: 10,
                physical_address: Some("00-11-22-33-44-55".to_string()),
            },
            windows_name: "Ethernet".to_string(),
            interface_description: "Fallback Ethernet adapter".to_string(),
            interface_type: "Ethernet".to_string(),
            oper_status: "ifoperstatusup".to_string(),
        },
        AdapterSnapshotEntry {
            identity: AdapterIdentity {
                persistent_id: "win-adapter:wifi-fallback".to_string(),
                adapter_name: "{FAKE-WIFI-ADAPTER}".to_string(),
                ipv6_if_index: 20,
                physical_address: Some("AA-BB-CC-DD-EE-FF".to_string()),
            },
            windows_name: "Wi-Fi".to_string(),
            interface_description: "Fallback Wi-Fi adapter".to_string(),
            interface_type: "Ieee80211".to_string(),
            oper_status: "ifoperstatusup".to_string(),
        },
        AdapterSnapshotEntry {
            identity: AdapterIdentity {
                persistent_id: "win-adapter:vpn-fallback".to_string(),
                adapter_name: "{FAKE-VPN-ADAPTER}".to_string(),
                ipv6_if_index: 30,
                physical_address: None,
            },
            windows_name: "VPN".to_string(),
            interface_description: "Fallback VPN tunnel".to_string(),
            interface_type: "Tunnel".to_string(),
            oper_status: "ifoperstatusdormant".to_string(),
        },
    ]
}

fn resolve_windows_name(friendly_name: &str, adapter_name: &str) -> String {
    let friendly_name = friendly_name.trim();
    if friendly_name.is_empty() {
        adapter_name.trim().to_string()
    } else {
        friendly_name.to_string()
    }
}

fn normalize_adapter_name(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn format_physical_address(value: Option<&[u8]>) -> Option<String> {
    let bytes = value?;
    if bytes.is_empty() {
        return None;
    }
    Some(
        bytes
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join("-"),
    )
}

fn build_persistent_id(
    normalized_adapter_name: &str,
    ipv6_if_index: u32,
    physical_address: Option<&str>,
) -> String {
    if !normalized_adapter_name.is_empty() {
        return format!("win-adapter:{normalized_adapter_name}");
    }
    if let Some(mac) = physical_address {
        return format!("win-ifindex-mac:{ipv6_if_index}:{mac}");
    }
    format!("win-ifindex:{ipv6_if_index}")
}

#[cfg(test)]
mod tests {
    use super::{
        adapter_identity_contract, adapters_snapshot, build_persistent_id, fallback_adapters,
    };
    use nrr_shared::{AdapterIdentityField, AdapterSnapshotDataSource};

    #[test]
    fn identity_contract_defines_stable_and_display_fields() {
        let contract = adapter_identity_contract();
        assert_eq!(contract.stable_fields[0], AdapterIdentityField::AdapterName);
        assert!(contract
            .display_only_fields
            .contains(&"interface_description"));
        assert!(contract.persistent_id_policy.contains("AdapterName"));
    }

    #[test]
    fn persistent_id_uses_adapter_name_when_available() {
        let id = build_persistent_id("test-adapter", 42, Some("AA-BB-CC-DD-EE-FF"));
        assert_eq!(id, "win-adapter:test-adapter");
    }

    #[test]
    fn persistent_id_falls_back_to_ifindex_and_mac() {
        let id = build_persistent_id("", 42, Some("AA-BB-CC-DD-EE-FF"));
        assert_eq!(id, "win-ifindex-mac:42:AA-BB-CC-DD-EE-FF");
    }

    #[test]
    fn fallback_snapshot_is_deterministic() {
        let first = fallback_adapters();
        let second = fallback_adapters();
        assert_eq!(first, second);
        assert_eq!(first.len(), 3);
    }

    #[test]
    fn adapters_snapshot_always_carries_identity_contract() {
        let snapshot = adapters_snapshot();
        assert!(!snapshot.adapters.is_empty());
        assert!(!snapshot.identity_contract.stable_fields.is_empty());
        assert!(matches!(
            snapshot.data_source,
            AdapterSnapshotDataSource::WindowsLive | AdapterSnapshotDataSource::FallbackMock
        ));
    }
}
