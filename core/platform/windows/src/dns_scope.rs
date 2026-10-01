//! Windows mechanism behind [`InterfaceDnsScopePort`].
//!
//! Everything needed is already on disk, written by whoever configured the
//! connection: under each interface's TCP/IP parameters the DHCP lease leaves
//! `DhcpDomain` and `DhcpNameServer`, and a hand-configured connection leaves
//! `Domain` and `NameServer` beside them. A corporate VPN fills the first pair
//! the moment it connects.
//!
//! Read straight from the registry rather than through the DNS cmdlets: this
//! runs on a service that must not spawn a shell per network change, and the
//! values are stable across every Windows version the product supports.
//!
//! Static configuration wins over the lease, matching how the DNS client itself
//! resolves the pair — an administrator who typed a value meant it.

#![cfg(target_os = "windows")]

use std::net::Ipv4Addr;

use nrr_platform_api::dns_scope::{
    is_actionable_scope, normalize_suffix, InterfaceDnsScope, InterfaceDnsScopePort,
};
use nrr_platform_api::{AdapterInfo, IfOperStatus, InterfaceType};
use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;

use crate::win32_ffi::registry;

/// Per-interface TCP/IP parameters. One subkey per adapter GUID.
const INTERFACES_KEY: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";

/// Production implementation.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsInterfaceDnsScopes;

impl InterfaceDnsScopePort for WindowsInterfaceDnsScopes {
    fn dns_scopes(&self) -> Vec<InterfaceDnsScope> {
        registry::enum_subkeys(HKEY_LOCAL_MACHINE, INTERFACES_KEY)
            .into_iter()
            .filter_map(|guid| scope_for_interface(&guid))
            .collect()
    }
}

/// Actionable claims of the connections the OS is using right now, our own
/// tunnel aside — the one set both the NRPT exemptions and the global search
/// list are built from.
///
/// A disconnected VPN keeps its registry values, and honouring them would send
/// a namespace to a resolver nothing can reach; our tunnel claiming one would
/// point it back at us. A suffix completed into the search list but not exempt
/// sends internal names (`printer.lan`) to the public upstream.
pub fn live_actionable_dns_scopes() -> Vec<InterfaceDnsScope> {
    use nrr_platform_api::route_table::RouteTablePort;

    let live = crate::windows_api::ProductionWindowsApi
        .get_adapter_infos()
        .unwrap_or_default();
    claims_of_live_adapters(WindowsInterfaceDnsScopes.dns_scopes(), &live)
}

fn claims_of_live_adapters(
    scopes: Vec<InterfaceDnsScope>,
    live: &[AdapterInfo],
) -> Vec<InterfaceDnsScope> {
    scopes
        .into_iter()
        .filter(is_actionable_scope)
        .filter(|scope| {
            live.iter().any(|a| {
                a.adapter_name.eq_ignore_ascii_case(&scope.adapter_id) && carries_live_claim(a)
            })
        })
        .collect()
}

/// Up, addressed, and not ours. Not `classify_availability`: it drops every
/// tunnel-typed or hypervisor adapter, and a corporate VPN is often the first,
/// a Hyper-V external switch the host's own uplink. Either one carrying a
/// suffix was given it by whoever configured the link, as for any other.
fn carries_live_claim(adapter: &AdapterInfo) -> bool {
    use nrr_shared::product_identity::PRODUCT_NAME;

    adapter.oper_status == IfOperStatus::Up
        && adapter.has_ipv4_address()
        && adapter.interface_type != InterfaceType::Loopback
        && !adapter.description.contains(PRODUCT_NAME)
        && !adapter.friendly_name.contains(PRODUCT_NAME)
}

/// Machine-wide DNS client parameters.
const PARAMETERS_KEY: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";

/// Where a domain policy sets the search list; it overrides the local one.
const POLICY_KEY: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";

/// The machine's global DNS suffix search list, as configured.
pub fn global_search_list() -> Vec<String> {
    read_value(PARAMETERS_KEY, "SearchList")
        .map(|raw| raw.split(',').filter_map(normalize_suffix).collect())
        .unwrap_or_default()
}

/// The primary DNS suffix, if the machine has one.
pub fn primary_dns_suffix() -> Option<String> {
    read_value(PARAMETERS_KEY, "Domain").and_then(|v| normalize_suffix(&v))
}

/// Does a domain policy own the search list?
pub fn search_list_is_policy_managed() -> bool {
    read_value(POLICY_KEY, "SearchList").is_some()
}

/// Read one interface's claim. `None` when it claims no namespace.
fn scope_for_interface(guid: &str) -> Option<InterfaceDnsScope> {
    let subkey = format!(r"{INTERFACES_KEY}\{guid}");
    // Static first: an administrator who typed a value meant it, and the DNS
    // client resolves the pair the same way.
    let suffix = read_value(&subkey, "Domain")
        .and_then(|v| normalize_suffix(&v))
        .or_else(|| read_value(&subkey, "DhcpDomain").and_then(|v| normalize_suffix(&v)))?;
    let servers = read_value(&subkey, "NameServer")
        .map(|v| parse_servers(&v))
        .filter(|v: &Vec<Ipv4Addr>| !v.is_empty())
        .or_else(|| read_value(&subkey, "DhcpNameServer").map(|v| parse_servers(&v)))
        .unwrap_or_default();
    Some(InterfaceDnsScope {
        adapter_id: guid.to_string(),
        // The registry knows the GUID, not the name a person recognises. The
        // caller has the adapter list and fills this in.
        display_name: String::new(),
        suffix,
        servers,
    })
}

/// Windows writes these lists space-separated, and older builds comma-separated.
/// Duplicates are common (the same server listed twice by DHCP) and pointless.
fn parse_servers(raw: &str) -> Vec<Ipv4Addr> {
    let mut out: Vec<Ipv4Addr> = Vec::new();
    for token in raw.split([' ', ',', '\t']) {
        let Ok(ip) = token.trim().parse::<Ipv4Addr>() else {
            continue;
        };
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

/// A string value under HKLM, or `None` when absent or empty.
fn read_value(subkey: &str, name: &str) -> Option<String> {
    registry::read_string(HKEY_LOCAL_MACHINE, subkey, Some(name)).filter(|v| !v.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both spellings Windows has used, plus the duplicate a DHCP lease
    /// routinely contains (the field case listed one server twice).
    #[test]
    fn a_server_list_is_parsed_in_both_spellings_without_duplicates() {
        assert_eq!(
            parse_servers("192.168.0.53 192.168.0.53"),
            vec![Ipv4Addr::new(192, 168, 0, 53)]
        );
        assert_eq!(
            parse_servers("10.0.0.1,10.0.0.2"),
            vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)]
        );
        assert_eq!(
            parse_servers("192.168.0.1 0.0.0.0"),
            vec![Ipv4Addr::new(192, 168, 0, 1), Ipv4Addr::UNSPECIFIED],
            "filtering is the neutral layer's job, not the reader's",
        );
    }

    #[test]
    fn nonsense_and_ipv6_in_the_list_are_skipped_rather_than_failing_it() {
        assert_eq!(
            parse_servers("not-an-ip 2001:db8::1 10.0.0.1"),
            vec![Ipv4Addr::new(10, 0, 0, 1)]
        );
        assert!(parse_servers("").is_empty());
        assert!(parse_servers("   ").is_empty());
    }

    const VPN_GUID: &str = "{00000000-0000-4000-8000-000000000001}";

    fn adapter(description: &str, interface_type: InterfaceType, up: bool) -> AdapterInfo {
        AdapterInfo {
            index: 7,
            adapter_name: VPN_GUID.to_ascii_lowercase(),
            description: description.into(),
            friendly_name: "Corp link".into(),
            mac: None,
            interface_type,
            oper_status: if up {
                IfOperStatus::Up
            } else {
                IfOperStatus::Down
            },
            ipv4_addresses: vec![Ipv4Addr::new(192, 0, 2, 10)],
            ipv6_addresses: Vec::new(),
            gateways: Vec::new(),
        }
    }

    fn corp_claim() -> Vec<InterfaceDnsScope> {
        vec![InterfaceDnsScope {
            adapter_id: VPN_GUID.into(),
            display_name: String::new(),
            suffix: "corp.example".into(),
            servers: vec![Ipv4Addr::new(192, 0, 2, 53)],
        }]
    }

    #[test]
    fn a_tunnel_typed_vpn_keeps_its_claim() {
        let live = [adapter("Corp Client Adapter", InterfaceType::Tunnel, true)];
        assert_eq!(
            claims_of_live_adapters(corp_claim(), &live),
            corp_claim(),
            "the claim the availability classifier used to drop",
        );
    }

    #[test]
    fn a_hypervisor_adapter_carrying_a_suffix_keeps_its_claim() {
        let live = [adapter(
            "Hyper-V Virtual Ethernet Adapter",
            InterfaceType::Ethernet,
            true,
        )];
        assert_eq!(claims_of_live_adapters(corp_claim(), &live), corp_claim());
    }

    #[test]
    fn our_own_tunnel_claims_nothing() {
        use nrr_shared::product_identity::PRODUCT_NAME;
        let by_description = adapter(
            &format!("{PRODUCT_NAME} Tunnel"),
            InterfaceType::Other(53),
            true,
        );
        let mut by_name = adapter("Wintun Userspace Tunnel", InterfaceType::Other(53), true);
        by_name.friendly_name = PRODUCT_NAME.into();
        assert!(claims_of_live_adapters(corp_claim(), &[by_description]).is_empty());
        assert!(claims_of_live_adapters(corp_claim(), &[by_name]).is_empty());
    }

    /// A home router's single-label lease and a suffix with no server to ask
    /// are left out, so neither reaches the search list without an exemption.
    #[test]
    fn a_claim_that_is_not_actionable_is_dropped_for_every_consumer() {
        let live = [adapter("Home Ethernet", InterfaceType::Ethernet, true)];
        let mut home = corp_claim();
        home[0].suffix = "lan".into();
        let mut serverless = corp_claim();
        serverless[0].servers.clear();
        assert!(claims_of_live_adapters(home, &live).is_empty());
        assert!(claims_of_live_adapters(serverless, &live).is_empty());
    }

    #[test]
    fn a_disconnected_or_unaddressed_adapter_claims_nothing() {
        let down = adapter("Corp Client Adapter", InterfaceType::Tunnel, false);
        let mut unaddressed = adapter("Corp Client Adapter", InterfaceType::Tunnel, true);
        unaddressed.ipv4_addresses.clear();
        assert!(claims_of_live_adapters(corp_claim(), &[down]).is_empty());
        assert!(claims_of_live_adapters(corp_claim(), &[unaddressed]).is_empty());
        assert!(
            claims_of_live_adapters(corp_claim(), &[]).is_empty(),
            "an adapter that is gone"
        );
    }

    /// Reads the real machine. Cannot assert what it finds — that depends on
    /// which connections exist — but every claim it returns must be shaped
    /// correctly, and it must not panic or hang.
    #[test]
    fn reading_the_live_machine_yields_well_formed_claims() {
        for scope in WindowsInterfaceDnsScopes.dns_scopes() {
            assert!(!scope.adapter_id.is_empty());
            assert!(!scope.suffix.is_empty(), "{scope:?}");
            assert_eq!(scope.suffix, scope.suffix.to_ascii_lowercase());
            assert!(!scope.suffix.starts_with('.') && !scope.suffix.ends_with('.'));
        }
    }
}
