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

#![allow(unsafe_code)]

use std::net::Ipv4Addr;

use nrr_platform_api::dns_scope::{normalize_suffix, InterfaceDnsScope, InterfaceDnsScopePort};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE,
    KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, REG_SAM_FLAGS, REG_VALUE_TYPE,
};

/// Per-interface TCP/IP parameters. One subkey per adapter GUID.
const INTERFACES_KEY: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";

/// Longest adapter GUID subkey name we will read. A GUID is 38 characters; the
/// bound only stops a malformed key from sizing a buffer.
const MAX_KEY_CHARS: usize = 128;

/// Production implementation.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsInterfaceDnsScopes;

impl InterfaceDnsScopePort for WindowsInterfaceDnsScopes {
    fn dns_scopes(&self) -> Vec<InterfaceDnsScope> {
        enum_subkeys(INTERFACES_KEY)
            .into_iter()
            .filter_map(|guid| scope_for_interface(&guid))
            .collect()
    }
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

// ── Registry helpers ─────────────────────────────────────────────────────────

fn open_key(subkey: &str, access: u32) -> Option<HKEY> {
    let wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let mut hkey = HKEY::default();
    // SAFETY: `wide` is NUL-terminated UTF-16 outliving the call; `hkey` is a
    // fresh out-param; the hive is a Win32 pseudo-handle.
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(wide.as_ptr()),
            0,
            REG_SAM_FLAGS(access),
            &mut hkey,
        )
    };
    (rc == ERROR_SUCCESS).then_some(hkey)
}

fn close_key(hkey: HKEY) {
    // SAFETY: `hkey` came from a successful `RegOpenKeyExW`.
    unsafe {
        let _ = RegCloseKey(hkey);
    }
}

fn enum_subkeys(subkey: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some(hkey) = open_key(subkey, KEY_ENUMERATE_SUB_KEYS.0 | KEY_QUERY_VALUE.0) else {
        return out;
    };
    let mut index = 0u32;
    loop {
        let mut buf = vec![0u16; MAX_KEY_CHARS];
        let mut len = buf.len() as u32;
        // SAFETY: `buf` is owned by this frame and `len` carries its length in
        // characters, so the call cannot write past it.
        let rc = unsafe {
            RegEnumKeyExW(
                hkey,
                index,
                windows::core::PWSTR(buf.as_mut_ptr()),
                &mut len,
                None,
                windows::core::PWSTR::null(),
                None,
                None,
            )
        };
        if rc == ERROR_NO_MORE_ITEMS {
            break;
        }
        if rc != ERROR_SUCCESS {
            // A name longer than the buffer, or a transient failure: skip this
            // one rather than abandoning the whole enumeration.
            index += 1;
            if index > 4096 {
                break;
            }
            continue;
        }
        out.push(String::from_utf16_lossy(&buf[..len as usize]));
        index += 1;
    }
    close_key(hkey);
    out
}

/// A `REG_SZ` value, or `None` when absent or empty.
fn read_value(subkey: &str, name: &str) -> Option<String> {
    let hkey = open_key(subkey, KEY_QUERY_VALUE.0)?;
    let value = read_open_key_string(hkey, name);
    close_key(hkey);
    value.filter(|v| !v.trim().is_empty())
}

fn read_open_key_string(hkey: HKEY, value_name: &str) -> Option<String> {
    let name_wide: Vec<u16> = value_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut size: u32 = 0;
    let mut value_type = REG_VALUE_TYPE::default();
    // SAFETY: `name_wide` is NUL-terminated and outlives the call; this probe
    // asks only for the byte length.
    let rc = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR(name_wide.as_ptr()),
            None,
            Some(&mut value_type),
            None,
            Some(&mut size),
        )
    };
    if rc != ERROR_SUCCESS || size == 0 {
        return None;
    }
    let mut buf: Vec<u16> = vec![0u16; (size as usize) / 2 + 1];
    let mut read: u32 = (buf.len() * 2) as u32;
    // SAFETY: `buf` is sized from the probe above and `read` carries its byte
    // length, so the call cannot write past it.
    let rc = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR(name_wide.as_ptr()),
            None,
            Some(&mut value_type),
            Some(buf.as_mut_ptr().cast()),
            Some(&mut read),
        )
    };
    if rc != ERROR_SUCCESS {
        return None;
    }
    let chars = (read as usize) / 2;
    Some(
        String::from_utf16_lossy(&buf[..chars.min(buf.len())])
            .trim_end_matches('\0')
            .to_string(),
    )
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
