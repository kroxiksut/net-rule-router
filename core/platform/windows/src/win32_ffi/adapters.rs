//! `GetAdaptersAddresses` FFI binding.
//!
//! Backs `WindowsApiPort::get_adapter_infos` and the adapter list on screen
//! (`interface_manager`, `interface_rows`) with one Win32 walker.
//!
//! ## Buffer growth strategy
//!
//! `GetAdaptersAddresses` is a classic Win32 "two-pass or grow-and-retry"
//! API: the caller hands in a buffer plus its size; the API either
//! succeeds or returns `ERROR_BUFFER_OVERFLOW` along with the required
//! size in the same `*mut u32`. We start at 16 KiB (covers most home
//! machines in one pass), retry up to 4 times doubling/clamping to a
//! 16 MiB ceiling, and fail with `Transient` if growth still doesn't
//! suffice — that scenario indicates an adversarial environment, not a
//! genuine adapter count.
//!
//! ## Encoding contract
//!
//! - `AdapterName` is the **ASCII GUID string** (`{12AB...}`) — read via
//!   [`super::wide::pcstr_lossy`].
//! - `Description` and `FriendlyName` are wide (UTF-16) — read via
//!   [`super::wide::pwstr_lossy`]. Lossy on purpose: one adapter with a
//!   malformed name must not cost the whole list.
//!
//! ## Address families
//!
//! `AF_UNSPEC` is requested, so addresses of BOTH families are collected.
//! Win32 returns the same adapter set either way — the family argument
//! narrows the address lists, not the adapters. [`AdapterInfo::gateways`]
//! stays IPv4-only (a v6 gateway belongs with v6 route reconciliation);
//! [`AdapterDetails`] carries both families for the adapter list.

#![allow(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST,
    GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GET_ADAPTERS_ADDRESSES_FLAGS,
    IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_DNS_SERVER_ADDRESS_XP, IP_ADAPTER_GATEWAY_ADDRESS_LH,
    IP_ADAPTER_UNICAST_ADDRESS_LH,
};
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS,
};

use crate::adapters::{AdapterInfo, IfOperStatus, InterfaceType};
use crate::error::PlatformError;

use super::wide::{pcstr_lossy, pwstr_lossy};

/// Initial buffer size for the first `GetAdaptersAddresses` call.
/// 16 KiB covers a typical home machine (5–10 adapters) without retry.
const INITIAL_BUFFER_BYTES: u32 = 16 * 1024;

/// Hard ceiling on the buffer size — defends against pathological
/// retries if Windows keeps returning `ERROR_BUFFER_OVERFLOW`.
const MAX_BUFFER_BYTES: u32 = 16 * 1024 * 1024;

/// Maximum number of grow-and-retry passes before giving up.
const MAX_RETRIES: u8 = 4;

const OPERATION: &str = "GetAdaptersAddresses";

const BASE_FLAGS: GET_ADAPTERS_ADDRESSES_FLAGS = GET_ADAPTERS_ADDRESSES_FLAGS(
    GAA_FLAG_INCLUDE_GATEWAYS.0 | GAA_FLAG_SKIP_ANYCAST.0 | GAA_FLAG_SKIP_MULTICAST.0,
);

/// What the adapter list on screen reads beyond [`AdapterInfo`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterDetails {
    pub info: AdapterInfo,
    /// `Ipv6IfIndex`: the persistent-id fallback when the adapter has no name.
    pub ipv6_if_index: u32,
    /// The whole hardware address, whatever its length; empty when there is none.
    pub physical_address: Vec<u8>,
    /// The IANA `ifType` as reported: [`InterfaceType`] folds Wi-Fi into
    /// Ethernet and PPP into `Other`, which the list tells apart.
    pub if_type: u32,
    /// Gateways of both families, in the order Win32 lists them.
    pub gateways: Vec<IpAddr>,
    /// DNS servers of both families, the preferred one first.
    pub dns_servers: Vec<IpAddr>,
}

/// Enumerate every adapter via `GetAdaptersAddresses`, with the unicast
/// addresses of both families.
///
/// Returns adapters as observed by the Win32 API at call time. The
/// caller is responsible for filtering virtual / loopback adapters
/// (see `crate::adapters::is_virtual_adapter`).
pub fn enumerate_adapters() -> Result<Vec<AdapterInfo>, PlatformError> {
    // DNS servers are skipped: this runs on every adapter tick and nothing
    // here reads them.
    enumerate(
        GET_ADAPTERS_ADDRESSES_FLAGS(BASE_FLAGS.0 | GAA_FLAG_SKIP_DNS_SERVER.0),
        read_info,
    )
}

/// Enumerate every adapter with the fields the adapter list shows.
pub fn enumerate_adapter_details() -> Result<Vec<AdapterDetails>, PlatformError> {
    enumerate(BASE_FLAGS, read_details)
}

fn enumerate<T>(
    flags: GET_ADAPTERS_ADDRESSES_FLAGS,
    read: unsafe fn(&IP_ADAPTER_ADDRESSES_LH) -> T,
) -> Result<Vec<T>, PlatformError> {
    let mut size = INITIAL_BUFFER_BYTES;
    for _ in 0..MAX_RETRIES {
        // Words, not bytes: the header holds pointers and `u64`s, so the
        // buffer must start 8-aligned, which a `Vec<u8>` does not promise.
        let mut buf: Vec<u64> = vec![0u64; (size as usize).div_ceil(8)];
        let head = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
        let mut out_size = size;

        // SAFETY: `buf` holds at least `size` bytes and starts 8-aligned,
        // which `IP_ADAPTER_ADDRESSES_LH` requires. `out_size` is
        // initialised to `size`. Win32 contract: it writes within
        // `out_size` bytes, and on overflow updates `out_size` with the
        // required length. Lifetime of `buf` covers the call.
        let code = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC.0),
                flags,
                None,
                Some(head),
                &mut out_size,
            )
        };

        if code == NO_ERROR.0 {
            // SAFETY: Win32 produced a valid linked-list-of-`IP_ADAPTER_
            // ADDRESSES_LH` that lives inside `buf`. `walk_chain` only
            // reads through `Next`/inner pointers and dereferences while
            // they remain non-null and within the buffer Win32 wrote.
            let result = unsafe { walk_chain(head, read) };
            return Ok(result);
        }
        if code == ERROR_NO_DATA.0 {
            return Ok(Vec::new());
        }
        if code == ERROR_BUFFER_OVERFLOW.0 {
            // Grow to whatever Win32 asked for, doubling the previous
            // size as a floor (avoids ping-pong if Win32 reports the
            // exact required size and another adapter shows up between
            // calls), and clamp to the safety ceiling.
            let next = out_size.max(size.saturating_mul(2)).min(MAX_BUFFER_BYTES);
            if next <= size {
                return Err(PlatformError::Transient {
                    operation: OPERATION,
                    detail: format!(
                        "buffer growth stuck: required {out_size} ≤ current {size}, ceiling {MAX_BUFFER_BYTES}"
                    ),
                });
            }
            size = next;
            continue;
        }
        return Err(PlatformError::Win32 {
            operation: OPERATION,
            code,
            message: format!("Win32 error {code}"),
        });
    }
    Err(PlatformError::Transient {
        operation: OPERATION,
        detail: format!("buffer growth exceeded {MAX_RETRIES} retries"),
    })
}

/// Walk the linked list returned by `GetAdaptersAddresses`.
///
/// # Safety
///
/// `head` must be either null or a pointer to a valid
/// `IP_ADAPTER_ADDRESSES_LH` linked list as produced by
/// `GetAdaptersAddresses` into a buffer that remains live for the
/// duration of the call; `read` must accept any such entry.
unsafe fn walk_chain<T>(
    head: *const IP_ADAPTER_ADDRESSES_LH,
    read: unsafe fn(&IP_ADAPTER_ADDRESSES_LH) -> T,
) -> Vec<T> {
    let mut out = Vec::new();
    let mut cur = head;
    let mut guard = 0u32;
    while !cur.is_null() && guard < MAX_ADAPTERS_GUARD {
        // SAFETY: `cur` is non-null and points to a Win32-produced
        // `IP_ADAPTER_ADDRESSES_LH` inside our buffer.
        let entry = unsafe { &*cur };
        out.push(unsafe { read(entry) });
        cur = entry.Next;
        guard += 1;
    }
    out
}

/// Defensive cap on linked-list traversal — Windows never returns
/// anywhere near this many adapters in practice (typical: 5–20). A
/// circular list would otherwise loop forever.
const MAX_ADAPTERS_GUARD: u32 = 4096;

/// Read one `IP_ADAPTER_ADDRESSES_LH` entry into our `AdapterInfo`.
///
/// # Safety
///
/// `entry` must be a valid reference (already dereffed safely via the
/// chain walker). Inner pointers (`AdapterName`, `Description`,
/// `FriendlyName`, the address lists) must be either null or valid as
/// filled by `GetAdaptersAddresses`.
unsafe fn read_info(entry: &IP_ADAPTER_ADDRESSES_LH) -> AdapterInfo {
    // SAFETY: forwarded caller contract.
    let gateways = unsafe { walk_addresses(entry.FirstGatewayAddress.cast_const()) };
    // SAFETY: forwarded caller contract.
    unsafe { read_info_with(entry, &gateways) }
}

/// [`read_info`] plus what the adapter list reads.
///
/// # Safety
///
/// Same contract as [`read_info`], `FirstDnsServerAddress` included.
unsafe fn read_details(entry: &IP_ADAPTER_ADDRESSES_LH) -> AdapterDetails {
    // SAFETY: forwarded caller contract.
    let gateways = unsafe { walk_addresses(entry.FirstGatewayAddress.cast_const()) };
    // SAFETY: forwarded caller contract.
    let dns_servers = unsafe { walk_addresses(entry.FirstDnsServerAddress.cast_const()) };
    AdapterDetails {
        // SAFETY: forwarded caller contract.
        info: unsafe { read_info_with(entry, &gateways) },
        ipv6_if_index: entry.Ipv6IfIndex,
        physical_address: physical_address(entry).to_vec(),
        if_type: entry.IfType,
        gateways,
        dns_servers,
    }
}

/// # Safety
///
/// Same contract as [`read_info`].
unsafe fn read_info_with(entry: &IP_ADAPTER_ADDRESSES_LH, gateways: &[IpAddr]) -> AdapterInfo {
    // SAFETY: union access — the `Anonymous` arm carries `IfIndex` per
    // the IP Helper API contract. The other arm is `Alignment: u64`,
    // which is also a valid `repr(C)` union view.
    let if_index = unsafe { entry.Anonymous1.Anonymous.IfIndex };

    // SAFETY: `AdapterName` is a Win32-owned, null-terminated PCSTR
    // valid for the lifetime of the buffer.
    let adapter_name = unsafe { pcstr_lossy(entry.AdapterName.0 as *const u8) };

    // SAFETY: same for `Description` (PWSTR / UTF-16).
    let description = unsafe { pwstr_lossy(entry.Description.0 as *const u16) };

    // SAFETY: same for `FriendlyName` — the renameable connection name.
    let friendly_name = unsafe { pwstr_lossy(entry.FriendlyName.0 as *const u16) };

    // SAFETY: linked-list head pointer remains valid for buffer lifetime.
    let unicast = unsafe { walk_addresses(entry.FirstUnicastAddress.cast_const()) };
    let ipv4_addresses = unicast.iter().filter_map(|ip| as_v4(*ip)).collect();
    let ipv6_addresses = unicast
        .iter()
        .filter_map(|ip| match ip {
            IpAddr::V6(v6) => Some(*v6),
            IpAddr::V4(_) => None,
        })
        .collect();

    AdapterInfo {
        index: if_index,
        adapter_name,
        description,
        friendly_name,
        mac: <[u8; 6]>::try_from(physical_address(entry)).ok(),
        interface_type: InterfaceType::from_raw(entry.IfType),
        oper_status: decode_oper_status(entry.OperStatus.0),
        ipv4_addresses,
        ipv6_addresses,
        gateways: gateways.iter().filter_map(|ip| as_v4(*ip)).collect(),
    }
}

fn as_v4(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    }
}

/// The reported hardware address, its length clamped to the array Win32 fills.
fn physical_address(entry: &IP_ADAPTER_ADDRESSES_LH) -> &[u8] {
    let len = usize::try_from(entry.PhysicalAddressLength)
        .unwrap_or(usize::MAX)
        .min(entry.PhysicalAddress.len());
    &entry.PhysicalAddress[..len]
}

/// Map `IF_OPER_STATUS` raw value to our domain `IfOperStatus`.
///
/// Win32 values per `IfMib.h`:
/// `1=Up, 2=Down, 3=Testing, 4=Unknown, 5=Dormant, 6=NotPresent, 7=LowerLayerDown`.
fn decode_oper_status(raw: i32) -> IfOperStatus {
    match raw {
        1 => IfOperStatus::Up,
        2 => IfOperStatus::Down,
        3 => IfOperStatus::Testing,
        5 => IfOperStatus::Dormant,
        6 => IfOperStatus::NotPresent,
        7 => IfOperStatus::LowerLayerDown,
        _ => IfOperStatus::Unknown,
    }
}

/// A node of one of the address lists hanging off an adapter entry.
trait AddressNode {
    fn next(&self) -> *const Self;
    fn address(&self) -> &SOCKET_ADDRESS;
}

macro_rules! address_node {
    ($($node:ty),+) => {$(
        impl AddressNode for $node {
            fn next(&self) -> *const Self {
                self.Next
            }
            fn address(&self) -> &SOCKET_ADDRESS {
                &self.Address
            }
        }
    )+};
}

address_node!(
    IP_ADAPTER_UNICAST_ADDRESS_LH,
    IP_ADAPTER_GATEWAY_ADDRESS_LH,
    IP_ADAPTER_DNS_SERVER_ADDRESS_XP
);

const MAX_ADDRS_GUARD: u32 = 1024;

/// Walk one address list, in order, keeping the IPv4 and IPv6 entries.
///
/// One pass per list: a second traversal would be a second chance for the
/// results to disagree about which addresses the adapter had at that instant.
///
/// # Safety
///
/// `head` must be either null or a valid pointer to a list of `N` as filled
/// by Win32, alive for the call.
unsafe fn walk_addresses<N: AddressNode>(head: *const N) -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut cur = head;
    let mut guard = 0u32;
    while !cur.is_null() && guard < MAX_ADDRS_GUARD {
        // SAFETY: Win32-produced linked-list node, alive for buffer lifetime.
        let node = unsafe { &*cur };
        // SAFETY: the node's socket address is Win32-filled like the node.
        if let Some(addr) = unsafe { socket_address_to_ip(node.address()) } {
            out.push(addr);
        }
        cur = node.next();
        guard += 1;
    }
    out
}

/// Decode a `SOCKET_ADDRESS` of family `AF_INET` or `AF_INET6`; anything
/// else, or a length too short for its family, is dropped.
///
/// The IPv6 scope id is dropped: the adapter is already known from the entry
/// that owns the list.
///
/// # Safety
///
/// `address.lpSockaddr` must be either null or point at
/// `address.iSockaddrLength` readable bytes owned by the Win32 buffer.
unsafe fn socket_address_to_ip(address: &SOCKET_ADDRESS) -> Option<IpAddr> {
    let ptr = address.lpSockaddr as *const SOCKADDR;
    let len = usize::try_from(address.iSockaddrLength).ok()?;
    if ptr.is_null() || len < std::mem::size_of::<SOCKADDR_IN>() {
        return None;
    }
    // SAFETY: `ptr` is non-null and at least a `SOCKADDR_IN` long, which
    // covers the family field.
    let family = unsafe { (*ptr).sa_family };
    if family == AF_INET {
        // SAFETY: when `sa_family == AF_INET`, the layout is `SOCKADDR_IN`,
        // and the length was checked above.
        let sa_in = unsafe { &*(ptr as *const SOCKADDR_IN) };
        // SAFETY: `S_addr` is a valid arm of the IN_ADDR union; bytes are
        // network-order (big-endian) per the Win32 contract.
        let net_order = unsafe { sa_in.sin_addr.S_un.S_addr };
        return Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(net_order))));
    }
    if family == AF_INET6 && len >= std::mem::size_of::<SOCKADDR_IN6>() {
        // SAFETY: when `sa_family == AF_INET6`, the layout is `SOCKADDR_IN6`,
        // and the length was checked just now.
        let sa_in6 = unsafe { &*(ptr as *const SOCKADDR_IN6) };
        // SAFETY: `Byte` is a valid arm of the IN6_ADDR union — 16 bytes in
        // network order, which is the order `Ipv6Addr::from([u8; 16])` expects.
        let octets = unsafe { sa_in6.sin6_addr.u.Byte };
        return Some(IpAddr::V6(Ipv6Addr::from(octets)));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::core::{PSTR, PWSTR};
    use windows::Win32::NetworkManagement::IpHelper::{
        IP_ADAPTER_ADDRESSES_LH_0, IP_ADAPTER_ADDRESSES_LH_0_0,
    };
    use windows::Win32::NetworkManagement::Ndis::IF_OPER_STATUS;
    use windows::Win32::Networking::WinSock::{
        ADDRESS_FAMILY, AF_IPX, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0,
    };

    // The fixtures leak: each list must stay put while the entry points at it.
    fn v4(ip: [u8; 4]) -> SOCKET_ADDRESS {
        let sa = Box::into_raw(Box::new(SOCKADDR_IN {
            sin_family: AF_INET,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from(Ipv4Addr::from(ip)).to_be(),
                },
            },
            ..Default::default()
        }));
        SOCKET_ADDRESS {
            lpSockaddr: sa.cast(),
            iSockaddrLength: std::mem::size_of::<SOCKADDR_IN>() as i32,
        }
    }

    fn v6(ip: &str) -> SOCKET_ADDRESS {
        let octets = ip.parse::<Ipv6Addr>().expect("v6 literal").octets();
        let sa = Box::into_raw(Box::new(SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_addr: IN6_ADDR {
                u: IN6_ADDR_0 { Byte: octets },
            },
            ..Default::default()
        }));
        SOCKET_ADDRESS {
            lpSockaddr: sa.cast(),
            iSockaddrLength: std::mem::size_of::<SOCKADDR_IN6>() as i32,
        }
    }

    fn list<N>(addresses: Vec<SOCKET_ADDRESS>, node: fn(SOCKET_ADDRESS, *mut N) -> N) -> *mut N {
        let mut next: *mut N = std::ptr::null_mut();
        for address in addresses.into_iter().rev() {
            next = Box::into_raw(Box::new(node(address, next)));
        }
        next
    }

    fn unicast(addresses: Vec<SOCKET_ADDRESS>) -> *mut IP_ADAPTER_UNICAST_ADDRESS_LH {
        list(addresses, |address, next| IP_ADAPTER_UNICAST_ADDRESS_LH {
            Address: address,
            Next: next,
            ..Default::default()
        })
    }

    fn gateways(addresses: Vec<SOCKET_ADDRESS>) -> *mut IP_ADAPTER_GATEWAY_ADDRESS_LH {
        list(addresses, |address, next| IP_ADAPTER_GATEWAY_ADDRESS_LH {
            Address: address,
            Next: next,
            ..Default::default()
        })
    }

    fn dns(addresses: Vec<SOCKET_ADDRESS>) -> *mut IP_ADAPTER_DNS_SERVER_ADDRESS_XP {
        list(addresses, |address, next| {
            IP_ADAPTER_DNS_SERVER_ADDRESS_XP {
                Address: address,
                Next: next,
                ..Default::default()
            }
        })
    }

    fn wide(text: &str) -> PWSTR {
        let units: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        PWSTR(Box::leak(units.into_boxed_slice()).as_mut_ptr())
    }

    fn entry() -> IP_ADAPTER_ADDRESSES_LH {
        IP_ADAPTER_ADDRESSES_LH {
            Anonymous1: IP_ADAPTER_ADDRESSES_LH_0 {
                Anonymous: IP_ADAPTER_ADDRESSES_LH_0_0 {
                    Length: 0,
                    IfIndex: 7,
                },
            },
            AdapterName: PSTR(c"{0000-AAAA}".as_ptr().cast::<u8>().cast_mut()),
            Description: wide("Example Wireless Adapter"),
            FriendlyName: wide("Wi-Fi"),
            PhysicalAddress: [0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0, 0],
            PhysicalAddressLength: 6,
            IfType: 71,
            OperStatus: IF_OPER_STATUS(7),
            Ipv6IfIndex: 12,
            FirstUnicastAddress: unicast(vec![
                v6("fe80::1"),
                v4([192, 168, 1, 20]),
                v6("2001:db8::20"),
            ]),
            FirstGatewayAddress: gateways(vec![v6("fe80::fe"), v4([192, 168, 1, 1])]),
            FirstDnsServerAddress: dns(vec![v4([192, 168, 1, 1]), v6("2001:db8::53")]),
            ..Default::default()
        }
    }

    #[test]
    fn details_carry_every_field_the_list_reads() {
        let entry = entry();
        // SAFETY: every pointer in `entry` was built above and leaks.
        let details = unsafe { read_details(&entry) };

        assert_eq!(details.info.index, 7);
        assert_eq!(details.info.adapter_name, "{0000-AAAA}");
        assert_eq!(details.info.description, "Example Wireless Adapter");
        assert_eq!(details.info.friendly_name, "Wi-Fi");
        assert_eq!(details.info.mac, Some([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]));
        assert_eq!(details.info.interface_type, InterfaceType::Ethernet);
        assert_eq!(details.info.oper_status, IfOperStatus::LowerLayerDown);
        assert_eq!(
            details.info.ipv4_addresses,
            vec![Ipv4Addr::new(192, 168, 1, 20)]
        );
        assert_eq!(
            details.info.ipv6_addresses,
            vec![
                "fe80::1".parse::<Ipv6Addr>().expect("v6"),
                "2001:db8::20".parse::<Ipv6Addr>().expect("v6"),
            ]
        );
        assert_eq!(
            details.info.gateways,
            vec![Ipv4Addr::new(192, 168, 1, 1)],
            "the tick-path gateways stay IPv4-only"
        );

        assert_eq!(details.ipv6_if_index, 12);
        assert_eq!(details.if_type, 71, "Wi-Fi stays told apart from Ethernet");
        assert_eq!(
            details.physical_address,
            vec![0x02, 0x11, 0x22, 0x33, 0x44, 0x55]
        );
        let ip = |text: &str| text.parse::<IpAddr>().expect("ip");
        assert_eq!(
            details.gateways,
            vec![ip("fe80::fe"), ip("192.168.1.1")],
            "both families, Win32 order"
        );
        assert_eq!(
            details.dns_servers,
            vec![ip("192.168.1.1"), ip("2001:db8::53")],
            "the preferred server stays first"
        );
    }

    #[test]
    fn the_tick_path_reads_the_same_info_as_the_details() {
        let entry = entry();
        // SAFETY: as above.
        let (info, details) = unsafe { (read_info(&entry), read_details(&entry)) };
        assert_eq!(info, details.info);
    }

    #[test]
    fn a_hardware_address_of_another_length_is_kept_whole_but_is_no_mac() {
        let mut entry = IP_ADAPTER_ADDRESSES_LH {
            PhysicalAddress: [1, 2, 3, 4, 5, 6, 7, 8],
            PhysicalAddressLength: 8,
            ..Default::default()
        };
        // SAFETY: every pointer is null, which the readers accept.
        let details = unsafe { read_details(&entry) };
        assert_eq!(details.physical_address, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(details.info.mac, None);

        entry.PhysicalAddressLength = u32::MAX;
        assert_eq!(physical_address(&entry).len(), 8, "clamped, no panic");

        entry.PhysicalAddressLength = 0;
        // SAFETY: as above.
        let details = unsafe { read_details(&entry) };
        assert!(details.physical_address.is_empty());
        assert_eq!(details.info.mac, None);
    }

    #[test]
    fn an_empty_entry_reads_as_empty_fields() {
        let entry = IP_ADAPTER_ADDRESSES_LH::default();
        // SAFETY: every pointer is null.
        let details = unsafe { read_details(&entry) };
        assert!(details.info.adapter_name.is_empty());
        assert!(details.info.friendly_name.is_empty());
        assert!(details.gateways.is_empty());
        assert!(details.dns_servers.is_empty());
        assert_eq!(details.info.oper_status, IfOperStatus::Unknown);
    }

    #[test]
    fn foreign_families_and_short_lengths_are_dropped() {
        let mut short = v6("2001:db8::1");
        short.iSockaddrLength = std::mem::size_of::<SOCKADDR_IN>() as i32;
        let mut negative = v4([10, 0, 0, 1]);
        negative.iSockaddrLength = -1;
        let foreign = v4([10, 0, 0, 2]);
        // SAFETY: `foreign` points at a leaked `SOCKADDR_IN` built by `v4`.
        unsafe { (*foreign.lpSockaddr).sa_family = ADDRESS_FAMILY(AF_IPX) };
        let null = SOCKET_ADDRESS::default();
        let head = unicast(vec![short, negative, foreign, null, v4([10, 0, 0, 3])]);
        // SAFETY: the list was built above and leaks.
        let addresses = unsafe { walk_addresses(head.cast_const()) };
        assert_eq!(addresses, vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3))]);
    }

    #[test]
    fn decode_oper_status_known_values() {
        assert_eq!(decode_oper_status(1), IfOperStatus::Up);
        assert_eq!(decode_oper_status(2), IfOperStatus::Down);
        assert_eq!(decode_oper_status(3), IfOperStatus::Testing);
        assert_eq!(decode_oper_status(5), IfOperStatus::Dormant);
        assert_eq!(decode_oper_status(6), IfOperStatus::NotPresent);
        assert_eq!(decode_oper_status(7), IfOperStatus::LowerLayerDown);
    }

    #[test]
    fn decode_oper_status_unknown_falls_back() {
        assert_eq!(decode_oper_status(0), IfOperStatus::Unknown);
        assert_eq!(decode_oper_status(99), IfOperStatus::Unknown);
        assert_eq!(decode_oper_status(-1), IfOperStatus::Unknown);
    }

    /// Both entry points on the test machine. Contents depend on its adapter
    /// inventory, so only success is asserted (`GetAdaptersAddresses` is a
    /// non-privileged call).
    #[test]
    fn both_enumerations_succeed_on_windows() {
        enumerate_adapters().expect("enumerate_adapters");
        enumerate_adapter_details().expect("enumerate_adapter_details");
    }
}
