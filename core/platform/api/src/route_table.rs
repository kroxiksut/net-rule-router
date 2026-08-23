//! The route table and the interfaces around it — the half of the old
//! `WindowsApiPort` that every OS can answer.
//!
//! Reading and mutating the system route table, enumerating adapters and their
//! addresses, and naming the interactive user are things Linux and macOS do as
//! readily as Windows; only the mechanism differs. They lived in a trait called
//! `WindowsApiPort` next to the WFP engine calls, which meant a Linux backend
//! had to stub eleven filter-engine methods it can never implement in order to
//! answer the seven it can — so it stubbed all eighteen and the routing layer
//! stayed Windows-only.
//!
//! Splitting them is what lets the neutral routing code (`route_reconciler`,
//! `route_coordinator`, the IPv6 route log, the connection-egress trace) name
//! [`RouteTablePort`] and work on any OS, while the filter engine stays behind
//! its own Windows-shaped port.

use crate::adapters::AdapterInfo;
use crate::error::PlatformError;
use crate::types::{Ipv6RouteRow, RouteEntry};

/// The system route table plus the interface facts the routing layer reads.
///
/// Every method is expressible on each target OS: Windows answers with
/// `GetIpForwardTable2` / `GetAdaptersAddresses`, Linux with rtnetlink, macOS
/// with the routing socket.
pub trait RouteTablePort: Send + Sync {
    // ── IPv4 route table ─────────────────────────────────────────────────────

    /// Enumerate all IPv4 routes the apply layer is interested in.
    fn get_ip_forward_table(&self) -> Result<Vec<RouteEntry>, PlatformError>;

    /// Add a single IPv4 route entry.
    fn create_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError>;

    /// Delete a single IPv4 route entry.
    fn delete_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError>;

    /// Read the IPv6 forwarding table. Diagnostics only — nothing installs v6
    /// routes — so the default is "this platform cannot tell", which reads the
    /// same as an empty table to every caller that just logs it.
    fn get_ipv6_forward_table(&self) -> Result<Vec<Ipv6RouteRow>, PlatformError> {
        Ok(Vec::new())
    }

    // ── Adapter enumeration ──────────────────────────────────────────────────

    /// Enumerate all network adapters with their current availability state.
    ///
    /// Returns info for all adapters including virtual and loopback.
    /// Callers filter via `is_virtual_adapter()` and `classify_availability()`.
    fn get_adapter_infos(&self) -> Result<Vec<AdapterInfo>, PlatformError>;

    /// All local unicast addresses (IPv4 **and** IPv6) paired with the interface
    /// index that owns each. The connection-egress trace maps a connection's
    /// local (source) address to its egress interface; unlike
    /// [`Self::get_adapter_infos`] (IPv4-only) this also covers IPv6. The
    /// default returns empty (no egress labelling) so test doubles need not
    /// implement it.
    fn unicast_ip_addresses(&self) -> Result<Vec<(std::net::IpAddr, u32)>, PlatformError> {
        Ok(Vec::new())
    }

    /// Identity of the user owning the active interactive session, in the
    /// platform's own spelling (a string SID on Windows). The service-driven
    /// routing scope uses it to pick the routing user when no GUI/tray is
    /// connected, so a managed policy is enforced from boot. `None` when there
    /// is no interactive user or the identity cannot be resolved.
    fn active_console_user_sid(&self) -> Option<String> {
        None
    }

    /// Resolve an interface index to the stable 64-bit interface identity the
    /// enforcement layer pins an egress condition on.
    ///
    /// On Windows that is the `NET_LUID.Value` a WFP filter's
    /// `FWPM_CONDITION_IP_LOCAL_INTERFACE` needs — the index alone will not do,
    /// because it is reused. Other platforms return whatever identifier plays
    /// the same role for them; the contract is only that it is stable for the
    /// life of the interface and non-zero.
    fn interface_luid_for_index(&self, ifindex: u32) -> Result<u64, PlatformError>;
}
