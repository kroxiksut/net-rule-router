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
use crate::enforcement::{RouteTableRef, UserPrincipal};
use crate::error::PlatformError;
use crate::types::RouteEntry;

/// The system route table plus the interface facts the routing layer reads.
///
/// Every method is expressible on each target OS: Windows answers with
/// `GetIpForwardTable2` / `GetAdaptersAddresses`, Linux with rtnetlink, macOS
/// with the routing socket.
pub trait RouteTablePort: Send + Sync {
    // ── Route table ──────────────────────────────────────────────────────────

    /// Enumerate the routes, both families.
    fn get_ip_forward_table(&self) -> Result<Vec<RouteEntry>, PlatformError>;

    /// Add a single route entry.
    fn create_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError>;

    /// Delete a single route entry.
    fn delete_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError>;

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
    fn interactive_user_sid(&self) -> Option<String> {
        None
    }

    /// Every user signed in interactively (console and remote, attached or
    /// disconnected), console user first, each once. The default answers with
    /// [`Self::interactive_user_sid`], which is right for a platform with one
    /// seat.
    fn interactive_user_sids(&self) -> Vec<String> {
        self.interactive_user_sid().into_iter().collect()
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

// ── Per-principal routing ────────────────────────────────────────────────────

/// What the selectors in front of one routing table must know about it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct TableSelector {
    /// The longest IPv4 overlay prefix the table holds. Routes this wide yield
    /// to the main table's more specific ones (the LAN, the tunnel's own subnet,
    /// a VPN server's host route), exactly as they did beside them in `main`.
    /// `None`: the table holds no overlay.
    pub overlay_prefix_v4: Option<u8>,
}

/// The selectors one routing pass asks for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SelectorPlan {
    /// Every present user: their traffic looks up their own table.
    pub users: Vec<(UserPrincipal, TableSelector)>,
    /// The machine's service accounts look up the system table; `None` with
    /// nobody present.
    pub system: Option<TableSelector>,
}

/// What a selector reconcile changed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SelectorDelta {
    pub added: usize,
    pub removed: usize,
}

/// Per-user policy routing: each present user's routes live in a table of
/// their own, picked by who sends the packet, so one user's rules never steer
/// another's traffic. Linux selects by uid (`ip rule uidrange`); a platform
/// without a driverless equivalent does not implement this port.
pub trait PrincipalRoutingPort: Send + Sync {
    /// The table holding `principal`'s routes; `None` when this machine has
    /// none to give them.
    fn table_for(&self, principal: &UserPrincipal) -> Option<RouteTableRef>;

    /// The table the machine's service accounts look up.
    fn system_table(&self) -> RouteTableRef;

    /// Whether `table` is one this port hands out: every route in it is ours.
    fn is_principal_table(&self, table: &RouteTableRef) -> bool;

    /// Make the installed selectors exactly the ones `plan` needs.
    /// [`PlatformError::NotSupported`] means the kernel cannot select by user,
    /// and nothing of ours is left selecting.
    fn reconcile_selectors(&self, plan: &SelectorPlan) -> Result<SelectorDelta, PlatformError>;

    /// Remove every selector of ours. Returns how many went.
    fn clear_selectors(&self) -> Result<usize, PlatformError>;
}
