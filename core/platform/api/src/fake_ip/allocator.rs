//! Fake-IP address pool and the hostname <-> fake-address map.
//!
//! Pure, OS-neutral, deterministic: given the same sequence of calls the same
//! hostname always lands on the same address, on every platform. The resolver
//! (Mode B) calls [`FakeIpAllocator::allocate`] when answering a query for a
//! hostname in scope; the userspace stack calls
//! [`FakeIpAllocator::domain_for_ip`] when a packet arrives for a fake address,
//! to learn which hostname (and therefore which route) the flow belongs to.
//!
//! ## Address space
//!
//! `198.18.0.0/15` (RFC 2544 benchmark test range) and `fc00::/18` (ULA). Both
//! are non-routable on the public internet, so an address that leaks out of a
//! misconfigured host goes nowhere instead of hitting a stranger's server.
//!
//! A binding is allocated as an *index* into the pool, and both the v4 and the
//! v6 address are derived from that one index — so a hostname's IPv4 and IPv6
//! fake addresses stay aligned and either one resolves back to the same entry.
//!
//! Indices 0 and 1 are reserved: 0 is the network address, 1 is the address the
//! TUN adapter itself carries (the peer/gateway the OS routes towards). The last
//! index of the v4 range is reserved as its broadcast address.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use crate::hosts_file::normalize_hostname;

/// Base of the default IPv4 fake-address pool (RFC 2544 benchmark range).
pub const FAKE_IP_V4_BASE: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 0);
/// Prefix length of the default IPv4 fake-address pool — 131 072 addresses.
pub const FAKE_IP_V4_PREFIX_LEN: u8 = 15;
/// Base of the default IPv6 fake-address pool (ULA, RFC 4193).
pub const FAKE_IP_V6_BASE: Ipv6Addr = Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0);
/// Prefix length of the default IPv6 fake-address pool.
pub const FAKE_IP_V6_PREFIX_LEN: u8 = 18;

/// Pool index carried by the TUN adapter itself (`198.18.0.1`) — the address the
/// OS sees as the next hop for the whole fake range. Never handed to a hostname.
pub const FAKE_IP_GATEWAY_INDEX: u32 = 1;
/// First index available to hostnames (0 = network, 1 = the adapter itself).
pub const FAKE_IP_FIRST_HOST_INDEX: u32 = 2;

/// A subnet already in use on the host — one of the active adapters' networks.
/// Enumerated per-OS (the adapter snapshot) and fed to
/// [`FakeIpPoolConfig::collisions`] before the fake pool is brought up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalSubnet {
    /// Network address of the subnet.
    pub network: IpAddr,
    /// Prefix length of the subnet.
    pub prefix_len: u8,
}

impl LocalSubnet {
    /// Convenience constructor.
    #[must_use]
    pub fn new(network: IpAddr, prefix_len: u8) -> Self {
        Self {
            network,
            prefix_len,
        }
    }
}

/// A live subnet found to overlap the fake pool — activation surfaces it rather
/// than bringing up a pool that would shadow real traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolCollision {
    /// Which family collided (`"ipv4"` / `"ipv6"`) — a stable slug for logs and
    /// the user-facing warning.
    pub family: &'static str,
    /// The offending local subnet.
    pub local: LocalSubnet,
}

/// Geometry of the fake-address pool. Defaults to the constants above; the
/// fields exist so a deployment that genuinely collides with `198.18/15` can be
/// moved without touching the allocator, and so tests can use a tiny pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FakeIpPoolConfig {
    /// Network address of the IPv4 range.
    pub v4_base: Ipv4Addr,
    /// Prefix length of the IPv4 range (`0..=30`).
    pub v4_prefix_len: u8,
    /// Network address of the IPv6 range; `None` disables v6 bindings.
    pub v6_base: Option<Ipv6Addr>,
    /// Prefix length of the IPv6 range (`0..=128`).
    pub v6_prefix_len: u8,
}

impl Default for FakeIpPoolConfig {
    fn default() -> Self {
        Self {
            v4_base: FAKE_IP_V4_BASE,
            v4_prefix_len: FAKE_IP_V4_PREFIX_LEN,
            v6_base: Some(FAKE_IP_V6_BASE),
            v6_prefix_len: FAKE_IP_V6_PREFIX_LEN,
        }
    }
}

impl FakeIpPoolConfig {
    /// IPv4-only pool — used where the host has no IPv6 or the edition ships
    /// v4-only bindings.
    #[must_use]
    pub fn v4_only() -> Self {
        Self {
            v6_base: None,
            ..Self::default()
        }
    }

    /// Number of addresses the IPv4 range spans, including the reserved ones.
    #[must_use]
    pub fn v4_address_count(&self) -> u32 {
        let host_bits = 32u32.saturating_sub(u32::from(self.v4_prefix_len));
        if host_bits >= 32 {
            u32::MAX
        } else {
            1u32 << host_bits
        }
    }

    /// How many hostnames the pool can hold at once: everything except the
    /// network address, the adapter's own address, and the broadcast address.
    #[must_use]
    pub fn capacity(&self) -> u32 {
        self.v4_address_count()
            .saturating_sub(FAKE_IP_FIRST_HOST_INDEX)
            .saturating_sub(1)
    }

    /// The address the TUN adapter itself must carry for this pool.
    #[must_use]
    pub fn gateway_v4(&self) -> Ipv4Addr {
        self.v4_at(FAKE_IP_GATEWAY_INDEX)
    }

    /// The inclusive `[first, last]` IPv4 addresses of the pool — the bounds a
    /// storage sweep needs to purge pool addresses that leaked into a cache
    /// modelled on the real network.
    #[must_use]
    pub fn v4_range(&self) -> (Ipv4Addr, Ipv4Addr) {
        let first = u32::from(self.v4_base);
        let last = first.wrapping_add(self.v4_address_count().saturating_sub(1));
        (Ipv4Addr::from(first), Ipv4Addr::from(last))
    }

    /// A stable text stamp of this pool's geometry. Persisted next to stored
    /// bindings so a changed pool invalidates them (an index only means
    /// anything relative to the pool it was dealt from).
    #[must_use]
    pub fn stamp(&self) -> String {
        match self.v6_base {
            Some(v6) => format!(
                "v4={}/{};v6={}/{}",
                self.v4_base, self.v4_prefix_len, v6, self.v6_prefix_len
            ),
            None => format!("v4={}/{}", self.v4_base, self.v4_prefix_len),
        }
    }

    /// The IPv6 address the TUN adapter itself must carry, when v6 is enabled.
    #[must_use]
    pub fn gateway_v6(&self) -> Option<Ipv6Addr> {
        self.v6_at(FAKE_IP_GATEWAY_INDEX)
    }

    fn v4_at(&self, index: u32) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.v4_base).wrapping_add(index))
    }

    fn v6_at(&self, index: u32) -> Option<Ipv6Addr> {
        self.v6_base
            .map(|base| Ipv6Addr::from(u128::from(base).wrapping_add(u128::from(index))))
    }

    /// Whether `addr` falls inside this pool's range — true even for an address
    /// no hostname currently holds, so the stack can recognise (and drop)
    /// traffic to a stale fake address instead of forwarding it somewhere real.
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => {
                let mask = prefix_mask_v4(self.v4_prefix_len);
                (u32::from(v4) & mask) == (u32::from(self.v4_base) & mask)
            }
            IpAddr::V6(v6) => match self.v6_base {
                Some(base) => {
                    let mask = prefix_mask_v6(self.v6_prefix_len);
                    (u128::from(v6) & mask) == (u128::from(base) & mask)
                }
                None => false,
            },
        }
    }

    /// Whether `addr` falls inside the DEFAULT pool ranges (RFC 2544
    /// `198.18.0.0/15`, plus the ULA slice when v6 is on).
    ///
    /// Observation and learning layers use this to keep virtual addresses out
    /// of anything that models the REAL network: an app-observation store, a
    /// reverse-DNS learner, or a per-IP route pin fed a fake address would
    /// steer pool traffic onto a physical adapter and away from the TUN.
    #[must_use]
    pub fn is_default_pool_addr(addr: IpAddr) -> bool {
        Self::default().contains(addr)
    }

    /// Any of `local` subnets that overlap this pool's ranges.
    ///
    /// Fake-IP hands applications addresses out of the pool; if the pool overlaps
    /// a real subnet the host is actually on, a fake address could shadow a real
    /// destination and the stack would swallow legitimate traffic. The default
    /// pool (`198.18.0.0/15`, RFC 2544) is chosen precisely to avoid the RFC 1918
    /// ranges (`10/8`, `172.16/12`, `192.168/16`), so a collision is rare — but a
    /// custom pool or an unusual corporate range can still clash, and activation
    /// must detect it up front rather than silently break routing.
    ///
    /// Two CIDRs overlap iff one contains the other, i.e. their bases agree under
    /// the SHORTER of the two prefixes.
    #[must_use]
    pub fn collisions(&self, local: &[LocalSubnet]) -> Vec<PoolCollision> {
        local
            .iter()
            .filter_map(|subnet| self.collision_with(subnet))
            .collect()
    }

    /// Whether any of `local` overlaps this pool.
    #[must_use]
    pub fn overlaps_any(&self, local: &[LocalSubnet]) -> bool {
        local.iter().any(|s| self.collision_with(s).is_some())
    }

    fn collision_with(&self, subnet: &LocalSubnet) -> Option<PoolCollision> {
        let overlaps = match subnet.network {
            IpAddr::V4(local_base) => {
                let shared = self.v4_prefix_len.min(subnet.prefix_len);
                let mask = prefix_mask_v4(shared);
                (u32::from(local_base) & mask) == (u32::from(self.v4_base) & mask)
            }
            IpAddr::V6(local_base) => match self.v6_base {
                Some(pool_base) => {
                    let shared = self.v6_prefix_len.min(subnet.prefix_len);
                    let mask = prefix_mask_v6(shared);
                    (u128::from(local_base) & mask) == (u128::from(pool_base) & mask)
                }
                None => false,
            },
        };
        overlaps.then(|| PoolCollision {
            family: if subnet.network.is_ipv4() {
                "ipv4"
            } else {
                "ipv6"
            },
            local: *subnet,
        })
    }

    /// Index of `addr` within the pool, or `None` when it is outside the range.
    fn index_of(&self, addr: IpAddr) -> Option<u32> {
        if !self.contains(addr) {
            return None;
        }
        match addr {
            IpAddr::V4(v4) => Some(u32::from(v4).wrapping_sub(u32::from(self.v4_base))),
            IpAddr::V6(v6) => {
                let base = self.v6_base?;
                u32::try_from(u128::from(v6).wrapping_sub(u128::from(base))).ok()
            }
        }
    }
}

fn prefix_mask_v4(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32u32.saturating_sub(u32::from(prefix_len)).min(31))
    }
}

fn prefix_mask_v6(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128u32.saturating_sub(u32::from(prefix_len)).min(127))
    }
}

/// A hostname's place in the pool: the index plus the addresses derived from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FakeIpBinding {
    /// Index within the pool — the identity of the binding.
    pub index: u32,
    /// IPv4 fake address handed to the client.
    pub v4: Ipv4Addr,
    /// IPv6 fake address, when the pool has a v6 range.
    pub v6: Option<Ipv6Addr>,
}

/// Why an allocation could not be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FakeIpError {
    /// The hostname was empty after normalization.
    EmptyDomain,
    /// The pool is full and nothing could be recycled — configuration error
    /// (a pool this small cannot serve the host); the caller falls back to the
    /// real address rather than failing the query.
    PoolExhausted,
}

impl fmt::Display for FakeIpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDomain => write!(f, "empty hostname cannot be given a fake address"),
            Self::PoolExhausted => write!(f, "fake-IP pool exhausted"),
        }
    }
}

impl std::error::Error for FakeIpError {}

#[derive(Clone, Debug)]
struct Slot {
    domain: String,
    /// Monotonic use counter — the recycling order when the pool fills up.
    last_used: u64,
}

/// A change to the hostname <-> index map, reported to the registered
/// [`BindingChangeSink`] so a persistence layer can mirror the map without the
/// allocator knowing anything about storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindingChange {
    /// `domain` now holds `index` (a fresh allocation or a recycled index —
    /// either way this pair is the current truth for both sides of it).
    Bound { domain: String, index: u32 },
    /// The binding at `index` was explicitly released.
    Released { index: u32 },
}

/// Observer for [`BindingChange`] events. Called synchronously from the
/// allocator's mutating calls, and only when the map actually changes — an
/// idempotent re-allocation stays silent, so a persistence sink writes once
/// per binding, not once per DNS query.
pub type BindingChangeSink = Arc<dyn Fn(&BindingChange) + Send + Sync>;

/// Bidirectional hostname <-> fake-address map over a bounded pool.
///
/// Allocation is stable (a hostname keeps its address for as long as it is
/// mapped) and idempotent (re-allocating returns the existing binding). When the
/// pool fills up the least-recently-used hostname is recycled — its flows are
/// long finished, and the alternative (refusing to answer) would break the very
/// query fake-IP exists to serve.
#[derive(Clone)]
pub struct FakeIpAllocator {
    config: FakeIpPoolConfig,
    by_domain: HashMap<String, u32>,
    by_index: HashMap<u32, Slot>,
    /// Next never-used index; only grows, so first-time allocations are O(1).
    cursor: u32,
    /// Indices freed by [`FakeIpAllocator::release`], reused before the cursor.
    freed: Vec<u32>,
    tick: u64,
    sink: Option<BindingChangeSink>,
}

impl fmt::Debug for FakeIpAllocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeIpAllocator")
            .field("config", &self.config)
            .field("bindings", &self.by_domain.len())
            .field("cursor", &self.cursor)
            .field("tick", &self.tick)
            .field("has_sink", &self.sink.is_some())
            .finish()
    }
}

impl Default for FakeIpAllocator {
    fn default() -> Self {
        Self::new(FakeIpPoolConfig::default())
    }
}

impl FakeIpAllocator {
    #[must_use]
    pub fn new(config: FakeIpPoolConfig) -> Self {
        Self {
            config,
            by_domain: HashMap::new(),
            by_index: HashMap::new(),
            cursor: FAKE_IP_FIRST_HOST_INDEX,
            freed: Vec::new(),
            tick: 0,
            sink: None,
        }
    }

    /// Register the observer that mirrors binding changes (persistence).
    /// Restores never fire it — only live mutations do.
    pub fn set_change_sink(&mut self, sink: BindingChangeSink) {
        self.sink = Some(sink);
    }

    /// Re-seat bindings persisted by an earlier run, oldest-touched FIRST so
    /// the restored recycling order matches the stored one. Invalid entries
    /// (reserved/out-of-range index, empty domain, duplicate of either side)
    /// are skipped — a stale store can never wedge the allocator. Does not
    /// fire the change sink: these rows came FROM the mirror.
    pub fn restore<I: IntoIterator<Item = (String, u32)>>(&mut self, bindings: I) {
        let last_host_index = self.last_host_index();
        for (domain, index) in bindings {
            let key = normalize_hostname(&domain);
            if key.is_empty()
                || index < FAKE_IP_FIRST_HOST_INDEX
                || index > last_host_index
                || self.by_index.contains_key(&index)
                || self.by_domain.contains_key(&key)
            {
                continue;
            }
            self.tick = self.tick.saturating_add(1);
            self.by_index.insert(
                index,
                Slot {
                    domain: key.clone(),
                    last_used: self.tick,
                },
            );
            self.by_domain.insert(key, index);
        }
        // Never-used allocation resumes past the highest restored index; the
        // gaps below it go to the free list so they are not lost to the pool.
        let max_restored = self.by_index.keys().copied().max();
        if let Some(max) = max_restored {
            self.cursor = max.saturating_add(1).max(self.cursor);
            self.freed = (FAKE_IP_FIRST_HOST_INDEX..self.cursor)
                .filter(|i| !self.by_index.contains_key(i))
                .collect();
        }
    }

    #[must_use]
    pub fn config(&self) -> FakeIpPoolConfig {
        self.config
    }

    /// Number of hostnames currently mapped.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_domain.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_domain.is_empty()
    }

    /// How many hostnames this pool can hold at once.
    #[must_use]
    pub fn capacity(&self) -> u32 {
        self.config.capacity()
    }

    /// Give `domain` a fake address, or return the one it already holds.
    pub fn allocate(&mut self, domain: &str) -> Result<FakeIpBinding, FakeIpError> {
        let key = normalize_hostname(domain);
        if key.is_empty() {
            return Err(FakeIpError::EmptyDomain);
        }
        self.tick = self.tick.saturating_add(1);
        if let Some(&index) = self.by_domain.get(&key) {
            if let Some(slot) = self.by_index.get_mut(&index) {
                slot.last_used = self.tick;
            }
            return Ok(self.binding_at(index));
        }
        let index = self.take_index()?;
        let tick = self.tick;
        self.by_index.insert(
            index,
            Slot {
                domain: key.clone(),
                last_used: tick,
            },
        );
        self.by_domain.insert(key.clone(), index);
        if let Some(sink) = &self.sink {
            sink(&BindingChange::Bound { domain: key, index });
        }
        Ok(self.binding_at(index))
    }

    /// The binding `domain` holds, without affecting the recycling order.
    #[must_use]
    pub fn binding_for_domain(&self, domain: &str) -> Option<FakeIpBinding> {
        let key = normalize_hostname(domain);
        self.by_domain.get(&key).map(|&i| self.binding_at(i))
    }

    /// The hostname `addr` stands for, marking it as recently used so an active
    /// flow's hostname is never the one recycled. `None` when the address is
    /// outside the pool or its binding was already recycled.
    pub fn domain_for_ip(&mut self, addr: IpAddr) -> Option<String> {
        let index = self.config.index_of(addr)?;
        self.tick = self.tick.saturating_add(1);
        let tick = self.tick;
        let slot = self.by_index.get_mut(&index)?;
        slot.last_used = tick;
        Some(slot.domain.clone())
    }

    /// Read-only variant of [`Self::domain_for_ip`] for diagnostics/explain.
    #[must_use]
    pub fn peek_domain_for_ip(&self, addr: IpAddr) -> Option<&str> {
        let index = self.config.index_of(addr)?;
        self.by_index.get(&index).map(|s| s.domain.as_str())
    }

    /// Whether `addr` belongs to the fake range at all (mapped or not).
    #[must_use]
    pub fn is_fake_address(&self, addr: IpAddr) -> bool {
        self.config.contains(addr)
    }

    /// Drop `domain`'s binding, returning its index to the pool. True when a
    /// binding was actually removed.
    pub fn release(&mut self, domain: &str) -> bool {
        let key = normalize_hostname(domain);
        match self.by_domain.remove(&key) {
            Some(index) => {
                self.by_index.remove(&index);
                self.freed.push(index);
                if let Some(sink) = &self.sink {
                    sink(&BindingChange::Released { index });
                }
                true
            }
            None => false,
        }
    }

    /// Drop every binding (policy reload, feature turned off, service stop).
    pub fn clear(&mut self) {
        self.by_domain.clear();
        self.by_index.clear();
        self.freed.clear();
        self.cursor = FAKE_IP_FIRST_HOST_INDEX;
    }

    fn binding_at(&self, index: u32) -> FakeIpBinding {
        FakeIpBinding {
            index,
            v4: self.config.v4_at(index),
            v6: self.config.v6_at(index),
        }
    }

    /// The highest index a hostname may hold (everything past it is reserved).
    fn last_host_index(&self) -> u32 {
        self.config
            .v4_address_count()
            .saturating_sub(2)
            .max(FAKE_IP_FIRST_HOST_INDEX)
    }

    /// A free index: a released one, then a never-used one, then the
    /// least-recently-used binding recycled.
    fn take_index(&mut self) -> Result<u32, FakeIpError> {
        if let Some(index) = self.freed.pop() {
            return Ok(index);
        }
        let last_host_index = self.last_host_index();
        if self.cursor <= last_host_index && self.config.capacity() > 0 {
            let index = self.cursor;
            self.cursor = self.cursor.saturating_add(1);
            return Ok(index);
        }
        let victim = self
            .by_index
            .iter()
            .min_by_key(|(index, slot)| (slot.last_used, **index))
            .map(|(index, slot)| (*index, slot.domain.clone()));
        match victim {
            Some((index, domain)) => {
                self.by_domain.remove(&domain);
                self.by_index.remove(&index);
                Ok(index)
            }
            None => Err(FakeIpError::PoolExhausted),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test address literal")
    }

    /// Deliberately tiny v4-only pool, so the recycling path is reachable in a
    /// test without allocating 131 069 hostnames.
    fn tiny_pool(prefix_len: u8) -> FakeIpAllocator {
        FakeIpAllocator::new(FakeIpPoolConfig {
            v4_base: Ipv4Addr::new(198, 18, 0, 0),
            v4_prefix_len: prefix_len,
            v6_base: None,
            v6_prefix_len: 0,
        })
    }

    #[test]
    fn restore_reseats_bindings_and_resumes_allocation_past_them() {
        let mut alloc = tiny_pool(28); // 16 addresses, indices 2..=14 usable
        alloc.restore(vec![
            ("old.example".to_string(), 2),
            ("newer.example".to_string(), 5),
            // Invalid entries are skipped, not fatal.
            ("reserved.example".to_string(), 1),
            ("out-of-range.example".to_string(), 15),
            ("dup-index.example".to_string(), 5),
            ("old.example".to_string(), 9),
        ]);
        assert_eq!(alloc.len(), 2);
        assert_eq!(
            alloc.binding_for_domain("old.example").map(|b| b.index),
            Some(2)
        );
        assert_eq!(
            alloc.binding_for_domain("newer.example").map(|b| b.index),
            Some(5)
        );
        // Gaps below the restored maximum are reused before fresh indices.
        let filled: Vec<u32> = (0..3)
            .map(|_| {
                alloc
                    .allocate(&format!("gap{}.example", alloc.len()))
                    .expect("allocate")
                    .index
            })
            .collect();
        for index in &filled {
            assert!((3..=4).contains(index) || *index >= 6, "unexpected {index}");
        }
    }

    #[test]
    fn change_sink_sees_bound_and_released_but_not_idempotent_reallocation() {
        use std::sync::Mutex as StdMutex;
        let events: Arc<StdMutex<Vec<BindingChange>>> = Arc::new(StdMutex::new(Vec::new()));
        let mut alloc = tiny_pool(28);
        alloc.set_change_sink({
            let events = Arc::clone(&events);
            Arc::new(move |change| {
                events.lock().expect("events").push(change.clone());
            })
        });
        let b = alloc.allocate("a.example").expect("allocate");
        let again = alloc.allocate("a.example").expect("re-allocate");
        assert_eq!(b, again);
        assert!(alloc.release("a.example"));
        let seen = events.lock().expect("events").clone();
        assert_eq!(
            seen,
            vec![
                BindingChange::Bound {
                    domain: "a.example".to_string(),
                    index: b.index
                },
                BindingChange::Released { index: b.index }
            ]
        );
    }

    #[test]
    fn pool_stamp_tracks_geometry() {
        assert_eq!(
            FakeIpPoolConfig::default().stamp(),
            "v4=198.18.0.0/15;v6=fc00::/18"
        );
        assert_eq!(FakeIpPoolConfig::v4_only().stamp(), "v4=198.18.0.0/15");
    }

    #[test]
    fn defaults_are_the_reserved_ranges() {
        let cfg = FakeIpPoolConfig::default();
        assert_eq!(cfg.v4_base, Ipv4Addr::new(198, 18, 0, 0));
        assert_eq!(cfg.v4_prefix_len, 15);
        assert_eq!(cfg.v6_base, Some(FAKE_IP_V6_BASE));
        assert_eq!(cfg.gateway_v4(), Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(cfg.v4_address_count(), 131_072);
        assert_eq!(cfg.capacity(), 131_069);
    }

    #[test]
    fn default_pool_does_not_collide_with_rfc1918_networks() {
        // The whole point of 198.18/15: it dodges the ranges real hosts use.
        let cfg = FakeIpPoolConfig::default();
        let home = [
            LocalSubnet::new(ip("10.0.0.0"), 8),
            LocalSubnet::new(ip("172.16.0.0"), 12),
            LocalSubnet::new(ip("192.168.1.0"), 24),
            LocalSubnet::new(ip("fe80::"), 10),
        ];
        assert!(cfg.collisions(&home).is_empty());
        assert!(!cfg.overlaps_any(&home));
    }

    #[test]
    fn default_pool_membership_helper_matches_the_default_ranges() {
        let (first, last) = FakeIpPoolConfig::default().v4_range();
        assert_eq!(first, Ipv4Addr::new(198, 18, 0, 0));
        assert_eq!(last, Ipv4Addr::new(198, 19, 255, 255));
        assert!(FakeIpPoolConfig::is_default_pool_addr(ip("198.18.0.35")));
        assert!(FakeIpPoolConfig::is_default_pool_addr(ip("198.19.255.254")));
        assert!(FakeIpPoolConfig::is_default_pool_addr(ip("fc00::2a")));
        assert!(!FakeIpPoolConfig::is_default_pool_addr(ip("198.20.0.1")));
        assert!(!FakeIpPoolConfig::is_default_pool_addr(ip(
            "198.17.255.255"
        )));
        assert!(!FakeIpPoolConfig::is_default_pool_addr(ip("8.8.8.8")));
    }

    #[test]
    fn a_local_subnet_inside_the_pool_is_flagged() {
        let cfg = FakeIpPoolConfig::default();
        // A corporate network that unusually uses part of 198.18/15.
        let clash = [LocalSubnet::new(ip("198.18.5.0"), 24)];
        let hits = cfg.collisions(&clash);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].family, "ipv4");
        assert_eq!(hits[0].local.network, ip("198.18.5.0"));
    }

    #[test]
    fn a_wider_local_subnet_containing_the_pool_is_flagged() {
        let cfg = FakeIpPoolConfig::default();
        // A /8 that swallows the whole pool overlaps just as much as a subset.
        let clash = [LocalSubnet::new(ip("198.0.0.0"), 8)];
        assert!(cfg.overlaps_any(&clash));
    }

    #[test]
    fn a_v6_subnet_inside_the_ula_pool_is_flagged() {
        let cfg = FakeIpPoolConfig::default();
        let clash = [LocalSubnet::new(ip("fc00::abcd"), 64)];
        let hits = cfg.collisions(&clash);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].family, "ipv6");
    }

    #[test]
    fn v6_subnet_ignored_when_the_pool_has_no_v6_range() {
        let cfg = FakeIpPoolConfig::v4_only();
        let v6 = [LocalSubnet::new(ip("fc00::1"), 64)];
        assert!(!cfg.overlaps_any(&v6));
    }

    #[test]
    fn allocation_is_stable_and_idempotent() {
        let mut alloc = FakeIpAllocator::default();
        let first = alloc.allocate("ChatGPT.com.").expect("allocate");
        let again = alloc.allocate("chatgpt.com").expect("allocate");
        assert_eq!(first, again, "normalized hostname keeps its address");
        assert_eq!(alloc.len(), 1);
        // First hostname gets the first host index, never the adapter address.
        assert_eq!(first.index, FAKE_IP_FIRST_HOST_INDEX);
        assert_eq!(first.v4, Ipv4Addr::new(198, 18, 0, 2));
    }

    #[test]
    fn distinct_hostnames_get_distinct_addresses() {
        let mut alloc = FakeIpAllocator::default();
        let a = alloc.allocate("chatgpt.com").expect("allocate");
        let b = alloc.allocate("www.google.com").expect("allocate");
        assert_ne!(a.v4, b.v4, "no collateral: one address per hostname");
        assert_ne!(a.v6, b.v6);
    }

    #[test]
    fn v4_and_v6_of_one_binding_resolve_to_the_same_hostname() {
        let mut alloc = FakeIpAllocator::default();
        let b = alloc.allocate("example.com").expect("allocate");
        let v6 = b.v6.expect("v6 enabled by default");
        assert_eq!(
            alloc.domain_for_ip(IpAddr::V4(b.v4)).as_deref(),
            Some("example.com")
        );
        assert_eq!(
            alloc.domain_for_ip(IpAddr::V6(v6)).as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn empty_hostname_is_rejected() {
        let mut alloc = FakeIpAllocator::default();
        assert_eq!(alloc.allocate("   "), Err(FakeIpError::EmptyDomain));
        assert_eq!(alloc.allocate("."), Err(FakeIpError::EmptyDomain));
    }

    #[test]
    fn addresses_outside_the_pool_are_not_fake() {
        let mut alloc = FakeIpAllocator::default();
        assert!(alloc.is_fake_address(ip("198.19.255.254")));
        assert!(!alloc.is_fake_address(ip("142.250.74.78")));
        assert!(!alloc.is_fake_address(ip("198.20.0.1")));
        assert_eq!(alloc.domain_for_ip(ip("142.250.74.78")), None);
    }

    #[test]
    fn unmapped_address_inside_the_pool_resolves_to_nothing() {
        let mut alloc = FakeIpAllocator::default();
        assert!(alloc.is_fake_address(ip("198.18.7.7")));
        assert_eq!(alloc.domain_for_ip(ip("198.18.7.7")), None);
    }

    #[test]
    fn released_index_is_reused_before_a_fresh_one() {
        let mut alloc = FakeIpAllocator::default();
        let a = alloc.allocate("a.example").expect("allocate");
        assert!(alloc.release("A.Example."), "release normalizes too");
        assert!(!alloc.release("a.example"), "second release is a no-op");
        let b = alloc.allocate("b.example").expect("allocate");
        assert_eq!(b.index, a.index, "freed index recycled first");
        assert_eq!(alloc.binding_for_domain("a.example"), None);
    }

    #[test]
    fn full_pool_recycles_the_least_recently_used_hostname() {
        // /29 → 8 addresses: 0 network, 1 adapter, 7 broadcast → indices 2..=6.
        let mut alloc = tiny_pool(29);
        assert_eq!(alloc.capacity(), 5);
        let mut bindings = Vec::new();
        for i in 0..5 {
            bindings.push(alloc.allocate(&format!("h{i}.example")).expect("allocate"));
        }
        assert_eq!(alloc.len(), 5, "pool is full");
        // Touch the oldest so it is no longer the recycling victim.
        let _ = alloc.domain_for_ip(IpAddr::V4(bindings[0].v4));
        let fresh = alloc.allocate("new.example").expect("allocate recycles");
        assert_eq!(alloc.len(), 5, "recycling keeps the pool at capacity");
        assert_eq!(
            fresh.index, bindings[1].index,
            "the least-recently-used binding is the one recycled"
        );
        assert_eq!(alloc.binding_for_domain("h1.example"), None);
        assert!(alloc.binding_for_domain("h0.example").is_some());
    }

    #[test]
    fn clear_returns_the_whole_pool() {
        let mut alloc = FakeIpAllocator::default();
        let first = alloc.allocate("a.example").expect("allocate");
        alloc.allocate("b.example").expect("allocate");
        alloc.clear();
        assert!(alloc.is_empty());
        let after = alloc.allocate("c.example").expect("allocate");
        assert_eq!(after.index, first.index);
    }
}
