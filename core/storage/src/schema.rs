//! SQLite schema definitions for the two storage databases.
//!
//! # Entity-Relationship Diagram — `nrr_fqdn_ip_cache.db`
//!
//! ```text
//!  ┌─────────────────────┐       ┌──────────────────────┐
//!  │      hostnames      │       │     ip_addresses      │
//!  │─────────────────────│       │──────────────────────│
//!  │ id PK               │       │ id PK                │
//!  │ canonical_host UNIQ │       │ address_family       │
//!  │ raw_sample          │       │ canonical_ip         │ ← UNIQUE(af, ip)
//!  │ first_seen_at       │       │ ipv4_packed          │
//!  │ last_seen_at        │       │ first_seen_at        │
//!  │ flags               │       │ last_seen_at         │
//!  └────────┬────────────┘       └─────────┬────────────┘
//!           │                              │
//!           │  hostname_ip_resolutions     │
//!           │  ┌───────────────────────── ┐│
//!           └──│ hostname_id FK           ├┘
//!              │ ip_id FK                 │
//!              │ source (TEXT)            │ ← UNIQUE(hostname_id, ip_id, source)
//!              │ ttl_seconds              │
//!              │ resolved_at              │
//!              │ expires_at               │
//!              │ freshness_state (TEXT)   │
//!              │ confidence               │
//!              │ active_revision_id       │
//!              │ diagnostic_flags (INT)   │
//!              └──────────────────────────┘
//!
//!  ┌───────────────────────────────────────────────────────────────┐
//!  │ negative_cache  │ lookup_events  │ cache_metadata (singleton) │
//!  └───────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Schema — `nrr_service_state.db`
//!
//! ```text
//!  active_revision   last_known_good   integrity_log
//! ```
//!
//! # Timestamp convention
//!
//! All persisted timestamps use the `_at` suffix and store **UTC Unix
//! milliseconds as `INTEGER` (`i64`)**.  Duration/TTL fields use the
//! `_seconds` suffix and store plain `INTEGER`.  Monotonic time is runtime-only
//! and must never be written to SQLite.
//!
//! # `FreshnessStateDb` TEXT values
//!
//! | Rust variant     | SQLite TEXT value   |
//! |------------------|---------------------|
//! | `Fresh`          | `"fresh"`           |
//! | `StaleUsable`    | `"stale_usable"`    |
//! | `StaleNotUsable` | `"stale_not_usable"`|
//! | `Conflicting`    | `"conflicting"`     |
//! | `NegativeCached` | `"negative_cached"` |
//!
//! (`Missing` is a runtime-only state; it is not persisted — a missing row
//! implies `Missing`.)

use bitflags::bitflags;
use nrr_domain::decision_lookup::CacheEntryState;

// ── DiagnosticFlags ───────────────────────────────────────────────────────────

bitflags! {
    /// Bitfield stored in `hostname_ip_resolutions.diagnostic_flags` and in
    /// the host-level `flags` columns of `hostnames` / `ip_addresses`.
    ///
    /// Persisted as `INTEGER` in SQLite via `bits() as i64` / `from_bits_truncate`.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub struct DiagnosticFlags: u32 {
        /// Multiple IPs map to this hostname and they lead to different
        /// rule matches — the router had to pick one.
        const AMBIGUOUS            = 0b0000_0001;
        /// Observed IP is not present in the cached hostname IP set.
        const CONFLICTING          = 0b0000_0010;
        /// Entry is past its TTL (either stale_usable or stale_not_usable).
        const STALE                = 0b0000_0100;
        /// This entry was written as a negative-cache result.
        const NEGATIVE_CACHED      = 0b0000_1000;
        /// The lookup that produced this entry failed or timed out.
        const LOOKUP_FAILED        = 0b0001_0000;
        /// Reserved bit: nothing sets it since IPv6 became a rule family. Kept
        /// so stored flag values keep their meaning.
        const UNSUPPORTED_ADDR_FAM = 0b0010_0000;
    }
}

impl DiagnosticFlags {
    /// Converts to the `INTEGER` value stored in SQLite.
    pub fn to_db(self) -> i64 {
        self.bits() as i64
    }

    /// Reconstructs from an `INTEGER` value read from SQLite.
    /// Unknown bits are silently discarded (`from_bits_truncate`).
    pub fn from_db(raw: i64) -> Self {
        Self::from_bits_truncate(raw as u32)
    }
}

// ── FreshnessStateDb ──────────────────────────────────────────────────────────

/// TEXT representation of freshness state as stored in SQLite.
///
/// This type handles serialization between the SQLite column and the domain
/// type [`CacheEntryState`].  `Missing` is runtime-only and has no TEXT form —
/// a missing row in the database implies `Missing`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FreshnessStateDb {
    Fresh,
    StaleUsable,
    StaleNotUsable,
    Conflicting,
    NegativeCached,
}

impl FreshnessStateDb {
    /// TEXT value written to / read from the `freshness_state` column.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::StaleUsable => "stale_usable",
            Self::StaleNotUsable => "stale_not_usable",
            Self::Conflicting => "conflicting",
            Self::NegativeCached => "negative_cached",
        }
    }

    /// Parses the TEXT value read from SQLite.  Returns `None` for unknown
    /// values (e.g. written by a future schema version).
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "fresh" => Some(Self::Fresh),
            "stale_usable" => Some(Self::StaleUsable),
            "stale_not_usable" => Some(Self::StaleNotUsable),
            "conflicting" => Some(Self::Conflicting),
            "negative_cached" => Some(Self::NegativeCached),
            _ => None,
        }
    }

    /// Converts to the domain-level [`CacheEntryState`] used by the rule engine.
    pub fn to_domain(self) -> CacheEntryState {
        match self {
            Self::Fresh => CacheEntryState::Fresh,
            Self::StaleUsable => CacheEntryState::StaleUsable,
            Self::StaleNotUsable => CacheEntryState::StaleNotUsable,
            Self::Conflicting => CacheEntryState::Conflicting,
            Self::NegativeCached => CacheEntryState::NegativeCached,
        }
    }

    /// Converts from a domain [`CacheEntryState`] to the DB representation.
    ///
    /// Returns `None` for `CacheEntryState::Missing` because `Missing` is a
    /// runtime state (no row present) and must not be persisted.
    pub fn from_domain(state: &CacheEntryState) -> Option<Self> {
        match state {
            CacheEntryState::Fresh => Some(Self::Fresh),
            CacheEntryState::StaleUsable => Some(Self::StaleUsable),
            CacheEntryState::StaleNotUsable => Some(Self::StaleNotUsable),
            CacheEntryState::Conflicting => Some(Self::Conflicting),
            CacheEntryState::NegativeCached => Some(Self::NegativeCached),
            CacheEntryState::Missing => None,
        }
    }
}

// ── AddressFamily ─────────────────────────────────────────────────────────────

pub use nrr_domain::address_class::AddressFamily;

// ── LookupDirection TEXT ──────────────────────────────────────────────────────

/// Returns the TEXT value used in `lookup_events.direction` for a given
/// [`LookupDirection`][nrr_domain::decision_lookup::LookupDirection].
///
/// Free functions rather than trait impls because `LookupDirection` is defined
/// in `nrr-domain` and we cannot add methods to it here.
pub fn lookup_direction_as_str(dir: &nrr_domain::decision_lookup::LookupDirection) -> &'static str {
    use nrr_domain::decision_lookup::LookupDirection;
    match dir {
        LookupDirection::HostnameToIp => "hostname_to_ip",
        LookupDirection::IpToHostname => "ip_to_hostname",
        LookupDirection::Both => "both",
    }
}

pub fn lookup_direction_from_str(s: &str) -> Option<nrr_domain::decision_lookup::LookupDirection> {
    use nrr_domain::decision_lookup::LookupDirection;
    match s {
        "hostname_to_ip" => Some(LookupDirection::HostnameToIp),
        "ip_to_hostname" => Some(LookupDirection::IpToHostname),
        "both" => Some(LookupDirection::Both),
        _ => None,
    }
}

mod cache_ddl;
pub use cache_ddl::*;
mod traffic_ddl;
pub use traffic_ddl::*;
mod state_ddl;
pub use state_ddl::*;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
