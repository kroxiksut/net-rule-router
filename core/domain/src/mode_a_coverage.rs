//! Mode-A coverage strategy.
//!
//! In the reactive enforcement mode (Mode A / `PreferPrimary`) NetRuleRouter
//! pins only the *seeded* destination IPs of a secondary (VPN) rule to the
//! secondary link. A routed domain behind a rotating CDN can resolve to a fresh
//! edge IP that is not yet seeded, so its packet takes the default route =
//! primary and can leak. This enum lets the user pick how an un-seeded IP of a
//! routed domain is handled — a per-SID leak-protection posture, not a
//! per-packet decision.
//!
//! Pure and deterministic: the variant only *selects* a codegen path; the actual
//! filter emission lives in `service-runtime::killswitch_codegen`.

use std::fmt;

/// How Mode A (`PreferPrimary`) treats a routed domain that resolves to an IP
/// NOT in the seeded secondary-destination set. Ordered default→strict is *not*
/// the discriminant order; see [`ModeACoverageStrategy::as_code`] for the stable
/// storage mapping.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ModeACoverageStrategy {
    /// Default: pin only the seeded destination IPs. Fast and precise, and crucially it
    /// does NOT install a catch-all block, so traffic that matches no secondary
    /// rule (default/primary-destined hosts, zone→primary sites) keeps flowing
    /// over the primary link instead of being blocked. The cost is a short
    /// un-protected window when a routed (secondary) domain rotates to a
    /// fresh, not-yet-seeded edge IP — that window is documented as a known
    /// pre-alpha limitation. Zero over-blocking.
    #[default]
    PerIp,
    /// Strict, explicit opt-in: fail-closed on
    /// an unknown IP — while leak protection is armed, escalate the Mode-A
    /// fail-closed block to a catch-all so a routed domain's un-seeded IP is
    /// BLOCKED rather than sent over the primary. Closes the rotating-IP leak
    /// entirely, but it ALSO blocks general/unmatched browsing (e.g. a host with
    /// no rule) while armed — a paranoid posture the user turns on deliberately.
    FailClosedUnknown,
    /// Widen coverage to the whole zone/suffix — route every edge IP of a routed
    /// domain to the secondary via its suffix/zone instead of individual /32s.
    /// Fewer false blocks than fail-closed, but heavier and can over-capture
    /// co-tenants. NOTE: the zone-level codegen is not yet implemented; until it
    /// is, the orchestrator treats this as [`ModeACoverageStrategy::PerIp`] and
    /// logs that the strategy is not yet enforced.
    ZoneWidening,
}

impl ModeACoverageStrategy {
    /// Wire/locale slug (kebab-case, stable). Used by the IPC DTO and GUI combo.
    pub const fn as_slug(self) -> &'static str {
        match self {
            Self::PerIp => "per-ip",
            Self::FailClosedUnknown => "fail-closed-unknown",
            Self::ZoneWidening => "zone-widening",
        }
    }

    /// Parse a wire slug. Unknown → `None` (caller falls back to the default).
    pub fn from_slug(slug: &str) -> Option<Self> {
        match slug {
            "per-ip" => Some(Self::PerIp),
            "fail-closed-unknown" => Some(Self::FailClosedUnknown),
            "zone-widening" => Some(Self::ZoneWidening),
            _ => None,
        }
    }

    /// Stable small-int for compact SQLite storage. APPEND-ONLY: a new variant
    /// gets the next code, existing codes never change (keeps stored rows valid
    /// across releases). Kept in sync with [`ModeACoverageStrategy::from_code`].
    pub const fn as_code(self) -> i64 {
        match self {
            Self::PerIp => 0,
            Self::FailClosedUnknown => 1,
            Self::ZoneWidening => 2,
        }
    }

    /// Inverse of [`ModeACoverageStrategy::as_code`]. Unknown → `None`.
    pub fn from_code(code: i64) -> Option<Self> {
        match code {
            0 => Some(Self::PerIp),
            1 => Some(Self::FailClosedUnknown),
            2 => Some(Self::ZoneWidening),
            _ => None,
        }
    }
}

impl fmt::Display for ModeACoverageStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_slug())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_and_code_round_trip() {
        for p in [
            ModeACoverageStrategy::PerIp,
            ModeACoverageStrategy::FailClosedUnknown,
            ModeACoverageStrategy::ZoneWidening,
        ] {
            assert_eq!(ModeACoverageStrategy::from_slug(p.as_slug()), Some(p));
            assert_eq!(ModeACoverageStrategy::from_code(p.as_code()), Some(p));
        }
        assert_eq!(ModeACoverageStrategy::from_slug("nope"), None);
        assert_eq!(ModeACoverageStrategy::from_code(99), None);
    }

    #[test]
    fn default_is_per_ip() {
        // The product default is PerIp — it installs
        // no catch-all, so default/primary-destined and zone→primary traffic is
        // not blocked. FailClosedUnknown is an explicit paranoid opt-in.
        assert_eq!(
            ModeACoverageStrategy::default(),
            ModeACoverageStrategy::PerIp
        );
    }
}
