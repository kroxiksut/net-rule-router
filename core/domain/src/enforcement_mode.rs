//! Enforcement mode.
//!
//! How NetRuleRouter learns the `hostname → IP` facts that drive domain-rule
//! enforcement (the `/32` routes + WFP filters). Two user-selectable modes:
//!
//! - **Resolver** (default): a local DNS resolver answers rule-host queries
//!   itself — it resolves upstream, installs enforcement SYNCHRONOUSLY, then
//!   returns the answer, so the first packet the app sends already has a
//!   matching route/filter. It redirects system DNS, which is invasive, but it
//!   is the mode the product is built around.
//! - **Reactive**: learn IPs PASSIVELY — the ETW DNS observer + the
//!   rule-hostname seeder write resolved addresses into the FQDN cache and the
//!   codegen fans them out. Correct only for addresses already seen, so a
//!   freshly-rotated IP has a brief unprotected window (inherent for
//!   `ping` / first-contact — see `DNS_RESOLVER_DESIGN.md` §1). Kept behind an
//!   explicit opt-in: shipping it as the default meant every fresh install (and
//!   every wiped state DB) silently ran the weaker mode.
//!
//! Neutral policy type — no OS specifics. The RESOLVER *mechanism* (a DNS
//! listener + pointing the OS at it) lives behind a per-OS `SystemDnsRedirectPort`
//! trait, keeping policy and mechanism separate. This enum only records WHICH
//! mode the user chose.

use std::fmt;

/// User-selectable enforcement mode. See module docs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EnforcementMode {
    /// Passive learning (ETW observer + seeder). Correct-once-seen with an
    /// inherent first-contact window; reachable only through the explicit
    /// opt-in in Settings.
    Reactive,
    /// Local DNS resolver drives synchronous, enforce-before-answer install.
    /// The default: it is the mode the enforcement story is built on, and a
    /// fresh install must not start in the weaker one. Requires the platform to
    /// support system-DNS redirect.
    #[default]
    Resolver,
}

impl EnforcementMode {
    /// Wire/locale slug (kebab-case, stable). Used by the IPC DTO and GUI combo.
    pub const fn as_slug(self) -> &'static str {
        match self {
            Self::Reactive => "reactive",
            Self::Resolver => "resolver",
        }
    }

    /// Parse a wire slug. Unknown → `None` (caller falls back to the default).
    pub fn from_slug(slug: &str) -> Option<Self> {
        match slug {
            "reactive" => Some(Self::Reactive),
            "resolver" => Some(Self::Resolver),
            _ => None,
        }
    }

    /// Stable small-int for compact SQLite storage. APPEND-ONLY: a new variant
    /// gets the next code, existing codes never change. Kept in sync with
    /// [`EnforcementMode::from_code`].
    pub const fn as_code(self) -> i64 {
        match self {
            Self::Reactive => 0,
            Self::Resolver => 1,
        }
    }

    /// Inverse of [`EnforcementMode::as_code`]. Unknown → `None`.
    pub fn from_code(code: i64) -> Option<Self> {
        match code {
            0 => Some(Self::Reactive),
            1 => Some(Self::Resolver),
            _ => None,
        }
    }
}

impl fmt::Display for EnforcementMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_slug())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_and_code_round_trip() {
        for m in [EnforcementMode::Reactive, EnforcementMode::Resolver] {
            assert_eq!(EnforcementMode::from_slug(m.as_slug()), Some(m));
            assert_eq!(EnforcementMode::from_code(m.as_code()), Some(m));
        }
        assert_eq!(EnforcementMode::from_slug("nope"), None);
        assert_eq!(EnforcementMode::from_code(99), None);
    }

    #[test]
    fn default_is_resolver() {
        // Resolver redirects system DNS, which IS invasive — and it is still
        // the default, because reactive mode leaves a first-contact window and
        // shipping it by default meant every fresh install (and every wiped
        // state DB) quietly ran the weaker enforcement. Reactive is reachable
        // only through the explicit opt-in in Settings.
        assert_eq!(EnforcementMode::default(), EnforcementMode::Resolver);
    }
}
