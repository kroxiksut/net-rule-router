//! Auto-rules mode — what happens to the companion domains discovered for a
//! routed site.
//!
//! A site routed over the additional link often pulls images, video and API
//! calls from CDN hosts the user's rules do not mention, so the page loads but
//! its media does not. The service can learn those companion domains; this
//! per-SID setting decides what it may then do with the finding.
//!
//! Deliberately three slugs and not a bool: v1 ships with application disabled
//! ([`AutoRulesMode::Suggest`]) until the discovery mechanism is verified in the
//! field, and flipping the default later must not need a schema change.
//!
//! Persisted per-SID on `secondary_block_policy` as the slug itself (TEXT +
//! CHECK) rather than an integer code — unlike [`crate::doh_lockdown`], whose
//! integer codes predate this convention — so the DB, the wire and the GUI all
//! speak one vocabulary.

/// What the service may do with a discovered companion domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AutoRulesMode {
    /// Do not collect and do not suggest — the discovery pass is off entirely.
    Off,
    /// Collect findings and offer them to the user (tray prompt). NOTHING is
    /// applied without an explicit confirmation. The v1 default.
    #[default]
    Suggest,
    /// Apply findings automatically and record them in the user's own rules.
    Auto,
}

impl AutoRulesMode {
    /// The wire/DB/GUI slug. One vocabulary for all three — the stored column
    /// value, the `auto-rules-mode` field of `RoutePolicyDto` /
    /// `RoutePolicyUpdateRequest`, and the QML combo-box value in
    /// `sections/settings/RoutingSettings.qml`.
    pub fn as_slug(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Suggest => "suggest",
            Self::Auto => "auto",
        }
    }

    /// Parse a slug. `None` on unknown → callers default (never silently widen
    /// what the service is allowed to apply on the user's behalf).
    pub fn from_slug(s: &str) -> Option<Self> {
        match s {
            "off" => Some(Self::Off),
            "suggest" => Some(Self::Suggest),
            "auto" => Some(Self::Auto),
            _ => None,
        }
    }

    /// Every slug, for wire/GUI validation allow-lists. Order matches the GUI
    /// dropdown (least to most autonomous).
    pub const ALL_SLUGS: &'static [&'static str] = &["off", "suggest", "auto"];
}

/// Default of `auto_rules_eager_delivery_names` — OFF.
///
/// The discovery engine normally waits for evidence before it names a
/// delivery-shaped host (a CDN endpoint) as a companion: it wants the anchor to
/// dominate that host's traffic across at least two visits. This flag drops that
/// wait, so such a host is offered on its first co-occurrence.
///
/// Off by default because the wait is what keeps an unrelated CDN — one that
/// happens to serve the routed site *and* half the internet — out of the user's
/// rule set. Users who prefer to see the suggestion immediately and judge it
/// themselves turn it on knowingly; the GUI states the trade-off next to the
/// checkbox.
///
/// Scope is deliberately narrow: only the delivery-name tier loses its gates.
/// Brand relation is offered from the first window regardless, and the plain
/// co-activity tier keeps its thresholds either way.
pub const AUTO_RULES_EAGER_DELIVERY_NAMES_DEFAULT: bool = false;

#[cfg(test)]
mod tests {
    use super::*;

    /// The slugs are a cross-process contract: the `auto_rules_mode` CHECK
    /// constraint in `STATE_DB_V42_DDL`, the `auto-rules-mode` wire field, and
    /// the QML combo-box in `sections/settings/RoutingSettings.qml` all repeat
    /// these three literals. Pin them here so a rename has to be deliberate.
    #[test]
    fn slugs_are_pinned() {
        assert_eq!(AutoRulesMode::Off.as_slug(), "off");
        assert_eq!(AutoRulesMode::Suggest.as_slug(), "suggest");
        assert_eq!(AutoRulesMode::Auto.as_slug(), "auto");
        assert_eq!(AutoRulesMode::ALL_SLUGS, &["off", "suggest", "auto"]);
    }

    /// v1 ships with application disabled: the owner verifies the discovery
    /// mechanism before anything lands in a user's rules unattended.
    #[test]
    fn default_is_suggest_only() {
        assert_eq!(AutoRulesMode::default(), AutoRulesMode::Suggest);
    }

    /// The eager delivery-name suggestion is an informed opt-in, never the
    /// state a user finds themselves in without asking.
    const _: () = assert!(!AUTO_RULES_EAGER_DELIVERY_NAMES_DEFAULT);

    #[test]
    fn slug_round_trip_and_unknown_is_none() {
        for slug in AutoRulesMode::ALL_SLUGS {
            let parsed = AutoRulesMode::from_slug(slug).expect("known slug");
            assert_eq!(parsed.as_slug(), *slug);
        }
        assert_eq!(AutoRulesMode::from_slug("apply"), None);
        assert_eq!(AutoRulesMode::from_slug(""), None);
    }
}
