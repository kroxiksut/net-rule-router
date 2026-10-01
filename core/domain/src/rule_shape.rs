//! Which rule shapes enforcement can carry out as written.
//!
//! The rule model is wider than enforcement: a rule may name a destination, an
//! application, or both, and the engine matches both as AND. A shape the
//! machine cannot enforce must be refused when submitted and skipped when
//! compiled — enforcing only the destination half would apply the rule to
//! every application, which is not what the user wrote.
//!
//! The decision is neutral. What enforcement can do arrives as
//! [`RuleShapeSupport`], which the service builds from its own emitters and the
//! platform's declared capabilities.

use core::fmt;

use crate::canonical::{CanonicalRule, CanonicalRuleBook, RuleAction};

/// What a rule's conditions constrain.
///
/// Exhaustive on purpose: a destination qualifier (ports, protocols, a CIDR)
/// arrives as a new variant, and [`shape_verdict`] then refuses to compile
/// until its support is decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RuleShape {
    /// A destination only: every application's traffic to it.
    Destination,
    /// An application only: every connection it opens.
    Source,
    /// One application's traffic to one destination.
    SourceAndDestination,
}

impl RuleShape {
    /// Every shape, for exhaustive tables and tests.
    pub const ALL: [Self; 3] = [Self::Destination, Self::Source, Self::SourceAndDestination];

    /// The shape of `rule`; `None` for a rule with no condition, which
    /// validation refuses on its own.
    #[must_use]
    pub fn of(rule: &CanonicalRule) -> Option<Self> {
        match (rule.address_match.is_some(), rule.app_match.is_some()) {
            (true, false) => Some(Self::Destination),
            (false, true) => Some(Self::Source),
            (true, true) => Some(Self::SourceAndDestination),
            (false, false) => None,
        }
    }
}

/// The app-scoped shapes enforcement implements on this machine.
///
/// Destination-only and application-only rules are the baseline every
/// platform enforces, so they carry no flag.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuleShapeSupport {
    /// Block one application's traffic to a destination, leaving other
    /// applications' traffic to it alone.
    pub app_scoped_destination_block: bool,
    /// Route one application's traffic to a destination over a link, leaving
    /// other applications' traffic to it on its own route.
    pub app_scoped_destination_route: bool,
}

impl RuleShapeSupport {
    /// No app-scoped destination shapes.
    pub const NONE: Self = Self {
        app_scoped_destination_block: false,
        app_scoped_destination_route: false,
    };
}

/// Why a shape cannot be enforced. The slug is stable: it reaches logs, error
/// messages and the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UnsupportedShapeReason {
    /// An application + destination Block.
    AppScopedDestinationBlock,
    /// An application + destination route.
    AppScopedDestinationRoute,
}

impl UnsupportedShapeReason {
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::AppScopedDestinationBlock => "app-scoped-destination-block",
            Self::AppScopedDestinationRoute => "app-scoped-destination-route",
        }
    }
}

impl fmt::Display for UnsupportedShapeReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

/// Whether a shape can be enforced as written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShapeVerdict {
    Supported,
    Unsupported { reason: UnsupportedShapeReason },
}

impl ShapeVerdict {
    #[must_use]
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::Supported)
    }
}

/// The table: can `shape` with `action` be enforced, given `support`.
#[must_use]
pub const fn shape_verdict(
    shape: RuleShape,
    action: RuleAction,
    support: RuleShapeSupport,
) -> ShapeVerdict {
    match (shape, action) {
        (RuleShape::Destination | RuleShape::Source, _) => ShapeVerdict::Supported,
        (RuleShape::SourceAndDestination, RuleAction::Block) => {
            if support.app_scoped_destination_block {
                ShapeVerdict::Supported
            } else {
                ShapeVerdict::Unsupported {
                    reason: UnsupportedShapeReason::AppScopedDestinationBlock,
                }
            }
        }
        (RuleShape::SourceAndDestination, RuleAction::Route) => {
            if support.app_scoped_destination_route {
                ShapeVerdict::Supported
            } else {
                ShapeVerdict::Unsupported {
                    reason: UnsupportedShapeReason::AppScopedDestinationRoute,
                }
            }
        }
    }
}

/// [`shape_verdict`] for one rule. A rule with no condition is not a shape
/// question and answers `Supported`.
#[must_use]
pub fn rule_verdict(rule: &CanonicalRule, support: RuleShapeSupport) -> ShapeVerdict {
    RuleShape::of(rule).map_or(ShapeVerdict::Supported, |shape| {
        shape_verdict(shape, rule.action, support)
    })
}

/// The first rule in `book` (primary, then secondary, canonical order) whose
/// shape cannot be enforced. Disabled rules count: enabling one later must not
/// be the moment it becomes unenforceable.
#[must_use]
pub fn first_unsupported(
    book: &CanonicalRuleBook,
    support: RuleShapeSupport,
) -> Option<(&CanonicalRule, UnsupportedShapeReason)> {
    first_unsupported_new(book, None, support)
}

/// [`first_unsupported`] over the rules `book` adds or changes relative to
/// `carried` (the book in force). A rule carried over unchanged is already
/// skipped by enforcement and listed as a conflict; refusing the whole book
/// over it would freeze every edit, and support differs per OS, so a book
/// from another platform or a backup would hit exactly that.
#[must_use]
pub fn first_unsupported_new<'a>(
    book: &'a CanonicalRuleBook,
    carried: Option<&CanonicalRuleBook>,
    support: RuleShapeSupport,
) -> Option<(&'a CanonicalRule, UnsupportedShapeReason)> {
    let (carried_primary, carried_secondary): (&[CanonicalRule], &[CanonicalRule]) =
        carried.map_or((&[], &[]), |c| (c.primary.rules(), c.secondary.rules()));
    let primary = book
        .primary
        .rules()
        .iter()
        .filter(|r| !carried_primary.contains(r));
    let secondary = book
        .secondary
        .rules()
        .iter()
        .filter(|r| !carried_secondary.contains(r));
    primary
        .chain(secondary)
        .find_map(|rule| match rule_verdict(rule, support) {
            ShapeVerdict::Supported => None,
            ShapeVerdict::Unsupported { reason } => Some((rule, reason)),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{
        CanonicalAddressMatch, CanonicalAppMatch, CanonicalAppPattern, CanonicalRuleSet,
    };
    use crate::RuleId;

    const ACTIONS: [RuleAction; 2] = [RuleAction::Route, RuleAction::Block];

    fn all_supports() -> [RuleShapeSupport; 4] {
        [(false, false), (true, false), (false, true), (true, true)].map(|(block, route)| {
            RuleShapeSupport {
                app_scoped_destination_block: block,
                app_scoped_destination_route: route,
            }
        })
    }

    fn rule(id: &str, address: bool, app: bool, action: RuleAction) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: address.then(|| CanonicalAddressMatch::ExactFqdn("host.example".into())),
            app_match: app.then(|| CanonicalAppMatch {
                pattern: CanonicalAppPattern::Exact("app.exe".into()),
                include_child_processes: false,
            }),
            comment: String::new(),
            action,
            origin: None,
        }
    }

    #[test]
    fn every_support_combination_is_covered() {
        let supports = all_supports();
        for (i, a) in supports.iter().enumerate() {
            for b in &supports[i + 1..] {
                assert_ne!(a, b, "the four combinations are distinct");
            }
        }
    }

    #[test]
    fn the_table_is_exhaustive() {
        for shape in RuleShape::ALL {
            for action in ACTIONS {
                for support in all_supports() {
                    let expected = match (shape, action) {
                        (RuleShape::Destination | RuleShape::Source, _) => ShapeVerdict::Supported,
                        (RuleShape::SourceAndDestination, RuleAction::Block)
                            if support.app_scoped_destination_block =>
                        {
                            ShapeVerdict::Supported
                        }
                        (RuleShape::SourceAndDestination, RuleAction::Block) => {
                            ShapeVerdict::Unsupported {
                                reason: UnsupportedShapeReason::AppScopedDestinationBlock,
                            }
                        }
                        (RuleShape::SourceAndDestination, RuleAction::Route)
                            if support.app_scoped_destination_route =>
                        {
                            ShapeVerdict::Supported
                        }
                        (RuleShape::SourceAndDestination, RuleAction::Route) => {
                            ShapeVerdict::Unsupported {
                                reason: UnsupportedShapeReason::AppScopedDestinationRoute,
                            }
                        }
                    };
                    assert_eq!(
                        shape_verdict(shape, action, support),
                        expected,
                        "{shape:?} / {action:?} / {support:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn one_flag_never_unlocks_the_other_action() {
        let block_only = RuleShapeSupport {
            app_scoped_destination_block: true,
            app_scoped_destination_route: false,
        };
        assert!(!shape_verdict(
            RuleShape::SourceAndDestination,
            RuleAction::Route,
            block_only
        )
        .is_supported());
        let route_only = RuleShapeSupport {
            app_scoped_destination_block: false,
            app_scoped_destination_route: true,
        };
        assert!(!shape_verdict(
            RuleShape::SourceAndDestination,
            RuleAction::Block,
            route_only
        )
        .is_supported());
    }

    #[test]
    fn shape_follows_the_conditions() {
        let a = RuleAction::Route;
        assert_eq!(
            RuleShape::of(&rule("d", true, false, a)),
            Some(RuleShape::Destination)
        );
        assert_eq!(
            RuleShape::of(&rule("s", false, true, a)),
            Some(RuleShape::Source)
        );
        assert_eq!(
            RuleShape::of(&rule("sd", true, true, a)),
            Some(RuleShape::SourceAndDestination)
        );
        assert_eq!(RuleShape::of(&rule("n", false, false, a)), None);
        assert!(rule_verdict(&rule("n", false, false, a), RuleShapeSupport::NONE).is_supported());
    }

    #[test]
    fn reason_slugs_are_stable() {
        assert_eq!(
            UnsupportedShapeReason::AppScopedDestinationBlock.slug(),
            "app-scoped-destination-block"
        );
        assert_eq!(
            UnsupportedShapeReason::AppScopedDestinationRoute.to_string(),
            "app-scoped-destination-route"
        );
    }

    #[test]
    fn first_unsupported_finds_a_disabled_rule_on_either_route() {
        let mut combined = rule("c", true, true, RuleAction::Block);
        combined.enabled = false;
        let book = CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![
                rule("d", true, false, RuleAction::Block),
                rule("s", false, true, RuleAction::Route),
            ]),
            secondary: CanonicalRuleSet::from_rules(vec![combined]),
        };
        let (found, reason) =
            first_unsupported(&book, RuleShapeSupport::NONE).expect("combined rule reported");
        assert_eq!(found.id.as_str(), "c");
        assert_eq!(reason, UnsupportedShapeReason::AppScopedDestinationBlock);
        let all = RuleShapeSupport {
            app_scoped_destination_block: true,
            app_scoped_destination_route: true,
        };
        assert!(first_unsupported(&book, all).is_none());
    }

    #[test]
    fn first_unsupported_new_spares_only_a_rule_carried_over_unchanged() {
        let combined = rule("c", true, true, RuleAction::Block);
        let carried = CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![combined.clone()]),
            secondary: CanonicalRuleSet::default(),
        };
        let added = CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![
                combined.clone(),
                rule("n", true, false, RuleAction::Route),
            ]),
            secondary: CanonicalRuleSet::default(),
        };
        assert!(first_unsupported_new(&added, Some(&carried), RuleShapeSupport::NONE).is_none());

        let mut edited = combined.clone();
        edited.enabled = false;
        let changed = CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![edited]),
            secondary: CanonicalRuleSet::default(),
        };
        assert!(first_unsupported_new(&changed, Some(&carried), RuleShapeSupport::NONE).is_some());

        // Moved to the other route: a new rule there.
        let moved = CanonicalRuleBook {
            primary: CanonicalRuleSet::default(),
            secondary: CanonicalRuleSet::from_rules(vec![combined]),
        };
        assert!(first_unsupported_new(&moved, Some(&carried), RuleShapeSupport::NONE).is_some());
        assert!(first_unsupported_new(&added, None, RuleShapeSupport::NONE).is_some());
    }
}
