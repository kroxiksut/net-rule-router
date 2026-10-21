//! Rules-table rows: their route and type, their wire form, and the two rules
//! files written from them.
//!
//! A row is the table's view of one rule. Besides the two adapter routes its
//! target can be [`TargetRoute::Block`] (drop), a pseudo-route that rides in
//! the secondary bucket. A route rule may also carry `?` ([`RuleRow::verify`]):
//! it works where it is written, and the service offers to move it when only
//! the other link reaches it.

mod file_text;
mod main_route;
mod overrides;
mod search;
mod wire;

use std::borrow::Cow;

use nrr_shared::rules_json::RuleAction;

use crate::Route;

pub use file_text::{
    build_rules_file_text, RulesFileOptions, PRESET_FORMAT_VERSION, RULES_FILE_HINT_KEYS,
};
pub use main_route::{main_route_check_hosts, main_route_rank, CHECK_MAX_POLLS, CHECK_POLL_SECS};
pub use overrides::{override_remaining, rule_override_key};
pub use search::{normalize_host_input, row_matches_search, search_box_text};
pub use wire::{
    drift_row_from_parsed_rule, drift_row_from_service_wire, file_row_from_service_wire,
    parsed_rule_target_route, parsed_rule_verify, rule_row_to_wire_dto, WireDtoOptions,
    WireRefusal,
};

/// Where a row sends its traffic.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TargetRoute {
    Primary,
    Secondary,
    /// Drop the traffic; kept in the secondary file as `!value`.
    Block,
    /// A slug this build does not know, kept verbatim. It belongs to no file.
    Other(String),
}

impl TargetRoute {
    /// Parses a table / wire slug. Case-sensitive, as the GUI is.
    pub fn from_slug(slug: &str) -> Self {
        match slug {
            "primary" => Self::Primary,
            "secondary" => Self::Secondary,
            "block" => Self::Block,
            other => Self::Other(other.to_owned()),
        }
    }

    /// The slug.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Primary => "primary",
            Self::Secondary => "secondary",
            Self::Block => "block",
            Self::Other(slug) => slug,
        }
    }

    /// The route bucket and rules file the row rides in (`routeBucket`): a
    /// block rides in the secondary one. `None` for an unknown slug.
    pub fn bucket(&self) -> Option<Route> {
        match self {
            Self::Primary => Some(Route::Primary),
            Self::Secondary | Self::Block => Some(Route::Secondary),
            Self::Other(_) => None,
        }
    }
}

impl From<Route> for TargetRoute {
    fn from(route: Route) -> Self {
        match route {
            Route::Primary => Self::Primary,
            Route::Secondary => Self::Secondary,
        }
    }
}

/// A row's rule type. Spellings stay distinct (`domain` vs `suffix-domain`,
/// `exact-ip` vs `exact-ipv4`) because a row keeps the one it arrived with;
/// [`RuleType::canonical_slug`] folds them for identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RuleType {
    /// The service's round-trip slug for both host kinds; a `*.` prefix on
    /// the value marks a suffix.
    Domain,
    SuffixDomain,
    ExactFqdn,
    Zone,
    ExactIp,
    ExactIpv4,
    ExactIpv6,
    Subnet,
    IpRange,
    Application,
    /// A slug this build does not know (another OS's application section,
    /// a newer build), kept verbatim.
    Other(String),
}

impl RuleType {
    /// Parses a slug. Case-sensitive, as the GUI is.
    pub fn from_slug(slug: &str) -> Self {
        match slug {
            "domain" => Self::Domain,
            "suffix-domain" => Self::SuffixDomain,
            "exact-fqdn" => Self::ExactFqdn,
            "zone" => Self::Zone,
            "exact-ip" => Self::ExactIp,
            "exact-ipv4" => Self::ExactIpv4,
            "exact-ipv6" => Self::ExactIpv6,
            "subnet" => Self::Subnet,
            "ip-range" => Self::IpRange,
            "application" => Self::Application,
            other => Self::Other(other.to_owned()),
        }
    }

    /// The slug.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Domain => "domain",
            Self::SuffixDomain => "suffix-domain",
            Self::ExactFqdn => "exact-fqdn",
            Self::Zone => "zone",
            Self::ExactIp => "exact-ip",
            Self::ExactIpv4 => "exact-ipv4",
            Self::ExactIpv6 => "exact-ipv6",
            Self::Subnet => "subnet",
            Self::IpRange => "ip-range",
            Self::Application => "application",
            Self::Other(slug) => slug,
        }
    }

    /// The value is a host name (`isHostlikeRuleType`): IDN handling applies.
    pub fn is_hostlike(&self) -> bool {
        matches!(
            self,
            Self::Zone | Self::Domain | Self::SuffixDomain | Self::ExactFqdn
        )
    }

    /// `?` fits a host name or one address (`ruleTypeAllowsVerify`): the
    /// rules file reads it in those sections only.
    pub fn allows_verify(&self) -> bool {
        matches!(
            self,
            Self::Domain
                | Self::SuffixDomain
                | Self::ExactFqdn
                | Self::ExactIp
                | Self::ExactIpv4
                | Self::ExactIpv6
        )
    }

    /// The one spelling of this type for identity (`canonicalRuleTypeSlug`):
    /// lower-cased, `suffix-domain` folded into `domain` and the address
    /// families into `exact-ip`.
    pub fn canonical_slug(&self) -> Cow<'_, str> {
        match self {
            Self::Domain | Self::SuffixDomain => Cow::Borrowed("domain"),
            Self::ExactIp | Self::ExactIpv4 | Self::ExactIpv6 => Cow::Borrowed("exact-ip"),
            Self::Other(slug) => {
                let lower = slug.to_lowercase();
                match lower.as_str() {
                    "suffix-domain" => Cow::Borrowed("domain"),
                    "exact-ipv4" | "exact-ipv6" => Cow::Borrowed("exact-ip"),
                    _ => Cow::Owned(lower),
                }
            }
            known => Cow::Borrowed(known.as_str()),
        }
    }
}

/// An IPv6 literal (`valueIsIpv6Literal`).
pub fn value_is_ipv6_literal(rule_type: &RuleType, value: &str) -> bool {
    match rule_type {
        RuleType::ExactIpv6 => true,
        RuleType::ExactIp => value.contains(':'),
        _ => false,
    }
}

/// `x.*` (`valueIsAnyZone`): a site in every zone names no single host, so
/// "check where it works" has nothing to check.
pub fn value_is_any_zone(value: &str) -> bool {
    value.trim().ends_with(".*")
}

/// Provenance of a rule the application authored on the user's behalf.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RowOrigin {
    /// Why it was authored; an empty reason marks no provenance at all.
    pub reason: String,
    /// The host it was authored for.
    pub anchor: String,
    /// `YYYY-MM-DD` it was added.
    pub added: String,
}

/// One row of the rules table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleRow {
    /// `R-NNNN`, or empty for a row that has none yet.
    pub id: String,
    pub enabled: bool,
    pub rule_type: RuleType,
    /// Host values in Unicode form; the wire side ACE-encodes.
    pub match_value: String,
    pub target_route: TargetRoute,
    /// `?`: check where the rule works. Kept as typed; [`RuleRow::is_verify`]
    /// says whether it means anything for this row.
    pub verify: bool,
    pub comment: String,
    pub origin: Option<RowOrigin>,
}

impl RuleRow {
    /// The provenance, when it names a reason.
    pub fn auto_origin(&self) -> Option<&RowOrigin> {
        self.origin
            .as_ref()
            .filter(|origin| !origin.reason.is_empty())
    }

    /// The `?` this row actually carries (`rowIsVerify`): a route rule of a
    /// type that takes it. A block, another type, a site in every zone or an
    /// IPv6 literal drops it.
    pub fn is_verify(&self) -> bool {
        self.verify
            && matches!(
                self.target_route,
                TargetRoute::Primary | TargetRoute::Secondary
            )
            && self.rule_type.allows_verify()
            && !value_is_any_zone(&self.match_value)
            && !self.is_ipv6_literal()
    }

    /// An IPv6 literal (`valueIsIpv6Literal`): the probe leaves from an IPv4
    /// source, so the service turns a `?` there into a plain route.
    pub fn is_ipv6_literal(&self) -> bool {
        value_is_ipv6_literal(&self.rule_type, &self.match_value)
    }

    /// The per-rule wire action.
    pub fn action(&self) -> RuleAction {
        if self.target_route == TargetRoute::Block {
            RuleAction::Block
        } else if self.is_verify() {
            RuleAction::VerifyPrimary
        } else {
            RuleAction::Route
        }
    }

    /// Import-merge identity (`mergeKey`): folded type, lower-cased value,
    /// target route as spelled. `?` is no part of it: `?x` and `x` on one
    /// route are one rule.
    pub fn merge_key(&self) -> String {
        format!(
            "{}|{}|{}",
            self.rule_type.canonical_slug(),
            self.match_value.to_lowercase(),
            self.target_route.as_str()
        )
    }

    /// The rule apart from its route (`ruleValueKey`): folded type and
    /// lower-cased value, as recent changes and an undo match rules.
    pub fn value_key(&self) -> String {
        format!(
            "{}|{}",
            self.rule_type.canonical_slug(),
            self.match_value.to_lowercase()
        )
    }

    /// Content signature for duplicate detection (`ruleSignature`): folded
    /// type, then route and value, both lower-cased.
    pub fn signature(&self) -> String {
        format!(
            "{}|{}|{}",
            self.rule_type.canonical_slug(),
            self.target_route.as_str().to_lowercase(),
            self.match_value.to_lowercase()
        )
    }
}
