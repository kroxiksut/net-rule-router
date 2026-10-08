//! Rules-table rows: their route and type, their wire form, and the two rules
//! files written from them.
//!
//! A row is the table's view of one rule. Besides the two adapter routes its
//! target can be one of two pseudo-routes that ride in the secondary bucket:
//! [`TargetRoute::Block`] (drop) and [`TargetRoute::Verify`] (`?host`: main
//! link until the service confirms it cannot reach the host).

mod file_text;
mod search;
mod wire;

use std::borrow::Cow;

use nrr_shared::rules_json::RuleAction;

use crate::Route;

pub use file_text::{build_rules_file_text, RulesFileOptions, PRESET_FORMAT_VERSION};
pub use search::{normalize_host_input, row_matches_search, search_box_text};
pub use wire::{
    drift_row_from_parsed_rule, drift_row_from_service_wire, file_row_from_service_wire,
    parsed_rule_target_route, rule_row_to_wire_dto, WireDtoOptions,
};

/// Where a row sends its traffic.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TargetRoute {
    Primary,
    Secondary,
    /// Drop the traffic; kept in the secondary file as `+block`.
    Block,
    /// `?host` in the secondary file; wire action `verify-primary`.
    Verify,
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
            "verify" => Self::Verify,
            other => Self::Other(other.to_owned()),
        }
    }

    /// The slug.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Primary => "primary",
            Self::Secondary => "secondary",
            Self::Block => "block",
            Self::Verify => "verify",
            Self::Other(slug) => slug,
        }
    }

    /// The route bucket and rules file the row rides in (`routeBucket`): a
    /// pseudo-route rides in the secondary one. `None` for an unknown slug.
    pub fn bucket(&self) -> Option<Route> {
        match self {
            Self::Primary => Some(Route::Primary),
            Self::Secondary | Self::Block | Self::Verify => Some(Route::Secondary),
            Self::Other(_) => None,
        }
    }

    /// This target as a rule of `rule_type` can carry it (`routeForRuleType`):
    /// verify on a type that cannot take it becomes secondary, where it would
    /// have ended up anyway.
    pub fn for_rule_type(self, rule_type: &RuleType) -> Self {
        if self == Self::Verify && !rule_type.allows_verify() {
            Self::Secondary
        } else {
            self
        }
    }

    /// The per-rule wire action.
    pub fn action(&self) -> RuleAction {
        match self {
            Self::Block => RuleAction::Block,
            Self::Verify => RuleAction::VerifyPrimary,
            _ => RuleAction::Route,
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

    /// Only a name can be tried on the main link first
    /// (`ruleTypeAllowsVerify`); the rules file reads `?` on host names only.
    pub fn allows_verify(&self) -> bool {
        matches!(self, Self::Domain | Self::SuffixDomain | Self::ExactFqdn)
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

    /// Import-merge identity (`mergeKey`): folded type, lower-cased value,
    /// target route as spelled.
    pub fn merge_key(&self) -> String {
        format!(
            "{}|{}|{}",
            self.rule_type.canonical_slug(),
            self.match_value.to_lowercase(),
            self.target_route.as_str()
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
