//! Rules of the two routes that claim the same hosts, and which one wins.
//!
//! The narrower rule wins without asking anyone — name over suffix over zone,
//! a longer suffix or zone over a shorter one. On a tie a Block beats a route,
//! then the main route beats the additional one. This only names the pairs so
//! the user can see them and confirm or change the route. `nrr-domain` pins
//! every reported winner against its matcher.
//!
//! Names are compared with names and addresses with addresses: whether an
//! address sits under a name rule is a question of resolution, not of the rule
//! book. The address pass is [`addresses`].

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use super::{ancestors_in, index_by_name};
use crate::rules_json::{
    folded_rule_name, AddressMatchDto, CanonicalRulesJsonV1, RuleAction, RuleDto,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RouteOverlapKind {
    /// Both claim the hosts equally strongly — the same rule on both routes.
    Duplicate,
    /// One rule sits inside the other.
    Nested,
    /// Two address rules share some addresses, neither holds the other.
    Intersecting,
}

/// One side of a pair, as the rules screen names a rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct OverlapRule {
    pub rule_id: String,
    /// `"primary"` / `"secondary"`.
    pub route: String,
    /// `"exact-fqdn"` / `"suffix-domain"` / `"zone"` / `"exact-ip"` /
    /// `"subnet"` / `"ip-range"`.
    pub rule_type: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RouteOverlap {
    /// What a confirmation is remembered by: both rules with their routes, so
    /// editing either rule or moving it to the other route asks again.
    pub key: String,
    pub kind: RouteOverlapKind,
    /// The rule whose route the shared hosts take.
    pub winner: OverlapRule,
    pub loser: OverlapRule,
    /// A Block won a tie against a route: the route names the hosts just as
    /// narrowly and never applies, which the screen warns about.
    #[serde(default)]
    pub block_wins_tie: bool,
    /// Addresses the main route names sit inside the additional route's
    /// network: they stay on the main link when the additional one is down,
    /// and the leak guard does not block them. The screen says so.
    #[serde(default)]
    pub main_stays_when_additional_down: bool,
}

/// Every pair of enabled name rules on different routes whose hosts
/// intersect. `include_subdomains` is the reader's setting under which an
/// exact rule is enforced as a suffix rule.
///
/// Rules with an application filter are left out: they claim the traffic of
/// one program, not hosts.
pub fn find_route_overlaps(
    dto: &CanonicalRulesJsonV1,
    include_subdomains: bool,
) -> Vec<RouteOverlap> {
    let mut found = addresses::find(&dto.primary, &dto.secondary);
    let primary = name_rules(&dto.primary, PRIMARY, include_subdomains);
    let secondary = name_rules(&dto.secondary, SECONDARY, include_subdomains);
    let primary_by_name = index_by_name(&primary, |r| r.name.as_str());
    let secondary_by_name = index_by_name(&secondary, |r| r.name.as_str());

    // A pair is found from the rule with the longer name, walking up its
    // labels; equal names are taken from the primary side only.
    for narrow in &primary {
        for wide in ancestors_in(&narrow.name, &secondary_by_name) {
            push_if_overlapping(narrow, wide, &mut found);
        }
    }
    for narrow in &secondary {
        for wide in ancestors_in(&narrow.name, &primary_by_name) {
            if wide.name != narrow.name {
                push_if_overlapping(narrow, wide, &mut found);
            }
        }
    }
    found.sort_by(|a, b| {
        a.winner
            .value
            .cmp(&b.winner.value)
            .then_with(|| a.loser.value.cmp(&b.loser.value))
            .then_with(|| a.key.cmp(&b.key))
    });
    found
}

const PRIMARY: &str = "primary";
const SECONDARY: &str = "secondary";

#[derive(Clone, Copy, PartialEq, Eq)]
enum NameKind {
    Exact,
    Suffix,
    Zone,
}

/// How strongly a rule claims a host it covers; `Ord` answers who wins.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Strength {
    Zone(usize),
    Suffix(usize),
    Exact,
}

struct NameRule<'a> {
    rule: &'a RuleDto,
    route: &'static str,
    /// Lowercase, no trailing dot — rules on screen may not be canonical yet.
    name: String,
    /// How the rule is enforced; differs from how it is written only for an
    /// exact rule under subdomain coverage.
    kind: NameKind,
    written_type: &'static str,
    written_value: &'a str,
}

impl NameRule<'_> {
    fn covers(&self, host: &str) -> bool {
        match self.kind {
            NameKind::Exact => host == self.name,
            NameKind::Suffix => host == self.name || is_below(host, &self.name),
            NameKind::Zone => is_below(host, &self.name),
        }
    }

    fn strength(&self) -> Strength {
        match self.kind {
            NameKind::Exact => Strength::Exact,
            NameKind::Suffix => Strength::Suffix(self.name.len()),
            NameKind::Zone => Strength::Zone(self.name.len()),
        }
    }

    fn side(&self) -> OverlapRule {
        OverlapRule {
            rule_id: self.rule.id.clone(),
            route: self.route.to_string(),
            rule_type: self.written_type.to_string(),
            value: self.written_value.to_string(),
        }
    }

    fn key_part(&self) -> String {
        format!("{}:{}:{}", self.route, self.written_type, self.name)
    }
}

fn is_below(host: &str, parent: &str) -> bool {
    host.len() > parent.len() + 1
        && host.ends_with(parent)
        && host.as_bytes()[host.len() - parent.len() - 1] == b'.'
}

fn name_rules<'a>(
    rules: &'a [RuleDto],
    route: &'static str,
    include_subdomains: bool,
) -> Vec<NameRule<'a>> {
    rules
        .iter()
        .filter(|rule| rule.enabled && rule.app_match.is_none())
        .filter_map(|rule| {
            let address = rule.address_match.as_ref()?;
            let (written_type, value, kind) = match address {
                // Under coverage `x` is enforced as `*.x`; comparing it as one
                // keeps `x` against `*.x` a duplicate rather than a nesting.
                AddressMatchDto::ExactFqdn { value } => (
                    "exact-fqdn",
                    value.as_str(),
                    if include_subdomains {
                        NameKind::Suffix
                    } else {
                        NameKind::Exact
                    },
                ),
                AddressMatchDto::SuffixDomain { suffix } => {
                    ("suffix-domain", suffix.as_str(), NameKind::Suffix)
                }
                AddressMatchDto::Zone { name } => ("zone", name.as_str(), NameKind::Zone),
                _ => return None,
            };
            let name = folded_rule_name(address)?;
            (!name.is_empty()).then_some(NameRule {
                rule,
                route,
                name,
                kind,
                written_type,
                written_value: value,
            })
        })
        .collect()
}

fn push_if_overlapping(narrow: &NameRule<'_>, wide: &NameRule<'_>, found: &mut Vec<RouteOverlap>) {
    // A host both rules cover: the narrow name itself, or one label below it
    // when the narrow rule is a zone and never covers its own name.
    let child = format!("x.{}", narrow.name);
    let shares_a_host = (narrow.covers(&narrow.name) && wide.covers(&narrow.name))
        || (narrow.covers(&child) && wide.covers(&child));
    if !shares_a_host {
        return;
    }
    // Only a Block against a route: two Blocks drop the hosts either way.
    let narrow_blocks = narrow.rule.action == RuleAction::Block;
    let one_blocks = narrow_blocks != (wide.rule.action == RuleAction::Block);
    let (winner, loser, kind) = match narrow.strength().cmp(&wide.strength()) {
        Ordering::Greater => (narrow, wide, RouteOverlapKind::Nested),
        Ordering::Less => (wide, narrow, RouteOverlapKind::Nested),
        Ordering::Equal if one_blocks && narrow_blocks => {
            (narrow, wide, RouteOverlapKind::Duplicate)
        }
        Ordering::Equal if one_blocks => (wide, narrow, RouteOverlapKind::Duplicate),
        Ordering::Equal if narrow.route == PRIMARY => (narrow, wide, RouteOverlapKind::Duplicate),
        Ordering::Equal => (wide, narrow, RouteOverlapKind::Duplicate),
    };
    found.push(RouteOverlap {
        key: format!("{}>{}", winner.key_part(), loser.key_part()),
        kind,
        winner: winner.side(),
        loser: loser.side(),
        block_wins_tie: one_blocks && kind == RouteOverlapKind::Duplicate,
        main_stays_when_additional_down: false,
    });
}

mod addresses;

#[cfg(test)]
mod tests;
