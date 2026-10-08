//! Where a user's own rules contradict each other, as the Overlaps screen
//! reports it.
//!
//! Both enforcement paths — the WFP codegen and the neutral planner — walk an
//! address rule's targets and ask [`AddressRuleWalk`] what to keep, so the
//! conflicts a user is shown come from the decision that was enforced, and are
//! the same on every platform.

use std::collections::HashSet;
use std::net::IpAddr;

use nrr_domain::canonical::{CanonicalAddressMatch, CanonicalRuleBook};
use nrr_domain::rule_shape::UnsupportedShapeReason;
use nrr_domain::RuleAction;
use nrr_shared::ipc_payloads::{RuleConflictDto, RuleConflictKind};

use crate::address_ownership::{AddressOwnership, Link};

/// One conflict, aggregated per rule: an example address plus a count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuleConflict {
    /// A Block yielded `ip` to a narrower route, leaving `host` reachable:
    /// `host` is not routed itself, it only shares the address with `via_host`.
    BlockLeaksSharedAddress {
        rule_id: String,
        ip: IpAddr,
        host: String,
        via_host: String,
        count: usize,
    },
    /// A route's address is dropped by a literal-IP Block, which vetoes every
    /// route on it. `host` is empty for a literal route.
    RouteOverriddenByLiteralBlock {
        rule_id: String,
        block_rule_id: String,
        ip: IpAddr,
        host: String,
        count: usize,
    },
    /// The rule cannot be enforced as written and was skipped whole.
    UnsupportedRuleShape {
        rule_id: String,
        reason: UnsupportedShapeReason,
    },
    /// Carving the narrower rules out of this network needed more than `cap`
    /// pieces: it covers its whole network and the narrower rules inside lose.
    NetworkCarvingOverCap {
        rule_id: String,
        pieces: usize,
        cap: usize,
    },
}

/// One address rule's fan-out: decides per target whether the rule's filter
/// acts on it, and notes the conflicts that decision exposes.
pub struct AddressRuleWalk<'a> {
    ownership: &'a AddressOwnership,
    action: RuleAction,
    addr_match: &'a CanonicalAddressMatch,
    link: Link,
    leak: Option<(IpAddr, String, String)>,
    leaked: HashSet<IpAddr>,
    vetoed: Option<(IpAddr, String, String)>,
    vetoed_ips: HashSet<IpAddr>,
}

impl<'a> AddressRuleWalk<'a> {
    #[must_use]
    pub fn new(
        ownership: &'a AddressOwnership,
        action: RuleAction,
        addr_match: &'a CanonicalAddressMatch,
        link: Link,
    ) -> Self {
        Self {
            ownership,
            action,
            addr_match,
            link,
            leak: None,
            leaked: HashSet::new(),
            vetoed: None,
            vetoed_ips: HashSet::new(),
        }
    }

    /// Whether the rule's filter may act on `ip`, reached through `host`
    /// (`None` for a literal address).
    ///
    /// A Block steers nothing but still loses an address a narrower rule names;
    /// a route may not take an address the main link's own rules name.
    pub fn keeps(&mut self, host: Option<&str>, ip: IpAddr) -> bool {
        let ownership = self.ownership;
        match self.action {
            RuleAction::Block => {
                if let Some(host) = host {
                    if let Some(via) = ownership.block_leak(host, ip, self.addr_match) {
                        if self.leaked.insert(ip) && self.leak.is_none() {
                            self.leak = Some((ip, host.to_string(), via.to_string()));
                        }
                    }
                }
                !ownership.block_yields(ip, self.addr_match)
            }
            RuleAction::Route | RuleAction::VerifyPrimary => {
                let steers = ownership.address_rule_may_steer(ip, self.link);
                if steers {
                    if let Some(block) = ownership.literal_block_of(ip) {
                        if self.vetoed_ips.insert(ip) && self.vetoed.is_none() {
                            self.vetoed =
                                Some((ip, host.unwrap_or_default().to_string(), block.to_string()));
                        }
                    }
                }
                steers
            }
        }
    }

    /// The conflicts found, the leak before the veto.
    pub fn finish(self, rule_id: &str) -> impl Iterator<Item = RuleConflict> {
        let leak = self.leak.map(
            |(ip, host, via_host)| RuleConflict::BlockLeaksSharedAddress {
                rule_id: rule_id.to_string(),
                ip,
                host,
                via_host,
                count: self.leaked.len(),
            },
        );
        let veto = self.vetoed.map(|(ip, host, block_rule_id)| {
            RuleConflict::RouteOverriddenByLiteralBlock {
                rule_id: rule_id.to_string(),
                block_rule_id,
                ip,
                host,
                count: self.vetoed_ips.len(),
            }
        });
        leak.into_iter().chain(veto)
    }
}

/// `conflicts` projected for the GUI, in the order they were found.
#[must_use]
pub fn rule_conflict_dtos(
    conflicts: &[RuleConflict],
    rule_book: &CanonicalRuleBook,
) -> Vec<RuleConflictDto> {
    let rule_of = |rule_id: &str| {
        rule_book
            .primary
            .rules()
            .iter()
            .chain(rule_book.secondary.rules())
            .find(|r| r.id.as_str() == rule_id)
    };
    let value_of = |rule_id: &str| -> String {
        rule_of(rule_id)
            .and_then(|r| r.address_match.as_ref())
            .map(display_value)
            .unwrap_or_default()
    };
    conflicts
        .iter()
        .map(|c| match c {
            RuleConflict::RouteOverriddenByLiteralBlock {
                rule_id,
                block_rule_id,
                ip,
                host,
                count,
            } => RuleConflictDto {
                kind: RuleConflictKind::LiteralBlockOverridesRoute,
                rule_id: rule_id.clone(),
                rule_value: value_of(rule_id),
                ip: ip.to_string(),
                count: u32::try_from(*count).unwrap_or(u32::MAX),
                other_rule_id: block_rule_id.clone(),
                host: host.clone(),
                via_host: String::new(),
                app: String::new(),
            },
            RuleConflict::BlockLeaksSharedAddress {
                rule_id,
                ip,
                host,
                via_host,
                count,
            } => RuleConflictDto {
                kind: RuleConflictKind::BlockLeaksSharedAddress,
                rule_id: rule_id.clone(),
                rule_value: value_of(rule_id),
                ip: ip.to_string(),
                count: u32::try_from(*count).unwrap_or(u32::MAX),
                other_rule_id: String::new(),
                host: host.clone(),
                via_host: via_host.clone(),
                app: String::new(),
            },
            RuleConflict::UnsupportedRuleShape { rule_id, .. } => RuleConflictDto {
                kind: RuleConflictKind::UnsupportedRuleShape,
                rule_id: rule_id.clone(),
                rule_value: value_of(rule_id),
                ip: String::new(),
                count: 0,
                other_rule_id: String::new(),
                host: String::new(),
                via_host: String::new(),
                app: rule_of(rule_id)
                    .and_then(|r| r.app_match.as_ref())
                    .map(|a| a.pattern.as_str().to_string())
                    .unwrap_or_default(),
            },
            RuleConflict::NetworkCarvingOverCap { rule_id, .. } => RuleConflictDto {
                kind: RuleConflictKind::NetworkCarvingOverCap,
                rule_id: rule_id.clone(),
                rule_value: value_of(rule_id),
                ip: String::new(),
                count: 0,
                other_rule_id: String::new(),
                host: String::new(),
                via_host: String::new(),
                app: String::new(),
            },
        })
        .collect()
}

/// `rule (pieces/cap)` for each network rule carved past the cap, for the log.
#[must_use]
pub fn over_cap_networks(conflicts: &[RuleConflict]) -> Vec<String> {
    conflicts
        .iter()
        .filter_map(|c| match c {
            RuleConflict::NetworkCarvingOverCap {
                rule_id,
                pieces,
                cap,
            } => Some(format!("{rule_id} ({pieces}/{cap})")),
            _ => None,
        })
        .collect()
}

/// A rule's address as the rules table spells it.
fn display_value(m: &CanonicalAddressMatch) -> String {
    match m {
        CanonicalAddressMatch::ExactFqdn(host) => host.clone(),
        CanonicalAddressMatch::SuffixDomain(suffix) => format!("*.{suffix}"),
        CanonicalAddressMatch::Zone(zone) => zone.clone(),
        CanonicalAddressMatch::ExactIp(ip) => ip.to_string(),
        CanonicalAddressMatch::Subnet(block) => block.to_string(),
        CanonicalAddressMatch::IpRange(range) => range.to_string(),
    }
}
