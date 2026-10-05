//! Which addresses the user's network rules give the additional link, for the
//! direct-host fake-IP answerers.
//!
//! A virtual address hands a flow to the relay, which picks the link by the
//! hostname — and a direct host's name says "main". When its real address lies
//! in a network the user routes over the additional link, the relay would carry
//! it out of the main link: the network rule broken by the very rescue meant to
//! keep the host working, and a leak while Fail-Closed holds that network. Such
//! a host keeps its real answer, which enforcement carries by address.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, OnceLock, RwLock};

use nrr_domain::canonical::CanonicalRuleBook;
use nrr_domain::rule_shape::RuleShapeSupport;
use nrr_shared::ip_block::IpBlock;

use crate::address_ownership::{Link, NetworkClaims};

/// Answers whether any of a host's real addresses belongs, by network, to the
/// additional link.
pub trait AdditionalNetworkOwner: Send + Sync {
    fn owns_any(&self, real: &[Ipv4Addr]) -> bool;
}

/// One principal's route networks, by longest prefix — the arbiter's own
/// table, so the answerers and enforcement cannot disagree on a network.
#[derive(Clone, Debug, Default)]
pub struct RuleNetworkIndex {
    claims: NetworkClaims,
}

impl RuleNetworkIndex {
    /// Against the shape support this service enforces.
    #[must_use]
    pub fn from_book(rule_book: &CanonicalRuleBook) -> Self {
        Self::from_book_with_support(rule_book, crate::wfp_codegen::current_rule_shape_support())
    }

    #[must_use]
    pub fn from_book_with_support(
        rule_book: &CanonicalRuleBook,
        support: RuleShapeSupport,
    ) -> Self {
        Self {
            claims: NetworkClaims::of_book(rule_book, support),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }

    /// The networks the user's route rules name, in address order.
    #[must_use]
    pub fn networks(&self) -> &[IpBlock] {
        self.claims.blocks()
    }

    /// The narrowest network holding `ip` is the additional link's. A main
    /// network inside it, or the same network on both links, keeps it main.
    #[must_use]
    pub fn additional_owns(&self, ip: Ipv4Addr) -> bool {
        self.claims.winner(IpAddr::V4(ip)) == Some(Link::Additional)
    }
}

impl AdditionalNetworkOwner for RuleNetworkIndex {
    fn owns_any(&self, real: &[Ipv4Addr]) -> bool {
        real.iter().any(|ip| self.additional_owns(*ip))
    }
}

/// Each principal's index as of its last compute, read by the DNS answerers.
/// A book without networks stores nothing, so the common read is one miss.
#[derive(Default)]
pub struct RuleNetworkCell {
    by_principal: RwLock<HashMap<String, Arc<RuleNetworkIndex>>>,
}

impl RuleNetworkCell {
    pub fn publish(&self, principal: &str, rule_book: &CanonicalRuleBook) {
        self.publish_with_support(
            principal,
            rule_book,
            crate::wfp_codegen::current_rule_shape_support(),
        );
    }

    fn publish_with_support(
        &self,
        principal: &str,
        rule_book: &CanonicalRuleBook,
        support: RuleShapeSupport,
    ) {
        let index = RuleNetworkIndex::from_book_with_support(rule_book, support);
        let mut map = self.by_principal.write().unwrap_or_else(|p| p.into_inner());
        if index.is_empty() {
            map.remove(principal);
        } else {
            map.insert(principal.to_string(), Arc::new(index));
        }
    }

    #[must_use]
    pub fn for_principal(&self, principal: &str) -> Option<Arc<RuleNetworkIndex>> {
        self.by_principal
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(principal)
            .cloned()
    }
}

/// The process-wide cell: the per-principal compute publishes, the answerers
/// read through [`ActivePrincipalNetworks`].
pub fn global_rule_networks() -> Arc<RuleNetworkCell> {
    static CELL: OnceLock<Arc<RuleNetworkCell>> = OnceLock::new();
    Arc::clone(CELL.get_or_init(Arc::default))
}

/// [`AdditionalNetworkOwner`] for whichever principal the fake-IP datapath
/// currently serves.
pub struct ActivePrincipalNetworks {
    cell: Arc<RuleNetworkCell>,
    active: Arc<dyn Fn() -> Option<String> + Send + Sync>,
}

impl ActivePrincipalNetworks {
    #[must_use]
    pub fn new(
        cell: Arc<RuleNetworkCell>,
        active: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    ) -> Self {
        Self { cell, active }
    }
}

impl AdditionalNetworkOwner for ActivePrincipalNetworks {
    fn owns_any(&self, real: &[Ipv4Addr]) -> bool {
        (self.active)()
            .and_then(|principal| self.cell.for_principal(&principal))
            .is_some_and(|index| index.owns_any(real))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_domain::canonical::{CanonicalAddressMatch, CanonicalRule, CanonicalRuleSet};
    use nrr_domain::{RuleAction, RuleId};
    use nrr_shared::ip_block::IpBlock;

    fn subnet_rule(id: &str, net: &str, action: RuleAction) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::Subnet(
                IpBlock::parse(net).expect("test network literal"),
            )),
            app_match: None,
            comment: String::new(),
            action,
            origin: None,
        }
    }

    fn book(primary: Vec<CanonicalRule>, secondary: Vec<CanonicalRule>) -> CanonicalRuleBook {
        CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(primary),
            secondary: CanonicalRuleSet::from_rules(secondary),
        }
    }

    fn with_networks() -> RuleShapeSupport {
        RuleShapeSupport {
            network_destination: true,
            ..crate::wfp_codegen::current_rule_shape_support()
        }
    }

    #[test]
    fn the_narrowest_network_decides() {
        let index = RuleNetworkIndex::from_book_with_support(
            &book(
                vec![subnet_rule("p", "10.5.0.0/16", RuleAction::Route)],
                vec![
                    subnet_rule("s", "10.0.0.0/8", RuleAction::Route),
                    subnet_rule("s-block", "172.16.0.0/12", RuleAction::Block),
                ],
            ),
            with_networks(),
        );
        assert!(index.additional_owns(Ipv4Addr::new(10, 1, 0, 1)));
        assert!(!index.additional_owns(Ipv4Addr::new(10, 5, 0, 1)));
        // A Block steers nothing, so it hands nothing to the relay either.
        assert!(!index.additional_owns(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(index.owns_any(&[Ipv4Addr::new(10, 5, 0, 1), Ipv4Addr::new(10, 9, 0, 1)]));
    }

    #[test]
    fn a_network_enforcement_cannot_carry_is_not_consulted() {
        let index = RuleNetworkIndex::from_book_with_support(
            &book(
                Vec::new(),
                vec![subnet_rule("s", "10.0.0.0/8", RuleAction::Route)],
            ),
            RuleShapeSupport::NONE,
        );
        assert!(index.is_empty());
        assert!(!index.additional_owns(Ipv4Addr::new(10, 1, 0, 1)));
    }

    #[test]
    fn a_published_book_makes_its_principal_report_its_networks() {
        let cell = Arc::new(RuleNetworkCell::default());
        let book = book(
            Vec::new(),
            vec![subnet_rule("s", "10.0.0.0/8", RuleAction::Route)],
        );
        cell.publish_with_support("S-1", &book, with_networks());
        let real = [Ipv4Addr::new(10, 1, 0, 1)];
        let owner =
            ActivePrincipalNetworks::new(Arc::clone(&cell), Arc::new(|| Some("S-1".to_string())));
        assert!(owner.owns_any(&real));
        assert_eq!(
            cell.for_principal("S-1")
                .expect("published")
                .networks()
                .len(),
            1
        );
        // Without network support the same book publishes nothing.
        cell.publish_with_support("S-2", &book, RuleShapeSupport::NONE);
        assert!(cell.for_principal("S-2").is_none());
    }

    #[test]
    fn the_active_principal_reads_its_own_index() {
        let cell = Arc::new(RuleNetworkCell::default());
        cell.by_principal.write().expect("lock").insert(
            "S-1".into(),
            Arc::new(RuleNetworkIndex::from_book_with_support(
                &book(
                    Vec::new(),
                    vec![subnet_rule("s", "10.0.0.0/8", RuleAction::Route)],
                ),
                with_networks(),
            )),
        );
        let real = [Ipv4Addr::new(10, 1, 0, 1)];
        let owner = |sid: Option<&'static str>| {
            ActivePrincipalNetworks::new(
                Arc::clone(&cell),
                Arc::new(move || sid.map(str::to_string)),
            )
        };
        assert!(owner(Some("S-1")).owns_any(&real));
        assert!(!owner(Some("S-2")).owns_any(&real));
        assert!(!owner(None).owns_any(&real));
        // A book without networks clears the principal's entry.
        cell.publish("S-1", &book(Vec::new(), Vec::new()));
        assert!(!owner(Some("S-1")).owns_any(&real));
    }
}
