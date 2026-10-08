//! What a submission must not lose or let through on its way to a revision.
//!
//! Rules of a kind this build cannot read are kept: the GUI never sees them, so
//! every book it submits lacks them, and an older build rewriting a revision a
//! newer one wrote would otherwise delete rules nobody asked it to touch. They
//! are carried forward from the book in force, stored and never applied.
//!
//! Network rules are screened against this machine's own links and the
//! service's virtual address pool: a subnet over either cuts the path the
//! rule's traffic travels or the machinery that serves it.

use std::collections::HashSet;
use std::hash::{Hash, Hasher};

use crate::route_codegen::network_routes::NetworkLinkConflict;
use nrr_domain::rules_revision::UnrecognizedRules;
use nrr_shared::ip_block::IpBlock;

use super::*;

/// Refusal code for a network over the tunnel server or a connected network.
pub const NETWORK_COVERS_LINK_CODE: &str = "network-covers-link";
/// Refusal code for a network over the service's virtual address pool.
pub const NETWORK_COVERS_FAKE_IP_POOL_CODE: &str = "network-covers-fake-ip-pool";
/// Refusal code for a submitted rule of a kind or action this build cannot read.
pub const RULE_KIND_UNKNOWN_CODE: &str = "rule-kind-unknown";

/// A client never sees the rules this build cannot read, so one arriving in a
/// submission is a broken payload: stored, it would neither apply nor show.
/// A malformed known kind is left for the codec to refuse with its own code.
pub(super) fn unreadable_submitted_rule(rules_json: &str) -> Option<OperationError> {
    let dto =
        serde_json::from_str::<nrr_shared::rules_json::CanonicalRulesJsonV1>(rules_json).ok()?;
    let rule = dto.primary.iter().chain(&dto.secondary).find(|rule| {
        rule.is_unrecognized()
            && !rule
                .address_match
                .as_ref()
                .is_some_and(nrr_shared::rules_json::AddressMatchDto::is_malformed)
    })?;
    Some(OperationError {
        args: Default::default(),
        code: RULE_KIND_UNKNOWN_CODE.into(),
        message: format!(
            "Rule {} has a kind or action this version cannot read; nothing was saved.",
            rule.id
        ),
    })
}

/// Why a network rule cannot be accepted on this machine as it is now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkRuleConflict {
    /// Covers the tunnel server or a network a link is attached to.
    CoversLink(NetworkLinkConflict),
    /// Overlaps the virtual address pool the service hands out.
    CoversFakeIpPool,
}

/// The runtime half of network-rule validation: what only the running service
/// knows (its links, its pool). The value rules — width, reserved space — are
/// the domain validator's and already ran.
pub trait NetworkRuleScreen: Send + Sync {
    /// A judge for one submission's networks. The machine is read once here,
    /// not once per network.
    fn checker(
        &self,
        principal: &str,
    ) -> Box<dyn Fn(IpBlock) -> Option<NetworkRuleConflict> + Send>;
}

impl ProductionMutationExecutor {
    /// Screen every network rule a submission newly enforces (see
    /// [`new_networks`]): a book saved before a link moved must stay editable.
    pub(super) fn network_refusal(
        &self,
        rules_json: &str,
        principal: &str,
    ) -> Option<OperationError> {
        let screen = self.network_screen.as_ref()?;
        let incoming = decode_rule_book(rules_json, self.host_platform)?;
        let carried = self
            .coordinator
            .rules_json_in_force_for(principal)
            .and_then(|json| {
                crate::production_rules_provider::read_stored_rules(&json, "rules-in-force").ok()
            })
            .and_then(|dto| rules_json_codec::decode(dto, self.host_platform).ok())
            .map(|content| content.rule_book);
        let new_networks = new_networks(&incoming, carried.as_ref());
        if new_networks.is_empty() {
            return None;
        }
        let check = screen.checker(principal);
        new_networks.into_iter().find_map(|(rule, address)| {
            let conflict = address
                .ip_blocks()?
                .iter()
                .find_map(|block| check(*block))?;
            Some(network_conflict_error(
                rule.id.as_str(),
                &address.to_display_string(),
                conflict,
            ))
        })
    }

    /// Carry the unrecognized rules of the book in force for `principal` into
    /// `payload` where it lacks them, re-hashing what changed. A payload that
    /// does not decode is left for the validator to refuse.
    pub(super) fn carry_unrecognized(&self, payload: &mut RulesUpdatePayload, principal: &str) {
        let Some(carried) = self.unrecognized_in_force(principal) else {
            return;
        };
        let Some(mut content) = nrr_shared::rules_json::from_canonical_string(&payload.rules_json)
            .ok()
            .and_then(|dto| rules_json_codec::decode(dto, self.host_platform).ok())
        else {
            return;
        };
        if carry_forward(&mut content, &carried) == 0 {
            return;
        }
        let Ok(canonical) = rules_json::to_canonical_string(&rules_json_codec::encode(&content))
        else {
            return;
        };
        report_unrecognized_rules(&canonical, content.unrecognized.len(), principal);
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        payload.content_hash = format!("{:x}", hasher.finalize());
        payload.rules_json = canonical;
    }

    /// The unrecognized rules of the book in force for `principal`; `None`
    /// when it holds none, which is every book this build wrote itself.
    pub(super) fn unrecognized_in_force(&self, principal: &str) -> Option<UnrecognizedRules> {
        let json = self.coordinator.rules_json_in_force_for(principal)?;
        let dto =
            crate::production_rules_provider::read_stored_rules(&json, "rules-in-force").ok()?;
        let content = rules_json_codec::decode(dto, self.host_platform).ok()?;
        (!content.unrecognized.is_empty()).then_some(content.unrecognized)
    }
}

/// Add to `content` every rule of `carried` whose id it does not already hold
/// on either route; returns how many were added. An id the submission reuses
/// is the submission's: two rules under one id would be a broken book.
pub(super) fn carry_forward(
    content: &mut nrr_domain::rules_revision::RulesRevisionContent,
    carried: &UnrecognizedRules,
) -> usize {
    let held: HashSet<String> = content
        .rule_book
        .primary
        .rules()
        .iter()
        .chain(content.rule_book.secondary.rules())
        .map(|rule| rule.id.as_str().to_owned())
        .chain(
            content
                .unrecognized
                .primary
                .iter()
                .chain(&content.unrecognized.secondary)
                .map(|rule| rule.id.clone()),
        )
        .collect();
    let mut added = 0;
    for (into, from) in [
        (&mut content.unrecognized.primary, &carried.primary),
        (&mut content.unrecognized.secondary, &carried.secondary),
    ] {
        let missing: Vec<_> = from
            .iter()
            .filter(|rule| !held.contains(&rule.id))
            .cloned()
            .collect();
        if missing.is_empty() {
            continue;
        }
        added += missing.len();
        into.extend(missing);
        // The order the codec decodes them in, so the bytes do not depend on
        // which path wrote the revision.
        into.sort_by(|a, b| a.id.cmp(&b.id));
    }
    added
}

/// One line per book per run saying rules of an unknown kind are kept but not
/// applied. Every reader of one book would repeat it otherwise.
pub(crate) fn report_unrecognized_rules(rules_json: &str, count: usize, principal: &str) {
    if count == 0 {
        return;
    }
    if first_report_of_book(rules_json) {
        tracing::warn!(
            target: "nrr::rules-provider",
            msg_key = "rules-unrecognized-kept",
            unrecognized = count,
            principal = %principal,
            "rules of a kind this version does not know are kept in the rule set, not applied",
        );
    }
}

/// True the first time this book is seen, whichever reader asks.
pub(crate) fn first_report_of_book(rules_json: &str) -> bool {
    static REPORTED: std::sync::OnceLock<Mutex<HashSet<u64>>> = std::sync::OnceLock::new();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    rules_json.hash(&mut hasher);
    let mut reported = REPORTED
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if reported.len() >= 64 {
        reported.clear();
    }
    reported.insert(hasher.finish())
}

/// The enabled network rules of `incoming` the book in force did not already
/// enforce on the same route with the same action. Only these are screened: a
/// book saved before a link moved must stay editable, while enabling a stored
/// network or moving it to the other route makes it newly enforced.
pub(super) fn new_networks<'a>(
    incoming: &'a nrr_domain::canonical::CanonicalRuleBook,
    carried: Option<&nrr_domain::canonical::CanonicalRuleBook>,
) -> Vec<(
    &'a nrr_domain::canonical::CanonicalRule,
    &'a nrr_domain::canonical::CanonicalAddressMatch,
)> {
    use nrr_domain::canonical::{CanonicalRule, CanonicalRuleBook};
    fn enforced(book: &CanonicalRuleBook) -> impl Iterator<Item = (bool, &CanonicalRule)> {
        let primary = book.primary.rules().iter().map(|rule| (false, rule));
        let secondary = book.secondary.rules().iter().map(|rule| (true, rule));
        primary.chain(secondary).filter(|(_, rule)| rule.enabled)
    }
    let held: HashSet<_> = carried
        .into_iter()
        .flat_map(enforced)
        .filter_map(|(secondary, rule)| {
            Some((secondary, rule.action, rule.address_match.as_ref()?))
        })
        .collect();
    enforced(incoming)
        .filter_map(|(secondary, rule)| {
            let address = rule.address_match.as_ref()?;
            let screened =
                address.ip_blocks().is_some() && !held.contains(&(secondary, rule.action, address));
            screened.then_some((rule, address))
        })
        .collect()
}

fn network_conflict_error(
    rule_id: &str,
    network: &str,
    conflict: NetworkRuleConflict,
) -> OperationError {
    let mut args = std::collections::BTreeMap::from([
        ("rule".to_owned(), rule_id.to_owned()),
        ("network".to_owned(), network.to_owned()),
    ]);
    match conflict {
        NetworkRuleConflict::CoversLink(what) => {
            let (kind, value) = match what {
                NetworkLinkConflict::CoversTunnelServer(server) => {
                    ("tunnel-server", server.to_string())
                }
                NetworkLinkConflict::OverlapsLocalNetwork(local) => {
                    ("local-network", local.to_string())
                }
            };
            args.insert("covers-kind".to_owned(), kind.to_owned());
            args.insert("covers".to_owned(), value.clone());
            let covered = if kind == "tunnel-server" {
                format!("the tunnel server {value}")
            } else {
                format!("the connected network {value}")
            };
            OperationError {
                code: NETWORK_COVERS_LINK_CODE.into(),
                message: format!(
                    "Rule {rule_id}: the network {network} takes in {covered}; routing it would \
                     cut the link its own traffic travels over."
                ),
                args,
            }
        }
        NetworkRuleConflict::CoversFakeIpPool => {
            args.insert("covers-kind".to_owned(), "fake-ip-pool".to_owned());
            OperationError {
                code: NETWORK_COVERS_FAKE_IP_POOL_CODE.into(),
                message: format!(
                    "Rule {rule_id}: the network {network} overlaps the address pool the service \
                     reserves for name-based routing."
                ),
                args,
            }
        }
    }
}
