//! Turning an accepted companion-domain suggestion into a real rule.
//!
//! The rule lands in the CALLER'S OWN rule set, through the ordinary mutation
//! path: read the principal's active book, append, re-encode canonically, hash,
//! and hand a `RulesUpdate` to the [`MutationExecutor`]. Going around the
//! executor — straight to `ActivationCoordinator::submit_candidate`, which is
//! `pub(crate)` precisely to discourage that — would skip the Free rule cap, the
//! tamper gate, the revision audit and the push events, so an auto-authored rule
//! would be a second-class citizen with different failure modes from a rule the
//! user typed. It is the same write either way; only the reason differs.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::SystemTime;

use nrr_domain::auto_rule_budget::{auto_rules_over_budget, MAX_AUTO_RULES};
use nrr_domain::canonical::{
    CanonicalAddressMatch, CanonicalRule, CanonicalRuleBook, CanonicalRuleSet,
};
use nrr_domain::decision_matching::{match_suffix_domain, match_zone};
use nrr_domain::rules_revision::RulesRevisionContent;
use nrr_domain::{rules_json_codec, RuleAction, RuleId};
use nrr_shared::rules_json;
use nrr_shared::{AutoRuleReason, RouteRole, RuleOrigin};
use sha2::{Digest, Sha256};

use crate::ipc_handlers::mutation_token_store::StoredMutation;
use crate::ipc_handlers::payloads::MutationKind;
use crate::ipc_handlers::providers::{MutationExecutor, MutationOutcome};
use crate::per_sid_orchestrator::RulesProvider;
use crate::routed_host_flow_refresh::{RoutedHost, RoutedHostFlowRefresh};

/// The shape of match an accepted suggestion becomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthoredMatchKind {
    /// One exact hostname.
    ExactHost,
    /// A domain and its subdomains.
    SuffixDomain,
}

/// One rule to author.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthoredRule {
    /// Route the rule joins — always the anchor's own route.
    pub route: RouteRole,
    pub match_kind: AuthoredMatchKind,
    /// Hostname (exact) or registrable domain (suffix).
    pub value: String,
    /// The routed host whose behaviour prompted the rule.
    pub anchor: String,
}

/// Why authoring failed, in the wire vocabulary the caller sees.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorError {
    /// Stable slug, e.g. `rule-cap-exceeded`. Mirrors the executor's own codes
    /// so the tray reports the same reason for the same underlying refusal
    /// whether the rule came from a suggestion or from the rules editor.
    pub code: String,
    pub message: String,
}

impl AuthorError {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
        }
    }
}

/// Appends accepted suggestions to a principal's own rule set.
pub trait AutoRuleAuthor: Send + Sync {
    /// Author `rules` for `principal`, stamping every rule with `reason`.
    /// Returns how many rules were actually new (a rule the book already
    /// contains is skipped, not duplicated).
    fn author(
        &self,
        principal: &str,
        reason: &AutoRuleReason,
        rules: &[AuthoredRule],
        now: SystemTime,
        correlation_id: &str,
    ) -> Result<u32, AuthorError>;
}

/// Production author: read-modify-write through the mutation executor.
pub struct ProductionAutoRuleAuthor {
    rules: Arc<dyn RulesProvider>,
    executor: Arc<dyn MutationExecutor>,
    /// `None` on a platform with no connection-table control wired: the rule
    /// still lands, the user just has to refresh the page themselves.
    flow_refresh: Option<Arc<RoutedHostFlowRefresh>>,
}

impl ProductionAutoRuleAuthor {
    pub fn new(rules: Arc<dyn RulesProvider>, executor: Arc<dyn MutationExecutor>) -> Self {
        Self {
            rules,
            executor,
            flow_refresh: None,
        }
    }

    /// Wire the teardown of connections the new rules leave on the old route.
    #[must_use]
    pub fn with_flow_refresh(mut self, refresh: Arc<RoutedHostFlowRefresh>) -> Self {
        self.flow_refresh = Some(refresh);
        self
    }
}

impl AutoRuleAuthor for ProductionAutoRuleAuthor {
    fn author(
        &self,
        principal: &str,
        reason: &AutoRuleReason,
        rules: &[AuthoredRule],
        now: SystemTime,
        correlation_id: &str,
    ) -> Result<u32, AuthorError> {
        if rules.is_empty() {
            return Ok(0);
        }
        // Read-through to the admin baseline when the user has not diverged yet
        // is exactly what we want: their first accepted suggestion is also the
        // moment their own rule set comes into existence, seeded from the
        // baseline rather than from nothing.
        let snapshot = self.rules.active_rules_for(principal).ok_or_else(|| {
            AuthorError::new(
                "no-active-revision",
                "there is no active rule set to add these addresses to yet",
            )
        })?;

        let added = added_date(now);
        let mut book = snapshot.rule_book;
        let mut authored = 0_u32;
        let mut landed: Vec<&AuthoredRule> = Vec::new();
        for rule in rules {
            if append_rule(&mut book, rule, reason, &added) {
                authored = authored.saturating_add(1);
                landed.push(rule);
            }
        }
        if authored == 0 {
            // Everything was already present — a no-op that must NOT enter the
            // mutation queue (submitting identical content would dedup to the
            // active revision and log a spurious activation).
            return Ok(0);
        }
        evict_over_budget(&mut book, principal);

        let content = RulesRevisionContent::new(book);
        let rules_json = rules_json::to_canonical_string(&rules_json_codec::encode(&content))
            .map_err(|e| {
                AuthorError::new("internal", format!("canonical serialise failed: {e}"))
            })?;
        let mut hasher = Sha256::new();
        hasher.update(rules_json.as_bytes());
        let content_hash = format!("{:x}", hasher.finalize());

        let stored = StoredMutation {
            kind: MutationKind::RulesUpdate,
            payload: serde_json::json!({
                "rules-json": rules_json,
                "content-hash": content_hash,
                "correlation-id": correlation_id,
            }),
            correlation_id: Some(correlation_id.to_string()),
            issuer_sid: principal.to_string(),
            // Authored on behalf of an ordinary user, never with elevation:
            // when an administrator has frozen rule authoring, a companion
            // domain accepted from the tray must be refused exactly like a
            // rule the user typed.
            caller_is_elevated: false,
        };
        match self.executor.execute(stored, principal) {
            MutationOutcome::Completed(_) => {
                // Strictly after the executor returns: it applies the policy
                // synchronously, so tearing down any earlier would have the
                // application reconnect over the route still in force.
                if let Some(refresh) = self.flow_refresh.as_ref() {
                    refresh.refresh(&hosts_to_refresh(&landed));
                }
                Ok(authored)
            }
            // The executor already reports the Free rule cap, the tamper gate's
            // refusal while a security alert is unacknowledged, and every policy
            // error with a stable code. Pass it through verbatim rather than
            // collapsing it: "you are at the rule limit" and "acknowledge the
            // security alert first" need different answers from the user.
            MutationOutcome::Failed(e) => Err(AuthorError::new(&e.code, e.message)),
        }
    }
}

/// Drops the oldest app-authored rules when the book has outgrown their budget.
///
/// Runs on the write path rather than on a sweep: this is the only place the
/// set grows, so it is the only place it can overflow, and a user who never
/// accepts another suggestion never pays for a pass over their rules.
fn evict_over_budget(book: &mut CanonicalRuleBook, principal: &str) {
    let doomed = auto_rules_over_budget(book, MAX_AUTO_RULES);
    if doomed.is_empty() {
        return;
    }
    let drop_set: HashSet<&str> = doomed.iter().map(RuleId::as_str).collect();
    let retain = |set: &CanonicalRuleSet| {
        CanonicalRuleSet::from_rules(
            set.rules()
                .iter()
                .filter(|rule| !drop_set.contains(rule.id.as_str()))
                .cloned()
                .collect(),
        )
    };
    book.primary = retain(&book.primary);
    book.secondary = retain(&book.secondary);
    // Named, not just counted: a rule that vanished without the user asking is
    // exactly the thing they will come looking for in the log.
    tracing::info!(
        target: "nrr::auto-rules",
        sid = %principal,
        dropped = doomed.len(),
        budget = MAX_AUTO_RULES,
        sample = %doomed.iter().take(5).map(RuleId::as_str).collect::<Vec<_>>().join(", "),
        "app-authored rules over budget — dropped the oldest; a site that still needs one is offered it again",
    );
}

/// The hosts worth tearing connections down for once `landed` is applied: the
/// newly routed names, plus the anchors they were offered next to.
///
/// The anchor matters as much as the rule itself. A page that is already open
/// holds its sockets and asks for nothing new, so the rule changes nothing the
/// user can see; drop the anchor's connections and the page re-opens them,
/// which is what pulls the newly routed addresses in without a manual refresh.
fn hosts_to_refresh(landed: &[&AuthoredRule]) -> Vec<RoutedHost> {
    let mut hosts = Vec::with_capacity(landed.len() * 2);
    let mut seen = HashSet::new();
    for rule in landed {
        let routed = match rule.match_kind {
            AuthoredMatchKind::ExactHost => RoutedHost::Exact(rule.value.clone()),
            AuthoredMatchKind::SuffixDomain => RoutedHost::Suffix(rule.value.clone()),
        };
        if seen.insert(rule.value.clone()) {
            hosts.push(routed);
        }
        if !rule.anchor.is_empty() && seen.insert(rule.anchor.clone()) {
            hosts.push(RoutedHost::Exact(rule.anchor.clone()));
        }
    }
    hosts
}

/// `true` when the route's existing rules already do everything `rule` would.
///
/// An offer can be parked long before it is accepted, and the book moves on
/// meanwhile — the user types a rule, imports a preset, accepts a broader
/// offer. Checked here rather than at parking time because this is the one
/// place that holds the freshly read book.
fn already_covered(set: &CanonicalRuleSet, rule: &AuthoredRule) -> bool {
    set.rules()
        .iter()
        // An app-scoped rule covers that app alone, so it never subsumes a
        // rule meant for all traffic to the same name.
        .filter(|r| r.enabled && r.app_match.is_none())
        .any(
            |existing| match (&existing.address_match, rule.match_kind) {
                (Some(CanonicalAddressMatch::ExactFqdn(host)), AuthoredMatchKind::ExactHost) => {
                    host == &rule.value
                }
                // A suffix owns a whole subtree, so only a suffix or zone above it
                // subsumes it; an exact rule on the same name covers just that name.
                (Some(CanonicalAddressMatch::SuffixDomain(suffix)), _) => {
                    match_suffix_domain(&rule.value, suffix)
                }
                (Some(CanonicalAddressMatch::Zone(zone)), _) => match_zone(&rule.value, zone),
                _ => false,
            },
        )
}

/// Appends one rule to `book`, or returns `false` when the route's rules
/// already cover it — accepting a suggestion must never grow the rule set with
/// dead weight.
fn append_rule(
    book: &mut CanonicalRuleBook,
    rule: &AuthoredRule,
    reason: &AutoRuleReason,
    added: &str,
) -> bool {
    let address_match = match rule.match_kind {
        AuthoredMatchKind::ExactHost => CanonicalAddressMatch::ExactFqdn(rule.value.clone()),
        AuthoredMatchKind::SuffixDomain => CanonicalAddressMatch::SuffixDomain(rule.value.clone()),
    };
    let set = match rule.route {
        RouteRole::Primary => &mut book.primary,
        RouteRole::Secondary => &mut book.secondary,
    };
    // The identical match is refused even while disabled: the rule id is derived
    // from (route, match), so re-adding it would mint a second row under an id
    // the book already holds.
    if set
        .rules()
        .iter()
        .any(|r| r.address_match.as_ref() == Some(&address_match) && r.app_match.is_none())
        || already_covered(set, rule)
    {
        return false;
    }
    let mut rules: Vec<CanonicalRule> = set.rules().to_vec();
    rules.push(CanonicalRule {
        id: RuleId(auto_rule_id(rule.route, &address_match)),
        enabled: true,
        address_match: Some(address_match),
        app_match: None,
        comment: String::new(),
        action: RuleAction::Route,
        origin: Some(RuleOrigin::auto(reason.clone(), &rule.anchor, added)),
    });
    *set = CanonicalRuleSet::from_rules(rules);
    true
}

/// Deterministic rule id: the same (route, match) always yields the same id, so
/// re-authoring after an export/import round trip does not mint a second
/// identity for the same rule.
fn auto_rule_id(route: RouteRole, address_match: &CanonicalAddressMatch) -> String {
    let (kind, value) = match address_match {
        CanonicalAddressMatch::ExactFqdn(v) => ("exact", v.as_str()),
        CanonicalAddressMatch::SuffixDomain(v) => ("suffix", v.as_str()),
        CanonicalAddressMatch::Zone(v) => ("zone", v.as_str()),
        // Never produced by a companion suggestion; folded in so the helper
        // stays total rather than growing a panic path.
        CanonicalAddressMatch::ExactIp(_) => ("ip", ""),
    };
    let mut hasher = Sha256::new();
    hasher.update(route.slug().as_bytes());
    hasher.update([0]);
    hasher.update(kind.as_bytes());
    hasher.update([0]);
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(20);
    out.push_str("auto-");
    for byte in digest.iter().take(6) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Local `YYYY-MM-DD` for the provenance comment, through the audit writer's
/// calendar so the service has one, not two.
fn added_date(now: SystemTime) -> String {
    let compact = nrr_diagnostics::local_date_string(now);
    if compact.len() == 8 {
        format!("{}-{}-{}", &compact[0..4], &compact[4..6], &compact[6..8])
    } else {
        compact
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn empty_book() -> CanonicalRuleBook {
        CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(Vec::new()),
            secondary: CanonicalRuleSet::from_rules(Vec::new()),
        }
    }

    fn exact(value: &str) -> AuthoredRule {
        AuthoredRule {
            route: RouteRole::Secondary,
            match_kind: AuthoredMatchKind::ExactHost,
            value: value.to_string(),
            anchor: "site.example".to_string(),
        }
    }

    #[test]
    fn appending_stamps_provenance_and_lands_on_the_anchors_route() {
        let mut book = empty_book();
        assert!(append_rule(
            &mut book,
            &exact("cdn.example"),
            &AutoRuleReason::SiteCompanion,
            "2026-07-31"
        ));
        assert!(book.primary.is_empty());
        let rule = book.secondary.rules().first().expect("one rule");
        assert_eq!(
            rule.address_match,
            Some(CanonicalAddressMatch::ExactFqdn("cdn.example".into()))
        );
        let origin = rule.origin.as_ref().expect("origin");
        assert_eq!(origin.reason(), &AutoRuleReason::SiteCompanion);
        assert_eq!(origin.anchor(), "site.example");
        assert_eq!(origin.added(), "2026-07-31");
    }

    #[test]
    fn appending_the_same_match_twice_is_refused() {
        let mut book = empty_book();
        assert!(append_rule(
            &mut book,
            &exact("cdn.example"),
            &AutoRuleReason::SiteCompanion,
            "2026-07-31"
        ));
        assert!(!append_rule(
            &mut book,
            &exact("cdn.example"),
            &AutoRuleReason::UserConfirmed,
            "2026-08-01"
        ));
        assert_eq!(book.secondary.len(), 1);
    }

    fn suffix(value: &str) -> AuthoredRule {
        AuthoredRule {
            route: RouteRole::Secondary,
            match_kind: AuthoredMatchKind::SuffixDomain,
            value: value.to_string(),
            anchor: "site.example".to_string(),
        }
    }

    #[test]
    fn the_refresh_set_names_the_new_host_and_the_site_it_was_offered_next_to() {
        let cdn = suffix("cdn.example");
        let hosts = hosts_to_refresh(&[&cdn]);
        assert_eq!(
            hosts,
            vec![
                RoutedHost::Suffix("cdn.example".into()),
                // Dropping the anchor's connections is what makes the page ask
                // for its images again instead of sitting on loaded ones.
                RoutedHost::Exact("site.example".into()),
            ]
        );
    }

    #[test]
    fn two_suggestions_sharing_an_anchor_name_it_once() {
        let first = suffix("cdn.example");
        let second = suffix("media.example");
        let hosts = hosts_to_refresh(&[&first, &second]);
        assert_eq!(
            hosts
                .iter()
                .filter(|h| matches!(h, RoutedHost::Exact(v) if v == "site.example"))
                .count(),
            1
        );
        assert_eq!(hosts.len(), 3);
    }

    #[test]
    fn a_broader_suffix_refuses_everything_under_it() {
        let mut book = empty_book();
        assert!(append_rule(
            &mut book,
            &suffix("site.example"),
            &AutoRuleReason::SiteCompanion,
            "2026-07-31"
        ));
        // `*.site.example` already routes the apex and every host below it, so
        // both shapes underneath it are dead weight.
        assert!(!append_rule(
            &mut book,
            &suffix("www.site.example"),
            &AutoRuleReason::UserConfirmed,
            "2026-08-01"
        ));
        assert!(!append_rule(
            &mut book,
            &exact("img.site.example"),
            &AutoRuleReason::UserConfirmed,
            "2026-08-01"
        ));
        assert_eq!(book.secondary.len(), 1);
    }

    #[test]
    fn an_exact_rule_does_not_refuse_the_suffix_above_it() {
        let mut book = empty_book();
        assert!(append_rule(
            &mut book,
            &exact("site.example"),
            &AutoRuleReason::SiteCompanion,
            "2026-07-31"
        ));
        // The exact rule covers one name; the suffix covers the subtree the
        // exact rule leaves unrouted, so it is a real addition.
        assert!(append_rule(
            &mut book,
            &suffix("site.example"),
            &AutoRuleReason::UserConfirmed,
            "2026-08-01"
        ));
        assert_eq!(book.secondary.len(), 2);
    }

    #[test]
    fn suffix_rules_use_the_subdomain_match_shape() {
        let mut book = empty_book();
        append_rule(
            &mut book,
            &AuthoredRule {
                route: RouteRole::Secondary,
                match_kind: AuthoredMatchKind::SuffixDomain,
                value: "cdn-relay.example".into(),
                anchor: "site.example".into(),
            },
            &AutoRuleReason::SiteCompanion,
            "2026-07-31",
        );
        assert_eq!(
            book.secondary
                .rules()
                .first()
                .and_then(|r| r.address_match.clone()),
            Some(CanonicalAddressMatch::SuffixDomain(
                "cdn-relay.example".into()
            ))
        );
    }

    #[test]
    fn rule_ids_are_deterministic_and_route_scoped() {
        let m = CanonicalAddressMatch::ExactFqdn("cdn.example".into());
        assert_eq!(
            auto_rule_id(RouteRole::Secondary, &m),
            auto_rule_id(RouteRole::Secondary, &m)
        );
        assert_ne!(
            auto_rule_id(RouteRole::Secondary, &m),
            auto_rule_id(RouteRole::Primary, &m)
        );
        assert!(auto_rule_id(RouteRole::Secondary, &m).starts_with("auto-"));
    }

    #[test]
    fn added_date_is_the_dashed_utc_calendar_day() {
        assert_eq!(added_date(SystemTime::UNIX_EPOCH), "1970-01-01");
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_785_456_000);
        assert_eq!(added_date(t), "2026-07-31");
    }
}
