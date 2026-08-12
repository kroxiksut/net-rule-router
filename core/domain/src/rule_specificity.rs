//! How specifically a rule set claims a hostname, as a comparable score.
//!
//! Two rule sets can both claim the same address — one by name, the other by a
//! wide suffix — and something has to decide which claim is the stronger one.
//! The shared-IP census is the caller that needs this: an address claimed by
//! `aistudio.google.com` on the additional route and by `*.google.com` on the
//! main one is not a tie, and treating it as one let the wide rule cancel the
//! narrow one's pin.
//!
//! Pure and total: no I/O, no clock, ordering fully determined by the inputs.

use crate::canonical::{CanonicalAddressMatch, CanonicalRuleSet};
use crate::decision_matching::{match_suffix_domain, match_zone};

/// Strength of a rule set's claim on one hostname. Ordered least to most
/// specific, so `Ord` answers "whose claim wins" directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MatchSpecificity {
    /// A zone rule (`.ru`, `.intra`) covers it. The widest claim there is.
    Zone {
        /// Longer zone label = narrower claim, so it sorts above a short one.
        label_len: usize,
    },
    /// A suffix rule (`*.example.com`) covers it — narrower than a zone,
    /// wider than a name.
    SuffixDomain {
        /// Longer suffix = narrower claim (`*.cdn.example.com` beats
        /// `*.example.com`).
        label_len: usize,
    },
    /// The rule names the host outright. Nothing is more specific.
    ExactFqdn,
}

/// The strongest claim `set` has on `hostname`, or `None` when nothing in it
/// matches by address.
///
/// Address matches only: an app-scoped rule says nothing about who owns an
/// address, and an exact-IP rule claims an address rather than a name — the
/// caller comparing two hostnames' claims must not read either as coverage.
pub fn match_specificity(hostname: &str, set: &CanonicalRuleSet) -> Option<MatchSpecificity> {
    set.rules()
        .iter()
        .filter(|rule| rule.enabled)
        .filter_map(|rule| match &rule.address_match {
            Some(CanonicalAddressMatch::ExactFqdn(name)) if name == hostname => {
                Some(MatchSpecificity::ExactFqdn)
            }
            Some(CanonicalAddressMatch::SuffixDomain(label))
                if match_suffix_domain(hostname, label) =>
            {
                Some(MatchSpecificity::SuffixDomain {
                    label_len: label.len(),
                })
            }
            Some(CanonicalAddressMatch::Zone(label)) if match_zone(hostname, label) => {
                Some(MatchSpecificity::Zone {
                    label_len: label.len(),
                })
            }
            _ => None,
        })
        .max()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::CanonicalRule;
    use crate::{RuleAction, RuleId};

    fn rule(id: &str, address_match: CanonicalAddressMatch) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.to_string()),
            enabled: true,
            address_match: Some(address_match),
            app_match: None,
            comment: String::new(),
            action: RuleAction::Route,
            origin: None,
        }
    }

    fn set(rules: Vec<CanonicalRule>) -> CanonicalRuleSet {
        CanonicalRuleSet::from_rules(rules)
    }

    #[test]
    fn a_name_beats_a_suffix_beats_a_zone() {
        assert!(MatchSpecificity::ExactFqdn > MatchSpecificity::SuffixDomain { label_len: 99 });
        assert!(
            MatchSpecificity::SuffixDomain { label_len: 1 }
                > MatchSpecificity::Zone { label_len: 99 }
        );
    }

    #[test]
    fn a_longer_suffix_is_the_narrower_claim() {
        let wide = set(vec![rule(
            "r1",
            CanonicalAddressMatch::SuffixDomain("google.com".into()),
        )]);
        let narrow = set(vec![rule(
            "r2",
            CanonicalAddressMatch::SuffixDomain("ai.google.com".into()),
        )]);
        let host = "studio.ai.google.com";
        assert!(match_specificity(host, &narrow) > match_specificity(host, &wide));
    }

    #[test]
    fn the_strongest_claim_in_a_set_is_the_one_reported() {
        let mixed = set(vec![
            rule("z", CanonicalAddressMatch::Zone("com".into())),
            rule(
                "s",
                CanonicalAddressMatch::SuffixDomain("google.com".into()),
            ),
            rule(
                "e",
                CanonicalAddressMatch::ExactFqdn("aistudio.google.com".into()),
            ),
        ]);
        assert_eq!(
            match_specificity("aistudio.google.com", &mixed),
            Some(MatchSpecificity::ExactFqdn)
        );
    }

    #[test]
    fn an_exact_rule_on_the_additional_route_outranks_a_wide_one_on_the_main() {
        // The case this exists for: both sets claim the same host, and the
        // narrow claim has to win.
        let secondary = set(vec![rule(
            "s1",
            CanonicalAddressMatch::ExactFqdn("aistudio.google.com".into()),
        )]);
        let primary = set(vec![rule(
            "p1",
            CanonicalAddressMatch::SuffixDomain("google.com".into()),
        )]);
        assert!(
            match_specificity("aistudio.google.com", &secondary)
                > match_specificity("workspace.google.com", &primary)
        );
    }

    #[test]
    fn no_address_match_is_no_claim() {
        let unrelated = set(vec![rule(
            "r",
            CanonicalAddressMatch::ExactFqdn("other.example".into()),
        )]);
        assert_eq!(match_specificity("a.nel.cloudflare.com", &unrelated), None);
        // A disabled rule claims nothing either.
        let mut disabled = rule("d", CanonicalAddressMatch::ExactFqdn("host.example".into()));
        disabled.enabled = false;
        assert_eq!(
            match_specificity("host.example", &set(vec![disabled])),
            None
        );
    }

    #[test]
    fn a_suffix_covers_the_apex_it_names() {
        let s = set(vec![rule(
            "r",
            CanonicalAddressMatch::SuffixDomain("example.com".into()),
        )]);
        assert!(match_specificity("example.com", &s).is_some());
        assert!(match_specificity("cdn.example.com", &s).is_some());
        assert_eq!(match_specificity("notexample.com", &s), None);
    }
}
