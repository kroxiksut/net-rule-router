//! Where a `site.*` rule has been seen: the `site.<zone>` names its
//! enforcement twins are built from.
//!
//! Enforcement fans out over suffix rules, so the rules provider hands it each
//! `site.*` rule as `*.site.<zone>` for every zone the FQDN cache knows the
//! site under ([`CanonicalRuleBook::with_any_zone_sites`]). The list changes
//! only when a zone appears for the first time; the DNS observer says so with
//! [`note_new_zone`], which moves [`generation`] and so every provider's
//! cached book.
//!
//! [`CanonicalRuleBook::with_any_zone_sites`]: nrr_domain::canonical::CanonicalRuleBook::with_any_zone_sites

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use nrr_domain::canonical::CanonicalRuleBook;
use nrr_domain::decision_matching::match_any_zone_domain;

use crate::fqdn_cache_lookup::FqdnCacheLookup;

/// Hosts read per rule; a site lives under a handful of zones, and its hosts
/// beyond this many add no zone the first ones did not.
const HOSTS_READ_PER_RULE: usize = 2048;

static SOURCE: OnceLock<Arc<dyn FqdnCacheLookup>> = OnceLock::new();
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// The cache the twins are read from. Set once at boot; a second call is
/// ignored, since every service builds its cache over the same store.
pub fn install(cache: Arc<dyn FqdnCacheLookup>) {
    let _ = SOURCE.set(cache);
}

/// Moves whenever the sites seen may have grown.
pub fn generation() -> u64 {
    GENERATION.load(Ordering::Acquire)
}

/// A host covered by a `site.*` rule was cached under a zone `book` has no
/// twin for yet.
pub fn note_new_zone() {
    GENERATION.fetch_add(1, Ordering::AcqRel);
}

/// Whether `hostname` is covered by a `site.*` rule of `book` under a zone
/// the book has no twin for: the moment [`note_new_zone`] is for.
pub fn opens_a_zone(book: &CanonicalRuleBook, hostname: &str) -> bool {
    book.primary
        .rules()
        .iter()
        .chain(book.secondary.rules())
        .filter(|r| r.enabled)
        .filter_map(|r| match &r.address_match {
            Some(nrr_domain::canonical::CanonicalAddressMatch::AnyZoneDomain(base)) => {
                match_any_zone_domain(hostname, base)
            }
            _ => None,
        })
        .any(|named| !book.names_suffix_outright(named))
}

/// `book` with its `site.*` rules' twins, when a cache is installed and the
/// book has such rules.
pub fn expand(book: CanonicalRuleBook) -> CanonicalRuleBook {
    let Some(cache) = SOURCE.get() else {
        return book;
    };
    if !book.has_any_zone_rules() {
        return book;
    }
    book.with_any_zone_sites(|base| named_sites(cache.as_ref(), base))
}

/// The `site.<zone>` names the cache knows `base` under.
pub fn named_sites(cache: &dyn FqdnCacheLookup, base: &str) -> Vec<String> {
    cache
        .hostnames_for_any_zone(base, HOSTS_READ_PER_RULE)
        .iter()
        .filter_map(|host| match_any_zone_domain(host, base).map(str::to_owned))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fqdn_cache_lookup::MockFqdnCacheLookup;
    use nrr_domain::canonical::{CanonicalAddressMatch, CanonicalRule, CanonicalRuleSet};
    use nrr_domain::{RuleAction, RuleId};
    use std::net::Ipv4Addr;

    fn rule(id: &str, address: CanonicalAddressMatch) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: Some(address),
            app_match: None,
            comment: String::new(),
            action: RuleAction::Route,
            origin: None,
        }
    }

    #[test]
    fn the_sites_are_the_zones_the_cache_knows_the_site_under() {
        let cache = MockFqdnCacheLookup::new();
        for host in [
            "autodesk.com",
            "webpub.autodesk.com",
            "Accounts.Autodesk.Co.Uk",
            "autodesk.com.mirror.example",
            "notautodesk.net",
        ] {
            cache.set_ips(host, vec![Ipv4Addr::new(192, 0, 2, 1)]);
        }
        let mut sites = named_sites(&cache, "autodesk");
        sites.sort();
        assert_eq!(sites, ["autodesk.co.uk", "autodesk.com", "autodesk.com"]);
    }

    #[test]
    fn only_a_zone_without_a_twin_moves_the_generation() {
        let book = CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![rule(
                "p",
                CanonicalAddressMatch::SuffixDomain("autodesk.by".into()),
            )]),
            secondary: CanonicalRuleSet::from_rules(vec![rule(
                "s",
                CanonicalAddressMatch::AnyZoneDomain("autodesk".into()),
            )]),
        };
        assert!(opens_a_zone(&book, "www.autodesk.com"));
        assert!(!opens_a_zone(&book, "www.autodesk.by"));
        assert!(!opens_a_zone(&book, "example.com"));
        let expanded = book.with_any_zone_sites(|_| vec!["autodesk.com".into()]);
        assert!(!opens_a_zone(&expanded, "www.autodesk.com"));
        assert!(opens_a_zone(&expanded, "autodesk.net"));
    }
}
