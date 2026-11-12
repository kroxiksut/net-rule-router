//! Diagnostic DNS identities, bounded in count and lifetime.
//! Shared addresses remain ambiguous; this memory never drives enforcement.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, OnceLock};

use crate::boot_clock::BootInstant;
use crate::recent_rule_addresses::{ENTRY_TTL, MAX_ENTRIES};

const MAX_NAMES_PER_ADDRESS: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostNameResolution {
    Unknown,
    Unique(String),
    Ambiguous,
}

#[derive(Default)]
struct AddressNames {
    names: HashMap<String, BootInstant>,
    overflow: Option<BootInstant>,
}

impl AddressNames {
    fn record(&mut self, hostname: &str, now: BootInstant) {
        self.names
            .retain(|_, at| now.saturating_duration_since(*at) < ENTRY_TTL);
        if self.names.len() >= MAX_NAMES_PER_ADDRESS && !self.names.contains_key(hostname) {
            if let Some(victim) = self
                .names
                .iter()
                .min_by(|(a, at_a), (b, at_b)| at_a.cmp(at_b).then_with(|| a.cmp(b)))
                .map(|(name, _)| name.clone())
            {
                self.names.remove(&victim);
            }
            self.overflow = Some(now);
        }
        self.names.insert(hostname.to_owned(), now);
    }
}

/// Global ambiguity and per-principal DNS evidence, never enforcement data.
#[derive(Default)]
pub struct ObservedHostNames {
    global: Mutex<HashMap<Ipv4Addr, AddressNames>>,
    owners: Mutex<HashMap<(String, Ipv4Addr), AddressNames>>,
}

impl ObservedHostNames {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Remember every address `hostname` just resolved to.
    pub fn record(&self, hostname: &str, addresses: &[Ipv4Addr]) {
        let hostname = hostname.trim_end_matches('.');
        if hostname.is_empty() || hostname.len() > 253 || !hostname.is_ascii() {
            return;
        }
        let hostname = hostname.to_ascii_lowercase();
        let now = BootInstant::now();
        let mut entries = self.global.lock().unwrap_or_else(|p| p.into_inner());
        for ip in addresses.iter().take(64) {
            if entries.len() >= MAX_ENTRIES && !entries.contains_key(ip) {
                if let Some(victim) = entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.names.values().copied().max())
                    .map(|(ip, _)| *ip)
                {
                    entries.remove(&victim);
                }
            }
            entries.entry(*ip).or_default().record(&hostname, now);
        }
    }

    pub fn record_for(&self, owner: &str, hostname: &str, addresses: &[Ipv4Addr]) {
        self.record(hostname, addresses);
        let hostname = hostname.trim_end_matches('.');
        if owner.is_empty()
            || owner.len() > 256
            || hostname.is_empty()
            || hostname.len() > 253
            || !hostname.is_ascii()
        {
            return;
        }
        let hostname = hostname.to_ascii_lowercase();
        let now = BootInstant::now();
        let mut entries = self.owners.lock().unwrap_or_else(|p| p.into_inner());
        for ip in addresses.iter().take(64) {
            let key = (owner.to_owned(), *ip);
            if entries.len() >= MAX_ENTRIES && !entries.contains_key(&key) {
                if let Some(victim) = entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.names.values().copied().max())
                    .map(|(key, _)| key.clone())
                {
                    entries.remove(&victim);
                }
            }
            entries.entry(key).or_default().record(&hostname, now);
        }
    }

    #[must_use]
    pub fn resolve_for(&self, owner: &str, ip: Ipv4Addr) -> HostNameResolution {
        let global = self.resolve(ip);
        if global == HostNameResolution::Ambiguous {
            return HostNameResolution::Ambiguous;
        }
        let entries = self.owners.lock().unwrap_or_else(|p| p.into_inner());
        let owned = Self::resolution(entries.get(&(owner.to_owned(), ip)));
        if let (HostNameResolution::Unique(global), HostNameResolution::Unique(owned)) =
            (&global, &owned)
        {
            if global != owned {
                return HostNameResolution::Ambiguous;
            }
        }
        owned
    }

    /// Owner-attributed DNS candidates for independent probes, never flow names.
    #[must_use]
    pub fn probe_names_for(&self, owner: &str, ip: Ipv4Addr) -> Vec<String> {
        let entries = self.owners.lock().unwrap_or_else(|p| p.into_inner());
        let Some(entry) = entries.get(&(owner.to_owned(), ip)) else {
            return Vec::new();
        };
        let mut names: Vec<_> = entry
            .names
            .iter()
            .filter(|(_, at)| at.elapsed() < ENTRY_TTL)
            .filter(|(name, _)| {
                !matches!(
                    nrr_domain::rule_value_validation::validate_rule_value("domain", name),
                    nrr_domain::rule_value_validation::RuleValueValidation::Error { .. }
                )
            })
            .map(|(name, _)| name.clone())
            .collect();
        names.sort();
        names.truncate(MAX_NAMES_PER_ADDRESS);
        names
    }

    /// A fresh unique name; a shared address deliberately has none.
    #[must_use]
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<String> {
        match self.resolve(ip) {
            HostNameResolution::Unique(host) => Some(host),
            _ => None,
        }
    }

    #[must_use]
    pub fn resolve(&self, ip: Ipv4Addr) -> HostNameResolution {
        let entries = self.global.lock().unwrap_or_else(|p| p.into_inner());
        Self::resolution(entries.get(&ip))
    }

    fn resolution(entry: Option<&AddressNames>) -> HostNameResolution {
        let Some(entry) = entry else {
            return HostNameResolution::Unknown;
        };
        if entry.overflow.is_some_and(|at| at.elapsed() < ENTRY_TTL) {
            return HostNameResolution::Ambiguous;
        }
        let mut names = entry
            .names
            .iter()
            .filter(|(_, at)| at.elapsed() < ENTRY_TTL)
            .map(|(name, _)| name);
        match (names.next(), names.next()) {
            (Some(name), None) => HostNameResolution::Unique(name.clone()),
            (Some(_), Some(_)) => HostNameResolution::Ambiguous,
            _ => HostNameResolution::Unknown,
        }
    }

    /// Addresses `name` or a name under it was seen at, newest first. For a
    /// diagnostic probe only — never for anything that enforces.
    #[must_use]
    pub fn addresses_under(&self, name: &str, limit: usize) -> Vec<Ipv4Addr> {
        let entries = self.global.lock().unwrap_or_else(|p| p.into_inner());
        let suffix = format!(".{name}");
        let mut matches: Vec<_> = entries
            .iter()
            .filter_map(|(ip, entry)| {
                entry
                    .names
                    .iter()
                    .filter(|(host, at)| {
                        at.elapsed() < ENTRY_TTL
                            && (host.as_str() == name || host.ends_with(&suffix))
                    })
                    .map(|(_, at)| *at)
                    .max()
                    .map(|at| (*ip, at))
            })
            .collect();
        matches.sort_by_key(|(_, at)| std::cmp::Reverse(*at));
        matches
            .into_iter()
            .take(limit.min(MAX_ENTRIES))
            .map(|(ip, _)| ip)
            .collect()
    }

    #[must_use]
    pub fn addresses_under_for(&self, owner: &str, name: &str, limit: usize) -> Vec<Ipv4Addr> {
        self.addresses_matching_for(owner, name, limit, true)
    }

    /// Fresh addresses witnessed for this owner's exact name, newest first.
    #[must_use]
    pub fn addresses_exact_for(&self, owner: &str, name: &str, limit: usize) -> Vec<Ipv4Addr> {
        self.addresses_matching_for(owner, name, limit, false)
    }

    fn addresses_matching_for(
        &self,
        owner: &str,
        name: &str,
        limit: usize,
        include_subdomains: bool,
    ) -> Vec<Ipv4Addr> {
        let entries = self.owners.lock().unwrap_or_else(|p| p.into_inner());
        let suffix = format!(".{name}");
        let mut matches: Vec<_> = entries
            .iter()
            .filter(|((sid, _), _)| sid == owner)
            .filter_map(|((_, ip), entry)| {
                entry
                    .names
                    .iter()
                    .filter(|(host, at)| {
                        at.elapsed() < ENTRY_TTL
                            && (host.as_str() == name
                                || (include_subdomains && host.ends_with(&suffix)))
                    })
                    .map(|(_, at)| *at)
                    .max()
                    .map(|at| (*ip, at))
            })
            .collect();
        matches.sort_by_key(|(_, at)| std::cmp::Reverse(*at));
        matches
            .into_iter()
            .take(limit.min(MAX_ENTRIES))
            .map(|(ip, _)| ip)
            .collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.global.lock().map(|entries| entries.len()).unwrap_or(0)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

static GLOBAL_OBSERVED_HOST_NAMES: OnceLock<Arc<ObservedHostNames>> = OnceLock::new();

/// Process-wide index. One per service run, shared by the DNS observation
/// consumer that fills it and the connection observer that reads it. Tests
/// construct [`ObservedHostNames`] directly and never touch this.
pub fn global_observed_host_names() -> Arc<ObservedHostNames> {
    Arc::clone(GLOBAL_OBSERVED_HOST_NAMES.get_or_init(|| Arc::new(ObservedHostNames::new())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_users_unique_dns_name_is_not_the_other_users_visit() {
        let names = ObservedHostNames::new();
        let address = Ipv4Addr::new(203, 0, 113, 11);
        names.record_for("alice", "alice-visit.example", &[address]);
        assert_eq!(
            names.resolve_for("alice", address),
            HostNameResolution::Unique("alice-visit.example".into())
        );
        assert_eq!(
            names.resolve_for("bob", address),
            HostNameResolution::Unknown
        );
    }

    #[test]
    fn a_newly_visited_cdn_name_is_not_lost_after_the_owners_eight_name_window_fills() {
        let names = ObservedHostNames::new();
        let address = Ipv4Addr::new(203, 0, 113, 19);
        for index in 0..MAX_NAMES_PER_ADDRESS {
            names.record_for("alice", &format!("old-{index}.example"), &[address]);
        }
        names.record_for("bob", "another-users-visit.example", &[address]);
        names.record_for("alice", "fresh-visit.example", &[address]);
        let candidates = names.probe_names_for("alice", address);
        assert!(
            candidates.iter().any(|host| host == "fresh-visit.example"),
            "the latest visit must remain available for its own independent confirmation"
        );
        assert_eq!(
            names.addresses_under("fresh-visit.example", 1),
            vec![address],
            "later diagnostic rechecks must retain the fresh name's address too"
        );
        assert!(candidates.len() <= MAX_NAMES_PER_ADDRESS);
        assert!(!candidates
            .iter()
            .any(|host| host == "another-users-visit.example"));
        assert_eq!(
            names.resolve_for("alice", address),
            HostNameResolution::Ambiguous
        );
    }

    #[test]
    fn a_cached_name_ages_out_across_sleep_and_cannot_name_the_new_tenant() {
        let names = ObservedHostNames::new();
        let address = Ipv4Addr::new(203, 0, 113, 8);
        names.record("old.example", &[address]);
        crate::boot_clock::simulate_sleep(ENTRY_TTL + std::time::Duration::from_secs(1));
        assert_eq!(names.resolve(address), HostNameResolution::Unknown);
        names.record("new.example", &[address]);
        assert_eq!(names.lookup(address).as_deref(), Some("new.example"));
    }

    #[test]
    fn overflowing_cdn_tenants_remains_ambiguous_instead_of_forgetting_into_a_guess() {
        let names = ObservedHostNames::new();
        let address = Ipv4Addr::new(203, 0, 113, 9);
        for index in 0..MAX_NAMES_PER_ADDRESS + 2 {
            names.record(&format!("h{index}.example"), &[address]);
        }
        assert_eq!(names.resolve(address), HostNameResolution::Ambiguous);
        assert_eq!(names.lookup(address), None);
    }

    #[test]
    fn a_shared_cdn_address_never_assigns_the_last_hostname_to_a_connection() {
        let names = ObservedHostNames::new();
        let address = Ipv4Addr::new(203, 0, 113, 7);
        names.record("visited.example", &[address]);
        names.record("unrelated.example", &[address]);
        assert_eq!(
            names.lookup(address),
            None,
            "an IP cannot identify either tenant"
        );
        assert_eq!(names.addresses_under("visited.example", 8), vec![address]);
    }

    #[test]
    fn addresses_under_a_name_cover_its_subtree_and_nothing_beside_it() {
        let names = ObservedHostNames::new();
        names.record("00.img.cdn.example", &[Ipv4Addr::new(192, 0, 2, 1)]);
        names.record("cdn.example", &[Ipv4Addr::new(192, 0, 2, 2)]);
        names.record("notcdn.example", &[Ipv4Addr::new(192, 0, 2, 3)]);
        let mut found = names.addresses_under("cdn.example", 8);
        found.sort();
        assert_eq!(
            found,
            vec![Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2)]
        );
        assert_eq!(names.addresses_under("cdn.example", 1).len(), 1, "capped");
    }

    #[test]
    fn a_recorded_host_is_found_by_any_of_its_addresses() {
        let idx = ObservedHostNames::new();
        let a = Ipv4Addr::new(203, 0, 113, 144);
        let b = Ipv4Addr::new(203, 0, 113, 145);
        assert!(idx.is_empty());
        idx.record("forum.talk.example", &[a, b]);
        assert_eq!(idx.lookup(a).as_deref(), Some("forum.talk.example"));
        assert_eq!(idx.lookup(b).as_deref(), Some("forum.talk.example"));
        assert_eq!(idx.len(), 2);
        assert_eq!(idx.lookup(Ipv4Addr::new(100, 64, 1, 1)), None);
    }

    #[test]
    fn an_empty_name_or_address_list_records_nothing() {
        let idx = ObservedHostNames::new();
        idx.record("", &[Ipv4Addr::new(100, 64, 1, 4)]);
        idx.record("host.example", &[]);
        assert!(idx.is_empty());
    }
}
