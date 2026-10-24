//! Which programs look names up past the system resolver, for the application
//! offer (see [`nrr_domain::own_resolver`]).
//!
//! Fed by the connection-trace ring with rows it has already named, on the
//! observer's drain tick: one map lookup per row, nothing on the traffic path.
//! A row's name can trail its connection by a DNS drain tick, so an unnamed
//! address is asked about once more before it counts, and only when a verdict
//! is within reach.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use nrr_domain::own_resolver::{
    is_nameable_destination, is_resolver_contact, resolves_names_itself, OwnResolverEvidence,
    OWN_RESOLVER_UNNAMED_CONFIRMATIONS,
};
use nrr_storage::doh_lockdown::DohTarget;

use crate::conn_observation_consumer::ConnectionTraceRecord;

/// Told `(sid, program, unnamed addresses)` once a program is judged.
pub type OwnResolverOfferFn = Arc<dyn Fn(&str, &str, &[IpAddr]) + Send + Sync>;

/// A program quiet this long starts over.
const WINDOW_MS: u64 = 10 * 60 * 1_000;
/// Two DNS drain ticks: a name that has not arrived by then is not coming.
const SETTLE_MS: u64 = 10_000;
const MAX_PROGRAMS: usize = 256;
const MAX_ADDRESSES_PER_PROGRAM: usize = 32;

/// The encrypted-DNS resolvers the product knows by address or by name.
#[derive(Debug, Default)]
pub struct KnownResolvers {
    addresses: HashSet<IpAddr>,
    hosts: HashSet<String>,
}

impl KnownResolvers {
    #[must_use]
    pub fn new(
        addresses: impl IntoIterator<Item = IpAddr>,
        hosts: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            addresses: addresses.into_iter().collect(),
            hosts: hosts.into_iter().map(|h| h.to_ascii_lowercase()).collect(),
        }
    }

    /// The built-in resolver list. A user's edits to the lockdown list change
    /// what is blocked, not what a resolver is.
    #[must_use]
    pub fn builtin() -> Self {
        let mut known = Self::default();
        for seed in crate::doh_seed::builtin_seed().entries {
            match seed.entry.target {
                DohTarget::Ip(ip) => {
                    known.addresses.insert(ip);
                }
                DohTarget::Host(host) => {
                    known.hosts.insert(host.to_ascii_lowercase());
                }
            }
        }
        known
    }

    fn lists(&self, rec: &ConnectionTraceRecord) -> bool {
        self.addresses.contains(&rec.remote.ip())
            || rec.remote_names.as_ref().is_some_and(|n| {
                n.names
                    .iter()
                    .any(|name| self.hosts.contains(&name.to_ascii_lowercase()))
            })
    }
}

/// One program judged to resolve names itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnResolverFinding {
    pub sid: String,
    pub program: String,
    /// The unnamed addresses it reached, ascending.
    pub unnamed: Vec<IpAddr>,
}

#[derive(Clone, Copy, Debug)]
struct Seen {
    named: bool,
    /// Asked about once more after settling and still unnamed.
    confirmed_unnamed: bool,
    first_ms: u64,
    last_ms: u64,
}

#[derive(Debug, Default)]
struct Tally {
    resolver_contacted: bool,
    addresses: HashMap<IpAddr, Seen>,
    last_ms: u64,
    offered: bool,
}

impl Tally {
    fn record(&mut self, remote: IpAddr, named: bool, at_ms: u64) {
        if let Some(seen) = self.addresses.get_mut(&remote) {
            seen.last_ms = at_ms;
            if named {
                seen.named = true;
                seen.confirmed_unnamed = false;
            }
            return;
        }
        if self.addresses.len() >= MAX_ADDRESSES_PER_PROGRAM {
            let oldest = self
                .addresses
                .iter()
                .min_by_key(|(_, s)| s.last_ms)
                .map(|(address, _)| *address);
            if let Some(oldest) = oldest {
                self.addresses.remove(&oldest);
            }
        }
        self.addresses.insert(
            remote,
            Seen {
                named,
                confirmed_unnamed: false,
                first_ms: at_ms,
                last_ms: at_ms,
            },
        );
    }

    fn evidence(&self) -> OwnResolverEvidence {
        let mut evidence = OwnResolverEvidence {
            resolver_contacted: self.resolver_contacted,
            ..OwnResolverEvidence::default()
        };
        for seen in self.addresses.values() {
            if seen.named {
                evidence.named_addresses += 1;
            } else if seen.confirmed_unnamed {
                evidence.unnamed_addresses += 1;
            }
        }
        evidence
    }

    /// Unnamed addresses old enough to be asked about once more.
    fn settled_unconfirmed(&self, now_ms: u64) -> Vec<IpAddr> {
        self.addresses
            .iter()
            .filter(|(_, s)| {
                !s.named && !s.confirmed_unnamed && now_ms.saturating_sub(s.first_ms) >= SETTLE_MS
            })
            .map(|(address, _)| *address)
            .collect()
    }

    fn unnamed(&self) -> Vec<IpAddr> {
        let mut out: Vec<IpAddr> = self
            .addresses
            .iter()
            .filter(|(_, s)| s.confirmed_unnamed)
            .map(|(address, _)| *address)
            .collect();
        out.sort();
        out
    }
}

pub struct OwnResolverWatch {
    known: KnownResolvers,
    programs: Mutex<HashMap<(String, String), Tally>>,
}

impl OwnResolverWatch {
    #[must_use]
    pub fn new(known: KnownResolvers) -> Self {
        Self {
            known,
            programs: Mutex::new(HashMap::new()),
        }
    }

    /// One traced row. `named_now` asks the namer again about an address; it
    /// is called at most once per address. Answers once per program and window.
    pub fn observe(
        &self,
        rec: &ConnectionTraceRecord,
        now_ms: u64,
        named_now: impl Fn(IpAddr) -> bool,
    ) -> Option<OwnResolverFinding> {
        let sid = rec
            .user_sid
            .as_deref()
            .filter(|s| !s.is_empty() && !nrr_platform_api::types::is_service_account_sid(s))?;
        let path = rec.process_path.as_deref()?;
        if !crate::conn_observation_consumer::offerable_program(path) {
            return None;
        }
        let program = nrr_domain::app_offer::program_name(path);
        let ip = rec.remote.ip();
        let contact = is_resolver_contact(rec.remote, self.known.lists(rec));
        if program.is_empty() || (!contact && !is_nameable_destination(ip)) {
            return None;
        }
        let at_ms = rec.observed_unix_ms.unwrap_or(now_ms);
        let named = rec
            .remote_names
            .as_ref()
            .is_some_and(|n| !n.names.is_empty() || n.fake_ip);

        let mut programs = self.programs.lock().unwrap_or_else(|p| p.into_inner());
        let key = (sid.to_owned(), program.clone());
        if !programs.contains_key(&key) && programs.len() >= MAX_PROGRAMS {
            let quietest = programs
                .iter()
                .min_by_key(|(_, t)| t.last_ms)
                .map(|(k, _)| k.clone());
            if let Some(quietest) = quietest {
                programs.remove(&quietest);
            }
        }
        let tally = programs.entry(key).or_default();
        if tally.last_ms != 0 && at_ms.saturating_sub(tally.last_ms) > WINDOW_MS {
            *tally = Tally::default();
        }
        tally.last_ms = tally.last_ms.max(at_ms);
        if contact {
            tally.resolver_contacted = true;
        } else {
            tally.record(ip, named, at_ms);
        }
        if tally.offered || !tally.resolver_contacted {
            return None;
        }
        let settled = tally.settled_unconfirmed(now_ms);
        let within_reach = tally.evidence().unnamed_addresses + settled.len()
            >= OWN_RESOLVER_UNNAMED_CONFIRMATIONS;
        if !within_reach {
            return None;
        }
        // The namer may read a store: asked with the map unlocked.
        drop(programs);
        let answers: Vec<(IpAddr, bool)> = settled
            .into_iter()
            .map(|address| (address, named_now(address)))
            .collect();
        let mut programs = self.programs.lock().unwrap_or_else(|p| p.into_inner());
        let tally = programs.get_mut(&(sid.to_owned(), program.clone()))?;
        if tally.offered {
            return None;
        }
        for (address, named_late) in answers {
            if let Some(seen) = tally.addresses.get_mut(&address) {
                seen.named |= named_late;
                seen.confirmed_unnamed = !seen.named;
            }
        }
        if !resolves_names_itself(tally.evidence()) {
            return None;
        }
        tally.offered = true;
        Some(OwnResolverFinding {
            sid: sid.to_owned(),
            program,
            unnamed: tally.unnamed(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn_trace_names::RemoteNames;
    use nrr_platform_api::conn_observe::egress::{EgressInterface, EgressRole};
    use nrr_platform_api::conn_observe::{ConnectionVerdict, TransportProtocol};
    use std::net::{Ipv4Addr, SocketAddr};

    const SID: &str = "S-1-5-21-1-2-3-1001";
    const APP: &str = r"C:\Program Files\Fetcher\fetcher.exe";
    const RESOLVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 53);

    fn watch() -> OwnResolverWatch {
        OwnResolverWatch::new(KnownResolvers::new(
            [IpAddr::V4(RESOLVER)],
            ["dns.resolver.example".to_owned()],
        ))
    }

    fn row(remote: Ipv4Addr, port: u16, names: &[&str], at_ms: u64) -> ConnectionTraceRecord {
        ConnectionTraceRecord {
            process_path: Some(APP.to_owned()),
            user_sid: Some(SID.to_owned()),
            protocol: TransportProtocol::Tcp,
            local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 50_000),
            remote: SocketAddr::new(IpAddr::V4(remote), port),
            egress: EgressInterface {
                ifindex: 1,
                role: EgressRole::Primary,
            },
            verdict: ConnectionVerdict::Permit,
            blocked_by_nrr: None,
            nrr_drop_spec_id: None,
            nrr_block_reason: None,
            observed_unix_ms: Some(at_ms),
            remote_names: (!names.is_empty()).then(|| {
                Arc::new(RemoteNames {
                    names: names.iter().map(|n| (*n).to_owned()).collect(),
                    total: names.len() as u32,
                    fake_ip: false,
                })
            }),
        }
    }

    fn site(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, last)
    }

    /// Feeds a resolver contact and `unnamed` unnamed sites at t=0, then one
    /// more row past the settle delay; returns what the last row answered.
    fn run(
        w: &OwnResolverWatch,
        resolver: ConnectionTraceRecord,
        unnamed: u8,
    ) -> Option<OwnResolverFinding> {
        assert_eq!(w.observe(&resolver, 0, |_| false), None);
        for last in 1..=unnamed {
            assert_eq!(w.observe(&row(site(last), 443, &[], 0), 0, |_| false), None);
        }
        w.observe(&row(site(1), 443, &[], SETTLE_MS), SETTLE_MS, |_| false)
    }

    #[test]
    fn a_program_with_its_own_resolver_is_found_once() {
        let w = watch();
        let found = run(&w, row(RESOLVER, 443, &[], 0), 3).expect("judged");
        assert_eq!(found.sid, SID);
        assert_eq!(found.program, "fetcher.exe");
        assert_eq!(found.unnamed.len(), 3);
        assert_eq!(
            w.observe(
                &row(site(9), 443, &[], SETTLE_MS * 2),
                SETTLE_MS * 2,
                |_| false
            ),
            None,
            "one finding per window"
        );
    }

    #[test]
    fn a_resolver_known_by_name_or_the_tls_port_counts() {
        let by_name = row(
            Ipv4Addr::new(198, 51, 100, 1),
            443,
            &["dns.resolver.example"],
            0,
        );
        assert!(run(&watch(), by_name, 3).is_some());
        let dot = row(Ipv4Addr::new(198, 51, 100, 2), 853, &[], 0);
        assert!(run(&watch(), dot, 3).is_some());
    }

    /// `nslookup` against a server of its own, a c-ares program with its own
    /// servers, a hypervisor relaying its guests' lookups: plain DNS past ours.
    #[test]
    fn plain_dns_to_a_server_of_its_own_counts() {
        let router = row(Ipv4Addr::new(192, 168, 1, 1), 53, &[], 0);
        assert!(run(&watch(), router, 3).is_some());
        let ours = row(Ipv4Addr::LOCALHOST, 53, &[], 0);
        assert_eq!(
            run(&watch(), ours, 3),
            None,
            "asking ours is the system's way"
        );
    }

    #[test]
    fn unnamed_sites_without_a_resolver_are_not_a_finding() {
        let unrelated = row(Ipv4Addr::new(198, 51, 100, 3), 443, &[], 0);
        assert_eq!(run(&watch(), unrelated, 8), None);
    }

    #[test]
    fn a_name_that_arrives_late_is_still_a_name() {
        let w = watch();
        assert_eq!(w.observe(&row(RESOLVER, 443, &[], 0), 0, |_| false), None);
        for last in 1..=4 {
            w.observe(&row(site(last), 443, &[], 0), 0, |_| false);
        }
        let late = w.observe(&row(site(1), 443, &[], SETTLE_MS), SETTLE_MS, |_| true);
        assert_eq!(late, None, "the DNS drain caught up: every site has a name");
    }

    #[test]
    fn nothing_is_judged_before_names_had_time_to_arrive() {
        let w = watch();
        w.observe(&row(RESOLVER, 443, &[], 0), 0, |_| false);
        for last in 1..=5 {
            assert_eq!(w.observe(&row(site(last), 443, &[], 0), 0, |_| false), None);
        }
    }

    #[test]
    fn os_programs_and_service_accounts_are_never_watched() {
        let w = watch();
        let mut system = row(RESOLVER, 443, &[], 0);
        system.process_path = Some(r"C:\Windows\System32\svchost.exe".to_owned());
        assert_eq!(w.observe(&system, 0, |_| false), None);
        let mut service = row(RESOLVER, 443, &[], 0);
        service.user_sid = Some("S-1-5-18".to_owned());
        assert_eq!(w.observe(&service, 0, |_| false), None);
        assert!(w
            .programs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty());
    }

    #[test]
    fn a_program_that_names_most_of_its_sites_uses_the_system() {
        let w = watch();
        w.observe(&row(RESOLVER, 443, &[], 0), 0, |_| false);
        for last in 1..=3 {
            w.observe(&row(site(last), 443, &[], 0), 0, |_| false);
        }
        for last in 10..=13 {
            w.observe(&row(site(last), 443, &["www.example"], 0), 0, |_| false);
        }
        assert_eq!(
            w.observe(&row(site(1), 443, &[], SETTLE_MS), SETTLE_MS, |_| false),
            None
        );
    }
}
