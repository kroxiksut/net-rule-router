//! Evidence about DNS compatibility, independent of notification mutes and routing policy.

use std::collections::{BTreeMap, BTreeSet};

use nrr_shared::RouteRole;

pub const MAX_PROGRAMS: usize = 64;
pub const MAX_PROGRAM_BYTES: usize = 4096;
pub const RECHECK_AFTER_MS: u64 = 10 * 60 * 1000;
pub const RETAIN_FOR_MS: u64 = 24 * 60 * 60 * 1000;
pub const BROWSER_CONFIRMATION_MS: u64 = 60_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reason {
    ResolverContact,
    OurDnsBlock,
    StrictBrowserDns,
    LocalResolverUnavailable,
    SecondaryUnavailable,
    Unknown,
}

impl Reason {
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::ResolverContact => "resolver-contact",
            Self::OurDnsBlock => "our-dns-block",
            Self::StrictBrowserDns => "strict-browser-dns",
            Self::LocalResolverUnavailable => "local-resolver-unavailable",
            Self::SecondaryUnavailable => "secondary-unavailable",
            Self::Unknown => "unknown",
        }
    }

    #[must_use]
    pub const fn confirmed(self) -> bool {
        !matches!(self, Self::ResolverContact | Self::Unknown)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observation {
    Problem(Reason),
    SystemDnsReady,
    SecondaryReady,
    BrowserSystemDnsVerified,
    /// A real upstream connection through the requested route, not a local TCP accept.
    BrowserPathVerified,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issue {
    pub reason: Reason,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub attempts: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramIssues {
    pub program: String,
    pub issues: Vec<Issue>,
    pub needs_recheck: bool,
}

#[derive(Debug, Default)]
struct Program {
    issues: BTreeMap<Reason, Issue>,
    last_seen_ms: u64,
    compatible_browser_dns_ms: Option<u64>,
    last_path_proof_ms: Option<u64>,
    last_receipt_ms: Option<u64>,
    clock_uncertain: bool,
}

#[derive(Debug, Default)]
pub struct Ledger {
    programs: BTreeMap<String, Program>,
    confirmation: Option<BrowserConfirmation>,
}

#[derive(Debug)]
struct BrowserConfirmation {
    host: String,
    route: RouteRole,
    requested_ms: u64,
    episodes: BTreeMap<String, BTreeMap<Reason, u64>>,
    confirmed_programs: BTreeSet<String>,
}

impl Ledger {
    pub fn invalidate_path_proofs(&mut self) {
        self.confirmation = None;
        for program in self.programs.values_mut() {
            program.last_path_proof_ms = None;
        }
    }

    fn make_room(&mut self, program: &str) {
        if !self.programs.contains_key(program) && self.programs.len() >= MAX_PROGRAMS {
            let oldest = self
                .programs
                .iter()
                .min_by_key(|(_, row)| (!row.issues.is_empty(), row.last_seen_ms))
                .map(|(name, _)| name.clone());
            if let Some(oldest) = oldest {
                self.programs.remove(&oldest);
            }
        }
    }

    #[must_use]
    pub fn has_current_path_proof(&self, program: &str) -> bool {
        self.programs
            .get(program)
            .is_some_and(|row| row.last_path_proof_ms.is_some() && !row.clock_uncertain)
    }

    pub fn request_browser_confirmation(
        &mut self,
        host: &str,
        route: RouteRole,
        now_ms: u64,
    ) -> bool {
        if host.is_empty() || host.len() > 253 {
            return false;
        }
        let episodes = self
            .snapshot(now_ms)
            .into_iter()
            .map(|row| {
                (
                    row.program,
                    row.issues
                        .into_iter()
                        .map(|issue| (issue.reason, issue.first_seen_ms))
                        .collect(),
                )
            })
            .collect();
        self.confirmation = Some(BrowserConfirmation {
            host: host.to_owned(),
            route,
            requested_ms: now_ms,
            episodes,
            confirmed_programs: BTreeSet::new(),
        });
        true
    }

    pub fn confirm_browser_path(
        &mut self,
        program: &str,
        host: &str,
        route: RouteRole,
        now_ms: u64,
    ) -> bool {
        if program.is_empty() || program.len() > MAX_PROGRAM_BYTES {
            return false;
        }
        let Some(confirmation) = self.confirmation.as_mut() else {
            return false;
        };
        if now_ms
            .checked_sub(confirmation.requested_ms)
            .is_none_or(|age| age > BROWSER_CONFIRMATION_MS)
        {
            return false;
        }
        if !confirmation
            .host
            .eq_ignore_ascii_case(host.trim_end_matches('.'))
            || confirmation.route != route
            || confirmation.confirmed_programs.contains(program)
            || confirmation.confirmed_programs.len() >= MAX_PROGRAMS
        {
            return false;
        }
        if let Some(row) = self.programs.get(program) {
            if row.issues.values().any(|issue| now_ms < issue.last_seen_ms) {
                return false;
            }
            for issue in row.issues.values().filter(|issue| {
                now_ms
                    .checked_sub(issue.last_seen_ms)
                    .is_none_or(|age| age <= RETAIN_FOR_MS)
            }) {
                if confirmation
                    .episodes
                    .get(program)
                    .and_then(|issues| issues.get(&issue.reason))
                    != Some(&issue.first_seen_ms)
                {
                    return false;
                }
            }
        }
        confirmation.confirmed_programs.insert(program.to_owned());
        self.make_room(program);
        let row = self.programs.entry(program.to_owned()).or_default();
        row.last_seen_ms = row.last_seen_ms.max(now_ms);
        self.observe_received(program, Observation::BrowserPathVerified, now_ms, now_ms)
    }

    pub fn observe(&mut self, program: &str, observation: Observation, now_ms: u64) {
        self.observe_received(program, observation, now_ms, now_ms);
    }

    pub fn observe_received(
        &mut self,
        program: &str,
        observation: Observation,
        now_ms: u64,
        received_ms: u64,
    ) -> bool {
        if program.is_empty() || program.len() > MAX_PROGRAM_BYTES {
            return false;
        }
        self.programs
            .retain(|_, p| now_ms < p.last_seen_ms || now_ms - p.last_seen_ms <= RETAIN_FOR_MS);
        if !self.programs.contains_key(program) {
            if !matches!(observation, Observation::Problem(_)) {
                return false;
            }
            self.make_room(program);
        }
        let row = self.programs.entry(program.to_owned()).or_default();
        if row.last_receipt_ms.is_some_and(|at| received_ms < at) {
            row.clock_uncertain = true;
            row.last_path_proof_ms = None;
        }
        row.last_receipt_ms = Some(received_ms);
        if matches!(
            observation,
            Observation::Problem(Reason::OurDnsBlock | Reason::ResolverContact | Reason::Unknown)
        ) && !row.clock_uncertain
            && row
                .last_path_proof_ms
                .is_some_and(|at| now_ms < at && received_ms >= at)
        {
            return false;
        }
        if !matches!(observation, Observation::Problem(_))
            && row.issues.values().any(|issue| now_ms < issue.last_seen_ms)
        {
            return false;
        }
        row.issues.retain(|_, issue| {
            now_ms
                .checked_sub(issue.last_seen_ms)
                .is_none_or(|age| age <= RETAIN_FOR_MS)
        });
        match observation {
            Observation::Problem(reason) => {
                if reason == Reason::StrictBrowserDns {
                    row.compatible_browser_dns_ms = None;
                }
                let issue = row.issues.entry(reason).or_insert(Issue {
                    reason,
                    first_seen_ms: now_ms,
                    last_seen_ms: now_ms,
                    attempts: 0,
                });
                if now_ms < issue.first_seen_ms {
                    issue.first_seen_ms = now_ms;
                }
                issue.last_seen_ms = issue.last_seen_ms.max(now_ms);
                issue.attempts = issue.attempts.saturating_add(1);
            }
            Observation::SystemDnsReady => {
                row.issues.remove(&Reason::LocalResolverUnavailable);
            }
            Observation::SecondaryReady => {
                row.issues.remove(&Reason::SecondaryUnavailable);
            }
            Observation::BrowserPathVerified => {
                row.last_path_proof_ms = Some(now_ms);
                row.clock_uncertain = false;
                row.issues.remove(&Reason::ResolverContact);
                row.issues.remove(&Reason::OurDnsBlock);
                row.issues.remove(&Reason::Unknown);
                if row.compatible_browser_dns_ms.is_some_and(|at| {
                    now_ms
                        .checked_sub(at)
                        .is_some_and(|age| age <= RECHECK_AFTER_MS)
                }) {
                    row.issues.remove(&Reason::StrictBrowserDns);
                }
            }
            Observation::BrowserSystemDnsVerified => {
                row.compatible_browser_dns_ms = Some(now_ms);
            }
        }
        row.last_seen_ms = row.last_seen_ms.max(now_ms);
        if row.issues.is_empty() && row.last_path_proof_ms.is_none() && !row.clock_uncertain {
            self.programs.remove(program);
        }
        true
    }

    #[must_use]
    pub fn snapshot(&self, now_ms: u64) -> Vec<ProgramIssues> {
        self.programs
            .iter()
            .filter_map(|(name, row)| {
                let age = now_ms.checked_sub(row.last_seen_ms);
                if age.is_some_and(|age| age > RETAIN_FOR_MS) {
                    return None;
                }
                let issues: Vec<_> = row
                    .issues
                    .values()
                    .filter(|issue| {
                        now_ms
                            .checked_sub(issue.last_seen_ms)
                            .is_none_or(|age| age <= RETAIN_FOR_MS)
                    })
                    .cloned()
                    .collect();
                if issues.is_empty() {
                    return None;
                }
                let needs_recheck = row.clock_uncertain
                    || issues.iter().any(|issue| {
                        now_ms
                            .checked_sub(issue.last_seen_ms)
                            .is_none_or(|age| age > RECHECK_AFTER_MS)
                    });
                Some(ProgramIssues {
                    program: name.clone(),
                    issues,
                    needs_recheck,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_working_system_lookup_does_not_clear_a_strict_browsers_conflict() {
        let mut ledger = Ledger::default();
        ledger.observe(
            "browser",
            Observation::Problem(Reason::StrictBrowserDns),
            10,
        );
        ledger.observe(
            "browser",
            Observation::Problem(Reason::LocalResolverUnavailable),
            10,
        );
        ledger.observe("browser", Observation::SystemDnsReady, 20);
        let rows = ledger.snapshot(20);
        assert_eq!(rows[0].issues.len(), 1);
        assert_eq!(rows[0].issues[0].reason, Reason::StrictBrowserDns);
    }

    #[test]
    fn a_contact_with_a_shared_resolver_address_does_not_prove_dns_failure() {
        assert!(!Reason::ResolverContact.confirmed());
        assert!(Reason::OurDnsBlock.confirmed());
    }

    #[test]
    fn clock_rollback_and_stale_evidence_require_rechecking_not_a_success_notice() {
        let mut ledger = Ledger::default();
        ledger.observe("browser", Observation::Problem(Reason::OurDnsBlock), 100);
        assert!(ledger.snapshot(99)[0].needs_recheck);
        assert!(ledger.snapshot(101 + RECHECK_AFTER_MS)[0].needs_recheck);
        assert!(ledger.snapshot(101 + RETAIN_FOR_MS).is_empty());
    }

    #[test]
    fn only_an_upstream_browser_connection_resolves_its_dns_issue() {
        let mut ledger = Ledger::default();
        ledger.observe("browser", Observation::Problem(Reason::OurDnsBlock), 10);
        ledger.observe(
            "browser",
            Observation::Problem(Reason::SecondaryUnavailable),
            10,
        );
        ledger.observe("browser", Observation::BrowserPathVerified, 20);
        assert_eq!(
            ledger.snapshot(20)[0].issues[0].reason,
            Reason::SecondaryUnavailable
        );
        ledger.observe("browser", Observation::SecondaryReady, 30);
        assert!(ledger.snapshot(30).is_empty());
    }

    #[test]
    fn a_cached_connection_does_not_override_a_confirmed_strict_dns_setting() {
        let mut ledger = Ledger::default();
        ledger.observe(
            "browser",
            Observation::Problem(Reason::StrictBrowserDns),
            10,
        );
        ledger.observe("browser", Observation::BrowserPathVerified, 20);
        assert_eq!(
            ledger.snapshot(20)[0].issues[0].reason,
            Reason::StrictBrowserDns
        );
        ledger.observe("browser", Observation::BrowserSystemDnsVerified, 30);
        assert_eq!(
            ledger.snapshot(30)[0].issues[0].reason,
            Reason::StrictBrowserDns
        );
        ledger.observe("browser", Observation::BrowserPathVerified, 40);
        assert!(ledger.snapshot(40).is_empty());
    }

    #[test]
    fn process_flood_and_oversized_paths_cannot_grow_the_ledger_without_bound() {
        let mut ledger = Ledger::default();
        ledger.observe(
            &"x".repeat(MAX_PROGRAM_BYTES + 1),
            Observation::Problem(Reason::OurDnsBlock),
            0,
        );
        assert!(ledger.snapshot(0).is_empty());
        for n in 0..MAX_PROGRAMS + 10 {
            ledger.observe(
                &format!("browser-{n}"),
                Observation::Problem(Reason::OurDnsBlock),
                n as u64,
            );
        }
        assert_eq!(
            ledger.snapshot(MAX_PROGRAMS as u64 + 10).len(),
            MAX_PROGRAMS
        );
    }

    #[test]
    fn changing_the_browser_setting_alone_does_not_prove_its_connection_recovers() {
        let mut ledger = Ledger::default();
        ledger.observe(
            "browser",
            Observation::Problem(Reason::StrictBrowserDns),
            10,
        );
        ledger.observe("browser", Observation::BrowserSystemDnsVerified, 20);
        let rows = ledger.snapshot(20);
        assert!(
            !rows.is_empty(),
            "a setting change alone is not a recovered browser connection"
        );
        assert_eq!(rows[0].issues[0].reason, Reason::StrictBrowserDns);
        ledger.observe("browser", Observation::BrowserPathVerified, 30);
        assert!(ledger.snapshot(30).is_empty());
    }

    #[test]
    fn a_delayed_success_cannot_clear_a_newer_browser_failure() {
        let mut ledger = Ledger::default();
        ledger.observe("browser", Observation::Problem(Reason::OurDnsBlock), 30);
        ledger.observe("browser", Observation::BrowserPathVerified, 20);
        let rows = ledger.snapshot(30);
        assert!(
            !rows.is_empty(),
            "a delayed success must retain newer failure evidence"
        );
        assert_eq!(rows[0].issues[0].reason, Reason::OurDnsBlock);
    }

    #[test]
    fn a_new_strict_setting_invalidates_an_earlier_compatible_setting() {
        let mut ledger = Ledger::default();
        ledger.observe(
            "browser",
            Observation::Problem(Reason::StrictBrowserDns),
            10,
        );
        ledger.observe("browser", Observation::BrowserSystemDnsVerified, 20);
        ledger.observe(
            "browser",
            Observation::Problem(Reason::StrictBrowserDns),
            30,
        );
        ledger.observe("browser", Observation::BrowserPathVerified, 40);
        assert_eq!(
            ledger.snapshot(40)[0].issues[0].reason,
            Reason::StrictBrowserDns
        );
    }

    #[test]
    fn requested_site_confirmation_rejects_a_background_host_and_the_wrong_route() {
        let mut ledger = Ledger::default();
        ledger.observe("browser", Observation::Problem(Reason::OurDnsBlock), 10);
        ledger.request_browser_confirmation("site.example", RouteRole::Secondary, 20);
        assert!(!ledger.confirm_browser_path(
            "browser",
            "background.example",
            RouteRole::Secondary,
            30
        ));
        assert!(!ledger.confirm_browser_path("browser", "site.example", RouteRole::Primary, 30));
        assert!(!ledger.snapshot(30).is_empty());
        assert!(ledger.confirm_browser_path("browser", "site.example", RouteRole::Secondary, 30));
        assert!(ledger.snapshot(30).is_empty());
    }

    #[test]
    fn stale_or_consumed_confirmations_cannot_erase_a_later_browser_failure() {
        let mut ledger = Ledger::default();
        ledger.observe("browser", Observation::Problem(Reason::OurDnsBlock), 10);
        ledger.request_browser_confirmation("site.example", RouteRole::Secondary, 20);
        assert!(!ledger.confirm_browser_path(
            "browser",
            "site.example",
            RouteRole::Secondary,
            20 + BROWSER_CONFIRMATION_MS + 1
        ));
        ledger.request_browser_confirmation("site.example", RouteRole::Secondary, 100_000);
        assert!(ledger.confirm_browser_path(
            "browser",
            "site.example",
            RouteRole::Secondary,
            100_001
        ));
        ledger.observe(
            "browser",
            Observation::Problem(Reason::OurDnsBlock),
            100_002,
        );
        assert!(!ledger.confirm_browser_path(
            "browser",
            "site.example",
            RouteRole::Secondary,
            100_003
        ));
        assert!(!ledger.snapshot(100_003).is_empty());
    }

    #[test]
    fn a_new_service_can_confirm_the_requested_site_without_inventing_an_old_issue() {
        let mut ledger = Ledger::default();
        ledger.request_browser_confirmation("site.example", RouteRole::Secondary, 20);
        assert!(ledger.confirm_browser_path("browser", "site.example", RouteRole::Secondary, 30));
        assert!(ledger.snapshot(30).is_empty());
        assert!(!ledger.confirm_browser_path("browser", "site.example", RouteRole::Secondary, 31));
    }
}
