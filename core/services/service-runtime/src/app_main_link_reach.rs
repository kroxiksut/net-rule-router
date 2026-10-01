//! How each program's connections fare on the main link, for the application
//! offer (see [`nrr_domain::app_offer`]).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};

use nrr_domain::app_offer::{main_link_carries_again, main_link_does_not_carry, AppMainLinkReach};

/// A program quiet this long starts over: old failures say nothing about now.
const WINDOW_MS: u64 = 10 * 60 * 1_000;
const MAX_PROGRAMS: usize = 256;
/// Past this the address heard from longest ago makes room, so the counts
/// always describe the program's latest addresses.
const MAX_ADDRESSES_PER_PROGRAM: usize = 32;

/// How the last connection to one address went.
#[derive(Clone, Copy, Debug)]
struct Outcome {
    stalled: bool,
    /// The stall had a host name, and so an offer of its own.
    named: bool,
    at_ms: u64,
}

#[derive(Debug, Default)]
struct Tally {
    /// Each address once, by its last outcome: one that stalled and then
    /// answered counts as working, not as both.
    addresses: HashMap<IpAddr, Outcome>,
    rides_additional_link: bool,
    last_ms: u64,
    judged: bool,
}

impl Tally {
    fn record(&mut self, remote: IpAddr, outcome: Outcome) {
        if self.addresses.len() >= MAX_ADDRESSES_PER_PROGRAM
            && !self.addresses.contains_key(&remote)
        {
            let oldest = self
                .addresses
                .iter()
                .min_by_key(|(_, o)| o.at_ms)
                .map(|(address, _)| *address);
            if let Some(oldest) = oldest {
                self.addresses.remove(&oldest);
            }
        }
        self.addresses.insert(remote, outcome);
    }

    fn reach(&self) -> AppMainLinkReach {
        let mut reach = AppMainLinkReach {
            rides_additional_link: self.rides_additional_link,
            ..AppMainLinkReach::default()
        };
        for outcome in self.addresses.values() {
            if !outcome.stalled {
                reach.working_addresses += 1;
                continue;
            }
            reach.failing_addresses += 1;
            if !outcome.named {
                reach.stalled_addresses += 1;
            }
        }
        reach
    }

    fn unnamed_stalls(&self) -> Vec<IpAddr> {
        let mut addresses: Vec<IpAddr> = self
            .addresses
            .iter()
            .filter(|(_, o)| o.stalled && !o.named)
            .map(|(address, _)| *address)
            .collect();
        addresses.sort();
        addresses
    }

    /// `Carried` when an earlier "not carried" no longer holds.
    fn withdrawn(&mut self) -> Option<AppVerdict> {
        if self.judged && main_link_carries_again(self.reach()) {
            self.judged = false;
            return Some(AppVerdict::Carried);
        }
        None
    }
}

/// What one outcome changed for a program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppVerdict {
    /// The main link was just judged not to carry it; these are the unnamed
    /// addresses it stalled on.
    NotCarried(Vec<IpAddr>),
    /// The judgement no longer holds — an offer about it is no longer true.
    Carried,
}

#[derive(Default)]
pub struct AppMainLinkReachRegistry {
    programs: Mutex<HashMap<String, Tally>>,
}

impl AppMainLinkReachRegistry {
    /// Records one main-link connection of `program` that stalled or closed in
    /// order. Only an unnamed stall counts toward the threshold — a named one
    /// has its own host offer — while every address counts toward "most of
    /// them fail". Answers only when the verdict turns.
    pub fn note(
        &self,
        program: &str,
        remote: IpAddr,
        stalled: bool,
        named: bool,
        at_ms: u64,
    ) -> Option<AppVerdict> {
        self.with_tally(program, at_ms, |tally| {
            tally.record(
                remote,
                Outcome {
                    stalled,
                    named,
                    at_ms,
                },
            );
            if !stalled {
                return tally.withdrawn();
            }
            if tally.judged || !main_link_does_not_carry(tally.reach()) {
                return None;
            }
            tally.judged = true;
            Some(AppVerdict::NotCarried(tally.unnamed_stalls()))
        })
    }

    /// A connection of `program` left over the additional link: it is already
    /// split between the links, so it is not to be moved whole.
    pub fn note_additional_link(&self, program: &str, at_ms: u64) -> Option<AppVerdict> {
        self.with_tally(program, at_ms, |tally| {
            tally.rides_additional_link = true;
            tally.withdrawn()
        })
    }

    fn with_tally(
        &self,
        program: &str,
        at_ms: u64,
        f: impl FnOnce(&mut Tally) -> Option<AppVerdict>,
    ) -> Option<AppVerdict> {
        if program.is_empty() {
            return None;
        }
        let mut programs = self.programs.lock().unwrap_or_else(|p| p.into_inner());
        if !programs.contains_key(program) && programs.len() >= MAX_PROGRAMS {
            programs.retain(|_, t| at_ms.saturating_sub(t.last_ms) < WINDOW_MS);
            if programs.len() >= MAX_PROGRAMS {
                return None;
            }
        }
        let tally = programs.entry(program.to_string()).or_default();
        if tally.last_ms != 0 && at_ms.saturating_sub(tally.last_ms) >= WINDOW_MS {
            *tally = Tally::default();
        }
        tally.last_ms = tally.last_ms.max(at_ms);
        f(tally)
    }
}

/// One registry for the process: the connection observer writes it and the
/// offer reads its verdicts, from different composition scopes.
pub fn global_app_main_link_reach() -> Arc<AppMainLinkReachRegistry> {
    static REGISTRY: OnceLock<Arc<AppMainLinkReachRegistry>> = OnceLock::new();
    Arc::clone(REGISTRY.get_or_init(|| Arc::new(AppMainLinkReachRegistry::default())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn addr(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
    }

    #[test]
    fn three_unnamed_stalls_turn_the_verdict_once() {
        let r = AppMainLinkReachRegistry::default();
        assert_eq!(r.note("app.exe", addr(1), true, false, 1_000), None);
        assert_eq!(r.note("app.exe", addr(2), true, false, 2_000), None);
        assert_eq!(
            r.note("app.exe", addr(3), true, false, 3_000),
            Some(AppVerdict::NotCarried(vec![addr(1), addr(2), addr(3)]))
        );
        assert_eq!(r.note("app.exe", addr(4), true, false, 4_000), None);
    }

    #[test]
    fn a_program_that_works_on_most_addresses_is_not_offered() {
        let r = AppMainLinkReachRegistry::default();
        for last in 10..=15 {
            assert_eq!(r.note("browser.exe", addr(last), false, true, 500), None);
        }
        for last in 1..=6 {
            assert_eq!(r.note("browser.exe", addr(last), true, false, 1_000), None);
        }
        // Positive control: one more failing address tips the majority.
        assert!(matches!(
            r.note("browser.exe", addr(7), true, false, 1_000),
            Some(AppVerdict::NotCarried(_))
        ));
    }

    #[test]
    fn a_program_on_the_additional_link_is_never_offered_and_its_offer_goes() {
        let r = AppMainLinkReachRegistry::default();
        for last in 1..=3 {
            r.note("browser.exe", addr(last), true, false, 1_000);
        }
        assert_eq!(
            r.note_additional_link("browser.exe", 1_500),
            Some(AppVerdict::Carried)
        );
        for last in 4..=8 {
            assert_eq!(r.note("browser.exe", addr(last), true, false, 2_000), None);
        }
    }

    #[test]
    fn named_stalls_do_not_count() {
        let r = AppMainLinkReachRegistry::default();
        for last in 1..=5 {
            assert_eq!(r.note("browser.exe", addr(last), true, true, 1_000), None);
        }
    }

    #[test]
    fn the_offer_goes_once_most_addresses_work_by_the_margin() {
        let r = AppMainLinkReachRegistry::default();
        for last in 1..=3 {
            r.note("app.exe", addr(last), true, false, 1_000);
        }
        for last in 7..=10 {
            assert_eq!(r.note("app.exe", addr(last), false, false, 2_000), None);
        }
        assert_eq!(
            r.note("app.exe", addr(11), false, false, 2_000),
            Some(AppVerdict::Carried)
        );
    }

    /// A full address book still lets failures outnumber the work: the oldest
    /// addresses make room instead of both sides stopping at the same cap.
    #[test]
    fn failures_can_still_win_after_many_working_addresses() {
        let r = AppMainLinkReachRegistry::default();
        for last in 1..=40 {
            r.note("app.exe", addr(last), false, false, u64::from(last));
        }
        let turned = (100..=140)
            .filter_map(|last| r.note("app.exe", addr(last), true, false, 1_000 + u64::from(last)))
            .collect::<Vec<_>>();
        assert!(
            matches!(turned.as_slice(), [AppVerdict::NotCarried(_)]),
            "{turned:?}"
        );
    }

    /// An address that stalled and then answered is working, once: five of
    /// them and one fresh stall are not a majority of failures.
    #[test]
    fn an_address_counts_by_its_last_outcome() {
        let r = AppMainLinkReachRegistry::default();
        for last in 1..=5 {
            assert_eq!(r.note("app.exe", addr(last), true, false, 1_000), None);
            assert_eq!(r.note("app.exe", addr(last), false, false, 1_500), None);
        }
        assert_eq!(r.note("app.exe", addr(6), true, false, 2_000), None);
    }

    /// One address flipping between a stall and a reply cannot flap the
    /// verdict, and the verdict is not raised again while it stands.
    #[test]
    fn one_flipping_address_does_not_flap_the_verdict() {
        let r = AppMainLinkReachRegistry::default();
        for last in 10..=12 {
            r.note("app.exe", addr(last), false, false, 500);
        }
        for last in 1..=3 {
            r.note("app.exe", addr(last), true, false, 1_000);
        }
        assert!(matches!(
            r.note("app.exe", addr(4), true, false, 1_000),
            Some(AppVerdict::NotCarried(_))
        ));
        for at in 0..5 {
            assert_eq!(r.note("app.exe", addr(4), false, false, 2_000 + at), None);
            assert_eq!(r.note("app.exe", addr(4), true, false, 2_500 + at), None);
        }
    }

    #[test]
    fn a_quiet_window_starts_the_tally_over() {
        let r = AppMainLinkReachRegistry::default();
        r.note("app.exe", addr(1), true, false, 1_000);
        r.note("app.exe", addr(2), true, false, 2_000);
        let later = 2_000 + WINDOW_MS;
        assert_eq!(r.note("app.exe", addr(3), true, false, later), None);
    }
}
