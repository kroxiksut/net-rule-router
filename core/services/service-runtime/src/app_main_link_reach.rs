//! How each program's connections fare on the main link, for the application
//! offer (see [`nrr_domain::app_offer`]).

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};

use nrr_domain::app_offer::{main_link_does_not_carry, AppMainLinkReach};

/// A program quiet this long starts over: old failures say nothing about now.
const WINDOW_MS: u64 = 10 * 60 * 1_000;
const MAX_PROGRAMS: usize = 256;
const MAX_ADDRESSES_PER_PROGRAM: usize = 16;

#[derive(Debug, Default)]
struct Tally {
    stalled: HashSet<IpAddr>,
    completed: u32,
    last_ms: u64,
    judged: bool,
}

impl Tally {
    fn reach(&self) -> AppMainLinkReach {
        AppMainLinkReach {
            stalled_addresses: self.stalled.len(),
            completed: self.completed,
        }
    }
}

/// What one outcome changed for a program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppVerdict {
    /// The main link was just judged not to carry it; these are the addresses
    /// it stalled on.
    NotCarried(Vec<IpAddr>),
    /// A connection of it completed after that judgement — an offer about it
    /// is no longer true.
    Carried,
}

#[derive(Default)]
pub struct AppMainLinkReachRegistry {
    programs: Mutex<HashMap<String, Tally>>,
}

impl AppMainLinkReachRegistry {
    /// Records one connection of `program` that stalled or closed in order.
    /// Only an unnamed address counts toward a stall — a named one has its own
    /// host offer — while any completion counts against the verdict. Answers
    /// only when the verdict turns.
    pub fn note(
        &self,
        program: &str,
        remote: IpAddr,
        stalled: bool,
        named: bool,
        at_ms: u64,
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
        if !stalled {
            tally.completed = tally.completed.saturating_add(1);
            if tally.judged {
                tally.judged = false;
                return Some(AppVerdict::Carried);
            }
            return None;
        }
        if !named && tally.stalled.len() < MAX_ADDRESSES_PER_PROGRAM {
            tally.stalled.insert(remote);
        }
        if tally.judged || !main_link_does_not_carry(tally.reach()) {
            return None;
        }
        tally.judged = true;
        let mut addresses: Vec<IpAddr> = tally.stalled.iter().copied().collect();
        addresses.sort();
        Some(AppVerdict::NotCarried(addresses))
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
    fn a_completion_first_keeps_the_program_out() {
        let r = AppMainLinkReachRegistry::default();
        assert_eq!(r.note("app.exe", addr(9), false, true, 500), None);
        for last in 1..=5 {
            assert_eq!(r.note("app.exe", addr(last), true, false, 1_000), None);
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
    fn a_completion_after_the_verdict_withdraws_it() {
        let r = AppMainLinkReachRegistry::default();
        for last in 1..=3 {
            r.note("app.exe", addr(last), true, false, 1_000);
        }
        assert_eq!(
            r.note("app.exe", addr(7), false, false, 2_000),
            Some(AppVerdict::Carried)
        );
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
