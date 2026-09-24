//! A censored name is not a visited one.
//!
//! A provider that stands a placeholder in for a site it will not carry
//! answers every query for that name the same way — including the ones nobody
//! asked for. A browser prefetching the links on a page, or a messenger
//! building a link preview, resolves hosts the user never opened, and each of
//! those answers used to become an offer to route a site nobody had been to.
//! On a screenshot that offer reads as browsing history that never happened.
//!
//! What separates the two is not the answer, it is what follows it: a person
//! opening the page connects to whatever they were handed, within a moment. So
//! the answer parks here instead of becoming an offer, and the offer is born
//! when a connection to one of those addresses arrives.
//!
//! The window is short on purpose. A placeholder answer carries documentation
//! space, which the provider reuses for every name it censors, so the address
//! alone cannot say WHICH name was opened; within a couple of seconds of the
//! answer it can, because nothing else was asked about.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// How far apart a placeholder answer and a connection may be and still be
/// read as one act.
///
/// A page load connects within tens of milliseconds, so the window is not
/// about the user's speed — it is about ours. The two facts arrive through
/// different observers, each draining on its own tick (seconds apart, in
/// either order), so a window measured in hundreds of milliseconds throws away
/// confirmations that did happen. Measured on the reporting run: the answer
/// was parked at 11:07:47.9 and the connection to it surfaced at 11:07:55.2.
const CONFIRM_WINDOW_MS: u64 = 15_000;

/// Answers waiting at once. Far above a page's worth of censored names, and
/// small enough that the scan is cheaper than an index.
const MAX_WAITING: usize = 64;

/// Connections remembered while their answer has not been parked yet.
const MAX_CONNECTED: usize = 128;

struct Waiting {
    host: String,
    addresses: Vec<Ipv4Addr>,
    at_ms: u64,
}

/// What parking an answer came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parked {
    /// Waiting for a connection to confirm it.
    Waiting,
    /// A connection to one of its addresses had already been seen, so the host
    /// is confirmed on the spot. Carries the name the caller should offer.
    AlreadyInUse(String),
    /// Nothing on this platform observes connections, so no confirmation can
    /// ever arrive. The caller decides on the answer alone, as it did before
    /// this gate existed — a gate nothing can open is a feature removed.
    ConfirmationUnavailable,
}

/// Placeholder answers waiting for someone to actually go there, and the
/// connections that arrived before their answer was parked.
///
/// Both halves are needed because the two observers drain independently: the
/// connection is as likely to be seen first as the answer, and a confirmation
/// that only looks forward in time misses half the cases.
#[derive(Default)]
pub struct PlaceholderWaitlist {
    waiting: Mutex<Vec<Waiting>>,
    /// Addresses connected to recently, newest last.
    connected: Mutex<Vec<(Ipv4Addr, u64)>>,
    confirmation_wired: AtomicBool,
}

impl PlaceholderWaitlist {
    /// Declared by the connection observer's wiring: from here on an answer
    /// waits for a connection instead of standing on its own.
    pub fn confirmation_is_wired(&self) {
        self.confirmation_wired.store(true, Ordering::Relaxed);
    }

    /// A provider placeholder was answered for `host`. Parked, not offered.
    pub fn note(&self, host: &str, addresses: &[Ipv4Addr], at_ms: u64) -> Parked {
        if !self.confirmation_wired.load(Ordering::Relaxed) {
            return Parked::ConfirmationUnavailable;
        }
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || addresses.is_empty() {
            return Parked::Waiting;
        }
        // Was one of these addresses already connected to? Then the
        // confirmation arrived before the answer was parked, and parking it to
        // wait for a second one would drop the offer on the floor.
        {
            let mut connected = self.connected.lock().unwrap_or_else(|p| p.into_inner());
            connected.retain(|(_, seen)| within_window(*seen, at_ms));
            if let Some(index) = connected.iter().position(|(ip, _)| addresses.contains(ip)) {
                connected.remove(index);
                return Parked::AlreadyInUse(host);
            }
        }
        let mut waiting = self.waiting.lock().unwrap_or_else(|p| p.into_inner());
        waiting.retain(|w| within_window(w.at_ms, at_ms) && w.host != host);
        if waiting.len() >= MAX_WAITING {
            waiting.remove(0);
        }
        waiting.push(Waiting {
            host,
            addresses: addresses.to_vec(),
            at_ms,
        });
        Parked::Waiting
    }

    /// A connection to `ip` was attempted. Names the host it confirms, once:
    /// the entry is taken, so a page retrying the same dead address cannot ask
    /// the user the same question twice.
    pub fn confirm(&self, ip: Ipv4Addr, at_ms: u64) -> Option<String> {
        let mut waiting = self.waiting.lock().unwrap_or_else(|p| p.into_inner());
        waiting.retain(|w| within_window(w.at_ms, at_ms));
        if let Some(index) = waiting.iter().rposition(|w| w.addresses.contains(&ip)) {
            return Some(waiting.remove(index).host);
        }
        drop(waiting);
        // Nothing parked for it yet. Remember the connection: the answer's own
        // observer may still be a tick behind.
        let mut connected = self.connected.lock().unwrap_or_else(|p| p.into_inner());
        connected.retain(|(seen_ip, seen)| within_window(*seen, at_ms) && *seen_ip != ip);
        if connected.len() >= MAX_CONNECTED {
            connected.remove(0);
        }
        connected.push((ip, at_ms));
        None
    }
}

/// Are the two moments close enough to be one act? Order-free on purpose: the
/// observers drain on their own ticks and either fact can be the older one.
fn within_window(a_ms: u64, b_ms: u64) -> bool {
    a_ms.abs_diff(b_ms) <= CONFIRM_WINDOW_MS
}

/// Process-wide instance: the answer is seen by the DNS observation consumer
/// and the connection by the connection one, built in different scopes.
pub fn global_placeholder_waitlist() -> Arc<PlaceholderWaitlist> {
    static LIST: OnceLock<Arc<PlaceholderWaitlist>> = OnceLock::new();
    Arc::clone(LIST.get_or_init(|| Arc::new(PlaceholderWaitlist::default())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, last)
    }

    fn wired() -> PlaceholderWaitlist {
        let list = PlaceholderWaitlist::default();
        list.confirmation_is_wired();
        list
    }

    /// A platform with no connection observer must keep the signal it had:
    /// an unopenable gate would remove the feature rather than narrow it.
    #[test]
    fn without_a_connection_observer_the_answer_stands_on_its_own() {
        let list = PlaceholderWaitlist::default();
        assert_eq!(
            list.note("censored.example", &[ip(1)], 1_000),
            Parked::ConfirmationUnavailable,
        );
        assert!(list.waiting.lock().expect("lock").is_empty());
    }

    /// The observers drain on their own ticks, so the connection is as likely
    /// to be seen before the answer as after it. Both orders confirm.
    #[test]
    fn a_connection_seen_before_the_answer_confirms_it_on_the_spot() {
        let list = wired();
        assert_eq!(list.confirm(ip(1), 1_000), None, "nothing parked yet");
        assert_eq!(
            list.note("opened.example", &[ip(1)], 1_400),
            Parked::AlreadyInUse("opened.example".to_string()),
        );
        // Taken once: a second answer does not re-offer the same host.
        assert_eq!(
            list.note("opened.example", &[ip(1)], 1_500),
            Parked::Waiting
        );
    }

    /// A connection far outside the window says nothing about an answer parked
    /// now - by then the user was doing something else.
    #[test]
    fn a_stale_connection_does_not_confirm_a_later_answer() {
        let list = wired();
        assert_eq!(list.confirm(ip(1), 1_000), None);
        assert_eq!(
            list.note("later.example", &[ip(1)], 1_000 + CONFIRM_WINDOW_MS + 1),
            Parked::Waiting,
        );
    }

    /// The case that made this necessary: a name resolved by a page's prefetch,
    /// never connected to. Nothing confirms it, so nothing is offered.
    #[test]
    fn a_name_nobody_connected_to_is_never_confirmed() {
        let list = wired();
        list.note("prefetched.example", &[ip(1)], 1_000);
        assert_eq!(list.confirm(ip(9), 1_050), None);
        assert_eq!(
            list.confirm(ip(1), 1_000 + CONFIRM_WINDOW_MS + 1),
            None,
            "outside the window",
        );
    }

    #[test]
    fn a_connection_inside_the_window_confirms_the_host_once() {
        let list = wired();
        list.note("opened.example", &[ip(1), ip(2)], 1_000);
        assert_eq!(
            list.confirm(ip(2), 1_200).as_deref(),
            Some("opened.example")
        );
        assert_eq!(
            list.confirm(ip(2), 1_300),
            None,
            "a retry must not ask the same question twice",
        );
    }

    /// Two censored names share the provider's placeholder address. The one
    /// asked about last is the one being opened — the other was resolved
    /// before it and nothing followed.
    #[test]
    fn the_most_recent_answer_wins_a_shared_placeholder_address() {
        let list = wired();
        list.note("first.example", &[ip(1)], 1_000);
        list.note("second.example", &[ip(1)], 1_500);
        assert_eq!(
            list.confirm(ip(1), 1_600).as_deref(),
            Some("second.example")
        );
    }

    #[test]
    fn the_list_is_bounded_and_a_repeat_answer_refreshes_rather_than_grows() {
        let list = wired();
        for n in 0..(MAX_WAITING as u8 + 10) {
            list.note(&format!("host{n}.example"), &[ip(n)], 1_000);
        }
        assert!(list.waiting.lock().expect("lock").len() <= MAX_WAITING);

        let list = wired();
        list.note("same.example", &[ip(1)], 1_000);
        list.note("same.example", &[ip(2)], 1_100);
        assert_eq!(list.waiting.lock().expect("lock").len(), 1);
        assert_eq!(list.confirm(ip(2), 1_200).as_deref(), Some("same.example"));
    }
}
