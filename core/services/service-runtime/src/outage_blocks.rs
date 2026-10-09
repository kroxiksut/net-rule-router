//! What leak protection blocked while a user's additional route was down.
//!
//! The block notice says how many connections an outage cost; this is the list
//! behind that number. Each principal has at most one outage episode: it opens
//! when their additional route goes down, closes when it comes back, and its
//! list stays readable until the next outage opens. Memory only, bounded per
//! principal, fed by the connection observer off the data path.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/// Folded entries kept per principal.
pub const MAX_ENTRIES_PER_PRINCIPAL: usize = 500;

/// How long after the route came back a drop still belongs to the outage that
/// just ended. The observer drains every few seconds and the leak guard
/// disarms on its own tick, so the last drops arrive after the end is known;
/// opening a new episode for them would wipe the list the user came to read.
const TAIL_GRACE_MS: u64 = 30_000;

/// One outage of a principal's additional route, in wall-clock Unix ms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutageEpisode {
    pub since_ms: u64,
    /// `None` while the outage lasts.
    pub until_ms: Option<u64>,
}

/// One program's blocked attempts at one address, folded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutageBlock {
    /// Lower-cased executable name: what is left to show when the path is not.
    pub process: String,
    pub process_path: Option<String>,
    /// The address, with the port of the latest attempt.
    pub remote: SocketAddr,
    pub host: Option<String>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub attempts: u32,
}

/// A principal's last outage as read: entries most recently attempted first.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OutageSnapshot {
    pub episode: Option<OutageEpisode>,
    pub entries: Vec<OutageBlock>,
    /// Entries evicted to stay within [`MAX_ENTRIES_PER_PRINCIPAL`].
    pub omitted: u32,
}

/// One drop the outage caused, as the observer hands it over.
#[derive(Clone, Copy, Debug)]
pub struct OutageDrop<'a> {
    pub sid: &'a str,
    /// Lower-cased executable name; the folding key with the address.
    pub app: &'a str,
    pub process_path: Option<&'a str>,
    pub remote: SocketAddr,
    pub host: Option<&'a str>,
    pub at_ms: u64,
}

struct PrincipalOutage {
    episode: OutageEpisode,
    entries: HashMap<(IpAddr, String), OutageBlock>,
    omitted: u32,
}

impl PrincipalOutage {
    fn opened_at(at_ms: u64) -> Self {
        Self {
            episode: OutageEpisode {
                since_ms: at_ms,
                until_ms: None,
            },
            entries: HashMap::new(),
            omitted: 0,
        }
    }
}

/// Per-principal outage episodes and their folded drops.
#[derive(Default)]
pub struct OutageBlocks {
    principals: Mutex<HashMap<String, PrincipalOutage>>,
    /// Set by an observer that can tell our drops from everything else. Without
    /// one the list stays empty however long the outage, and the reader must
    /// say "not watching" rather than "nothing was blocked".
    fed: AtomicBool,
}

impl OutageBlocks {
    pub fn new() -> Self {
        Self::default()
    }

    /// An observer that attributes drops is feeding this store.
    pub fn mark_fed(&self) {
        self.fed.store(true, Ordering::Relaxed);
    }

    pub fn is_fed(&self) -> bool {
        self.fed.load(Ordering::Relaxed)
    }

    /// `sid`'s additional route went down at `at_ms`. Opens a new episode,
    /// clearing the last one's list, unless one is already open.
    pub fn outage_began(&self, sid: &str, at_ms: u64) {
        let mut guard = self.principals.lock().unwrap_or_else(|p| p.into_inner());
        let open = guard
            .get(sid)
            .is_some_and(|state| state.episode.until_ms.is_none());
        if !open {
            guard.insert(sid.to_owned(), PrincipalOutage::opened_at(at_ms));
        }
    }

    /// `sid`'s additional route is usable again. Closes the open episode, if
    /// any; its list stays readable.
    pub fn outage_ended(&self, sid: &str, at_ms: u64) {
        let mut guard = self.principals.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(state) = guard.get_mut(sid) {
            if state.episode.until_ms.is_none() {
                state.episode.until_ms = Some(at_ms.max(state.episode.since_ms));
            }
        }
    }

    /// Fold one drop into its principal's episode. A drop with no open episode
    /// opens one: the route status can lag the leak guard (a vanished adapter
    /// is reported only after a wait, a dead tunnel never), and the drop itself
    /// proves the outage. Past the cap the entry attempted longest ago goes.
    pub fn record(&self, blocked: OutageDrop<'_>) {
        if blocked.sid.is_empty() {
            return;
        }
        let mut guard = self.principals.lock().unwrap_or_else(|p| p.into_inner());
        if !guard.contains_key(blocked.sid) {
            guard.insert(
                blocked.sid.to_owned(),
                PrincipalOutage::opened_at(blocked.at_ms),
            );
        }
        let Some(state) = guard.get_mut(blocked.sid) else {
            return;
        };
        if let Some(until) = state.episode.until_ms {
            if blocked.at_ms > until.saturating_add(TAIL_GRACE_MS) {
                *state = PrincipalOutage::opened_at(blocked.at_ms);
            }
        }
        let key = (blocked.remote.ip(), blocked.app.to_owned());
        if let Some(entry) = state.entries.get_mut(&key) {
            entry.attempts = entry.attempts.saturating_add(1);
            entry.first_seen_ms = entry.first_seen_ms.min(blocked.at_ms);
            if blocked.at_ms >= entry.last_seen_ms {
                entry.last_seen_ms = blocked.at_ms;
                entry.remote = blocked.remote;
            }
            if entry.host.is_none() {
                entry.host = blocked.host.map(str::to_owned);
            }
            if entry.process_path.is_none() {
                entry.process_path = blocked.process_path.map(str::to_owned);
            }
            return;
        }
        if state.entries.len() >= MAX_ENTRIES_PER_PRINCIPAL {
            // A scan, but only for a new address at a full list.
            let oldest = state
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_seen_ms)
                .map(|(k, _)| k.clone());
            if let Some(oldest) = oldest {
                state.entries.remove(&oldest);
                state.omitted = state.omitted.saturating_add(1);
            }
        }
        let process = key.1.clone();
        state.entries.insert(
            key,
            OutageBlock {
                process,
                process_path: blocked.process_path.map(str::to_owned),
                remote: blocked.remote,
                host: blocked.host.map(str::to_owned),
                first_seen_ms: blocked.at_ms,
                last_seen_ms: blocked.at_ms,
                attempts: 1,
            },
        );
    }

    /// `sid`'s last outage, or an empty snapshot when it had none.
    pub fn snapshot(&self, sid: &str) -> OutageSnapshot {
        let guard = self.principals.lock().unwrap_or_else(|p| p.into_inner());
        let Some(state) = guard.get(sid) else {
            return OutageSnapshot::default();
        };
        let episode = state.episode;
        let omitted = state.omitted;
        let mut entries: Vec<OutageBlock> = state.entries.values().cloned().collect();
        drop(guard);
        entries.sort_by(|a, b| {
            b.last_seen_ms
                .cmp(&a.last_seen_ms)
                .then_with(|| a.remote.ip().cmp(&b.remote.ip()))
        });
        OutageSnapshot {
            episode: Some(episode),
            entries,
            omitted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn addr(last: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)), port)
    }

    fn drop_of<'a>(sid: &'a str, app: &'a str, remote: SocketAddr, at_ms: u64) -> OutageDrop<'a> {
        OutageDrop {
            sid,
            app,
            process_path: Some(r"C:\Apps\browser.exe"),
            remote,
            host: Some("site.example"),
            at_ms,
        }
    }

    #[test]
    fn attempts_fold_by_program_and_address_keeping_the_latest_port() {
        let store = OutageBlocks::new();
        store.outage_began("S-1", 1_000);
        store.record(drop_of("S-1", "browser.exe", addr(10, 443), 2_000));
        store.record(drop_of("S-1", "browser.exe", addr(10, 80), 3_000));
        store.record(drop_of("S-1", "mail.exe", addr(10, 443), 2_500));
        let snap = store.snapshot("S-1");
        assert_eq!(
            snap.episode,
            Some(OutageEpisode {
                since_ms: 1_000,
                until_ms: None
            })
        );
        assert_eq!(snap.entries.len(), 2, "two programs, one address");
        let browser = &snap.entries[0];
        assert_eq!(browser.attempts, 2);
        assert_eq!(browser.process, "browser.exe");
        assert_eq!(browser.first_seen_ms, 2_000);
        assert_eq!(browser.last_seen_ms, 3_000);
        assert_eq!(browser.remote, addr(10, 80));
        assert_eq!(browser.host.as_deref(), Some("site.example"));
        assert_eq!(snap.entries[1].last_seen_ms, 2_500, "newest attempt first");
        assert_eq!(snap.omitted, 0);
    }

    #[test]
    fn past_the_cap_the_longest_unseen_entry_goes_and_is_counted() {
        let store = OutageBlocks::new();
        store.outage_began("S-1", 0);
        for n in 0..MAX_ENTRIES_PER_PRINCIPAL as u64 {
            let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0x0A00_0000 + n as u32)), 443);
            store.record(drop_of("S-1", "app.exe", remote, 1_000 + n));
        }
        // Seen again, so it is no longer the oldest.
        let first = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0x0A00_0000)), 443);
        store.record(drop_of("S-1", "app.exe", first, 9_000));
        store.record(drop_of("S-1", "app.exe", addr(99, 443), 9_500));
        let snap = store.snapshot("S-1");
        assert_eq!(snap.entries.len(), MAX_ENTRIES_PER_PRINCIPAL);
        assert_eq!(snap.omitted, 1);
        let second = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0x0A00_0001)), 443);
        assert!(
            !snap.entries.iter().any(|e| e.remote == second),
            "the entry attempted longest ago was evicted"
        );
        assert!(snap.entries.iter().any(|e| e.remote == first));
        assert_eq!(snap.entries[0].remote, addr(99, 443));
    }

    #[test]
    fn the_last_list_survives_the_end_and_is_cleared_by_the_next_outage() {
        let store = OutageBlocks::new();
        store.outage_began("S-1", 1_000);
        store.record(drop_of("S-1", "browser.exe", addr(10, 443), 2_000));
        store.outage_ended("S-1", 5_000);
        let ended = store.snapshot("S-1");
        assert_eq!(
            ended.episode,
            Some(OutageEpisode {
                since_ms: 1_000,
                until_ms: Some(5_000)
            })
        );
        assert_eq!(ended.entries.len(), 1, "readable after the outage");

        store.outage_ended("S-1", 7_000);
        assert_eq!(
            store.snapshot("S-1").episode.and_then(|e| e.until_ms),
            Some(5_000),
            "a second end does not move the first"
        );

        store.outage_began("S-1", 100_000);
        let next = store.snapshot("S-1");
        assert_eq!(
            next.episode,
            Some(OutageEpisode {
                since_ms: 100_000,
                until_ms: None
            })
        );
        assert!(next.entries.is_empty(), "the next outage starts clean");
        store.outage_began("S-1", 200_000);
        assert_eq!(
            store.snapshot("S-1").episode.map(|e| e.since_ms),
            Some(100_000),
            "an open outage is not restarted"
        );
    }

    #[test]
    fn a_tail_drop_joins_the_ended_outage_and_a_later_one_opens_a_new_one() {
        let store = OutageBlocks::new();
        store.outage_began("S-1", 1_000);
        store.record(drop_of("S-1", "browser.exe", addr(10, 443), 2_000));
        store.outage_ended("S-1", 5_000);
        store.record(drop_of(
            "S-1",
            "mail.exe",
            addr(11, 443),
            5_000 + TAIL_GRACE_MS,
        ));
        let tail = store.snapshot("S-1");
        assert_eq!(tail.entries.len(), 2, "drained late, same outage");
        assert_eq!(tail.episode.and_then(|e| e.until_ms), Some(5_000));

        let later = 5_000 + TAIL_GRACE_MS + 1;
        store.record(drop_of("S-1", "mail.exe", addr(12, 443), later));
        let fresh = store.snapshot("S-1");
        assert_eq!(
            fresh.episode,
            Some(OutageEpisode {
                since_ms: later,
                until_ms: None
            })
        );
        assert_eq!(fresh.entries.len(), 1);
    }

    #[test]
    fn a_drop_opens_an_outage_the_route_status_has_not_reported() {
        let store = OutageBlocks::new();
        store.record(drop_of("S-1", "browser.exe", addr(10, 443), 4_000));
        assert_eq!(
            store.snapshot("S-1").episode,
            Some(OutageEpisode {
                since_ms: 4_000,
                until_ms: None
            })
        );
    }

    #[test]
    fn principals_never_see_each_others_drops() {
        let store = OutageBlocks::new();
        store.outage_began("S-1", 1_000);
        store.record(drop_of("S-1", "browser.exe", addr(10, 443), 2_000));
        store.record(drop_of("S-2", "mail.exe", addr(11, 443), 2_000));
        store.record(drop_of("", "orphan.exe", addr(12, 443), 2_000));
        assert_eq!(store.snapshot("S-1").entries.len(), 1);
        assert_eq!(store.snapshot("S-2").entries[0].remote, addr(11, 443));
        assert_eq!(store.snapshot("S-3"), OutageSnapshot::default());
        assert_eq!(
            store.snapshot(""),
            OutageSnapshot::default(),
            "an owner-less drop is nobody's"
        );
        store.outage_ended("S-1", 3_000);
        assert_eq!(
            store.snapshot("S-2").episode.and_then(|e| e.until_ms),
            None,
            "one user's route coming back ends only their outage"
        );
    }
}
