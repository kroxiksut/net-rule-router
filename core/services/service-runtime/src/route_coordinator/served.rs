//! Who the route table serves: every signed-in user, longest-served first.
//!
//! The machine has one route table, so a destination two users send through
//! different links can carry only one of them. The user served longer keeps it:
//! someone signing in must never move the routes another person is already
//! using.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::*;

/// How long a user who dropped out of the answer keeps their place. A session
/// lookup can fail for a moment (a reconnecting RDP session, a token the OS has
/// not issued yet); without this the longest-served user would come back as
/// the newest and lose every contested route to whoever stayed.
const RANK_MEMORY: Duration = Duration::from_secs(120);

/// How long a session enumeration answers the hot readers (a DNS answer, a
/// connection batch). A pass asks afresh, so a sign-in is never missed by the
/// recompute it triggers.
const SESSION_LOOKUP_TTL: Duration = Duration::from_secs(1);

#[derive(Default)]
pub(super) struct ServedRanks {
    next: u64,
    /// Rank (smaller = served longer) and, while absent, since when.
    ranks: HashMap<String, (u64, Option<Instant>)>,
}

impl ServedRanks {
    /// `present` ordered by how long each has been served; a newcomer ranks
    /// after everyone already known, ties broken by `present` order.
    pub(super) fn order(&mut self, present: &[String], now: Instant) -> Vec<String> {
        // Forgotten before anyone returns: back after a long absence is new.
        self.ranks.retain(|_, (_, gone)| {
            gone.is_none_or(|since| now.saturating_duration_since(since) < RANK_MEMORY)
        });
        for (sid, (_, gone)) in self.ranks.iter_mut() {
            if present.contains(sid) {
                *gone = None;
            } else if gone.is_none() {
                *gone = Some(now);
            }
        }
        for sid in present {
            if !self.ranks.contains_key(sid) {
                self.ranks.insert(sid.clone(), (self.next, None));
                self.next += 1;
            }
        }
        let mut ordered: Vec<(u64, &String)> = present
            .iter()
            .filter_map(|sid| self.ranks.get(sid).map(|(rank, _)| (*rank, sid)))
            .collect();
        ordered.sort_unstable_by_key(|(rank, _)| *rank);
        ordered.dedup_by(|a, b| a.1 == b.1);
        ordered.into_iter().map(|(_, sid)| sid.clone()).collect()
    }
}

/// How long a signed-in user missing from the session list stays served. One
/// enumeration can miss a session (a token not issued yet, a reconnecting RDP
/// session); without this a single miss pulls their routes and hands their
/// contested destinations to the next user, only to take them back a pass
/// later. Short: a real sign-out costs the leaver's routes these few seconds.
pub const DEPARTURE_GRACE: Duration = Duration::from_secs(5);

/// The last session enumeration and when it was taken.
pub(super) type SessionCache = Option<(Instant, Vec<String>)>;

/// The signed-in users as the last answer gave them, and since when each one
/// the enumeration stopped listing has been missing.
pub(super) struct SignedInMemory {
    grace: Duration,
    answered: Vec<String>,
    missing_since: HashMap<String, Instant>,
}

impl SignedInMemory {
    pub(super) fn new(grace: Duration) -> Self {
        Self {
            grace,
            answered: Vec::new(),
            missing_since: HashMap::new(),
        }
    }

    #[cfg(test)]
    pub(super) fn set_grace(&mut self, grace: Duration) {
        self.grace = grace;
    }

    /// `enumerated`, plus each user of the previous answer it misses for less
    /// than the grace, counted from the first enumeration that missed them.
    pub(super) fn answer(&mut self, enumerated: Vec<String>, now: Instant) -> Vec<String> {
        self.missing_since
            .retain(|sid, _| !enumerated.contains(sid));
        let mut users = enumerated;
        for sid in std::mem::take(&mut self.answered) {
            if users.contains(&sid) {
                continue;
            }
            let since = *self.missing_since.entry(sid.clone()).or_insert(now);
            if now.saturating_duration_since(since) < self.grace {
                tracing::debug!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    "signed-in user missing from the session list — still served for the grace",
                );
                users.push(sid);
            } else {
                self.missing_since.remove(&sid);
                tracing::info!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    "signed-in user gone from the session list past the grace — no longer served",
                );
            }
        }
        self.answered = users.clone();
        users
    }
}

impl SecondaryRouteCoordinator {
    /// Everyone whose routes and filters are in force, longest-served first:
    /// the tray-connected users and, under service-driven scope, every user
    /// signed in at the console or remotely, tray or no tray. Empty under
    /// app-driven scope with no tray. Cheap enough for a per-answer reader.
    pub fn served_sids(&self, tray_active: &[String]) -> Vec<String> {
        self.served_sids_with(tray_active, false)
    }

    /// [`Self::served_sids`] with a session lookup that skips the cache, for a
    /// pass: the recompute a sign-in triggers must see the new session.
    pub(super) fn served_sids_fresh(&self, tray_active: &[String]) -> Vec<String> {
        self.served_sids_with(tray_active, true)
    }

    /// Tests about who is served, not about a missed enumeration.
    #[cfg(test)]
    pub(crate) fn with_departure_grace(self, grace: Duration) -> Self {
        self.signed_in_memory
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .set_grace(grace);
        self
    }

    /// Whether `sid` is among the users served right now.
    pub fn is_served(&self, sid: &str, tray_active: &[String]) -> bool {
        self.served_sids(tray_active).iter().any(|s| s == sid)
    }

    fn served_sids_with(&self, tray_active: &[String], fresh: bool) -> Vec<String> {
        let mut present: Vec<String> = Vec::with_capacity(tray_active.len() + 1);
        for sid in tray_active {
            if !present.contains(sid) {
                present.push(sid.clone());
            }
        }
        if (self.rule_scope_service_driven)() {
            for sid in self.signed_in_users(fresh) {
                if !present.contains(&sid) {
                    present.push(sid);
                }
            }
        }
        if present.is_empty() {
            return present;
        }
        self.served_ranks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .order(&present, Instant::now())
    }

    fn signed_in_users(&self, fresh: bool) -> Vec<String> {
        let mut cache = self.session_cache.lock().unwrap_or_else(|p| p.into_inner());
        if !fresh {
            if let Some((at, users)) = cache.as_ref() {
                if at.elapsed() < SESSION_LOOKUP_TTL {
                    return users.clone();
                }
            }
        }
        let now = Instant::now();
        let users = self
            .signed_in_memory
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .answer(self.api.interactive_user_sids(), now);
        *cache = Some((now, users.clone()));
        users
    }
}

/// The served set as an [`ActivePrincipalSource`], so a per-user task covers
/// every signed-in user rather than the first.
///
/// [`ActivePrincipalSource`]: nrr_platform_api::active_principals::ActivePrincipalSource
pub struct ServedPrincipals {
    pub coord: Arc<SecondaryRouteCoordinator>,
    pub registry: Arc<crate::active_sid_registry::ActiveSidRegistry>,
}

impl nrr_platform_api::active_principals::ActivePrincipalSource for ServedPrincipals {
    fn active_principals(
        &self,
    ) -> Result<
        Vec<nrr_platform_api::enforcement::UserPrincipal>,
        nrr_platform_api::active_principals::ActivePrincipalError,
    > {
        Ok(self
            .coord
            .served_sids(&self.registry.active_sids())
            .iter()
            .filter_map(|sid| nrr_platform_api::enforcement::UserPrincipal::from_stored(sid).ok())
            .collect())
    }

    fn authority(&self) -> &'static str {
        "sessions"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sids(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_newcomer_ranks_after_everyone_already_served() {
        let mut ranks = ServedRanks::default();
        let t0 = Instant::now();
        assert_eq!(ranks.order(&sids(&["A"]), t0), sids(&["A"]));
        // B arrives listed first (a tray connects before the console user is
        // enumerated): A was served first and stays first.
        assert_eq!(ranks.order(&sids(&["B", "A"]), t0), sids(&["A", "B"]));
    }

    #[test]
    fn ties_follow_the_order_they_were_reported_in() {
        let mut ranks = ServedRanks::default();
        assert_eq!(
            ranks.order(&sids(&["C", "A", "B"]), Instant::now()),
            sids(&["C", "A", "B"])
        );
    }

    #[test]
    fn one_missed_enumeration_keeps_the_user_and_a_lasting_absence_does_not() {
        let mut memory = SignedInMemory::new(DEPARTURE_GRACE);
        let t0 = Instant::now();
        assert_eq!(memory.answer(sids(&["A", "B"]), t0), sids(&["A", "B"]));
        assert_eq!(
            memory.answer(sids(&["B"]), t0 + Duration::from_secs(1)),
            sids(&["B", "A"]),
            "a single miss must not flip anyone's routes"
        );
        assert_eq!(
            memory.answer(sids(&["A", "B"]), t0 + Duration::from_secs(2)),
            sids(&["A", "B"])
        );
        // Missing again: the grace counts from this miss, not the first one.
        let t1 = t0 + Duration::from_secs(10);
        assert_eq!(memory.answer(sids(&["B"]), t1), sids(&["B", "A"]));
        assert_eq!(
            memory.answer(
                sids(&["B"]),
                t1 + DEPARTURE_GRACE - Duration::from_millis(1)
            ),
            sids(&["B", "A"])
        );
        assert_eq!(
            memory.answer(sids(&["B"]), t1 + DEPARTURE_GRACE),
            sids(&["B"]),
            "gone past the grace is gone"
        );
        assert_eq!(
            memory.answer(sids(&["B"]), t1 + DEPARTURE_GRACE * 2),
            sids(&["B"]),
            "and stays gone"
        );
    }

    #[test]
    fn an_empty_enumeration_is_a_miss_too() {
        let mut memory = SignedInMemory::new(DEPARTURE_GRACE);
        let t0 = Instant::now();
        memory.answer(sids(&["A"]), t0);
        assert_eq!(memory.answer(Vec::new(), t0), sids(&["A"]));
        assert!(memory.answer(Vec::new(), t0 + DEPARTURE_GRACE).is_empty());
    }

    #[test]
    fn without_a_grace_a_missing_user_leaves_at_once() {
        let mut memory = SignedInMemory::new(Duration::ZERO);
        let t0 = Instant::now();
        memory.answer(sids(&["A", "B"]), t0);
        assert_eq!(memory.answer(sids(&["B"]), t0), sids(&["B"]));
    }

    #[test]
    fn a_short_absence_keeps_the_place_and_a_long_one_loses_it() {
        let mut ranks = ServedRanks::default();
        let t0 = Instant::now();
        ranks.order(&sids(&["A", "B"]), t0);
        assert_eq!(ranks.order(&sids(&["B"]), t0), sids(&["B"]));
        assert_eq!(
            ranks.order(&sids(&["B", "A"]), t0 + Duration::from_secs(5)),
            sids(&["A", "B"]),
            "a lookup blip must not make the longest-served user the newest"
        );
        ranks.order(&sids(&["B"]), t0 + Duration::from_secs(10));
        assert_eq!(
            ranks.order(
                &sids(&["B", "A"]),
                t0 + RANK_MEMORY + Duration::from_secs(20)
            ),
            sids(&["B", "A"]),
            "a user who left and came back later is a newcomer"
        );
    }
}
