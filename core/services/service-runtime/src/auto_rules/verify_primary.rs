//! `?host` rules: routed via the main link until it is shown not to reach the
//! host, then rewritten into plain additional-route rules.
//!
//! Lazy by design. A host is checked only after the user's own DNS asked for
//! it; probing every `?` host at import would leave a trail of attempts to
//! blocked sites the user never opened. The check rides the auto-rules tick,
//! one host and at most two probes per tick, never the data path.
//!
//! "Does not reach" needs the TLS probe ([`PathProbe::probe_tls`]): filtering by
//! name lets TCP through, so a TCP probe would answer "reachable" for exactly
//! these hosts. Two misses on the main link, ticks apart, AND an answer over
//! the additional link — a host down on both proves nothing about the main one.

use std::net::Ipv4Addr;

use nrr_domain::canonical::CanonicalRule;
use nrr_domain::decision_matching::match_suffix_domain;
use nrr_domain::RuleAction;
use nrr_shared::ipc_payloads::StatusUpdateEvent;

use super::*;
use crate::path_probe::{PathProbe, PathVerdict};
use crate::production_auto_rule_probe::EgressSources;

/// What the check needs beyond the engine: the probe and the two links'
/// source addresses. Attached once at the composition root, like the author.
pub struct VerifyPrimaryWiring {
    pub probe: Arc<dyn PathProbe>,
    pub egress: Arc<dyn EgressSources>,
    /// The principal's "include subdomains" setting: with it on, an exact rule
    /// also routes its subdomains, so it is also what their check is about.
    pub include_subdomains: Arc<dyn Fn(&str) -> bool + Send + Sync>,
}

/// Misses on the main link before the additional one is asked.
const MAIN_LINK_MISSES: u8 = 2;
/// How long "the main link reaches it" holds on the same main-link address.
const MAIN_LINK_OK_FOR: Duration = Duration::from_secs(24 * 3600);
/// How often the `?` rules are re-read when the stored book cannot be named,
/// or to pick up the subdomain setting while the principal has `?` rules.
const RULES_REREAD_EVERY: Duration = Duration::from_secs(60);
/// Bounds each connect, write and read of a probe, so one probe can take up to
/// three times this; the tick that decides runs two (a miss and the control).
const PROBE_TIMEOUT: Duration = Duration::from_millis(2500);
/// The wait after a check that settled nothing, doubling up to
/// [`INCONCLUSIVE_WAIT_MAX`]: re-probing a filtered name every time it is
/// queried is the trail of attempts this check exists to avoid.
const INCONCLUSIVE_WAIT_MIN: Duration = Duration::from_secs(60);
const INCONCLUSIVE_WAIT_MAX: Duration = Duration::from_secs(30 * 60);
/// Hosts waiting for a check, per principal.
const MAX_PENDING: usize = 32;
/// Recent queries no `?` rule covered yet, kept for the next re-read: a rule
/// added a moment ago must not miss the query that made the user add it.
const MAX_RECENT: usize = 64;

/// One principal's `?` rules and what is known about their hosts.
#[derive(Default)]
pub(super) struct VerifyState {
    rules: Vec<CanonicalAddressMatch>,
    /// Whether an exact rule covers its subdomains, read with the rules.
    subdomains: bool,
    rules_read_at: Option<Instant>,
    /// The stored book `rules` were read from, when the provider names it.
    revision: Option<String>,
    /// Host → its addresses as last resolved.
    pending: HashMap<String, Vec<Ipv4Addr>>,
    misses: HashMap<String, u8>,
    /// Host → the main-link address it was reached from, and when.
    main_link_ok: HashMap<String, (Ipv4Addr, Instant)>,
    /// Host → when its last check settled nothing, and how long it waits.
    inconclusive: HashMap<String, (SystemTime, Duration)>,
    /// When the executor last refused to move a rule.
    move_refused_at: Option<SystemTime>,
    /// Recent queries the `?` rules as last read did not cover, oldest first.
    recent: std::collections::VecDeque<(String, Vec<Ipv4Addr>)>,
}

impl VerifyState {
    /// Read, and no `?` rule: nothing a query could be checked for.
    fn idle(&self) -> bool {
        self.rules_read_at.is_some() && self.rules.is_empty()
    }

    /// `host`'s check settled nothing at `now`: it waits before the next.
    fn settled_nothing(&mut self, host: &str, now: SystemTime) {
        // Forgotten only well after the longest wait, so a host queried
        // seldom still climbs towards it.
        self.inconclusive
            .retain(|_, &mut (since, _)| still_waiting(since, INCONCLUSIVE_WAIT_MAX * 2, now));
        let wait = self
            .inconclusive
            .get(host)
            .map_or(INCONCLUSIVE_WAIT_MIN, |&(_, wait)| {
                (wait * 2).min(INCONCLUSIVE_WAIT_MAX)
            });
        self.inconclusive.insert(host.to_owned(), (now, wait));
    }
}

fn covers(rule: &CanonicalAddressMatch, host: &str, subdomains: bool) -> bool {
    match rule {
        CanonicalAddressMatch::ExactFqdn(d) => {
            d == host || (subdomains && match_suffix_domain(host, d))
        }
        CanonicalAddressMatch::SuffixDomain(d) => match_suffix_domain(host, d),
        _ => false,
    }
}

/// The stored book with every enabled `?` rule covering `host` turned into a
/// plain additional-route rule; `None` when there is none left to turn. A
/// disabled one was never checked, so it keeps its `?`.
fn promoted(book: &CanonicalRuleBook, host: &str, subdomains: bool) -> Option<CanonicalRuleBook> {
    let mut changed = false;
    let rules: Vec<CanonicalRule> = book
        .secondary
        .rules()
        .iter()
        .map(|r| {
            let hit = r.enabled
                && r.action == RuleAction::VerifyPrimary
                && r.address_match
                    .as_ref()
                    .is_some_and(|m| covers(m, host, subdomains));
            if hit {
                changed = true;
                CanonicalRule {
                    action: RuleAction::Route,
                    ..r.clone()
                }
            } else {
                r.clone()
            }
        })
        .collect();
    changed.then(|| CanonicalRuleBook {
        primary: book.primary.clone(),
        secondary: nrr_domain::canonical::CanonicalRuleSet::from_rules(rules),
    })
}

impl AutoRulesEngine {
    /// Attach the probe and the link addresses. `false` when already attached.
    pub fn attach_verify_primary(&self, wiring: VerifyPrimaryWiring) -> bool {
        self.verify_wiring.set(wiring).is_ok()
    }

    /// The user's DNS asked for `host` and it matched a rule. Runs per DNS
    /// answer: a principal whose rules were read and hold no `?` rule costs
    /// one lock and one lookup, and allocates nothing.
    pub fn note_verify_candidate(&self, sid: &str, host: &str, addresses: &[Ipv4Addr]) {
        if addresses.is_empty() || self.verify_wiring.get().is_none() {
            return;
        }
        let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
        if states.get(sid).is_some_and(VerifyState::idle) {
            return;
        }
        let state = states.entry(sid.to_owned()).or_default();
        if state
            .rules
            .iter()
            .any(|r| covers(r, host, state.subdomains))
        {
            if state.pending.len() < MAX_PENDING {
                state.pending.insert(host.to_owned(), addresses.to_vec());
            }
            return;
        }
        state.recent.retain(|(h, _)| h != host);
        if state.recent.len() >= MAX_RECENT {
            state.recent.pop_front();
        }
        state
            .recent
            .push_back((host.to_owned(), addresses.to_vec()));
    }

    /// One step of the check for `sid`: re-read the `?` rules when the book
    /// changed, probe one waiting host, and move its rule when the main link
    /// is shown not to reach it. With nothing waiting it reads no link.
    pub(super) fn verify_primary_step(&self, sid: &str, now: SystemTime) {
        let Some(wiring) = self.verify_wiring.get() else {
            return;
        };
        self.reread_verify_rules(sid, wiring);
        {
            let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
            let Some(state) = states.get_mut(sid) else {
                return;
            };
            // A refused move (rules lock, security alert) lifts by an act this
            // tick does not see; probing meanwhile could change nothing.
            if state
                .move_refused_at
                .is_some_and(|at| still_waiting(at, REFUSED_REWRITE_RETRY, now))
            {
                return;
            }
            let waits = &state.inconclusive;
            state.pending.retain(|h, _| {
                !waits
                    .get(h)
                    .is_some_and(|&(since, wait)| still_waiting(since, wait, now))
            });
            if state.pending.is_empty() {
                return;
            }
        }

        let (main, additional) = wiring.egress.egress_source_ips(sid);
        let (Some(main), Some(additional)) = (main, additional) else {
            // Without both links no check can conclude, and a probe would only
            // add to the trail. The next query queues the host again.
            let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(state) = states.get_mut(sid) {
                state.pending.clear();
            }
            return;
        };
        let next = {
            let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
            let Some(state) = states.get_mut(sid) else {
                return;
            };
            state
                .main_link_ok
                .retain(|_, (from, at)| *from == main && at.elapsed() < MAIN_LINK_OK_FOR);
            let ok = &state.main_link_ok;
            state.pending.retain(|h, _| !ok.contains_key(h));
            let host = state.pending.keys().next().cloned();
            host.and_then(|h| state.pending.get(&h).map(|a| (h, a.clone())))
        };
        let Some((host, addresses)) = next else {
            return;
        };
        let Some(&target) = addresses.first() else {
            return;
        };

        let verdict = wiring
            .probe
            .probe_tls(target, &host, Some(main), PROBE_TIMEOUT);
        // At most one line per tick, and only while a `?` host waits: the
        // only trace of why a rule did or did not move.
        tracing::info!(
            target: "nrr::auto-rules",
            sid = %sid,
            host = %host,
            verdict = ?verdict,
            "? rule host checked over the main link",
        );
        match verdict {
            PathVerdict::Answered => {
                let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(state) = states.get_mut(sid) {
                    state.pending.remove(&host);
                    state.misses.remove(&host);
                    state.inconclusive.remove(&host);
                    state.main_link_ok.insert(host, (main, Instant::now()));
                }
            }
            PathVerdict::Indeterminate => {
                // Nothing measured; the first query after the wait queues it.
                let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(state) = states.get_mut(sid) {
                    state.pending.remove(&host);
                    state.settled_nothing(&host, now);
                }
            }
            PathVerdict::Silent => {
                let misses = {
                    let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
                    let Some(state) = states.get_mut(sid) else {
                        return;
                    };
                    let m = state.misses.entry(host.clone()).or_insert(0);
                    *m = m.saturating_add(1);
                    *m
                };
                // The second miss comes a tick later: one lost hello is not a
                // verdict.
                if misses < MAIN_LINK_MISSES {
                    return;
                }
                let control =
                    wiring
                        .probe
                        .probe_tls(target, &host, Some(additional), PROBE_TIMEOUT);
                let moved = control == PathVerdict::Answered;
                if moved {
                    self.move_to_additional(sid, &host, (wiring.include_subdomains)(sid), now);
                } else {
                    tracing::info!(
                        target: "nrr::auto-rules",
                        sid = %sid,
                        host = %host,
                        control = ?control,
                        "main link silent but no answer over the additional one either; rule kept",
                    );
                }
                let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(state) = states.get_mut(sid) {
                    state.pending.remove(&host);
                    state.misses.remove(&host);
                    if moved {
                        state.inconclusive.remove(&host);
                    } else {
                        state.settled_nothing(&host, now);
                    }
                }
            }
        }
    }

    /// Re-read `sid`'s `?` rules when the stored book changed. The book is
    /// decoded only then, or every [`RULES_REREAD_EVERY`] while the provider
    /// cannot name it or the principal has `?` rules; most have none.
    fn reread_verify_rules(&self, sid: &str, wiring: &VerifyPrimaryWiring) {
        let revision = self.rules.stored_revision_for(sid);
        let (due, new_book) = {
            let states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
            match states.get(sid) {
                None => (true, false),
                Some(s) => {
                    let new_book = revision.is_some() && s.revision != revision;
                    let stale = s
                        .rules_read_at
                        .is_none_or(|at| at.elapsed() >= RULES_REREAD_EVERY);
                    let slow_clock = stale && (revision.is_none() || !s.rules.is_empty());
                    (
                        s.rules_read_at.is_none() || new_book || slow_clock,
                        new_book,
                    )
                }
            }
        };
        if !due {
            return;
        }
        let rules: Vec<CanonicalAddressMatch> = self
            .rules
            .stored_rules_for(sid)
            .map(|s| {
                s.rule_book
                    .secondary
                    .rules()
                    .iter()
                    .filter(|r| r.enabled && r.action == RuleAction::VerifyPrimary)
                    .filter_map(|r| r.address_match.clone())
                    .collect()
            })
            .unwrap_or_default();
        let subdomains = (wiring.include_subdomains)(sid);
        let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
        let state = states.entry(sid.to_owned()).or_default();
        if new_book {
            // A new book is a new question: earlier waits do not carry over.
            state.inconclusive.clear();
            state.move_refused_at = None;
        }
        state
            .pending
            .retain(|h, _| rules.iter().any(|r| covers(r, h, subdomains)));
        // Queries that came before a rule was read now count for it. With no
        // `?` rule at all they are dropped: such a principal keeps no buffer.
        let recent = std::mem::take(&mut state.recent);
        for (host, addresses) in recent {
            if rules.iter().any(|r| covers(r, &host, subdomains)) {
                if state.pending.len() < MAX_PENDING {
                    state.pending.insert(host, addresses);
                }
            } else if !rules.is_empty() {
                state.recent.push_back((host, addresses));
            }
        }
        state.rules = rules;
        state.subdomains = subdomains;
        state.rules_read_at = Some(Instant::now());
        state.revision = revision;
    }

    fn move_to_additional(&self, sid: &str, host: &str, subdomains: bool, now: SystemTime) {
        let Some(author) = self.author.get() else {
            return;
        };
        let correlation = format!("auto-rules-verify-{}", unix_ms(now));
        let edit = |book: &CanonicalRuleBook| promoted(book, host, subdomains);
        match author.rewrite(sid, &edit, &correlation) {
            Ok(true) => {
                tracing::info!(
                    target: "nrr::auto-rules",
                    msg_key = "auto-rules-verify-moved",
                    sid = %sid,
                    host = %host,
                    "the main link does not reach this host; its ? rule now uses the additional route",
                );
                if let Some(bus) = self.events.as_ref() {
                    bus.publish_for(
                        sid,
                        StatusUpdateEvent::VerifyPrimaryMoved {
                            sid: sid.to_owned(),
                            host: host.to_owned(),
                        },
                    );
                }
                let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(state) = states.get_mut(sid) {
                    state.rules_read_at = None;
                }
            }
            Ok(false) => {}
            // Refused (rules lock, security alert): the rule keeps its `?`,
            // and the check rests until the refusal can have lifted.
            Err(e) => {
                tracing::debug!(
                    target: "nrr::auto-rules",
                    sid = %sid,
                    host = %host,
                    code = %e.code,
                    "? rule not moved yet",
                );
                let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(state) = states.get_mut(sid) {
                    state.move_refused_at = Some(now);
                }
            }
        }
    }
}
