//! `?` rules: a route of the set they are written in, checked on that link.
//! When the written link is shown not to reach a destination while the other
//! link answers, the check reaches a verdict: the rule is enforced on the other
//! link until the service restarts, and the user is offered the move. Nothing
//! is rewritten until they accept it.
//!
//! Lazy by design. A destination is checked only after the user's own DNS asked
//! for it (a name rule) or a program connected to it (an address rule); probing
//! every `?` value at import would leave a trail of attempts to blocked sites
//! the user never opened. The check rides the auto-rules tick, one destination
//! and at most two probes per tick, never the data path.
//!
//! "Does not reach" for a name needs the TLS probe ([`PathProbe::probe_tls`]):
//! filtering by name lets TCP through. For an address the TCP connect is the
//! question, since blocking by address drops the connection itself. Two misses
//! on the written link, ticks apart, AND an answer over the other link — a
//! destination down on both proves nothing about either.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;

use nrr_domain::canonical::{CanonicalRule, CanonicalRuleSet};
use nrr_domain::decision_matching::match_suffix_domain;
use nrr_domain::{RuleAction, RuleId};
use nrr_shared::ipc_payloads::{StatusUpdateEvent, VerifyVerdictDto};

use super::*;
use crate::path_probe::{PathProbe, PathVerdict};
use crate::production_auto_rule_probe::EgressSources;

/// What the check needs beyond the engine: the probe, the two links' source
/// addresses and a way to re-apply. Attached once at the composition root.
pub struct VerifyPrimaryWiring {
    pub probe: Arc<dyn PathProbe>,
    pub egress: Arc<dyn EgressSources>,
    /// The principal's "include subdomains" setting: with it on, an exact rule
    /// also routes its subdomains, so it is also what their check is about.
    pub include_subdomains: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    /// Re-applies one principal's policy at once after its verdicts moved a
    /// rule. `None` leaves it to the next enforcement pass, which counts the
    /// verdicts among its inputs.
    pub reapply: Option<Reapply>,
}

/// Re-applies one principal's policy.
pub type Reapply = Arc<dyn Fn(&str) + Send + Sync>;

/// Misses on the written link before the other one is asked.
const WRITTEN_LINK_MISSES: u8 = 2;
/// How long "the written link reaches it" holds on the same link address.
const WRITTEN_LINK_OK_FOR: Duration = Duration::from_secs(24 * 3600);
/// How often the `?` rules are re-read when the stored book cannot be named,
/// or to pick up the subdomain setting while the principal has `?` rules.
const RULES_REREAD_EVERY: Duration = Duration::from_secs(60);
/// Bounds each connect, write and read of a probe, so one probe can take up to
/// three times this; the tick that decides runs two (a miss and the control).
const PROBE_TIMEOUT: Duration = Duration::from_millis(2500);
/// The port an address is checked on when the connection named none.
const FALLBACK_PORT: u16 = 443;
/// The wait after a check that settled nothing, doubling up to
/// [`INCONCLUSIVE_WAIT_MAX`]: re-probing a filtered destination every time it
/// is used is the trail of attempts this check exists to avoid.
const INCONCLUSIVE_WAIT_MIN: Duration = Duration::from_secs(60);
const INCONCLUSIVE_WAIT_MAX: Duration = Duration::from_secs(30 * 60);
/// Destinations waiting for a check, per principal.
const MAX_PENDING: usize = 32;
/// Recent queries no `?` rule covered yet, kept for the next re-read: a rule
/// added a moment ago must not miss the query that made the user add it.
const MAX_RECENT: usize = 64;

/// One enabled `?` rule as stored.
#[derive(Clone)]
struct VerifyRule {
    id: RuleId,
    matcher: CanonicalAddressMatch,
    written: RouteRole,
}

/// A destination waiting for its check.
#[derive(Clone)]
struct Candidate {
    rule: RuleId,
    addresses: Vec<Ipv4Addr>,
    /// `Some` for an address rule: the port the program connected to. `None`
    /// checks the name over TLS.
    port: Option<u16>,
}

/// "Does not open where it is written, opens on the other link".
struct Verdict {
    written: RouteRole,
    matcher: CanonicalAddressMatch,
    host: String,
    since_ms: i64,
    dismissed: bool,
}

/// One principal's `?` rules and what is known about their destinations.
#[derive(Default)]
pub(super) struct VerifyState {
    rules: Vec<VerifyRule>,
    /// The address rules among `rules`, by address: what a connection is
    /// looked up in.
    ips: HashMap<Ipv4Addr, RuleId>,
    /// Whether an exact rule covers its subdomains, read with the rules.
    subdomains: bool,
    rules_read_at: Option<Instant>,
    /// The stored book `rules` were read from, when the provider names it.
    revision: Option<String>,
    /// Host name or address text → its candidate.
    pending: HashMap<String, Candidate>,
    misses: HashMap<String, u8>,
    /// Host → the written link's address it was reached from, and when.
    reached: HashMap<String, (Ipv4Addr, Instant)>,
    /// Host → when its last check settled nothing, and how long it waits.
    inconclusive: HashMap<String, (SystemTime, Duration)>,
    /// Recent queries the `?` rules as last read did not cover, oldest first.
    recent: VecDeque<(String, Vec<Ipv4Addr>)>,
    verdicts: BTreeMap<RuleId, Verdict>,
}

impl VerifyState {
    /// Read, and no `?` rule: nothing a query could be checked for.
    fn idle(&self) -> bool {
        self.rules_read_at.is_some() && self.rules.is_empty()
    }

    /// The `?` rule that decides `host`: the narrowest one covering it.
    fn rule_for_host(&self, host: &str) -> Option<&VerifyRule> {
        self.rules
            .iter()
            .filter(|r| covers(&r.matcher, host, self.subdomains))
            .max_by_key(|r| specificity(&r.matcher))
    }

    fn written_of(&self, rule: &RuleId) -> Option<RouteRole> {
        self.rules.iter().find(|r| r.id == *rule).map(|r| r.written)
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

    fn pending_count(&self) -> usize {
        self.verdicts.values().filter(|v| !v.dismissed).count()
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

/// The narrower rule wins, as in enforcement: an exact value over any suffix,
/// a longer suffix over a shorter one.
fn specificity(rule: &CanonicalAddressMatch) -> (u8, usize) {
    match rule {
        CanonicalAddressMatch::SuffixDomain(d) => (0, d.len()),
        _ => (1, 0),
    }
}

fn other_route(role: RouteRole) -> RouteRole {
    match role {
        RouteRole::Primary => RouteRole::Secondary,
        RouteRole::Secondary => RouteRole::Primary,
    }
}

/// The stored book with each `?` rule in `rules` moved into the other set as a
/// plain route, same id and origin; one whose plain twin is already there is
/// just dropped. `None` when none of them is in the book any more.
fn moved_for_good(
    book: &CanonicalRuleBook,
    rules: &BTreeMap<RuleId, RouteRole>,
) -> Option<(CanonicalRuleBook, u32)> {
    let mut primary = book.primary.rules().to_vec();
    let mut secondary = book.secondary.rules().to_vec();
    let mut moved = 0;
    for (id, written) in rules {
        let (from, to) = match written {
            RouteRole::Primary => (&mut primary, &mut secondary),
            RouteRole::Secondary => (&mut secondary, &mut primary),
        };
        let Some(at) = from
            .iter()
            .position(|r| r.id == *id && r.action == RuleAction::Verify)
        else {
            continue;
        };
        let plain = CanonicalRule {
            action: RuleAction::Route,
            ..from.remove(at)
        };
        moved += 1;
        let twin = to.iter().any(|r| {
            r.action == RuleAction::Route
                && r.enabled == plain.enabled
                && r.address_match == plain.address_match
                && r.app_match == plain.app_match
        });
        if !twin {
            to.push(plain);
        }
    }
    (moved > 0).then(|| {
        (
            CanonicalRuleBook {
                primary: CanonicalRuleSet::from_rules(primary),
                secondary: CanonicalRuleSet::from_rules(secondary),
            },
            moved,
        )
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
        if let Some(rule) = state.rule_for_host(host).map(|r| r.id.clone()) {
            // A live verdict already answered for this rule.
            if !state.verdicts.contains_key(&rule) && state.pending.len() < MAX_PENDING {
                state.pending.insert(
                    host.to_owned(),
                    Candidate {
                        rule,
                        addresses: addresses.to_vec(),
                        port: None,
                    },
                );
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

    /// A connection of `sid`'s to `remote`, from the pass that already reads
    /// every connection. Costs one atomic load unless somebody has a `?` rule
    /// on an IPv4 address, and one lookup for those who do.
    pub fn note_verify_connection(&self, sid: &str, remote: SocketAddr) {
        if !self.verify_watches_ips.load(Ordering::Relaxed) {
            return;
        }
        let IpAddr::V4(ip) = remote.ip() else {
            return;
        };
        let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
        let Some(state) = states.get_mut(sid) else {
            return;
        };
        let Some(rule) = state.ips.get(&ip) else {
            return;
        };
        if state.verdicts.contains_key(rule) || state.pending.len() >= MAX_PENDING {
            return;
        }
        let rule = rule.clone();
        state
            .pending
            .entry(ip.to_string())
            .or_insert_with(|| Candidate {
                rule,
                addresses: vec![ip],
                port: Some(remote.port()),
            });
    }

    /// One step of the check for `sid`: re-read the `?` rules when the book
    /// changed, probe one waiting destination, and reach a verdict when the
    /// written link is shown not to reach it. With nothing waiting it reads
    /// no link.
    pub(super) fn verify_step(&self, sid: &str, now: SystemTime) {
        let Some(wiring) = self.verify_wiring.get() else {
            return;
        };
        self.reread_verify_rules(sid, wiring);
        {
            let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
            let Some(state) = states.get_mut(sid) else {
                return;
            };
            let waits = &state.inconclusive;
            let verdicts = &state.verdicts;
            state.pending.retain(|h, c| {
                !verdicts.contains_key(&c.rule)
                    && !waits
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
            // add to the trail. The next use queues the destination again.
            let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(state) = states.get_mut(sid) {
                state.pending.clear();
            }
            return;
        };
        let link = |role: RouteRole| match role {
            RouteRole::Primary => main,
            RouteRole::Secondary => additional,
        };
        let next = {
            let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
            let Some(state) = states.get_mut(sid) else {
                return;
            };
            state
                .reached
                .retain(|_, (_, at)| at.elapsed() < WRITTEN_LINK_OK_FOR);
            let rules = &state.rules;
            let reached = &state.reached;
            state.pending.retain(|h, c| {
                rules.iter().find(|r| r.id == c.rule).is_some_and(|r| {
                    reached
                        .get(h)
                        .is_none_or(|(from, _)| *from != link(r.written))
                })
            });
            let first = state
                .pending
                .iter()
                .next()
                .map(|(h, c)| (h.clone(), c.clone()));
            first.and_then(|(h, c)| state.written_of(&c.rule).map(|written| (h, c, written)))
        };
        let Some((host, candidate, written)) = next else {
            return;
        };
        let Some(&target) = candidate.addresses.first() else {
            return;
        };
        let check = |source: Ipv4Addr| match candidate.port {
            None => wiring
                .probe
                .probe_tls(target, &host, Some(source), PROBE_TIMEOUT),
            Some(port) => {
                let port = if port == 0 { FALLBACK_PORT } else { port };
                wiring
                    .probe
                    .probe(target, port, Some(source), PROBE_TIMEOUT)
            }
        };

        let verdict = check(link(written));
        // At most one line per tick, and only while a `?` destination waits:
        // the only trace of why a rule did or did not move.
        tracing::info!(
            target: "nrr::auto-rules",
            sid = %sid,
            host = %host,
            route = written.slug(),
            verdict = ?verdict,
            "? rule destination checked over the route it is written for",
        );
        match verdict {
            PathVerdict::Answered => {
                let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(state) = states.get_mut(sid) {
                    state.pending.remove(&host);
                    state.misses.remove(&host);
                    state.inconclusive.remove(&host);
                    state.reached.insert(host, (link(written), Instant::now()));
                }
            }
            PathVerdict::Indeterminate => {
                // Nothing measured; the first use after the wait queues it.
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
                // The second miss comes a tick later: one lost attempt is not
                // a verdict.
                if misses < WRITTEN_LINK_MISSES {
                    return;
                }
                let control = check(link(other_route(written)));
                let proven = control == PathVerdict::Answered;
                if proven {
                    self.reach_verdict(sid, &host, &candidate.rule, now);
                } else {
                    tracing::info!(
                        target: "nrr::auto-rules",
                        sid = %sid,
                        host = %host,
                        control = ?control,
                        "written route silent but no answer over the other one either; rule kept",
                    );
                }
                let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(state) = states.get_mut(sid) {
                    state.pending.remove(&host);
                    state.misses.remove(&host);
                    if proven {
                        state.inconclusive.remove(&host);
                    } else {
                        state.settled_nothing(&host, now);
                    }
                }
            }
        }
    }

    /// Record the verdict for `rule`, proven by `host`, and act on it.
    fn reach_verdict(&self, sid: &str, host: &str, rule: &RuleId, now: SystemTime) {
        let written = {
            let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
            let Some(state) = states.get_mut(sid) else {
                return;
            };
            let Some(found) = state.rules.iter().find(|r| r.id == *rule).cloned() else {
                return;
            };
            if state.verdicts.contains_key(rule) {
                return;
            }
            state.verdicts.insert(
                rule.clone(),
                Verdict {
                    written: found.written,
                    matcher: found.matcher,
                    host: host.to_owned(),
                    since_ms: unix_ms(now),
                    dismissed: false,
                },
            );
            found.written
        };
        tracing::info!(
            target: "nrr::auto-rules",
            msg_key = "auto-rules-verify-verdict",
            sid = %sid,
            host = %host,
            from = written.slug(),
            to = other_route(written).slug(),
            "the route a ? rule is written for does not reach this host and the other route does; the rule uses the other route until restart, and the move is offered",
        );
        self.verdicts_changed(sid, true);
    }

    /// Serve `sid`'s verdicts to enforcement, tell its clients, and re-apply
    /// when `reapply` and the enforced set moved.
    fn verdicts_changed(&self, sid: &str, reapply: bool) {
        let (moved, pending) = {
            let states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
            states.get(sid).map_or((BTreeSet::new(), 0), |state| {
                (
                    state.verdicts.keys().cloned().collect::<BTreeSet<_>>(),
                    state.pending_count(),
                )
            })
        };
        let enforcement_moved = crate::verify_overlay::set(sid, moved);
        if let Some(bus) = self.events.as_ref() {
            bus.publish_for(
                sid,
                StatusUpdateEvent::VerifyVerdictsChanged {
                    sid: sid.to_owned(),
                    pending_count: pending as u64,
                },
            );
        }
        if reapply && enforcement_moved {
            if let Some(hook) = self.verify_wiring.get().and_then(|w| w.reapply.as_ref()) {
                hook(sid);
            }
        }
    }

    /// `sid`'s verdicts, newest first.
    pub fn verify_verdicts(&self, sid: &str) -> Vec<VerifyVerdictDto> {
        let states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
        let Some(state) = states.get(sid) else {
            return Vec::new();
        };
        let mut out: Vec<VerifyVerdictDto> = state
            .verdicts
            .iter()
            .map(|(id, v)| VerifyVerdictDto {
                rule_id: id.0.clone(),
                value: v.matcher.to_display_string(),
                kind: if matches!(v.matcher, CanonicalAddressMatch::ExactIp(_)) {
                    "ip"
                } else {
                    "domain"
                }
                .to_owned(),
                from_route: v.written.slug().to_owned(),
                to_route: other_route(v.written).slug().to_owned(),
                host: v.host.clone(),
                since_unix_ms: v.since_ms,
                dismissed: v.dismissed,
            })
            .collect();
        out.sort_by(|a, b| {
            b.since_unix_ms
                .cmp(&a.since_unix_ms)
                .then_with(|| a.rule_id.cmp(&b.rule_id))
        });
        out
    }

    /// "Not now": the move holds until restart, the notice goes. Returns how
    /// many verdicts this changed.
    pub fn dismiss_verify_verdicts(&self, sid: &str, rule_ids: &[String]) -> u32 {
        let dismissed = {
            let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
            let Some(state) = states.get_mut(sid) else {
                return 0;
            };
            let mut n = 0;
            for id in rule_ids {
                if let Some(v) = state.verdicts.get_mut(&RuleId(id.clone())) {
                    if !v.dismissed {
                        v.dismissed = true;
                        n += 1;
                    }
                }
            }
            n
        };
        if dismissed > 0 {
            self.verdicts_changed(sid, false);
        }
        dismissed
    }

    /// "Move": rewrite the given `?` rules into the other set for good, in
    /// `sid`'s own rules. A refusal leaves every verdict as it was.
    pub fn accept_verify_verdicts(
        &self,
        sid: &str,
        rule_ids: &[String],
        now: SystemTime,
    ) -> Result<u32, AuthorError> {
        let wanted: BTreeMap<RuleId, RouteRole> = {
            let states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
            let Some(state) = states.get(sid) else {
                return Ok(0);
            };
            rule_ids
                .iter()
                .filter_map(|id| {
                    let id = RuleId(id.clone());
                    let written = state.verdicts.get(&id)?.written;
                    Some((id, written))
                })
                .collect()
        };
        if wanted.is_empty() {
            return Ok(0);
        }
        let Some(author) = self.author.get() else {
            return Err(AuthorError {
                code: "unavailable".to_owned(),
                message: "this service cannot change rules on the user's behalf".to_owned(),
            });
        };
        let moved = std::cell::Cell::new(0u32);
        let edit = |book: &CanonicalRuleBook| {
            moved_for_good(book, &wanted).map(|(book, n)| {
                moved.set(n);
                book
            })
        };
        let correlation = format!("auto-rules-verify-{}", unix_ms(now));
        let rewritten = author.rewrite(sid, &edit, &correlation)?;
        {
            let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(state) = states.get_mut(sid) {
                // Rewritten, or no longer in the book: either way nothing is
                // left to offer for them.
                state.verdicts.retain(|id, _| !wanted.contains_key(id));
                state.rules_read_at = None;
            }
        }
        let moved = if rewritten { moved.get() } else { 0 };
        if moved > 0 {
            tracing::info!(
                target: "nrr::auto-rules",
                msg_key = "auto-rules-verify-accepted",
                sid = %sid,
                count = moved,
                "? rules moved to the route that works for them, as the user accepted",
            );
        }
        // The activation of the rewrite already enforces the moved rules.
        self.verdicts_changed(sid, false);
        Ok(moved)
    }

    /// Re-read `sid`'s `?` rules when the stored book changed. The book is
    /// decoded only then, or every [`RULES_REREAD_EVERY`] while the provider
    /// cannot name it or the principal has `?` rules; most have none. A
    /// verdict whose rule changed is dropped.
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
        let mut rules: Vec<VerifyRule> = Vec::new();
        if let Some(stored) = self.rules.stored_rules_for(sid) {
            let book = &stored.rule_book;
            for (written, set) in [
                (RouteRole::Primary, &book.primary),
                (RouteRole::Secondary, &book.secondary),
            ] {
                rules.extend(
                    set.rules()
                        .iter()
                        .filter(|r| r.enabled && r.action == RuleAction::Verify)
                        .filter_map(|r| {
                            Some(VerifyRule {
                                id: r.id.clone(),
                                matcher: r.address_match.clone()?,
                                written,
                            })
                        }),
                );
            }
        }
        let subdomains = (wiring.include_subdomains)(sid);
        let dropped = {
            let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
            let state = states.entry(sid.to_owned()).or_default();
            if new_book {
                // A new book is a new question: earlier waits do not carry over.
                state.inconclusive.clear();
            }
            let before = state.verdicts.len();
            state.verdicts.retain(|id, v| {
                rules
                    .iter()
                    .any(|r| r.id == *id && r.written == v.written && r.matcher == v.matcher)
            });
            let dropped = state.verdicts.len() != before;
            state.ips = rules
                .iter()
                .filter_map(|r| match r.matcher {
                    CanonicalAddressMatch::ExactIp(IpAddr::V4(ip)) => Some((ip, r.id.clone())),
                    _ => None,
                })
                .collect();
            state.rules = rules;
            state.subdomains = subdomains;
            let VerifyState {
                rules,
                pending,
                recent,
                ..
            } = &mut *state;
            pending.retain(|host, c| {
                rules.iter().any(|r| {
                    r.id == c.rule && (c.port.is_some() || covers(&r.matcher, host, subdomains))
                })
            });
            // Queries that came before a rule was read now count for it. With
            // no `?` rule at all they are dropped: such a principal keeps no
            // buffer.
            let earlier = std::mem::take(recent);
            for (host, addresses) in earlier {
                let rule = rules
                    .iter()
                    .filter(|r| covers(&r.matcher, &host, subdomains))
                    .max_by_key(|r| specificity(&r.matcher))
                    .map(|r| r.id.clone());
                match rule {
                    Some(rule) if pending.len() < MAX_PENDING => {
                        pending.insert(
                            host,
                            Candidate {
                                rule,
                                addresses,
                                port: None,
                            },
                        );
                    }
                    Some(_) => {}
                    None if !rules.is_empty() => recent.push_back((host, addresses)),
                    None => {}
                }
            }
            state.rules_read_at = Some(Instant::now());
            state.revision = revision;
            let watches = states.values().any(|s| !s.ips.is_empty());
            self.verify_watches_ips.store(watches, Ordering::Relaxed);
            dropped
        };
        if dropped {
            self.verdicts_changed(sid, true);
        }
    }
}
