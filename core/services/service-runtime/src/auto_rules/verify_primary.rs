//! `?` rules: a route of the set they are written in, checked on that link.
//! When the written link is shown not to reach a destination while the other
//! link answers, the check reaches a verdict: the rule is enforced on the other
//! link until the service restarts, and the user is offered the move. Nothing
//! is rewritten until they accept it.
//!
//! Lazy by design. A destination is checked only after the user's own DNS asked
//! for it (a name rule) or a program connected to it (an address rule); probing
//! every `?` value at import would leave a trail of attempts to blocked sites
//! the user never opened. The tick only hands one destination per principal to
//! a worker thread; the probes (at most two) run there and a later tick applies
//! the outcome. Never the data path, and never waiting on a dead link inside
//! the tick that serves everybody.
//!
//! "Does not reach" for a name needs the TLS probe ([`PathProbe::probe_tls`]):
//! filtering by name lets TCP through. For an address the TCP connect is the
//! question, since blocking by address drops the connection itself. Two misses
//! on the written link, ticks apart, AND an answer over the other link — a
//! destination down on both proves nothing about either.

use std::collections::{HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;

use nrr_domain::canonical::{CanonicalRule, CanonicalRuleSet, VerifyKey};
use nrr_domain::decision_matching::match_suffix_domain;
use nrr_domain::RuleAction;
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

/// A destination waiting for its check.
#[derive(Clone)]
struct Candidate {
    key: VerifyKey,
    addresses: Vec<Ipv4Addr>,
    /// `Some` for an address rule: the port the program connected to. `None`
    /// checks the name over TLS.
    port: Option<u16>,
}

/// One destination's check, handed to the worker: everything it needs, none
/// of the engine's state.
pub(super) struct VerifyCheck {
    sid: String,
    host: String,
    key: VerifyKey,
    target: Ipv4Addr,
    port: Option<u16>,
    written_source: Ipv4Addr,
    other_source: Ipv4Addr,
    /// Misses already on the written link: the control probe runs only when
    /// this one makes the second.
    misses_before: u8,
    probe: Arc<dyn PathProbe>,
}

/// What a check found, applied to the principal's state by a later step.
pub(super) struct VerifyOutcome {
    sid: String,
    host: String,
    key: VerifyKey,
    written_source: Ipv4Addr,
    verdict: PathVerdict,
    /// The other link's answer; `Some` only after a silent written link that
    /// made the second miss.
    control: Option<PathVerdict>,
}

impl VerifyCheck {
    fn probe_over(&self, source: Ipv4Addr) -> PathVerdict {
        match self.port {
            None => self
                .probe
                .probe_tls(self.target, &self.host, Some(source), PROBE_TIMEOUT),
            Some(port) => {
                let port = if port == 0 { FALLBACK_PORT } else { port };
                self.probe
                    .probe(self.target, port, Some(source), PROBE_TIMEOUT)
            }
        }
    }

    fn outcome(&self, verdict: PathVerdict, control: Option<PathVerdict>) -> VerifyOutcome {
        VerifyOutcome {
            sid: self.sid.clone(),
            host: self.host.clone(),
            key: self.key.clone(),
            written_source: self.written_source,
            verdict,
            control,
        }
    }

    fn run(&self) -> VerifyOutcome {
        let verdict = self.probe_over(self.written_source);
        // At most one line per check, and only while a `?` destination waits:
        // the only trace of why a rule did or did not move.
        tracing::info!(
            target: "nrr::auto-rules",
            sid = %self.sid,
            host = %self.host,
            route = self.key.written.slug(),
            verdict = ?verdict,
            "? rule destination checked over the route it is written for",
        );
        let control = (verdict == PathVerdict::Silent
            && self.misses_before.saturating_add(1) >= WRITTEN_LINK_MISSES)
            .then(|| self.probe_over(self.other_source));
        self.outcome(verdict, control)
    }
}

/// Checks queued behind the running one. A principal has at most one in
/// flight, so this only fills when many wait at once.
const CHECK_QUEUE: usize = 16;
/// Finished checks kept for principals whose next step never comes.
const MAX_FINISHED: usize = 64;

/// Runs `?` checks off the auto-rules tick: a probe waits seconds on a dead
/// link, and the tick serves every principal.
#[derive(Default)]
pub(super) struct VerifyRunner {
    inline: std::sync::atomic::AtomicBool,
    worker: OnceLock<Option<std::sync::mpsc::SyncSender<VerifyCheck>>>,
    finished: Arc<Mutex<Vec<VerifyOutcome>>>,
}

impl VerifyRunner {
    /// Run checks on the calling thread, so a test sees the outcome at once.
    #[cfg(test)]
    pub(super) fn run_inline(&self) {
        self.inline.store(true, Ordering::Relaxed);
    }

    /// `false` when the check could not be queued.
    fn submit(&self, check: VerifyCheck) -> bool {
        if self.inline.load(Ordering::Relaxed) {
            push_finished(&self.finished, check.run());
            return true;
        }
        let queue = self.worker.get_or_init(|| {
            let (tx, rx) = std::sync::mpsc::sync_channel::<VerifyCheck>(CHECK_QUEUE);
            let finished = Arc::clone(&self.finished);
            std::thread::Builder::new()
                .name("nrr-verify-check".to_owned())
                .spawn(move || {
                    for check in rx {
                        // A panicking probe must not leave its principal
                        // waiting for an answer forever.
                        let outcome =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check.run()))
                                .unwrap_or_else(|_| {
                                    check.outcome(PathVerdict::Indeterminate, None)
                                });
                        push_finished(&finished, outcome);
                    }
                })
                .ok()
                .map(|_| tx)
        });
        queue.as_ref().is_some_and(|tx| tx.try_send(check).is_ok())
    }

    fn take_finished(&self, sid: &str) -> Vec<VerifyOutcome> {
        let mut finished = self.finished.lock().unwrap_or_else(|p| p.into_inner());
        if finished.is_empty() {
            return Vec::new();
        }
        let (mine, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut *finished)
            .into_iter()
            .partition(|o| o.sid == sid);
        *finished = rest;
        mine
    }

    fn forget(&self, sid: &str) {
        self.finished
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|o| o.sid != sid);
    }
}

fn push_finished(finished: &Mutex<Vec<VerifyOutcome>>, outcome: VerifyOutcome) {
    let mut finished = finished.lock().unwrap_or_else(|p| p.into_inner());
    if finished.len() >= MAX_FINISHED {
        finished.remove(0);
    }
    finished.push(outcome);
}

/// "Does not open where it is written, opens on the other link".
struct Verdict {
    host: String,
    since_ms: i64,
    dismissed: bool,
}

/// One principal's `?` rules and what is known about their destinations.
/// A rule is its set and address ([`VerifyKey`]): a number is route-local
/// and moves under an inserted line.
#[derive(Default)]
pub(super) struct VerifyState {
    /// The enabled `?` rules as stored.
    rules: Vec<VerifyKey>,
    /// Enabled ordinary name rules of both sets: a narrower one owns its host.
    ordinary: Vec<CanonicalAddressMatch>,
    /// The address rules among `rules`, by address: what a connection is
    /// looked up in.
    ips: HashMap<Ipv4Addr, VerifyKey>,
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
    verdicts: HashMap<VerifyKey, Verdict>,
    /// The destination whose check is running off the tick.
    probing: Option<String>,
}

impl VerifyState {
    /// Read, and no `?` rule: nothing a query could be checked for.
    fn idle(&self) -> bool {
        self.rules_read_at.is_some() && self.rules.is_empty()
    }

    /// The `?` rule that decides `host`.
    fn rule_for_host(&self, host: &str) -> Option<&VerifyKey> {
        decider(&self.rules, &self.ordinary, host, self.subdomains)
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

/// How closely `rule` names `host`, as enforcement ranks it: an exact name over
/// any suffix, a longer suffix over a shorter one. `None`: it does not cover it.
fn rank(rule: &CanonicalAddressMatch, host: &str, subdomains: bool) -> Option<(u8, usize)> {
    match rule {
        CanonicalAddressMatch::ExactFqdn(d) if d == host => Some((2, d.len())),
        CanonicalAddressMatch::ExactFqdn(d) if subdomains && match_suffix_domain(host, d) => {
            Some((1, d.len()))
        }
        CanonicalAddressMatch::SuffixDomain(d) if match_suffix_domain(host, d) => {
            Some((1, d.len()))
        }
        _ => None,
    }
}

/// The `?` rule whose route `host` takes: the narrowest `?` rule covering it,
/// unless an ordinary rule is narrower still. Probing a host over a link its
/// own rule does not assign would pin the wider rule's verdict on it.
fn decider<'a>(
    rules: &'a [VerifyKey],
    ordinary: &[CanonicalAddressMatch],
    host: &str,
    subdomains: bool,
) -> Option<&'a VerifyKey> {
    let (key, best) = rules
        .iter()
        .filter_map(|r| Some((r, rank(&r.address, host, subdomains)?)))
        .max_by_key(|&(_, rank)| rank)?;
    let owned_elsewhere = ordinary
        .iter()
        .filter_map(|a| rank(a, host, subdomains))
        .any(|r| r > best);
    (!owned_elsewhere).then_some(key)
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
    rules: &HashSet<VerifyKey>,
) -> Option<(CanonicalRuleBook, u32)> {
    let mut primary = book.primary.rules().to_vec();
    let mut secondary = book.secondary.rules().to_vec();
    let mut moved = 0;
    for key in rules {
        let (from, to) = match key.written {
            RouteRole::Primary => (&mut primary, &mut secondary),
            RouteRole::Secondary => (&mut secondary, &mut primary),
        };
        let names = |r: &CanonicalRule| {
            r.action == RuleAction::Verify && r.address_match.as_ref() == Some(&key.address)
        };
        let Some(at) = from.iter().position(names) else {
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
        if let Some(key) = state.rule_for_host(host).cloned() {
            // A live verdict already answered for this rule.
            if !state.verdicts.contains_key(&key) && state.pending.len() < MAX_PENDING {
                state.pending.insert(
                    host.to_owned(),
                    Candidate {
                        key,
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
        let Some(key) = state.ips.get(&ip) else {
            return;
        };
        if state.verdicts.contains_key(key) || state.pending.len() >= MAX_PENDING {
            return;
        }
        let key = key.clone();
        state
            .pending
            .entry(ip.to_string())
            .or_insert_with(|| Candidate {
                key,
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
        self.settle_verify_checks(sid, now);
        self.reread_verify_rules(sid, wiring);
        {
            let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
            let Some(state) = states.get_mut(sid) else {
                return;
            };
            // One check per principal at a time; its outcome is applied by a
            // later step.
            if state.probing.is_some() {
                return;
            }
            let waits = &state.inconclusive;
            let verdicts = &state.verdicts;
            state.pending.retain(|h, c| {
                !verdicts.contains_key(&c.key)
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
        let job = {
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
                rules.contains(&c.key)
                    && reached
                        .get(h)
                        .is_none_or(|(from, _)| *from != link(c.key.written))
            });
            let Some((host, candidate)) = state.pending.iter().next() else {
                return;
            };
            let Some(&target) = candidate.addresses.first() else {
                return;
            };
            // The link the rule is written for, never the other set's rule of
            // the same number: a tunnel host must not send its name over the
            // primary.
            let written = candidate.key.written;
            let job = VerifyCheck {
                sid: sid.to_owned(),
                host: host.clone(),
                key: candidate.key.clone(),
                target,
                port: candidate.port,
                written_source: link(written),
                other_source: link(other_route(written)),
                misses_before: state.misses.get(host).copied().unwrap_or(0),
                probe: Arc::clone(&wiring.probe),
            };
            state.probing = Some(job.host.clone());
            job
        };
        if !self.verify_runner.submit(job) {
            // Queue full or no worker: the destination stays pending for a
            // later step.
            let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(state) = states.get_mut(sid) {
                state.probing = None;
            }
            return;
        }
        // An inline runner (tests) has the outcome ready already.
        self.settle_verify_checks(sid, now);
    }

    /// Apply the checks that finished for `sid` since the last step.
    fn settle_verify_checks(&self, sid: &str, now: SystemTime) {
        for outcome in self.verify_runner.take_finished(sid) {
            self.apply_check_outcome(outcome, now);
        }
    }

    fn apply_check_outcome(&self, outcome: VerifyOutcome, now: SystemTime) {
        let VerifyOutcome {
            sid,
            host,
            key,
            written_source,
            verdict,
            control,
        } = outcome;
        let sid = sid.as_str();
        {
            let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
            let Some(state) = states.get_mut(sid) else {
                return;
            };
            // A principal reset while the check ran: its answer is stale.
            if state.probing.as_deref() != Some(host.as_str()) {
                return;
            }
            state.probing = None;
        }
        match verdict {
            PathVerdict::Answered => {
                let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(state) = states.get_mut(sid) {
                    state.pending.remove(&host);
                    state.misses.remove(&host);
                    state.inconclusive.remove(&host);
                    state.reached.insert(host, (written_source, Instant::now()));
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
                {
                    let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
                    let Some(state) = states.get_mut(sid) else {
                        return;
                    };
                    let m = state.misses.entry(host.clone()).or_insert(0);
                    *m = m.saturating_add(1);
                }
                // The second miss comes a tick later: one lost attempt is not
                // a verdict.
                let Some(control) = control else {
                    return;
                };
                let proven = control == PathVerdict::Answered;
                if proven {
                    self.reach_verdict(sid, &host, &key, now);
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

    /// Record the verdict for `key`, proven by `host`, and act on it.
    fn reach_verdict(&self, sid: &str, host: &str, key: &VerifyKey, now: SystemTime) {
        let written = {
            let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
            let Some(state) = states.get_mut(sid) else {
                return;
            };
            if !state.rules.contains(key) || state.verdicts.contains_key(key) {
                return;
            }
            state.verdicts.insert(
                key.clone(),
                Verdict {
                    host: host.to_owned(),
                    since_ms: unix_ms(now),
                    dismissed: false,
                },
            );
            key.written
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
            states.get(sid).map_or((HashSet::new(), 0), |state| {
                (
                    state.verdicts.keys().cloned().collect::<HashSet<_>>(),
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

    /// A full reset of `sid`: no `?` rule, check or verdict is remembered.
    pub(super) fn forget_verify_state(&self, sid: &str) {
        let watches = {
            let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
            states.remove(sid);
            self.verify_runner.forget(sid);
            states.values().any(|s| !s.ips.is_empty())
        };
        self.verify_watches_ips.store(watches, Ordering::Relaxed);
        if crate::verify_overlay::set(sid, HashSet::new()) {
            self.verdicts_changed(sid, true);
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
            .map(|(key, v)| VerifyVerdictDto {
                rule_id: key.to_string(),
                value: key.address.to_display_string(),
                kind: if matches!(key.address, CanonicalAddressMatch::ExactIp(_)) {
                    "ip"
                } else {
                    "domain"
                }
                .to_owned(),
                from_route: key.written.slug().to_owned(),
                to_route: other_route(key.written).slug().to_owned(),
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
    /// many verdicts this changed. `rule_ids` are the handles the list gave
    /// out; one that names no live verdict is ignored.
    pub fn dismiss_verify_verdicts(&self, sid: &str, rule_ids: &[String]) -> u32 {
        let dismissed = {
            let mut states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
            let Some(state) = states.get_mut(sid) else {
                return 0;
            };
            // One pass over the verdicts, whatever the caller sent.
            let asked: HashSet<&str> = rule_ids.iter().map(String::as_str).collect();
            let mut n = 0;
            for (key, v) in state.verdicts.iter_mut() {
                if !v.dismissed && asked.contains(key.to_string().as_str()) {
                    v.dismissed = true;
                    n += 1;
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
        let wanted: HashSet<VerifyKey> = {
            let states = self.verify.lock().unwrap_or_else(|p| p.into_inner());
            let Some(state) = states.get(sid) else {
                return Ok(0);
            };
            let asked: HashSet<&str> = rule_ids.iter().map(String::as_str).collect();
            state
                .verdicts
                .keys()
                .filter(|key| asked.contains(key.to_string().as_str()))
                .cloned()
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
                state.verdicts.retain(|key, _| !wanted.contains(key));
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
        let mut rules: Vec<VerifyKey> = Vec::new();
        let mut ordinary: Vec<CanonicalAddressMatch> = Vec::new();
        if let Some(stored) = self.rules.stored_rules_for(sid) {
            let book = &stored.rule_book;
            for written in [RouteRole::Primary, RouteRole::Secondary] {
                rules.extend(
                    book.set_for(written)
                        .rules()
                        .iter()
                        .filter(|r| r.enabled && r.action == RuleAction::Verify)
                        .filter_map(|r| VerifyKey::of(written, r)),
                );
                // Only rules for every program: an app-scoped one owns nothing
                // by name.
                ordinary.extend(
                    book.set_for(written)
                        .rules()
                        .iter()
                        .filter(|r| r.enabled && r.action != RuleAction::Verify)
                        .filter(|r| r.app_match.is_none())
                        .filter_map(|r| r.address_match.clone()),
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
            // A verdict outlives a renumbering: the rule it names is still
            // there, under whatever line number the edit left it.
            let before = state.verdicts.len();
            state.verdicts.retain(|key, _| rules.contains(key));
            let dropped = state.verdicts.len() != before;
            state.ips = rules
                .iter()
                .filter_map(|r| match r.address {
                    CanonicalAddressMatch::ExactIp(IpAddr::V4(ip)) => Some((ip, r.clone())),
                    _ => None,
                })
                .collect();
            state.rules = rules;
            state.ordinary = ordinary;
            state.subdomains = subdomains;
            let VerifyState {
                rules,
                ordinary,
                pending,
                recent,
                ..
            } = &mut *state;
            pending.retain(|host, c| {
                rules.contains(&c.key)
                    && (c.port.is_some()
                        || decider(rules, ordinary, host, subdomains) == Some(&c.key))
            });
            // Queries that came before a rule was read now count for it. With
            // no `?` rule at all they are dropped: such a principal keeps no
            // buffer.
            let earlier = std::mem::take(recent);
            for (host, addresses) in earlier {
                let key = decider(rules, ordinary, &host, subdomains).cloned();
                match key {
                    Some(key) if pending.len() < MAX_PENDING => {
                        pending.insert(
                            host,
                            Candidate {
                                key,
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
