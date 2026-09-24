//! The automatic-proposal tick and the cadence that decides when it may run.
//!
//! Split out of `service_tasks`; the code is unchanged.

use super::*;

/// Companion-domain proposal tick.
///
/// Harvests the suggestions the DNS-observation feed has been accumulating and
/// acts on them per the active user's `auto_rules_mode`. Deliberately a separate,
/// SLOW task rather than work folded into the 1 Hz observe drain: proposal
/// computation walks the whole candidate table and the exclusions read the rule
/// book, neither of which belongs on a per-observation path. Optional class —
/// the discovery pass is a convenience and its failure must never affect routing.
/// How often a principal's automatic main-link pass may run, and whether they
/// asked for one at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AutoProbeCadence {
    pub enabled: bool,
    pub repeat: Duration,
}

/// The automatic "does it answer on the main link?" pass.
///
/// The manual button and this share one runner: the pass is the same question,
/// only the trigger differs. Without it the verdict on a suggestion stays
/// `Unknown` for as long as the additional route is down — which is exactly
/// when there is no traffic to learn from and the user is asked to decide with
/// no evidence.
#[derive(Clone)]
pub struct AutoProbeWiring {
    pub runner: Arc<dyn crate::ipc_handlers::providers::AutoRuleProbeRunner>,
    pub cadence: Arc<dyn Fn(&str) -> AutoProbeCadence + Send + Sync>,
}

/// Is this principal's automatic pass due?
///
/// `last` is when their previous pass started. Off means never; a pass that
/// just ran waits out the whole window, so a busy tick cannot turn a courtesy
/// check into a stream of connections.
pub(super) fn auto_probe_is_due(
    cadence: AutoProbeCadence,
    last: Option<Instant>,
    now: Instant,
) -> bool {
    if !cadence.enabled {
        return false;
    }
    match last {
        None => true,
        Some(previous) => now.saturating_duration_since(previous) >= cadence.repeat,
    }
}

/// Should this tick run the automatic main-link pass?
///
/// Both gates in one place so the caller cannot advance the window on a tick
/// that did not probe. `waiting` is how many suggestions are actually queued
/// for an answer.
///
/// A candidate we have never probed overrides the repeat window. The window
/// exists to stop us re-measuring the SAME hosts every ten seconds; a host that
/// just appeared has no measurement at all, and until it gets one it is offered
/// with "not checked on the main route" — which is exactly how a host the main
/// link serves perfectly well ends up looking like something to fix. Waiting up
/// to five minutes for that verdict means the user's first impression of a
/// fresh rule is formed before we know anything.
pub(super) fn auto_probe_should_run(
    cadence: AutoProbeCadence,
    last: Option<Instant>,
    now: Instant,
    waiting: usize,
    has_unprobed_candidate: bool,
) -> bool {
    if waiting == 0 || !cadence.enabled {
        return false;
    }
    has_unprobed_candidate || auto_probe_is_due(cadence, last, now)
}

pub fn build_auto_rules_task(
    engine: Arc<crate::auto_rules::AutoRulesEngine>,
    active_sid: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    auto_probe: Option<AutoProbeWiring>,
) -> ServiceTask {
    // Per principal: when their last automatic pass started, and which
    // candidate ids that pass covered. The ids are what tell a fresh host from
    // one we already measured — the count alone cannot, since an accepted offer
    // and a new one arriving in the same window leave it unchanged.
    type ProbeMark = (Instant, std::collections::HashSet<String>);
    let probed_at: Mutex<std::collections::HashMap<String, ProbeMark>> =
        Mutex::new(std::collections::HashMap::new());
    ServiceTask::periodic(
        TASK_ID_AUTO_RULES,
        TaskClass::Optional,
        AUTO_RULES_INTERVAL,
        0,
        move |_stop| {
            let Some(sid) = active_sid() else {
                tracing::debug!(
                    target: "nrr::auto-rules",
                    "companion-domain tick skipped: no routing-active user",
                );
                return TaskOutcome::Continue;
            };
            let summary = engine.tick(&sid, SystemTime::now());
            if let Some(probe) = auto_probe.as_ref() {
                let cadence = (probe.cadence)(&sid);
                let now = Instant::now();
                // Only when something is actually waiting on an answer: a pass
                // over an empty inbox leaves the machine for nothing.
                let pending: Vec<String> =
                    engine.candidates(&sid).into_iter().map(|c| c.id).collect();
                let waiting = pending.len();
                let (last, unprobed) = {
                    let seen = probed_at.lock().unwrap_or_else(|p| p.into_inner());
                    match seen.get(&sid) {
                        Some((at, covered)) => {
                            (Some(*at), pending.iter().any(|id| !covered.contains(id)))
                        }
                        None => (None, !pending.is_empty()),
                    }
                };
                if auto_probe_should_run(cadence, last, now, waiting, unprobed) {
                    // Stamped HERE, not at the due check. Stamping on every due
                    // tick spent the window on ticks where no pass ran: the
                    // inbox is empty most of the time, so the one moment a
                    // suggestion appeared almost never coincided with a due
                    // mark, and hosts kept being offered with no main-link
                    // verdict at all — which is exactly what makes a shared CDN
                    // look unreachable and land on the offer list.
                    probed_at
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .insert(sid.clone(), (now, pending.iter().cloned().collect()));
                    let accepted = probe.runner.probe(&sid, &[], &[]).accepted;
                    tracing::debug!(
                        target: "nrr::auto-rules",
                        sid = %sid,
                        accepted,
                        waiting,
                        unprobed,
                        "main-link pass started for parked suggestions",
                    );
                } else if waiting > 0 {
                    // A suggestion is waiting and the pass did not run. Says
                    // which of the two gates held it, because "no verdict" and
                    // "verdict says unreachable" produce the same offer.
                    tracing::debug!(
                        target: "nrr::auto-rules",
                        sid = %sid,
                        waiting,
                        enabled = cadence.enabled,
                        repeat_secs = cadence.repeat.as_secs(),
                        "main-link pass NOT started while suggestions wait",
                    );
                }
            }
            if summary.parked > 0 || summary.authored > 0 {
                tracing::info!(
                    target: "nrr::auto-rules",
                    sid = %sid,
                    parked = summary.parked,
                    authored = summary.authored,
                    pending = summary.pending,
                    published = summary.published,
                    "companion-domain tick: found addresses a routed site needs",
                );
            } else {
                // An empty tick and a tick that never ran look identical from
                // the outside; say which one happened.
                tracing::debug!(
                    target: "nrr::auto-rules",
                    sid = %sid,
                    pending = summary.pending,
                    "companion-domain tick: nothing new",
                );
            }
            TaskOutcome::Continue
        },
    )
}
