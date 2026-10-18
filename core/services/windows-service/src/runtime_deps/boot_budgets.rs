//! Time budgets for boot-path steps that talk to the filtering engine (WFP)
//! or spin up an observer, plus the bounded-wait helper they share.

use super::*;

/// How long the startup strip may take before boot goes on without it — a
/// wedged filtering engine otherwise parks the whole service in
/// START_PENDING with no way back.
pub(super) const ORPHAN_STRIP_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);

/// Budget for bringing a connection observer up. Shorter than the strip's: the
/// trace is pure diagnostics and nothing downstream waits on it.
pub(super) const CONN_OBSERVER_START_BUDGET: std::time::Duration =
    std::time::Duration::from_secs(10);

/// How long boot waits for the engine handle behind the apply layer.
/// `FwpmEngineOpen0` is an RPC into BFE and a wedged engine never answers it;
/// past this the service comes up without enforcement and the opener keeps
/// asking in the background.
const WFP_OPEN_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);

/// Pause between open attempts the engine refused, doubling up to the cap.
const WFP_OPEN_RETRY_FIRST: std::time::Duration = std::time::Duration::from_secs(5);
const WFP_OPEN_RETRY_CAP: std::time::Duration = std::time::Duration::from_secs(60);

/// How long the offline sweep waits on the filtering engine.
///
/// Generous: a real sweep of a few thousand filters measures in seconds, and
/// this runs when something is already wrong. Bounded all the same — the whole
/// point of this tool is to rescue a machine whose engine may be the thing that
/// is stuck, and a recovery command that hangs forever rescues nobody.
pub(super) const WFP_SWEEP_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// How slow an engine open has to be before it is worth a line in the log. A
/// healthy open is single-digit milliseconds.
const WFP_OPEN_SLOW_THRESHOLD: std::time::Duration = std::time::Duration::from_secs(1);

#[derive(Clone, Copy, PartialEq, Eq)]
enum OpenPhase {
    Booting,
    OpenedInTime,
    BootGaveUp,
}

/// Open `session` on a thread of its own, retrying until the engine answers
/// or a stop begins, and wait up to the boot budget for it. Returns whether
/// it opened in time; when it did not, `on_late` runs on the opener's thread
/// once it does, so whoever owns the session finishes the start there.
pub(super) fn open_wfp_session_or_keep_trying(
    session: Arc<WfpSession>,
    on_late: Box<dyn FnOnce() + Send>,
) -> bool {
    let started = std::time::Instant::now();
    let handoff = Arc::new((Mutex::new(OpenPhase::Booting), std::sync::Condvar::new()));
    let opener_handoff = Arc::clone(&handoff);
    let spawned = std::thread::Builder::new()
        .name("nrr-wfp-open".to_string())
        .spawn(move || {
            let opened = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                open_and_hand_over(&session, &opener_handoff, started, on_late)
            }));
            if opened.is_err() {
                tracing::error!(
                    target: "nrr::boot",
                    msg_key = "svc-boot-wfp-opener-panicked",
                    "the filtering-engine opener stopped on an internal error — rules stay \
                     unenforced until the service restarts",
                );
            }
        });
    if spawned.is_err() {
        tracing::error!(
            target: "nrr::boot",
            "could not start the filtering-engine opener — the service runs without enforcement",
        );
        return false;
    }
    let (phase, answered) = &*handoff;
    let guard = phase.lock().unwrap_or_else(|p| p.into_inner());
    let (mut guard, _) = answered
        .wait_timeout_while(guard, WFP_OPEN_BUDGET, |p| *p == OpenPhase::Booting)
        .unwrap_or_else(|p| p.into_inner());
    if *guard == OpenPhase::OpenedInTime {
        let elapsed = started.elapsed();
        if elapsed >= WFP_OPEN_SLOW_THRESHOLD {
            tracing::warn!(
                target: "nrr::boot",
                msg_key = "svc-boot-wfp-session-slow",
                elapsed_ms = elapsed.as_millis() as u64,
                "the filtering engine took a long time to hand out a session — enforcement is up, \
                 but the engine on this machine is answering slowly",
            );
        }
        return true;
    }
    *guard = OpenPhase::BootGaveUp;
    tracing::error!(
        target: "nrr::boot",
        msg_key = "svc-boot-wfp-session-timeout",
        budget_secs = WFP_OPEN_BUDGET.as_secs(),
        "no filtering-engine session within the boot budget — the service starts without \
         enforcement and keeps asking; rules are applied as soon as the engine answers",
    );
    false
}

/// The opener's whole run: open, then tell boot it was in time or finish the
/// start itself. A stop that began meanwhile gets nothing applied: the stop
/// owns the engine from there.
fn open_and_hand_over(
    session: &WfpSession,
    handoff: &(Mutex<OpenPhase>, std::sync::Condvar),
    started: std::time::Instant,
    on_late: Box<dyn FnOnce() + Send>,
) {
    if !open_until_answered(session) {
        return;
    }
    // Every runtime filter write goes through this session, so from here a
    // late boot strip could hit a live kill-switch.
    super::offline_reset::mark_runtime_owns_filters();
    let (phase, answered) = handoff;
    let late = {
        let mut phase = phase.lock().unwrap_or_else(|p| p.into_inner());
        if *phase == OpenPhase::Booting {
            *phase = OpenPhase::OpenedInTime;
            answered.notify_all();
            false
        } else {
            true
        }
    };
    if !late || nrr_service_runtime::teardown_in_progress() {
        return;
    }
    tracing::info!(
        target: "nrr::boot",
        msg_key = "svc-boot-wfp-session-opened-late",
        waited_secs = started.elapsed().as_secs(),
        "the filtering engine answered late — rules are enforced from now on",
    );
    on_late();
}

/// Blocks until the engine hands out a session; `false` when a stop began
/// first. Only the first refusal is worth a line.
fn open_until_answered(session: &WfpSession) -> bool {
    let mut pause = WFP_OPEN_RETRY_FIRST;
    let mut reported = false;
    loop {
        if nrr_service_runtime::teardown_in_progress() {
            return false;
        }
        match session.ensure_open() {
            Ok(()) => return true,
            Err(e) if !reported => {
                reported = true;
                tracing::warn!(
                    target: "nrr::boot",
                    msg_key = "svc-boot-wfp-session-open-failed",
                    error = %e,
                    retry_secs = pause.as_secs(),
                    "the filtering engine refused a session — retrying",
                );
            }
            Err(e) => {
                tracing::debug!(target: "nrr::boot", error = %e, "filtering engine still refuses a session")
            }
        }
        std::thread::sleep(pause);
        pause = (pause * 2).min(WFP_OPEN_RETRY_CAP);
    }
}

/// Run `work` on its own thread and give up waiting after `budget`.
///
/// A thread left behind is deliberate: whatever it is stuck in would not answer
/// a cancel either, and every caller here does work that is safe to land late
/// or never. Returns the timeout as a `Transient` error so callers degrade
/// through their existing error path.
pub(super) fn with_budget<T, F>(
    what: &'static str,
    budget: std::time::Duration,
    work: F,
) -> Result<T, nrr_platform_windows::PlatformError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, nrr_platform_windows::PlatformError> + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    if std::thread::Builder::new()
        .name("nrr-budgeted-start".to_string())
        .spawn(move || {
            let _ = tx.send(work());
        })
        .is_err()
    {
        return Err(nrr_platform_windows::PlatformError::Transient {
            operation: "budgeted start",
            detail: format!("could not spawn a worker for {what}"),
        });
    }
    rx.recv_timeout(budget).unwrap_or_else(|_| {
        tracing::warn!(
            target: "nrr::boot",
            msg_key = "svc-boot-step-budget-exceeded",
            what,
            budget_secs = budget.as_secs(),
            "step did not answer within its budget — continuing without it",
        );
        Err(nrr_platform_windows::PlatformError::Transient {
            operation: "budgeted start",
            detail: format!("{what} did not finish within {:?}", budget),
        })
    })
}
