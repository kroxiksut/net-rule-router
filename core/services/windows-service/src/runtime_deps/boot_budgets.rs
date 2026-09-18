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

/// Budget for the boot-path engine handle behind the apply layer. `FwpmEngineOpen0`
/// is an RPC into BFE, and a wedged engine never answers it — this call sits on
/// the only path to Running, so without a ceiling the service parks in
/// START_PENDING for good. Timing out costs enforcement (the apply layer drops to
/// noop) and buys a service that is up, reachable over IPC and diagnosable.
const WFP_OPEN_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);

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

pub(super) fn open_wfp_session_budgeted(
    api: Arc<dyn WindowsApiPort>,
) -> Result<WfpSession, nrr_platform_windows::PlatformError> {
    let started = std::time::Instant::now();
    let opened = with_budget(
        "WFP engine open (apply layer)",
        WFP_OPEN_BUDGET,
        move || WfpSession::open(api),
    );
    let elapsed = started.elapsed();
    match &opened {
        Ok(_) if elapsed >= WFP_OPEN_SLOW_THRESHOLD => tracing::warn!(
            target: "nrr::boot",
            elapsed_ms = elapsed.as_millis() as u64,
            "the filtering engine took a long time to hand out a session — enforcement is up, \
             but the engine on this machine is answering slowly",
        ),
        Ok(_) => {}
        Err(_) => tracing::error!(
            target: "nrr::boot",
            elapsed_ms = elapsed.as_millis() as u64,
            budget_secs = WFP_OPEN_BUDGET.as_secs(),
            "could not get a filtering-engine session within the boot budget — the service will \
             start WITHOUT enforcement (rules are not applied). Restart the Base Filtering Engine \
             (BFE) service and then restart this service",
        ),
    }
    opened
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
