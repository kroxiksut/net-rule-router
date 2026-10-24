//! What `cleanup` does on a machine whose service is not running.
//!
//! The boot wiring next door builds a service; this builds nothing and only
//! takes away — filters, routes, the NRPT redirect, the DNS suffix list, the
//! machine-wide engine options. It is the path a user reaches after a hard kill or a crash, so
//! every step is best-effort and says what it could not do rather than
//! stopping at the first refusal.

use super::*;

use std::sync::atomic::{AtomicBool, Ordering};

use nrr_platform_windows::constants::MAX_FILTERS_PER_TRANSACTION;
use nrr_platform_windows::{ErrorClass, PlatformError, WfpAction};
use nrr_service_runtime::lifecycle_matrix::{
    after_crash_plan, orphaned_blocks_at_start, FilterTeardown, LifecycleInputs, OrphanedBlocks,
};

/// Set once the runtime holds its own engine session. From then on a block
/// under our provider may be a live kill-switch, and the runtime strips its
/// predecessor's orphans itself before its first write — so a boot strip that
/// lands after this point must not delete anything.
static RUNTIME_OWNS_FILTERS: AtomicBool = AtomicBool::new(false);

pub(super) fn mark_runtime_owns_filters() {
    RUNTIME_OWNS_FILTERS.store(true, Ordering::SeqCst);
}

#[derive(Debug, PartialEq, Eq)]
enum OrphanStrip {
    Stripped(usize),
    /// The strip landed after the runtime took over; nothing was deleted.
    RuntimeOwnsFilters,
}

/// Deletes the block filters that existed when it enumerated, unless the
/// runtime has taken over. The check runs inside each open write transaction:
/// the engine serializes writers, so a check that passes there cannot be
/// overtaken by a runtime write before the deletes commit.
fn strip_orphaned_blocks_unless_runtime_armed(
    session: &WfpSession,
    runtime_armed: &AtomicBool,
) -> Result<OrphanStrip, PlatformError> {
    let orphans: Vec<_> = session
        .enumerate_our_filters()?
        .into_iter()
        .filter(|f| f.action == WfpAction::Block)
        .map(|f| f.id)
        .collect();
    let mut removed = 0usize;
    for batch in orphans.chunks(MAX_FILTERS_PER_TRANSACTION) {
        let txn = session.begin_transaction()?;
        if runtime_armed.load(Ordering::SeqCst) {
            // Dropping the guard aborts; batches already committed held only
            // orphans, since the check passed inside their transactions.
            return Ok(OrphanStrip::RuntimeOwnsFilters);
        }
        for id in batch {
            match session.delete_filter(*id) {
                Ok(()) => removed += 1,
                Err(e) if e.classify() == ErrorClass::Idempotent => {}
                // Best-effort: one block that will not go must not keep the
                // rest armed.
                Err(e) => tracing::warn!(
                    target: "nrr::runtime",
                    msg_key = "svc-offline-standalone-strip-failed",
                    error = %e,
                    "standalone block-filter strip failed",
                ),
            }
        }
        txn.commit()?;
    }
    Ok(OrphanStrip::Stripped(removed))
}

pub(crate) fn strip_orphaned_block_filters_standalone() {
    let (tx, rx) = std::sync::mpsc::channel();
    // Detached on purpose: if it is stuck in the engine it will not answer a
    // cancel either. A late landing is safe: it deletes nothing once the
    // runtime owns the filters.
    std::thread::Builder::new()
        .name("nrr-orphan-strip".to_string())
        .spawn(move || {
            strip_orphaned_block_filters_blocking();
            let _ = tx.send(());
        })
        .ok();
    if rx.recv_timeout(ORPHAN_STRIP_BUDGET).is_err() {
        tracing::warn!(
            target: "nrr::runtime",
            msg_key = "svc-offline-orphan-strip-timed-out",
            budget_secs = ORPHAN_STRIP_BUDGET.as_secs(),
            "startup: orphaned-filter strip did not finish in time — continuing the boot without it \
             (a leftover kill-switch may still be in force until the strip lands)",
        );
    }
}

fn strip_orphaned_block_filters_blocking() {
    // With leak protection on for anyone, a dead instance's blocks hold until
    // the first pass adopts them; stripping them here is a leak for the whole
    // boot, endless under a crash loop.
    if orphaned_blocks_at_start(leak_guard_armed_anywhere()) == OrphanedBlocks::AdoptOnFirstPass {
        tracing::info!(
            target: "nrr::runtime",
            msg_key = "svc-offline-orphan-strip-deferred",
            "startup: leak protection is on — a previous instance's blocks stay until the first pass adopts them",
        );
        return;
    }
    tracing::debug!(target: "nrr::runtime", "startup: opening WFP to strip orphaned block filters");
    let api: Arc<dyn WindowsApiPort> = Arc::new(ProductionWindowsApi);
    match WfpSession::open(Arc::clone(&api)) {
        Ok(session) => {
            match strip_orphaned_blocks_unless_runtime_armed(&session, &RUNTIME_OWNS_FILTERS) {
                Ok(OrphanStrip::Stripped(0)) => {}
                Ok(OrphanStrip::RuntimeOwnsFilters) => tracing::info!(
                    target: "nrr::runtime",
                    "startup: orphaned-filter strip landed after the runtime took over its filters — \
                     skipped (the runtime already stripped its predecessor's blocks)",
                ),
                Ok(OrphanStrip::Stripped(n)) => tracing::warn!(
                    target: "nrr::runtime",
                    msg_key = "svc-offline-standalone-blocks-stripped",
                    stripped_blocks = n as u64,
                    "startup: stripped orphaned block/kill-switch WFP filter(s) \
                     (standalone recovery path)",
                ),
                Err(e) => tracing::warn!(
                    target: "nrr::runtime",
                    msg_key = "svc-offline-standalone-strip-failed",
                    error = %e,
                    "standalone block-filter strip failed",
                ),
            }
        }
        Err(e) => tracing::warn!(
            target: "nrr::runtime",
            msg_key = "svc-offline-standalone-engine-open-failed",
            error = %e,
            "standalone block-filter strip: WFP engine open failed",
        ),
    }
    tracing::debug!(target: "nrr::runtime", "startup: orphaned-filter strip finished");
}

/// Disaster-recovery offline reset — strip **every** NetRuleRouter WFP filter
/// (block AND permit) and any leftover NRR-owned route WITHOUT the service
/// running. Backs the `cleanup` console subcommand.
///
/// A crashed/hard-killed service leaves its non-dynamic WFP filters behind:
/// they survive `taskkill /F` until deleted or rebooted, and an orphaned
/// kill-switch block can lock the machine off the network with nothing left
/// to lift it. Opens its own short-lived WFP engine session — the same sweep
/// [`nrr_service_runtime::per_sid_orchestrator::PerSidApplyOrchestrator::cleanup_wfp`]
/// runs via [`WfpSession::cleanup_all`] — deletes our filters, then sweeps the
/// OS route table for routes carrying our signature. Safe when the service is
/// installed but stopped (nothing else holds the engine).
///
/// Requires elevation: `FwpmEngineOpen0` returns access-denied for a
/// non-elevated caller ([`ErrorClass::PrivilegeRequired`]), turned into a
/// "re-run elevated" message.
pub(crate) fn run_offline_reset() -> std::process::ExitCode {
    unless_service_live(live_service_state(), || {
        with_overrides_revoked(finish_offline_reset())
    })
}

/// A live service would put every piece straight back, and its blocks are a
/// protection the user asked for: that is the stopping variant's call, so
/// `reset` runs only when the service is stopped or absent.
fn unless_service_live(
    live: Option<nrr_platform_api::service_control::ServiceRunState>,
    reset: impl FnOnce() -> std::process::ExitCode,
) -> std::process::ExitCode {
    if let Some(state) = live {
        eprintln!(
            "cleanup: the service is {}; it keeps this state in place and would put back \
             anything removed now.",
            state.slug()
        );
        eprintln!(
            "To stop it and restore the network, run `{} reset-network --confirm --stop-service`.",
            nrr_shared::product_identity::BinaryRole::Console.host_file_name()
        );
        return std::process::ExitCode::from(
            nrr_platform_api::service_control::EXIT_SERVICE_RUNNING,
        );
    }
    reset()
}

/// The user's emergency reset also takes back every confirmed override of the
/// protection of system programs, so the machine comes back protected. Not
/// the after-crash sweep: nobody asked for a reset there.
fn with_overrides_revoked(code: std::process::ExitCode) -> std::process::ExitCode {
    let path = match nrr_storage::resolve_storage_topology(
        &nrr_storage::StorageProfile::ProductionService,
    ) {
        Ok(topology) => topology.state_db_path,
        Err(e) => {
            eprintln!(
                "cleanup: the service's data could not be found ({e:?}); \
                 no confirmation was revoked."
            );
            return std::process::ExitCode::from(1);
        }
    };
    match nrr_service_runtime::override_grants::revoke_all_offline(&path) {
        Ok(n) => {
            println!("  rules confirmed despite the protection: {n} revoked");
            code
        }
        Err(e) => {
            eprintln!(
                "cleanup: rules confirmed despite the protection could not be revoked ({e}); \
                 revoke them in the rules list once the service runs."
            );
            std::process::ExitCode::from(1)
        }
    }
}

/// "Stop the service and restore the network": a clean stop, the process ended
/// when it hangs past the budget, then the same sweep as `cleanup`.
///
/// The SCM restarts a process that was ended, so its recovery actions are off
/// from the stop until the sweep is done; without that hold the service is not
/// ended at all, only asked to stop.
pub(crate) fn run_stop_and_cleanup() -> std::process::ExitCode {
    use nrr_platform_api::service_control::{
        ServiceControlError, ServiceControlPort, STOP_FOR_RESET_BUDGET,
    };
    use nrr_platform_windows::service_control::{hold_recovery, WindowsServiceControl};
    let control = WindowsServiceControl::new();
    let hold = match hold_recovery() {
        Ok(hold) => Some(hold),
        Err(ServiceControlError::NotInstalled) => None,
        Err(ServiceControlError::AccessDenied) => return std::process::ExitCode::from(3),
        Err(e) => {
            eprintln!(
                "stop-and-cleanup: the service's restart-on-failure could not be paused ({e}); \
                 it will be asked to stop, not ended."
            );
            None
        }
    };
    let stopped = if hold.is_some() {
        control.stop_or_kill(STOP_FOR_RESET_BUDGET)
    } else {
        control.stop(STOP_FOR_RESET_BUDGET)
    };
    match stopped {
        Ok(()) | Err(ServiceControlError::NotInstalled) => {}
        Err(ServiceControlError::AccessDenied) => return std::process::ExitCode::from(3),
        Err(e) => {
            eprintln!(
                "stop-and-cleanup: the service could not be stopped ({e}); nothing was reset."
            );
            return std::process::ExitCode::from(1);
        }
    }
    let code = with_overrides_revoked(finish_offline_reset());
    if let Some(hold) = hold {
        if let Err(e) = hold.release() {
            eprintln!(
                "stop-and-cleanup: the service's restart-on-failure could not be put back ({e}); \
                 reinstalling the service restores it."
            );
        }
    }
    if let Some(state) = live_service_state() {
        eprintln!(
            "stop-and-cleanup: the service is {} again; it puts back what was removed.",
            state.slug()
        );
        return std::process::ExitCode::from(1);
    }
    code
}

/// The service's state when it is anything but stopped or absent. A question
/// the SCM cannot answer is no reason to leave a machine cut off: it is said,
/// and read as stopped.
fn live_service_state() -> Option<nrr_platform_api::service_control::ServiceRunState> {
    use nrr_platform_api::service_control::{ServiceControlPort, ServiceRunState};
    match nrr_platform_windows::service_control::WindowsServiceControl::new().query() {
        Ok(report) => report
            .map(|report| report.run_state)
            .filter(|state| *state != ServiceRunState::Stopped),
        Err(e) => {
            eprintln!("cleanup: the service manager could not say whether the service runs ({e}).");
            None
        }
    }
}

fn finish_offline_reset() -> std::process::ExitCode {
    match sweep_orphaned_machine_state() {
        SweepOutcome::Done => std::process::ExitCode::SUCCESS,
        // The console relays this verbatim as its own "needs privilege" code,
        // which is what its documented contract promises and what makes its
        // elevation offer fire. Reported as a plain failure it was
        // indistinguishable from a wedged engine, and the one command a locked-
        // out user is told to run gave the wrong advice back.
        SweepOutcome::PrivilegeRequired => std::process::ExitCode::from(3),
        SweepOutcome::Failed => std::process::ExitCode::from(1),
    }
}

/// SCM's last failure action, run once the restarts are spent. Nothing answers
/// on the loopback resolver any more, so the DNS redirect goes whatever the
/// settings; filters and routes go too unless someone's leak protection asked
/// for blocking over leaking.
pub(crate) fn run_after_crash() -> std::process::ExitCode {
    use nrr_service_runtime::lifecycle_journal::{after_crash_record, AfterCrashResult};
    let plan = after_crash_plan(LifecycleInputs {
        leak_guard_armed: leak_guard_armed_anywhere(),
        keep_rule_routes_on_stop: false,
    });
    // This process has no log of ours: the operator's event log is the only
    // trace that the service gave up.
    let record = |result| {
        use nrr_platform_api::system_event_log::SystemEventLogPort;
        nrr_platform_windows::event_log::WindowsEventLog::new().write(&after_crash_record(result));
    };
    if plan.filters == FilterTeardown::RemoveAll {
        let done = matches!(sweep_orphaned_machine_state(), SweepOutcome::Done);
        record(if done {
            AfterCrashResult::NetworkRestored
        } else {
            AfterCrashResult::Incomplete
        });
        return std::process::ExitCode::from(if done { 0 } else { 1 });
    }
    let dns_sweep = nrr_platform_windows::dns_redirect::sweep_orphan_dns_state(
        &nrr_platform_windows::dns_redirect::TransactedNrptStore,
        &nrr_platform_windows::dns_redirect::WindowsSearchList,
    );
    println!("NetRuleRouter: the service stopped for good; name resolution handed back.");
    println!("  Leak protection is on, so its blocks stay until the service runs again.");
    if dns_sweep.is_clean() {
        record(AfterCrashResult::DnsHandedBack);
        std::process::ExitCode::SUCCESS
    } else {
        eprintln!(
            "after-crash: the DNS redirect could not be removed; run \
             `nrr-cli reset-network --confirm`."
        );
        record(AfterCrashResult::Incomplete);
        std::process::ExitCode::from(1)
    }
}

/// Unknown counts as armed: lifting a block the user asked for is the one
/// mistake this question exists to avoid.
pub(super) fn leak_guard_armed_anywhere() -> bool {
    let Ok(topology) =
        nrr_storage::resolve_storage_topology(&nrr_storage::StorageProfile::ProductionService)
    else {
        return true;
    };
    nrr_service_runtime::lifecycle_matrix::leak_guard_armed_at(&topology.state_db_path)
}

/// Why an offline sweep stopped.
pub(crate) enum SweepOutcome {
    /// Everything reachable was cleared.
    Done,
    /// The engine refused this caller — the console has to be elevated.
    PrivilegeRequired,
    /// Anything else; already reported on stderr.
    Failed,
}

/// The sweep itself. Not a `bool`: "we were refused" and "it did not work" ask
/// opposite things of the person running it, and only the sweep knows which
/// happened.
pub(crate) fn sweep_orphaned_machine_state() -> SweepOutcome {
    let api: Arc<dyn WindowsApiPort> = Arc::new(ProductionWindowsApi);
    let wfp_api = Arc::clone(&api);
    sweep_in_order(&SweepSteps {
        dns: &|| {
            nrr_platform_windows::dns_redirect::sweep_orphan_dns_state(
                &nrr_platform_windows::dns_redirect::TransactedNrptStore,
                &nrr_platform_windows::dns_redirect::WindowsSearchList,
            )
        },
        // Opening the engine and sweeping it are one budgeted unit: both are
        // RPC into the Base Filtering Engine, and a wedged engine answers
        // neither. `cleanup_all` deletes every filter under our provider in one
        // transaction, as the orchestrator's `cleanup_wfp` does.
        wfp: &|| {
            let api = Arc::clone(&wfp_api);
            with_budget("WFP filter sweep", WFP_SWEEP_BUDGET, move || {
                WfpSession::open(api).and_then(|session| session.cleanup_all())
            })
        },
        // An instance that was killed never restored the engine options it
        // changed; it wrote down what they held, which makes this possible.
        engine_options: &nrr_platform_windows::conn_observe::wfp_events::restore_engine_options,
        // Signature-based, so it needs no per-SID state; non-fatal, our routes
        // do not survive a reboot.
        routes: &|| {
            nrr_service_runtime::route_reconciler::sweep_owned_routes(
                Arc::clone(&api) as Arc<dyn nrr_platform_api::route_table::RouteTablePort>
            )
            .map_err(|e| e.to_string())
        },
    })
}

/// The steps of an offline sweep, apart so their order can be tested.
pub(crate) struct SweepSteps<'a> {
    pub(crate) dns: &'a dyn Fn() -> nrr_platform_windows::dns_redirect::OrphanDnsSweep,
    pub(crate) wfp: &'a dyn Fn() -> Result<usize, PlatformError>,
    pub(crate) engine_options: &'a dyn Fn(),
    pub(crate) routes: &'a dyn Fn() -> Result<usize, String>,
}

/// DNS first and whatever else fails: a crashed Mode-B session leaves an NRPT
/// catch-all pointing all name resolution at our dead loopback, and a wedged
/// filter engine that ends the sweep must not leave the machine without names.
/// The suffix list we wrote outlives even a reboot.
pub(crate) fn sweep_in_order(steps: &SweepSteps<'_>) -> SweepOutcome {
    let dns_sweep = (steps.dns)();
    if let Err(e) = &dns_sweep.nrpt_rules {
        eprintln!(
            "cleanup: NRPT/DNS-redirect sweep failed ({e}); if DNS is broken, remove the \
             rule manually (`Get-DnsClientNrptRule | Where Comment -eq \
             'NetRuleRouter-ModeB-DnsRedirect' | Remove-DnsClientNrptRule -Force`) or reboot."
        );
    }
    if let Err(e) = &dns_sweep.search_list {
        eprintln!(
            "cleanup: DNS suffix search list sweep failed ({e}); check the list with \
             `Get-DnsClientGlobalSetting` and remove suffixes NetRuleRouter added."
        );
    }

    let filters_removed = match (steps.wfp)() {
        Ok(n) => n,
        Err(e) if e.classify() == ErrorClass::PrivilegeRequired => {
            eprintln!(
                "cleanup: access denied opening the WFP engine. Re-run from an elevated \
                 (Administrator) console (the `scripts/reset-network.ps1` wrapper \
                 self-elevates via UAC)."
            );
            report_dns(&dns_sweep);
            return SweepOutcome::PrivilegeRequired;
        }
        Err(nrr_platform_windows::PlatformError::Transient {
            operation: "budgeted start",
            ..
        }) => {
            eprintln!(
                "cleanup: the Windows Base Filtering Engine did not answer within \
                 {} s — it is wedged, and nothing here can move it.",
                WFP_SWEEP_BUDGET.as_secs()
            );
            eprintln!(
                "  Our filters are not persistent: a REBOOT clears them and restores \
                 the network. Restarting the `BFE` service first is worth a try."
            );
            report_dns(&dns_sweep);
            return SweepOutcome::Failed;
        }
        Err(e) => {
            eprintln!("cleanup: WFP filter sweep failed: {e:?}");
            report_dns(&dns_sweep);
            return SweepOutcome::Failed;
        }
    };

    (steps.engine_options)();
    let routes_removed: Option<usize> = match (steps.routes)() {
        Ok(n) => Some(n),
        Err(e) => {
            eprintln!(
                "cleanup: route sweep failed ({e}); a reboot fully clears any remaining \
                 NetRuleRouter routes."
            );
            None
        }
    };

    // ── Summary ────────────────────────────────────────────────────────
    println!("NetRuleRouter offline reset complete.");
    println!("  WFP filters removed: {filters_removed}");
    match routes_removed {
        Some(n) => println!("  routes removed: {n}"),
        None => println!("  routes removed: <sweep skipped — clears on reboot>"),
    }
    match &dns_sweep.nrpt_rules {
        Ok(n) => println!("  DNS redirect (NRPT) rules removed: {n}"),
        Err(_) => println!("  DNS redirect (NRPT) rules: <sweep failed — see above>"),
    }
    match &dns_sweep.search_list {
        Ok(true) => println!("  DNS suffix search list: restored"),
        Ok(false) => println!("  DNS suffix search list: nothing of ours"),
        Err(_) => println!("  DNS suffix search list: <sweep failed — see above>"),
    }
    println!("Reboot to fully clear any remainder.");
    if dns_sweep.is_clean() {
        SweepOutcome::Done
    } else {
        SweepOutcome::Failed
    }
}

/// What the DNS half did, for a sweep that stopped before its summary.
fn report_dns(dns_sweep: &nrr_platform_windows::dns_redirect::OrphanDnsSweep) {
    match &dns_sweep.nrpt_rules {
        Ok(n) => println!("  DNS redirect (NRPT) rules removed: {n}"),
        Err(_) => println!("  DNS redirect (NRPT) rules: <sweep failed — see above>"),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nrr_platform_windows::{
        MockWindowsApi, WfpFilterAction, WfpFilterId, WfpFilterSpec, WfpLayerKey,
    };
    use std::net::Ipv4Addr;

    fn filter(id: u64, action: WfpAction) -> WfpFilterSpec {
        WfpFilterSpec {
            layer: WfpLayerKey::AleAuthConnectV4,
            action,
            remote_ip: Some(Ipv4Addr::new(192, 0, 2, id as u8)),
            remote_ip_set: Vec::new(),
            remote_ip_set_v6: Vec::new(),
            remote_port: None,
            weight: 0x100000 + id,
            id: WfpFilterId::from_raw(id),
            user_sid: None,
            app_pattern: None,
            local_interface_luid: None,
            remote_subnet: None,
            remote_subnet_v6: None,
            ip_protocol: None,
            remote_subnet_set: Vec::new(),
        }
    }

    fn install(session: &WfpSession, filters: &[WfpFilterSpec]) {
        let actions: Vec<_> = filters
            .iter()
            .cloned()
            .map(WfpFilterAction::AddFilter)
            .collect();
        session.execute_wfp_plan(&actions).unwrap();
    }

    fn installed_ids(api: &MockWindowsApi) -> Vec<u64> {
        let mut ids: Vec<u64> = api
            .wfp_filters
            .lock()
            .unwrap()
            .iter()
            .map(|f| f.id.raw)
            .collect();
        ids.sort_unstable();
        ids
    }

    fn session(api: &Arc<MockWindowsApi>) -> WfpSession {
        WfpSession::open(Arc::clone(api) as Arc<dyn WindowsApiPort>).unwrap()
    }

    #[test]
    fn strip_before_the_runtime_arms_removes_orphaned_blocks_and_keeps_permits() {
        let api = Arc::new(MockWindowsApi::new());
        let crashed_run = session(&api);
        install(
            &crashed_run,
            &[
                filter(1, WfpAction::Block),
                filter(2, WfpAction::Permit),
                filter(3, WfpAction::Block),
            ],
        );

        let outcome =
            strip_orphaned_blocks_unless_runtime_armed(&session(&api), &AtomicBool::new(false))
                .unwrap();

        assert_eq!(outcome, OrphanStrip::Stripped(2));
        assert_eq!(installed_ids(&api), vec![2]);
    }

    #[test]
    fn strip_landing_after_the_runtime_armed_leaves_its_blocks_installed() {
        let api = Arc::new(MockWindowsApi::new());
        install(
            &session(&api),
            &[filter(1, WfpAction::Block), filter(3, WfpAction::Block)],
        );
        // The runtime takes over: strips its predecessor's blocks itself, then
        // arms a kill-switch — one under an id an orphan also carried, since
        // filter ids are derived deterministically.
        let armed = AtomicBool::new(true);
        let runtime = session(&api);
        runtime.cleanup_blocks_only().unwrap();
        install(
            &runtime,
            &[filter(1, WfpAction::Block), filter(10, WfpAction::Block)],
        );

        let outcome = strip_orphaned_blocks_unless_runtime_armed(&session(&api), &armed).unwrap();

        assert_eq!(outcome, OrphanStrip::RuntimeOwnsFilters);
        assert_eq!(installed_ids(&api), vec![1, 10]);
    }

    #[test]
    fn restore_network_refuses_a_live_service_and_removes_nothing() {
        use nrr_platform_api::service_control::{ServiceRunState, EXIT_SERVICE_RUNNING};
        for live in [
            ServiceRunState::Running,
            ServiceRunState::StartPending,
            ServiceRunState::StopPending,
            ServiceRunState::Other,
        ] {
            let mut reset_ran = false;
            let code = unless_service_live(Some(live), || {
                reset_ran = true;
                std::process::ExitCode::SUCCESS
            });
            assert!(!reset_ran, "{live:?}: the sweep ran under a live service");
            assert_eq!(code, std::process::ExitCode::from(EXIT_SERVICE_RUNNING));
        }
        let mut reset_ran = false;
        let code = unless_service_live(None, || {
            reset_ran = true;
            std::process::ExitCode::SUCCESS
        });
        assert!(reset_ran, "a stopped service is swept");
        assert_eq!(code, std::process::ExitCode::SUCCESS);
    }

    #[test]
    fn strip_crossing_the_batch_cap_removes_every_orphan() {
        let api = Arc::new(MockWindowsApi::new());
        let orphans: Vec<_> = (0..(MAX_FILTERS_PER_TRANSACTION as u64 + 3))
            .map(|id| filter(id, WfpAction::Block))
            .collect();
        install(&session(&api), &orphans);

        let outcome =
            strip_orphaned_blocks_unless_runtime_armed(&session(&api), &AtomicBool::new(false))
                .unwrap();

        assert_eq!(outcome, OrphanStrip::Stripped(orphans.len()));
        assert!(installed_ids(&api).is_empty());
    }

    /// A wedged or refusing filter engine ends the sweep early. The NRPT
    /// redirect to our dead resolver must already be gone by then, or the
    /// machine is left without names until somebody finds the rule by hand.
    #[test]
    fn the_dns_redirect_goes_first_whatever_the_filter_engine_does() {
        use std::cell::RefCell;
        let failures = [
            PlatformError::AccessDenied {
                operation: "FwpmEngineOpen0",
            },
            PlatformError::Transient {
                operation: "budgeted start",
                detail: "wedged".to_owned(),
            },
            PlatformError::StateCorrupted {
                detail: "broken".to_owned(),
            },
        ];
        for failure in failures {
            let order = RefCell::new(Vec::new());
            let wfp_error = RefCell::new(Some(failure));
            let outcome = sweep_in_order(&SweepSteps {
                dns: &|| {
                    order.borrow_mut().push("dns");
                    nrr_platform_windows::dns_redirect::OrphanDnsSweep {
                        nrpt_rules: Ok(1),
                        search_list: Ok(false),
                    }
                },
                wfp: &|| {
                    order.borrow_mut().push("wfp");
                    Err(wfp_error.borrow_mut().take().expect("one call"))
                },
                engine_options: &|| order.borrow_mut().push("engine"),
                routes: &|| {
                    order.borrow_mut().push("routes");
                    Ok(0)
                },
            });
            assert!(!matches!(outcome, SweepOutcome::Done));
            assert_eq!(order.borrow().first(), Some(&"dns"), "{:?}", order.borrow());
            assert!(order.borrow().contains(&"dns"));
        }
    }
}
