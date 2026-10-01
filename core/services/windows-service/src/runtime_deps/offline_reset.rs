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

    // ── WFP filter sweep (the lockout risk) ────────────────────────────
    // Opening the engine and sweeping it are one budgeted unit: both are RPC
    // into the Base Filtering Engine, and a wedged engine answers neither. This
    // command exists to rescue a machine that is already in trouble, so it must
    // come back and say so rather than sit there.
    //
    // `cleanup_all` enumerates every filter under the NRR provider GUID and
    // deletes it in one transaction (block AND permit) — the same sweep the
    // orchestrator's `cleanup_wfp` runs, minus the in-memory tracked-id pass
    // (there is no live orchestrator state to consult offline).
    let swept = with_budget("WFP filter sweep", WFP_SWEEP_BUDGET, {
        let api = Arc::clone(&api);
        move || WfpSession::open(api).and_then(|session| session.cleanup_all())
    });
    let filters_removed = match swept {
        Ok(n) => n,
        Err(e) if e.classify() == ErrorClass::PrivilegeRequired => {
            eprintln!(
                "cleanup: access denied opening the WFP engine. Re-run from an elevated \
                 (Administrator) console (the `scripts/reset-network.ps1` wrapper \
                 self-elevates via UAC)."
            );
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
            return SweepOutcome::Failed;
        }
        Err(e) => {
            eprintln!("cleanup: WFP filter sweep failed: {e:?}");
            return SweepOutcome::Failed;
        }
    };

    // Machine-wide Base Filtering Engine options. An instance that was killed
    // rather than stopped never ran its own restore and left them changed; it
    // wrote down what they held, which is what makes this possible from here.
    nrr_platform_windows::conn_observe::wfp_events::restore_engine_options();

    // ── Route sweep (best-effort) ──────────────────────────────────────
    // Signature-based, so it needs no per-SID state; the same sweep the Linux
    // daemon's `cleanup` runs. Non-fatal: our routes do not survive a reboot.
    let routes_removed: Option<usize> =
        match nrr_service_runtime::route_reconciler::sweep_owned_routes(
            Arc::clone(&api) as Arc<dyn nrr_platform_api::route_table::RouteTablePort>
        ) {
            Ok(n) => Some(n),
            Err(e) => {
                eprintln!(
                    "cleanup: route sweep failed ({e}); a reboot fully clears any remaining \
                     NetRuleRouter routes."
                );
                None
            }
        };

    // ── DNS sweep: NRPT redirect + suffix search list ─────────────────
    // A crashed Mode-B (Resolver) session leaves an NRPT catch-all pointing ALL
    // name resolution at our dead loopback :53 — no name resolves until it
    // goes or the machine reboots. A suffix list we wrote outlives even a
    // reboot. Both removals are scoped to what we wrote; the same sweep the
    // service runs at boot and the uninstall runs.
    let dns_sweep = nrr_platform_windows::dns_redirect::sweep_orphan_dns_state(
        &nrr_platform_windows::dns_redirect::TransactedNrptStore,
        &nrr_platform_windows::dns_redirect::WindowsSearchList,
    );
    if let Err(e) = &dns_sweep.nrpt_rules {
        eprintln!(
            "cleanup: NRPT/DNS-redirect sweep failed ({e}); if DNS is broken, remove the \
             rule manually (`Get-DnsClientNrptRule | Where Comment -eq \
             'NetRuleRouter-ModeB-DnsRedirect' | Remove-DnsClientNrptRule -Force`) or reboot."
        );
    }
    if let Err(e) = &dns_sweep.search_list {
        eprintln!(
            "cleanup: DNS suffix search list sweep failed ({e}); check the list with              `Get-DnsClientGlobalSetting` and remove suffixes NetRuleRouter added."
        );
    }

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
}
