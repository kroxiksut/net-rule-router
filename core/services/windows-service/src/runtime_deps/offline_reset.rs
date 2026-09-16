//! What `cleanup` does on a machine whose service is not running.
//!
//! The boot wiring next door builds a service; this builds nothing and only
//! takes away — filters, routes, the NRPT redirect, the machine-wide engine
//! options. It is the path a user reaches after a hard kill or a crash, so
//! every step is best-effort and says what it could not do rather than
//! stopping at the first refusal.

use super::*;

pub(crate) fn strip_orphaned_block_filters_standalone() {
    let (tx, rx) = std::sync::mpsc::channel();
    // Detached on purpose: if it is stuck in the engine it will not answer a
    // cancel either, and the cleanup it performs is idempotent whenever it lands.
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
        Ok(session) => match session.cleanup_blocks_only() {
            Ok(0) => {}
            Ok(n) => tracing::warn!(
                target: "nrr::runtime",
                stripped_blocks = n as u64,
                "startup: stripped orphaned block/kill-switch WFP filter(s) \
                 (standalone recovery path)",
            ),
            Err(e) => tracing::warn!(
                target: "nrr::runtime",
                "standalone block-filter strip failed: {e:?}",
            ),
        },
        Err(e) => tracing::warn!(
            target: "nrr::runtime",
            "standalone block-filter strip: WFP engine open failed: {e:?}",
        ),
    }
    tracing::debug!(target: "nrr::runtime", "startup: orphaned-filter strip finished");
}

/// Disaster-recovery offline reset — strip **every** NetRuleRouter WFP filter
/// (block AND permit) and any leftover NRR-owned route WITHOUT the service
/// running. Backs the `cleanup` console subcommand.
///
/// A crashed / hard-killed service leaves its non-dynamic WFP session's filters
/// behind: they survive `taskkill /F` until an explicit delete or a reboot, and
/// an orphaned kill-switch / fail-closed block can lock the machine off the
/// network with no service left to lift it. This opens its OWN short-lived WFP
/// engine session — the same enumerate-by-provider-GUID sweep
/// [`nrr_service_runtime::per_sid_orchestrator::PerSidApplyOrchestrator::cleanup_wfp`]
/// runs via [`WfpSession::cleanup_all`] — deletes all our filters, then sweeps
/// the OS route table for routes carrying our signature and removes them. Safe
/// to run when the service is installed but stopped (nothing else holds the
/// engine).
///
/// Requires elevation: `FwpmEngineOpen0` returns access-denied for a
/// non-elevated caller, which we detect via [`ErrorClass::PrivilegeRequired`]
/// and turn into a "re-run elevated" message (no new `unsafe` token probe).
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
    use nrr_platform_windows::ErrorClass;

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
    // Enumerate the live OS route table and adopt every route carrying our
    // signature (`SECONDARY_ROUTE_METRIC` at prefix /32 or /2 — the secondary
    // host routes and the mode-A counter-overlay halves), then `clear()`
    // deletes them. Purely signature-based, so it needs no per-SID binding
    // state and works fully offline — the same shapes
    // `SecondaryRouteCoordinator::adopt_orphans_from_table` adopts on startup.
    // Any failure is non-fatal: our routes are non-persistent and clear on the
    // next reboot regardless.
    let routes_removed: Option<usize> = match api.get_ip_forward_table() {
        Ok(table) => {
            let orphans: Vec<_> = table
                .into_iter()
                .filter(|r| {
                    // Shape asked of the codegen, family included: `/32` on an
                    // IPv6 row is a PREFIX, not a host route, and adopting one
                    // would hand the reconciler a stranger to delete.
                    r.metric == nrr_service_runtime::route_codegen::SECONDARY_ROUTE_METRIC
                        && nrr_service_runtime::route_codegen::is_owned_shape(
                            r.destination,
                            r.prefix_length,
                        )
                })
                .map(|mut r| {
                    r.is_ours = true;
                    r
                })
                .collect();
            if orphans.is_empty() {
                Some(0)
            } else {
                let reconciler =
                    nrr_service_runtime::route_reconciler::SecondaryRouteReconciler::new(
                        Arc::clone(&api) as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
                    );
                reconciler.adopt_owned(orphans);
                match reconciler.clear() {
                    Ok(delta) => Some(delta.removed),
                    Err(e) => {
                        eprintln!(
                            "cleanup: route sweep failed ({e:?}); a reboot fully clears any \
                             remaining NetRuleRouter routes."
                        );
                        None
                    }
                }
            }
        }
        Err(e) => {
            eprintln!(
                "cleanup: could not enumerate the route table ({e:?}); a reboot fully clears \
                 any remaining NetRuleRouter routes."
            );
            None
        }
    };

    // ── NRPT / DNS-redirect sweep (the DNS-lockout risk) ───────────────
    // A crashed Mode-B (Resolver) session leaves an NRPT catch-all rule
    // pointing ALL name resolution at our loopback :53 listener. With the
    // service dead that listener is gone, so EVERY DNS query fails until the
    // rule is removed or the machine reboots — a worse lockout than the WFP
    // filters (no name resolves at all). `clear_orphan_redirect` removes only
    // rules carrying our marker, so an admin's or a VPN's own NRPT rule is
    // untouched. Same sweep the service runs at boot; here it runs offline.
    // Best-effort — the marker-scoped removal is safe to attempt regardless of
    // whether a rule exists.
    let nrpt_cleared = match nrr_platform_windows::dns_redirect::clear_orphan_redirect(
        &nrr_platform_windows::dns_redirect::TransactedNrptStore,
    ) {
        Ok(removed) => Some(removed),
        Err(e) => {
            eprintln!(
                "cleanup: NRPT/DNS-redirect sweep failed ({e:?}); if DNS is broken, remove the \
                 rule manually (`Get-DnsClientNrptRule | Where Comment -eq \
                 'NetRuleRouter-ModeB-DnsRedirect' | Remove-DnsClientNrptRule -Force`) or reboot."
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
    match nrpt_cleared {
        Some(n) => println!("  DNS redirect (NRPT) rules removed: {n}"),
        None => println!("  DNS redirect (NRPT) rules: <sweep failed — see above>"),
    }
    println!("Reboot to fully clear any remainder.");
    if nrpt_cleared.is_some() {
        SweepOutcome::Done
    } else {
        SweepOutcome::Failed
    }
}
