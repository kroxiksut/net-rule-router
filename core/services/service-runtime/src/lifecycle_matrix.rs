//! The lifecycle table: for every edge the service lives through, what must be
//! on the machine afterwards, and the plan each OS wiring runs to get there.
//!
//! One answer for both OSes. The decisions are here and tested once; the
//! platform layers only carry them out (strip or keep filters, remove routes,
//! hand DNS back). A cell no test can reach without hardware is listed in
//! [`LIVE_CHECKS`] rather than left implicit. `tests/lifecycle_matrix_rows.rs`
//! and `tests/lifecycle_matrix_runtime.rs` drive each row through the code
//! that carries it out and hold the result to [`expected_after`].
//!
//! The one rule behind every cell: a failure, a crash or a power-off never
//! lifts protection someone asked for. Blocks come off only when the service
//! is stopped on purpose on a machine that keeps running, or when nobody has
//! leak protection on.

use std::time::Duration;

/// Why the runtime is stopping. Carried by the stop token so the teardown can
/// tell a service stop from a machine going down.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StopReason {
    /// Someone stopped the service; the machine keeps running.
    ServiceStop,
    /// The machine is going down while system services still run. Filters do
    /// not survive it anyway, so removing them only opens a window.
    MachineShutdown,
}

/// An edge of the service lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LifecycleEdge {
    /// A start after a clean exit: nothing of ours is on the machine.
    Start,
    /// A start with a dead instance's filters still installed.
    StartAfterCrash,
    /// A start that cannot reach `Running` (recovery required).
    BlockedStart,
    /// An orderly stop.
    Stop(StopReason),
    /// The supervisor gave up restarting a crashing service.
    RestartsExhausted,
    /// The last signed-in user left.
    LastUserSignedOut,
    /// A user signed in (console, remote desktop, SSH).
    UserSignedIn,
    /// A user paused routing or ran safe-disable.
    UserPaused,
    /// The machine woke from sleep.
    ResumeFromSleep,
    /// The additional link went down.
    SecondaryDown,
    /// Something outside the service flushed our filters or routes.
    ExternalReset,
    /// The service is being removed.
    Uninstall,
    /// "Restore network": the service is stopped and whatever it left is swept.
    NetworkReset,
    /// A task or thread of the service panicked.
    TaskPanic,
}

/// What happens to one kind of state on an edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// Left exactly as it is.
    Keep,
    /// Taken off the machine.
    Remove,
    /// Brought back in line with the rule book by the next pass.
    Reconcile,
}

/// What routes the stop leaves behind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteTeardown {
    /// Nothing is touched.
    Keep,
    /// The rule routes stay on the additional link; only our overlays go.
    KeepRuleRoutes,
    /// Every route of ours goes.
    RemoveAll,
}

/// What filters the stop leaves behind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterTeardown {
    /// Nothing is touched.
    Keep,
    /// Every filter of ours goes, blocks included.
    RemoveAll,
}

/// What a start does with the blocks a dead instance left.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrphanedBlocks {
    /// Delete them before anything else runs.
    StripNow,
    /// Leave them in force; the first pass re-adds what the rule book wants
    /// and deletes what it does not.
    AdoptOnFirstPass,
}

/// The settings the table reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct LifecycleInputs {
    /// Someone on the machine has leak protection on (`sites` or `everything`).
    pub leak_guard_armed: bool,
    /// The stop setting asks to keep rule routes on the additional link.
    pub keep_rule_routes_on_stop: bool,
}

/// What stands on the machine after an edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpectedState {
    /// Per-user permit and block filters.
    pub user_filters: Disposition,
    /// The leak-protection blocks.
    pub fail_closed_blocks: Disposition,
    /// Our routes (and the `ip rule` entries on Linux).
    pub routes: Disposition,
    /// The system DNS redirect to our resolver.
    pub dns_redirect: Disposition,
}

impl ExpectedState {
    const fn all(d: Disposition) -> Self {
        Self {
            user_filters: d,
            fail_closed_blocks: d,
            routes: d,
            dns_redirect: d,
        }
    }
}

/// The plan an orderly stop runs. Built once from the reason and the
/// settings, then carried out in [`TEARDOWN_ORDER`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StopPlan {
    pub routes: RouteTeardown,
    pub filters: FilterTeardown,
}

/// One step of the stop. The order is the same on every OS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TeardownStep {
    /// The resolver hands system DNS back and stops answering.
    RestoreDns,
    /// Our routes go while the filters still hold.
    RemoveRoutes,
    /// Last: the filters, under a deadline.
    RemoveFilters,
}

/// Routes go first, filters last: between the two a rule host is blocked, not
/// leaked. The reverse order opens a window in which traffic to protected
/// hosts takes whatever path the OS has.
pub const TEARDOWN_ORDER: [TeardownStep; 3] = [
    TeardownStep::RestoreDns,
    TeardownStep::RemoveRoutes,
    TeardownStep::RemoveFilters,
];

/// How long the filter removal may take before the stop goes on without it.
/// A filtering engine that has wedged answers nothing; a stop that waits on it
/// forever is killed, and a killed service leaves the filters anyway.
pub const FILTER_TEARDOWN_DEADLINE: Duration = Duration::from_secs(60);

/// What the machine must look like after `edge`.
pub fn expected_after(edge: LifecycleEdge, inputs: LifecycleInputs) -> ExpectedState {
    use Disposition::{Keep, Reconcile, Remove};
    match edge {
        LifecycleEdge::Start => ExpectedState::all(Reconcile),
        LifecycleEdge::StartAfterCrash => ExpectedState {
            user_filters: Reconcile,
            fail_closed_blocks: match orphaned_blocks_at_start(inputs.leak_guard_armed) {
                OrphanedBlocks::AdoptOnFirstPass => Reconcile,
                OrphanedBlocks::StripNow => Remove,
            },
            routes: Reconcile,
            dns_redirect: Reconcile,
        },
        // Nothing runs, so nothing of the previous instance may be taken off
        // unless nobody asked for blocking over leaking.
        LifecycleEdge::BlockedStart => ExpectedState {
            user_filters: Keep,
            fail_closed_blocks: if inputs.leak_guard_armed {
                Keep
            } else {
                Remove
            },
            routes: Keep,
            dns_redirect: Remove,
        },
        LifecycleEdge::Stop(reason) => {
            let plan = stop_plan(reason, inputs);
            ExpectedState {
                user_filters: match plan.filters {
                    FilterTeardown::Keep => Keep,
                    FilterTeardown::RemoveAll => Remove,
                },
                fail_closed_blocks: match plan.filters {
                    FilterTeardown::Keep => Keep,
                    FilterTeardown::RemoveAll => Remove,
                },
                routes: match plan.routes {
                    RouteTeardown::Keep | RouteTeardown::KeepRuleRoutes => Keep,
                    RouteTeardown::RemoveAll => Remove,
                },
                dns_redirect: Remove,
            }
        }
        LifecycleEdge::RestartsExhausted => {
            let plan = after_crash_plan(inputs);
            ExpectedState {
                user_filters: match plan.filters {
                    FilterTeardown::Keep => Keep,
                    FilterTeardown::RemoveAll => Remove,
                },
                fail_closed_blocks: match plan.filters {
                    FilterTeardown::Keep => Keep,
                    FilterTeardown::RemoveAll => Remove,
                },
                routes: match plan.routes {
                    RouteTeardown::Keep | RouteTeardown::KeepRuleRoutes => Keep,
                    RouteTeardown::RemoveAll => Remove,
                },
                dns_redirect: Remove,
            }
        }
        // Both halves go together: routes without filters or filters without
        // routes each send system traffic somewhere nobody chose.
        LifecycleEdge::LastUserSignedOut => ExpectedState {
            user_filters: Remove,
            fail_closed_blocks: Remove,
            routes: Remove,
            dns_redirect: Keep,
        },
        // Theirs at once, nobody else's touched; DNS is already the machine's.
        LifecycleEdge::UserSignedIn => ExpectedState {
            user_filters: Reconcile,
            fail_closed_blocks: Reconcile,
            routes: Reconcile,
            dns_redirect: Keep,
        },
        LifecycleEdge::UserPaused => ExpectedState {
            user_filters: Remove,
            fail_closed_blocks: Remove,
            routes: if inputs.keep_rule_routes_on_stop {
                Keep
            } else {
                Remove
            },
            dns_redirect: Keep,
        },
        LifecycleEdge::ResumeFromSleep | LifecycleEdge::ExternalReset => {
            ExpectedState::all(Reconcile)
        }
        // The next pass re-plans against the dead link: under leak protection
        // that pass is what blocks the rule hosts (`protection_posture`).
        LifecycleEdge::SecondaryDown => ExpectedState {
            user_filters: Reconcile,
            fail_closed_blocks: Reconcile,
            routes: Reconcile,
            dns_redirect: Keep,
        },
        LifecycleEdge::Uninstall | LifecycleEdge::NetworkReset => ExpectedState::all(Remove),
        LifecycleEdge::TaskPanic => ExpectedState::all(Keep),
    }
}

/// Whether a start deletes the blocks a dead instance left or lets the first
/// pass take them over. With leak protection on for anyone, a strip before
/// the first pass is a leak for the whole boot, and endless under a crash
/// loop.
pub fn orphaned_blocks_at_start(leak_guard_armed: bool) -> OrphanedBlocks {
    if leak_guard_armed {
        OrphanedBlocks::AdoptOnFirstPass
    } else {
        OrphanedBlocks::StripNow
    }
}

/// The plan for an orderly stop.
pub fn stop_plan(reason: StopReason, inputs: LifecycleInputs) -> StopPlan {
    match reason {
        // Filters are not persistent and the routes go with the network; the
        // only thing a teardown could add here is a window.
        StopReason::MachineShutdown => StopPlan {
            routes: RouteTeardown::Keep,
            filters: FilterTeardown::Keep,
        },
        StopReason::ServiceStop => StopPlan {
            routes: if inputs.keep_rule_routes_on_stop {
                RouteTeardown::KeepRuleRoutes
            } else {
                RouteTeardown::RemoveAll
            },
            // A block with no service to lift it is a lockout; the user
            // stopped the service, so it comes off with everything else.
            filters: FilterTeardown::RemoveAll,
        },
    }
}

/// The plan once the restarts are spent. The service will not come back on
/// its own, so DNS is handed back whatever the settings; blocks stay only
/// when someone asked for blocking over leaking.
pub fn after_crash_plan(inputs: LifecycleInputs) -> StopPlan {
    if inputs.leak_guard_armed {
        StopPlan {
            routes: RouteTeardown::Keep,
            filters: FilterTeardown::Keep,
        }
    } else {
        StopPlan {
            routes: RouteTeardown::RemoveAll,
            filters: FilterTeardown::RemoveAll,
        }
    }
}

/// Whether anyone on this machine has leak protection on, read straight from
/// the state database so a process with no runtime (the start before deps,
/// the after-crash verb) can ask. Unknown counts as armed: lifting a block
/// the user asked for is the one mistake this question exists to avoid; a
/// database that does not exist yet has nobody in it.
pub fn leak_guard_armed_at(state_db_path: &std::path::Path) -> bool {
    if !state_db_path.exists() {
        return false;
    }
    let Ok(conn) = nrr_storage::migration::open_connection(state_db_path) else {
        return true;
    };
    nrr_storage::route_bindings::RouteBindingsRepository::new(&conn)
        .any_leak_guard_armed()
        .unwrap_or(true)
}

/// Run `work` on its own thread and wait at most `deadline` for it. A step
/// that overruns is left to finish on its own; `None` says so. Used for the
/// filter removal at stop: a wedged engine answers nothing, and a stop that
/// waits on it forever gets killed with the filters still in place.
pub fn within_deadline<T, F>(what: &'static str, deadline: Duration, work: F) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name(format!("nrr-{what}"))
        .spawn(move || {
            let _ = tx.send(work());
        });
    if spawned.is_err() {
        tracing::warn!(
            target: "nrr::lifecycle",
            msg_key = "lifecycle-step-spawn-failed",
            step = what,
            "lifecycle step could not be spawned — skipped",
        );
        return None;
    }
    match rx.recv_timeout(deadline) {
        Ok(value) => Some(value),
        Err(_) => {
            tracing::warn!(
                target: "nrr::lifecycle",
                msg_key = "lifecycle-step-overran-deadline",
                step = what,
                deadline_secs = deadline.as_secs(),
                "lifecycle step outran its deadline — detached, continuing",
            );
            None
        }
    }
}

/// Cells that only a machine can show. Each names what to do and what to
/// look at; the tests below hold the rest of the table.
pub const LIVE_CHECKS: &[(LifecycleEdge, &str)] = &[
    (
        LifecycleEdge::Stop(StopReason::MachineShutdown),
        "reboot a VM with leak protection on and a rule host held; during the shutdown the host \
         stays blocked (Windows: no `svc-boot-wfp-filters-stripped` line; Linux: nft table \
         present until the unit is gone)",
    ),
    (
        LifecycleEdge::StartAfterCrash,
        "kill the service hard with leak protection on and the additional link down; the rule \
         host stays blocked through the restart and after its first pass",
    ),
    (
        LifecycleEdge::BlockedStart,
        "with a DNS redirect left by a killed instance, start a service whose start is blocked \
         (damaged state database): names resolve, health says recovery required, the dead \
         instance's leak-protection blocks stay",
    ),
    (
        LifecycleEdge::ResumeFromSleep,
        "sleep and wake a laptop whose additional link changed its address; one pass after the \
         wake re-pins the rule hosts to the new address",
    ),
    (
        LifecycleEdge::LastUserSignedOut,
        "sign the last user out on Windows; routes and filters go together",
    ),
    (
        LifecycleEdge::UserSignedIn,
        "sign a second user in over remote desktop (Windows) or SSH (Linux); within one pass \
         their rule host leaves through the additional link, the first user's routing unchanged",
    ),
    (
        LifecycleEdge::ExternalReset,
        "Linux: `nft flush ruleset` under a live service; the next tick restores the table",
    ),
    (
        LifecycleEdge::RestartsExhausted,
        "kill the service past its restart budget; with leak protection on the blocks stay and \
         DNS is handed back, without it the machine is clean",
    ),
    (
        LifecycleEdge::Uninstall,
        "uninstall with leak protection on, a rule host routed and the rule routes kept on stop; \
         afterwards no filter, route, DNS redirect or (Linux) `ip rule` of ours is left",
    ),
    (
        LifecycleEdge::NetworkReset,
        "run Restore network from the window, the terminal UI and `nrr-cli reset-network` with \
         the service running; it is stopped first, then nothing of ours is left",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use Disposition::{Keep, Reconcile, Remove};

    const ARMED: LifecycleInputs = LifecycleInputs {
        leak_guard_armed: true,
        keep_rule_routes_on_stop: false,
    };
    const UNARMED: LifecycleInputs = LifecycleInputs {
        leak_guard_armed: false,
        keep_rule_routes_on_stop: false,
    };

    #[test]
    fn a_crashed_instances_blocks_stay_while_someone_has_leak_protection() {
        assert_eq!(
            orphaned_blocks_at_start(true),
            OrphanedBlocks::AdoptOnFirstPass
        );
        assert_eq!(orphaned_blocks_at_start(false), OrphanedBlocks::StripNow);
        assert_eq!(
            expected_after(LifecycleEdge::StartAfterCrash, ARMED).fail_closed_blocks,
            Reconcile
        );
        assert_eq!(
            expected_after(LifecycleEdge::StartAfterCrash, UNARMED).fail_closed_blocks,
            Remove
        );
    }

    #[test]
    fn a_blocked_start_takes_nothing_off_a_protected_machine() {
        let blocked = expected_after(LifecycleEdge::BlockedStart, ARMED);
        assert_eq!(blocked.fail_closed_blocks, Keep);
        assert_eq!(blocked.user_filters, Keep);
        assert_eq!(blocked.dns_redirect, Remove);
        assert_eq!(
            expected_after(LifecycleEdge::BlockedStart, UNARMED).fail_closed_blocks,
            Remove
        );
    }

    #[test]
    fn a_machine_shutdown_keeps_every_block_and_route() {
        for inputs in [ARMED, UNARMED] {
            let plan = stop_plan(StopReason::MachineShutdown, inputs);
            assert_eq!(plan.filters, FilterTeardown::Keep);
            assert_eq!(plan.routes, RouteTeardown::Keep);
            let state = expected_after(LifecycleEdge::Stop(StopReason::MachineShutdown), inputs);
            assert_eq!(state.fail_closed_blocks, Keep);
            assert_eq!(state.routes, Keep);
            assert_eq!(
                state.dns_redirect, Remove,
                "DNS is persistent and always comes back"
            );
        }
    }

    #[test]
    fn a_service_stop_removes_filters_and_follows_the_route_setting() {
        let plan = stop_plan(StopReason::ServiceStop, UNARMED);
        assert_eq!(plan.filters, FilterTeardown::RemoveAll);
        assert_eq!(plan.routes, RouteTeardown::RemoveAll);
        let keeping = LifecycleInputs {
            keep_rule_routes_on_stop: true,
            ..UNARMED
        };
        assert_eq!(
            stop_plan(StopReason::ServiceStop, keeping).routes,
            RouteTeardown::KeepRuleRoutes
        );
        // Leak protection does not keep a block the user stopped on purpose.
        assert_eq!(
            stop_plan(StopReason::ServiceStop, ARMED).filters,
            FilterTeardown::RemoveAll
        );
    }

    /// Bytes from the network can at worst crash a unit of work, and through
    /// it the process: every step of that chain keeps a protected user's
    /// blocks — the panic, the restart, and the restarts running out.
    #[test]
    fn a_crash_from_hostile_bytes_never_lifts_leak_protection() {
        let chain = [
            LifecycleEdge::TaskPanic,
            LifecycleEdge::StartAfterCrash,
            LifecycleEdge::RestartsExhausted,
        ];
        for edge in chain {
            assert_ne!(
                expected_after(edge, ARMED).fail_closed_blocks,
                Remove,
                "{edge:?} lifted a protected user's blocks"
            );
        }
        assert_eq!(
            orphaned_blocks_at_start(true),
            OrphanedBlocks::AdoptOnFirstPass
        );
    }

    #[test]
    fn spent_restarts_keep_blocks_only_under_leak_protection() {
        assert_eq!(
            after_crash_plan(ARMED),
            StopPlan {
                routes: RouteTeardown::Keep,
                filters: FilterTeardown::Keep,
            }
        );
        assert_eq!(
            after_crash_plan(UNARMED),
            StopPlan {
                routes: RouteTeardown::RemoveAll,
                filters: FilterTeardown::RemoveAll,
            }
        );
        assert_eq!(
            expected_after(LifecycleEdge::RestartsExhausted, ARMED).dns_redirect,
            Remove
        );
    }

    #[test]
    fn routes_go_before_filters_on_every_os() {
        let routes = TEARDOWN_ORDER
            .iter()
            .position(|s| *s == TeardownStep::RemoveRoutes)
            .expect("routes step");
        let filters = TEARDOWN_ORDER
            .iter()
            .position(|s| *s == TeardownStep::RemoveFilters)
            .expect("filters step");
        assert!(routes < filters);
        assert_eq!(TEARDOWN_ORDER[0], TeardownStep::RestoreDns);
        assert!(FILTER_TEARDOWN_DEADLINE >= Duration::from_secs(30));
    }

    #[test]
    fn a_step_that_overruns_its_deadline_is_left_behind() {
        let (block_tx, block_rx) = std::sync::mpsc::channel::<()>();
        let late = within_deadline("test-late", Duration::from_millis(50), move || {
            let _ = block_rx.recv();
            7
        });
        assert_eq!(late, None);
        let _ = block_tx.send(());
        assert_eq!(
            within_deadline("test-prompt", Duration::from_secs(5), || 7),
            Some(7)
        );
    }

    #[test]
    fn a_missing_state_db_means_nobody_is_protected() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(!leak_guard_armed_at(&dir.path().join("absent.db")));
        // A file that is not a database is an unknown, and unknown is armed.
        let broken = dir.path().join("broken.db");
        std::fs::write(&broken, b"not sqlite").expect("write");
        assert!(leak_guard_armed_at(&broken));
    }

    #[test]
    fn a_panic_a_link_outage_and_a_pause_touch_only_their_own_unit() {
        assert_eq!(
            expected_after(LifecycleEdge::TaskPanic, ARMED),
            ExpectedState::all(Keep)
        );
        let outage = expected_after(LifecycleEdge::SecondaryDown, ARMED);
        assert_eq!(outage.fail_closed_blocks, Reconcile);
        assert_eq!(outage.dns_redirect, Keep);
        let paused = expected_after(LifecycleEdge::UserPaused, ARMED);
        assert_eq!(paused.fail_closed_blocks, Remove);
        assert_eq!(paused.dns_redirect, Keep);
        assert_eq!(
            expected_after(LifecycleEdge::Uninstall, ARMED),
            ExpectedState::all(Remove)
        );
        assert_eq!(
            expected_after(LifecycleEdge::Start, UNARMED),
            ExpectedState::all(Reconcile)
        );
    }

    /// Every edge of the table is either held by a test (here or in the
    /// crate's `lifecycle_matrix_*` tests) or named as a live check; an edge
    /// that is neither is a row nobody owns.
    #[test]
    fn every_edge_is_tested_or_a_live_check() {
        const TESTED: &[LifecycleEdge] = &[
            LifecycleEdge::Start,
            LifecycleEdge::StartAfterCrash,
            LifecycleEdge::BlockedStart,
            LifecycleEdge::Stop(StopReason::ServiceStop),
            LifecycleEdge::Stop(StopReason::MachineShutdown),
            LifecycleEdge::RestartsExhausted,
            LifecycleEdge::LastUserSignedOut,
            LifecycleEdge::UserSignedIn,
            LifecycleEdge::UserPaused,
            LifecycleEdge::ResumeFromSleep,
            LifecycleEdge::SecondaryDown,
            LifecycleEdge::ExternalReset,
            LifecycleEdge::TaskPanic,
        ];
        let all = [
            LifecycleEdge::Start,
            LifecycleEdge::StartAfterCrash,
            LifecycleEdge::BlockedStart,
            LifecycleEdge::Stop(StopReason::ServiceStop),
            LifecycleEdge::Stop(StopReason::MachineShutdown),
            LifecycleEdge::RestartsExhausted,
            LifecycleEdge::LastUserSignedOut,
            LifecycleEdge::UserSignedIn,
            LifecycleEdge::UserPaused,
            LifecycleEdge::ResumeFromSleep,
            LifecycleEdge::SecondaryDown,
            LifecycleEdge::ExternalReset,
            LifecycleEdge::Uninstall,
            LifecycleEdge::NetworkReset,
            LifecycleEdge::TaskPanic,
        ];
        for edge in all {
            let tested = TESTED.contains(&edge);
            let live = LIVE_CHECKS.iter().any(|(e, _)| *e == edge);
            assert!(
                tested || live,
                "{edge:?} has neither a test nor a live check"
            );
        }
        for (edge, what) in LIVE_CHECKS {
            assert!(!what.is_empty(), "{edge:?} live check says nothing");
        }
    }
}
