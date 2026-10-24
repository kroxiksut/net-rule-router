//! Who holds a filter set is decided in one place, under one lock.
//!
//! Three writers used to decide it from their own snapshots — the pass, the
//! registry listener and the fake-IP replan — and the oldest view landed last.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Barrier;

use crate::routing_pause::PauseDispatcher;
use crate::OrchestratorPauseDispatcher;

/// A scripted decider: answers `sids`, or `fail`; `hold` makes the next
/// answer wait on a barrier AFTER it has been read, which is how a test puts a
/// writer "in the middle of a pass" with an already-taken view.
#[derive(Default)]
struct Decided {
    sids: Mutex<Vec<String>>,
    fail: Mutex<Option<String>>,
    hold: Mutex<Option<Arc<Barrier>>>,
    calls: AtomicUsize,
}

impl Decided {
    fn naming(sids: &[&str]) -> Arc<Self> {
        let decided = Arc::new(Self::default());
        decided.set(sids);
        decided
    }

    fn set(&self, sids: &[&str]) {
        *self.sids.lock().unwrap() = sids.iter().map(|s| s.to_string()).collect();
    }

    fn fail_with(&self, reason: &str) {
        *self.fail.lock().unwrap() = Some(reason.to_string());
    }

    fn hold_next_answer(&self, barrier: Arc<Barrier>) {
        *self.hold.lock().unwrap() = Some(barrier);
    }

    fn answer(&self) -> Result<Vec<String>, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(reason) = self.fail.lock().unwrap().clone() {
            return Err(reason);
        }
        let answer = self.sids.lock().unwrap().clone();
        if let Some(barrier) = self.hold.lock().unwrap().take() {
            barrier.wait();
        }
        Ok(answer)
    }
}

/// The shared fixture with the decider wired; two users have a policy.
#[allow(clippy::type_complexity)]
fn decided_fixture(
    decided: &Arc<Decided>,
) -> (
    Arc<MockWindowsApi>,
    Arc<PerSidApplyOrchestrator>,
    Arc<ScriptedRules>,
) {
    let (api, orch, src, rules, _audit) = fixture();
    src.set("A", snap_full("Wi-Fi", "TAP"));
    src.set("B", snap_full("Wi-Fi", "TAP"));
    let decided = Arc::clone(decided);
    let orch = Arc::new(
        Arc::try_unwrap(orch)
            .unwrap_or_else(|_| panic!("sole owner"))
            .with_enforced_sids(Arc::new(move || decided.answer())),
    );
    (api, orch, rules)
}

fn sids(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn settle_installs_who_the_decider_names_and_removes_everyone_else() {
    let decided = Decided::naming(&["A", "B"]);
    let (api, orch, _rules) = decided_fixture(&decided);

    assert_eq!(orch.settle().unwrap(), sids(&["A", "B"]));
    assert_eq!(orch.installed_sids(), sids(&["A", "B"]));
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 2 * (2 + EXEMPT));

    decided.set(&["B"]);
    assert_eq!(orch.settle().unwrap(), sids(&["B"]));
    assert_eq!(orch.installed_sids(), sids(&["B"]));
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 2 + EXEMPT);
}

/// The last user leaving takes their filters with them, the way their routes
/// already went: with nobody served there is no route-table owner, so a pin
/// without its route would only be a dead end for system traffic.
#[test]
fn nobody_signed_in_takes_the_filters_down_with_the_routes() {
    let decided = Decided::naming(&["A"]);
    let (api, orch, _rules) = decided_fixture(&decided);
    orch.settle().unwrap();
    assert_eq!(orch.installed_sids(), sids(&["A"]));

    decided.set(&[]);
    assert!(orch.settle().unwrap().is_empty());
    assert!(orch.installed_sids().is_empty());
    assert!(api.wfp_filters.lock().unwrap().is_empty());
}

/// An answer that is not known is neither "nobody" nor "everyone as before":
/// a pause-flag read that fails must not strip a guard, and must not put a
/// paused user's set back.
#[test]
fn a_decider_that_cannot_answer_leaves_every_set_as_it_is() {
    let decided = Decided::naming(&["A"]);
    let (api, orch, _rules) = decided_fixture(&decided);
    orch.settle().unwrap();
    let before = api.wfp_filters.lock().unwrap().len();

    decided.fail_with("database is locked");
    assert!(matches!(
        orch.settle(),
        Err(OrchestratorError::MembershipUnknown(_))
    ));
    assert_eq!(orch.installed_sids(), sids(&["A"]));
    assert_eq!(api.wfp_filters.lock().unwrap().len(), before);
    assert!(matches!(
        orch.settle_and_recompile(),
        Err(OrchestratorError::MembershipUnknown(_))
    ));
    assert_eq!(orch.installed_sids(), sids(&["A"]));
}

/// A tray exit in the middle of a pass. The pass took its view ("A is
/// enforced") before the exit; the exit's settle has to wait for the pass and
/// then act on the newer view — so the departed user's set is gone at the
/// end, instead of being put back by the pass that finished last.
#[test]
fn a_tray_exit_during_a_pass_is_not_overtaken_by_the_pass() {
    let decided = Decided::naming(&["A"]);
    let (api, orch, _rules) = decided_fixture(&decided);
    let mid_pass = Arc::new(Barrier::new(2));
    decided.hold_next_answer(Arc::clone(&mid_pass));

    let pass = {
        let orch = Arc::clone(&orch);
        std::thread::spawn(move || orch.settle())
    };
    // The pass has read "A" and is about to install it.
    mid_pass.wait();

    // The tray exits: the listener settles on the new answer.
    decided.set(&[]);
    let exit = orch.settle().unwrap();
    assert!(exit.is_empty());

    assert_eq!(pass.join().unwrap().unwrap(), sids(&["A"]));
    assert_eq!(
        decided.calls.load(Ordering::SeqCst),
        2,
        "the exit decided after the pass, not beside it"
    );
    assert!(
        orch.installed_sids().is_empty(),
        "the pass's older view did not win"
    );
    assert!(api.wfp_filters.lock().unwrap().is_empty());
}

/// A pause in the middle of a pass: the dispatcher is one more settle under
/// the same lock, so the pass cannot hand the paused user their block-all
/// back. A resume is the mirror image.
#[test]
fn a_pause_during_a_pass_wins_over_the_pass_and_a_resume_puts_the_set_back() {
    let decided = Decided::naming(&["A", "B"]);
    let (_api, orch, _rules) = decided_fixture(&decided);
    let dispatcher = OrchestratorPauseDispatcher::new(Arc::clone(&orch));
    let mid_pass = Arc::new(Barrier::new(2));
    decided.hold_next_answer(Arc::clone(&mid_pass));

    let pass = {
        let orch = Arc::clone(&orch);
        std::thread::spawn(move || orch.settle())
    };
    mid_pass.wait();

    // The pause flag is stored first (the coordinator's order); the decider
    // reads it from then on.
    decided.set(&["B"]);
    dispatcher.remove_for_sid("A").unwrap();
    pass.join().unwrap().unwrap();
    assert_eq!(orch.installed_sids(), sids(&["B"]));

    decided.set(&["A", "B"]);
    dispatcher.install_for_sid("A").unwrap();
    assert_eq!(orch.installed_sids(), sids(&["A", "B"]));
}

/// A pause whose flag the decider does not see is reported, not claimed.
#[test]
fn a_pause_the_decider_still_contradicts_is_refused() {
    let decided = Decided::naming(&["A"]);
    let (_api, orch, _rules) = decided_fixture(&decided);
    orch.settle().unwrap();
    let dispatcher = OrchestratorPauseDispatcher::new(Arc::clone(&orch));

    assert!(dispatcher.remove_for_sid("A").is_err());
    assert_eq!(orch.installed_sids(), sids(&["A"]));

    decided.fail_with("database is locked");
    assert!(dispatcher.remove_for_sid("A").is_err());
    assert!(dispatcher.install_for_sid("A").is_err());
}

/// A recompile (a fake-IP replan, a policy edit) of a user holding no set
/// installs one only if the decider names them: the install is the decider's
/// alone, so a replan can no longer put back the set of a user who just left.
#[test]
fn a_recompile_of_a_user_the_decider_does_not_name_installs_nothing() {
    let decided = Decided::naming(&[]);
    let (api, orch, _rules) = decided_fixture(&decided);

    assert_eq!(orch.recompile_for_sid("A").unwrap(), 0);
    assert!(orch.installed_sids().is_empty());
    assert!(api.wfp_filters.lock().unwrap().is_empty());

    decided.set(&["A"]);
    assert_eq!(orch.recompile_for_sid("A").unwrap(), 2 + EXEMPT);
    assert_eq!(orch.installed_sids(), sids(&["A"]));
}

/// The fake-IP replan: membership first, then every set still held is
/// recompiled — and nobody else's.
#[test]
fn settle_and_recompile_recompiles_exactly_the_sets_the_decider_keeps() {
    let decided = Decided::naming(&["A", "B"]);
    let (api, orch, rules) = decided_fixture(&decided);
    orch.settle().unwrap();
    assert_eq!(orch.filter_count_for("A"), 2 + EXEMPT);

    rules.set(rules_with_n_primary_ips(3));
    decided.set(&["A"]);
    orch.settle_and_recompile().unwrap();

    assert_eq!(orch.installed_sids(), sids(&["A"]));
    assert_eq!(orch.filter_count_for("A"), 3 + EXEMPT);
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 3 + EXEMPT);
}

/// Without a decider the explicit snapshot stays the only writer, and the
/// recompile of a never-installed user still installs — the shape every
/// other test in this module's siblings was written against.
#[test]
fn without_a_decider_the_snapshot_and_the_recompile_behave_as_before() {
    let (_api, orch, src, _rules, _audit) = fixture();
    src.set("A", snap_full("Wi-Fi", "TAP"));
    assert_eq!(orch.settle().unwrap(), Vec::<String>::new());
    assert_eq!(orch.recompile_for_sid("A").unwrap(), 2 + EXEMPT);
    assert_eq!(orch.settle().unwrap(), sids(&["A"]));
    orch.settle_and_recompile().unwrap();
    assert_eq!(orch.installed_sids(), sids(&["A"]));
}

/// One user's unreadable policy is that user's failure alone: the pass still
/// installs the user after them, takes down the one who left, reports the
/// failure after the full pass, and names the failed user to health.
#[test]
fn one_unreadable_user_does_not_stall_the_rest_of_the_pass() {
    let (api, orch, src, _rules, audit) = fixture();
    src.set("B", snap_primary_only("Wi-Fi"));
    src.set("C", snap_primary_only("Wi-Fi"));
    orch.reconcile(&sids(&["C"])).unwrap();
    assert_eq!(orch.installed_sids(), sids(&["C"]));

    // "A" sorts first, so the old pass stopped on it before reaching anyone.
    src.fail_reads_of("A");
    assert!(matches!(
        orch.reconcile(&sids(&["A", "B"])),
        Err(OrchestratorError::PolicyUnreadable(_))
    ));
    assert_eq!(
        orch.installed_sids(),
        sids(&["B"]),
        "B installed, C removed"
    );
    let filters = api.wfp_filters.lock().unwrap();
    assert_eq!(filters.len(), 2);
    assert!(filters.iter().all(|f| f.user_sid.as_deref() == Some("B")));
    drop(filters);
    assert!(
        audit
            .snapshot()
            .iter()
            .any(|r| r.sid == "A" && r.kind == PerSidApplyAuditKind::Failed),
        "the failed user is reported to health"
    );
}
