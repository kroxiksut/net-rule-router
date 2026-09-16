use super::*;
use nrr_storage::{open_connection, repository::MigrationRunner, SqliteMigrationRunner};
use tempfile::TempDir;

/// Opens + migrates a fresh state DB and wraps it the same way
/// `runtime_deps.rs` wires `ProductionServiceStability` in production.
fn fresh_conn() -> (TempDir, Arc<Mutex<Connection>>) {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("nrr_service_state.db");
    let conn = open_connection(&path).expect("open");
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().expect("migrate");
    (dir, Arc::new(Mutex::new(runner.into_connection())))
}

#[test]
fn verbose_logging_persists_through_production_writer() {
    let (_dir, conn) = fresh_conn();
    let stab = ProductionServiceStability::new(Arc::clone(&conn));

    let base = ServiceStabilityConfigProvider::get(&stab);
    assert!(!base.verbose_logging, "default must be off");

    let mut dto = base;
    dto.verbose_logging = true;
    let written =
        ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST")).expect("set must succeed");
    assert!(written.verbose_logging, "Set must echo verbose=true");

    let readback = ServiceStabilityConfigProvider::get(&stab);
    assert!(
        readback.verbose_logging,
        "verbose_logging must be durably persisted to service_stability_config"
    );
}

/// Proves the get-merge-set contract the QML patch queue relies on: as
/// long as each Set is preceded by a fresh Get of the PREVIOUS writer's
/// result (never a stale/concurrent base), two different "panels" writing
/// disjoint fields in sequence never clobber each other.
#[test]
fn sequential_get_merge_set_round_trips_do_not_clobber_each_other() {
    let (_dir, conn) = fresh_conn();
    let stab = ProductionServiceStability::new(Arc::clone(&conn));

    // "Diagnostics" panel: Get → flip verbose_logging only → Set.
    let mut after_diag = ServiceStabilityConfigProvider::get(&stab);
    after_diag.verbose_logging = true;
    let written_diag = ServiceStabilityConfigWriter::set(&stab, &after_diag, Some("S-DIAG"))
        .expect("diagnostics set");
    assert!(written_diag.verbose_logging);
    assert_eq!(written_diag.enforcement_mode, "resolver");

    // "Routing" panel: Get (must observe the diagnostics write) → flip
    // enforcement_mode only → Set.
    let mut after_routing = ServiceStabilityConfigProvider::get(&stab);
    assert!(
        after_routing.verbose_logging,
        "routing panel's Get must see the diagnostics panel's prior Set"
    );
    // Flip AWAY from the default: writing the value the row already holds
    // would pass even if the write were dropped entirely.
    after_routing.enforcement_mode = "reactive".to_string();
    let written_routing = ServiceStabilityConfigWriter::set(&stab, &after_routing, Some("S-ROUTE"))
        .expect("routing set");
    assert!(
        written_routing.verbose_logging,
        "routing panel's Set must not clobber the diagnostics panel's verbose flag"
    );
    assert_eq!(written_routing.enforcement_mode, "reactive");

    let final_state = ServiceStabilityConfigProvider::get(&stab);
    assert!(final_state.verbose_logging);
    assert_eq!(final_state.enforcement_mode, "reactive");
}

/// P3 — proves `set()` drives the live tracing-reload
/// seam through `VerbosityControl::set_verbose`, using a fake recorder
/// instead of a real `tracing_subscriber` reload handle (that path is
/// covered separately in `nrr_diagnostics::logs::tracing_layer`'s own
/// tests). Records every call so both the "turn on" and "turn off"
/// directions — and the exact value forwarded — are asserted, not just
/// "was called at least once".
#[test]
fn verbose_logging_set_drives_live_reload() {
    use crate::verbosity_control::VerbosityControl;
    use std::sync::Mutex as StdMutex;

    #[derive(Default)]
    struct FakeVerbosityControl {
        calls: StdMutex<Vec<bool>>,
    }

    impl VerbosityControl for FakeVerbosityControl {
        fn set_verbose(&self, verbose: bool) {
            self.calls
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(verbose);
        }
    }

    let (_dir, conn) = fresh_conn();
    let fake = Arc::new(FakeVerbosityControl::default());
    let stab = ProductionServiceStability::new(Arc::clone(&conn))
        .with_verbosity_control(Arc::clone(&fake) as Arc<dyn VerbosityControl>);

    let mut dto = ServiceStabilityConfigProvider::get(&stab);
    assert!(!dto.verbose_logging, "default must be off");

    // Flip on.
    dto.verbose_logging = true;
    ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST")).expect("set on must succeed");
    assert_eq!(
        *fake.calls.lock().unwrap(),
        vec![true],
        "set(verbose=true) must drive VerbosityControl::set_verbose(true)"
    );

    // A redundant Save with the SAME value still drives the (idempotent)
    // live-apply call — mirrors the unconditional resolver-controller
    // pattern this seam was modelled on.
    ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST"))
        .expect("redundant set must succeed");
    assert_eq!(*fake.calls.lock().unwrap(), vec![true, true]);

    // Flip off.
    dto.verbose_logging = false;
    ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST")).expect("set off must succeed");
    assert_eq!(
        *fake.calls.lock().unwrap(),
        vec![true, true, false],
        "set(verbose=false) must drive VerbosityControl::set_verbose(false)"
    );
}

/// Without a wired `VerbosityControl` (tests / degraded boot), `set()`
/// must still succeed and persist — the live-apply seam is additive,
/// never a precondition for the settings write itself.
#[test]
fn verbose_logging_set_succeeds_without_verbosity_control_wired() {
    let (_dir, conn) = fresh_conn();
    let stab = ProductionServiceStability::new(Arc::clone(&conn));

    let mut dto = ServiceStabilityConfigProvider::get(&stab);
    dto.verbose_logging = true;
    let written = ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST"))
        .expect("set must succeed with no VerbosityControl wired");
    assert!(written.verbose_logging);
}

/// Fake-IP UDP relay — proves `set()` drives the live-apply
/// hook with the persisted value, same contract proof as the verbose-
/// logging test above but for `with_udp_relay_apply`.
#[test]
fn udp_relay_set_drives_live_apply_with_persisted_value() {
    use std::sync::Mutex as StdMutex;

    let (_dir, conn) = fresh_conn();
    let calls: Arc<StdMutex<Vec<bool>>> = Arc::new(StdMutex::new(Vec::new()));
    let stab = ProductionServiceStability::new(Arc::clone(&conn)).with_udp_relay_apply({
        let calls = Arc::clone(&calls);
        Arc::new(move |desired: bool| {
            calls
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(desired);
        })
    });

    let base = ServiceStabilityConfigProvider::get(&stab);
    assert!(!base.fake_ip_udp_relay, "default must be off");

    let mut dto = base;
    dto.fake_ip_udp_relay = true;
    let written = ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST"))
        .expect("set on must succeed");
    assert!(written.fake_ip_udp_relay);
    assert_eq!(*calls.lock().unwrap(), vec![true]);

    dto.fake_ip_udp_relay = false;
    ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST")).expect("set off must succeed");
    assert_eq!(*calls.lock().unwrap(), vec![true, false]);

    let readback = ServiceStabilityConfigProvider::get(&stab);
    assert!(!readback.fake_ip_udp_relay, "off must be durably persisted");
}

/// The administrative rules lock defaults to permissive and round-trips
/// through the real writer/provider pair.
#[test]
fn rules_lock_defaults_to_allowed_and_round_trips() {
    let (_dir, conn) = fresh_conn();
    let stab = ProductionServiceStability::new(Arc::clone(&conn));

    let base = ServiceStabilityConfigProvider::get(&stab);
    assert_eq!(
        base.allow_user_rule_edits,
        Some(true),
        "a machine nobody configured must let its users edit rules"
    );

    let mut dto = base;
    dto.allow_user_rule_edits = Some(false);
    let written = ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-ADMIN")).expect("lock");
    assert_eq!(written.allow_user_rule_edits, Some(false));
    assert_eq!(
        ServiceStabilityConfigProvider::get(&stab).allow_user_rule_edits,
        Some(false),
        "the lock must be durably persisted"
    );

    dto.allow_user_rule_edits = Some(true);
    ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-ADMIN")).expect("unlock");
    assert_eq!(
        ServiceStabilityConfigProvider::get(&stab).allow_user_rule_edits,
        Some(true),
        "an administrator must be able to lift the lock again"
    );
}

/// The full-row Set replaces every other field wholesale, which is why
/// this one is an `Option`: a client saving an unrelated toggle without
/// mentioning the lock must leave it exactly where the administrator put
/// it — in BOTH directions, so neither a silent unlock nor a silent lock
/// can arrive as a side effect.
#[test]
fn a_set_that_omits_the_rules_lock_preserves_it() {
    let (_dir, conn) = fresh_conn();
    let stab = ProductionServiceStability::new(Arc::clone(&conn));

    let mut dto = ServiceStabilityConfigProvider::get(&stab);
    dto.allow_user_rule_edits = Some(false);
    ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-ADMIN")).expect("lock");

    // A different panel saves an unrelated toggle with no opinion on the
    // lock (the shape an older client sends).
    dto.allow_user_rule_edits = None;
    dto.verbose_logging = true;
    let written =
        ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-OTHER")).expect("unrelated set");
    assert!(written.verbose_logging, "the unrelated field must be saved");
    assert_eq!(
        written.allow_user_rule_edits,
        Some(false),
        "an omitted lock must never lift an administrator's lock"
    );

    // Same in the other direction: an omitted field must not impose a lock
    // on a machine that never had one.
    let (_dir2, conn2) = fresh_conn();
    let stab2 = ProductionServiceStability::new(Arc::clone(&conn2));
    let mut open = ServiceStabilityConfigProvider::get(&stab2);
    open.allow_user_rule_edits = None;
    let written2 = ServiceStabilityConfigWriter::set(&stab2, &open, Some("S-OTHER")).expect("set");
    assert_eq!(written2.allow_user_rule_edits, Some(true));
}

/// Without a wired live-apply hook (tests / degraded boot), `set()` must
/// still succeed and persist — the seam is additive, never a precondition.
#[test]
fn udp_relay_set_succeeds_without_apply_hook_wired() {
    let (_dir, conn) = fresh_conn();
    let stab = ProductionServiceStability::new(Arc::clone(&conn));

    let mut dto = ServiceStabilityConfigProvider::get(&stab);
    dto.fake_ip_udp_relay = true;
    let written = ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST"))
        .expect("set must succeed with no udp-relay apply hook wired");
    assert!(written.fake_ip_udp_relay);
}

/// Fake-IP instant reset — proves `set()` drives the live
/// flag with the persisted value, same contract proof as the UDP-relay
/// test above but for `with_instant_rst_flag` (a stored `AtomicBool`, not
/// a replan closure — see the field doc on `instant_rst_flag`).
#[test]
fn instant_rst_set_drives_live_flag_with_persisted_value() {
    let (_dir, conn) = fresh_conn();
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let stab =
        ProductionServiceStability::new(Arc::clone(&conn)).with_instant_rst_flag(Arc::clone(&flag));

    let base = ServiceStabilityConfigProvider::get(&stab);
    assert!(base.fake_ip_instant_rst, "default must be on");

    let mut dto = base;
    dto.fake_ip_instant_rst = false;
    let written = ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST"))
        .expect("set off must succeed");
    assert!(!written.fake_ip_instant_rst);
    assert!(
        !flag.load(std::sync::atomic::Ordering::Relaxed),
        "the live flag must observe the OFF write immediately"
    );

    dto.fake_ip_instant_rst = true;
    ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST")).expect("set on must succeed");
    assert!(flag.load(std::sync::atomic::Ordering::Relaxed));

    let readback = ServiceStabilityConfigProvider::get(&stab);
    assert!(readback.fake_ip_instant_rst, "on must be durably persisted");
}

/// Without a wired live-flag seam (tests / degraded boot), `set()` must
/// still succeed and persist — the seam is additive, never a precondition.
#[test]
fn instant_rst_set_succeeds_without_flag_wired() {
    let (_dir, conn) = fresh_conn();
    let stab = ProductionServiceStability::new(Arc::clone(&conn));

    let mut dto = ServiceStabilityConfigProvider::get(&stab);
    dto.fake_ip_instant_rst = false;
    let written = ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST"))
        .expect("set must succeed with no instant-rst flag wired");
    assert!(!written.fake_ip_instant_rst);
}

/// One `(desired, dns_flush_reasons)` entry per `set()` observed by the
/// recording fake-IP apply hook.
type FakeIpHookCalls = Arc<Mutex<Vec<(bool, Vec<&'static str>)>>>;

/// Wires a recording fake-IP apply hook and returns the shared call log
/// of `(desired, dns_flush_reasons)` per `set()`.
fn stab_with_recording_fake_ip_hook(
    conn: &Arc<Mutex<Connection>>,
) -> (ProductionServiceStability, FakeIpHookCalls) {
    let calls: FakeIpHookCalls = Arc::new(Mutex::new(Vec::new()));
    let stab = ProductionServiceStability::new(Arc::clone(conn)).with_fake_ip_apply({
        let calls = Arc::clone(&calls);
        Arc::new(move |req: FakeIpApplyRequest| {
            calls
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push((req.desired, req.dns_flush_reasons));
        })
    });
    (stab, calls)
}

/// A redundant save (no value changed) must still drive the live-apply
/// hook (runtime/DB convergence contract) but must NOT request an OS DNS
/// cache flush — flushing on every unrelated settings write forces a
/// machine-wide re-resolve wave for nothing.
#[test]
fn redundant_set_requests_no_dns_cache_flush() {
    let (_dir, conn) = fresh_conn();
    let (stab, calls) = stab_with_recording_fake_ip_hook(&conn);

    let dto = ServiceStabilityConfigProvider::get(&stab);
    ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST"))
        .expect("redundant set must succeed");

    let calls = calls.lock().unwrap();
    assert_eq!(
        calls.len(),
        1,
        "the live-apply hook must still run on a redundant save"
    );
    assert!(
        calls[0].1.is_empty(),
        "no resolve-affecting value changed — no flush must be requested"
    );
}

/// Flow-behavior toggles (UDP relay, instant reset) change how existing
/// flows behave, never which addresses names resolve to — flipping them
/// must not request a flush.
#[test]
fn relay_and_instant_rst_changes_request_no_dns_cache_flush() {
    let (_dir, conn) = fresh_conn();
    let (stab, calls) = stab_with_recording_fake_ip_hook(&conn);

    let mut dto = ServiceStabilityConfigProvider::get(&stab);
    dto.fake_ip_udp_relay = !dto.fake_ip_udp_relay;
    dto.fake_ip_instant_rst = !dto.fake_ip_instant_rst;
    ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST")).expect("set must succeed");

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert!(
        calls[0].1.is_empty(),
        "relay/instant-rst flips are flow-behavior only — no flush"
    );
}

/// An effective fake-IP transition (toggle flip while the resolver mode is
/// active) must request exactly one flush, attributed to the toggle; the
/// same toggle flipped in Reactive mode transitions nothing and must not.
#[test]
fn fake_ip_enabled_change_requests_dns_cache_flush() {
    let (_dir, conn) = fresh_conn();
    let (stab, calls) = stab_with_recording_fake_ip_hook(&conn);

    // Enable: reactive/off -> resolver/on is an effective false -> true.
    let mut dto = ServiceStabilityConfigProvider::get(&stab);
    dto.enforcement_mode = "resolver".to_string();
    dto.fake_ip_enabled = true;
    ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST")).expect("set on");
    assert_eq!(
        *calls.lock().unwrap(),
        vec![(true, vec!["fake_ip_enabled"])],
        "an effective enable must request a flush attributed to the toggle"
    );

    // Disable the toggle only: effective true -> false, flush again.
    dto.fake_ip_enabled = false;
    ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST")).expect("set off");
    assert_eq!(
        calls.lock().unwrap()[1],
        (false, vec!["fake_ip_enabled"]),
        "an effective disable must request a flush too"
    );

    // Back to Reactive first, then flip the toggle: the stack never runs
    // in Reactive, so neither write after the mode change transitions it.
    dto.enforcement_mode = "reactive".to_string();
    ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST")).expect("set reactive");
    dto.fake_ip_enabled = true;
    ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST")).expect("toggle in reactive");
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 4);
    assert!(
        calls[2].1.is_empty() && calls[3].1.is_empty(),
        "no effective stack transition in Reactive mode — no flush"
    );
}

/// The client-resolve DNS toggles request a flush when (and only when)
/// their persisted value changes; several changes in one write coalesce
/// into ONE hook call carrying every trigger — one flush per Set.
#[test]
fn dns_toggle_changes_request_single_flush_with_reasons() {
    let (_dir, conn) = fresh_conn();
    let (stab, calls) = stab_with_recording_fake_ip_hook(&conn);

    let mut dto = ServiceStabilityConfigProvider::get(&stab);
    dto.dns_via_secondary = !dto.dns_via_secondary;
    dto.dns_fast_answers = !dto.dns_fast_answers;
    ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST")).expect("set must succeed");

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1, "one Set — one hook call, one flush");
    assert_eq!(
        calls[0].1,
        vec!["dns_via_secondary", "dns_fast_answers"],
        "both changed toggles must be reported as the flush reason"
    );
}
