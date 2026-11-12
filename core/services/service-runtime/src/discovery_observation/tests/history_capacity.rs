use super::*;

fn fill_history(pipeline: &DiscoveryObservationPipeline, count: usize, repeat: Duration) {
    let now = BootInstant::now();
    let mut memory = pipeline.memory.lock().unwrap_or_else(|p| p.into_inner());
    for index in 0..count {
        memory.recent.insert(
            (OTHER.to_owned(), format!("private-history-{index}.example")),
            Recent {
                at: now,
                repeat,
                last_probe_started_unix_ms: None,
            },
        );
    }
}

fn assert_resource_wait(f: &Fixture, host: &str) {
    let snapshot = serde_json::to_value(f.engine.discovery_snapshot(OWNER, SystemTime::now()))
        .unwrap_or_else(|error| panic!("snapshot: {error}"));
    let row = snapshot["episodes"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["host"] == host))
        .unwrap_or_else(|| panic!("queued host must remain visible"));
    assert_eq!(
        row["probe-queue"]["wait-kind"], "resources",
        "a full history must not be described as an ordinary scheduled check"
    );
    assert!(
        row["probe-queue"]["eligible-in-ms"].is_null(),
        "resource capacity is not a promised start time"
    );
    assert!(
        !snapshot.to_string().contains("private-history-"),
        "another owner's retained names must stay private"
    );
    assert!(
        f.probe
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty(),
        "a resource refusal must not send an untracked probe"
    );
    assert!(f.engine.candidates(OWNER).is_empty());
}

#[test]
fn a_full_history_explains_resource_wait_and_recovers_without_another_browser_attempt() {
    let host = "history-capacity-wait.example";
    let f = fixture(host);
    remember_shared_name(&f.pipeline, host, TARGET);
    fill_history(&f.pipeline, MAX_RECENT, Duration::from_secs(30));
    shared_attempt(&f.pipeline, TARGET);
    assert_resource_wait(&f, host);
    {
        let memory = f.pipeline.memory.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(memory.recent.len(), MAX_RECENT);
        assert_eq!(memory.pending.len(), 1);
    }
    crate::boot_clock::simulate_sleep(Duration::from_secs(31));
    f.pipeline.pump();
    wait_for_workers(&f.pipeline);
    assert!(
        f.engine
            .candidates(OWNER)
            .iter()
            .any(|candidate| candidate.proposed_match == host),
        "freeing a history slot must resume retained work without another visit"
    );
    assert!(f
        .probe
        .calls
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .any(|(_, source)| *source == SECONDARY));
    let memory = f.pipeline.memory.lock().unwrap_or_else(|p| p.into_inner());
    assert!(memory.recent.len() <= MAX_RECENT);
    assert!(memory.pending.is_empty());
}

#[test]
fn a_reserved_inflight_history_slot_is_not_reported_as_immediately_available() {
    let host = "reserved-history-slot.example";
    let f = fixture(host);
    remember_shared_name(&f.pipeline, host, TARGET);
    fill_history(&f.pipeline, MAX_RECENT - 1, Duration::from_secs(86400));
    f.pipeline
        .memory
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .in_flight
        .insert(
            (
                OTHER.to_owned(),
                "private-history-inflight.example".to_owned(),
            ),
            BootInstant::now(),
        );
    shared_attempt(&f.pipeline, TARGET);
    assert_resource_wait(&f, host);
}

#[test]
fn a_full_owner_budget_table_reports_resource_wait_without_disclosing_other_owners() {
    let host = "owner-table-capacity.example";
    let f = fixture(host);
    remember_shared_name(&f.pipeline, host, TARGET);
    {
        let now = BootInstant::now();
        let mut memory = f.pipeline.memory.lock().unwrap_or_else(|p| p.into_inner());
        for index in 0..MAX_RECENT {
            memory
                .budgets
                .insert(format!("private-owner-{index}"), Bucket::empty(now));
        }
    }
    shared_attempt(&f.pipeline, TARGET);
    assert_resource_wait(&f, host);
    let snapshot = serde_json::to_string(&f.engine.discovery_snapshot(OWNER, SystemTime::now()))
        .unwrap_or_else(|error| panic!("snapshot: {error}"));
    assert!(!snapshot.contains("private-owner-"));
    crate::boot_clock::simulate_sleep(Duration::from_secs(16));
    f.pipeline.pump();
    wait_for_workers(&f.pipeline);
    assert!(f
        .engine
        .candidates(OWNER)
        .iter()
        .any(|candidate| candidate.proposed_match == host));
    assert!(
        f.pipeline
            .memory
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .budgets
            .len()
            <= MAX_RECENT
    );
}

#[test]
fn expired_history_does_not_promise_a_slot_while_an_unfinished_probe_still_owns_it() {
    let host = "unfinished-history-slot.example";
    let f = fixture(host);
    remember_shared_name(&f.pipeline, host, TARGET);
    fill_history(&f.pipeline, MAX_RECENT, Duration::from_secs(86400));
    {
        let now = BootInstant::now();
        let mut memory = f.pipeline.memory.lock().unwrap_or_else(|p| p.into_inner());
        let key = (OTHER.to_owned(), "private-history-0.example".to_owned());
        memory
            .recent
            .get_mut(&key)
            .unwrap_or_else(|| panic!("retained history"))
            .repeat = Duration::from_secs(1);
        memory.in_flight.insert(key, now);
    }
    crate::boot_clock::simulate_sleep(Duration::from_secs(2));
    shared_attempt(&f.pipeline, TARGET);
    assert_resource_wait(&f, host);
}
