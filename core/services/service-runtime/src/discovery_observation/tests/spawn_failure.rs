use super::*;

#[test]
fn a_worker_that_cannot_start_keeps_the_original_flow_destination_in_the_diagnostic() {
    let host = "spawn-destination-regression.example";
    let f = fixture(host);
    let now = BootInstant::now();
    let reservation = f
        .pipeline
        .reserve(OWNER, host, Duration::from_secs(300), now)
        .unwrap_or_else(|reason| panic!("initial reservation: {reason:?}"));
    let destination = "192.0.2.10:49152 -> 203.0.113.10:443";
    f.pipeline.start_confirmation(
        Confirmation {
            owner: OWNER.into(),
            host: host.into(),
            destination: destination.into(),
            target: TARGET,
            source: PRIMARY,
            secondary: Some(SECONDARY),
            timeout: Duration::from_millis(300),
            process: Some("C:\\Browser\\browser.exe".into()),
            shared_address: false,
        },
        reservation,
        |_| Err(std::io::Error::other("worker creation refused")),
    );
    let rows = f
        .engine
        .discovery_snapshot(OWNER, SystemTime::now())
        .episodes;
    let row = rows
        .iter()
        .find(|episode| episode.host.as_deref() == Some(host))
        .unwrap_or_else(|| panic!("failed worker episode"));
    assert_eq!(
        row.destination.as_deref(),
        Some(destination),
        "an unavailable worker must not erase the observed flow address"
    );
    assert_eq!(row.reason, "probe-start-failed");
    assert_eq!(f.pipeline.workers.load(Ordering::Acquire), 0);
    assert!(f
        .probe
        .calls
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .is_empty());
    let retry = f
        .pipeline
        .reserve(OWNER, host, Duration::from_secs(300), now)
        .unwrap_or_else(|reason| panic!("a failed spawn must not spend credits: {reason:?}"));
    f.pipeline.rollback_reservation(retry);
}
