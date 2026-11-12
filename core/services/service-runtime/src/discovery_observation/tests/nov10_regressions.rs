use super::*;

#[test]
fn nov10_a_tls_reply_does_not_erase_a_real_browser_failure_offer() {
    let host = "browser-fails-despite-tls.example";
    let f = fixture(host);
    close(&f, Some(OWNER), ConnectionProgress::Reset);
    assert_eq!(
        f.engine.candidates(OWNER).len(),
        1,
        "a real failing flow earned an offer"
    );
    f.probe.primary_answers.store(true, Ordering::Release);
    DiscoveryObservationPipeline::confirm(
        &f.pipeline.wiring,
        Confirmation {
            owner: OWNER.into(),
            host: host.into(),
            destination: "browser flow".into(),
            target: TARGET,
            source: PRIMARY,
            secondary: Some(SECONDARY),
            timeout: Duration::from_millis(300),
            process: Some("C:\\Browser\\browser.exe".into()),
            shared_address: false,
        },
    );
    assert_eq!(
        f.engine.candidates(OWNER).len(),
        1,
        "a TLS handshake is not evidence that the browser's HTTP exchange recovered"
    );
    assert_eq!(
        crate::primary_stall_registry::global_primary_stalls().behavior_of(OWNER, host),
        nrr_domain::companion_affinity::PrimaryBehavior::Stalls
    );
    assert!(f.engine.candidates(OTHER).is_empty());
}

#[test]
fn nov10_a_service_owned_flow_cannot_schedule_confirmation_as_a_user_visit() {
    let f = fixture("service-probe-is-not-navigation.example");
    let mut attempt = observation(Some(OWNER), ConnectionProgress::Attempt);
    attempt.pid = std::process::id();
    attempt.process_path = Some(
        std::env::current_exe()
            .unwrap_or_else(|error| panic!("image: {error}"))
            .to_string_lossy()
            .into_owned(),
    );
    let mut closed = attempt.clone();
    closed.progress = ConnectionProgress::ClosedUnknown;
    closed.process_path = None;
    f.pipeline.observe(&attempt, EgressRole::Primary);
    f.pipeline.observe(&closed, EgressRole::Primary);
    wait_for_workers(&f.pipeline);
    assert!(
        f.probe
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty(),
        "active probes must not trigger more automatic probes"
    );
    assert!(f.engine.candidates(OWNER).is_empty());
}

#[test]
fn nov10_browser_failure_reaches_owner_candidate_push_and_read_dto_despite_later_attempts() {
    use crate::ipc_handlers::event_bus::EventBus;
    use nrr_shared::ipc_payloads::StatusUpdateEvent;
    for scenario in [
        "failure",
        "healthy-primary",
        "secondary-missing",
        "another-owner",
    ] {
        let host = format!("browser-to-tray-{scenario}.example");
        let mut f = fixture(&host);
        let bus = Arc::new(EventBus::new());
        let own = bus
            .subscribe_as("own-tray".into(), Some(OWNER.into()), None)
            .subscription_id;
        let foreign = bus
            .subscribe_as("foreign-tray".into(), Some(OTHER.into()), None)
            .subscription_id;
        let engine = Arc::new(
            AutoRulesEngine::new(
                f.rules.clone(),
                Arc::new(|_| nrr_storage::auto_rules::AutoRulesMode::Suggest),
                Arc::new(InMemoryDismissalStore::new()),
                Arc::new(InMemoryPendingStore::new()),
                SystemTime::now(),
            )
            .with_primary_behavior_source(Arc::new(|owner, host| {
                crate::primary_stall_registry::global_primary_stalls()
                    .behavior_of_subtree(owner, host)
            }))
            .with_event_bus(Arc::clone(&bus)),
        );
        Arc::get_mut(&mut f.pipeline.wiring)
            .unwrap_or_else(|| panic!("unshared wiring"))
            .engine = Arc::clone(&engine);
        if scenario == "healthy-primary" {
            f.probe.primary_answers.store(true, Ordering::Release);
        }
        if scenario == "secondary-missing" {
            struct PrimaryOnly;
            impl EgressSources for PrimaryOnly {
                fn egress_source_ips(&self, _: &str) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
                    (Some(PRIMARY), None)
                }
            }
            Arc::get_mut(&mut f.pipeline.wiring)
                .unwrap_or_else(|| panic!("unshared wiring"))
                .egress = Arc::new(PrimaryOnly);
        }
        let pipeline = Arc::new(f.pipeline);
        let api = nrr_platform_api::windows_api::MockWindowsApi::new();
        api.set_adapter_infos(vec![nrr_platform_api::adapters::AdapterInfo {
            index: 7,
            adapter_name: "primary".into(),
            description: "primary".into(),
            friendly_name: "primary".into(),
            mac: None,
            interface_type: nrr_platform_api::adapters::InterfaceType::Ethernet,
            oper_status: nrr_platform_api::adapters::IfOperStatus::Up,
            ipv4_addresses: vec![PRIMARY],
            ipv6_addresses: Vec::new(),
            gateways: vec![Ipv4Addr::new(192, 0, 2, 1)],
        }]);
        let consumer =
            crate::conn_observation_consumer::ConnectionObservationConsumer::with_egress(
                Arc::new(api),
                Arc::new(|_| (Some(7), None)),
                Arc::new(|| Some(OWNER.into())),
                false,
            )
            .with_discovery_observation(Arc::clone(&pipeline));
        let owner = if scenario == "another-owner" {
            OTHER
        } else {
            OWNER
        };
        let attempted = observation(Some(owner), ConnectionProgress::Attempt);
        let closed = observation(Some(owner), ConnectionProgress::ClosedUnknown);
        consumer.consume(&[attempted.clone(), closed], SystemTime::now());
        wait_for_workers(&pipeline);
        // A later browser table observation is routine evidence, not a withdrawal.
        consumer.consume(&[attempted], SystemTime::now());
        wait_for_workers(&pipeline);
        let rows = engine.candidates(OWNER);
        let pushes: Vec<_> = bus
            .peek_pending_for(&own, 64)
            .into_iter()
            .filter_map(|envelope| match envelope.event {
                StatusUpdateEvent::AutoRuleCandidatesChanged {
                    pending_count,
                    announces: true,
                    ..
                } => Some(pending_count),
                _ => None,
            })
            .collect();
        if scenario == "failure" {
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].proposed_match, host);
            assert!(!rows[0].served_by_main_link);
            assert!(
                pushes.contains(&1),
                "the owning tray must receive a push that resolves to its actual read DTO"
            );
            assert!(bus.peek_pending_for(&foreign, 64).is_empty());
            let snapshot = engine.discovery_snapshot(OWNER, SystemTime::now());
            let episode = snapshot
                .episodes
                .iter()
                .find(|episode| episode.host.as_deref() == Some(host.as_str()))
                .unwrap_or_else(|| panic!("browser episode"));
            assert_eq!(episode.candidate_id.as_deref(), Some(rows[0].id.as_str()));
            assert_eq!(
                episode.state, "ready",
                "a parked actionable offer stays ready while routine observations continue"
            );
            assert_eq!(episode.reason, "offer-ready");
            assert!(
                episode
                    .history
                    .iter()
                    .any(|step| step.reason == "insufficient-evidence"),
                "raw subsequent observation remains in history"
            );
        } else {
            assert!(
                rows.is_empty(),
                "{scenario} must not create this owner's route offer"
            );
            assert!(pushes.is_empty());
        }
    }
}
