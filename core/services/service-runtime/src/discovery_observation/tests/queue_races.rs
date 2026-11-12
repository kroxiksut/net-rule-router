use super::*;

#[test]
fn unrelated_udp_batches_do_not_starve_queued_tcp_discovery() {
    use crate::conn_observation_consumer::{
        ConnTraceTee, ConnectionObservationConsumer, ConnectionTraceRing,
    };
    struct NoBindings;
    impl nrr_platform_api::enforcement::EgressBindingSource for NoBindings {
        fn bindings_for(
            &self,
            _: &nrr_platform_api::enforcement::UserPrincipal,
        ) -> nrr_platform_api::enforcement::EgressBinding {
            nrr_platform_api::enforcement::EgressBinding::default()
        }
    }
    for tee in [false, true] {
        let f = fixture("a-udp-warm-0.example");
        let healthy: Vec<_> = (0..8).map(|n| format!("a-udp-warm-{n}.example")).collect();
        for host in &healthy {
            f.pipeline.wiring.names.record_for(OWNER, host, &[TARGET]);
        }
        *f.probe
            .primary_answering_hosts
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = healthy;
        let pipeline = Arc::new(f.pipeline);
        shared_attempt(&pipeline, TARGET);
        let target = Ipv4Addr::new(203, 0, 116, 1);
        let fresh = "queued-during-unrelated-udp.example";
        remember_shared_name(&pipeline, fresh, target);
        shared_attempt(&pipeline, target);
        crate::boot_clock::simulate_sleep(Duration::from_secs(40));
        let mut unrelated = observation(Some(OWNER), ConnectionProgress::Attempt);
        unrelated.protocol = TransportProtocol::Udp;
        unrelated.remote = SocketAddr::new(Ipv4Addr::new(198, 51, 100, 99).into(), 9999);
        unrelated.process_path = None;
        let api = Arc::new(nrr_platform_api::windows_api::MockWindowsApi::new());
        let applied = Arc::new(AtomicUsize::new(0));
        if tee {
            ConnTraceTee::new(
                Arc::new(ConnectionTraceRing::new(8)),
                api,
                Arc::new(NoBindings),
            )
            .with_discovery_observation(Arc::clone(&pipeline))
            .record(&[unrelated], 0);
        } else {
            let consumer = Arc::new(
                ConnectionObservationConsumer::with_egress(
                    api,
                    Arc::new(|_| (None, None)),
                    Arc::new(|| None),
                    false,
                )
                .with_discovery_observation(Arc::clone(&pipeline)),
            );
            let source =
                Arc::new(nrr_platform_api::conn_observe::MockConnectionObservationSource::new());
            source.push(unrelated);
            let count = Arc::clone(&applied);
            let mut task = crate::service_tasks::build_conn_observe_task_reporting(
                source,
                consumer,
                Some(Arc::new(move || {
                    count.fetch_add(1, Ordering::Relaxed);
                })),
                None,
            );
            assert_eq!(
                (task.tick)(&crate::lifecycle::StopToken::new()),
                crate::runtime_loop::TaskOutcome::Continue
            );
        }
        wait_for_workers(&pipeline);
        assert!(
            f.engine
                .candidates(OWNER)
                .iter()
                .any(|candidate| candidate.proposed_match == fresh),
            "periodic discovery must advance even when every new observation is unrelated UDP"
        );
        assert_eq!(applied.load(Ordering::Relaxed), 0);
        assert!(f.engine.seen_with(OWNER, fresh, 8).is_empty());
    }
}

#[test]
fn queued_refreshes_use_the_current_repeat_setting_in_both_directions() {
    for lowering in [false, true] {
        let mut f = fixture(if lowering {
            "shortened-repeat.example"
        } else {
            "lengthened-repeat.example"
        });
        f.pipeline
            .wiring
            .names
            .record("foreign-repeat-policy.example", &[TARGET]);
        f.probe.primary_answers.store(true, Ordering::Release);
        let repeat = Arc::new(AtomicUsize::new(if lowering { 86400 } else { 300 }));
        let read = Arc::clone(&repeat);
        let read_limits = Arc::clone(&repeat);
        let wiring = Arc::get_mut(&mut f.pipeline.wiring).expect("unshared wiring");
        wiring.cadence = Arc::new(move |_| AutoProbeCadence {
            enabled: true,
            repeat: Duration::from_secs(read.load(Ordering::Acquire) as u64),
        });
        wiring.limits = Arc::new(move |_| {
            ProbeLimits::new(
                Duration::from_millis(300),
                8,
                Duration::from_secs(read_limits.load(Ordering::Acquire) as u64),
            )
        });
        let pipeline = Arc::new(f.pipeline);
        shared_attempt(&pipeline, TARGET);
        shared_attempt(&pipeline, TARGET);
        assert_eq!(
            f.probe
                .calls
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .len(),
            1
        );
        repeat.store(if lowering { 300 } else { 86400 }, Ordering::Release);
        crate::boot_clock::simulate_sleep(Duration::from_secs(400));
        idle_discovery_tick(&pipeline, false);
        assert_eq!(
            f.probe
                .calls
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .len(),
            if lowering { 2 } else { 1 },
            "a queued refresh must honor both reduced and increased host cooldowns"
        );
    }
}

#[test]
fn both_windows_observer_builders_pump_an_empty_source_without_route_progress() {
    use crate::conn_observation_consumer::ConnectionObservationConsumer;
    use crate::service_tasks::{build_conn_observe_task, build_conn_observe_task_reporting};
    for reporting in [false, true] {
        let mut f = fixture("a-windows-idle.example");
        f.pipeline
            .wiring
            .names
            .record_for(OWNER, "b-windows-idle.example", &[TARGET]);
        Arc::get_mut(&mut f.pipeline.wiring)
            .expect("unshared wiring")
            .limits =
            Arc::new(|_| ProbeLimits::new(Duration::from_millis(300), 1, Duration::from_secs(300)));
        let pipeline = Arc::new(f.pipeline);
        shared_attempt(&pipeline, TARGET);
        assert_eq!(f.engine.candidates(OWNER).len(), 1);
        let api = Arc::new(nrr_platform_api::windows_api::MockWindowsApi::new());
        let consumer = Arc::new(
            ConnectionObservationConsumer::with_egress(
                api,
                Arc::new(|_| (None, None)),
                Arc::new(|| None),
                false,
            )
            .with_discovery_observation(Arc::clone(&pipeline)),
        );
        let source =
            Arc::new(nrr_platform_api::conn_observe::MockConnectionObservationSource::new());
        let progressed = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&progressed);
        let hook: crate::supervised_runtime::RouteRecomputeHook = Arc::new(move || {
            count.fetch_add(1, Ordering::Relaxed);
        });
        let mut task = if reporting {
            build_conn_observe_task_reporting(source, consumer, Some(hook), None)
        } else {
            build_conn_observe_task(source, consumer, Some(hook))
        };
        crate::boot_clock::simulate_sleep(Duration::from_secs(2));
        assert_eq!(
            (task.tick)(&crate::lifecycle::StopToken::new()),
            crate::runtime_loop::TaskOutcome::Continue
        );
        wait_for_workers(&pipeline);
        assert_eq!(
            f.engine.candidates(OWNER).len(),
            2,
            "Windows' real observer tick must pump deferred work on an empty drain"
        );
        assert_eq!(
            progressed.load(Ordering::Relaxed),
            0,
            "diagnostic progress must not reapply routes"
        );
    }
}

#[test]
fn a_probe_port_panic_keeps_other_names_without_refunding_a_started_attempt() {
    struct PanicsOnce {
        once: AtomicBool,
    }
    impl PathProbe for PanicsOnce {
        fn probe(&self, _: Ipv4Addr, _: u16, _: Option<Ipv4Addr>, _: Duration) -> PathVerdict {
            unreachable!("TLS only")
        }
        fn probe_tls(
            &self,
            _: Ipv4Addr,
            host: &str,
            source: Option<Ipv4Addr>,
            _: Duration,
        ) -> PathVerdict {
            if host == "a-panicking-job.example" {
                assert!(
                    !self.once.swap(false, Ordering::AcqRel),
                    "simulated probe port panic"
                );
            }
            if source == Some(PRIMARY) {
                PathVerdict::Silent
            } else {
                PathVerdict::Answered
            }
        }
    }
    let mut f = fixture("a-panicking-job.example");
    f.pipeline
        .wiring
        .names
        .record_for(OWNER, "b-recovered-tail.example", &[TARGET]);
    Arc::get_mut(&mut f.pipeline.wiring)
        .expect("unshared wiring")
        .probe = Arc::new(PanicsOnce {
        once: AtomicBool::new(true),
    });
    let pipeline = Arc::new(f.pipeline);
    shared_attempt(&pipeline, TARGET);
    idle_discovery_tick(&pipeline, false);
    assert!(
        f.engine
            .candidates(OWNER)
            .iter()
            .any(|candidate| candidate.proposed_match == "b-recovered-tail.example"),
        "an unwound worker must not strand an unstarted owner's name or in-flight lease"
    );
    for index in 0..6 {
        let target = Ipv4Addr::new(203, 0, 114, index + 1);
        remember_shared_name(&pipeline, &format!("after-panic-{index}.example"), target);
        shared_attempt(&pipeline, target);
    }
    let overflow = Ipv4Addr::new(203, 0, 114, 100);
    remember_shared_name(&pipeline, "after-panic-overflow.example", overflow);
    shared_attempt(&pipeline, overflow);
    assert_eq!(
        f.engine.candidates(OWNER).len(),
        7,
        "the started failed attempt spends one token; only unstarted leases are refunded"
    );
}

#[test]
fn a_binding_change_before_an_unstarted_batch_item_retries_it_on_current_sources() {
    struct LiveLinks(Arc<AtomicBool>);
    const NEW_PRIMARY: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 11);
    impl EgressSources for LiveLinks {
        fn egress_source_ips(&self, _: &str) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
            (
                Some(if self.0.load(Ordering::Acquire) {
                    NEW_PRIMARY
                } else {
                    PRIMARY
                }),
                Some(SECONDARY),
            )
        }
    }
    struct SwitchingProbe {
        switched: Arc<AtomicBool>,
        calls: Mutex<Vec<(String, Ipv4Addr)>>,
    }
    impl PathProbe for SwitchingProbe {
        fn probe(&self, _: Ipv4Addr, _: u16, _: Option<Ipv4Addr>, _: Duration) -> PathVerdict {
            unreachable!("TLS only")
        }
        fn probe_tls(
            &self,
            _: Ipv4Addr,
            host: &str,
            source: Option<Ipv4Addr>,
            _: Duration,
        ) -> PathVerdict {
            let source = source.expect("bound source");
            self.calls
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push((host.to_owned(), source));
            if source == SECONDARY {
                if host == "a-binding-switch.example" {
                    self.switched.store(true, Ordering::Release);
                }
                PathVerdict::Answered
            } else {
                PathVerdict::Silent
            }
        }
    }
    let mut f = fixture("a-binding-switch.example");
    f.pipeline
        .wiring
        .names
        .record_for(OWNER, "b-binding-retry.example", &[TARGET]);
    let switched = Arc::new(AtomicBool::new(false));
    let probe = Arc::new(SwitchingProbe {
        switched: Arc::clone(&switched),
        calls: Mutex::new(Vec::new()),
    });
    let wiring = Arc::get_mut(&mut f.pipeline.wiring).expect("unshared wiring");
    wiring.egress = Arc::new(LiveLinks(switched));
    wiring.probe = probe.clone();
    wiring.limits =
        Arc::new(|_| ProbeLimits::new(Duration::from_millis(300), 1, Duration::from_secs(300)));
    let pipeline = Arc::new(f.pipeline);
    shared_attempt(&pipeline, TARGET);
    idle_discovery_tick(&pipeline, false);
    assert!(
        f.engine
            .candidates(OWNER)
            .iter()
            .any(|candidate| candidate.proposed_match == "b-binding-retry.example"),
        "a binding flap before sending must retain valid work and refresh its sources"
    );
    let calls = probe.calls.lock().unwrap_or_else(|p| p.into_inner());
    assert!(calls
        .iter()
        .any(|(host, source)| host == "b-binding-retry.example" && *source == NEW_PRIMARY));
    assert!(!calls
        .iter()
        .any(|(host, source)| host == "b-binding-retry.example" && *source == PRIMARY));
}

#[test]
fn a_name_that_becomes_shared_during_a_probe_never_credits_a_browser_visit() {
    struct BecomesShared {
        names: Arc<ObservedHostNames>,
        probe: Arc<Probe>,
        once: AtomicBool,
    }
    impl PathProbe for BecomesShared {
        fn probe(&self, _: Ipv4Addr, _: u16, _: Option<Ipv4Addr>, _: Duration) -> PathVerdict {
            unreachable!("TLS only")
        }
        fn probe_tls(
            &self,
            target: Ipv4Addr,
            host: &str,
            source: Option<Ipv4Addr>,
            timeout: Duration,
        ) -> PathVerdict {
            if self.once.swap(false, Ordering::AcqRel) {
                self.names
                    .record("newly-discovered-neighbor.example", &[target]);
            }
            self.probe.probe_tls(target, host, source, timeout)
        }
    }
    let host = "identity-changes-during-probe.example";
    let mut f = fixture(host);
    let names = Arc::clone(&f.pipeline.wiring.names);
    Arc::get_mut(&mut f.pipeline.wiring)
        .expect("unshared wiring")
        .probe = Arc::new(BecomesShared {
        names,
        probe: Arc::clone(&f.probe),
        once: AtomicBool::new(true),
    });
    let stalls = crate::primary_stall_registry::global_primary_stalls();
    let before = stalls.behavior_of(OWNER, host);
    close(&f, Some(OWNER), ConnectionProgress::Reset);
    let offered = f.engine.candidates(OWNER);
    assert_eq!(offered.len(), 1);
    assert_eq!(offered[0].signal, "shared-address-reachability");
    assert_eq!(offered[0].match_kind, "exact");
    assert_eq!(offered[0].observations, None);
    assert_eq!(stalls.behavior_of(OWNER, host), before);
}

#[test]
fn a_full_owner_queue_reports_a_real_refusal_without_promising_an_automatic_retry() {
    let f = fixture("a-queue-warm-0.example");
    let healthy: Vec<_> = (0..8)
        .map(|n| format!("a-queue-warm-{n}.example"))
        .collect();
    for host in &healthy {
        f.pipeline.wiring.names.record_for(OWNER, host, &[TARGET]);
    }
    *f.probe
        .primary_answering_hosts
        .lock()
        .unwrap_or_else(|p| p.into_inner()) = healthy;
    let pipeline = Arc::new(f.pipeline);
    shared_attempt(&pipeline, TARGET);
    for index in 0..64 {
        let target = Ipv4Addr::new(203, 0, 115, index + 1);
        remember_shared_name(&pipeline, &format!("queued-flood-{index}.example"), target);
        shared_attempt(&pipeline, target);
    }
    let overflow = "queue-capacity-refusal.example";
    let target = Ipv4Addr::new(203, 0, 115, 200);
    remember_shared_name(&pipeline, overflow, target);
    shared_attempt(&pipeline, target);
    let snapshot = f.engine.discovery_snapshot(OWNER, SystemTime::now());
    let episode = snapshot
        .episodes
        .iter()
        .find(|episode| episode.host.as_deref() == Some(overflow))
        .expect("refusal episode");
    assert_eq!(episode.reason, "probe-memory-limit");
    assert_eq!(episode.state, "not-created");
    assert!(f.engine.candidates(OWNER).is_empty());
    assert_eq!(
        f.probe
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len(),
        8
    );
}
