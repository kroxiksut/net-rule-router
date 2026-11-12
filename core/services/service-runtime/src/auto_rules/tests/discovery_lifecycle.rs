use super::*;
use crate::principal_reset::PrincipalStateHolder;

fn parked_offer(engine: &AutoRulesEngine, at: SystemTime) -> AutoRuleCandidateDto {
    let mut dto = main_link_dto(
        "down.example",
        "down.example",
        AUTO_RULE_SIGNAL_MAIN_LINK_BLOCKED,
        nrr_shared::ipc_payloads::AUTO_RULE_PRIMARY_BEHAVIOR_STALLS,
    );
    dto.id = candidate_id(SID, AUTO_RULE_MATCH_KIND_SUFFIX, &dto.proposed_match);
    engine.park(
        SID,
        vec![PendingCandidate {
            dto: dto.clone(),
            route: RouteRole::Secondary,
            match_kind: AuthoredMatchKind::SuffixDomain,
        }],
        unix_ms(at),
    );
    dto
}

#[test]
fn reading_an_expired_offer_does_not_invent_a_fresh_discovery_episode() {
    let f = fixture(AutoRulesMode::Suggest);
    let now = wall_clock();
    parked_offer(&f.engine, now);
    let expired =
        now + Duration::from_millis(nrr_domain::suggestion_discovery::EPISODE_TTL_MS as u64 + 1);
    assert!(f
        .engine
        .discovery_snapshot(SID, expired)
        .episodes
        .is_empty());
    assert!(f
        .engine
        .discovery_snapshot(SID, expired + Duration::from_secs(1))
        .episodes
        .is_empty());
}

#[test]
fn an_unrelated_offer_does_not_refresh_an_old_hosts_discovery_window() {
    let f = fixture(AutoRulesMode::Suggest);
    let now = wall_clock();
    parked_offer(&f.engine, now);
    let later =
        now + Duration::from_millis(nrr_domain::suggestion_discovery::EPISODE_TTL_MS as u64 - 1);
    let mut dto = main_link_dto(
        "other.example",
        "other.example",
        AUTO_RULE_SIGNAL_MAIN_LINK_BLOCKED,
        nrr_shared::ipc_payloads::AUTO_RULE_PRIMARY_BEHAVIOR_STALLS,
    );
    dto.id = candidate_id(SID, AUTO_RULE_MATCH_KIND_SUFFIX, &dto.proposed_match);
    f.engine.park(
        SID,
        vec![PendingCandidate {
            dto,
            route: RouteRole::Secondary,
            match_kind: AuthoredMatchKind::SuffixDomain,
        }],
        unix_ms(later),
    );
    let episodes = f
        .engine
        .discovery_snapshot(SID, later + Duration::from_millis(2))
        .episodes;
    assert_eq!(episodes.len(), 1);
    assert_eq!(episodes[0].host.as_deref(), Some("other.example"));
}

#[test]
fn reading_a_waiting_offer_preserves_the_actual_reason_its_probe_did_not_run() {
    let mut f = fixture(AutoRulesMode::Suggest);
    f.engine.main_link_pass_enabled = Some(Arc::new(|_| true));
    let mut dto = main_link_dto(
        "site.example",
        "down.other",
        AUTO_RULE_SIGNAL_CO_ACTIVITY,
        "",
    );
    dto.id = candidate_id(SID, AUTO_RULE_MATCH_KIND_SUFFIX, &dto.proposed_match);
    f.engine.park(
        SID,
        vec![PendingCandidate {
            dto,
            route: RouteRole::Secondary,
            match_kind: AuthoredMatchKind::SuffixDomain,
        }],
        unix_ms(wall_clock()),
    );
    for reason in [
        "probe-inconclusive",
        "probe-no-address",
        "capacity-limit",
        "probe-cooldown",
        "probe-budget-exhausted",
        "probe-memory-limit",
        "probe-workers-busy",
        "probe-start-failed",
    ] {
        f.engine.note_discovery(
            SID,
            Some("down.other"),
            None,
            DiscoveryDecision::new("probe", "deferred", reason),
            wall_clock(),
        );
        assert_eq!(
            f.engine.discovery_snapshot(SID, wall_clock()).episodes[0].reason,
            reason
        );
    }
}

#[test]
fn a_principal_reset_removes_private_discovery_even_without_pending_rules() {
    let f = fixture(AutoRulesMode::Suggest);
    for owner in [SID, "another-user"] {
        f.engine.note_discovery(
            owner,
            Some("private.example"),
            None,
            DiscoveryDecision::new("name", "not-created", "name-unknown"),
            wall_clock(),
        );
    }
    f.engine.forget_principal(SID);
    assert!(f
        .engine
        .discovery_snapshot(SID, wall_clock())
        .episodes
        .is_empty());
    assert_eq!(
        f.engine
            .discovery_snapshot("another-user", wall_clock())
            .episodes
            .len(),
        1
    );
}

#[test]
fn a_full_reset_removes_discovery_only_principals() {
    let f = fixture(AutoRulesMode::Suggest);
    f.engine.note_discovery(
        "discovery-only",
        None,
        Some("192.0.2.1:443"),
        DiscoveryDecision::new("name", "not-created", "name-unknown"),
        wall_clock(),
    );
    f.engine.forget_everyone();
    assert!(f
        .engine
        .discovery_snapshot("discovery-only", wall_clock())
        .episodes
        .is_empty());
}

#[test]
fn a_service_restart_never_reuses_an_episode_identity_in_a_later_archive() {
    let first = fixture(AutoRulesMode::Suggest);
    let second = fixture(AutoRulesMode::Suggest);
    for engine in [&first.engine, &second.engine] {
        engine.note_discovery(
            SID,
            Some("private.example"),
            None,
            DiscoveryDecision::new("name", "not-created", "name-unknown"),
            wall_clock(),
        );
    }
    assert_ne!(
        first.engine.discovery_snapshot(SID, wall_clock()).episodes[0].id,
        second.engine.discovery_snapshot(SID, wall_clock()).episodes[0].id
    );
}

#[test]
fn a_secondary_recovery_is_recorded_without_needing_a_client_to_read() {
    let f = fixture(AutoRulesMode::Suggest);
    parked_offer(&f.engine, wall_clock());
    f.engine
        .note_secondary_reach(SID, "down.example", false, wall_clock());
    f.engine.note_secondary_reach(
        SID,
        "down.example",
        true,
        wall_clock() + Duration::from_secs(1),
    );
    let episodes = f
        .engine
        .discovery
        .lock()
        .unwrap()
        .snapshot(SID, unix_ms(wall_clock()) + 1000, 128)
        .0;
    assert_eq!(
        episodes[0].history.back().unwrap().decision.reason,
        "offer-ready"
    );
}

#[test]
fn successful_answers_update_the_episode_before_another_client_reads() {
    for accept in [false, true] {
        let f = fixture(AutoRulesMode::Suggest);
        let dto = parked_offer(&f.engine, wall_clock());
        let ids = vec![dto.id];
        f.engine
            .record_discovery_feedback(SID, &ids, "delivered", "shown", wall_clock());
        if accept {
            assert_eq!(
                f.engine
                    .accept(SID, &ids, false, wall_clock())
                    .unwrap()
                    .applied,
                1
            );
        } else {
            assert_eq!(f.engine.dismiss(SID, &ids, wall_clock()).applied, 1);
        }
        let episodes = f
            .engine
            .discovery
            .lock()
            .unwrap()
            .snapshot(SID, unix_ms(wall_clock()), 128)
            .0;
        assert_eq!(
            episodes[0].history.back().unwrap().decision.reason,
            if accept {
                "already-covered"
            } else {
                "user-dismissed"
            }
        );
        assert!(!f
            .engine
            .publish_state
            .lock()
            .unwrap()
            .get(SID)
            .is_some_and(|state| state.delivered.contains(&ids[0])));
    }
}

#[test]
fn forgetting_an_offer_removes_its_private_episode_and_delivery_marker() {
    let f = fixture(AutoRulesMode::Suggest);
    let dto = parked_offer(&f.engine, wall_clock());
    f.engine.record_discovery_feedback(
        SID,
        std::slice::from_ref(&dto.id),
        "delivered",
        "shown",
        wall_clock(),
    );
    f.engine
        .forget_candidates(SID, std::slice::from_ref(&dto.id), wall_clock());
    assert!(f
        .engine
        .discovery
        .lock()
        .unwrap()
        .snapshot(SID, unix_ms(wall_clock()), 128)
        .0
        .is_empty());
    assert!(!f
        .engine
        .publish_state
        .lock()
        .unwrap()
        .get(SID)
        .is_some_and(|state| state.delivered.contains(&dto.id)));
}

#[test]
fn a_new_covering_rule_retires_the_episode_without_a_list_read() {
    let f = fixture(AutoRulesMode::Suggest);
    parked_offer(&f.engine, wall_clock());
    f.rules.also_route_primary(&["down.example"]);
    let rules = f.rules.active_rules_for(SID).unwrap();
    f.engine.retire_covered(SID, &rules, unix_ms(wall_clock()));
    let episodes = f
        .engine
        .discovery
        .lock()
        .unwrap()
        .snapshot(SID, unix_ms(wall_clock()), 128)
        .0;
    assert_eq!(
        episodes[0].history.back().unwrap().decision.reason,
        "already-covered"
    );
}

#[test]
fn a_late_secondary_result_cannot_create_an_episode_for_a_removed_offer() {
    let f = fixture(AutoRulesMode::Suggest);
    f.engine
        .note_secondary_reach(SID, "missing.example", false, wall_clock());
    assert!(f
        .engine
        .discovery_snapshot(SID, wall_clock())
        .episodes
        .is_empty());
}

#[test]
fn a_publisher_cannot_erase_shown_while_the_acknowledgement_is_being_logged() {
    use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
    use tracing::{
        field::{Field, Visit},
        Event, Subscriber,
    };
    use tracing_subscriber::{layer::Context, prelude::*, Layer};

    struct State(bool);
    impl Visit for State {
        fn record_debug(&mut self, _: &Field, _: &dyn std::fmt::Debug) {}
        fn record_str(&mut self, field: &Field, value: &str) {
            if field.name() == "state" && value == "delivered" {
                self.0 = true;
            }
        }
    }
    struct PauseShown {
        reached: SyncSender<()>,
        resume: Mutex<Receiver<()>>,
    }
    impl<S: Subscriber> Layer<S> for PauseShown {
        fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
            let mut state = State(false);
            event.record(&mut state);
            if event.metadata().target() == "nrr::discovery" && state.0 {
                self.reached.send(()).unwrap();
                self.resume
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
            }
        }
    }
    let f = fixture(AutoRulesMode::Suggest);
    let dto = parked_offer(&f.engine, wall_clock());
    let engine = Arc::new(f.engine);
    let (reached, wait) = sync_channel(0);
    let (resume, resumed) = sync_channel(0);
    let subscriber = tracing_subscriber::registry().with(PauseShown {
        reached,
        resume: Mutex::new(resumed),
    });
    let ack_engine = Arc::clone(&engine);
    let ack_id = dto.id.clone();
    let ack = std::thread::spawn(move || {
        tracing::subscriber::with_default(subscriber, || {
            ack_engine.record_discovery_feedback(
                SID,
                &[ack_id],
                "delivered",
                "shown",
                wall_clock(),
            );
        })
    });
    wait.recv_timeout(Duration::from_secs(5)).unwrap();
    engine.record_candidate_discovery(
        SID,
        &dto,
        DiscoveryDecision::new("notice", "deferred", "awaiting-client"),
        wall_clock(),
    );
    resume.send(()).unwrap();
    ack.join().unwrap();
    let episodes = engine
        .discovery
        .lock()
        .unwrap()
        .snapshot(SID, unix_ms(wall_clock()), 128)
        .0;
    assert_eq!(episodes[0].history.back().unwrap().decision.reason, "shown");
}
