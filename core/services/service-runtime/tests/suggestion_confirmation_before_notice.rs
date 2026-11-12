use std::sync::Arc;
use std::time::SystemTime;

use nrr_domain::companion_affinity::PrimaryBehavior;
use nrr_service_runtime::auto_rules::{
    AutoRulesEngine, InMemoryDismissalStore, InMemoryPendingStore,
};
use nrr_service_runtime::ipc_handlers::event_bus::EventBus;
use nrr_service_runtime::navigation_registry::HostCounts;
use nrr_service_runtime::per_sid_orchestrator::{ActiveRulesSnapshot, RulesProvider};

struct EmptyRules;
impl RulesProvider for EmptyRules {
    fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
        Some(ActiveRulesSnapshot::default())
    }
}

#[test]
fn an_application_offer_does_not_wait_for_an_impossible_hostname_probe() {
    let bus = Arc::new(EventBus::new());
    let subscription = bus.subscribe_as("tray".into(), Some("S-owner".into()), None);
    let engine = AutoRulesEngine::new(
        Arc::new(EmptyRules),
        Arc::new(|_| nrr_storage::auto_rules::AutoRulesMode::Suggest),
        Arc::new(InMemoryDismissalStore::new()),
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::now(),
    )
    .with_event_bus(Arc::clone(&bus))
    .with_main_link_pass_enabled(Arc::new(|_| true));
    assert!(engine.note_app_main_link_blocked(
        "S-owner",
        "client.exe",
        &["203.0.113.1".parse().expect("ip")],
        SystemTime::now()
    ));
    let notices = bus
        .peek_pending_for(&subscription.subscription_id, 100)
        .into_iter()
        .filter(|entry| {
            matches!(
                entry.event,
                nrr_shared::ipc_payloads::StatusUpdateEvent::AutoRuleCandidatesChanged {
                    announces: true,
                    ..
                }
            )
        })
        .count();
    assert_eq!(
        notices, 1,
        "an application is identified by its process, not a hostname to probe"
    );
}

#[test]
fn an_automatic_notice_waits_for_the_alternative_check_instead_of_flashing_an_unverified_failure() {
    let bus = Arc::new(EventBus::new());
    let subscription = bus.subscribe_as("tray".into(), Some("S-owner".into()), None);
    let engine = AutoRulesEngine::new(
        Arc::new(EmptyRules),
        Arc::new(|_| nrr_storage::auto_rules::AutoRulesMode::Suggest),
        Arc::new(InMemoryDismissalStore::new()),
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::now(),
    )
    .with_event_bus(Arc::clone(&bus))
    .with_primary_behavior_source(Arc::new(|_, _| PrimaryBehavior::Stalls))
    .with_main_link_pass_enabled(Arc::new(|_| true));
    assert!(engine.note_main_link_blocked_host(
        "S-owner",
        "site.example",
        HostCounts::default(),
        SystemTime::now()
    ));
    let notices = bus
        .peek_pending_for(&subscription.subscription_id, 100)
        .into_iter()
        .filter(|entry| {
            matches!(
                entry.event,
                nrr_shared::ipc_payloads::StatusUpdateEvent::AutoRuleCandidatesChanged {
                    announces: true,
                    ..
                }
            )
        })
        .count();
    assert_eq!(notices, 0, "while automatic confirmation is pending a transient stall must not raise a card; badge updates remain allowed");
    assert_eq!(
        engine.candidates("S-owner").len(),
        1,
        "the evidence stays available for checking"
    );
    let confirmed_at = SystemTime::now() + std::time::Duration::from_secs(30);
    engine.note_secondary_reach("S-owner", "site.example", true, confirmed_at);
    engine.tick("S-owner", confirmed_at);
    let notices = bus
        .peek_pending_for(&subscription.subscription_id, 100)
        .into_iter()
        .filter(|entry| {
            matches!(
                entry.event,
                nrr_shared::ipc_payloads::StatusUpdateEvent::AutoRuleCandidatesChanged {
                    announces: true,
                    ..
                }
            )
        })
        .count();
    assert_eq!(
        notices, 1,
        "confirmation releases the held card without another browser attempt"
    );
}
