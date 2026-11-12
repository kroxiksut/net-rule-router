use nrr_shared::ipc_payloads::DiscoveryEpisodeDto;
use serde_json::{json, Value};

fn episode(queue: Value) -> Value {
    json!({
        "id": "discovery-private", "host": "site.example", "destination": null,
        "state": "deferred", "reason": "probe-queued", "stage": "probe",
        "first-seen-unix-ms": 1000, "last-seen-unix-ms": 2000,
        "candidate-id": null, "platform-limitation": null,
        "history": [{"stage":"probe", "state":"not-created",
            "reason":"primary-responds", "at-unix-ms":1500}],
        "probe-queue": queue
    })
}

#[test]
fn a_waiting_episode_preserves_why_it_waits_without_erasing_its_previous_result() {
    for kind in [
        "rate",
        "workers",
        "cooldown",
        "ahead",
        "scheduled",
        "resources",
        "rules",
    ] {
        let queue = json!({"wait-kind":kind, "queued-ahead":3,
            "eligible-in-ms":1875, "last-probe-started-unix-ms":1250});
        let parsed: DiscoveryEpisodeDto = serde_json::from_value(episode(queue.clone()))
            .unwrap_or_else(|error| panic!("episode: {error}"));
        let wire = serde_json::to_value(parsed).unwrap_or_else(|error| panic!("wire: {error}"));
        assert_eq!(wire["probe-queue"], queue, "lost the reason for waiting");
        assert_eq!(wire["history"][0]["reason"], "primary-responds");
        assert_eq!(wire["history"][0]["at-unix-ms"], 1500);
    }
}

#[test]
fn an_old_service_episode_does_not_invent_a_queue_position_or_start_time() {
    let mut old = episode(Value::Null);
    old.as_object_mut()
        .unwrap_or_else(|| panic!("object"))
        .remove("probe-queue");
    let parsed: DiscoveryEpisodeDto =
        serde_json::from_value(old).unwrap_or_else(|error| panic!("old episode: {error}"));
    let wire = serde_json::to_value(parsed).unwrap_or_else(|error| panic!("wire: {error}"));
    assert!(wire.get("probe-queue").is_none());
}
