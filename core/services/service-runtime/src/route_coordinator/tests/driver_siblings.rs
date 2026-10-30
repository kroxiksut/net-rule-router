//! A VPN client on a stock driver brings up whichever copy of it it likes; a
//! route bound to the copy left dead must not stay dead without a word, and
//! must not be moved behind the user's back either.

use super::*;
use crate::ipc_handlers::event_bus::EventBus;
use nrr_shared::ipc_payloads::StatusUpdateEvent;

fn tap(seed: &str, idx: u32, up: bool, number: u32) -> nrr_platform_api::AdapterInfo {
    let mut info = if up {
        adapter(seed, idx, true, true, Some([10, 8, 0, idx as u8]))
    } else {
        adapter(seed, idx, false, false, None)
    };
    info.friendly_name = format!("Ethernet {number}");
    info.description = format!("TAP-Windows Adapter V9 #{number}");
    info
}

fn nic() -> nrr_platform_api::AdapterInfo {
    let mut info = adapter("nic", 30, true, true, Some([192, 168, 0, 1]));
    info.friendly_name = "Ethernet".into();
    info.description = "Example PCIe GbE Controller".into();
    info
}

/// Status and candidates of each notice about the additional route.
type Notices = Vec<(String, Vec<String>)>;

/// What the additional route's notices said over two passes, every heal
/// written meanwhile, and whether the first pass routed.
fn secondary_notices(
    infos: Vec<nrr_platform_api::AdapterInfo>,
    bind: impl FnOnce(&FakePolicy),
) -> (Notices, Vec<String>, bool) {
    let api = Arc::new(MockWindowsApi::new());
    api.set_adapter_infos(infos);
    let policy = Arc::new(FakePolicy::new());
    bind(&policy);
    let bus = Arc::new(EventBus::new());
    let sub = bus
        .subscribe_as("test".into(), Some("S-TAP".into()), None)
        .subscription_id;
    let healed: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&healed);
    let coord = coordinator_with_policy(
        Arc::clone(&api),
        Arc::new(FakeRules::new()),
        Arc::clone(&policy),
    )
    .with_event_bus(Arc::clone(&bus))
    .with_gone_grace(std::time::Duration::ZERO)
    .with_binding_heal_persist(Arc::new(move |_, role, id, _| {
        seen.lock().unwrap().push(format!("{role}|{id}"));
    }));
    let routed = coord.resolve("S-TAP").secondary.is_some();
    let _ = coord.resolve("S-TAP");
    let notices = bus
        .peek_pending_for(&sub, 32)
        .iter()
        .filter_map(|e| match &e.event {
            StatusUpdateEvent::EnforcementStatusChanged {
                status,
                role,
                candidates,
                ..
            } if role == "secondary" => Some((status.clone(), candidates.clone())),
            _ => None,
        })
        .collect();
    let healed = healed.lock().unwrap().clone();
    (notices, healed, routed)
}

fn bound_to_tap3(policy: &FakePolicy) {
    policy.bind_secondary_named("S-TAP", "win-adapter:tap3", "Ethernet 3");
}

#[test]
fn a_dead_tap_with_one_live_copy_of_its_driver_asks_the_user_to_pick_that_copy() {
    let (notices, healed, routed) = secondary_notices(
        vec![tap("tap3", 3, false, 3), nic(), tap("tap5", 5, true, 5)],
        bound_to_tap3,
    );
    assert_eq!(
        notices,
        vec![(
            "adapter-choice-needed".to_string(),
            vec!["Ethernet 5".to_string()]
        )],
        "the user is told once, naming the copy the VPN brought up",
    );
    assert!(!routed, "nothing is routed through an adapter nobody chose");
    assert!(healed.is_empty(), "the binding is never moved silently");
}

#[test]
fn two_live_copies_of_the_driver_are_not_guessed_between() {
    let (notices, healed, routed) = secondary_notices(
        vec![
            tap("tap3", 3, false, 3),
            tap("tap5", 5, true, 5),
            tap("tap7", 7, true, 7),
        ],
        bound_to_tap3,
    );
    assert_eq!(
        notices,
        vec![("secondary-down".to_string(), Vec::new())],
        "with two candidates the service says only what it knows",
    );
    assert!(!routed);
    assert!(healed.is_empty());
}

#[test]
fn an_adapter_of_another_driver_is_never_proposed() {
    let mut other = adapter("wg", 9, true, true, Some([10, 9, 0, 1]));
    other.friendly_name = "Ethernet 9".into();
    other.description = "WireGuard Tunnel #9".into();
    let (notices, _, _) = secondary_notices(
        vec![
            tap("tap3", 3, false, 3),
            nic(),
            other,
            tap("tap4", 4, false, 4),
        ],
        bound_to_tap3,
    );
    assert_eq!(notices, vec![("secondary-down".to_string(), Vec::new())]);
}

#[test]
fn the_main_link_is_never_proposed_for_the_additional_route() {
    let (notices, _, _) = secondary_notices(
        vec![tap("tap3", 3, false, 3), tap("tap5", 5, true, 5)],
        |policy| {
            bound_to_tap3(policy);
            policy.bind_primary("S-TAP", "win-adapter:tap5");
        },
    );
    assert_eq!(notices, vec![("secondary-down".to_string(), Vec::new())]);
}

/// The bound copy is down and two live adapters answer to its saved name:
/// "choose" alone, not "choose" and "not up" taking turns on every pass.
#[test]
fn a_down_binding_with_two_namesakes_asks_once_and_stays_asked() {
    let mut down = adapter("old", 1, false, false, None);
    down.friendly_name = "acme vpn adapter".into();
    down.description = "acme vpn adapter".into();
    let mut a = adapter("tap-a", 21, true, true, Some([10, 0, 0, 1]));
    a.friendly_name = "acme vpn adapter".into();
    a.description = "acme vpn adapter".into();
    let mut b = adapter("tap-b", 22, true, true, Some([10, 0, 0, 2]));
    b.friendly_name = "acme vpn adapter".into();
    b.description = "acme vpn adapter".into();
    let (notices, healed, _) = secondary_notices(vec![down, a, b], |policy| {
        policy.bind_secondary_named("S-TAP", "win-adapter:old", "acme vpn adapter");
    });
    assert_eq!(
        notices,
        vec![(
            "adapter-choice-needed".to_string(),
            vec![
                "acme vpn adapter".to_string(),
                "acme vpn adapter".to_string()
            ]
        )],
    );
    assert!(healed.is_empty());
}

/// Windows names connections by itself, in the system language, with a number:
/// two of them share every word but the number, which says nothing about
/// whose they are.
#[test]
fn connection_names_windows_made_up_never_answer_to_each_other() {
    for (saved, live) in [
        (
            "Подключение по локальной сети 12",
            "Подключение по локальной сети 25",
        ),
        (
            "Подключение по локальной сети* 1",
            "Подключение по локальной сети* 2",
        ),
        ("Беспроводная сеть 2", "Беспроводная сеть 3"),
        (
            "Сетевое подключение Bluetooth",
            "Сетевое подключение Bluetooth 2",
        ),
        ("Local Area Connection* 1", "Local Area Connection* 2"),
        ("Wi-Fi", "Wi-Fi 2"),
    ] {
        assert!(
            !description_matches_display_name(live, saved),
            "{live:?} must not answer to {saved:?}",
        );
    }
    // A vendor word still matches, whatever the case of its letters.
    assert!(description_matches_display_name(
        "ПРИМЕРВПН 3.0 Адаптер",
        "ПримерВПН Адаптер"
    ));
}

#[test]
fn a_stale_binding_never_heals_to_another_numbered_local_connection() {
    let mut other = adapter("{other}", 25, true, true, Some([10, 0, 0, 25]));
    other.friendly_name = "Подключение по локальной сети 25".into();
    other.description = "Example VPN Miniport #2".into();
    let (notices, healed, routed) = secondary_notices(vec![other], |policy| {
        policy.bind_secondary_named(
            "S-TAP",
            "win-adapter:{gone}",
            "Подключение по локальной сети 12",
        );
    });
    assert!(healed.is_empty(), "no heal by words Windows made up");
    assert!(!routed);
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].0, "adapter-gone");
}

/// Whoever reads a field archive learns why the heal did nothing: how many
/// adapters answered to the saved name and how many were someone else's.
#[test]
fn the_down_binding_log_line_counts_namesakes_and_refusals() {
    use tracing_subscriber::layer::SubscriberExt;

    let api = Arc::new(MockWindowsApi::new());
    api.set_adapter_infos(vec![tap("tap3", 3, false, 3), nic()]);
    let policy = Arc::new(FakePolicy::new());
    bound_to_tap3(&policy);
    let coord = coordinator_with_policy(
        Arc::clone(&api),
        Arc::new(FakeRules::new()),
        Arc::clone(&policy),
    );
    let dir = tempfile::TempDir::new().expect("temp dir");
    let writer = Arc::new(nrr_diagnostics::LogWriter::open(
        nrr_diagnostics::LogWriterConfig::new(dir.path()),
    ));
    let subscriber =
        tracing_subscriber::registry().with(nrr_diagnostics::NdjsonTracingLayer::new(writer));
    tracing::subscriber::with_default(subscriber, || {
        let _ = coord.resolve("S-TAP");
    });
    let mut lines = Vec::new();
    for entry in std::fs::read_dir(dir.path()).expect("logs dir") {
        let text = std::fs::read_to_string(entry.expect("entry").path()).expect("read");
        lines.extend(
            text.lines()
                .filter(|l| l.contains("diag.event.route-binding-down-no-heal"))
                .map(str::to_owned),
        );
    }
    assert_eq!(lines.len(), 1, "{lines:?}");
    for field in ["name_matched", "refused_foreign"] {
        assert!(lines[0].contains(field), "{field} missing: {}", lines[0]);
    }
}
