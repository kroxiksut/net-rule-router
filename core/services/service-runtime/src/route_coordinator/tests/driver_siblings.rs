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

/// The VPN vendor's own adapter, on a driver of its own.
fn vendor(seed: &str, idx: u32, up: bool) -> nrr_platform_api::AdapterInfo {
    let mut info = if up {
        adapter(seed, idx, true, true, Some([10, 91, 0, 1]))
    } else {
        adapter(seed, idx, false, false, None)
    };
    info.friendly_name = "Example VPN OpenVPN Adapter".into();
    info.description = "Example VPN 3.0 OpenVPN Adapter".into();
    info
}

/// Status and candidates of each notice about the additional route; a move
/// of the route reads as `additional-connection-moved` with the new name.
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
            StatusUpdateEvent::AdditionalConnectionMoved { adapter_name, .. } => Some((
                "additional-connection-moved".to_string(),
                vec![adapter_name.clone()],
            )),
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
fn a_vpn_that_came_up_on_another_copy_of_the_bound_tap_is_followed_there() {
    let (notices, healed, routed) = secondary_notices(
        vec![tap("tap3", 3, false, 3), nic(), tap("tap5", 5, true, 5)],
        bound_to_tap3,
    );
    assert!(routed, "the rules go through the copy the VPN brought up");
    assert_eq!(
        healed,
        vec!["secondary|win-adapter:tap5".to_string()],
        "the move is saved once, so the next start binds the live copy",
    );
    assert!(
        notices
            .iter()
            .all(|(status, _)| status != "adapter-choice-needed" && status != "secondary-down"),
        "nothing is left for the user to fix: {notices:?}",
    );
}

/// Forty idle copies of one driver, the VPN up on one of them: the same answer
/// however many dead copies surround the live one.
#[test]
fn a_bound_copy_among_many_dead_ones_follows_the_one_the_vpn_uses() {
    let mut infos: Vec<_> = (2..=40)
        .map(|n| tap(&format!("tap{n}"), n, false, n))
        .collect();
    infos[20] = tap("tap22", 22, true, 22);
    infos.push(nic());
    let (_, healed, routed) = secondary_notices(infos, bound_to_tap3);
    assert!(routed);
    assert_eq!(healed, vec!["secondary|win-adapter:tap22".to_string()]);
}

/// Two live copies: which of them is the user's is not ours to guess, so the
/// user is asked between the two by name.
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
    let asked = (
        "adapter-choice-needed".to_string(),
        vec!["Ethernet 5".to_string(), "Ethernet 7".to_string()],
    );
    assert!(notices.contains(&asked), "{notices:?}");
    assert!(
        notices
            .iter()
            .all(|(status, _)| status != "additional-connection-moved"),
        "{notices:?}"
    );
    assert!(!routed);
    assert!(healed.is_empty());
}

/// The field machine: forty dead copies of the stock driver, the route bound
/// to one of them, and the VPN up on its vendor's own adapter — another
/// driver. The additional connection follows the VPN there, the move is
/// saved, and the user is told where it went.
#[test]
fn a_vpn_that_came_up_on_its_own_adapter_is_followed_from_a_dead_tap() {
    let mut infos: Vec<_> = (2..=40)
        .map(|n| tap(&format!("tap{n}"), n, false, n))
        .collect();
    infos.push(nic());
    infos.push(vendor("vendor", 52, true));
    let (notices, healed, routed) = secondary_notices(infos, bound_to_tap3);
    assert!(
        routed,
        "the rules go through the adapter the VPN came up on"
    );
    assert_eq!(healed, vec!["secondary|win-adapter:vendor".to_string()]);
    let moved = (
        "additional-connection-moved".to_string(),
        vec!["Example VPN OpenVPN Adapter".to_string()],
    );
    assert!(notices.contains(&moved), "{notices:?}");
    assert!(
        notices
            .iter()
            .all(|(status, _)| status != "adapter-choice-needed" && status != "secondary-down"),
        "nothing is left for the user to fix: {notices:?}",
    );
}

/// The bound adapter is not merely down but gone from the machine, and the
/// VPN is up on another: the route follows it rather than wait out the grace
/// for a replacement nobody can name.
#[test]
fn a_vpn_up_elsewhere_is_followed_from_a_binding_that_is_gone() {
    let (notices, healed, routed) =
        secondary_notices(vec![nic(), vendor("vendor", 52, true)], |policy| {
            policy.bind_secondary_named("S-TAP", "win-adapter:{gone}", "Ethernet 3");
        });
    assert!(routed);
    assert_eq!(healed, vec!["secondary|win-adapter:vendor".to_string()]);
    assert!(
        notices
            .iter()
            .any(|(status, _)| status == "additional-connection-moved"),
        "{notices:?}"
    );
}

#[test]
fn two_live_tunnels_are_not_guessed_between() {
    let mut wg = adapter("wg", 9, true, true, Some([10, 9, 0, 1]));
    wg.friendly_name = "wg-home".into();
    wg.description = "WireGuard Tunnel".into();
    let (notices, healed, routed) = secondary_notices(
        vec![
            tap("tap3", 3, false, 3),
            nic(),
            wg,
            vendor("vendor", 52, true),
        ],
        bound_to_tap3,
    );
    assert_eq!(
        notices,
        vec![(
            "adapter-choice-needed".to_string(),
            vec![
                "wg-home".to_string(),
                "Example VPN OpenVPN Adapter".to_string()
            ]
        )],
    );
    assert!(!routed);
    assert!(healed.is_empty());
}

/// An employer's tunnel is up beside the user's VPN that is off: the route
/// is not moved onto it, the VPN being off is all that is said.
#[test]
fn a_corporate_tunnel_is_never_taken_for_the_additional_connection() {
    let mut corporate = adapter("corp", 9, true, true, Some([10, 9, 0, 1]));
    corporate.friendly_name = "Ethernet 9".into();
    corporate.description = "FortiClient SSL VPN Virtual Ethernet Adapter".into();
    let (notices, healed, routed) = secondary_notices(
        vec![tap("tap3", 3, false, 3), nic(), corporate],
        bound_to_tap3,
    );
    assert_eq!(notices, vec![("secondary-down".to_string(), Vec::new())]);
    assert!(!routed);
    assert!(
        healed.iter().all(|h| !h.starts_with("secondary|")),
        "{healed:?}"
    );
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

/// A user whose main connection is itself a tunnel-named link: the dead
/// additional binding never moves onto their uplink, whatever it is called.
#[test]
fn the_main_link_is_never_taken_for_the_additional_connection() {
    let mut uplink = adapter("pppoe", 7, true, true, Some([203, 0, 113, 1]));
    uplink.friendly_name = "Provider VPN".into();
    uplink.description = "WAN Miniport (PPPOE)".into();
    let (notices, healed, routed) =
        secondary_notices(vec![tap("tap3", 3, false, 3), uplink], |policy| {
            bound_to_tap3(policy);
            policy.bind_primary("S-TAP", "win-adapter:pppoe");
        });
    assert_eq!(notices, vec![("secondary-down".to_string(), Vec::new())]);
    assert!(!routed);
    // The main binding may learn its connection name; the additional one stays.
    assert!(
        healed.iter().all(|h| !h.starts_with("secondary|")),
        "{healed:?}"
    );
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
    // A plain network card, so only the name could tie it to the binding.
    let mut other = adapter("{other}", 25, true, true, Some([10, 0, 0, 25]));
    other.friendly_name = "Подключение по локальной сети 25".into();
    other.description = "Example PCIe GbE Controller #2".into();
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
