use super::*;

/// Build a usable adapter whose connection name and driver description differ,
/// which is the case the offer ordering turns on.
fn named_adapter(friendly: &str, description: &str) -> nrr_platform_api::AdapterInfo {
    let mut info = adapter(friendly, 7, true, true, Some([10, 0, 0, 1]));
    info.friendly_name = friendly.to_string();
    info.description = description.to_string();
    info
}

/// When the bound tunnel is gone, what we offer instead is read as advice.
///
/// Every usable connection is still offered — we cannot know which one replaced
/// it, and guessing is what the ambiguous branch refuses to do — but for the
/// ADDITIONAL route the tunnel-looking ones go first. Ethernet and a VPN are not
/// equals there: one is what the rules were pointing at, the other is the link
/// those rules exist to route around, and a list that opens with the wrong one
/// invites the user to bind their main link as their tunnel.
#[test]
fn a_replacement_for_the_additional_route_leads_with_the_tunnels() {
    let infos = vec![
        named_adapter("Ethernet", "Intel(R) Ethernet Connection"),
        named_adapter("my-tunnel", "WireGuard Tunnel"),
    ];
    let offered = replacement_candidates(&infos, "secondary");
    assert_eq!(
        offered.len(),
        2,
        "nothing is removed — an unrecognised tunnel must still be offered",
    );
    assert_eq!(
        offered[0], "my-tunnel",
        "the connection that reads as a tunnel leads the offer",
    );
    assert_eq!(
        offered.last().map(String::as_str),
        Some("Ethernet"),
        "the main link is offered last, not first",
    );

    // The primary role has no such asymmetry: every usable connection is an
    // equally plausible main link, so the order is left as the OS gave it.
    let primary = replacement_candidates(&infos, "primary");
    assert_eq!(primary[0], "Ethernet", "the primary offer keeps OS order");
}

#[test]
fn a_tunnel_adapter_whose_mac_follows_its_guid_gets_no_anchor() {
    // Taken from a live run: TAP-Windows reported MAC 00:FF:AA:BB:CC:DD under
    // GUID {AABBCCDD-1111-2222-3333-444444444444}. The two rotate together on
    // every reconnect, so the MAC is not an identity of its own.
    let mut tap = adapter(
        "{AABBCCDD-1111-2222-3333-444444444444}",
        14,
        true,
        true,
        None,
    );
    tap.mac = Some([0x00, 0xFF, 0xAA, 0xBB, 0xCC, 0xDD]);
    tap.description = "TAP-Windows Adapter V9".into();
    assert_eq!(mac_anchor_id(&tap), None);
}

#[test]
fn a_physical_adapter_anchors_on_its_mac_and_is_found_by_it_after_a_guid_change() {
    let mut nic = adapter(
        "{282A0045-3DE1-4BFE-8296-B000D7F933ED}",
        18,
        true,
        true,
        None,
    );
    nic.mac = Some([0x00, 0x11, 0x22, 0x33, 0x44, 0xAA]);
    nic.description = "Realtek(R) PCI(e) Ethernet Controller".into();
    let anchor = mac_anchor_id(&nic).expect("a burned-in MAC is an anchor");
    assert_eq!(anchor, "win-mac:00-11-22-33-44-AA");

    // Same card, new GUID and new ifindex (came back on another port): the
    // anchor still names it, which is the whole point.
    let mut moved = adapter(
        "{99999999-0000-0000-0000-000000000000}",
        41,
        true,
        true,
        None,
    );
    moved.mac = nic.mac;
    assert!(adapter_binding_matches(&moved, &anchor));
    // A different card must not answer to it.
    let mut other = adapter(
        "{88888888-0000-0000-0000-000000000000}",
        42,
        true,
        true,
        None,
    );
    other.mac = Some([0x00, 0x11, 0x22, 0x33, 0x44, 0xAB]);
    assert!(!adapter_binding_matches(&other, &anchor));
}

#[test]
fn a_virtual_software_adapter_gets_no_anchor() {
    let mut vswitch = adapter(
        "{11111111-0000-0000-0000-000000000000}",
        20,
        true,
        true,
        None,
    );
    vswitch.mac = Some([0x00, 0x15, 0x5D, 0x01, 0x02, 0x03]);
    vswitch.description = "Hyper-V Virtual Ethernet Adapter".into();
    assert_eq!(mac_anchor_id(&vswitch), None);
}

#[test]
fn the_mac_anchor_is_persisted_once_per_binding() {
    let api = Arc::new(MockWindowsApi::new());
    let mut nic = adapter("boundnic", 7, true, true, Some([10, 0, 0, 1]));
    nic.mac = Some([0x00, 0x11, 0x22, 0x33, 0x44, 0xAA]);
    api.set_adapter_infos(vec![nic]);

    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary_named("S-ANCHOR", "win-adapter:boundnic", "desc boundnic");

    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let cap = Arc::clone(&captured);
    let coord = coordinator_with_policy(
        Arc::clone(&api),
        Arc::new(FakeRules::new()),
        Arc::clone(&policy),
    )
    .with_binding_anchor_persist(Arc::new(move |sid, role, anchor| {
        cap.lock().unwrap().push(format!("{sid}|{role}|{anchor}"));
    }));

    let _ = coord.resolve("S-ANCHOR");
    let _ = coord.resolve("S-ANCHOR");
    let c = captured.lock().unwrap();
    assert_eq!(
        *c,
        vec!["S-ANCHOR|secondary|win-mac:00-11-22-33-44-AA".to_string()],
        "the anchor is learned on resolve and written once, not every reconcile"
    );
}

#[test]
fn two_live_adapters_answering_to_the_saved_name_ask_the_user_instead_of_guessing() {
    use crate::ipc_handlers::event_bus::EventBus;
    use nrr_shared::ipc_payloads::StatusUpdateEvent;

    let api = Arc::new(MockWindowsApi::new());
    // Two usable adapters of the same family — the bound GUID is gone.
    let mut a = adapter("tap-a", 21, true, true, Some([10, 0, 0, 1]));
    a.description = "acme vpn adapter".into();
    a.friendly_name = "acme vpn adapter".into();
    let mut b = adapter("tap-b", 22, true, true, Some([10, 0, 0, 2]));
    b.description = "acme vpn adapter".into();
    b.friendly_name = "acme vpn adapter".into();
    api.set_adapter_infos(vec![a, b]);

    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary_named("S-AMBIG", "win-adapter:{gone}", "acme vpn adapter");

    let bus = Arc::new(EventBus::new());
    // The notice names this SID, so it is delivered to that principal;
    // an unnamed subscriber is shown machine-wide events only.
    let sub = bus
        .subscribe_as("test".into(), Some("S-AMBIG".into()), None)
        .subscription_id;
    let coord = coordinator_with_policy(
        Arc::clone(&api),
        Arc::new(FakeRules::new()),
        Arc::clone(&policy),
    )
    .with_event_bus(Arc::clone(&bus));

    let r = coord.resolve("S-AMBIG");
    assert!(
        r.secondary.is_none(),
        "an ambiguous name must not be resolved by guessing"
    );
    // Re-resolving the same state must not re-publish.
    let _ = coord.resolve("S-AMBIG");

    let events = bus.peek_pending_for(&sub, 16);
    let published: Vec<_> = events
        .iter()
        .filter_map(|e| match &e.event {
            StatusUpdateEvent::EnforcementStatusChanged {
                status,
                role,
                candidates,
                ..
            } => Some((status.clone(), role.clone(), candidates.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(
        published,
        vec![(
            "adapter-choice-needed".to_string(),
            "secondary".to_string(),
            vec![
                "acme vpn adapter".to_string(),
                "acme vpn adapter".to_string()
            ]
        )],
        "the choice is announced once, with the adapters to choose from"
    );
}

/// The vendor replaced its adapter outright: the bound GUID is gone and NO
/// live name answers for it. The field case is swiftvpn switching from its
/// OpenVPN adapter to a WireGuard tunnel — a different device with a different
/// name, while the old one stayed behind as a driver that will not start.
///
/// Before this the branch only wrote a log line, so the product went quiet at
/// the exact moment it stopped routing. The cause cannot be known from here,
/// but the answer is the same for every cause: hand the choice back.
#[test]
fn a_bound_adapter_that_no_longer_exists_asks_the_user_instead_of_going_quiet() {
    use crate::ipc_handlers::event_bus::EventBus;
    use nrr_shared::ipc_payloads::StatusUpdateEvent;

    let api = Arc::new(MockWindowsApi::new());
    // What is left after the swap: the machine NIC and the new tunnel. Neither
    // shares a name with the binding.
    let mut nic = adapter("nic", 19, true, true, Some([192, 168, 0, 2]));
    nic.description = "Realtek Gaming GbE".into();
    nic.friendly_name = "Ethernet".into();
    // The hard case: the replacement carries NOTHING of the vendor's name,
    // so no amount of token matching can tie it to the binding. A vendor
    // that keeps its brand (`acme_VPN`) is healed automatically instead —
    // see the control test below.
    let mut tun = adapter("wg", 64, true, true, Some([10, 88, 0, 191]));
    tun.description = "WireGuard Tunnel".into();
    tun.friendly_name = "Tunnel 1".into();
    api.set_adapter_infos(vec![nic, tun]);

    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary_named(
        "S-GONE",
        "win-adapter:{aaaaaaaa-0000-0000-0000-000000000000}",
        "acme VPN 3.0 OpenVPN Adapter",
    );

    let bus = Arc::new(EventBus::new());
    let sub = bus
        .subscribe_as("test".into(), Some("S-GONE".into()), None)
        .subscription_id;
    let coord = coordinator_with_policy(
        Arc::clone(&api),
        Arc::new(FakeRules::new()),
        Arc::clone(&policy),
    )
    .with_event_bus(Arc::clone(&bus));

    let r = coord.resolve("S-GONE");
    assert!(r.secondary.is_none(), "nothing to route through");
    // The steady state stays quiet: the same missing adapter must not
    // re-announce itself on every reconcile.
    let _ = coord.resolve("S-GONE");

    let published: Vec<_> = bus
        .peek_pending_for(&sub, 16)
        .iter()
        .filter_map(|e| match &e.event {
            StatusUpdateEvent::EnforcementStatusChanged {
                status,
                role,
                candidates,
                ..
            } => Some((status.clone(), role.clone(), candidates.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(
        published,
        vec![(
            "adapter-gone".to_string(),
            "secondary".to_string(),
            vec!["Tunnel 1".to_string(), "Ethernet".to_string()]
        )],
        "said once, every usable adapter is offered to choose from, and the \
         tunnel-looking one leads: for the ADDITIONAL route the main link is a \
         replacement the user should have to look past, not the first offered",
    );
}

/// The same missing adapter, told two ways. A device that is merely broken is
/// still on the machine, and the user's next step is to repair it rather than
/// to choose a replacement — so the two must not share a sentence.
#[test]
fn a_bound_adapter_whose_driver_will_not_start_is_reported_as_broken_not_gone() {
    use crate::ipc_handlers::event_bus::EventBus;
    use nrr_platform_api::device_status::{DeviceState, NetworkDeviceStatusPort};
    use nrr_shared::ipc_payloads::StatusUpdateEvent;

    struct Fixed(Option<DeviceState>);
    impl NetworkDeviceStatusPort for Fixed {
        fn device_state(&self, _adapter_guid: &str) -> Option<DeviceState> {
            self.0
        }
    }

    // Same world for every run: the bound adapter is absent from the
    // enumeration and nothing answers to its name.
    let statuses = |port: Option<Arc<dyn NetworkDeviceStatusPort>>| -> Vec<String> {
        let api = Arc::new(MockWindowsApi::new());
        let mut nic = adapter("nic", 19, true, true, Some([192, 168, 0, 2]));
        nic.description = "Realtek Gaming GbE".into();
        nic.friendly_name = "Ethernet".into();
        api.set_adapter_infos(vec![nic]);
        let policy = Arc::new(FakePolicy::new());
        policy.bind_secondary_named(
            "S-BROKEN",
            "win-adapter:{aaaaaaaa-0000-0000-0000-000000000000}",
            "acme VPN 3.0 OpenVPN Adapter",
        );
        let bus = Arc::new(EventBus::new());
        let sub = bus
            .subscribe_as("test".into(), Some("S-BROKEN".into()), None)
            .subscription_id;
        let mut coord = coordinator_with_policy(
            Arc::clone(&api),
            Arc::new(FakeRules::new()),
            Arc::clone(&policy),
        )
        .with_event_bus(Arc::clone(&bus));
        if let Some(port) = port {
            coord = coord.with_device_status(port);
        }
        let _ = coord.resolve("S-BROKEN");
        bus.peek_pending_for(&sub, 16)
            .iter()
            .filter_map(|e| match &e.event {
                StatusUpdateEvent::EnforcementStatusChanged { status, role, .. }
                    if role == "secondary" =>
                {
                    Some(status.clone())
                }
                _ => None,
            })
            .collect()
    };

    assert_eq!(
        statuses(Some(Arc::new(Fixed(Some(DeviceState::FailedToStart))))),
        vec!["adapter-failed".to_string()],
    );
    assert_eq!(
        statuses(Some(Arc::new(Fixed(Some(DeviceState::Disabled))))),
        vec!["adapter-failed".to_string()],
        "switched off is also present-but-unusable",
    );
    assert_eq!(
        statuses(Some(Arc::new(Fixed(Some(DeviceState::Absent))))),
        vec!["adapter-gone".to_string()],
    );
    // A platform with no mechanism, and a build with none wired, must keep the
    // wording they had rather than inventing an answer.
    assert_eq!(
        statuses(Some(Arc::new(Fixed(None)))),
        vec!["adapter-gone".to_string()],
    );
    assert_eq!(statuses(None), vec!["adapter-gone".to_string()]);
}

/// Control for the test above, and the field case as it actually stands: the
/// vendor kept its brand in the connection name when it swapped transport, so
/// the binding heals itself and the user is asked nothing. This is what makes
/// the "gone" branch above a genuine last resort rather than the normal path.
#[test]
fn a_vendor_that_keeps_its_brand_across_a_transport_change_heals_without_asking() {
    use crate::ipc_handlers::event_bus::EventBus;
    use nrr_shared::ipc_payloads::StatusUpdateEvent;

    let api = Arc::new(MockWindowsApi::new());
    let mut nic = adapter("nic", 19, true, true, Some([192, 168, 0, 2]));
    nic.description = "Realtek Gaming GbE".into();
    nic.friendly_name = "Ethernet".into();
    // OpenVPN adapter replaced by a WireGuard tunnel; only the brand survived.
    let mut tun = adapter("wg", 64, true, true, Some([10, 88, 0, 191]));
    tun.description = "WireGuard Tunnel".into();
    tun.friendly_name = "acme.name_VPN".into();
    api.set_adapter_infos(vec![nic, tun]);

    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary_named(
        "S-BRAND",
        "win-adapter:{aaaaaaaa-0000-0000-0000-000000000000}",
        "acme.name VPN 3.0 OpenVPN Adapter",
    );

    let bus = Arc::new(EventBus::new());
    let sub = bus
        .subscribe_as("test".into(), Some("S-BRAND".into()), None)
        .subscription_id;
    let coord = coordinator_with_policy(
        Arc::clone(&api),
        Arc::new(FakeRules::new()),
        Arc::clone(&policy),
    )
    .with_event_bus(Arc::clone(&bus));

    assert!(
        coord.resolve("S-BRAND").secondary.is_some(),
        "the tunnel that kept the brand is adopted",
    );
    // Only the role under test: the fixture binds no primary, and that
    // notice is a separate, correct statement about a different role.
    let statuses: Vec<String> = bus
        .peek_pending_for(&sub, 16)
        .iter()
        .filter_map(|e| match &e.event {
            StatusUpdateEvent::EnforcementStatusChanged { status, role, .. }
                if role == "secondary" =>
            {
                Some(status.clone())
            }
            _ => None,
        })
        .collect();
    assert_eq!(statuses, vec!["ok".to_string()], "nothing to ask about");
}

#[test]
fn a_binding_that_resolves_clears_the_standing_enforcement_notice() {
    use crate::ipc_handlers::event_bus::EventBus;
    use nrr_shared::ipc_payloads::StatusUpdateEvent;

    let api = Arc::new(MockWindowsApi::new());
    api.set_adapter_infos(vec![adapter("nic", 30, true, true, Some([10, 0, 0, 1]))]);
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary_named("S-OK", "win-adapter:nic", "desc nic");

    let bus = Arc::new(EventBus::new());
    // The notice names this SID, so it is delivered to that principal;
    // an unnamed subscriber is shown machine-wide events only.
    let sub = bus
        .subscribe_as("test".into(), Some("S-OK".into()), None)
        .subscription_id;
    let coord = coordinator_with_policy(
        Arc::clone(&api),
        Arc::new(FakeRules::new()),
        Arc::clone(&policy),
    )
    .with_event_bus(Arc::clone(&bus));

    let _ = coord.resolve("S-OK");
    let _ = coord.resolve("S-OK");
    let statuses: Vec<(String, String)> = bus
        .peek_pending_for(&sub, 16)
        .iter()
        .filter_map(|e| match &e.event {
            StatusUpdateEvent::EnforcementStatusChanged { status, role, .. } => {
                Some((role.clone(), status.clone()))
            }
            _ => None,
        })
        .collect();
    // The secondary resolves; this fixture has no primary and no OS default
    // route to derive one, so the two roles report independently — and each
    // reports once, however many times the reconcile runs.
    assert_eq!(
        statuses,
        vec![
            ("secondary".to_string(), "ok".to_string()),
            ("primary".to_string(), "no-primary-route".to_string()),
        ],
        "published on change only, per role"
    );
}

#[test]
fn found_but_down_bound_adapter_heals_to_available_same_name_sibling() {
    // the bound GUID is still ENUMERATED but DOWN (a GUID-churning
    // VPN can leave a stale/down TAP instance visible while the freshly-connected
    // one carries traffic). The resolver must heal to the live same-name SIBLING
    // instead of failing closed on the down instance.
    let api = Arc::new(MockWindowsApi::new());
    // `down` = the bound (present-but-down) instance; `sibling` = a live
    // same-family adapter whose version token differs.
    let mut down = adapter("oldtap", 1, false, false, None);
    down.description = "swiftvpn vpn 3.0 adapter".into();
    down.friendly_name = down.description.clone();
    let mut sibling = adapter("newtap", 2, true, true, Some([10, 0, 0, 1]));
    sibling.description = "swiftvpn vpn adapter".into();
    sibling.friendly_name = sibling.description.clone();
    api.set_adapter_infos(vec![down, sibling]);

    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary_named("S-DOWN", "win-adapter:oldtap", "swiftvpn vpn 3.0 adapter");

    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let cap = Arc::clone(&captured);
    let coord = coordinator_with_policy(
        Arc::clone(&api),
        Arc::new(FakeRules::new()),
        Arc::clone(&policy),
    )
    .with_binding_heal_persist(Arc::new(move |sid, role, id, name| {
        cap.lock()
            .unwrap()
            .push(format!("{sid}|{role}|{id}|{name}"));
    }));

    let r = coord.resolve("S-DOWN");
    assert!(
        r.secondary.is_some(),
        "a present-but-down bound adapter must heal to the live same-name sibling, not fail closed"
    );
    let c = captured.lock().unwrap();
    assert_eq!(c.len(), 1, "the healed sibling id is persisted once");
    assert_eq!(
        c[0],
        "S-DOWN|secondary|win-adapter:newtap|swiftvpn vpn adapter"
    );
}

/// The GUI decides "adapter not found" with its own copy of the name matcher,
/// and a copy that lagged behind this one told a user their re-matched VPN was
/// gone. The token list is the part that drifts silently.
#[test]
#[allow(clippy::expect_used)]
fn the_gui_name_matcher_ignores_the_same_generic_words_as_the_service() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../apps/desktop/qml/lib/pure.js");
    let source = std::fs::read_to_string(&path).expect("pure.js is readable");
    let body = source
        .split("var ADAPTER_GENERIC_NAME_TOKENS = [")
        .nth(1)
        .and_then(|rest| rest.split(']').next())
        .expect("pure.js declares ADAPTER_GENERIC_NAME_TOKENS");
    let gui: Vec<&str> = body
        .split(',')
        .map(|t| t.trim().trim_matches('"'))
        .filter(|t| !t.is_empty())
        .collect();
    assert_eq!(gui, super::binding_resolver::GENERIC_NAME_TOKENS);
}
