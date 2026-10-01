use super::*;

/// An up, gateway-backed, non-tunnel adapter; tests bend it from here.
fn wired(name: &str) -> InterfaceRouteRow {
    InterfaceRouteRow {
        persistent_id: format!("preview-adapter:{}", name.to_ascii_lowercase()),
        adapter_name: format!("{{{name}}}"),
        name: name.to_string(),
        interface_description: format!("{name} adapter"),
        interface_type: "Ethernet".to_string(),
        is_bluetooth_like: false,
        local_ip: "192.0.2.10".to_string(),
        gateway: "192.0.2.1".to_string(),
        dns_servers: "192.0.2.53".to_string(),
        has_default_route: true,
        has_forwarding_path: Some(true),
        runtime_data_unavailable: false,
        availability_status: BasicAvailabilityStatus::Available,
        observed_facts: ObservedInterfaceFacts {
            connectivity_state: ConnectivityState::Available,
            external_ip_status: ExternalIpStatus::NotChecked,
            external_ip: None,
            external_probe_attempted: false,
            external_probe_note: String::new(),
        },
        derived_assessment: DerivedInterfaceAssessment {
            vpn_tunnel_likelihood: DerivedLikelihood::Unlikely,
            virtual_interface_likelihood: DerivedLikelihood::Unlikely,
            service_interface_likelihood: DerivedLikelihood::Unlikely,
            classification: "regular-interface".to_string(),
            confidence_percent: 0,
            heuristic_only: true,
            signals: Vec::new(),
        },
        recommendation: unknown_recommendation(),
        selected_role: None,
        route_state: RouteSelectionState::NotSelected,
    }
}

/// A tunnel that is up but not yet routing: the usual state while binding.
fn tunnel(name: &str) -> InterfaceRouteRow {
    let mut row = wired(name);
    row.interface_type = "Tunnel".to_string();
    row.local_ip = "198.51.100.7".to_string();
    row.gateway = "-".to_string();
    row.has_default_route = false;
    row.has_forwarding_path = Some(false);
    row.observed_facts.connectivity_state = ConnectivityState::Degraded;
    row.derived_assessment.vpn_tunnel_likelihood = DerivedLikelihood::Likely;
    row
}

fn find<'a>(rows: &'a [InterfaceRouteRow], name: &str) -> &'a InterfaceRouteRow {
    rows.iter()
        .find(|row| row.name == name)
        .unwrap_or_else(|| panic!("row '{name}' not found"))
}

fn has_signal(row: &InterfaceRouteRow, slug: &str) -> bool {
    row.recommendation.key_signals.iter().any(|s| s == slug)
}

#[test]
fn a_wired_link_and_a_tunnel_are_recommended_for_their_roles() {
    let mut rows = vec![wired("Wired"), tunnel("Tunnel")];
    assign_recommendations(&mut rows);

    assert_eq!(
        find(&rows, "Wired").recommendation.class,
        RecommendationClass::PreferredPrimary
    );
    assert_eq!(
        find(&rows, "Tunnel").recommendation.class,
        RecommendationClass::PreferredSecondary
    );
    assert!(rows.iter().all(|row| row.recommendation.advisory_only));
}

/// A Bluetooth link that out-scores everything must not take the maximum:
/// winning it and then being classed "not preferred" left no preferred
/// primary at all and pointed every other row at the Bluetooth adapter.
#[test]
fn a_bluetooth_link_never_takes_the_top_spot() {
    let mut wifi = wired("Wi-Fi");
    wifi.persistent_id.clear();
    wifi.gateway = "-".to_string();
    wifi.has_default_route = false;
    wifi.observed_facts.connectivity_state = ConnectivityState::Degraded;
    let mut bluetooth = wired("Bluetooth PAN");
    bluetooth.is_bluetooth_like = true;
    bluetooth.observed_facts.external_ip_status = ExternalIpStatus::Resolved;
    let mut rows = vec![wifi, bluetooth];

    assign_recommendations(&mut rows);

    let bluetooth = find(&rows, "Bluetooth PAN");
    assert_eq!(
        bluetooth.recommendation.class,
        RecommendationClass::AllowedButNotRecommended
    );
    assert!(has_signal(
        bluetooth,
        "bluetooth-adapter-nondefault-routing-profile"
    ));
    assert_eq!(
        find(&rows, "Wi-Fi").recommendation.class,
        RecommendationClass::PreferredPrimary
    );
    assert!(rows.iter().all(|row| !row
        .recommendation
        .excluded_alternatives
        .iter()
        .any(|alternative| alternative.ends_with("Bluetooth PAN"))));
}

/// A failed IP query leaves EVERY row at `"-"`; read as "no address" it
/// would declare a machine with a working link to have no usable adapter.
#[test]
fn an_unreadable_query_does_not_block_the_adapter() {
    let mut row = wired("Primary");
    row.local_ip = "-".to_string();
    row.gateway = "-".to_string();
    row.runtime_data_unavailable = true;

    let unreadable = score_row(&row);
    assert!(!unreadable.blocked);
    assert!(unreadable
        .key_signals
        .iter()
        .any(|s| s == "adapter-data-unreadable"));

    row.runtime_data_unavailable = false;
    let genuine = score_row(&row);
    assert!(
        genuine.blocked,
        "the same row with real data has no address"
    );
    assert!(genuine
        .key_signals
        .iter()
        .any(|s| s == "blocked-missing-local-ip"));
}

/// Preferring an adapter that reaches nothing as the secondary would route
/// rules into a dead link. A tunnel is exempt: it is normally still down
/// while the user binds it.
#[test]
fn an_adapter_with_no_way_out_is_not_recommended_unless_it_looks_like_a_tunnel() {
    let mut host_only = wired("Host-only");
    host_only.gateway = "-".to_string();
    host_only.has_default_route = false;
    host_only.has_forwarding_path = Some(false);
    host_only.observed_facts.connectivity_state = ConnectivityState::Degraded;
    let mut rows = vec![wired("Wired"), host_only, tunnel("Tunnel")];

    assign_recommendations(&mut rows);

    let host_only = find(&rows, "Host-only");
    assert!(has_signal(host_only, "no-forwarding-path"));
    assert_ne!(
        host_only.recommendation.class,
        RecommendationClass::PreferredSecondary
    );
    assert!(!has_signal(find(&rows, "Tunnel"), "no-forwarding-path"));
}

/// The cold start scores rows that crossed the wire, the refresh shows what
/// the service scored: both must land on the same verdicts.
#[test]
fn a_wire_round_trip_does_not_change_the_verdict() {
    let mut sent = vec![wired("Wired"), tunnel("Tunnel"), wired("Spare")];
    sent[2].observed_facts.connectivity_state = ConnectivityState::Timeout;
    assign_recommendations(&mut sent);

    let mut received = sent
        .iter()
        .map(|row| {
            InterfaceRouteRow::from_wire_dto(&nrr_shared::ipc_payloads::InterfaceRowDto::from(row))
        })
        .collect::<Vec<_>>();
    assign_recommendations(&mut received);

    for (before, after) in sent.iter().zip(&received) {
        assert_eq!(
            before.recommendation, after.recommendation,
            "{}",
            before.name
        );
    }
}

#[test]
fn a_saved_binding_resolves_by_id_first_then_by_name() {
    let rows = [wired("Ethernet"), wired("Wi-Fi")];
    let ethernet_id = rows[0].persistent_id.clone();

    assert_eq!(
        find_adapter_index(&rows, None, Some(" ethernet "), None),
        Some(0),
        "a name is matched trimmed and case-insensitively"
    );
    assert_eq!(
        find_adapter_index(
            &rows,
            Some(&ethernet_id.to_uppercase()),
            Some("Wi-Fi"),
            None
        ),
        Some(0),
        "the id wins over a stale name"
    );
    assert_eq!(
        find_adapter_index(&rows, Some("  "), Some("Wi-Fi"), None),
        Some(1),
        "a blank id is no id"
    );
    assert_eq!(
        find_adapter_index(&rows, Some("preview-adapter:gone"), Some("Wi-Fi"), None),
        Some(1),
        "an id no adapter carries falls back to the name"
    );
    assert_eq!(
        find_adapter_index(&rows, Some(&ethernet_id), None, Some(0)),
        None,
        "the excluded row is never the answer"
    );
    assert_eq!(find_adapter_index(&rows, None, None, None), None);
}
