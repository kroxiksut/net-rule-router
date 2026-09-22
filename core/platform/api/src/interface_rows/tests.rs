/// The OS never promised an order, so "the first IPv4" could change the
/// displayed address between two calls with nothing changed on the machine.
#[test]
fn the_displayed_address_does_not_depend_on_enumeration_order() {
    use std::net::IpAddr;
    let a: IpAddr = "192.168.0.5".parse().expect("ip");
    let b: IpAddr = "10.0.0.9".parse().expect("ip");
    assert_eq!(
        super::preferred_display_address(&[a, b]),
        super::preferred_display_address(&[b, a]),
    );
    assert_eq!(
        super::preferred_display_address(&[a, b]).as_deref(),
        Some("10.0.0.9"),
    );
}

/// An IPv6-only adapter has an address; reporting "-" made it unselectable.
#[test]
fn an_ipv6_only_adapter_still_reports_an_address() {
    use std::net::IpAddr;
    let link_local: IpAddr = "fe80::1".parse().expect("ip");
    let global: IpAddr = "2001:db8::5".parse().expect("ip");
    assert_eq!(
        super::preferred_display_address(&[link_local, global]).as_deref(),
        Some("2001:db8::5"),
        "a routable address outranks a link-local one",
    );
    assert!(super::preferred_display_address(&[]).is_none());
}

/// A failed DHCP lease (169.254) is worth showing, but never over a real
/// address — and never over IPv6 either: it is still IPv4 reachability.
#[test]
fn a_routable_address_outranks_an_autoconfigured_one() {
    use std::net::IpAddr;
    let apipa: IpAddr = "169.254.3.4".parse().expect("ip");
    let real: IpAddr = "192.168.1.7".parse().expect("ip");
    assert_eq!(
        super::preferred_display_address(&[apipa, real]).as_deref(),
        Some("192.168.1.7"),
    );
    assert_eq!(
        super::preferred_display_address(&[apipa]).as_deref(),
        Some("169.254.3.4"),
    );
}

use super::*;

fn route(dest: [u8; 4], prefix: u8, next_hop: [u8; 4], ifindex: u32, metric: u32) -> RouteEntry {
    RouteEntry {
        destination: IpAddr::V4(Ipv4Addr::from(dest)),
        prefix_length: prefix,
        next_hop: IpAddr::V4(Ipv4Addr::from(next_hop)),
        interface_index: ifindex,
        metric,
        is_ours: false,
        table: crate::RouteTableRef::Main,
    }
}

#[test]
fn a_gateway_less_tunnel_forwards_through_its_split_default_routes() {
    // The shape a live OpenVPN link leaves behind: no adapter gateway, but
    // `0.0.0.0/1` + `128.0.0.0/1` pointing at the tunnel peer. The GUI must
    // see this as usable, not as "nowhere to forward to" — the whole reason
    // this signal exists instead of reading `has_default_route`.
    let routes = vec![
        route([0, 0, 0, 0], 1, [10, 91, 192, 1], 23, 1),
        route([128, 0, 0, 0], 1, [10, 91, 192, 1], 23, 1),
        route([10, 91, 193, 99], 32, [0, 0, 0, 0], 23, 256), // on-link, ignored
    ];
    assert_eq!(
        derive_forwarding_next_hop(&routes, 23),
        Some(Ipv4Addr::new(10, 91, 192, 1))
    );
}

#[test]
fn a_host_only_adapter_with_only_on_link_routes_has_nowhere_to_forward() {
    // The VirtualBox host-only shape: an on-link subnet route and nothing
    // else. This is the case the warning is actually for.
    let routes = vec![
        route([192, 168, 56, 0], 24, [0, 0, 0, 0], 15, 256),
        route([0, 0, 0, 0], 0, [192, 168, 0, 1], 17, 25), // another interface
    ];
    assert_eq!(derive_forwarding_next_hop(&routes, 15), None);
}

#[test]
fn a_real_default_route_outranks_the_split_halves_and_metric_breaks_ties() {
    let routes = vec![
        route([0, 0, 0, 0], 1, [10, 0, 0, 1], 5, 1),
        route([0, 0, 0, 0], 0, [10, 0, 0, 9], 5, 50),
    ];
    assert_eq!(
        derive_forwarding_next_hop(&routes, 5),
        Some(Ipv4Addr::new(10, 0, 0, 9)),
        "a real /0 wins over a /1 half even with a worse metric"
    );
    let tie = vec![
        route([0, 0, 0, 0], 0, [10, 0, 0, 9], 5, 50),
        route([0, 0, 0, 0], 0, [10, 0, 0, 3], 5, 10),
    ];
    assert_eq!(
        derive_forwarding_next_hop(&tie, 5),
        Some(Ipv4Addr::new(10, 0, 0, 3))
    );
}

#[test]
fn a_loopback_next_hop_or_a_narrow_on_link_route_never_counts_as_a_way_out() {
    let routes = vec![
        route([0, 0, 0, 0], 0, [127, 0, 0, 1], 5, 1),
        route([10, 0, 0, 0], 8, [0, 0, 0, 0], 5, 1),
    ];
    assert_eq!(derive_forwarding_next_hop(&routes, 5), None);
}

#[test]
fn a_peerless_tunnel_covering_the_internet_on_link_forwards_through_the_interface() {
    // swiftvpn over WireGuard (Wintun), 10.88.0.191/32, ifindex 66: no
    // gateway, no /0, no /1 halves — the client covers the internet with a
    // redirect SET of on-link prefixes, and traffic flows fine (170 MiB in
    // one session). The old rule saw "only on-link routes" and failed
    // closed on a working tunnel.
    let routes = vec![
        route([0, 0, 0, 0], 5, [0, 0, 0, 0], 66, 0),
        route([8, 0, 0, 0], 7, [0, 0, 0, 0], 66, 0),
        route([11, 0, 0, 0], 8, [0, 0, 0, 0], 66, 0),
        route([12, 0, 0, 0], 6, [0, 0, 0, 0], 66, 0),
        route([16, 0, 0, 0], 4, [0, 0, 0, 0], 66, 0),
        route([32, 0, 0, 0], 3, [0, 0, 0, 0], 66, 0),
        route([64, 0, 0, 0], 2, [0, 0, 0, 0], 66, 0),
        route([128, 0, 0, 0], 2, [0, 0, 0, 0], 66, 0),
        route([192, 0, 0, 0], 9, [0, 0, 0, 0], 66, 0),
        route([224, 0, 0, 0], 3, [0, 0, 0, 0], 66, 0), // multicast, ignored
        route([10, 88, 0, 191], 32, [0, 0, 0, 0], 66, 256), // own address
        route([0, 0, 0, 0], 0, [192, 168, 0, 1], 19, 10), // primary NIC
    ];
    assert_eq!(
        derive_forwarding_next_hop(&routes, 66),
        Some(Ipv4Addr::UNSPECIFIED)
    );
    // A plain on-link default (WireGuard with AllowedIPs = 0.0.0.0/0) is
    // the same answer.
    let plain = vec![route([0, 0, 0, 0], 0, [0, 0, 0, 0], 66, 0)];
    assert_eq!(
        derive_forwarding_next_hop(&plain, 66),
        Some(Ipv4Addr::UNSPECIFIED)
    );
    // A split-tunnel WireGuard profile routing ONE corporate /16 is not a
    // way out for the rest of the internet.
    let split = vec![
        route([10, 200, 0, 0], 16, [0, 0, 0, 0], 66, 0),
        route([10, 88, 0, 191], 32, [0, 0, 0, 0], 66, 256),
    ];
    assert_eq!(derive_forwarding_next_hop(&split, 66), None);
    // A real peer, when there is one, still wins over on-link coverage.
    let mixed = vec![
        route([0, 0, 0, 0], 0, [0, 0, 0, 0], 66, 0),
        route([0, 0, 0, 0], 1, [10, 88, 0, 1], 66, 1),
    ];
    assert_eq!(
        derive_forwarding_next_hop(&mixed, 66),
        Some(Ipv4Addr::new(10, 88, 0, 1))
    );
}

#[test]
fn a_tunnel_with_only_on_link_routes_derives_nothing_yet() {
    // swiftvpn OpenVPN, 10.88.1.41/24, ifindex 60: the
    // adapter is Up with IPv4 but the client has not yet installed any
    // gateway route — the table holds only on-link entries. There is
    // genuinely nothing to derive; the state resolves itself seconds
    // later when the client installs its split-default catch-alls.
    let routes = vec![
        route([10, 88, 1, 0], 24, [0, 0, 0, 0], 60, 256),
        route([10, 88, 1, 41], 32, [0, 0, 0, 0], 60, 256),
        route([0, 0, 0, 0], 0, [192, 168, 0, 1], 16, 25), // primary NIC
    ];
    assert_eq!(derive_forwarding_next_hop(&routes, 60), None);
}

#[test]
fn a_gateway_style_host_route_recovers_the_peer_when_catch_alls_are_absent() {
    // Same tunnel after the routing layer stripped the VPN's catch-alls
    // and (say) a service restart lost the in-memory next-hop cache: the
    // /32 overlays installed earlier still name the tunnel peer, so the
    // last-resort rank recovers 10.88.0.1 from them.
    let routes = vec![
        route([10, 88, 1, 0], 24, [0, 0, 0, 0], 60, 256), // on-link, ignored
        route([23, 10, 20, 78], 32, [10, 88, 0, 1], 60, 5),
        route([23, 10, 20, 128], 32, [10, 88, 0, 1], 60, 5),
        route([0, 0, 0, 0], 0, [192, 168, 0, 1], 16, 25), // primary NIC
    ];
    assert_eq!(
        derive_forwarding_next_hop(&routes, 60),
        Some(Ipv4Addr::new(10, 88, 0, 1))
    );
}

#[test]
fn catch_all_routes_outrank_the_last_resort_host_routes() {
    // A live split-default names the CURRENT peer; stale host routes from
    // a previous session must never outvote it, whatever their metric.
    let routes = vec![
        route([23, 10, 20, 78], 32, [10, 88, 0, 1], 60, 1), // stale peer
        route([0, 0, 0, 0], 1, [10, 89, 0, 1], 60, 30),     // current peer
        route([128, 0, 0, 0], 1, [10, 89, 0, 1], 60, 30),
    ];
    assert_eq!(
        derive_forwarding_next_hop(&routes, 60),
        Some(Ipv4Addr::new(10, 89, 0, 1))
    );
}

#[test]
fn data_source_round_trips_and_unknown_reads_as_placeholder() {
    for source in [
        InterfacesDataSource::WindowsLive,
        InterfacesDataSource::FallbackMock,
    ] {
        assert_eq!(InterfacesDataSource::from_title(source.title()), source);
    }
    // A peer this build cannot vouch for must not be believed to be live:
    // the placeholder reading is the one that keeps invented adapters out
    // of the list the user binds routes in.
    assert_eq!(
        InterfacesDataSource::from_title("something-newer"),
        InterfacesDataSource::FallbackMock
    );
    assert!(InterfacesDataSource::WindowsLive.is_live());
    assert!(!InterfacesDataSource::FallbackMock.is_live());
}

#[test]
fn fallback_rows_are_deterministic_and_enriched() {
    let rows = fallback_rows();
    assert_eq!(rows.len(), 4);
    let vpn = rows
        .iter()
        .find(|r| r.windows_name == "VPN")
        .expect("vpn row");
    assert_eq!(
        vpn.derived_assessment.vpn_tunnel_likelihood,
        DerivedLikelihood::Likely
    );
    assert!(vpn.derived_assessment.heuristic_only);
    assert_eq!(
        vpn.observed_facts.external_ip_status,
        ExternalIpStatus::NotChecked
    );
}

#[test]
fn only_a_live_adapter_with_a_routable_address_is_probed() {
    assert_eq!(
        external_probe_target(BasicAvailabilityStatus::Available, "192.168.1.20"),
        Some(Ipv4Addr::new(192, 168, 1, 20)),
        "a private LAN address is the normal case — NAT is what we ask about"
    );
    assert_eq!(
        external_probe_target(BasicAvailabilityStatus::Available, " 10.10.0.15 "),
        Some(Ipv4Addr::new(10, 10, 0, 15)),
        "surrounding whitespace must not disqualify an adapter"
    );

    for unusable in [
        "-",           // the enumeration's "no address" marker
        "",            //
        "127.0.0.1",   // loopback
        "0.0.0.0",     // unspecified
        "169.254.4.7", // APIPA: DHCP never answered
        "224.0.0.1",   // multicast
        "255.255.255.255",
        "fe80::1", // IPv6: the probe binds an IPv4 source
        "not-an-address",
    ] {
        assert_eq!(
            external_probe_target(BasicAvailabilityStatus::Available, unusable),
            None,
            "{unusable} must not be probed"
        );
    }

    for status in [
        BasicAvailabilityStatus::Unavailable,
        BasicAvailabilityStatus::RequiresCheck,
    ] {
        assert_eq!(
            external_probe_target(status, "192.168.1.20"),
            None,
            "{status:?} adapters must not be probed"
        );
    }
}

#[test]
fn probe_outcomes_fold_into_honest_observed_facts() {
    let base = || build_observed_facts(BasicAvailabilityStatus::Available, "10.0.0.2", "10.0.0.1");

    let mut resolved = base();
    apply_external_probe(
        &mut resolved,
        ExternalIpProbeOutcome::Resolved(Ipv4Addr::new(203, 0, 113, 10)),
    );
    assert_eq!(resolved.external_ip_status, ExternalIpStatus::Resolved);
    assert_eq!(resolved.external_ip.as_deref(), Some("203.0.113.10"));
    assert!(resolved.external_probe_attempted);

    // A VPN or split-tunnel adapter with no reachable path degrades to a
    // failed check — never to a stale or borrowed address.
    let mut unreachable = base();
    apply_external_probe(&mut unreachable, ExternalIpProbeOutcome::Unreachable);
    assert_eq!(
        unreachable.external_ip_status,
        ExternalIpStatus::CheckFailed
    );
    assert_eq!(unreachable.external_ip, None);
    assert!(unreachable.external_probe_attempted);

    let mut blocked = base();
    apply_external_probe(&mut blocked, ExternalIpProbeOutcome::LocallyBlocked);
    assert_eq!(blocked.external_ip_status, ExternalIpStatus::Blocked);
    assert_eq!(blocked.external_ip, None);

    let mut skipped = base();
    apply_external_probe(&mut skipped, ExternalIpProbeOutcome::Skipped);
    assert_eq!(skipped.external_ip_status, ExternalIpStatus::NotChecked);
    assert_eq!(skipped.external_ip, None);
    assert!(!skipped.external_probe_attempted);
}

#[test]
fn a_resolved_row_survives_the_wire_round_trip() {
    let mut row = fallback_rows()
        .into_iter()
        .find(|r| r.windows_name == "Wi-Fi")
        .expect("wifi row");
    apply_external_probe(
        &mut row.observed_facts,
        ExternalIpProbeOutcome::Resolved(Ipv4Addr::new(198, 51, 100, 7)),
    );
    let dto = nrr_shared::ipc_payloads::InterfaceRowDto::from(&row);
    assert_eq!(dto.observed_facts.external_ip_status, "resolved");
    assert_eq!(
        dto.observed_facts.external_ip.as_deref(),
        Some("198.51.100.7")
    );

    let back = InterfaceRouteRow::from_wire_dto(&dto);
    assert_eq!(
        back.observed_facts.external_ip_status,
        ExternalIpStatus::Resolved
    );
    assert_eq!(
        back.observed_facts.external_ip.as_deref(),
        Some("198.51.100.7")
    );
    assert!(back.observed_facts.external_probe_attempted);
}

#[test]
fn dto_projection_matches_cold_start_slug_shape() {
    let rows = fallback_rows();
    let ethernet = rows
        .iter()
        .find(|r| r.windows_name == "Ethernet")
        .expect("ethernet row");
    let dto = nrr_shared::ipc_payloads::InterfaceRowDto::from(ethernet);
    assert_eq!(dto.windows_name, "Ethernet");
    assert_eq!(dto.availability, "available");
    assert_eq!(dto.route_state, "not-selected");
    assert_eq!(dto.selected_role, None);
    // The placeholder dataset runs no probe, so it must not claim one.
    assert_eq!(dto.observed_facts.external_ip_status, "not-checked");
    assert_eq!(dto.derived_assessment.classification, "regular-interface");
    // kebab-case wire round-trip preserves the nested shape.
    let json = serde_json::to_value(&dto).expect("serialize");
    assert_eq!(json["windows-name"], "Ethernet");
    assert_eq!(json["has-default-route"], true);
    assert_eq!(json["observed-facts"]["external-ip-status"], "not-checked");
    assert_eq!(
        json["derived-assessment"]["vpn-tunnel-likelihood"],
        "unlikely"
    );
}

#[test]
fn wire_dto_round_trip_preserves_display_and_scoring_fields() {
    let rows = fallback_rows();
    let vpn = rows
        .iter()
        .find(|r| r.windows_name == "VPN")
        .expect("vpn row");
    let dto = nrr_shared::ipc_payloads::InterfaceRowDto::from(vpn);
    let back = InterfaceRouteRow::from_wire_dto(&dto);

    // Identity + display fields survive the slug round-trip.
    assert_eq!(back.persistent_id, vpn.persistent_id);
    assert_eq!(back.windows_name, "VPN");
    assert_eq!(back.interface_type, vpn.interface_type);
    assert_eq!(back.dns_servers, vpn.dns_servers);
    assert_eq!(back.is_bluetooth_like, vpn.is_bluetooth_like);
    // Scoring-input enums are faithfully parsed back.
    assert_eq!(back.availability_status, vpn.availability_status);
    assert_eq!(
        back.observed_facts.connectivity_state,
        vpn.observed_facts.connectivity_state
    );
    assert_eq!(
        back.derived_assessment.vpn_tunnel_likelihood,
        vpn.derived_assessment.vpn_tunnel_likelihood
    );
    // Decoration slots are reset for the caller to re-apply.
    assert_eq!(back.selected_role, None);
    assert_eq!(back.route_state, RouteSelectionState::NotSelected);
}

// ── The IPv6 forwarding path ──────────────────────────────────────────

fn v6_route(dst: &str, prefix: u8, next_hop: &str, ifindex: u32) -> RouteEntry {
    RouteEntry {
        destination: IpAddr::V6(dst.parse().expect("literal")),
        prefix_length: prefix,
        next_hop: IpAddr::V6(next_hop.parse().expect("literal")),
        interface_index: ifindex,
        metric: 0,
        is_ours: false,
        table: crate::RouteTableRef::Main,
    }
}

#[test]
fn a_v6_default_route_names_the_peer() {
    let routes = [v6_route("::", 0, "fe80::1", 7)];
    assert_eq!(
        derive_forwarding_next_hop_v6(&routes, 7),
        Some("fe80::1".parse().expect("literal"))
    );
}

#[test]
fn the_v6_redirect_halves_name_the_peer_too() {
    let routes = [
        v6_route("::", 1, "2001:db8::1", 7),
        v6_route("8000::", 1, "2001:db8::1", 7),
    ];
    assert_eq!(
        derive_forwarding_next_hop_v6(&routes, 7),
        Some("2001:db8::1".parse().expect("literal"))
    );
}

#[test]
fn a_peerless_v6_tunnel_forwards_on_link() {
    // The client covers the space with on-link halves and no peer at all.
    let routes = [v6_route("::", 1, "::", 7), v6_route("8000::", 1, "::", 7)];
    assert_eq!(
        derive_forwarding_next_hop_v6(&routes, 7),
        Some(Ipv6Addr::UNSPECIFIED),
        "an on-link redirect set IS a forwarding path"
    );
}

#[test]
fn the_scopes_every_interface_carries_are_not_a_forwarding_path() {
    // What a link with no IPv6 service still has: its own address, the
    // link-local prefix and the multicast scope.
    let routes = [
        v6_route("fe80::", 64, "::", 7),
        v6_route("fe80::abcd", 128, "::", 7),
        v6_route("ff00::", 8, "::", 7),
    ];
    assert_eq!(derive_forwarding_next_hop_v6(&routes, 7), None);
}

#[test]
fn a_narrow_on_link_prefix_is_not_the_internet() {
    let routes = [v6_route("2001:db8::", 64, "::", 7)];
    assert_eq!(derive_forwarding_next_hop_v6(&routes, 7), None);
}

#[test]
fn a_v6_peer_beats_a_less_default_route_and_a_worse_metric() {
    let mut far = v6_route("2001:db8:1::", 48, "2001:db8::9", 7);
    far.metric = 1;
    let mut near = v6_route("::", 0, "2001:db8::1", 7);
    near.metric = 5;
    assert_eq!(
        derive_forwarding_next_hop_v6(&[far, near], 7),
        Some("2001:db8::1".parse().expect("literal")),
        "how DEFAULT the route is outranks its metric"
    );
}

#[test]
fn the_v6_derivation_ignores_other_interfaces_and_the_other_family() {
    let routes = [
        v6_route("::", 0, "fe80::1", 9),
        RouteEntry {
            destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            prefix_length: 0,
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            interface_index: 7,
            metric: 0,
            is_ours: false,
            table: crate::RouteTableRef::Main,
        },
    ];
    assert_eq!(derive_forwarding_next_hop_v6(&routes, 7), None);
}

#[test]
fn every_placeholder_row_carries_a_declared_preview_id() {
    for row in fallback_rows() {
        assert!(
            is_preview_persistent_id(&row.persistent_id),
            "{} is handed out by the placeholder dataset but not declared in PREVIEW_PERSISTENT_IDS \
             — the service would take it for a real adapter",
            row.persistent_id
        );
    }
}

#[test]
fn a_live_adapter_id_is_not_mistaken_for_a_placeholder() {
    assert!(!is_preview_persistent_id(
        "win-adapter:{00000000-1111-2222-3333-444444444444}"
    ));
    assert!(!is_preview_persistent_id("linux-adapter:wlp3s0"));
    assert!(!is_preview_persistent_id(""));
}
