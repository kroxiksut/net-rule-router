//! Another VPN's handshake under the guard: through the blanket, and only
//! through it.

use super::*;

const PROTO_ESP: u8 = 50;
const GATEWAY: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);

fn esp_permit(filters: &[nrr_platform_api::types::WfpFilterRecord]) -> bool {
    filters.iter().any(|f| {
        f.layer == WfpLayerKey::OutboundTransportV4
            && f.action == WfpAction::Permit
            && f.ip_protocol == Some(PROTO_ESP)
            && f.remote_ip.is_none()
            // The tunnel's own ESP egress is pinned to its interface.
            && f.local_interface_luid.is_none()
    })
}

/// "Everything" with the tunnel gone: ESP passes, and a gateway the user
/// confirmed is reachable on the handshake ports for that user alone.
#[test]
fn the_block_all_lets_another_vpns_handshake_through() {
    let sid = "S-1-5-21-77-77-77-1001";
    crate::vpn_gateway_confirm::global_vpn_gateways()
        .replace_confirmed(
            sid,
            vec![nrr_shared::ipc_payloads::VpnGatewayDto {
                address: GATEWAY.to_string(),
                program: String::new(),
            }],
        )
        .expect("confirmed");
    let (api, orch, src, rules) = fixture_with_luid(None);
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(203, 0, 113, 9)));
    let mut snap = snap_block("Wi-Fi", "TAP");
    snap.leak_protection = nrr_domain::LeakProtection::Everything;
    src.set(sid, snap);

    orch.install_for_sid(sid).unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    assert!(esp_permit(&filters), "ESP passes the block-all");
    let gateway: Vec<_> = filters
        .iter()
        .filter(|f| f.remote_ip == Some(GATEWAY) && f.action == WfpAction::Permit)
        .collect();
    let mut ports: Vec<u16> = gateway.iter().filter_map(|f| f.remote_port).collect();
    ports.sort_unstable();
    assert_eq!(ports, vec![500, 1701, 4500, 51820]);
    assert!(gateway
        .iter()
        .all(|f| f.user_sid.as_deref() == Some(sid) && f.ip_protocol == Some(17)));
}

/// The IPv6 cut below ALE names a protocol and never UDP, so a confirmed v6
/// gateway needs only its user's ALE permit on the handshake ports, and the
/// machine-wide layer opens nothing for it.
#[test]
fn a_confirmed_v6_gateway_is_opened_for_its_user_and_nothing_below_ale_cuts_udp() {
    let sid = "S-1-5-21-77-77-77-1006";
    let gateway: std::net::Ipv6Addr = "2001:db8::20".parse().expect("ip");
    crate::vpn_gateway_confirm::global_vpn_gateways()
        .replace_confirmed(
            sid,
            vec![nrr_shared::ipc_payloads::VpnGatewayDto {
                address: gateway.to_string(),
                program: String::new(),
            }],
        )
        .expect("confirmed");
    let (api, orch, src, rules) = fixture_with_ipv6(
        None,
        "example.test",
        vec![std::net::IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))],
    );
    rules.set(rules_with_secondary_host("example.test"));
    src.set(sid, snap_block_mode_b("Wi-Fi", "TAP"));

    orch.install_for_sid(sid).unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    let ale: Vec<_> = filters
        .iter()
        .filter(|f| {
            f.layer == WfpLayerKey::AleAuthConnectV6
                && f.action == WfpAction::Permit
                && f.remote_subnet_v6 == Some((gateway, 128))
        })
        .collect();
    assert!(
        !ale.is_empty(),
        "the confirmed gateway passes the user's block"
    );
    assert!(ale
        .iter()
        .all(|f| f.user_sid.as_deref() == Some(sid) && f.ip_protocol == Some(17)));
    assert!(
        filters
            .iter()
            .filter(|f| f.action == WfpAction::Block
                && matches!(
                    f.layer,
                    WfpLayerKey::OutboundTransportV6 | WfpLayerKey::OutboundIpPacketV6
                ))
            .all(|f| f.ip_protocol.is_some_and(|p| p != 17 && p != 6)),
        "a block below ALE would cut the system's IKE to the gateway"
    );
    assert!(
        filters
            .iter()
            .filter(|f| f.action == WfpAction::Permit && f.layer == WfpLayerKey::OutboundTransportV6)
            .all(|f| f.remote_subnet_v6.is_some()
                || f.local_interface_luid.is_some()
                || f.ip_protocol == Some(50)),
        "every transport-layer permit names an address, our own link or ESP"
    );
}

/// "Routed sites" cuts nothing but rule hosts: nothing to spare.
#[test]
fn the_per_destination_guard_adds_nothing() {
    let (api, orch, src, rules) = fixture_with_luid(Some(KS_LUID));
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(203, 0, 113, 9)));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
    orch.install_for_sid("S-1-5-21-A").unwrap();
    assert!(!esp_permit(&api.wfp_filters.lock().unwrap()));
}
