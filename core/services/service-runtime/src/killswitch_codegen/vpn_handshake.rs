//! Another VPN's handshake through a blanket block, as WFP filters — the live
//! twin of `enforcement_planner::vpn_handshake`.
//!
//! - ESP on `OUTBOUND_TRANSPORT_V4`, where the posture's ESP block sits. The
//!   layer has no user condition, so the permit is machine-wide by
//!   construction; ESP carries no ports and only another VPN's encryption. The
//!   v6 packet layer has no protocol condition, so v6 ESP is not opened.
//! - IKE from the OS IKE service: ALE, UDP 500/4500, the svchost image AND the
//!   service accounts. A user's own blanket never matches LocalSystem; this is
//!   for the service accounts' share of the guard.
//! - Each confirmed gateway: ALE, UDP to that address on the handshake ports,
//!   for that user; a v6 gateway also gets a host permit on the v6 packet
//!   layer, which can name nothing narrower.

use nrr_platform_api::types::{WfpFilterId, SERVICE_ACCOUNTS_PRINCIPAL};
use nrr_shared::ipc_payloads::{VPN_GATEWAYS_MAX, VPN_HANDSHAKE_UDP_PORTS};

use crate::enforcement_planner::IKE_UDP_PORTS;
use crate::wfp_bands::{PACKET_VPN_HANDSHAKE_PERMIT_BASE, VPN_HANDSHAKE_PERMIT_BASE};

use super::*;

const PROTO_UDP: u8 = 17;
const PROTO_ESP: u8 = 50;

/// First slot of the IKE pairs in the handshake band, past every gateway's.
const IKE_SLOT_BASE: u64 = 0x80;

fn permit(layer: WfpLayerKey, weight: u64, id: WfpFilterId) -> WfpFilterSpec {
    WfpFilterSpec {
        layer,
        action: WfpAction::Permit,
        remote_ip: None,
        remote_ip_set: Vec::new(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight,
        id,
        user_sid: None,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
        remote_subnet_set: Vec::new(),
    }
}

/// `sid`'s share: ESP anywhere and the confirmed `gateways` on the handshake
/// ports. Only for a blanket block, which the caller knows it armed: under
/// the per-destination guard nothing but rule hosts is cut.
#[must_use]
pub fn vpn_handshake_filters(sid: &str, gateways: &[IpAddr]) -> Vec<WfpFilterSpec> {
    let mut out = vec![WfpFilterSpec {
        ip_protocol: Some(PROTO_ESP),
        ..permit(
            WfpLayerKey::OutboundTransportV4,
            PACKET_VPN_HANDSHAKE_PERMIT_BASE,
            filter_id_for(sid, KILLSWITCH_ROLE, "", "ks-vpn-esp", "any"),
        )
    }];
    let mut seen = std::collections::HashSet::new();
    let mut slot = 0u64;
    for ip in gateways
        .iter()
        .copied()
        .filter(|ip| !is_exempt_from_blocking(*ip) && seen.insert(*ip))
        .take(VPN_GATEWAYS_MAX)
    {
        let target = ip.to_string();
        for port in VPN_HANDSHAKE_UDP_PORTS {
            let (layer, remote_ip, remote_subnet_v6) = match ip {
                IpAddr::V4(v4) => (WfpLayerKey::AleAuthConnectV4, Some(v4), None),
                IpAddr::V6(v6) => (WfpLayerKey::AleAuthConnectV6, None, Some((v6, 128))),
            };
            out.push(WfpFilterSpec {
                remote_ip,
                remote_subnet_v6,
                remote_port: Some(port),
                ip_protocol: Some(PROTO_UDP),
                user_sid: Some(sid.to_string()),
                ..permit(
                    layer,
                    VPN_HANDSHAKE_PERMIT_BASE + slot,
                    filter_id_for(
                        sid,
                        KILLSWITCH_ROLE,
                        &target,
                        "ks-vpn-gw",
                        &port.to_string(),
                    ),
                )
            });
            slot += 1;
        }
        if let IpAddr::V6(v6) = ip {
            out.push(WfpFilterSpec {
                remote_subnet_v6: Some((v6, 128)),
                ..permit(
                    WfpLayerKey::OutboundIpPacketV6,
                    VPN_HANDSHAKE_PERMIT_BASE + slot,
                    filter_id_for(sid, KILLSWITCH_ROLE, &target, "ks-vpn-gw-v6-pkt", "host"),
                )
            });
            slot += 1;
        }
    }
    out
}

/// The OS IKE service's share of `owner`'s service-account guard: UDP 500 and
/// 4500 from `images` (the svchost that hosts IKEEXT) in both families, for
/// the service accounts. Empty while `service` holds no posture block, or
/// with no image to name.
#[must_use]
pub fn ike_service_filters(
    owner: &str,
    service: &[WfpFilterSpec],
    images: &[String],
) -> Vec<WfpFilterSpec> {
    if images.is_empty() || !has_posture_block(service) {
        return Vec::new();
    }
    let seed = service_account_seed(owner);
    let mut out = Vec::new();
    let mut slot = IKE_SLOT_BASE;
    for image in images {
        for port in IKE_UDP_PORTS {
            for (layer, family) in [
                (WfpLayerKey::AleAuthConnectV4, "v4"),
                (WfpLayerKey::AleAuthConnectV6, "v6"),
            ] {
                out.push(WfpFilterSpec {
                    remote_port: Some(port),
                    ip_protocol: Some(PROTO_UDP),
                    user_sid: Some(SERVICE_ACCOUNTS_PRINCIPAL.to_string()),
                    app_pattern: Some(image.clone()),
                    ..permit(
                        layer,
                        VPN_HANDSHAKE_PERMIT_BASE + slot,
                        filter_id_for(
                            &seed,
                            KILLSWITCH_ROLE,
                            image,
                            "ks-vpn-ike",
                            &format!("{port}-{family}"),
                        ),
                    )
                });
                slot += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: &str = "S-1-5-21-1-2-3-1001";
    const SVCHOST: &str = r"C:\Windows\System32\svchost.exe";

    #[test]
    fn esp_is_permitted_on_the_transport_layer_above_the_posture_block() {
        let filters = vpn_handshake_filters(SID, &[]);
        assert_eq!(filters.len(), 1);
        let esp = &filters[0];
        assert_eq!(esp.layer, WfpLayerKey::OutboundTransportV4);
        assert_eq!(esp.action, WfpAction::Permit);
        assert_eq!(esp.ip_protocol, Some(PROTO_ESP));
        assert_eq!(esp.user_sid, None, "the layer carries no user");
        assert!(esp.weight > PACKET_BLOCK_BASE && esp.weight < PACKET_EXEMPT_BASE);
        assert!(esp.remote_port.is_none() && esp.remote_ip.is_none());
    }

    #[test]
    fn no_ike_permit_without_a_service_account_block() {
        assert!(ike_service_filters(SID, &[], &[SVCHOST.to_string()]).is_empty());
    }

    /// The gateway is reachable on the handshake ports by UDP for its user,
    /// and on nothing else: no TCP, no 443.
    #[test]
    fn a_confirmed_gateway_gets_udp_on_the_handshake_ports_only() {
        let gateway: IpAddr = "198.51.100.20".parse().expect("ip");
        let filters = vpn_handshake_filters(SID, &[gateway]);
        let ale: Vec<&WfpFilterSpec> = filters
            .iter()
            .filter(|f| f.layer == WfpLayerKey::AleAuthConnectV4)
            .collect();
        assert_eq!(ale.len(), VPN_HANDSHAKE_UDP_PORTS.len());
        for f in &ale {
            assert_eq!(f.remote_ip, Some("198.51.100.20".parse().expect("ip")));
            assert_eq!(f.ip_protocol, Some(PROTO_UDP));
            assert!(f
                .remote_port
                .is_some_and(|p| VPN_HANDSHAKE_UDP_PORTS.contains(&p)));
            assert_eq!(f.user_sid.as_deref(), Some(SID));
            assert!(f.weight > KILLSWITCH_PERMIT_BASE && f.weight < APP_EXEMPT_BASE);
        }
        assert!(filters.iter().all(|f| f.remote_port != Some(443)));
        let mut ids: Vec<u64> = filters.iter().map(|f| f.id.raw).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), filters.len(), "every filter its own id");
    }

    #[test]
    fn a_v6_gateway_is_opened_on_both_v6_layers() {
        let gateway: IpAddr = "2001:db8::20".parse().expect("ip");
        let filters = vpn_handshake_filters(SID, &[gateway]);
        assert_eq!(
            filters
                .iter()
                .filter(|f| f.layer == WfpLayerKey::AleAuthConnectV6)
                .count(),
            VPN_HANDSHAKE_UDP_PORTS.len()
        );
        assert!(filters
            .iter()
            .any(|f| f.layer == WfpLayerKey::OutboundIpPacketV6
                && f.remote_subnet_v6 == Some(("2001:db8::20".parse().expect("ip"), 128))));
    }

    #[test]
    fn ike_is_narrowed_to_the_service_image_and_the_service_accounts() {
        let service = vec![WfpFilterSpec {
            user_sid: Some(SERVICE_ACCOUNTS_PRINCIPAL.to_string()),
            ..catch_all_block(SID, None)
        }];
        let filters = ike_service_filters(SID, &service, &[SVCHOST.to_string()]);
        assert_eq!(filters.len(), 4, "two ports, two families");
        for f in &filters {
            assert_eq!(f.app_pattern.as_deref(), Some(SVCHOST));
            assert_eq!(f.user_sid.as_deref(), Some(SERVICE_ACCOUNTS_PRINCIPAL));
            assert_eq!(f.ip_protocol, Some(PROTO_UDP));
            assert!(f.remote_port.is_some_and(|p| IKE_UDP_PORTS.contains(&p)));
        }
        assert!(ike_service_filters(SID, &service, &[]).is_empty());
    }
}
