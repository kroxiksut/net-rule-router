//! What every posture that blocks the main link leaves open for another VPN's
//! handshake.
//!
//! A VPN the system runs itself (IKEv2 and L2TP/IPsec on Windows, strongSwan
//! or libreswan on Linux) has no client program the user could confirm: its
//! key exchange comes from the OS IKE service and its ESP from the kernel.
//! Cut either and that VPN never connects while protection is on. So:
//!
//! - ESP to any address of either family, for the user, under a blanket
//!   block. ESP carries no ports, and its payload is the other VPN's own
//!   encryption.
//! - IKE (UDP 500 and 4500) from the OS IKE service only, for the service
//!   accounts it runs as. Never from a user's program: that could be anything
//!   dressed as IKE.
//! - Each gateway the user confirmed (`vpn_gateway_confirm`): UDP to that
//!   address on the handshake ports, for that user, under a blanket block.
//!
//! The per-destination guard cuts nothing but rule hosts, so it spares the
//! user nothing here; the service accounts only ever get that guard, which is
//! why the IKE service is spared from it, as the tunnel clients are.
//! Each OS lowers it with the narrowest match its mechanism has.

use super::*;
use nrr_shared::ipc_payloads::{VPN_GATEWAYS_MAX, VPN_HANDSHAKE_UDP_PORTS};

/// First ordinal of these permits in the exemption band: past the foreign
/// tunnels' permits, so the two never share a slot.
pub const VPN_HANDSHAKE_ORDINAL_BASE: u32 =
    nrr_platform_api::enforcement::VPN_HANDSHAKE_ORDINAL_BASE;

/// The IKE ports: plain, and behind NAT.
pub const IKE_UDP_PORTS: [u16; 2] = [500, 4500];

/// The program key the OS IKE service's permit carries.
pub const IKE_SERVICE_KEY: &str = "os-ike-service";

/// How narrowly an OS can name its IKE service.
#[derive(Clone, Copy, Debug)]
pub enum IkeServiceMatch<'a> {
    /// By the image hosting it (Windows: the svchost that runs IKEEXT). An
    /// empty list names nothing, and nothing is permitted.
    Images(&'a [String]),
    /// The mechanism has no per-program match, so the service accounts the
    /// daemon runs as are the narrowest (Linux: the system uids).
    AnyServiceProgram,
}

/// Whether `flows` hold `principal`'s blanket block: the catch-all, or the
/// block-all with the tunnel gone.
fn blanket_blocks(principal: &PrincipalScope, flows: &[FlowRule]) -> bool {
    flows.iter().any(|f| {
        f.principal == *principal
            && f.verdict == Verdict::Block
            && f.precedence.class == PrecedenceClass::CatchAllBlock
    })
}

/// Whether `flows` hold a block the guard placed for `principal`. The DoH
/// lockdown is not one: it blocks resolvers, never the main link.
fn guard_blocks(principal: &PrincipalScope, flows: &[FlowRule]) -> bool {
    flows.iter().any(|f| {
        f.principal == *principal
            && f.precedence.class != PrecedenceClass::DohBlock
            && f.precedence.class.rank() < PrecedenceClass::CatchAllExempt.rank()
            && (f.verdict == Verdict::Block
                || (matches!(f.egress, EgressConstraint::OnlyVia(_))
                    && f.flow.dst != DstMatch::Any))
    })
}

fn handshake_permit(
    principal: &PrincipalScope,
    dst: DstMatch,
    dst_port: Option<u16>,
    protocol: L4Proto,
    app: AppScope,
    coverage: Coverage,
    ordinal: u32,
) -> FlowRule {
    FlowRule {
        verdict: Verdict::Permit,
        precedence: Precedence {
            class: PrecedenceClass::CatchAllExempt,
            ordinal,
        },
        flow: FlowMatch {
            dst,
            dst_port,
            protocol: Some(protocol),
        },
        principal: principal.clone(),
        app,
        egress: EgressConstraint::Any,
        coverage,
        observed_by_program: false,
    }
}

/// The user's share: ESP anywhere, and the confirmed gateways on the
/// handshake ports. Empty unless `flows` hold the user's blanket block.
#[must_use]
pub fn plan_vpn_handshake_permits(
    sid: &str,
    flows: &[FlowRule],
    gateways: &[IpAddr],
) -> Vec<FlowRule> {
    let principal = principal_scope(sid);
    if !blanket_blocks(&principal, flows) {
        return Vec::new();
    }
    let mut out = vec![handshake_permit(
        &principal,
        DstMatch::Any,
        None,
        L4Proto::Esp,
        AppScope::Any,
        Coverage::AllPackets,
        VPN_HANDSHAKE_ORDINAL_BASE,
    )];
    // Named per family: the Windows lowering reads `Any` as IPv4.
    out.push(handshake_permit(
        &principal,
        DstMatch::SubnetV6 {
            net: Ipv6Addr::UNSPECIFIED,
            prefix: 0,
        },
        None,
        L4Proto::Esp,
        AppScope::Any,
        Coverage::AllPackets,
        VPN_HANDSHAKE_ORDINAL_BASE,
    ));
    let mut ordinal = VPN_HANDSHAKE_ORDINAL_BASE + 1;
    let mut seen = std::collections::HashSet::new();
    for ip in gateways
        .iter()
        .copied()
        .filter(|ip| !nrr_platform_api::is_exempt_from_blocking(*ip) && seen.insert(*ip))
        .take(VPN_GATEWAYS_MAX)
    {
        for port in VPN_HANDSHAKE_UDP_PORTS {
            out.push(handshake_permit(
                &principal,
                host_match(ip),
                Some(port),
                L4Proto::Udp,
                AppScope::Any,
                Coverage::ConnectOnly,
                ordinal,
            ));
            ordinal += 1;
        }
    }
    out
}

/// The OS IKE service's share: UDP 500 and 4500 in both families, for the
/// service accounts. Empty while `flows` block nothing of theirs.
#[must_use]
pub fn plan_ike_service_permits(flows: &[FlowRule], ike: IkeServiceMatch<'_>) -> Vec<FlowRule> {
    let principal = PrincipalScope::ServiceAccounts;
    if !guard_blocks(&principal, flows) {
        return Vec::new();
    }
    let app = match ike {
        IkeServiceMatch::Images([]) => return Vec::new(),
        IkeServiceMatch::Images(images) => AppScope::Program {
            key: IKE_SERVICE_KEY.to_owned(),
            exe_paths: images.iter().map(PathBuf::from).collect(),
        },
        IkeServiceMatch::AnyServiceProgram => AppScope::Any,
    };
    let families = [
        DstMatch::Any,
        DstMatch::SubnetV6 {
            net: Ipv6Addr::UNSPECIFIED,
            prefix: 0,
        },
    ];
    let mut out = Vec::new();
    let mut ordinal = nrr_platform_api::enforcement::VPN_HANDSHAKE_IKE_ORDINAL_BASE;
    for port in IKE_UDP_PORTS {
        for dst in families {
            out.push(handshake_permit(
                &principal,
                dst,
                Some(port),
                L4Proto::Udp,
                app.clone(),
                Coverage::ConnectOnly,
                ordinal,
            ));
            ordinal += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests;
