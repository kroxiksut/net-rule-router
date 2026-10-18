//! Where one program connected lately, most likely VPN gateway first. A VPN
//! that must reach its gateway over the other link needs an ordinary rule on
//! that address; this read finds the address. Its tunnel packets come from the
//! VPN's own service, so the caller is shown service accounts' connections too.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use nrr_domain::user_principal::UserPrincipal;
use nrr_platform_api::conn_observe::TransportProtocol;
use nrr_platform_api::fake_ip::FakeIpPoolConfig;
use nrr_platform_api::types::SERVICE_ACCOUNT_SIDS;
use nrr_shared::ipc_payloads::{
    VpnGatewayCandidateDto, VpnGatewayCandidatesRequest, VpnGatewayCandidatesResponse,
};

use super::conn_trace::{exe_name, is_own_service};
use super::*;
use crate::conn_observation_consumer::ConnectionTraceRecord;

/// Addresses one answer names; the rest are counted in `omitted`.
pub const MAX_GATEWAY_CANDIDATES: usize = 16;
/// Ports listed per address.
const MAX_PORTS: usize = 16;
/// `SYS_UID_MAX` when the platform names none: the shadow-utils default.
pub const DEFAULT_UNIX_SYS_UID_MAX: u32 = 999;
/// The overflow uid daemons drop to.
const NOBODY_UID: u32 = 65534;
/// Per-service virtual accounts (`NT SERVICE\…`).
const WINDOWS_SERVICE_SID_PREFIX: &str = "S-1-5-80-";

pub struct VpnGatewayCandidatesListHandler {
    ring: Arc<ConnectionTraceRing>,
    unix_sys_uid_max: u32,
}

impl VpnGatewayCandidatesListHandler {
    pub fn new(ring: Arc<ConnectionTraceRing>) -> Self {
        Self {
            ring,
            unix_sys_uid_max: DEFAULT_UNIX_SYS_UID_MAX,
        }
    }

    /// The machine's own system-uid ceiling, where the platform has one.
    #[must_use]
    pub fn with_unix_sys_uid_max(mut self, sys_uid_max: u32) -> Self {
        self.unix_sys_uid_max = sys_uid_max;
        self
    }
}

/// Whether `owner` is an account services run under: LocalSystem,
/// LocalService, NetworkService or a per-service account on Windows; a system
/// uid or `nobody` on Unix.
pub(crate) fn is_service_account(owner: &str, unix_sys_uid_max: u32) -> bool {
    if SERVICE_ACCOUNT_SIDS
        .iter()
        .any(|sid| owner.eq_ignore_ascii_case(sid))
        || owner
            .get(..WINDOWS_SERVICE_SID_PREFIX.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(WINDOWS_SERVICE_SID_PREFIX))
    {
        return true;
    }
    UserPrincipal::from_stored(owner)
        .ok()
        .and_then(|p| p.as_unix_uid())
        .is_some_and(|uid| uid <= unix_sys_uid_max || uid == NOBODY_UID)
}

/// Whether `caller` may be offered a row owned by `owner`: their own, the
/// machine's, or a service account's. Never another person's, elevated or not:
/// another user's destinations are theirs, and a VPN client runs as a service.
pub(super) fn gateway_row_visible(
    caller: &str,
    owner: Option<&str>,
    unix_sys_uid_max: u32,
) -> bool {
    let Some(owner) = owner.map(str::trim).filter(|o| !o.is_empty()) else {
        return true;
    };
    (!caller.is_empty() && owner.eq_ignore_ascii_case(caller))
        || is_service_account(owner, unix_sys_uid_max)
}

/// An address a VPN gateway can have: public, and not one of the product's
/// own virtual addresses.
fn is_gateway_address(ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    };
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    if FakeIpPoolConfig::is_default_pool_addr(ip) {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            let cgnat = o[0] == 100 && (64..128).contains(&o[1]);
            !(v4.is_private() || v4.is_link_local() || v4.is_broadcast() || cgnat || o[0] == 0)
        }
        IpAddr::V6(v6) => {
            let head = v6.segments()[0];
            let link_local = head & 0xffc0 == 0xfe80;
            let unique_local = head & 0xfe00 == 0xfc00;
            !(link_local || unique_local)
        }
    }
}

/// The program a request names, as rows spell it: the file name only. A path
/// ending in a separator names none.
fn requested_program(raw: &str) -> String {
    raw.trim()
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned()
}

fn protocol_slug(p: TransportProtocol) -> String {
    match p {
        TransportProtocol::Tcp => "tcp".into(),
        TransportProtocol::Udp => "udp".into(),
        TransportProtocol::Other(n) => format!("ip-{n}"),
    }
}

#[derive(Default)]
struct Folded {
    hostname: String,
    hostname_at: u64,
    ports: BTreeSet<u16>,
    protocols: BTreeSet<String>,
    connections: u32,
    last_seen_ms: u64,
    ike: bool,
    https: bool,
}

impl Folded {
    /// IKE / NAT-T first, then 443, then the rest.
    fn tier(&self) -> u8 {
        if self.ike {
            0
        } else if self.https {
            1
        } else {
            2
        }
    }
}

/// The candidates `rows` hold for `program`, ranked, plus how many the cap
/// left out. Rows the caller may not see are expected to be filtered already.
pub(super) fn fold_gateway_candidates<'a>(
    rows: impl IntoIterator<Item = &'a ConnectionTraceRecord>,
    program: &str,
) -> (Vec<VpnGatewayCandidateDto>, u32) {
    let mut by_address: HashMap<IpAddr, Folded> = HashMap::new();
    for rec in rows {
        let process = exe_name(rec.process_path.as_deref());
        if !process.eq_ignore_ascii_case(program) || is_own_service(&process) {
            continue;
        }
        let remote = match rec.remote.ip() {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(rec.remote.ip(), IpAddr::V4),
            v4 => v4,
        };
        if !is_gateway_address(remote) || rec.remote_names.as_ref().is_some_and(|n| n.fake_ip) {
            continue;
        }
        let at = rec.observed_unix_ms.unwrap_or(0);
        let port = rec.remote.port();
        let folded = by_address.entry(remote).or_default();
        folded.connections = folded.connections.saturating_add(1);
        folded.last_seen_ms = folded.last_seen_ms.max(at);
        if folded.ports.len() < MAX_PORTS || folded.ports.contains(&port) {
            folded.ports.insert(port);
        }
        folded.protocols.insert(protocol_slug(rec.protocol));
        folded.ike |= rec.protocol == TransportProtocol::Udp && matches!(port, 500 | 4500);
        folded.https |= port == 443
            && matches!(
                rec.protocol,
                TransportProtocol::Tcp | TransportProtocol::Udp
            );
        if let Some(name) = rec
            .remote_names
            .as_ref()
            .and_then(|n| n.names.first())
            .filter(|n| !n.is_empty())
        {
            if folded.hostname.is_empty() || at >= folded.hostname_at {
                folded.hostname.clone_from(name);
                folded.hostname_at = at;
            }
        }
    }
    let mut ranked: Vec<(IpAddr, Folded)> = by_address.into_iter().collect();
    ranked.sort_by(|(a_ip, a), (b_ip, b)| {
        a.tier()
            .cmp(&b.tier())
            .then(b.connections.cmp(&a.connections))
            .then(b.last_seen_ms.cmp(&a.last_seen_ms))
            .then(a_ip.cmp(b_ip))
    });
    let omitted =
        u32::try_from(ranked.len().saturating_sub(MAX_GATEWAY_CANDIDATES)).unwrap_or(u32::MAX);
    let candidates = ranked
        .into_iter()
        .take(MAX_GATEWAY_CANDIDATES)
        .map(|(ip, f)| VpnGatewayCandidateDto {
            address: ip.to_string(),
            hostname: f.hostname,
            ports: f.ports.into_iter().collect(),
            protocols: f.protocols.into_iter().collect(),
            connections: f.connections,
            last_seen_ms: i64::try_from(f.last_seen_ms).unwrap_or(i64::MAX),
        })
        .collect();
    (candidates, omitted)
}

impl IpcHandler for VpnGatewayCandidatesListHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        const OP: &str = "vpn.gateway-candidates.list";
        let req: VpnGatewayCandidatesRequest = if request.payload.is_null() {
            VpnGatewayCandidatesRequest::default()
        } else {
            serde_json::from_value(request.payload.clone()).map_err(|e| malformed(OP, e))?
        };
        let program = requested_program(&req.program);
        if program.is_empty() {
            return Err(malformed_msg(OP, "program is required"));
        }
        // Derived from the connection, never from the request.
        let caller = ctx.caller_stored();
        let rows = self.ring.snapshot_where(0, usize::MAX, |rec| {
            gateway_row_visible(caller, rec.user_sid.as_deref(), self.unix_sys_uid_max)
        });
        let (candidates, omitted) = fold_gateway_candidates(&rows, &program);
        serialise(
            OP,
            &VpnGatewayCandidatesResponse {
                program,
                candidates,
                omitted,
                observer_active: self.ring.observer_active(),
            },
        )
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::conn_trace_names::RemoteNames;
    use nrr_platform_api::conn_observe::egress::{EgressInterface, EgressRole};
    use nrr_platform_api::conn_observe::ConnectionVerdict;
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};

    const VPN: &str = "corpvpn.exe";

    fn row(
        process: &str,
        owner: Option<&str>,
        proto: TransportProtocol,
        remote: &str,
        at_ms: u64,
    ) -> ConnectionTraceRecord {
        ConnectionTraceRecord {
            process_path: Some(format!(r"\device\hd\apps\{process}")),
            user_sid: owner.map(str::to_owned),
            protocol: proto,
            local: "192.0.2.10:52000".parse().expect("local"),
            remote: remote.parse().expect("remote"),
            egress: EgressInterface {
                ifindex: 7,
                role: EgressRole::Primary,
            },
            verdict: ConnectionVerdict::Permit,
            blocked_by_nrr: None,
            nrr_drop_spec_id: None,
            nrr_block_reason: None,
            observed_unix_ms: Some(at_ms),
            remote_names: None,
        }
    }

    fn vpn_row(proto: TransportProtocol, remote: &str, at_ms: u64) -> ConnectionTraceRecord {
        row(VPN, Some("S-1-5-18"), proto, remote, at_ms)
    }

    fn ctx(principal: Option<UserPrincipal>, elevated: bool) -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: elevated,
            caller_principal: principal,
            caller_pid: None,
        }
    }

    fn ask(
        handler: &VpnGatewayCandidatesListHandler,
        program: &str,
        ctx: &IpcRequestContext,
    ) -> Result<VpnGatewayCandidatesResponse, IpcError> {
        let env = IpcRequestEnvelope {
            protocol_version: crate::ipc::IPC_PROTOCOL_VERSION,
            request_id: "r".into(),
            correlation_id: None,
            operation: IpcOperationName::VpnGatewayCandidatesList,
            operation_class: crate::ipc::IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload: serde_json::json!({ "program": program }),
        };
        handler
            .handle(&env, ctx)
            .map(|v| serde_json::from_value(v).expect("decode VpnGatewayCandidatesResponse"))
    }

    fn addresses(resp: &VpnGatewayCandidatesResponse) -> Vec<&str> {
        resp.candidates.iter().map(|c| c.address.as_str()).collect()
    }

    fn ring_of(rows: Vec<ConnectionTraceRecord>) -> Arc<ConnectionTraceRing> {
        let ring = Arc::new(ConnectionTraceRing::new(64));
        for r in rows {
            ring.push(r);
        }
        ring
    }

    fn handler_over(rows: Vec<ConnectionTraceRecord>) -> VpnGatewayCandidatesListHandler {
        VpnGatewayCandidatesListHandler::new(ring_of(rows))
    }

    fn me() -> UserPrincipal {
        UserPrincipal::from_linux_uid(1000)
    }

    fn sorted_addresses(resp: VpnGatewayCandidatesResponse) -> Vec<String> {
        let mut a: Vec<String> = resp.candidates.into_iter().map(|c| c.address).collect();
        a.sort();
        a
    }

    fn doc_addresses(hosts: &[u8]) -> Vec<String> {
        let mut a: Vec<String> = hosts.iter().map(|n| format!("203.0.113.{n}")).collect();
        a.sort();
        a
    }

    #[test]
    fn ike_ports_rank_first_then_443_then_count_then_recency() {
        let rows = vec![
            vpn_row(TransportProtocol::Tcp, "203.0.113.30:8080", 50),
            vpn_row(TransportProtocol::Tcp, "203.0.113.30:8080", 51),
            vpn_row(TransportProtocol::Tcp, "203.0.113.30:8080", 52),
            vpn_row(TransportProtocol::Tcp, "203.0.113.20:443", 10),
            vpn_row(TransportProtocol::Tcp, "203.0.113.20:443", 11),
            vpn_row(TransportProtocol::Udp, "203.0.113.10:4500", 5),
            vpn_row(TransportProtocol::Tcp, "203.0.113.21:443", 90),
            vpn_row(TransportProtocol::Udp, "203.0.113.22:443", 80),
            vpn_row(TransportProtocol::Tcp, "203.0.113.23:443", 1),
            vpn_row(TransportProtocol::Tcp, "203.0.113.23:443", 2),
            // TCP 500 is not IKE.
            vpn_row(TransportProtocol::Tcp, "203.0.113.40:500", 100),
        ];
        let resp = ask(&handler_over(rows), VPN, &ctx(Some(me()), false)).expect("answers");
        assert_eq!(
            addresses(&resp),
            vec![
                "203.0.113.10",
                "203.0.113.20",
                "203.0.113.23",
                "203.0.113.21",
                "203.0.113.22",
                "203.0.113.30",
                "203.0.113.40",
            ]
        );
        let ike = &resp.candidates[0];
        assert_eq!(ike.ports, vec![4500]);
        assert_eq!(ike.protocols, vec!["udp"]);
        let https = &resp.candidates[1];
        assert_eq!((https.connections, https.last_seen_ms), (2, 11));
        assert_eq!(resp.program, VPN);
        assert_eq!(resp.omitted, 0);
    }

    #[test]
    fn local_private_multicast_and_own_virtual_addresses_are_never_gateways() {
        let mut fake_named = vpn_row(TransportProtocol::Udp, "203.0.113.99:500", 9);
        fake_named.remote_names = Some(Arc::new(RemoteNames {
            names: vec!["virtual.example".into()],
            total: 1,
            fake_ip: true,
        }));
        let rows = vec![
            vpn_row(TransportProtocol::Udp, "127.0.0.1:500", 1),
            vpn_row(TransportProtocol::Udp, "10.1.2.3:500", 1),
            vpn_row(TransportProtocol::Udp, "172.16.5.5:500", 1),
            vpn_row(TransportProtocol::Udp, "192.168.1.1:500", 1),
            vpn_row(TransportProtocol::Udp, "169.254.1.1:500", 1),
            vpn_row(TransportProtocol::Udp, "100.64.0.1:500", 1),
            vpn_row(TransportProtocol::Udp, "224.0.0.251:5353", 1),
            vpn_row(TransportProtocol::Udp, "255.255.255.255:500", 1),
            vpn_row(TransportProtocol::Udp, "198.18.0.7:500", 1),
            vpn_row(TransportProtocol::Udp, "198.19.255.1:500", 1),
            vpn_row(TransportProtocol::Udp, "[::1]:500", 1),
            vpn_row(TransportProtocol::Udp, "[fe80::1]:500", 1),
            vpn_row(TransportProtocol::Udp, "[fd00::1]:500", 1),
            vpn_row(TransportProtocol::Udp, "[ff02::1]:500", 1),
            vpn_row(TransportProtocol::Udp, "[::ffff:10.0.0.1]:500", 1),
            fake_named,
            // Positive controls: public addresses of both families stay.
            vpn_row(TransportProtocol::Udp, "198.51.100.7:500", 2),
            vpn_row(TransportProtocol::Udp, "[2001:db8::7]:500", 1),
            vpn_row(TransportProtocol::Udp, "[::ffff:203.0.113.5]:500", 0),
        ];
        let resp = ask(&handler_over(rows), VPN, &ctx(Some(me()), false)).expect("answers");
        assert_eq!(
            addresses(&resp),
            vec!["198.51.100.7", "2001:db8::7", "203.0.113.5"]
        );
    }

    #[test]
    fn only_the_named_program_counts_whatever_its_case_or_path() {
        let rows = vec![
            row(
                "CorpVPN.EXE",
                Some("S-1-5-18"),
                TransportProtocol::Udp,
                "203.0.113.1:500",
                1,
            ),
            row(
                "browser.exe",
                Some("S-1-5-18"),
                TransportProtocol::Tcp,
                "203.0.113.2:443",
                1,
            ),
        ];
        let handler = handler_over(rows);
        let resp = ask(
            &handler,
            r"C:\Program Files\Corp\corpvpn.exe",
            &ctx(Some(me()), false),
        )
        .expect("answers");
        assert_eq!(addresses(&resp), vec!["203.0.113.1"]);
        assert_eq!(resp.program, VPN);
    }

    #[test]
    fn a_request_without_a_program_is_refused() {
        let handler = handler_over(Vec::new());
        for program in ["", "   ", "/"] {
            let err = ask(&handler, program, &ctx(Some(me()), false)).expect_err("refused");
            assert_eq!(err.code, IpcErrorCode::MalformedRequest, "{program:?}");
        }
    }

    /// Another person's destinations stay theirs, elevated caller or not; the
    /// machine's service accounts are where a VPN client runs, so they show.
    #[test]
    fn a_caller_sees_their_own_unowned_and_service_account_rows_only() {
        let owners: [(Option<&str>, &str); 11] = [
            (Some("unix:uid:1000"), "203.0.113.1:500"),
            (None, "203.0.113.2:500"),
            (Some("S-1-5-18"), "203.0.113.3:500"),
            (Some("S-1-5-19"), "203.0.113.4:500"),
            (Some("S-1-5-20"), "203.0.113.5:500"),
            (Some("s-1-5-80-1-2-3-4-5"), "203.0.113.6:500"),
            (Some("unix:uid:0"), "203.0.113.7:500"),
            (Some("unix:uid:65534"), "203.0.113.8:500"),
            (Some("unix:uid:1001"), "203.0.113.9:500"),
            (Some("S-1-5-21-1-2-3-1001"), "203.0.113.10:500"),
            (Some("unix:uid:1500"), "203.0.113.11:500"),
        ];
        let ring = ring_of(
            owners
                .iter()
                .map(|(owner, remote)| row(VPN, *owner, TransportProtocol::Udp, remote, 1))
                .collect(),
        );
        let handler = VpnGatewayCandidatesListHandler::new(Arc::clone(&ring));
        let seen = |handler: &VpnGatewayCandidatesListHandler, ctx: IpcRequestContext| {
            sorted_addresses(ask(handler, VPN, &ctx).expect("answers"))
        };
        let expected = doc_addresses(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(seen(&handler, ctx(Some(me()), false)), expected);
        assert_eq!(
            seen(&handler, ctx(Some(me()), true)),
            expected,
            "elevation does not open another person's rows"
        );
        assert_eq!(
            seen(&handler, ctx(None, false)),
            doc_addresses(&[2, 3, 4, 5, 6, 7, 8]),
            "an unattributed caller owns nothing"
        );
        // Positive control for the uid ceiling: on a machine whose system
        // range reaches 1500 that uid is a service.
        let wide = VpnGatewayCandidatesListHandler::new(ring).with_unix_sys_uid_max(1999);
        assert!(seen(&wide, ctx(Some(me()), false)).contains(&"203.0.113.11".to_owned()));
    }

    /// The service's own process is not a VPN client: its relay carries every
    /// user's traffic, and that stays with the administrator's trace view.
    #[test]
    fn the_services_own_rows_are_never_offered() {
        let own = nrr_shared::product_identity::BinaryRole::Service;
        let rows = vec![
            row(
                own.windows_file_name(),
                Some("S-1-5-18"),
                TransportProtocol::Tcp,
                "203.0.113.1:443",
                1,
            ),
            row(
                own.unix_file_name(),
                Some("unix:uid:0"),
                TransportProtocol::Tcp,
                "203.0.113.2:443",
                1,
            ),
            // Positive control: another service-account program shows.
            row(
                VPN,
                Some("S-1-5-18"),
                TransportProtocol::Tcp,
                "203.0.113.3:443",
                1,
            ),
        ];
        let handler = handler_over(rows);
        for program in [own.windows_file_name(), own.unix_file_name()] {
            let resp = ask(&handler, program, &ctx(Some(me()), true)).expect("answers");
            assert!(
                resp.candidates.is_empty(),
                "{program}: {:?}",
                resp.candidates
            );
        }
        let resp = ask(&handler, VPN, &ctx(Some(me()), false)).expect("answers");
        assert_eq!(addresses(&resp), vec!["203.0.113.3"]);
    }

    #[test]
    fn the_list_is_capped_and_says_how_many_it_left_out() {
        let rows: Vec<ConnectionTraceRecord> = (1..=20u8)
            .map(|n| {
                vpn_row(
                    TransportProtocol::Tcp,
                    &format!("203.0.113.{n}:443"),
                    u64::from(n),
                )
            })
            .collect();
        let resp = ask(&handler_over(rows), VPN, &ctx(Some(me()), false)).expect("answers");
        assert_eq!(resp.candidates.len(), MAX_GATEWAY_CANDIDATES);
        assert_eq!(resp.omitted, 4);
        assert_eq!(
            resp.candidates[0].address, "203.0.113.20",
            "newest first in a tie"
        );
    }

    #[test]
    fn the_newest_name_seen_for_an_address_is_its_hostname() {
        let named = |name: &str, at: u64| {
            let mut r = vpn_row(TransportProtocol::Udp, "203.0.113.1:4500", at);
            r.remote_names = Some(Arc::new(RemoteNames {
                names: vec![name.to_owned()],
                total: 1,
                fake_ip: false,
            }));
            r
        };
        let rows = vec![
            named("old-gw.example", 1),
            named("gw.example", 5),
            vpn_row(TransportProtocol::Udp, "203.0.113.1:500", 9),
            vpn_row(TransportProtocol::Udp, "203.0.113.2:500", 9),
        ];
        let resp = ask(&handler_over(rows), VPN, &ctx(Some(me()), false)).expect("answers");
        let first = &resp.candidates[0];
        assert_eq!(first.address, "203.0.113.1");
        assert_eq!(first.hostname, "gw.example");
        assert_eq!(first.ports, vec![500, 4500]);
        assert_eq!(first.connections, 3);
        assert_eq!(resp.candidates[1].hostname, "");
    }

    #[test]
    fn an_unwatched_machine_says_so() {
        let ring = Arc::new(ConnectionTraceRing::new(4));
        let handler = VpnGatewayCandidatesListHandler::new(Arc::clone(&ring));
        let resp = ask(&handler, VPN, &ctx(Some(me()), false)).expect("answers");
        assert!(!resp.observer_active);
        ring.mark_observer_active();
        let resp = ask(&handler, VPN, &ctx(Some(me()), false)).expect("answers");
        assert!(resp.observer_active, "positive control");
    }

    #[test]
    fn the_audience_rule_on_its_own() {
        assert!(gateway_row_visible(
            "unix:uid:1000",
            Some("UNIX:UID:1000"),
            999
        ));
        assert!(gateway_row_visible("unix:uid:1000", Some(""), 999));
        assert!(gateway_row_visible("", None, 999));
        assert!(gateway_row_visible("", Some("S-1-5-18"), 999));
        assert!(!gateway_row_visible("", Some("unix:uid:1000"), 999));
        assert!(gateway_row_visible("S-1-5-21-9", Some("unix:uid:999"), 999));
        assert!(!gateway_row_visible(
            "S-1-5-21-9",
            Some("unix:uid:1000"),
            999
        ));
        assert!(!gateway_row_visible(
            "S-1-5-21-9",
            Some("__baseline__"),
            999
        ));
        assert!(!gateway_row_visible("S-1-5-21-9", Some("S-1-5-21-10"), 999));
    }
}
