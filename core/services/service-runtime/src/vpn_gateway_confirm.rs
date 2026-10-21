//! Another VPN's gateway, let through leak protection by the user.
//!
//! The system's own VPN handshakes pass by default (see
//! `enforcement_planner::vpn_handshake`). What is left is a VPN whose
//! handshake looks like any program's traffic: a client nobody recognised, or
//! a kernel tunnel whose packets carry the user's socket. Its first dropped
//! attempt is noted here as pending for that user, the user is asked once,
//! and a yes stores the address. The exemption then names that address on the
//! handshake ports only, for that user only.
//!
//! Noting reads what the drop tick already gathered; nothing here runs per
//! packet.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use nrr_platform_api::conn_observe::TransportProtocol;
use nrr_shared::ipc_payloads::{
    RouteVpnGatewaysSetRequest, VpnGatewayDto, VPN_GATEWAYS_MAX, VPN_GATEWAY_PROGRAM_MAX_CHARS,
    VPN_HANDSHAKE_UDP_PORTS,
};

/// IP protocol number of ESP.
const IP_PROTO_ESP: u8 = 50;

/// Pending questions per user; past it a new gateway waits for an answer.
const PENDING_CAP_PER_SID: usize = VPN_GATEWAYS_MAX;

/// Users with a pending question at once; a guard against churn, not a
/// number a real machine reaches.
const PENDING_SIDS_CAP: usize = 256;

/// Whether a dropped flow has the shape of a VPN handshake: UDP to an IKE,
/// L2TP or WireGuard port, or ESP.
#[must_use]
pub fn handshake_shaped(protocol: TransportProtocol, remote_port: u16) -> bool {
    match protocol {
        TransportProtocol::Udp => VPN_HANDSHAKE_UDP_PORTS.contains(&remote_port),
        TransportProtocol::Other(proto) => proto == IP_PROTO_ESP,
        TransportProtocol::Tcp => false,
    }
}

/// The program a handshake drop is credited to, when it can be. ESP, and UDP
/// from a port to the same port (IPsec behind NAT), are built by the kernel
/// out of another program's packet, so naming that program would name the
/// wrong one.
#[must_use]
pub fn handshake_program(
    protocol: TransportProtocol,
    local_port: u16,
    remote_port: u16,
    process_path: Option<&str>,
) -> Option<&str> {
    let kernel_built = match protocol {
        TransportProtocol::Other(_) => true,
        TransportProtocol::Udp => local_port == remote_port,
        TransportProtocol::Tcp => false,
    };
    process_path.filter(|p| !kernel_built && !p.trim().is_empty())
}

/// Where the confirmed gateways persist.
pub trait VpnGatewayStore: Send + Sync {
    fn load(&self, sid: &str) -> Result<Vec<VpnGatewayDto>, String>;
    fn replace(&self, sid: &str, gateways: &[VpnGatewayDto]) -> Result<(), String>;
}

/// Tells one user's clients their pending list changed.
pub type VpnGatewayPushFn = Arc<dyn Fn(&str, Vec<VpnGatewayDto>) + Send + Sync>;

/// Pending and confirmed gateways, per user.
#[derive(Default)]
pub struct VpnGatewayBook {
    pending: Mutex<HashMap<String, Vec<VpnGatewayDto>>>,
    /// A user's entry appears once loaded; absent means "ask the store".
    confirmed: RwLock<HashMap<String, Vec<VpnGatewayDto>>>,
    store: OnceLock<Arc<dyn VpnGatewayStore>>,
    push: OnceLock<VpnGatewayPushFn>,
}

impl VpnGatewayBook {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Wire persistence once, at boot. A second call is ignored.
    pub fn attach_store(&self, store: Arc<dyn VpnGatewayStore>) {
        let _ = self.store.set(store);
    }

    /// Wire the per-user push once, at boot. A second call is ignored.
    pub fn attach_push(&self, push: VpnGatewayPushFn) {
        let _ = self.push.set(push);
    }

    /// `sid`'s confirmed gateways. The first read per user asks the store;
    /// a failed read is retried on the next one.
    #[must_use]
    pub fn confirmed_for(&self, sid: &str) -> Vec<VpnGatewayDto> {
        if let Some(list) = self
            .confirmed
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
        {
            return list.clone();
        }
        let Some(store) = self.store.get() else {
            return Vec::new();
        };
        match store.load(sid) {
            Ok(list) => {
                self.confirmed
                    .write()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(sid.to_owned(), list.clone());
                list
            }
            Err(error) => {
                tracing::warn!(
                    target: "nrr::vpn-gateways",
                    sid,
                    error = %error,
                    "confirmed VPN gateways could not be read; none are let through until they are",
                );
                Vec::new()
            }
        }
    }

    /// `sid`'s confirmed gateway addresses, the exemption's input.
    #[must_use]
    pub fn confirmed_addresses(&self, sid: &str) -> Vec<IpAddr> {
        self.confirmed_for(sid)
            .iter()
            .filter_map(|g| g.address.parse().ok())
            .collect()
    }

    /// `sid`'s unanswered questions.
    #[must_use]
    pub fn pending_for(&self, sid: &str) -> Vec<VpnGatewayDto> {
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .cloned()
            .unwrap_or_default()
    }

    /// Note a handshake leak protection dropped for `sid`. Returns whether it
    /// became a new question; the user's clients hear of it then.
    pub fn note_drop(&self, sid: &str, address: IpAddr, program: Option<&str>) -> bool {
        if sid.is_empty() {
            return false;
        }
        let address_text = address.to_string();
        if self
            .confirmed_for(sid)
            .iter()
            .any(|g| g.address == address_text)
        {
            return false;
        }
        let list = {
            let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            if !pending.contains_key(sid) && pending.len() >= PENDING_SIDS_CAP {
                return false;
            }
            let list = pending.entry(sid.to_owned()).or_default();
            if list.len() >= PENDING_CAP_PER_SID || list.iter().any(|g| g.address == address_text) {
                return false;
            }
            list.push(VpnGatewayDto {
                address: address_text,
                program: bounded_program(program.unwrap_or_default()),
            });
            list.clone()
        };
        tracing::info!(
            target: "nrr::vpn-gateways",
            msg_key = "vpn-gateway-awaiting-confirmation",
            sid,
            address = %address,
            "leak protection stopped what looks like another VPN reaching its gateway; the user is asked whether to let it through",
        );
        self.publish(sid, list);
        true
    }

    /// Replace `sid`'s confirmed gateways with an already checked list,
    /// persisting first. Their questions are answered with it.
    pub fn replace_confirmed(
        &self,
        sid: &str,
        gateways: Vec<VpnGatewayDto>,
    ) -> Result<Vec<VpnGatewayDto>, String> {
        if sid.is_empty() {
            return Err("caller SID unavailable".into());
        }
        if let Some(store) = self.store.get() {
            store.replace(sid, &gateways)?;
        }
        self.confirmed
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .insert(sid.to_owned(), gateways.clone());
        let left = {
            let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            match pending.get_mut(sid) {
                Some(list) => {
                    let before = list.len();
                    list.retain(|p| !gateways.iter().any(|g| g.address == p.address));
                    let left = (list.len() != before).then(|| list.clone());
                    if list.is_empty() {
                        pending.remove(sid);
                    }
                    left
                }
                None => None,
            }
        };
        if let Some(left) = left {
            self.publish(sid, left);
        }
        Ok(gateways)
    }

    /// Drop everything held for `sid` (a full reset of that user).
    pub fn forget(&self, sid: &str) {
        self.confirmed
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .remove(sid);
        let had_pending = self
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(sid)
            .is_some();
        if had_pending {
            self.publish(sid, Vec::new());
        }
    }

    /// Drop everything held for every user (a full reset of all of them).
    pub fn forget_everyone(&self) {
        self.confirmed
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
        let asked: Vec<String> = self
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .drain()
            .map(|(sid, _)| sid)
            .collect();
        for sid in asked {
            self.publish(&sid, Vec::new());
        }
    }

    fn publish(&self, sid: &str, list: Vec<VpnGatewayDto>) {
        if let Some(push) = self.push.get() {
            push(sid, list);
        }
    }
}

/// The state database as [`VpnGatewayStore`].
pub struct StateDbVpnGatewayStore {
    conn: Arc<Mutex<rusqlite::Connection>>,
}

impl StateDbVpnGatewayStore {
    #[must_use]
    pub fn new(conn: Arc<Mutex<rusqlite::Connection>>) -> Self {
        Self { conn }
    }
}

impl VpnGatewayStore for StateDbVpnGatewayStore {
    fn load(&self, sid: &str) -> Result<Vec<VpnGatewayDto>, String> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        nrr_storage::VpnGatewayConfirmationsRepository::new(&conn)
            .load_for_sid(sid)
            .map(|rows| {
                rows.into_iter()
                    .map(|row| VpnGatewayDto {
                        address: row.address.to_string(),
                        program: row.program,
                    })
                    .collect()
            })
            .map_err(|e| format!("{e:?}"))
    }

    fn replace(&self, sid: &str, gateways: &[VpnGatewayDto]) -> Result<(), String> {
        let rows: Vec<nrr_storage::VpnGatewayConfirmation> = gateways
            .iter()
            .filter_map(|g| {
                Some(nrr_storage::VpnGatewayConfirmation {
                    address: g.address.parse().ok()?,
                    program: g.program.clone(),
                })
            })
            .collect();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        nrr_storage::VpnGatewayConfirmationsRepository::new(&conn)
            .replace_for_sid(sid, &rows, now)
            .map_err(|e| format!("{e:?}"))
    }
}

/// Wire the process-wide book to the state database and to each user's
/// clients. Called once by each service's composition root.
pub fn wire_production(
    conn: Arc<Mutex<rusqlite::Connection>>,
    events: Arc<crate::ipc_handlers::event_bus::EventBus>,
) {
    let book = global_vpn_gateways();
    book.attach_store(Arc::new(StateDbVpnGatewayStore::new(conn)));
    // A full reset empties the cache too, or the erased rows would keep
    // enforcing until a restart.
    static HOLDER: OnceLock<Arc<dyn crate::principal_reset::PrincipalStateHolder>> =
        OnceLock::new();
    crate::principal_reset::register(HOLDER.get_or_init(|| Arc::new(BookHolder)));
    book.attach_push(Arc::new(move |sid: &str, gateways| {
        events.publish_for(
            sid,
            nrr_shared::ipc_payloads::StatusUpdateEvent::VpnGatewayAwaitingConfirmation {
                sid: sid.to_owned(),
                gateways,
            },
        );
    }));
}

struct BookHolder;

impl crate::principal_reset::PrincipalStateHolder for BookHolder {
    fn forget_principal(&self, sid: &str) {
        global_vpn_gateways().forget(sid);
    }

    fn forget_everyone(&self) {
        global_vpn_gateways().forget_everyone();
    }
}

/// The drop tick's sink into the process-wide book.
#[must_use]
pub fn production_drop_sink() -> crate::conn_observation_consumer::VpnGatewayDropFn {
    Arc::new(|sid: &str, address, program: Option<&str>| {
        global_vpn_gateways().note_drop(sid, address, program);
    })
}

/// The process-wide book: noted by the drop tick, read by the plan and the
/// snapshot, written by `route.vpn-gateways.set`.
pub fn global_vpn_gateways() -> &'static VpnGatewayBook {
    static BOOK: OnceLock<VpnGatewayBook> = OnceLock::new();
    BOOK.get_or_init(VpnGatewayBook::new)
}

fn bounded_program(program: &str) -> String {
    program
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(VPN_GATEWAY_PROGRAM_MAX_CHARS)
        .collect()
}

/// A `route.vpn-gateways.set` list as the service will keep it: each address
/// a routable unicast one in its canonical spelling, once; programs bounded.
/// Anything else refuses the whole request.
pub fn checked_gateways(
    request: &RouteVpnGatewaysSetRequest,
) -> Result<Vec<VpnGatewayDto>, String> {
    use nrr_domain::address_class::{classify, AddressClass};
    if request.gateways.len() > VPN_GATEWAYS_MAX {
        return Err(format!(
            "at most {VPN_GATEWAYS_MAX} VPN gateways, {} given",
            request.gateways.len()
        ));
    }
    let mut out: Vec<VpnGatewayDto> = Vec::with_capacity(request.gateways.len());
    for gateway in &request.gateways {
        let raw = gateway.address.trim();
        let address: IpAddr = raw
            .parse()
            .map_err(|_| format!("{raw:?} is not an IP address"))?;
        if classify(address) != AddressClass::Routable {
            return Err(format!("{address} is not an internet address"));
        }
        if gateway.program.chars().count() > VPN_GATEWAY_PROGRAM_MAX_CHARS
            || gateway.program.chars().any(char::is_control)
        {
            return Err("program name too long or not printable".into());
        }
        let address = address.to_string();
        if out.iter().any(|g| g.address == address) {
            continue;
        }
        out.push(VpnGatewayDto {
            address,
            program: gateway.program.trim().to_owned(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const SID: &str = "S-1-5-21-1-2-3-1001";
    const OTHER: &str = "S-1-5-21-1-2-3-1002";

    fn x() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20))
    }

    type Pushed = Arc<Mutex<Vec<(String, Vec<VpnGatewayDto>)>>>;

    fn pushes(book: &VpnGatewayBook) -> Pushed {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        book.attach_push(Arc::new(move |sid: &str, list| {
            sink.lock().unwrap().push((sid.to_owned(), list));
        }));
        seen
    }

    #[test]
    fn only_handshake_shaped_drops_count() {
        for port in VPN_HANDSHAKE_UDP_PORTS {
            assert!(handshake_shaped(TransportProtocol::Udp, port));
        }
        assert!(handshake_shaped(TransportProtocol::Other(50), 0));
        assert!(!handshake_shaped(TransportProtocol::Udp, 443));
        assert!(!handshake_shaped(TransportProtocol::Tcp, 500));
        assert!(!handshake_shaped(TransportProtocol::Other(47), 0));
    }

    #[test]
    fn a_kernel_built_packet_names_no_program() {
        let app = Some("/usr/bin/browser");
        assert_eq!(
            handshake_program(TransportProtocol::Udp, 4500, 4500, app),
            None
        );
        assert_eq!(
            handshake_program(TransportProtocol::Other(50), 0, 0, app),
            None
        );
        assert_eq!(
            handshake_program(TransportProtocol::Udp, 50123, 4500, Some("agent.exe")),
            Some("agent.exe")
        );
    }

    /// A drop on 4500 from an unknown program to X is one question, to that
    /// user only, however often it repeats.
    #[test]
    fn a_dropped_handshake_is_asked_once_and_only_of_its_user() {
        let book = VpnGatewayBook::new();
        let seen = pushes(&book);
        assert!(book.note_drop(SID, x(), Some("agent.exe")));
        assert!(!book.note_drop(SID, x(), Some("agent.exe")));
        assert!(!book.note_drop("", x(), None));
        let pushed = seen.lock().unwrap().clone();
        assert_eq!(pushed.len(), 1);
        assert_eq!(pushed[0].0, SID);
        assert_eq!(pushed[0].1[0].address, "203.0.113.20");
        assert!(book.pending_for(OTHER).is_empty());
    }

    /// A yes lets X through for that user alone and answers the question; a
    /// revoke takes it back.
    #[test]
    fn a_confirmation_exempts_that_address_and_a_revoke_removes_it() {
        let book = VpnGatewayBook::new();
        let seen = pushes(&book);
        book.note_drop(SID, x(), None);
        let checked = checked_gateways(&RouteVpnGatewaysSetRequest {
            gateways: book.pending_for(SID),
        })
        .expect("valid");
        book.replace_confirmed(SID, checked).expect("stored");
        assert_eq!(book.confirmed_addresses(SID), vec![x()]);
        assert!(book.confirmed_addresses(OTHER).is_empty());
        assert!(book.pending_for(SID).is_empty());
        assert_eq!(
            seen.lock().unwrap().last().map(|(_, l)| l.len()),
            Some(0),
            "the answered question is withdrawn from the user's clients"
        );
        assert!(
            !book.note_drop(SID, x(), None),
            "confirmed is not asked again"
        );

        book.replace_confirmed(SID, Vec::new()).expect("revoked");
        assert!(book.confirmed_addresses(SID).is_empty());
    }

    #[test]
    fn the_request_is_refused_whole_for_one_bad_entry() {
        let gateway = |address: &str| VpnGatewayDto {
            address: address.into(),
            program: String::new(),
        };
        for bad in [
            "127.0.0.1",
            "fe80::1",
            "224.0.0.5",
            "0.0.0.0",
            "255.255.255.255",
            "nonsense",
            "",
        ] {
            let request = RouteVpnGatewaysSetRequest {
                gateways: vec![gateway("203.0.113.20"), gateway(bad)],
            };
            assert!(checked_gateways(&request).is_err(), "{bad}");
        }
        let too_many = RouteVpnGatewaysSetRequest {
            gateways: (1..=VPN_GATEWAYS_MAX as u8 + 1)
                .map(|n| gateway(&format!("203.0.113.{n}")))
                .collect(),
        };
        assert!(checked_gateways(&too_many).is_err());
        let ok = checked_gateways(&RouteVpnGatewaysSetRequest {
            gateways: vec![gateway(" 2001:DB8:0::7 "), gateway("2001:db8::7")],
        })
        .expect("valid");
        assert_eq!(ok.len(), 1, "one entry per address");
        assert_eq!(ok[0].address, "2001:db8::7");
    }
}
