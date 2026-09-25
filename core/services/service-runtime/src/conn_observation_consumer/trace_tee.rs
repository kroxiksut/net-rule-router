//! Trace rows for connections another task already drains.
//!
//! Where the source is drained by the application-destination tick, a second
//! drain would split its events between two readers. The tick hands its batch
//! here instead, and the panel sees the same connections the app rules learn
//! from, labelled by the same pure classification the full consumer uses.

use std::collections::HashMap;

use nrr_platform_api::enforcement::{EgressBindingSource, UserPrincipal};

use super::*;

pub struct ConnTraceTee {
    ring: Arc<ConnectionTraceRing>,
    api: Arc<dyn RouteTablePort>,
    bindings: Arc<dyn EgressBindingSource>,
}

impl ConnTraceTee {
    /// Marks the ring as fed: the tee exists only where a source runs.
    pub fn new(
        ring: Arc<ConnectionTraceRing>,
        api: Arc<dyn RouteTablePort>,
        bindings: Arc<dyn EgressBindingSource>,
    ) -> Self {
        ring.mark_observer_active();
        Self {
            ring,
            api,
            bindings,
        }
    }

    pub fn ring(&self) -> Arc<ConnectionTraceRing> {
        Arc::clone(&self.ring)
    }

    /// Append one row per connection in `batch`, stamped `now_ms` when the
    /// backend gave no time of its own.
    pub fn record(&self, batch: &[ConnectionObservation], now_ms: u64) {
        let mut attempts = batch
            .iter()
            .filter(|o| o.progress == ConnectionProgress::Attempt)
            .peekable();
        if attempts.peek().is_none() {
            return;
        }
        let adapters = self.api.get_adapter_infos().unwrap_or_default();
        let mut unicast = self.api.unicast_ip_addresses().unwrap_or_default();
        if unicast.is_empty() {
            unicast = build_unicast_table(&adapters);
        }
        // Each connection is labelled against its OWN user's bindings: two
        // people on one machine can bind different links.
        let mut roles: HashMap<&str, (Option<u32>, Option<u32>)> = HashMap::new();
        for obs in attempts {
            let (primary, secondary) = match obs.user_sid.as_deref() {
                Some(sid) => *roles
                    .entry(sid)
                    .or_insert_with(|| self.bound_ifindexes(sid, &adapters)),
                None => (None, None),
            };
            let mut rec = classify_connection(obs, &unicast, primary, secondary);
            rec.observed_unix_ms.get_or_insert(now_ms);
            self.ring.push(rec);
        }
    }

    fn bound_ifindexes(&self, sid: &str, adapters: &[AdapterInfo]) -> (Option<u32>, Option<u32>) {
        let Ok(principal) = UserPrincipal::from_stored(sid) else {
            return (None, None);
        };
        let binding = self.bindings.bindings_for(&principal);
        let index_of = |name: Option<String>| {
            let name = name?;
            adapters
                .iter()
                .find(|a| a.friendly_name == name || a.adapter_name == name)
                .map(|a| a.index)
        };
        (index_of(binding.primary), index_of(binding.secondary))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::adapters::{IfOperStatus, InterfaceType};
    use nrr_platform_api::conn_observe::TransportProtocol;
    use nrr_platform_api::enforcement::EgressBinding;
    use nrr_platform_api::windows_api::MockWindowsApi;
    use std::net::Ipv4Addr;

    struct Bound;
    impl EgressBindingSource for Bound {
        fn bindings_for(&self, _principal: &UserPrincipal) -> EgressBinding {
            EgressBinding {
                primary: Some("eth0".into()),
                secondary: Some("wg0".into()),
            }
        }
    }

    fn adapter(index: u32, name: &str, ip: Ipv4Addr) -> AdapterInfo {
        AdapterInfo {
            index,
            adapter_name: name.into(),
            description: name.into(),
            friendly_name: name.into(),
            mac: None,
            interface_type: InterfaceType::Ethernet,
            oper_status: IfOperStatus::Up,
            ipv4_addresses: vec![ip],
            ipv6_addresses: Vec::new(),
            gateways: Vec::new(),
        }
    }

    fn observation(local: Ipv4Addr, progress: ConnectionProgress) -> ConnectionObservation {
        ConnectionObservation {
            pid: 7,
            process_path: Some("/usr/bin/app".into()),
            user_sid: Some(UserPrincipal::from_linux_uid(1000).as_stored().to_owned()),
            protocol: TransportProtocol::Tcp,
            local: SocketAddr::new(IpAddr::V4(local), 40000),
            remote: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443),
            verdict: ConnectionVerdict::Unknown,
            drop_filter_id: None,
            blocked_by_nrr: None,
            nrr_drop_spec_id: None,
            observed_unix_ms: None,
            progress,
        }
    }

    #[test]
    fn a_connection_is_labelled_by_the_link_its_user_bound() {
        let api = MockWindowsApi::new();
        api.set_adapter_infos(vec![
            adapter(2, "eth0", Ipv4Addr::new(192, 168, 0, 5)),
            adapter(9, "wg0", Ipv4Addr::new(10, 8, 0, 2)),
        ]);
        let ring = Arc::new(ConnectionTraceRing::new(8));
        let tee = ConnTraceTee::new(Arc::clone(&ring), Arc::new(api), Arc::new(Bound));

        tee.record(
            &[
                observation(Ipv4Addr::new(10, 8, 0, 2), ConnectionProgress::Attempt),
                observation(Ipv4Addr::new(192, 168, 0, 5), ConnectionProgress::Attempt),
                observation(
                    Ipv4Addr::new(192, 168, 0, 5),
                    ConnectionProgress::ClosedInOrder,
                ),
            ],
            1234,
        );

        assert!(ring.observer_active());
        let (rows, total) = ring.snapshot(0, 8);
        assert_eq!(
            total, 2,
            "only connections become rows, not evidence about them"
        );
        assert_eq!(rows[0].egress.role, EgressRole::Primary);
        assert_eq!(rows[1].egress.role, EgressRole::Secondary);
        assert_eq!(rows[1].observed_unix_ms, Some(1234));
    }
}
