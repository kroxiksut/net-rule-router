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
    /// Whether each row is also written to the operational log. Shared with
    /// the settings writer so a save applies without a restart.
    log_ndjson: Arc<AtomicBool>,
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
            log_ndjson: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Follow the live "write the trace to the log" switch.
    #[must_use]
    pub fn with_log_ndjson_flag(mut self, flag: Arc<AtomicBool>) -> Self {
        self.log_ndjson = flag;
        self
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
        let log_ndjson = self.log_ndjson.load(Ordering::Relaxed);
        for obs in attempts {
            let (primary, secondary) = match obs.user_sid.as_deref() {
                Some(sid) => *roles
                    .entry(sid)
                    .or_insert_with(|| self.bound_ifindexes(sid, &adapters)),
                None => (None, None),
            };
            let mut rec = classify_connection(obs, &unicast, primary, secondary);
            rec.observed_unix_ms.get_or_insert(now_ms);
            if log_ndjson {
                log_observed_connection(&rec);
            }
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

    /// The log line is the one the full consumer writes, owned by the
    /// connection's user so a log read scoped to them returns it — and it is
    /// written only while the switch is on.
    #[test]
    fn a_logged_row_is_its_users_line_and_follows_the_switch() {
        use tracing_subscriber::layer::SubscriberExt;

        let api = MockWindowsApi::new();
        api.set_adapter_infos(vec![adapter(2, "eth0", Ipv4Addr::new(192, 168, 0, 5))]);
        let flag = Arc::new(AtomicBool::new(false));
        let tee = ConnTraceTee::new(
            Arc::new(ConnectionTraceRing::new(8)),
            Arc::new(api),
            Arc::new(Bound),
        )
        .with_log_ndjson_flag(Arc::clone(&flag));
        let dir = tempfile::TempDir::new().expect("temp dir");
        let writer = Arc::new(nrr_diagnostics::LogWriter::open(
            nrr_diagnostics::LogWriterConfig::new(dir.path()),
        ));
        let subscriber = tracing_subscriber::registry().with(
            nrr_diagnostics::NdjsonTracingLayer::new(Arc::clone(&writer)),
        );
        let attempt = [observation(
            Ipv4Addr::new(192, 168, 0, 5),
            ConnectionProgress::Attempt,
        )];
        tracing::subscriber::with_default(subscriber, || {
            tee.record(&attempt, 1);
            flag.store(true, Ordering::Relaxed);
            tee.record(&attempt, 2);
        });

        let mut owners = Vec::new();
        for entry in std::fs::read_dir(dir.path()).expect("logs dir") {
            let text = std::fs::read_to_string(entry.expect("entry").path()).expect("read");
            for line in text.lines() {
                let v: serde_json::Value = serde_json::from_str(line).expect("ndjson line");
                if v["message_key"] == "diag.event.connobs-outbound-connection-observed" {
                    owners.push(v["principal"].as_str().unwrap_or_default().to_string());
                }
            }
        }
        assert_eq!(
            owners,
            vec![UserPrincipal::from_linux_uid(1000).as_stored().to_string()],
            "one line, written after the switch, owned by the connection's user"
        );
    }
}
