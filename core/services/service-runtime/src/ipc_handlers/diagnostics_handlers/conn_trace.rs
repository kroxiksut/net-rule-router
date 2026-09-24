//! Recent connections, as the Diagnostics panel shows them.
//!
//! Split out of `diagnostics_handlers`; the code is unchanged.

use super::*;

// ── ConnTraceEntriesListHandler ───────────────────────────────────────────

/// Read-only, paginated view of the connection-trace ring the
/// connection-observer feeds. Mirrors [`CacheEntriesListHandler`]: same
/// pagination cursor. The local own-machine viewer is never redacted (real
/// remote/local IPs + full exe path), so it does not need the diagnostics
/// facade for a redaction tier.
pub struct ConnTraceEntriesListHandler {
    ring: Arc<ConnectionTraceRing>,
    /// Machine settings, consulted per request so the "show the trace in the
    /// GUI" switch acts at once instead of at the next service start. It gates
    /// the ANSWER, never the observer: app-routing, FCrDNS learning and the
    /// VPN learners read the same observation stream and must keep running.
    gui_stream: Option<Arc<dyn ServiceStabilityConfigProvider>>,
    /// Optional inputs for the `expected_route` stamp: the active
    /// user's rule book + the FQDN cache yield the set of IPv4s a secondary
    /// rule currently owns, so each trace row can carry where policy EXPECTS
    /// it to egress. All-or-nothing: absent deps simply leave the field empty.
    expectation: Option<ConnTraceExpectation>,
}

impl ConnTraceEntriesListHandler {
    pub fn new(ring: Arc<ConnectionTraceRing>) -> Self {
        Self {
            ring,
            gui_stream: None,
            expectation: None,
        }
    }

    /// Honour the user's "show connection trace in the GUI" switch. Without
    /// this the viewer answers regardless of the setting.
    pub fn with_gui_stream_gate(
        mut self,
        settings: Arc<dyn ServiceStabilityConfigProvider>,
    ) -> Self {
        self.gui_stream = Some(settings);
        self
    }

    /// Whether the viewer may answer at all. An absent provider means the
    /// deployment has no settings DB — answering is then the useful default.
    fn gui_stream_enabled(&self) -> bool {
        self.gui_stream
            .as_ref()
            .map(|s| s.get().conn_trace_gui)
            .unwrap_or(true)
    }

    /// Enable the expected-route stamp (see the struct field doc).
    pub fn with_route_expectation(
        mut self,
        rules: Arc<dyn RulesProvider>,
        fqdn: Arc<dyn FqdnCacheLookup>,
        active_sid: ActiveSidFn,
    ) -> Self {
        self.expectation = Some((rules, fqdn, active_sid));
        self
    }

    /// The secondary-owned IPv4 set for the active user, or `None` when the
    /// expectation deps are absent / no user is routing-active. Built once per
    /// page request (bounded by the owners fan-out cap), never per row.
    fn secondary_owned_ips(&self) -> Option<std::collections::HashMap<std::net::Ipv4Addr, String>> {
        let (rules, fqdn, active_sid) = self.expectation.as_ref()?;
        let sid = active_sid()?;
        let snapshot = rules.active_rules_for(&sid)?;
        Some(build_secondary_ip_owners(
            &snapshot.rule_book.secondary,
            fqdn.as_ref(),
        ))
    }
}

/// True when the trace row belongs to our own service process. The fake-IP
/// relay dials the real destination from here, so such a row is traffic carried
/// for an application, not the service's own errand.
fn is_own_service(process: &str) -> bool {
    let service = nrr_shared::product_identity::BinaryRole::Service;
    [service.windows_file_name(), service.unix_file_name()]
        .iter()
        .any(|name| process.eq_ignore_ascii_case(name))
}

/// Executable name from a device/NT path (`\device\…\chrome.exe` → `chrome.exe`).
fn exe_name(path: Option<&str>) -> String {
    match path {
        Some(p) => p
            .rsplit(['\\', '/'])
            .find(|s| !s.is_empty())
            .unwrap_or(p)
            .to_string(),
        None => "?".to_string(),
    }
}

impl IpcHandler for ConnTraceEntriesListHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        const OP: &str = "conn-trace.entries.list";
        let req: ConnTraceEntriesListRequest = if request.payload.is_null() {
            ConnTraceEntriesListRequest::default()
        } else {
            serde_json::from_value(request.payload.clone()).map_err(|e| malformed(OP, e))?
        };

        // The switch is off: answer with an empty page and say why, rather
        // than with rows the user asked not to be shown.
        if !self.gui_stream_enabled() {
            return serialise(
                OP,
                &ConnTraceEntriesListResponse {
                    page: PageResult {
                        items: Vec::new(),
                        next_cursor: None,
                        total_count: None,
                        stale: false,
                    },
                    redacted: false,
                    observer_active: self.ring.observer_active(),
                    gui_stream_enabled: false,
                },
            );
        }

        // This is the user's own-machine connection viewer (per-SID,
        // DACL-protected local pipe), so show real remote/local IPs and the
        // full exe path, exactly like the cache viewer. The user needs to see
        // WHICH IP an app reached; masking it to `<public-ipv4>` defeats the
        // panel. Not gated on a diagnostic session for the same reason the
        // cache viewer is not.
        let mode = RedactionMode::Diagnostics;

        let limit = req.pagination.effective_page_size();
        let offset = req
            .pagination
            .cursor
            .as_ref()
            .and_then(|c| c.parse())
            .map(|(o, _)| o.max(0) as u32)
            .unwrap_or(0);

        // Newest-first; fetch `limit + 1` so the extra row signals another page.
        let (rows, _total) = self.ring.snapshot(offset as usize, limit as usize + 1);
        let has_more = rows.len() as u32 > limit;

        let fmt_addr = |sa: &std::net::SocketAddr| -> String {
            let ip = redact_ipv4_str(&sa.ip().to_string(), mode).display_or_marker();
            format!("{ip}:{}", sa.port())
        };

        // The secondary-owned IPv4 set, built ONCE per page. A row
        // whose remote is in this set is EXPECTED to egress the secondary link;
        // the GUI flags expected=secondary + egress=primary permits as leaks.
        let secondary_owned = self.secondary_owned_ips();
        // The same map answers both questions: whether policy expects this
        // remote on the secondary link, and — for a flow the service itself
        // opened — whose traffic it is carrying.
        let owner_of = |remote: &std::net::SocketAddr| -> Option<&String> {
            match (remote.ip(), secondary_owned.as_ref()) {
                (std::net::IpAddr::V4(v4), Some(owned)) => owned.get(&v4),
                _ => None,
            }
        };
        let expected_route = |remote: &std::net::SocketAddr| -> String {
            match owner_of(remote) {
                Some(_) => "secondary".to_string(),
                // An IPv6 remote is not "no rule covers it" — no rule CAN, the
                // family is not routed in this edition. Say which of the two it
                // is instead of letting the row read as an uncovered host.
                None if remote.is_ipv6() => "ipv6".to_string(),
                None => String::new(),
            }
        };

        let items: Vec<ConnTraceEntryDto> = rows
            .into_iter()
            .take(limit as usize)
            .map(|r| ConnTraceEntryDto {
                relay_for: match owner_of(&r.remote) {
                    Some(host) if is_own_service(&exe_name(r.process_path.as_deref())) => {
                        host.clone()
                    }
                    _ => String::new(),
                },
                process: exe_name(r.process_path.as_deref()),
                process_path: r.process_path.clone().unwrap_or_default(),
                proto: proto_str(r.protocol).to_string(),
                local: fmt_addr(&r.local),
                remote: fmt_addr(&r.remote),
                egress_role: role_str(r.egress.role).to_string(),
                egress_ifindex: r.egress.ifindex,
                verdict: verdict_str(r.verdict).to_string(),
                blocked_by: match r.blocked_by_nrr {
                    Some(true) => "netrulerouter".to_string(),
                    Some(false) => "other".to_string(),
                    None => String::new(),
                },
                block_reason: r.nrr_block_reason.unwrap_or_default().to_string(),
                rule_host: owner_of(&r.remote).cloned().unwrap_or_default(),
                expected_route: expected_route(&r.remote),
                observed_at_ms: r.observed_unix_ms.map(|v| v as i64).unwrap_or(0),
            })
            .collect();

        let next_cursor = if has_more {
            Some(PageCursor::from_position(
                i64::from(offset) + i64::from(limit),
                "conn-trace",
            ))
        } else {
            None
        };

        let response = ConnTraceEntriesListResponse {
            page: PageResult {
                items,
                next_cursor,
                total_count: None,
                stale: false,
            },
            // Never redacted: local own-machine viewer
            // shows real addresses (see the mode note above). The GUI's
            // "addresses masked" notice therefore stays hidden.
            redacted: false,
            observer_active: self.ring.observer_active(),
            gui_stream_enabled: true,
        };
        serialise(OP, &response)
    }
}
