//! Recent connections, as the Diagnostics panel shows them, and what the
//! caller's last route outage blocked.

use super::*;

use nrr_shared::ipc_payloads::{
    ConnTraceOutageBlocksRequest, ConnTraceOutageBlocksResponse, OutageBlockDto, OutageEpisodeDto,
};

/// The local own-machine viewer shows real addresses and full exe paths, like
/// the cache viewer: the user needs to see WHICH address an app reached, and
/// masking it defeats the panel. Not gated on a diagnostic session for the
/// same reason the cache viewer is not.
const VIEWER_REDACTION: RedactionMode = RedactionMode::Diagnostics;

/// What both trace views consult per request: the "show the trace in the GUI"
/// switch and the inputs that name the rule behind an address.
#[derive(Clone, Default)]
struct TraceViewGates {
    /// Machine settings, consulted per request so the switch acts at once
    /// instead of at the next service start. It gates the ANSWER, never the
    /// observer: app-routing, FCrDNS learning and the VPN learners read the
    /// same observation stream and must keep running.
    gui_stream: Option<Arc<dyn ServiceStabilityConfigProvider>>,
    /// The active user's rule book + the FQDN cache yield the addresses a
    /// secondary rule currently owns. All-or-nothing: absent deps simply leave
    /// the rule fields empty.
    expectation: Option<ConnTraceExpectation>,
}

impl TraceViewGates {
    /// An absent provider means the deployment has no settings DB — answering
    /// is then the useful default.
    fn gui_stream_enabled(&self) -> bool {
        self.gui_stream
            .as_ref()
            .map(|s| s.get().conn_trace_gui)
            .unwrap_or(true)
    }

    /// What the active user's rules send over the secondary link, or `None`
    /// when the deps are absent, nobody is routing-active, or `only_for` names
    /// someone else — another user's rules say nothing about this user's rows.
    /// Built once per request, never per row.
    fn secondary_owners(&self, only_for: Option<&str>) -> Option<SecondaryAddressOwners> {
        let (rules, fqdn, active_sid) = self.expectation.as_ref()?;
        let sid = active_sid()?;
        if only_for.is_some_and(|caller| !caller.eq_ignore_ascii_case(&sid)) {
            return None;
        }
        let snapshot = rules.active_rules_for(&sid)?;
        Some(SecondaryAddressOwners::build(
            &snapshot.rule_book,
            fqdn.as_ref(),
        ))
    }
}

// ── ConnTraceEntriesListHandler ───────────────────────────────────────────

/// Read-only, paginated view of the connection-trace ring the
/// connection-observer feeds. Mirrors [`CacheEntriesListHandler`]: same
/// pagination cursor. Rows are scoped to the caller's diagnostics audience.
pub struct ConnTraceEntriesListHandler {
    ring: Arc<ConnectionTraceRing>,
    gates: TraceViewGates,
}

impl ConnTraceEntriesListHandler {
    pub fn new(ring: Arc<ConnectionTraceRing>) -> Self {
        Self {
            ring,
            gates: TraceViewGates::default(),
        }
    }

    /// Honour the user's "show connection trace in the GUI" switch. Without
    /// this the viewer answers regardless of the setting.
    pub fn with_gui_stream_gate(
        mut self,
        settings: Arc<dyn ServiceStabilityConfigProvider>,
    ) -> Self {
        self.gates.gui_stream = Some(settings);
        self
    }

    /// Stamp each row with where policy EXPECTS it to egress.
    pub fn with_route_expectation(
        mut self,
        rules: Arc<dyn RulesProvider>,
        fqdn: Arc<dyn FqdnCacheLookup>,
        active_sid: ActiveSidFn,
    ) -> Self {
        self.gates.expectation = Some((rules, fqdn, active_sid));
        self
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

/// An address as the viewers show it.
fn shown_ip(ip: std::net::IpAddr) -> String {
    redact_ipv4_str(&ip.to_string(), VIEWER_REDACTION).display_or_marker()
}

/// Whether `audience` may see a row owned by `owner`. Rows with no owner and
/// the service's own connections belong to the machine, not to a person; the
/// relay rows among the latter carry the caller's own traffic.
fn row_visible_to(
    audience: &DiagnosticsAudience,
    rec: &crate::conn_observation_consumer::ConnectionTraceRecord,
) -> bool {
    let Some(caller) = audience.principal() else {
        return true;
    };
    rec.user_sid
        .as_deref()
        .is_none_or(|owner| owner.is_empty() || owner.eq_ignore_ascii_case(caller))
        || is_own_service(&exe_name(rec.process_path.as_deref()))
}

impl IpcHandler for ConnTraceEntriesListHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        const OP: &str = "conn-trace.entries.list";
        let req: ConnTraceEntriesListRequest = if request.payload.is_null() {
            ConnTraceEntriesListRequest::default()
        } else {
            serde_json::from_value(request.payload.clone()).map_err(|e| malformed(OP, e))?
        };

        // The switch is off: answer with an empty page and say why, rather
        // than with rows the user asked not to be shown.
        if !self.gates.gui_stream_enabled() {
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

        let limit = req.pagination.effective_page_size();
        let offset = req
            .pagination
            .cursor
            .as_ref()
            .and_then(|c| c.parse())
            .map(|(o, _)| o.max(0) as u32)
            .unwrap_or(0);

        // Derived from the connection, never from the request: another user's
        // rows name their programs and destinations.
        let audience = ctx.diagnostics_audience();
        // Newest-first; fetch `limit + 1` so the extra row signals another page.
        let rows = self
            .ring
            .snapshot_where(offset as usize, limit as usize + 1, |rec| {
                row_visible_to(&audience, rec)
            });
        let has_more = rows.len() as u32 > limit;

        let fmt_addr = |sa: &std::net::SocketAddr| -> String {
            format!("{}:{}", shown_ip(sa.ip()), sa.port())
        };

        // Built ONCE per page. A row whose remote it owns is EXPECTED to
        // egress the secondary link; the GUI flags expected=secondary +
        // egress=primary permits as leaks.
        let secondary_owners = self.gates.secondary_owners(None);
        // The same owners answer both questions: whether policy expects this
        // remote on the secondary link, and — for a flow the service itself
        // opened — whose traffic it is carrying.
        let owner_of = |remote: &std::net::SocketAddr| -> Option<String> {
            secondary_owners
                .as_ref()?
                .owner_of(remote.ip())
                .map(std::borrow::Cow::into_owned)
        };
        let expected_route = |remote: &std::net::SocketAddr, owned: bool| -> String {
            if owned {
                "secondary".to_string()
            } else if remote.is_ipv6() {
                // Host and literal owners are IPv4-only, so an IPv6 remote no
                // network claims says so instead of reading as uncovered.
                "ipv6".to_string()
            } else {
                String::new()
            }
        };

        let items: Vec<ConnTraceEntryDto> = rows
            .into_iter()
            .take(limit as usize)
            .map(|r| {
                let owner = owner_of(&r.remote);
                ConnTraceEntryDto {
                    relay_for: match owner.as_ref() {
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
                    expected_route: expected_route(&r.remote, owner.is_some()),
                    rule_host: owner.unwrap_or_default(),
                    observed_at_ms: r.observed_unix_ms.map(|v| v as i64).unwrap_or(0),
                    remote_hosts: r
                        .remote_names
                        .as_ref()
                        .map(|n| n.names.clone())
                        .unwrap_or_default(),
                    remote_host_count: r.remote_names.as_ref().map_or(0, |n| n.total),
                    remote_host_floor: r
                        .remote_names
                        .as_ref()
                        .and_then(|n| n.names.first())
                        .and_then(|name| nrr_domain::companion_affinity::registrable_domain(name))
                        .unwrap_or_default()
                        .to_string(),
                    remote_fake_ip: r.remote_names.as_ref().is_some_and(|n| n.fake_ip),
                }
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
            // Never redacted (see `VIEWER_REDACTION`), so the GUI's
            // "addresses masked" notice stays hidden.
            redacted: false,
            observer_active: self.ring.observer_active(),
            gui_stream_enabled: true,
        };
        serialise(OP, &response)
    }
}

// ── ConnTraceOutageBlocksListHandler ──────────────────────────────────────

/// What leak protection blocked during the caller's last outage of the
/// additional route. Always the caller's own: the request names nobody, and
/// an elevated caller sees only their own list too — the list is the
/// counterpart of their own block notice, not a machine log.
pub struct ConnTraceOutageBlocksListHandler {
    ring: Arc<ConnectionTraceRing>,
    gates: TraceViewGates,
}

impl ConnTraceOutageBlocksListHandler {
    pub fn new(ring: Arc<ConnectionTraceRing>) -> Self {
        Self {
            ring,
            gates: TraceViewGates::default(),
        }
    }

    /// Honour the "show connection trace in the GUI" switch, as the trace does.
    pub fn with_gui_stream_gate(
        mut self,
        settings: Arc<dyn ServiceStabilityConfigProvider>,
    ) -> Self {
        self.gates.gui_stream = Some(settings);
        self
    }

    /// Name the secondary rule behind each address, as the trace does.
    pub fn with_route_expectation(
        mut self,
        rules: Arc<dyn RulesProvider>,
        fqdn: Arc<dyn FqdnCacheLookup>,
        active_sid: ActiveSidFn,
    ) -> Self {
        self.gates.expectation = Some((rules, fqdn, active_sid));
        self
    }
}

fn wire_ms(ms: u64) -> i64 {
    i64::try_from(ms).unwrap_or(i64::MAX)
}

impl IpcHandler for ConnTraceOutageBlocksListHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        const OP: &str = "conn-trace.outage-blocks.list";
        if !request.payload.is_null() {
            let _: ConnTraceOutageBlocksRequest =
                serde_json::from_value(request.payload.clone()).map_err(|e| malformed(OP, e))?;
        }
        let outages = self.ring.outage_blocks();
        let observer_active = self.ring.observer_active() && outages.is_fed();
        let empty = |gui_stream_enabled: bool| ConnTraceOutageBlocksResponse {
            episode: None,
            entries: Vec::new(),
            omitted: 0,
            redacted: false,
            observer_active,
            gui_stream_enabled,
        };
        if !self.gates.gui_stream_enabled() {
            return serialise(OP, empty(false));
        }
        // An unattributed caller owns nothing; the empty principal is not a
        // key anyone's drops are filed under.
        let caller = ctx.caller_stored();
        if caller.is_empty() {
            return serialise(OP, empty(true));
        }
        let snapshot = outages.snapshot(caller);
        let owners = self.gates.secondary_owners(Some(caller));
        let entries = snapshot
            .entries
            .into_iter()
            .map(|e| OutageBlockDto {
                process: match e.process_path.as_deref() {
                    Some(path) => exe_name(Some(path)),
                    None => e.process,
                },
                process_path: e.process_path.unwrap_or_default(),
                remote_ip: shown_ip(e.remote.ip()),
                remote_port: e.remote.port(),
                host: e.host.unwrap_or_default(),
                rule_host: owners
                    .as_ref()
                    .and_then(|o| o.owner_of(e.remote.ip()))
                    .map(std::borrow::Cow::into_owned)
                    .unwrap_or_default(),
                first_seen_ms: wire_ms(e.first_seen_ms),
                last_seen_ms: wire_ms(e.last_seen_ms),
                attempts: e.attempts,
            })
            .collect();
        serialise(
            OP,
            &ConnTraceOutageBlocksResponse {
                episode: snapshot.episode.map(|ep| OutageEpisodeDto {
                    since_unix_ms: wire_ms(ep.since_ms),
                    until_unix_ms: ep.until_ms.map(wire_ms),
                }),
                entries,
                omitted: snapshot.omitted,
                redacted: false,
                observer_active,
                gui_stream_enabled: true,
            },
        )
    }
}
