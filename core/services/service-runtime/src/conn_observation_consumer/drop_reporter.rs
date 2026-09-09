//! Why a connection was dropped, said once.
//!
//! A blocked connection produces one notice and one log line, not one per
//! retry: the same host is re-tried for as long as the user keeps clicking,
//! and without the once-per-key latch the operational log becomes the
//! drop's own denial of service. Tearing a flow down is tracked here too,
//! because 'was this already torn down' is the same question.
//!
//! Same inherent impl, split across files. Behaviour is unchanged.

use super::*;

impl ConnectionObservationConsumer {
    /// Destinations whose flows this session already tore down once — the fact
    /// that separates "socket older than the pin" from "the application holds a
    /// pre-rule DNS answer". Bounded like every other per-session set here.
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn note_torn_down(&self, ip: std::net::Ipv4Addr) {
        let mut seen = self
            .torn_down_before
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if seen.len() >= COMPANION_REPORT_CAP {
            seen.clear();
        }
        seen.insert(ip);
    }

    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn was_torn_down_before(&self, ip: std::net::Ipv4Addr) -> bool {
        self.torn_down_before
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains(&ip)
    }

    /// Did traffic leave over the secondary link recently enough that a direct
    /// connection now is plausibly part of the same page?
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn beside_routed_traffic(&self) -> bool {
        self.last_secondary_at
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_some_and(|at| at.elapsed() <= COMPANION_WINDOW)
    }

    /// Did the DoH/DoT lockdown band produce this drop? Read by the notice
    /// reason and by the FCrDNS gate, which must not name a resolver the
    /// lockdown just cut.
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn is_dns_lockdown_drop(&self, rec: &ConnectionTraceRecord) -> bool {
        rec.nrr_drop_spec_id
            .zip(self.dns_lockdown_drop_check.as_ref())
            .is_some_and(|(spec_id, check)| check(spec_id))
    }

    /// Turn one OUR-attributed Block into a `BlockAttempt` and hand it to the
    /// wired sink. A foreign filter (`blocked_by_nrr == Some(false)`) never
    /// reaches this method — see the `consume` call site — because blaming
    /// our policy for someone else's firewall would be actively wrong.
    /// `default_block_id` is the deterministic id of the "no rule covers this
    /// host" catch-all for the active SID (see `block_reason_for`).
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn note_block_attempt(
        &self,
        rec: &ConnectionTraceRecord,
        killswitch_verified: bool,
        default_block_id: Option<u64>,
    ) {
        let Some(sink) = self.block_notice_sink.as_ref() else {
            return;
        };
        // Discovery, neighbour upkeep, address configuration: no site behind
        // it and no rule the user could write about it. The drop still shows
        // up in the trace line above — only the news is withheld.
        if nrr_domain::address_class::is_local_housekeeping_endpoint(
            rec.remote.ip(),
            rec.remote.port(),
        ) {
            return;
        }
        let ipv6_cut = rec
            .nrr_drop_spec_id
            .zip(self.ipv6_cut_drop_check.as_ref())
            .is_some_and(|(spec_id, check)| check(spec_id));
        let dns_lockdown = self.is_dns_lockdown_drop(rec);
        let armed = self.fail_closed_armed.as_ref().is_some_and(|armed| armed());
        let reason = block_reason_for(
            rec.nrr_drop_spec_id,
            killswitch_verified,
            default_block_id,
            armed,
            ipv6_cut,
            dns_lockdown,
        );
        // The outage is one fact about the machine, not one fact per
        // application that ran into it. A disarmed block-all means the wait is
        // over, so the next one is news again — this is also what keeps the
        // latch from surviving a link that came back while nothing was trying.
        if !armed {
            self.outage_announced
                .store(false, std::sync::atomic::Ordering::Relaxed);
        }
        if !nrr_domain::block_notice::announces_individually(
            reason,
            self.outage_announced
                .load(std::sync::atomic::Ordering::Relaxed),
        ) {
            return;
        }
        // Latched by the notice that actually announces the outage — not by
        // any drop that happens to land while one is armed. Marking it on a
        // rule-block would swallow the outage notice that follows.
        if reason == nrr_domain::block_notice::BlockReason::RouteUnavailable {
            self.outage_announced
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        let host = match rec.remote.ip() {
            IpAddr::V4(ip) => self
                .block_notice_name_for_address
                .as_ref()
                .and_then(|name_of| name_of(ip)),
            IpAddr::V6(_) => None,
        };
        let app = rec
            .process_path
            .as_deref()
            .map(process_basename_lower)
            .filter(|s| !s.is_empty());
        sink(
            rec.user_sid.as_deref().unwrap_or_default(),
            BlockAttempt {
                host,
                dest: rec.remote.ip().to_string(),
                app,
                reason,
            },
        );
    }

    /// Detail-log ONE blocked connection, once per
    /// `(process, remote ip, remote port)` triple per session (debug on
    /// repeats). Unconditional — NOT gated on `log_ndjson`: attributed drops
    /// are the single most valuable diagnostic line this observer produces,
    /// and the once-per-triple gate keeps the volume bounded.
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn log_drop_once(&self, rec: &ConnectionTraceRecord, drop_filter_id: Option<u64>) {
        let process = rec.process_path.as_deref().unwrap_or("?");
        let key = (
            process_basename_lower(process),
            rec.remote.ip(),
            rec.remote.port(),
        );
        let first = {
            let mut g = self.drop_logged.lock().unwrap_or_else(|p| p.into_inner());
            if g.len() >= DROP_LOG_KEY_CAP {
                g.clear();
            }
            g.insert(key)
        };
        let owner = match rec.blocked_by_nrr {
            Some(true) => "nrr",
            Some(false) => "foreign",
            None => "unknown",
        };
        // What the destination IS, when it is a well-known group rather than a
        // site — the line for `ff02::fb` is unreadable without it.
        let purpose =
            nrr_domain::address_class::well_known_purpose(rec.remote.ip(), rec.remote.port())
                .unwrap_or("");
        if first {
            tracing::info!(
                target: "nrr::conn-trace",
                remote_ip = %rec.remote.ip(),
                remote_port = rec.remote.port(),
                protocol = proto_str(rec.protocol),
                process = process,
                blocked_by = owner,
                purpose,
                drop_filter_id = drop_filter_id.unwrap_or(0),
                // The reason is decided from the SPEC id, not the runtime one:
                // without it a line cannot tell "filter unidentified" from
                // "identified, and none of the bands we can name".
                spec_id = rec.nrr_drop_spec_id.unwrap_or(0),
                "observed BLOCKED connection (first per app/destination this session)",
            );
        } else {
            tracing::debug!(
                target: "nrr::conn-trace",
                remote_ip = %rec.remote.ip(),
                remote_port = rec.remote.port(),
                process = process,
                blocked_by = owner,
                purpose,
                "observed blocked connection (repeat)",
            );
        }
    }
}
