//! What a companion address did, reported back.
//!
//! Two sinks the companion-affinity engine reads: whether an address the
//! engine is watching carried traffic, and whether it stalled on the main
//! route. Neither decides anything here — they are observations handed
//! upward, which is why they sit apart from the drop path.
//!
//! Same inherent impl, split across files. Behaviour is unchanged.

use super::*;

impl ConnectionObservationConsumer {
    /// A resend or an orderly close on the primary link, reported as at most
    /// one outcome per connection: the verdict counts connections, and one loss
    /// burst resends many segments at once. NOT deduped per address — the
    /// verdict is built from how often each outcome happened.
    // `pub(super)`: the impl is split across files.
    pub(super) fn note_companion_primary_health(&self, obs: &ConnectionObservation, now_ms: u64) {
        if self.companion_primary_health.is_none() && self.app_main_link.is_none() {
            return;
        }
        let IpAddr::V4(ip) = obs.remote.ip() else {
            return;
        };
        let at_ms = obs.observed_unix_ms.unwrap_or(now_ms);
        let Some(stalled) = self
            .primary_stall_evidence
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .note(obs.local, obs.remote, obs.progress, at_ms)
        else {
            return;
        };
        // Rule hosts first, then the rule-less ones. A host with a rule
        // is named by the memory that also drives enforcement; anything
        // else is named only well enough to be talked about.
        let hostname = self
            .name_for_address
            .as_ref()
            .and_then(|name_of| name_of(ip))
            .or_else(|| {
                self.health_name_fallback
                    .as_ref()
                    .and_then(|name_of| name_of(ip))
            });
        if let Some(app) = self.app_main_link.as_ref() {
            let program = self
                .connection_programs
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(&(obs.local, obs.remote))
                .map(|(program, _)| program.clone());
            if let Some(program) = program {
                app(&program, obs.remote.ip(), stalled, hostname.is_some());
            }
        }
        if let (Some(sink), Some(hostname)) = (self.companion_primary_health.as_ref(), hostname) {
            sink(&hostname, stalled);
        }
    }

    /// Which program opened this connection, for the application measure: the
    /// stack's resends and closes carry only a pid, and by then it may be gone.
    /// The operating system's own programs and tunnel clients are never
    /// offered, so they are not remembered.
    pub(super) fn remember_program(&self, rec: &super::ConnectionTraceRecord, at_ms: u64) {
        const MAX_REMEMBERED: usize = 4096;
        const REMEMBERED_MS: u64 = 120_000;
        if self.app_main_link.is_none() {
            return;
        }
        let Some(path) = rec.process_path.as_deref() else {
            return;
        };
        if nrr_domain::app_offer::is_os_program(path)
            || super::connection_facts::process_name_matches_vpn(Some(path))
        {
            return;
        }
        let program = nrr_domain::app_offer::program_name(path);
        if program.is_empty() {
            return;
        }
        let mut programs = self
            .connection_programs
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if programs.len() >= MAX_REMEMBERED {
            programs.retain(|_, (_, at)| at_ms.saturating_sub(*at) < REMEMBERED_MS);
            if programs.len() >= MAX_REMEMBERED {
                programs.clear();
            }
        }
        programs.insert((rec.local, rec.remote), (program, at_ms));
    }

    /// One outbound connection attempt, reported to the navigation measure.
    ///
    /// Named through the same two sources the health path uses, so a
    /// destination the measure can talk about is exactly one the verdict can
    /// talk about. An unnamed one is still reported: it cannot credit a host,
    /// but it is part of its process's burst, and that is what says whether
    /// the named connection beside it was a page load.
    pub(super) fn note_navigation_attempt(
        &self,
        process: Option<&str>,
        remote: IpAddr,
        at_ms: u64,
    ) {
        let Some(sink) = self.navigation_attempt.as_ref() else {
            return;
        };
        let hostname = match remote {
            IpAddr::V4(ip) => self
                .name_for_address
                .as_ref()
                .and_then(|name_of| name_of(ip))
                .or_else(|| {
                    self.health_name_fallback
                        .as_ref()
                        .and_then(|name_of| name_of(ip))
                }),
            IpAddr::V6(_) => None,
        };
        sink(process, hostname.as_deref(), at_ms);
    }

    /// Somebody went to a censored host: this connection is to an address a
    /// provider placeholder just handed out. Until now that answer alone was
    /// enough to offer the host, which turned a page's prefetch into a
    /// suggestion for a site nobody had opened.
    ///
    /// Called for every observation, established or not — see the caller.
    pub(super) fn confirm_placeholder_use(&self, remote: IpAddr, at_ms: u64) {
        let Some(sink) = self.placeholder_confirmed.as_ref() else {
            return;
        };
        let IpAddr::V4(ip) = remote else {
            return;
        };
        if let Some(host) =
            crate::placeholder_waitlist::global_placeholder_waitlist().confirm(ip, at_ms)
        {
            tracing::debug!(
                target: "nrr::auto-rules",
                host = %host,
                address = %ip,
                "a censored host was actually connected to - its offer may be parked now",
            );
            sink(&host);
        }
    }

    /// One connection that left over the primary link: if we can name its
    /// destination, that name is a companion the user's traffic reached the
    /// wrong way.
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn note_companion_in_use(&self, remote: IpAddr) {
        let (Some(name_of), Some(sink)) = (
            self.name_for_address.as_ref(),
            self.companion_in_use.as_ref(),
        ) else {
            return;
        };
        let IpAddr::V4(ip) = remote else {
            return;
        };
        {
            let mut seen = self
                .companion_reported
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if seen.len() >= COMPANION_REPORT_CAP {
                seen.clear();
            }
            if !seen.insert(ip) {
                return;
            }
        }
        let Some(hostname) = name_of(ip) else {
            // Nobody resolved this address through us — the browser answered
            // from its own cache or over DoH. The name is recoverable only by
            // reverse lookup, and only if a routed site is actually in play:
            // on an idle machine every direct connection would queue a query
            // for nothing.
            if self.beside_routed_traffic() {
                if let Some(learner) = self.reverse_dns_learner.as_ref() {
                    if is_learnable_endpoint(ip) {
                        // Not a drop at all — a flow that left over the primary
                        // beside a routed site. Nothing forbids the direct
                        // classification here.
                        learner(
                            ip,
                            true,
                            crate::conn_observation_consumer::ReverseLearnOrigin::PrimaryEgress,
                        );
                    }
                }
            }
            return;
        };
        sink(&hostname);
    }
}
