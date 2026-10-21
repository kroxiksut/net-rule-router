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
        let remembered = self
            .connection_programs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&(obs.local, obs.remote))
            .map(|(program, owner, _)| (program.clone(), owner.clone()));
        // A resend or a close carries no owner of its own on every platform.
        let owner = obs
            .user_sid
            .clone()
            .or_else(|| remembered.as_ref().and_then(|(_, owner)| owner.clone()));
        if let (Some(app), Some((program, _))) = (self.app_main_link.as_ref(), remembered.as_ref())
        {
            app(
                owner.as_deref(),
                program.as_str(),
                obs.remote.ip(),
                stalled,
                hostname.is_some(),
            );
        }
        if let (Some(sink), Some(hostname)) = (self.companion_primary_health.as_ref(), hostname) {
            sink(owner.as_deref(), &hostname, stalled);
        }
    }

    /// Which program opened this connection, for the application measure: the
    /// stack's resends and closes carry only a pid, and by then it may be gone.
    pub(super) fn remember_program(&self, rec: &super::ConnectionTraceRecord, at_ms: u64) {
        const MAX_REMEMBERED: usize = 4096;
        const REMEMBERED_MS: u64 = 120_000;
        if self.app_main_link.is_none() && self.companion_primary_health.is_none() {
            return;
        }
        let Some(path) = rec.process_path.as_deref() else {
            return;
        };
        if !super::connection_facts::offerable_program(path) {
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
            programs.retain(|_, (_, _, at)| at_ms.saturating_sub(*at) < REMEMBERED_MS);
            if programs.len() >= MAX_REMEMBERED {
                programs.clear();
            }
        }
        programs.insert(
            (rec.local, rec.remote),
            (program, rec.user_sid.clone(), at_ms),
        );
    }

    /// A connection the stack established over the additional link, attributed
    /// to its program. The caller passes only establishments: a drop or a
    /// filter classify carried nothing, so it says nothing about a split.
    pub(super) fn note_app_additional_link(&self, rec: &super::ConnectionTraceRecord) {
        let Some(sink) = self.app_additional_link.as_ref() else {
            return;
        };
        let Some(path) = rec.process_path.as_deref() else {
            return;
        };
        if !super::connection_facts::offerable_program(path) {
            return;
        }
        let program = nrr_domain::app_offer::program_name(path);
        if !program.is_empty() {
            sink(rec.user_sid.as_deref(), &program);
        }
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
        owner: Option<&str>,
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
        sink(owner, process, hostname.as_deref(), at_ms);
    }

    /// Somebody went to a censored host: this connection is to an address a
    /// provider placeholder just handed out. Until now that answer alone was
    /// enough to offer the host, which turned a page's prefetch into a
    /// suggestion for a site nobody had opened.
    ///
    /// Called for every observation, established or not — see the caller.
    pub(super) fn confirm_placeholder_use(&self, remote: IpAddr, at_ms: u64, owner: Option<&str>) {
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
            sink(owner, &host);
        }
    }

    /// Owners remembered as on a routed site at once; past it the list starts
    /// over, which only delays a lookup.
    const OWNERS_ON_SECONDARY_CAP: usize = 64;
    /// Reverse lookups of direct connections per window, machine-wide.
    const REVERSE_LOOKUPS_PER_WINDOW: u32 = 8;
    const REVERSE_LOOKUP_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);

    /// `owner`'s traffic just left over their additional link.
    pub(super) fn note_owner_on_secondary(&self, owner: Option<&str>) {
        let mut seen = self
            .owner_secondary_at
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let key = owner.unwrap_or_default();
        if seen.len() >= Self::OWNERS_ON_SECONDARY_CAP && !seen.contains_key(key) {
            seen.clear();
        }
        seen.insert(key.to_owned(), Instant::now());
    }

    /// Whether a direct connection of `owner`'s whose name nobody resolved may
    /// be named by reverse lookup: only for an owner who collects suggestions,
    /// whose OWN traffic is on a routed site right now, and within a small
    /// budget. The lookup asks a resolver by plain text, so it is never made
    /// for a user who did not ask for suggestions.
    pub(super) fn primary_egress_may_learn(&self, owner: Option<&str>) -> bool {
        let Some(learns) = self.primary_egress_learning.as_ref() else {
            return false;
        };
        let key = owner.unwrap_or_default();
        let on_secondary = self
            .owner_secondary_at
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(key)
            .is_some_and(|at| at.elapsed() <= COMPANION_WINDOW);
        if !on_secondary || !learns(key) {
            return false;
        }
        let mut budget = self
            .reverse_budget
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        let fresh = budget
            .0
            .is_none_or(|start| now.saturating_duration_since(start) > Self::REVERSE_LOOKUP_WINDOW);
        if fresh {
            *budget = (Some(now), 0);
        }
        if budget.1 >= Self::REVERSE_LOOKUPS_PER_WINDOW {
            return false;
        }
        budget.1 += 1;
        true
    }

    /// One connection that left over the primary link: if we can name its
    /// destination, that name is a companion the user's traffic reached the
    /// wrong way.
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn note_companion_in_use(&self, remote: IpAddr, owner: Option<&str>) {
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
            // Cheapest checks first: a private or reserved address never
            // spends the shared budget.
            if let Some(learner) = self.reverse_dns_learner.as_ref() {
                if is_learnable_endpoint(ip) && self.primary_egress_may_learn(owner) {
                    // Not a drop at all — a flow that left over the primary
                    // beside a routed site. Nothing forbids the direct
                    // classification here.
                    learner(
                        ip,
                        true,
                        crate::conn_observation_consumer::ReverseLearnOrigin::PrimaryEgress,
                        owner,
                    );
                }
            }
            return;
        };
        sink(owner, &hostname);
    }
}
