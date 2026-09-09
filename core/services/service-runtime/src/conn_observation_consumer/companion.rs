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
    /// One connection to a named destination stalled or finished cleanly on the
    /// primary link. Unlike [`Self::note_companion_in_use`] this is NOT deduped
    /// per address: the verdict is built from how often each outcome happened,
    /// so collapsing repeats would erase the evidence.
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn note_companion_primary_health(&self, remote: IpAddr, stalled: bool) {
        let Some(sink) = self.companion_primary_health.as_ref() else {
            return;
        };
        let IpAddr::V4(ip) = remote else {
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
        if let Some(hostname) = hostname {
            sink(&hostname, stalled);
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
                        learner(ip, true);
                    }
                }
            }
            return;
        };
        sink(&hostname);
    }
}
