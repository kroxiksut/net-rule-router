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
        let (Some(name_of), Some(sink)) = (
            self.name_for_address.as_ref(),
            self.companion_primary_health.as_ref(),
        ) else {
            return;
        };
        let IpAddr::V4(ip) = remote else {
            return;
        };
        if let Some(hostname) = name_of(ip) {
            sink(&hostname, stalled);
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
                        learner(ip, true);
                    }
                }
            }
            return;
        };
        sink(&hostname);
    }
}
