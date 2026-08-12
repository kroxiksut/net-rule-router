//! Per-adapter external (reflexive) address discovery.
//!
//! "Which address does the outside world see when traffic leaves *this*
//! adapter?" is the question the interfaces list asks once per adapter, and a
//! STUN binding request answers it in one ~20-byte datagram: the response
//! carries the source address as observed from outside the local NAT.
//!
//! The module is split along the usual seam:
//!
//! - [`stun`] is pure policy — message building and parsing over bytes, with
//!   no clock, no sockets and no randomness, so it is tested by fixtures.
//! - [`probe`] is the transport — `std::net` only, portable as written, with
//!   hard timeouts and a wall-clock budget.
//!
//! The outcome type below is the third piece: it is what the rest of the
//! product consumes, and it is deliberately coarse. The user is being told
//! whether an address could be observed, not how the observation was made.
//!
//! **Honesty over optimism.** A probe that is refused by a local packet
//! filter, that reaches a server which never answers, or that runs against an
//! adapter with no usable source address are three different stories, and each
//! keeps its own outcome. Nothing here ever guesses an address.

mod probe;
mod stun;

use std::net::Ipv4Addr;

use nrr_shared::ExternalIpStatus;

pub use probe::{
    probe_external_ipv4_batch, ATTEMPT_TIMEOUT, MAX_ATTEMPTS, PROBE_BUDGET, STUN_SERVERS,
};

/// What came of asking one adapter for its external address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternalIpProbeOutcome {
    /// A server answered and the reflexive address was read from its response.
    Resolved(Ipv4Addr),
    /// The probe went out but nothing usable came back inside the budget:
    /// no route, a filtered path, a dead endpoint, a captive portal.
    Unreachable,
    /// The local network stack refused to send the probe at all — a leak
    /// protection posture, a personal firewall, a policy filter.
    LocallyBlocked,
    /// No probe was sent: the adapter has no source address worth binding, or
    /// it is not up. Distinct from a failure — nothing was tried.
    Skipped,
}

impl ExternalIpProbeOutcome {
    /// Project onto the status slug the GUI renders.
    ///
    /// `RateLimited` has no counterpart here: STUN has no "slow down" reply,
    /// so a throttling server is indistinguishable from a silent one and is
    /// reported as a failed check. The status stays in the shared enum for
    /// probe kinds that can tell the difference.
    #[must_use]
    pub const fn status(self) -> ExternalIpStatus {
        match self {
            Self::Resolved(_) => ExternalIpStatus::Resolved,
            Self::Unreachable => ExternalIpStatus::CheckFailed,
            Self::LocallyBlocked => ExternalIpStatus::Blocked,
            Self::Skipped => ExternalIpStatus::NotChecked,
        }
    }

    /// The observed address, when there is one.
    #[must_use]
    pub const fn address(self) -> Option<Ipv4Addr> {
        match self {
            Self::Resolved(address) => Some(address),
            _ => None,
        }
    }

    /// Whether a packet actually left (or was meant to leave) the machine.
    #[must_use]
    pub const fn was_attempted(self) -> bool {
        !matches!(self, Self::Skipped)
    }

    /// Operator-facing English note carried in the snapshot next to the
    /// status. Diagnostic prose, not user-visible copy — the GUI renders the
    /// localized status slug.
    #[must_use]
    pub const fn note(self) -> &'static str {
        match self {
            Self::Resolved(_) => "External address observed from a STUN binding response.",
            Self::Unreachable => {
                "External probe sent; no usable response arrived within the probe budget."
            }
            Self::LocallyBlocked => {
                "External probe was refused by the local network stack before it left the machine."
            }
            Self::Skipped => {
                "External probe skipped: the adapter is not up or has no routable IPv4 source address."
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_projection_is_total_and_honest() {
        let resolved = ExternalIpProbeOutcome::Resolved(Ipv4Addr::new(203, 0, 113, 10));
        assert_eq!(resolved.status(), ExternalIpStatus::Resolved);
        assert_eq!(
            ExternalIpProbeOutcome::Unreachable.status(),
            ExternalIpStatus::CheckFailed
        );
        assert_eq!(
            ExternalIpProbeOutcome::LocallyBlocked.status(),
            ExternalIpStatus::Blocked
        );
        assert_eq!(
            ExternalIpProbeOutcome::Skipped.status(),
            ExternalIpStatus::NotChecked
        );
    }

    #[test]
    fn only_a_resolved_outcome_carries_an_address() {
        assert_eq!(
            ExternalIpProbeOutcome::Resolved(Ipv4Addr::new(198, 51, 100, 7)).address(),
            Some(Ipv4Addr::new(198, 51, 100, 7))
        );
        for outcome in [
            ExternalIpProbeOutcome::Unreachable,
            ExternalIpProbeOutcome::LocallyBlocked,
            ExternalIpProbeOutcome::Skipped,
        ] {
            assert_eq!(
                outcome.address(),
                None,
                "{outcome:?} must not claim an address"
            );
        }
    }

    #[test]
    fn only_a_skipped_outcome_reports_no_attempt() {
        assert!(!ExternalIpProbeOutcome::Skipped.was_attempted());
        for outcome in [
            ExternalIpProbeOutcome::Resolved(Ipv4Addr::new(203, 0, 113, 10)),
            ExternalIpProbeOutcome::Unreachable,
            ExternalIpProbeOutcome::LocallyBlocked,
        ] {
            assert!(outcome.was_attempted(), "{outcome:?} did reach the network");
        }
    }

    #[test]
    fn every_outcome_explains_itself() {
        for outcome in [
            ExternalIpProbeOutcome::Resolved(Ipv4Addr::new(203, 0, 113, 10)),
            ExternalIpProbeOutcome::Unreachable,
            ExternalIpProbeOutcome::LocallyBlocked,
            ExternalIpProbeOutcome::Skipped,
        ] {
            assert!(!outcome.note().is_empty());
        }
    }
}
