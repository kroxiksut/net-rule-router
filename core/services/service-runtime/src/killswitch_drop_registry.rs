//! Registry of the WFP filter ids that make up the CURRENT kill-switch /
//! fail-closed BLOCK set, published by [`crate::per_sid_orchestrator`] on
//! every filter recompute.
//!
//! This closes the filter-role gap in the reactive VPN-endpoint learner (see
//! [`crate::conn_observation_consumer`]): a connection observation only
//! carries the WFP filter id that produced a DROP
//! ([`nrr_platform_api::conn_observe::ConnectionObservation::nrr_drop_spec_id`]),
//! decoded from the filter's own key — it says nothing about which of OUR
//! filters dropped it. A user's own Block rule and a mode-A leak-guard block
//! both decode to a valid NRR spec id, but only a kill-switch/fail-closed
//! Block is safe to treat as "this drop proves the tunnel needs an
//! exemption". Membership in this registry is exactly that distinction.
//!
//! [`KillswitchBlockFilterRegistry::publish_scoped`] replaces the whole
//! published set — the caller is expected to pass the FULL current
//! kill-switch/fail-closed Block id set on every call, not a delta.
//!
//! ## Scopes, not one set
//!
//! The published set is split by BLOCKING SCOPE, because the parts fail in
//! completely different ways and the drop detector must not conflate them:
//!
//! - **destination-scoped** — the block carries a remote address (`/32`, a
//!   subnet, or the catch-all). Its companion permit becomes satisfiable the
//!   moment the destination's secondary route is installed, so a drop here
//!   while the secondary is usable means the pin outran the route (or the
//!   scope is genuinely too wide) — actionable.
//! - **ipv6-cut** — the blanket close of the IPv6 family (see
//!   `killswitch_codegen::catch_all_v6_filters`). Deliberately NOT part of the
//!   role-verification set: a v6 drop proves nothing about the tunnel, it only
//!   needs its own wording in the notice.
//! - **app-scoped** — the block carries only an `ALE_APP_ID` condition and no
//!   destination (`killswitch_codegen::app_kill_switch_filters`). It covers
//!   EVERY destination the process talks to, including the ones the routing
//!   layer has never seen; a secondary-routed app's first contact with a new
//!   address is therefore dropped by design (that drop is what teaches
//!   `app_observation_lookup` the address, after which the route and the
//!   per-destination pin follow). Expected, self-healing, and not evidence of
//!   a scope bug.
//! - **dns-lockdown** — the DoH/DoT block band
//!   (`killswitch_codegen::doh_dot_block_filters`). It fires when an app goes
//!   to a public resolver of its own instead of the one policy provides, which
//!   is neither the tunnel's business nor a rule the user wrote. Like the v6
//!   cut it is identifiable but never role-verifying.

use std::collections::HashSet;
use std::sync::RwLock;

/// One compute's BLOCK ids, split by blocking scope — see the module doc for
/// what each band means and why they must not be conflated.
#[derive(Debug, Default, Clone)]
pub struct ScopedBlockIds {
    /// Role-verifying kill-switch / fail-closed blocks.
    pub all: HashSet<u64>,
    /// Subset of `all` whose blocks carry only an app-id condition.
    pub app_scoped: HashSet<u64>,
    /// The blanket IPv6 close; identifiable, never role-verifying.
    pub ipv6_cut: HashSet<u64>,
    /// The DoH/DoT lockdown band; identifiable, never role-verifying.
    pub dns_lockdown: HashSet<u64>,
}

impl ScopedBlockIds {
    /// Nothing published in any band — the caller's entry can be dropped
    /// rather than kept as a stale set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.all.is_empty() && self.ipv6_cut.is_empty() && self.dns_lockdown.is_empty()
    }
}

/// Shared, lock-protected set of WFP filter spec ids ([`WfpFilterId::raw`](nrr_platform_api::types::WfpFilterId))
/// belonging to the currently-installed kill-switch / fail-closed BLOCK
/// filters. Cheap to query (`contains`) from the connection-observation
/// drain path; updated at reconcile cadence (`publish_scoped`).
#[derive(Default)]
pub struct KillswitchBlockFilterRegistry {
    blocks: RwLock<ScopedBlockIds>,
}

impl KillswitchBlockFilterRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the published set with `ids`, none of them scoped. Kept for
    /// callers that do not classify (tests, and any caller that only needs the
    /// role-verification gate).
    pub fn publish(&self, ids: HashSet<u64>) {
        self.publish_scoped(ScopedBlockIds {
            all: ids,
            ..ScopedBlockIds::default()
        });
    }

    /// Replace the published set with `ids`, band for band (see the module
    /// doc). Called with the FULL current id set — never a partial delta.
    /// `app_scoped` is expected to be a subset of `all`; ids outside `all` are
    /// harmless (they can never match a role-verified drop).
    pub fn publish_scoped(&self, ids: ScopedBlockIds) {
        let mut guard = self.blocks.write().unwrap_or_else(|p| p.into_inner());
        *guard = ids;
    }

    /// Whether `id` is currently one of ours (kill-switch / fail-closed
    /// Block), i.e. a drop attributed to it is role-verified.
    pub fn contains(&self, id: u64) -> bool {
        self.blocks
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .all
            .contains(&id)
    }

    /// Whether `id` is one of the blocks that close the IPv6 family while the
    /// protection is on. A drop attributed to one of them has nothing to do
    /// with the user's rules, and telling them a rule did it sends them
    /// editing a file that cannot contain the cause.
    pub fn is_ipv6_cut(&self, id: u64) -> bool {
        self.blocks
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .ipv6_cut
            .contains(&id)
    }

    /// Whether `id` is one of the DoH/DoT lockdown blocks — the app reached
    /// for a resolver of its own and the lockdown closed it. No rule of the
    /// user's did it, and the tunnel proves nothing about it either.
    pub fn is_dns_lockdown(&self, id: u64) -> bool {
        self.blocks
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .dns_lockdown
            .contains(&id)
    }

    /// Whether `id` is one of the APP-SCOPED blocks — a block with no
    /// destination condition, which by construction also covers destinations
    /// the routing layer has not learned yet (see the module doc).
    pub fn is_app_scoped(&self, id: u64) -> bool {
        self.blocks
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .app_scoped
            .contains(&id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_registry_contains_nothing() {
        let registry = KillswitchBlockFilterRegistry::new();
        assert!(!registry.contains(42));
    }

    #[test]
    fn publish_then_contains_published_ids_only() {
        let registry = KillswitchBlockFilterRegistry::new();
        registry.publish(HashSet::from([1, 2, 3]));
        assert!(registry.contains(1));
        assert!(registry.contains(2));
        assert!(registry.contains(3));
        assert!(!registry.contains(4));
    }

    #[test]
    fn publish_replaces_the_previous_set() {
        let registry = KillswitchBlockFilterRegistry::new();
        registry.publish(HashSet::from([1, 2]));
        registry.publish(HashSet::from([3]));
        assert!(!registry.contains(1));
        assert!(!registry.contains(2));
        assert!(registry.contains(3));
    }

    #[test]
    fn publish_empty_clears_membership() {
        let registry = KillswitchBlockFilterRegistry::new();
        registry.publish(HashSet::from([1]));
        registry.publish(HashSet::new());
        assert!(!registry.contains(1));
    }

    #[test]
    fn app_scoped_ids_are_role_verified_and_separately_identifiable() {
        let registry = KillswitchBlockFilterRegistry::new();
        registry.publish_scoped(ScopedBlockIds {
            all: HashSet::from([1, 2]),
            app_scoped: HashSet::from([2]),
            ..ScopedBlockIds::default()
        });
        // Both halves still pass the role-verification gate…
        assert!(registry.contains(1));
        assert!(registry.contains(2));
        // …but only the app-only block is app-scoped.
        assert!(!registry.is_app_scoped(1));
        assert!(registry.is_app_scoped(2));
    }

    #[test]
    fn publish_scoped_replaces_both_sets_together() {
        let registry = KillswitchBlockFilterRegistry::new();
        registry.publish_scoped(ScopedBlockIds {
            all: HashSet::from([1, 2]),
            app_scoped: HashSet::from([2]),
            ..ScopedBlockIds::default()
        });
        registry.publish_scoped(ScopedBlockIds {
            all: HashSet::from([3]),
            ..ScopedBlockIds::default()
        });
        assert!(!registry.is_app_scoped(2));
        assert!(!registry.contains(2));
        assert!(registry.contains(3));
    }

    #[test]
    fn ipv6_cut_ids_are_identifiable_without_being_role_verified() {
        let registry = KillswitchBlockFilterRegistry::new();
        registry.publish_scoped(ScopedBlockIds {
            all: HashSet::from([1]),
            ipv6_cut: HashSet::from([9]),
            ..ScopedBlockIds::default()
        });
        assert!(registry.is_ipv6_cut(9));
        assert!(
            !registry.contains(9),
            "a v6 drop must not role-verify a tunnel"
        );
        assert!(!registry.is_ipv6_cut(1));
    }

    #[test]
    fn plain_publish_classifies_nothing_as_app_scoped() {
        let registry = KillswitchBlockFilterRegistry::new();
        registry.publish_scoped(ScopedBlockIds {
            all: HashSet::from([1]),
            app_scoped: HashSet::from([1]),
            ..ScopedBlockIds::default()
        });
        registry.publish(HashSet::from([1]));
        assert!(registry.contains(1));
        assert!(!registry.is_app_scoped(1));
    }

    #[test]
    fn dns_lockdown_ids_are_identifiable_without_being_role_verified() {
        let registry = KillswitchBlockFilterRegistry::new();
        registry.publish_scoped(ScopedBlockIds {
            all: HashSet::from([1]),
            dns_lockdown: HashSet::from([7]),
            ..ScopedBlockIds::default()
        });
        assert!(registry.is_dns_lockdown(7));
        assert!(
            !registry.contains(7),
            "a resolver drop must not role-verify a tunnel"
        );
        assert!(!registry.is_dns_lockdown(1));
    }

    #[test]
    fn a_band_only_publish_is_not_empty() {
        // The orchestrator drops a SID's entry when its ids are empty; a
        // lockdown-only compute must survive that check or the band vanishes.
        assert!(!ScopedBlockIds {
            dns_lockdown: HashSet::from([7]),
            ..ScopedBlockIds::default()
        }
        .is_empty());
        assert!(ScopedBlockIds::default().is_empty());
    }
}
