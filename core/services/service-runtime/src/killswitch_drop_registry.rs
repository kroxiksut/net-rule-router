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
//! ## Two scopes, not one
//!
//! The published set is split by BLOCKING SCOPE, because the two
//! halves fail in completely different ways and the drop detector must not
//! conflate them:
//!
//! - **destination-scoped** — the block carries a remote address (`/32`, a
//!   subnet, or the catch-all). Its companion permit becomes satisfiable the
//!   moment the destination's secondary route is installed, so a drop here
//!   while the secondary is usable means the pin outran the route (or the
//!   scope is genuinely too wide) — actionable.
//! - **app-scoped** — the block carries only an `ALE_APP_ID` condition and no
//!   destination (`killswitch_codegen::app_kill_switch_filters`). It covers
//!   EVERY destination the process talks to, including the ones the routing
//!   layer has never seen; a secondary-routed app's first contact with a new
//!   address is therefore dropped by design (that drop is what teaches
//!   `app_observation_lookup` the address, after which the route and the
//!   per-destination pin follow). Expected, self-healing, and not evidence of
//!   a scope bug.

use std::collections::HashSet;
use std::sync::RwLock;

/// The published sets behind one lock, so a reader never sees an id in `all`
/// whose scope classification is from a previous publish.
#[derive(Default)]
struct PublishedBlocks {
    all: HashSet<u64>,
    app_scoped: HashSet<u64>,
}

/// Shared, lock-protected set of WFP filter spec ids ([`WfpFilterId::raw`](nrr_platform_api::types::WfpFilterId))
/// belonging to the currently-installed kill-switch / fail-closed BLOCK
/// filters. Cheap to query (`contains`) from the connection-observation
/// drain path; updated at reconcile cadence (`publish_scoped`).
#[derive(Default)]
pub struct KillswitchBlockFilterRegistry {
    blocks: RwLock<PublishedBlocks>,
}

impl KillswitchBlockFilterRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the published set with `ids`, none of them app-scoped. Kept for
    /// callers that do not classify (tests, and any caller that only needs the
    /// role-verification gate).
    pub fn publish(&self, ids: HashSet<u64>) {
        self.publish_scoped(ids, HashSet::new());
    }

    /// Replace the published set with `all`, of which `app_scoped` are the
    /// app-only blocks (see the module doc). Called with the FULL current
    /// kill-switch/fail-closed Block id set — never a partial delta.
    /// `app_scoped` is expected to be a subset of `all`; ids outside `all` are
    /// harmless (they can never match a role-verified drop).
    pub fn publish_scoped(&self, all: HashSet<u64>, app_scoped: HashSet<u64>) {
        let mut guard = self.blocks.write().unwrap_or_else(|p| p.into_inner());
        *guard = PublishedBlocks { all, app_scoped };
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
        registry.publish_scoped(HashSet::from([1, 2]), HashSet::from([2]));
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
        registry.publish_scoped(HashSet::from([1, 2]), HashSet::from([2]));
        registry.publish_scoped(HashSet::from([3]), HashSet::new());
        assert!(!registry.is_app_scoped(2));
        assert!(!registry.contains(2));
        assert!(registry.contains(3));
    }

    #[test]
    fn plain_publish_classifies_nothing_as_app_scoped() {
        let registry = KillswitchBlockFilterRegistry::new();
        registry.publish_scoped(HashSet::from([1]), HashSet::from([1]));
        registry.publish(HashSet::from([1]));
        assert!(registry.contains(1));
        assert!(!registry.is_app_scoped(1));
    }
}
