//! Say it once per state change, not once per reconcile.
//!
//! Every one of these answers the same question — has this `(sid, role)`
//! already been logged in this state? — and they exist because the
//! reconcile loop runs every few seconds: without the latch a stale binding
//! floods the operational log forever. Together they are the module's
//! logging policy, which is a different subject from routing.
//!
//! Same inherent impl, split across files. Behaviour is unchanged.

use super::*;

impl SecondaryRouteCoordinator {
    /// Returns `true` the first time a given `stale → healed` binding mapping
    /// is observed for `(sid, role)` (and again whenever it changes), `false`
    /// while it repeats. Backs the once-per-state-change dedup of the
    /// stale-binding auto-heal WARN so a long-lived stale binding does not
    /// flood the operational log every reconcile cycle.
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn note_heal_once(
        &self,
        sid: &str,
        role: &str,
        stale_id: &str,
        healed_id: &str,
    ) -> bool {
        let key = format!("{sid}|{role}");
        let value = (stale_id.to_string(), healed_id.to_string());
        let mut guard = self.heal_logged.lock().unwrap_or_else(|p| p.into_inner());
        if guard.get(&key) == Some(&value) {
            return false;
        }
        guard.insert(key, value);
        true
    }

    /// Returns `true` the first time this `(sid, role, anchor)` is offered for
    /// persistence, `false` while it repeats — the reconcile re-derives the same
    /// anchor every cycle, and the reloaded binding only shows it a cycle later.
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn note_anchor_once(&self, sid: &str, role: &str, anchor: &str) -> bool {
        self.anchor_persisted
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(format!("{sid}|{role}|{anchor}"))
    }

    /// Returns `true` the first time the "bound adapter NOT FOUND" state is seen
    /// for `(sid, role)` with a given `(stale_id, live-set fingerprint)`, and
    /// again whenever either changes; `false` while it repeats. Dedups the
    /// NOT-FOUND WARN so a bound-but-absent secondary (VPN turned off) does not
    /// flood the operational log at reconcile cadence.
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn note_not_found_once(
        &self,
        sid: &str,
        role: &str,
        stale_id: &str,
        live_fp: &str,
    ) -> bool {
        let key = format!("{sid}|{role}");
        let value = (stale_id.to_string(), live_fp.to_string());
        let mut guard = self
            .not_found_logged
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if guard.get(&key) == Some(&value) {
            return false;
        }
        guard.insert(key, value);
        true
    }

    /// Returns `true` the first time the "bound adapter NOT usable" state is
    /// observed for `(sid, role)` with this `stable_id`, and again whenever
    /// the adapter transitions back to not-usable after having been usable
    /// (see [`Self::clear_not_usable`]); `false` while the same not-usable
    /// spell continues. Dedups the NOT-usable WARN so a flapping adapter does
    /// not flood the operational log at reconcile cadence.
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn note_not_usable_once(&self, sid: &str, role: &str, stable_id: &str) -> bool {
        let key = format!("{sid}|{role}");
        let mut guard = self
            .not_usable_logged
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if guard.get(&key).map(String::as_str) == Some(stable_id) {
            return false;
        }
        guard.insert(key, stable_id.to_string());
        true
    }

    /// Remember the next-hop derived for `ifindex` and say whether it is NEWS.
    ///
    /// The derive itself repeats on every resolve, so logging its result each
    /// time buries the log in one answer (verbose capture: 6257 identical
    /// lines, 23% of a session). The cache has to be written either way — it is what lets
    /// routing survive the catch-all routes being stripped — so the latch is
    /// the write's own return value rather than a second map.
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn note_derived_next_hop(&self, ifindex: u32, next_hop: std::net::Ipv4Addr) -> bool {
        self.next_hop_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(ifindex, next_hop)
            != Some(next_hop)
    }

    /// Re-arm [`Self::note_not_usable_once`] for `(sid, role)` — called once
    /// the binding resolves to a usable adapter again, so the next
    /// usable→not-usable transition warns instead of staying silent forever.
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn clear_not_usable(&self, sid: &str, role: &str) {
        let key = format!("{sid}|{role}");
        let mut guard = self
            .not_usable_logged
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        guard.remove(&key);
    }

    /// `true` exactly once per no-next-hop spell for `(sid, role)` (see
    /// [`Self::no_next_hop_logged`]); `false` while the same spell continues.
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn note_no_next_hop_once(&self, sid: &str, role: &str) -> bool {
        let mut guard = self
            .no_next_hop_logged
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        guard.insert(format!("{sid}|{role}"))
    }

    /// Re-arm [`Self::note_no_next_hop_once`] for `(sid, role)` — called once
    /// the binding resolves to a route target again.
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn clear_no_next_hop(&self, sid: &str, role: &str) {
        let mut guard = self
            .no_next_hop_logged
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        guard.remove(&format!("{sid}|{role}"));
    }
}
