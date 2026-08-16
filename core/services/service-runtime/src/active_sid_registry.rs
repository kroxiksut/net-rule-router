//! `ActiveSidRegistry` tracks the routing-presence model.
//!
//! Tracks which OS users (identified by SID) currently have a live IPC
//! connection from a GUI or tray client. The "routing-active set" is
//! the input to the per-user apply layer: when a user's
//! tray comes up, their per-SID `route_bindings` /
//! `behavior_mode` / `secondary_block_policy` are translated into WFP
//! user-SID-conditioned filters and installed; when the tray exits,
//! the filters are withdrawn.
//!
//! ## Trigger semantics
//!
//! - A user is **"routing-active"** only when they have at least one
//!   live `IpcClientProfile::TrayLightweight` connection. The tray is
//!   the routing agent; the GUI is a management console.
//! - **GUI connections are tracked but never trigger routing
//!   transitions.** Closing the GUI does not remove WFP filters.
//!   Opening the GUI does not install them.
//! - The registry preserves entries while ANY connection (gui or tray)
//!   is alive — diagnostics can see GUI-only users via `is_known` /
//!   `known_sids`. Routing consumers use `is_active` / `active_sids`
//!   which both check `tray_connections > 0`.
//! - Listeners fire on `tray_connections` 0 ↔ 1+ transitions only;
//!   GUI-only changes are silent.
//! - An RDP user with their own session and tray is just another SID
//!   in the set; no special handling.
//!
//! ## Connection lifecycle hooks
//!
//! `WindowsNamedPipeAcceptor::handle_connection` calls:
//! - `on_connect(sid, profile)` — after identity classification
//!   succeeds, before serving frames.
//! - `on_disconnect(sid, profile)` — in the connection's exit path,
//!   after the last frame is processed and before the pipe closes.
//!
//! Connection counting is per-(SID, profile) so a GUI + tray pair from
//! the same user share the SID entry and the registry doesn't lose
//! track when one disconnects.
//!
//! ## Internal listeners
//!
//! On every set-membership transition (SID enters / exits the active
//! set), every registered listener is invoked synchronously with a
//! sorted snapshot of the current active SIDs. The orchestrator
//! registers a listener that recompiles WFP filters; the
//! wire-event push channel (`StatusUpdatesSubscribe`) is
//! intentionally **not** wired here — internal control events do not
//! cross the IPC boundary.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use nrr_shared::ipc::IpcClientProfile;

/// Per-SID activity record. Lives in [`ActiveSidRegistry::inner`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveSidEntry {
    /// Total live connections from this SID across all client kinds.
    pub connection_count: u32,
    /// Live `IpcClientProfile::TrayLightweight` connection counter.
    /// Held separately so the orchestrator can prefer "tray running"
    /// in heuristics (e.g. should we keep filters when only a GUI is
    /// open vs. when a tray is open).
    pub tray_connections: u32,
    /// Live `IpcClientProfile::GuiInteractive` connection counter.
    pub gui_connections: u32,
    /// Wall-clock instant when the SID first appeared in the
    /// registry (or last appeared after a previous removal).
    pub first_seen_at: SystemTime,
    /// Wall-clock instant of the most recent on_connect /
    /// on_disconnect for this SID.
    pub last_event_at: SystemTime,
}

impl ActiveSidEntry {
    /// `true` if the SID has at least one live tray connection.
    pub const fn has_tray(&self) -> bool {
        self.tray_connections > 0
    }
    /// `true` if the SID has at least one live GUI connection.
    pub const fn has_gui(&self) -> bool {
        self.gui_connections > 0
    }
}

/// Registry of currently-active SIDs. Cheap (in-memory `HashMap`),
/// `Send + Sync` — production wiring shares one `Arc<ActiveSidRegistry>`
/// across the IPC transport, the orchestrator, and any diagnostics
/// reader.
///
/// ## Invariants
/// - `connection_count == tray_connections + gui_connections` for
///   every entry in the map.
/// - Entries are removed from the map when `connection_count` hits 0.
/// - All `on_*` methods are idempotent in the sense that overflow is
///   saturated (impossibly large counts saturate at `u32::MAX`) and
///   underflow is clamped at 0 (defensive — should not happen if
///   on_connect / on_disconnect are paired correctly).
///
/// Listener invoked on every active-set membership transition. The
/// argument is a sorted snapshot of the active SIDs after the
/// transition. Listeners run synchronously on the thread that called
/// `on_connect` / `on_disconnect`, so they must be cheap or hand off
/// to a worker.
pub type ActiveSidsListener = Arc<dyn Fn(&[String]) + Send + Sync>;

pub struct ActiveSidRegistry {
    inner: Mutex<HashMap<String, ActiveSidEntry>>,
    listeners: Mutex<Vec<ActiveSidsListener>>,
}

impl ActiveSidRegistry {
    /// Build an empty registry with no listeners. The orchestrator
    /// registers itself via `add_listener` after construction.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            listeners: Mutex::new(Vec::new()),
        }
    }

    /// Add a membership-change listener. Listeners are invoked
    /// synchronously on every transition (SID enters or exits the
    /// active set) with a sorted snapshot of the current active SIDs.
    /// Listeners are kept indefinitely; there is no `remove_listener`
    /// because the registry's lifetime matches the service.
    pub fn add_listener(&self, listener: ActiveSidsListener) {
        self.listeners
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(listener);
    }

    /// Register a new IPC connection from `sid`. The registry decides
    /// whether the SID just **entered the routing-active set**
    /// (`tray_connections` went from 0 to 1+). On a routing transition,
    /// listeners are invoked with the new sorted snapshot of
    /// routing-active SIDs.
    pub fn on_connect(&self, sid: &str, profile: IpcClientProfile) {
        if sid.is_empty() {
            return;
        }
        let now = SystemTime::now();
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let was_routing_active = guard
            .get(sid)
            .map(|e| e.tray_connections > 0)
            .unwrap_or(false);
        let entry = guard
            .entry(sid.to_string())
            .or_insert_with(|| ActiveSidEntry {
                connection_count: 0,
                tray_connections: 0,
                gui_connections: 0,
                first_seen_at: now,
                last_event_at: now,
            });
        entry.connection_count = entry.connection_count.saturating_add(1);
        match profile {
            IpcClientProfile::GuiInteractive => {
                entry.gui_connections = entry.gui_connections.saturating_add(1);
            }
            IpcClientProfile::TrayLightweight => {
                entry.tray_connections = entry.tray_connections.saturating_add(1);
            }
            // The console is counted as a connection but is neither a GUI
            // session nor a routing signal: an operator running `status` must
            // not make a user routing-active, nor keep them so.
            IpcClientProfile::AdminConsole => {}
        }
        entry.last_event_at = now;
        let is_routing_active = entry.tray_connections > 0;
        let entered_routing = !was_routing_active && is_routing_active;
        let snapshot: Vec<String> = if entered_routing {
            routing_active_snapshot(&guard)
        } else {
            Vec::new()
        };
        drop(guard);
        if entered_routing {
            self.invoke_listeners(&snapshot);
        }
    }

    /// Decrement the connection counter for `sid`. Listeners fire when
    /// the SID **leaves the routing-active set** (`tray_connections`
    /// went from 1+ to 0); GUI-only disconnects are silent. Idempotent
    /// on unknown SIDs / underflow.
    pub fn on_disconnect(&self, sid: &str, profile: IpcClientProfile) {
        if sid.is_empty() {
            return;
        }
        let now = SystemTime::now();
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let was_routing_active = guard
            .get(sid)
            .map(|e| e.tray_connections > 0)
            .unwrap_or(false);
        let entry_removed = if let Some(entry) = guard.get_mut(sid) {
            entry.connection_count = entry.connection_count.saturating_sub(1);
            match profile {
                IpcClientProfile::GuiInteractive => {
                    entry.gui_connections = entry.gui_connections.saturating_sub(1);
                }
                IpcClientProfile::TrayLightweight => {
                    entry.tray_connections = entry.tray_connections.saturating_sub(1);
                }
                // Mirrors `on_connect`: never counted, never decremented.
                IpcClientProfile::AdminConsole => {}
            }
            entry.last_event_at = now;
            entry.connection_count == 0
        } else {
            false
        };
        if entry_removed {
            guard.remove(sid);
        }
        let is_routing_active = guard
            .get(sid)
            .map(|e| e.tray_connections > 0)
            .unwrap_or(false);
        let exited_routing = was_routing_active && !is_routing_active;
        let snapshot: Vec<String> = if exited_routing {
            routing_active_snapshot(&guard)
        } else {
            Vec::new()
        };
        drop(guard);
        if exited_routing {
            self.invoke_listeners(&snapshot);
        }
    }

    /// **M-1 routing-active check.** `true` if `sid` has at least one
    /// live `TrayLightweight` connection. GUI-only SIDs return `false`
    /// even though they are tracked in the entry map.
    pub fn is_active(&self, sid: &str) -> bool {
        let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard
            .get(sid)
            .map(|e| e.tray_connections > 0)
            .unwrap_or(false)
    }

    /// `true` if `sid` is tracked at all (any GUI or tray connection
    /// alive). Returns `false` for SIDs absent from the registry.
    pub fn is_known(&self, sid: &str) -> bool {
        let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.contains_key(sid)
    }

    /// Number of distinct routing-active SIDs (those with at least one
    /// live tray connection).
    pub fn len(&self) -> usize {
        let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.values().filter(|e| e.tray_connections > 0).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Snapshot of routing-active SIDs (sorted) — those with at least
    /// one tray connection. This is the M-1 set: filters apply only to
    /// these users.
    pub fn active_sids(&self) -> Vec<String> {
        let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        routing_active_snapshot(&guard)
    }

    /// Snapshot of every tracked SID (any GUI or tray connection),
    /// sorted. Use for diagnostics / metrics; for routing consumers
    /// always use [`active_sids`][Self::active_sids].
    pub fn known_sids(&self) -> Vec<String> {
        let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let mut sids: Vec<String> = guard.keys().cloned().collect();
        sids.sort();
        sids
    }

    /// Read the full entry for `sid`, if present. Cloned to avoid
    /// holding the internal mutex.
    pub fn entry(&self, sid: &str) -> Option<ActiveSidEntry> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .cloned()
    }

    fn invoke_listeners(&self, snapshot: &[String]) {
        let listeners: Vec<ActiveSidsListener> = self
            .listeners
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .cloned()
            .collect();
        for l in listeners {
            l(snapshot);
        }
    }
}

/// Returns the routing-active SIDs (those with `tray_connections > 0`)
/// in sorted order. Used by `active_sids` and the listener snapshot.
fn routing_active_snapshot(map: &HashMap<String, ActiveSidEntry>) -> Vec<String> {
    let mut sids: Vec<String> = map
        .iter()
        .filter(|(_, e)| e.tray_connections > 0)
        .map(|(sid, _)| sid.clone())
        .collect();
    sids.sort();
    sids
}

impl Default for ActiveSidRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SID_A: &str = "S-1-5-21-A";
    const SID_B: &str = "S-1-5-21-B";

    #[test]
    fn empty_registry_has_no_active_sids() {
        let reg = ActiveSidRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        assert!(!reg.is_active(SID_A));
        assert!(!reg.is_known(SID_A));
        assert!(reg.entry(SID_A).is_none());
    }

    #[test]
    fn empty_sid_is_ignored() {
        let reg = ActiveSidRegistry::new();
        reg.on_connect("", IpcClientProfile::GuiInteractive);
        reg.on_disconnect("", IpcClientProfile::GuiInteractive);
        assert!(reg.is_empty());
    }

    // ── M-1 routing-presence semantics ────────────────────────────────────────

    #[test]
    fn gui_only_connect_does_not_make_sid_routing_active() {
        let reg = ActiveSidRegistry::new();
        reg.on_connect(SID_A, IpcClientProfile::GuiInteractive);
        // GUI is tracked → SID is `known` …
        assert!(reg.is_known(SID_A));
        let entry = reg.entry(SID_A).unwrap();
        assert_eq!(entry.gui_connections, 1);
        assert_eq!(entry.tray_connections, 0);
        // …but NOT routing-active.
        assert!(!reg.is_active(SID_A));
        assert!(reg.active_sids().is_empty());
        assert_eq!(reg.known_sids(), vec![SID_A.to_string()]);
        // Disconnect: entry removed.
        reg.on_disconnect(SID_A, IpcClientProfile::GuiInteractive);
        assert!(!reg.is_known(SID_A));
    }

    #[test]
    fn tray_connect_is_routing_active() {
        let reg = ActiveSidRegistry::new();
        reg.on_connect(SID_A, IpcClientProfile::TrayLightweight);
        assert!(reg.is_active(SID_A));
        assert!(reg.is_known(SID_A));
        assert_eq!(reg.active_sids(), vec![SID_A.to_string()]);
        reg.on_disconnect(SID_A, IpcClientProfile::TrayLightweight);
        assert!(!reg.is_active(SID_A));
        assert!(!reg.is_known(SID_A));
    }

    #[test]
    fn gui_then_tray_only_tray_triggers_routing_transition() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let reg = ActiveSidRegistry::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_l = Arc::clone(&calls);
        reg.add_listener(Arc::new(move |_| {
            calls_l.fetch_add(1, Ordering::SeqCst);
        }));

        // GUI connect: tracked but no routing transition.
        reg.on_connect(SID_A, IpcClientProfile::GuiInteractive);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!reg.is_active(SID_A));
        assert!(reg.is_known(SID_A));

        // Tray connect: routing-entered → fires.
        reg.on_connect(SID_A, IpcClientProfile::TrayLightweight);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(reg.is_active(SID_A));

        // GUI disconnect: tray still up → no fire.
        reg.on_disconnect(SID_A, IpcClientProfile::GuiInteractive);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(reg.is_active(SID_A));

        // Tray disconnect: routing-exited → fires.
        reg.on_disconnect(SID_A, IpcClientProfile::TrayLightweight);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(!reg.is_active(SID_A));
    }

    #[test]
    fn gui_only_connect_disconnect_does_not_fire_listener() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let reg = ActiveSidRegistry::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_l = Arc::clone(&calls);
        reg.add_listener(Arc::new(move |_| {
            calls_l.fetch_add(1, Ordering::SeqCst);
        }));
        reg.on_connect(SID_A, IpcClientProfile::GuiInteractive);
        reg.on_disconnect(SID_A, IpcClientProfile::GuiInteractive);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "GUI-only churn must be silent under M-1"
        );
    }

    #[test]
    fn second_tray_connect_is_silent_for_already_routing_active() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let reg = ActiveSidRegistry::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_l = Arc::clone(&calls);
        reg.add_listener(Arc::new(move |_| {
            calls_l.fetch_add(1, Ordering::SeqCst);
        }));
        // Two trays from the same SID (e.g. tray + secondary helper).
        reg.on_connect(SID_A, IpcClientProfile::TrayLightweight);
        reg.on_connect(SID_A, IpcClientProfile::TrayLightweight);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // First tray drop: still routing-active → silent.
        reg.on_disconnect(SID_A, IpcClientProfile::TrayLightweight);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // Second drop: exit → fires.
        reg.on_disconnect(SID_A, IpcClientProfile::TrayLightweight);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn snapshot_includes_only_routing_active_sids() {
        let reg = ActiveSidRegistry::new();
        reg.on_connect("S-1-5-21-Z", IpcClientProfile::GuiInteractive); // GUI-only
        reg.on_connect("S-1-5-21-A", IpcClientProfile::TrayLightweight); // tray
        reg.on_connect("S-1-5-21-M", IpcClientProfile::GuiInteractive); // GUI-only
        reg.on_connect("S-1-5-21-K", IpcClientProfile::TrayLightweight); // tray
        let active = reg.active_sids();
        assert_eq!(active, vec!["S-1-5-21-A", "S-1-5-21-K"]);
        let known = reg.known_sids();
        assert_eq!(
            known,
            vec!["S-1-5-21-A", "S-1-5-21-K", "S-1-5-21-M", "S-1-5-21-Z"]
        );
        assert_eq!(reg.len(), 2, "len counts routing-active only");
    }

    #[test]
    fn listener_snapshot_only_lists_tray_connected_sids() {
        use std::sync::Mutex;
        let reg = ActiveSidRegistry::new();
        let snapshots: Arc<Mutex<Vec<Vec<String>>>> = Arc::new(Mutex::new(Vec::new()));
        let snapshots_l = Arc::clone(&snapshots);
        reg.add_listener(Arc::new(move |snap: &[String]| {
            snapshots_l.lock().unwrap().push(snap.to_vec());
        }));
        // GUI connect (silent)
        reg.on_connect(SID_B, IpcClientProfile::GuiInteractive);
        // Tray connect (fires; snapshot excludes GUI-only SID_B)
        reg.on_connect(SID_A, IpcClientProfile::TrayLightweight);
        let s = snapshots.lock().unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0], vec![SID_A.to_string()]);
    }

    // ── Connection accounting (preserved across M-1 change) ──────────────────

    #[test]
    fn gui_plus_tray_share_one_entry_with_correct_per_kind_counts() {
        let reg = ActiveSidRegistry::new();
        reg.on_connect(SID_A, IpcClientProfile::GuiInteractive);
        reg.on_connect(SID_A, IpcClientProfile::TrayLightweight);
        let e = reg.entry(SID_A).unwrap();
        assert_eq!(e.connection_count, 2);
        assert_eq!(e.gui_connections, 1);
        assert_eq!(e.tray_connections, 1);
        assert!(e.has_gui());
        assert!(e.has_tray());

        // Drop GUI; tray still keeps SID routing-active.
        reg.on_disconnect(SID_A, IpcClientProfile::GuiInteractive);
        let e = reg.entry(SID_A).unwrap();
        assert_eq!(e.connection_count, 1);
        assert_eq!(e.gui_connections, 0);
        assert_eq!(e.tray_connections, 1);
        assert!(!e.has_gui());
        assert!(e.has_tray());
        assert!(reg.is_active(SID_A));

        // Drop tray; SID exits routing.
        reg.on_disconnect(SID_A, IpcClientProfile::TrayLightweight);
        assert!(!reg.is_active(SID_A));
    }

    #[test]
    fn separate_sids_are_independent() {
        let reg = ActiveSidRegistry::new();
        reg.on_connect(SID_A, IpcClientProfile::TrayLightweight);
        reg.on_connect(SID_B, IpcClientProfile::TrayLightweight);
        assert_eq!(reg.len(), 2);
        assert_eq!(
            reg.active_sids(),
            vec![SID_A.to_string(), SID_B.to_string()]
        );
        reg.on_disconnect(SID_A, IpcClientProfile::TrayLightweight);
        assert_eq!(reg.active_sids(), vec![SID_B.to_string()]);
    }

    #[test]
    fn redundant_disconnect_does_not_corrupt_state() {
        let reg = ActiveSidRegistry::new();
        reg.on_disconnect(SID_A, IpcClientProfile::TrayLightweight); // unknown SID, ignored
        reg.on_connect(SID_A, IpcClientProfile::TrayLightweight);
        reg.on_disconnect(SID_A, IpcClientProfile::TrayLightweight);
        // Stray extra disconnect: no panic, no underflow.
        reg.on_disconnect(SID_A, IpcClientProfile::TrayLightweight);
        assert!(reg.is_empty());
    }

    #[test]
    fn multiple_listeners_all_fire() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let reg = ActiveSidRegistry::new();
        let a = Arc::new(AtomicUsize::new(0));
        let b = Arc::new(AtomicUsize::new(0));
        let aa = Arc::clone(&a);
        let bb = Arc::clone(&b);
        reg.add_listener(Arc::new(move |_| {
            aa.fetch_add(1, Ordering::SeqCst);
        }));
        reg.add_listener(Arc::new(move |_| {
            bb.fetch_add(1, Ordering::SeqCst);
        }));
        reg.on_connect(SID_A, IpcClientProfile::TrayLightweight);
        reg.on_disconnect(SID_A, IpcClientProfile::TrayLightweight);
        assert_eq!(a.load(Ordering::SeqCst), 2);
        assert_eq!(b.load(Ordering::SeqCst), 2);
    }
}
