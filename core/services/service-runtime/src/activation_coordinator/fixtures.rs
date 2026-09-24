//! Doubles for the ports above, shared by the tests of this module and of the
//! ones that drive it. Always compiled, like the rest of `test_support`.
//!
//! Split out of `activation_coordinator`; the code is unchanged.

use super::*;

// ── Test fixtures (test-only, public for cross-module use) ────────────────────

/// Fixed-time clock for tests. Seconds advance only via `tick()`.
pub struct FixedClock {
    secs: Mutex<i64>,
}

// Test double: lock-poisoning `unwrap()`/`expect()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl FixedClock {
    pub fn new(initial: i64) -> Arc<Self> {
        Arc::new(Self {
            secs: Mutex::new(initial),
        })
    }

    pub fn tick(&self, by: i64) {
        let mut s = self.secs.lock().expect("clock mutex poisoned");
        *s += by;
    }
}

// Test double: lock-poisoning `unwrap()`/`expect()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl Clock for FixedClock {
    fn now_secs(&self) -> i64 {
        *self.secs.lock().expect("clock mutex poisoned")
    }
}

/// Counter-based ID generator for deterministic tests.
pub struct CounterIds {
    counter: Mutex<u64>,
}

impl Default for CounterIds {
    fn default() -> Self {
        Self::new()
    }
}

impl CounterIds {
    pub fn new() -> Self {
        Self {
            counter: Mutex::new(0),
        }
    }
}

// Test double: lock-poisoning `unwrap()`/`expect()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl IdGenerator for CounterIds {
    fn new_revision_id(&self) -> RevisionId {
        let mut c = self.counter.lock().expect("ids mutex poisoned");
        *c += 1;
        let id = format!("rev-{:08}", *c);
        RevisionId::from_prefixed_string(id).expect("counter ids are well-formed")
    }

    fn new_token(&self) -> String {
        let mut c = self.counter.lock().expect("ids mutex poisoned");
        *c += 1;
        format!("tok-{:08}", *c)
    }

    fn new_attempt_id(&self) -> String {
        let mut c = self.counter.lock().expect("ids mutex poisoned");
        *c += 1;
        format!("att-{:08}", *c)
    }
}

/// Records every audit event for assertions.
pub struct RecordingAudit {
    events: Mutex<Vec<ActivationAuditEvent>>,
}

impl Default for RecordingAudit {
    fn default() -> Self {
        Self::new()
    }
}

// Test double: lock-poisoning `unwrap()`/`expect()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl RecordingAudit {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    pub fn snapshot(&self) -> Vec<ActivationAuditEvent> {
        self.events.lock().expect("audit mutex poisoned").clone()
    }
}

// Test double: lock-poisoning `unwrap()`/`expect()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl ActivationAuditEmitter for RecordingAudit {
    fn emit(&self, event: ActivationAuditEvent) {
        self.events
            .lock()
            .expect("audit mutex poisoned")
            .push(event);
    }
}

/// In-memory marker store for tests. Production uses a SQLite-backed
/// impl.
pub struct InMemoryMarkerStore {
    inner: Mutex<Option<ApplyAttemptMarker>>,
}

impl Default for InMemoryMarkerStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryMarkerStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }
}

// Test double: lock-poisoning `unwrap()`/`expect()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl ApplyMarkerStore for InMemoryMarkerStore {
    fn read(&self) -> Option<ApplyAttemptMarker> {
        self.inner.lock().expect("marker mutex poisoned").clone()
    }

    fn write(&self, marker: &ApplyAttemptMarker) -> Result<(), String> {
        *self.inner.lock().expect("marker mutex poisoned") = Some(marker.clone());
        Ok(())
    }

    fn clear(&self) -> Result<(), String> {
        *self.inner.lock().expect("marker mutex poisoned") = None;
        Ok(())
    }
}

/// Scriptable dispatcher — tests assign per-SID outcomes.
pub struct ScriptedDispatcher {
    apply_outcomes: Mutex<BTreeMap<String, Vec<Result<(), DispatchFailure>>>>,
    pre_flight_outcomes: Mutex<BTreeMap<String, Vec<PreFlightWarning>>>,
    pre_flight_errors: Mutex<BTreeMap<String, DispatchFailure>>,
    apply_log: Mutex<Vec<(String, String)>>,
    revert_log: Mutex<Vec<(String, String)>>,
    revert_outcomes: Mutex<BTreeMap<String, Vec<Result<(), DispatchFailure>>>>,
}

impl Default for ScriptedDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

// Test double: lock-poisoning `unwrap()`/`expect()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl ScriptedDispatcher {
    pub fn new() -> Self {
        Self {
            apply_outcomes: Mutex::new(BTreeMap::new()),
            pre_flight_outcomes: Mutex::new(BTreeMap::new()),
            pre_flight_errors: Mutex::new(BTreeMap::new()),
            apply_log: Mutex::new(Vec::new()),
            revert_log: Mutex::new(Vec::new()),
            revert_outcomes: Mutex::new(BTreeMap::new()),
        }
    }

    /// Queue a per-SID `apply_for_sid` outcome. Multiple queued outcomes
    /// are drained in FIFO order.
    pub fn queue_apply(&self, sid: &str, outcome: Result<(), DispatchFailure>) {
        self.apply_outcomes
            .lock()
            .expect("dispatcher mutex poisoned")
            .entry(sid.to_string())
            .or_default()
            .push(outcome);
    }

    /// Queue a per-SID `revert_for_sid` outcome, FIFO like `queue_apply`.
    pub fn queue_revert(&self, sid: &str, outcome: Result<(), DispatchFailure>) {
        self.revert_outcomes
            .lock()
            .expect("dispatcher mutex poisoned")
            .entry(sid.to_string())
            .or_default()
            .push(outcome);
    }

    /// Configure pre-flight to return warnings (categories that upgrade
    /// to failures will fail Phase 2a).
    pub fn set_pre_flight(&self, sid: &str, warnings: Vec<PreFlightWarning>) {
        self.pre_flight_outcomes
            .lock()
            .expect("dispatcher mutex poisoned")
            .insert(sid.to_string(), warnings);
    }

    /// Configure pre-flight to return an outright dispatcher failure.
    pub fn set_pre_flight_error(&self, sid: &str, failure: DispatchFailure) {
        self.pre_flight_errors
            .lock()
            .expect("dispatcher mutex poisoned")
            .insert(sid.to_string(), failure);
    }

    pub fn apply_log(&self) -> Vec<(String, String)> {
        self.apply_log
            .lock()
            .expect("dispatcher mutex poisoned")
            .clone()
    }

    pub fn revert_log(&self) -> Vec<(String, String)> {
        self.revert_log
            .lock()
            .expect("dispatcher mutex poisoned")
            .clone()
    }
}

// Test double: lock-poisoning `unwrap()`/`expect()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl RulesApplyDispatcher for ScriptedDispatcher {
    fn dry_run_for_sid(
        &self,
        sid: &str,
        _rules_json: &str,
    ) -> Result<SidActionPlanSummary, DispatchFailure> {
        Ok(SidActionPlanSummary {
            sid: sid.to_string(),
            filter_additions: 1,
            filter_removals: 0,
            routing_actions: 0,
        })
    }

    fn pre_flight_for_sid(
        &self,
        sid: &str,
        _rules_json: &str,
    ) -> Result<Vec<PreFlightWarning>, DispatchFailure> {
        if let Some(err) = self
            .pre_flight_errors
            .lock()
            .expect("dispatcher mutex poisoned")
            .remove(sid)
        {
            return Err(err);
        }
        Ok(self
            .pre_flight_outcomes
            .lock()
            .expect("dispatcher mutex poisoned")
            .get(sid)
            .cloned()
            .unwrap_or_default())
    }

    fn apply_for_sid(&self, sid: &str, rules_json: &str) -> Result<(), DispatchFailure> {
        self.apply_log
            .lock()
            .expect("dispatcher mutex poisoned")
            .push((sid.to_string(), rules_json.to_string()));
        let mut map = self
            .apply_outcomes
            .lock()
            .expect("dispatcher mutex poisoned");
        let queue = map.entry(sid.to_string()).or_default();
        if queue.is_empty() {
            Ok(())
        } else {
            queue.remove(0)
        }
    }

    fn revert_for_sid(&self, sid: &str, previous_rules_json: &str) -> Result<(), DispatchFailure> {
        self.revert_log
            .lock()
            .expect("dispatcher mutex poisoned")
            .push((sid.to_string(), previous_rules_json.to_string()));
        let mut queued = self
            .revert_outcomes
            .lock()
            .expect("dispatcher mutex poisoned");
        match queued.get_mut(sid).and_then(|q| {
            if q.is_empty() {
                None
            } else {
                Some(q.remove(0))
            }
        }) {
            Some(outcome) => outcome,
            None => Ok(()),
        }
    }
}
