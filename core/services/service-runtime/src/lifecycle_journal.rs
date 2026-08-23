//! Which lifecycle transitions the operator's own log deserves to hear about.
//!
//! The mechanism is per-OS ([`SystemEventLogPort`]); this is the decision, and
//! it is shared. Two rules do the work:
//!
//! - **Outcomes, not intentions.** `Starting` and `Stopping` say only that
//!   something was attempted; an operator wants the answer, so only the states
//!   that ARE an answer get a record.
//! - **Changes, not pings.** The SCM re-reports `Running` for as long as the
//!   service lives. Writing each one would bury the interesting entries in a
//!   log we do not own and cannot rotate, so the journal keeps the last state
//!   recorded and stays silent until it moves.

use nrr_platform_api::system_event_log::{
    SystemEventLogPort, SystemEventRecord, SystemEventSeverity,
};

use crate::state::ServiceRuntimeState;

/// Event ids, stable so an operator can filter on them. Kept small on purpose:
/// the Windows sink borrows a generic message table that only renders low ids.
const EVENT_ID_STARTED: u32 = 1;
const EVENT_ID_STOPPED: u32 = 2;
const EVENT_ID_DEGRADED: u32 = 3;
const EVENT_ID_RECOVERY_REQUIRED: u32 = 4;
const EVENT_ID_DISABLED: u32 = 5;

/// The record a state deserves, or `None` when the state is an intention rather
/// than an outcome.
pub fn record_for(state: ServiceRuntimeState) -> Option<SystemEventRecord> {
    let (severity, event_id, message) = match state {
        ServiceRuntimeState::Starting | ServiceRuntimeState::Stopping => return None,
        ServiceRuntimeState::Running => (
            SystemEventSeverity::Info,
            EVENT_ID_STARTED,
            "NetRuleRouter service started and is applying routing policy.",
        ),
        ServiceRuntimeState::Stopped => (
            SystemEventSeverity::Info,
            EVENT_ID_STOPPED,
            "NetRuleRouter service stopped.",
        ),
        // Running, but something it depends on is unhealthy. Warning rather than
        // error: policy is still being applied.
        ServiceRuntimeState::Degraded => (
            SystemEventSeverity::Warning,
            EVENT_ID_DEGRADED,
            "NetRuleRouter service is running in a degraded state. Open Diagnostics in the app \
             for the failing component.",
        ),
        // The one an operator must not miss: the process is up, so every naive
        // health check passes, and nothing is being enforced.
        ServiceRuntimeState::RecoveryRequired => (
            SystemEventSeverity::Error,
            EVENT_ID_RECOVERY_REQUIRED,
            "NetRuleRouter service started but cannot apply routing policy and needs recovery. \
             Traffic is not being routed by policy.",
        ),
        ServiceRuntimeState::Disabled => (
            SystemEventSeverity::Warning,
            EVENT_ID_DISABLED,
            "NetRuleRouter service is installed but routing is disabled.",
        ),
    };
    Some(SystemEventRecord {
        severity,
        event_id,
        message: message.to_string(),
    })
}

/// Change-suppressing writer around a [`SystemEventLogPort`].
///
/// Give it every state report; it writes the ones that are both worth a record
/// and new.
pub struct LifecycleJournal {
    sink: std::sync::Arc<dyn SystemEventLogPort>,
    last: std::sync::Mutex<Option<ServiceRuntimeState>>,
}

impl LifecycleJournal {
    pub fn new(sink: std::sync::Arc<dyn SystemEventLogPort>) -> Self {
        Self {
            sink,
            last: std::sync::Mutex::new(None),
        }
    }

    /// Observe a reported state. Writes at most one record.
    pub fn observe(&self, state: ServiceRuntimeState) {
        let mut last = self.last.lock().unwrap_or_else(|p| p.into_inner());
        if *last == Some(state) {
            return;
        }
        // Remember the state even when it earns no record, so a
        // Running → Stopping → Running flap still writes the second Running.
        *last = Some(state);
        drop(last);
        if let Some(record) = record_for(state) {
            self.sink.write(&record);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct RecordingSink {
        written: Mutex<Vec<SystemEventRecord>>,
    }

    impl SystemEventLogPort for RecordingSink {
        fn write(&self, record: &SystemEventRecord) {
            self.written
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(record.clone());
        }
    }

    fn written(sink: &Arc<RecordingSink>) -> Vec<SystemEventRecord> {
        sink.written
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    #[test]
    fn intentions_earn_no_record() {
        assert!(record_for(ServiceRuntimeState::Starting).is_none());
        assert!(record_for(ServiceRuntimeState::Stopping).is_none());
    }

    /// The state that must never be quiet: up, healthy-looking, enforcing
    /// nothing.
    #[test]
    fn recovery_required_is_an_error_not_a_warning() {
        let record = record_for(ServiceRuntimeState::RecoveryRequired).expect("record");
        assert_eq!(record.severity, SystemEventSeverity::Error);
        assert!(record.message.contains("not being routed"));
    }

    #[test]
    fn a_repeated_state_is_written_once() {
        let sink = Arc::new(RecordingSink::default());
        let journal = LifecycleJournal::new(Arc::clone(&sink) as Arc<dyn SystemEventLogPort>);
        for _ in 0..5 {
            journal.observe(ServiceRuntimeState::Running);
        }
        assert_eq!(written(&sink).len(), 1, "SCM pings must not fill the log");
    }

    #[test]
    fn a_full_run_writes_start_then_stop() {
        let sink = Arc::new(RecordingSink::default());
        let journal = LifecycleJournal::new(Arc::clone(&sink) as Arc<dyn SystemEventLogPort>);
        for state in [
            ServiceRuntimeState::Starting,
            ServiceRuntimeState::Running,
            ServiceRuntimeState::Running,
            ServiceRuntimeState::Stopping,
            ServiceRuntimeState::Stopped,
        ] {
            journal.observe(state);
        }
        let ids: Vec<u32> = written(&sink).iter().map(|r| r.event_id).collect();
        assert_eq!(ids, vec![EVENT_ID_STARTED, EVENT_ID_STOPPED]);
    }

    /// A degrade and a recovery are both transitions, so both are recorded —
    /// otherwise the log would show a service that went bad and never came back.
    #[test]
    fn degrading_and_recovering_are_both_recorded() {
        let sink = Arc::new(RecordingSink::default());
        let journal = LifecycleJournal::new(Arc::clone(&sink) as Arc<dyn SystemEventLogPort>);
        journal.observe(ServiceRuntimeState::Running);
        journal.observe(ServiceRuntimeState::Degraded);
        journal.observe(ServiceRuntimeState::Running);
        let ids: Vec<u32> = written(&sink).iter().map(|r| r.event_id).collect();
        assert_eq!(
            ids,
            vec![EVENT_ID_STARTED, EVENT_ID_DEGRADED, EVENT_ID_STARTED]
        );
    }
}
