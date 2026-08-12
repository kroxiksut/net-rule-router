//! Write-only sink interfaces for diagnostics and audit.
//!
//! # Two distinct sink types
//!
//! | Trait              | Stream              | On write failure                          |
//! |--------------------|---------------------|-------------------------------------------|
//! | [`DiagnosticsSink`]| Operational logs    | Drop event; increment dropped counter     |
//! | [`AuditSink`]      | Security audit NDJSON| Return `Err`; caller must block or recover|
//!
//! # Test utilities
//!
//! [`NoopSink`] discards all events silently — suitable for tests that do
//! not assert on emitted events.
//!
//! [`CapturingSink`] stores events in an `Arc<Mutex<Vec<E>>>` so tests can
//! assert the exact sequence of emitted events.
//!
//! # Event types
//!
//! The concrete event types (`LogEvent`, `AuditEvent`) are defined
//! elsewhere in this crate. These traits are generic over the event type so
//! that this module can be compiled and tested independently.

use std::sync::{Arc, Mutex};

use crate::error::DiagnosticsError;

// ── DiagnosticsSink ───────────────────────────────────────────────────────────

/// Write-only sink for operational diagnostic events.
///
/// Implementations write events to the NDJSON operational log files.
/// Failure to write must be handled gracefully: the service
/// must not crash on log write failure.
///
/// The bound `Send + Sync + 'static` allows sinks to be shared across
/// service tasks via `Arc<dyn DiagnosticsSink<…>>`.
pub trait DiagnosticsSink: Send + Sync {
    /// The event type this sink accepts.
    type Event: Send + 'static;

    /// Emit a single diagnostic event.
    ///
    /// If the underlying writer is unavailable the event must be silently
    /// dropped and the implementation's dropped-event counter incremented.
    /// This method must not block indefinitely.
    fn emit(&self, event: Self::Event);

    /// Best-effort flush of any internally buffered events.
    ///
    /// Called on service shutdown.  Implementations that write synchronously
    /// may make this a no-op.
    fn flush(&self) {}

    /// Number of events dropped since the sink was created due to write errors
    /// or back-pressure.  Used for the health status field `dropped_event_count`.
    fn dropped_count(&self) -> u64 {
        0
    }
}

// ── AuditSink ─────────────────────────────────────────────────────────────────

/// Write-only sink for security audit events (append-only NDJSON trail).
///
/// Unlike [`DiagnosticsSink`], this trait returns a `Result` because audit
/// write failures are security-significant: the caller must not proceed with
/// a security-critical state transition if the audit write fails.
pub trait AuditSink: Send + Sync {
    /// The audit event type this sink accepts.
    type Event: Send + 'static;

    /// Append an audit event to the NDJSON audit trail.
    ///
    /// Returns `Err(DiagnosticsError::AuditWriteFailed)` on failure.
    /// The caller must block the security-critical action or initiate
    /// the explicit recovery flow on error.
    fn append(&self, event: Self::Event) -> Result<(), DiagnosticsError>;
}

// ── NoopSink ──────────────────────────────────────────────────────────────────

/// A sink that discards all events.
///
/// Use in tests and scaffold code where event output is not under test.
pub struct NoopSink<E> {
    _marker: std::marker::PhantomData<fn(E)>,
}

impl<E> NoopSink<E> {
    pub fn new() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }
}

impl<E> Default for NoopSink<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E: Send + 'static> DiagnosticsSink for NoopSink<E> {
    type Event = E;
    fn emit(&self, _event: E) {}
}

impl<E: Send + 'static> AuditSink for NoopSink<E> {
    type Event = E;
    fn append(&self, _event: E) -> Result<(), DiagnosticsError> {
        Ok(())
    }
}

// ── CapturingSink ─────────────────────────────────────────────────────────────

/// A sink that records all events for test assertions.
///
/// Thread-safe: can be cloned and shared across tasks.
/// `Clone` is implemented manually so that `E: Clone` is not required —
/// cloning the sink shares the same underlying `Arc`, not the events.
pub struct CapturingSink<E> {
    events: Arc<Mutex<Vec<E>>>,
}

impl<E> Clone for CapturingSink<E> {
    fn clone(&self) -> Self {
        Self {
            events: Arc::clone(&self.events),
        }
    }
}

// Test-support sink: lock-poisoning `expect()` is acceptable scaffolding.
#[allow(clippy::expect_used)]
impl<E> CapturingSink<E> {
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Drain all captured events, returning them in emission order.
    pub fn drain(&self) -> Vec<E> {
        self.events
            .lock()
            .expect("CapturingSink mutex poisoned")
            .drain(..)
            .collect()
    }

    /// Number of events captured so far.
    pub fn len(&self) -> usize {
        self.events
            .lock()
            .expect("CapturingSink mutex poisoned")
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<E> Default for CapturingSink<E> {
    fn default() -> Self {
        Self::new()
    }
}

// Test-support sink: lock-poisoning `expect()` is acceptable scaffolding.
#[allow(clippy::expect_used)]
impl<E: Send + 'static> DiagnosticsSink for CapturingSink<E> {
    type Event = E;

    fn emit(&self, event: E) {
        self.events
            .lock()
            .expect("CapturingSink mutex poisoned")
            .push(event);
    }
}

// Test-support sink: lock-poisoning `expect()` is acceptable scaffolding.
#[allow(clippy::expect_used)]
impl<E: Send + 'static> AuditSink for CapturingSink<E> {
    type Event = E;

    fn append(&self, event: E) -> Result<(), DiagnosticsError> {
        self.events
            .lock()
            .expect("CapturingSink mutex poisoned")
            .push(event);
        Ok(())
    }
}

// ── FailingAuditSink ──────────────────────────────────────────────────────────

/// An [`AuditSink`] that always returns `AuditWriteFailed`.
///
/// Use in tests that verify callers block on audit failure.
pub struct FailingAuditSink<E> {
    _marker: std::marker::PhantomData<fn(E)>,
}

impl<E> FailingAuditSink<E> {
    pub fn new() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }
}

impl<E> Default for FailingAuditSink<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E: Send + 'static> AuditSink for FailingAuditSink<E> {
    type Event = E;

    fn append(&self, _event: E) -> Result<(), DiagnosticsError> {
        Err(DiagnosticsError::AuditWriteFailed {
            reason: "FailingAuditSink: always fails (test fixture)".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq)]
    struct TestEvent(u32);

    #[test]
    fn noop_sink_accepts_events_silently() {
        let sink: NoopSink<TestEvent> = NoopSink::new();
        sink.emit(TestEvent(1));
        sink.emit(TestEvent(2));
        assert_eq!(sink.dropped_count(), 0);
    }

    #[test]
    fn noop_audit_sink_returns_ok() {
        let sink: NoopSink<TestEvent> = NoopSink::new();
        assert!(sink.append(TestEvent(99)).is_ok());
    }

    #[test]
    fn capturing_sink_records_events_in_order() {
        let sink: CapturingSink<TestEvent> = CapturingSink::new();
        sink.emit(TestEvent(10));
        sink.emit(TestEvent(20));
        sink.emit(TestEvent(30));
        assert_eq!(sink.len(), 3);
        let events = sink.drain();
        assert_eq!(events, [TestEvent(10), TestEvent(20), TestEvent(30)]);
        assert!(sink.is_empty());
    }

    #[test]
    fn capturing_audit_sink_records_and_returns_ok() {
        let sink: CapturingSink<TestEvent> = CapturingSink::new();
        assert!(sink.append(TestEvent(1)).is_ok());
        assert!(sink.append(TestEvent(2)).is_ok());
        let events = sink.drain();
        assert_eq!(events, [TestEvent(1), TestEvent(2)]);
    }

    #[test]
    fn capturing_sink_clone_shares_storage() {
        let sink: CapturingSink<TestEvent> = CapturingSink::new();
        let clone = sink.clone();
        sink.emit(TestEvent(7));
        clone.emit(TestEvent(8));
        assert_eq!(sink.len(), 2);
    }

    #[test]
    fn failing_audit_sink_returns_err() {
        let sink: FailingAuditSink<TestEvent> = FailingAuditSink::new();
        let result = sink.append(TestEvent(0));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DiagnosticsError::AuditWriteFailed { .. }
        ));
    }

    #[test]
    fn noop_sink_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NoopSink<u32>>();
    }

    #[test]
    fn capturing_sink_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CapturingSink<u32>>();
    }
}
