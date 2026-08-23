//! The OS's own operator-facing log — the place an administrator looks before
//! they know this product has logs of its own.
//!
//! Our NDJSON trail stays the primary channel: it is complete, structured and
//! ours. This port carries the handful of facts an operator needs from OUTSIDE
//! the product — did the service start, did it stop, is it running but not
//! enforcing — into the log their tooling already watches. Windows: the
//! Application event log. Linux: nothing to implement, because the daemon's
//! stdout is already the journal.

/// Severity as the host log understands it. Deliberately three levels: an
/// operator log that distinguishes more than "fine / worth a look / broken"
/// invites the writer to agonise over gradations nobody filters on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemEventSeverity {
    Info,
    Warning,
    Error,
}

/// One record for the host log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemEventRecord {
    pub severity: SystemEventSeverity,
    /// Stable per kind of event, so an operator can filter on it. Small values
    /// only — see the Windows implementation for why the range matters.
    pub event_id: u32,
    pub message: String,
}

/// Writes records into the host's operator log. Best-effort by contract: a log
/// nobody can write to must never stop the service, so the implementation
/// swallows its own failures and the caller has nothing to handle.
pub trait SystemEventLogPort: Send + Sync {
    fn write(&self, record: &SystemEventRecord);
}
