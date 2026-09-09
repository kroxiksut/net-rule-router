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

/// Writes records into the host's operator log, and reads back the one boot
/// milestone the product needs from it.
///
/// Best-effort by contract on both halves: a log nobody can write to must never
/// stop the service, and a milestone nobody can read is answered with `None`
/// rather than an error the caller would have to invent a story for.
pub trait SystemEventLogPort: Send + Sync {
    fn write(&self, record: &SystemEventRecord);

    /// When THIS boot asked the user to sign in, as Unix milliseconds.
    ///
    /// The product is regularly suspected of slowing down boot, and the honest
    /// answer is a comparison: the service either started before that moment or
    /// after it. Windows records the moment as `Wininit` event 14; a host with
    /// no equivalent answers `None`, which the caller renders as "cannot tell"
    /// — never as "zero delay", because an unanswerable question must not read
    /// as an exoneration.
    ///
    /// Defaulted so a backend that has no such record — and every test double —
    /// stays honest without writing a stub that lies.
    fn sign_in_prompt_at_ms(&self) -> Option<u64> {
        None
    }
}
