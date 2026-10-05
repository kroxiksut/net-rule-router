//! Verbose service logging: a [`TimedSwitch`] driving the live tracing filter.
//!
//! Verbose logging writes debug events and unredacted hosts and addresses, so
//! it is a window that ends by itself (`crate::timed_window`).

use std::path::Path;
use std::sync::Arc;

use crate::timed_window::{now_ms, TimedSwitch, TimedWindow, WindowKind, WindowSink};
use crate::verbosity_control::VerbosityControl;

/// Resume after a restart. The boot path already installed the filter the
/// stored deadline asks for, so the live filter is touched only when that
/// deadline has passed since — leaving an `NRR_LOG` override alone otherwise.
#[must_use]
pub fn resume(
    persisted_until_ms: Option<i64>,
    now_ms: i64,
    control: Option<Arc<dyn VerbosityControl>>,
) -> TimedSwitch {
    let sink = control
        .map(|control| Arc::new(move |verbose: bool| control.set_verbose(verbose)) as WindowSink);
    TimedSwitch::resume(WindowKind::VerboseLogging, persisted_until_ms, now_ms, sink)
}

/// Whether a starting service logs verbosely: a stored window is still open.
/// Read on a short-lived connection before tracing is installed, so the first
/// event already meets the right filter. Anything unreadable is normal logging.
#[must_use]
pub fn verbose_at_boot(state_db_path: &Path) -> bool {
    let now = now_ms();
    TimedWindow::resumed(persisted_until_at_boot(state_db_path), now).is_open(now)
}

/// The stored deadline, whether or not it has passed.
#[must_use]
pub fn persisted_until_at_boot(state_db_path: &Path) -> Option<i64> {
    if !state_db_path.exists() {
        return None;
    }
    // The storage factory, not a raw open: its busy timeout keeps a momentary
    // writer lock from reading as "no window".
    let conn = nrr_storage::migration::open_connection(state_db_path).ok()?;
    nrr_storage::service_stability_config::probe_verbose_until(&conn)
}

#[cfg(test)]
mod tests;
