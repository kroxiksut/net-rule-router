//! Verbose service logging as a window that ends by itself.
//!
//! Verbose logging writes debug events and unredacted hosts and addresses, so
//! a switch left on costs disk and privacy for as long as nobody remembers it.
//! Every window therefore ends on its own — at its deadline, or when the
//! service restarts — and only a timed window is persisted, as an absolute
//! deadline, so a restart inside it resumes it and a restart after it does not.

use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use nrr_shared::ipc_payloads::{VerboseLoggingChange, VerboseLoggingMode};

use crate::verbosity_control::VerbosityControl;

/// How verbosely the service logs right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerboseWindow {
    Off,
    Until { deadline_ms: i64 },
    UntilRestart,
}

impl VerboseWindow {
    /// The window a starting service resumes: a stored deadline still ahead,
    /// or normal logging.
    #[must_use]
    pub fn resumed(persisted_until_ms: Option<i64>, now_ms: i64) -> Self {
        match persisted_until_ms {
            Some(deadline_ms) if deadline_ms > now_ms => Self::Until { deadline_ms },
            _ => Self::Off,
        }
    }

    /// The window a client asked for at `now_ms`.
    #[must_use]
    pub fn requested(change: VerboseLoggingChange, now_ms: i64) -> Self {
        match (change, change.window_ms()) {
            (_, Some(len)) => Self::Until {
                deadline_ms: now_ms.saturating_add(len),
            },
            (VerboseLoggingChange::UntilRestart, None) => Self::UntilRestart,
            _ => Self::Off,
        }
    }

    #[must_use]
    pub fn is_verbose(self, now_ms: i64) -> bool {
        match self {
            Self::Off => false,
            Self::Until { deadline_ms } => now_ms < deadline_ms,
            Self::UntilRestart => true,
        }
    }

    /// What may outlive the process: a timed window's deadline, nothing else.
    #[must_use]
    pub fn persisted_until_ms(self) -> Option<i64> {
        match self {
            Self::Until { deadline_ms } => Some(deadline_ms),
            Self::Off | Self::UntilRestart => None,
        }
    }

    /// The wire answer at `now_ms`: the mode and a timed window's deadline.
    #[must_use]
    pub fn reported(self, now_ms: i64) -> (VerboseLoggingMode, i64) {
        match self {
            Self::Until { deadline_ms } if now_ms < deadline_ms => {
                (VerboseLoggingMode::Timed, deadline_ms)
            }
            Self::UntilRestart => (VerboseLoggingMode::UntilRestart, 0),
            _ => (VerboseLoggingMode::Off, 0),
        }
    }
}

/// The running window and the live filter it drives. The deadline is kept by a
/// timer thread per timed window; a newer window retires the older timer.
pub struct VerboseLogging {
    shared: Arc<Shared>,
}

struct Shared {
    slot: Mutex<Slot>,
    changed: Condvar,
    control: Option<Arc<dyn VerbosityControl>>,
}

struct Slot {
    window: VerboseWindow,
    generation: u64,
}

impl VerboseLogging {
    /// Resume after a restart. The boot path already installed the filter the
    /// stored deadline asks for, so the live filter is touched only when that
    /// deadline has passed since — leaving an `NRR_LOG` override alone
    /// otherwise.
    #[must_use]
    pub fn resume(
        persisted_until_ms: Option<i64>,
        now_ms: i64,
        control: Option<Arc<dyn VerbosityControl>>,
    ) -> Self {
        let window = VerboseWindow::resumed(persisted_until_ms, now_ms);
        let this = Self {
            shared: Arc::new(Shared {
                slot: Mutex::new(Slot {
                    window,
                    generation: 0,
                }),
                changed: Condvar::new(),
                control,
            }),
        };
        match window {
            VerboseWindow::Until { deadline_ms } => this.arm_expiry(0, deadline_ms),
            _ if persisted_until_ms.is_some() => {
                if let Some(control) = &this.shared.control {
                    control.set_verbose(false);
                }
            }
            _ => {}
        }
        this
    }

    /// Whether a live filter is attached, i.e. whether a change applies now.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.shared.control.is_some()
    }

    #[must_use]
    pub fn window(&self) -> VerboseWindow {
        lock(&self.shared.slot).window
    }

    /// Switch to `window` and drive the live filter to match.
    pub fn set(&self, window: VerboseWindow, now_ms: i64) {
        let generation = {
            let mut slot = lock(&self.shared.slot);
            slot.window = window;
            slot.generation = slot.generation.wrapping_add(1);
            // Under the lock, so two racing writes cannot leave the filter
            // disagreeing with the window that won.
            if let Some(control) = &self.shared.control {
                control.set_verbose(window.is_verbose(now_ms));
            }
            slot.generation
        };
        self.shared.changed.notify_all();
        if let VerboseWindow::Until { deadline_ms } = window {
            self.arm_expiry(generation, deadline_ms);
        }
    }

    /// Only a live filter needs the timer: without one the window is read
    /// against the clock, which already ends it on time.
    fn arm_expiry(&self, generation: u64, deadline_ms: i64) {
        if self.shared.control.is_none() {
            return;
        }
        let shared = Arc::clone(&self.shared);
        let spawned = std::thread::Builder::new()
            .name("nrr-verbose-expiry".to_owned())
            .spawn(move || expire_at(&shared, generation, deadline_ms));
        if let Err(e) = spawned {
            tracing::warn!(
                target: "nrr::stability",
                msg_key = "verbose-logging-expiry-unarmed",
                error = %e,
                "verbose logging timer could not start; the window ends at the next service restart",
            );
        }
    }
}

fn expire_at(shared: &Shared, generation: u64, deadline_ms: i64) {
    let mut slot = lock(&shared.slot);
    loop {
        if slot.generation != generation {
            return;
        }
        let now = now_ms();
        if now >= deadline_ms {
            slot.window = VerboseWindow::Off;
            slot.generation = slot.generation.wrapping_add(1);
            if let Some(control) = &shared.control {
                control.set_verbose(false);
            }
            tracing::info!(
                target: "nrr::stability",
                msg_key = "verbose-logging-window-ended",
                "verbose service logging window ended; back to normal logging",
            );
            return;
        }
        // A clock stepped backwards only lengthens the wait; the loop re-reads it.
        let wait = Duration::from_millis(u64::try_from(deadline_ms - now).unwrap_or(0));
        slot = match shared.changed.wait_timeout(slot, wait) {
            Ok((guard, _)) => guard,
            Err(poisoned) => poisoned.into_inner().0,
        };
    }
}

/// Wall-clock UTC milliseconds: deadlines are stored as absolute times.
#[must_use]
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn lock(slot: &Mutex<Slot>) -> MutexGuard<'_, Slot> {
    slot.lock().unwrap_or_else(|p| p.into_inner())
}

/// Whether a starting service logs verbosely: a stored window is still open.
/// Read on a short-lived connection before tracing is installed, so the first
/// event already meets the right filter. Anything unreadable is normal logging.
#[must_use]
pub fn verbose_at_boot(state_db_path: &Path) -> bool {
    let now = now_ms();
    VerboseWindow::resumed(persisted_until_at_boot(state_db_path), now).is_verbose(now)
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
