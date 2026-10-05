//! A diagnostic log switch as a window that closes by itself.
//!
//! Verbose logging and the connection trace on disk both write privacy-
//! sensitive detail and cost disk for as long as nobody remembers them. Every
//! window therefore ends on its own — at its deadline, or when the service
//! restarts — and only a timed window is persisted, as an absolute deadline,
//! so a restart inside it resumes it and a restart after it does not.

use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use nrr_shared::ipc_payloads::{LogWindowChange, LogWindowMode};

/// Where a window stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimedWindow {
    Off,
    Until { deadline_ms: i64 },
    UntilRestart,
}

impl TimedWindow {
    /// The window a starting service resumes: a stored deadline still ahead,
    /// or closed.
    #[must_use]
    pub fn resumed(persisted_until_ms: Option<i64>, now_ms: i64) -> Self {
        match persisted_until_ms {
            Some(deadline_ms) if deadline_ms > now_ms => Self::Until { deadline_ms },
            _ => Self::Off,
        }
    }

    /// The window a client asked for at `now_ms`.
    #[must_use]
    pub fn requested(change: LogWindowChange, now_ms: i64) -> Self {
        match (change, change.window_ms()) {
            (_, Some(len)) => Self::Until {
                deadline_ms: now_ms.saturating_add(len),
            },
            (LogWindowChange::UntilRestart, None) => Self::UntilRestart,
            _ => Self::Off,
        }
    }

    #[must_use]
    pub fn is_open(self, now_ms: i64) -> bool {
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
    pub fn reported(self, now_ms: i64) -> (LogWindowMode, i64) {
        match self {
            Self::Until { deadline_ms } if now_ms < deadline_ms => {
                (LogWindowMode::Timed, deadline_ms)
            }
            Self::UntilRestart => (LogWindowMode::UntilRestart, 0),
            _ => (LogWindowMode::Off, 0),
        }
    }
}

/// Which switch a window drives: names its timer thread and its log lines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowKind {
    VerboseLogging,
    ConnTraceLog,
}

impl WindowKind {
    fn thread_name(self) -> &'static str {
        match self {
            Self::VerboseLogging => "nrr-verbose-expiry",
            Self::ConnTraceLog => "nrr-conn-trace-expiry",
        }
    }

    fn log_ended(self) {
        match self {
            Self::VerboseLogging => tracing::info!(
                target: "nrr::stability",
                msg_key = "verbose-logging-window-ended",
                "verbose service logging window ended; back to normal logging",
            ),
            Self::ConnTraceLog => tracing::info!(
                target: "nrr::stability",
                msg_key = "conn-trace-log-window-ended",
                "connection trace log window ended; connections are no longer written to the log",
            ),
        }
    }

    fn log_unarmed(self, error: &std::io::Error) {
        match self {
            Self::VerboseLogging => tracing::warn!(
                target: "nrr::stability",
                msg_key = "verbose-logging-expiry-unarmed",
                error = %error,
                "verbose logging timer could not start; the window ends at the next restart",
            ),
            Self::ConnTraceLog => tracing::warn!(
                target: "nrr::stability",
                msg_key = "conn-trace-log-expiry-unarmed",
                error = %error,
                "connection trace log timer could not start; the window ends at the next restart",
            ),
        }
    }
}

/// What a window drives: told `true` as it opens and `false` as it closes.
pub type WindowSink = Arc<dyn Fn(bool) + Send + Sync>;

/// The running window and the sink it drives. Clones share one window. The
/// deadline is kept by a timer thread per timed window; a newer window
/// retires the older timer.
#[derive(Clone)]
pub struct TimedSwitch {
    shared: Arc<Shared>,
}

struct Shared {
    kind: WindowKind,
    slot: Mutex<Slot>,
    changed: Condvar,
    sink: Option<WindowSink>,
}

struct Slot {
    window: TimedWindow,
    generation: u64,
}

impl TimedSwitch {
    /// Resume after a restart. The caller already started the sink in the
    /// state a stored deadline asks for, so the sink is touched only when that
    /// deadline has passed since — leaving any boot-time override alone
    /// otherwise.
    #[must_use]
    pub fn resume(
        kind: WindowKind,
        persisted_until_ms: Option<i64>,
        now_ms: i64,
        sink: Option<WindowSink>,
    ) -> Self {
        let window = TimedWindow::resumed(persisted_until_ms, now_ms);
        let this = Self {
            shared: Arc::new(Shared {
                kind,
                slot: Mutex::new(Slot {
                    window,
                    generation: 0,
                }),
                changed: Condvar::new(),
                sink,
            }),
        };
        match window {
            TimedWindow::Until { deadline_ms } => this.arm_expiry(0, deadline_ms),
            _ if persisted_until_ms.is_some() => {
                if let Some(sink) = &this.shared.sink {
                    sink(false);
                }
            }
            _ => {}
        }
        this
    }

    /// Whether a sink is attached, i.e. whether a change applies now.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.shared.sink.is_some()
    }

    #[must_use]
    pub fn window(&self) -> TimedWindow {
        lock(&self.shared.slot).window
    }

    /// The window to report against a stored deadline. "Until restart" lives
    /// only in the process; a timed window is whatever the stored deadline
    /// says, which keeps every instance on one answer.
    #[must_use]
    pub fn effective(&self, persisted_until_ms: Option<i64>, now_ms: i64) -> TimedWindow {
        match self.window() {
            TimedWindow::UntilRestart => TimedWindow::UntilRestart,
            _ => TimedWindow::resumed(persisted_until_ms, now_ms),
        }
    }

    /// Switch to `window` and drive the sink to match.
    pub fn set(&self, window: TimedWindow, now_ms: i64) {
        let generation = {
            let mut slot = lock(&self.shared.slot);
            slot.window = window;
            slot.generation = slot.generation.wrapping_add(1);
            // Under the lock, so two racing writes cannot leave the sink
            // disagreeing with the window that won.
            if let Some(sink) = &self.shared.sink {
                sink(window.is_open(now_ms));
            }
            slot.generation
        };
        self.shared.changed.notify_all();
        if let TimedWindow::Until { deadline_ms } = window {
            self.arm_expiry(generation, deadline_ms);
        }
    }

    /// Only a live sink needs the timer: without one the window is read
    /// against the clock, which already ends it on time.
    fn arm_expiry(&self, generation: u64, deadline_ms: i64) {
        if self.shared.sink.is_none() {
            return;
        }
        let shared = Arc::clone(&self.shared);
        let spawned = std::thread::Builder::new()
            .name(self.shared.kind.thread_name().to_owned())
            .spawn(move || expire_at(&shared, generation, deadline_ms));
        if let Err(e) = spawned {
            self.shared.kind.log_unarmed(&e);
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
            slot.window = TimedWindow::Off;
            slot.generation = slot.generation.wrapping_add(1);
            if let Some(sink) = &shared.sink {
                sink(false);
            }
            shared.kind.log_ended();
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

#[cfg(test)]
mod tests;
