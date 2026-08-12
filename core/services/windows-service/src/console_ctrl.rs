//! Console control handler — block 16.7.
//!
//! Replaces the `ctrlc_install` placeholder in `main.rs`. Registers a
//! `SetConsoleCtrlHandler` callback that flips a stored
//! [`StopToken`][nrr_service_runtime::StopToken] when the user presses
//! Ctrl+C, Ctrl+Break, or closes the console window.
//!
//! ## Why not `ctrlc` crate?
//!
//! Same reason the original placeholder gave: dragging in a third-party
//! crate for a single-line need is overkill. We already pull `windows`
//! for the named-pipe IPC server (block 16.1), so adding the
//! `Win32_System_Console` feature is incremental.
//!
//! ## Why a static `OnceLock<StopToken>`?
//!
//! `SetConsoleCtrlHandler` takes a plain `extern "system" fn` — no
//! closure, no user pointer. The handler must look up the token through
//! a process-global. `OnceLock` makes the assignment idempotent and
//! thread-safe; double-install (e.g. accidental call from both `console`
//! and SCM paths) is a no-op rather than a panic. Production paths only
//! call `install()` once.
//!
//! ## SCM mode
//!
//! `windows-service` already drives stop/shutdown through the SCM
//! control handler in `scm.rs`. Console-control events do not flow under
//! SCM dispatch. This module is therefore wired from `run_console`
//! only — calling it under SCM is harmless (the handler is never
//! invoked) but unnecessary.

#![cfg(windows)]
// SAFETY: This module deliberately uses `unsafe` for one reason — calling
// `SetConsoleCtrlHandler` with a function-pointer callback registered for
// the lifetime of the process. The workspace lint `unsafe_code = "deny"`
// is overridden here with a written justification per the policy in
// CLAUDE.md "`unsafe` Rust requires justification and must be localized".
#![allow(unsafe_code)]

use std::sync::OnceLock;

use nrr_service_runtime::StopToken;
use windows::Win32::Foundation::BOOL;
use windows::Win32::System::Console::{
    SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_C_EVENT, CTRL_LOGOFF_EVENT,
    CTRL_SHUTDOWN_EVENT,
};

/// Process-global stop token consulted by [`console_ctrl_handler`].
///
/// Set exactly once via [`install`]. The handler reads it through a
/// borrow that lives for the rest of the process — `OnceLock` guarantees
/// the data behind the borrow never moves.
static STOP_TOKEN: OnceLock<StopToken> = OnceLock::new();

/// Outcome of [`install`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallOutcome {
    /// The handler is registered and will fire on console-control events.
    Installed,
    /// `install` was already called earlier in this process — the prior
    /// registration is in effect, and the supplied token is ignored.
    AlreadyInstalled,
    /// The Win32 `SetConsoleCtrlHandler` call returned an error. The
    /// caller should fall back to "service runs until killed" mode (the
    /// pre-block-16.7 behaviour) and surface a warning to stderr.
    RegistrationFailed,
}

/// Install the console-control handler so Ctrl+C / Ctrl+Break / window
/// close requests flip `stop`.
///
/// Idempotent: subsequent calls return [`InstallOutcome::AlreadyInstalled`]
/// and leave the original token wired up.
pub fn install(stop: StopToken) -> InstallOutcome {
    if STOP_TOKEN.set(stop).is_err() {
        return InstallOutcome::AlreadyInstalled;
    }
    // SAFETY: `SetConsoleCtrlHandler` requires the callback to remain
    // valid for the entire time the handler is registered. Our callback
    // is a plain `extern "system" fn` with `'static` lifetime. The
    // second argument `TRUE` (`true`) means "register" rather than
    // "unregister"; passing `Some(handler)` enrolls the function pointer.
    let result = unsafe { SetConsoleCtrlHandler(Some(console_ctrl_handler), true) };
    if result.is_ok() {
        InstallOutcome::Installed
    } else {
        InstallOutcome::RegistrationFailed
    }
}

/// Win32 console-control callback.
///
/// Returns `TRUE` (`1`) for the events we handle so Windows does not
/// invoke the default handler (which terminates the process). For other
/// events we return `FALSE` so the default chain continues.
unsafe extern "system" fn console_ctrl_handler(ctrl_type: u32) -> BOOL {
    match ctrl_type {
        CTRL_C_EVENT | CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT
        | CTRL_SHUTDOWN_EVENT => {
            if let Some(stop) = STOP_TOKEN.get() {
                stop.request_stop();
            }
            BOOL(1)
        }
        _ => BOOL(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_outcome_variants_are_distinct() {
        assert_ne!(InstallOutcome::Installed, InstallOutcome::AlreadyInstalled);
        assert_ne!(
            InstallOutcome::Installed,
            InstallOutcome::RegistrationFailed,
        );
    }

    // Note: actually calling `install()` would mutate process-global
    // state and break other tests run in the same binary. The handler
    // function and OnceLock are exercised in integration tests under
    // `tests/console_ctrl_test.rs` (block 16.7), which spawn a child
    // process so the global registration is isolated.
}
