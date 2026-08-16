//! Windows mechanism behind the single-instance port: a named kernel mutex.
//!
//! `Local\` scopes the name to the logon session, so two users each get their
//! own surfaces. The mutex is never *acquired* — only created: its existence is
//! the claim, and the object disappears once the last handle closes, which the
//! kernel does even for a process that was killed. There is no stale state to
//! reclaim and no PID to probe.

#![cfg(target_os = "windows")]

use nrr_platform_api::error::PlatformError;
use nrr_platform_api::single_instance::{SingleInstanceClaim, SingleInstancePort};

/// Names the claim `Local\NetRuleRouter.<key>`.
#[derive(Debug, Default)]
pub struct WindowsSingleInstance;

impl SingleInstancePort for WindowsSingleInstance {
    fn claim(&self, key: &str) -> Result<Option<Box<dyn SingleInstanceClaim>>, PlatformError> {
        create_named_mutex(&format!("Local\\NetRuleRouter.{key}"))
    }
}

/// The raw handle, kept as a `usize` so the claim is `Send` without an unsafe
/// impl: nothing reads it except `CloseHandle` on drop.
struct MutexClaim(usize);

impl SingleInstanceClaim for MutexClaim {}

impl Drop for MutexClaim {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        // SAFETY: the handle came from a successful `CreateMutexW` and is
        // closed exactly once, here.
        unsafe {
            let _ = CloseHandle(HANDLE(self.0 as *mut std::ffi::c_void));
        }
    }
}

#[allow(unsafe_code)]
fn create_named_mutex(name: &str) -> Result<Option<Box<dyn SingleInstanceClaim>>, PlatformError> {
    use windows::core::HSTRING;
    use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
    use windows::Win32::System::Threading::CreateMutexW;

    let wide = HSTRING::from(name);
    // SAFETY: `wide` outlives the call; `None` for the security attributes
    // takes the default descriptor, and `false` means "create, do not acquire".
    let handle = unsafe { CreateMutexW(None, false, &wide) }.map_err(|e| PlatformError::Win32 {
        operation: "CreateMutexW",
        code: e.code().0 as u32,
        message: e.message(),
    })?;
    // SAFETY: read immediately after the call that set it, on the same thread.
    let already_exists = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    let claim = MutexClaim(handle.0 as usize);
    if already_exists {
        // Dropping closes our handle; the owner's keeps the object alive.
        return Ok(None);
    }
    Ok(Some(Box::new(claim)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_claim_of_the_same_key_is_refused_while_the_first_is_held() {
        let port = WindowsSingleInstance;
        let key = format!("test-{}-{}", std::process::id(), line!());
        let first = port.claim(&key).expect("claim succeeds");
        assert!(first.is_some(), "an unclaimed key must be claimable");
        let second = port.claim(&key).expect("claim succeeds");
        assert!(second.is_none(), "a held key must refuse a second claim");
        drop(first);
        let third = port.claim(&key).expect("claim succeeds");
        assert!(third.is_some(), "releasing the claim must free the key");
    }

    #[test]
    fn distinct_keys_do_not_collide() {
        let port = WindowsSingleInstance;
        let pid = std::process::id();
        let gui = port.claim(&format!("gui-{pid}")).expect("claim succeeds");
        let tray = port.claim(&format!("tray-{pid}")).expect("claim succeeds");
        assert!(gui.is_some() && tray.is_some());
    }
}
