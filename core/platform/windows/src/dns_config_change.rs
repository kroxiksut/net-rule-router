//! Windows mechanism behind [`DnsConfigChangeObserver`]: a registry change
//! notification on the TCP/IP parameters.
//!
//! Everything the DNS claims are read from lives under that key — each
//! interface's `DhcpDomain`/`Domain` and servers, the global `SearchList` and
//! the primary suffix — and a DHCP lease or a VPN client writes there without
//! any interface or route event. The watch covers the subtree, so one
//! registration sees them all.
//!
//! One thread per subscription parks in `WaitForMultipleObjects` on the change
//! event and a stop event: no timer, no wakeup while nothing changes.

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::sync::mpsc;
use std::thread::JoinHandle;

use nrr_platform_api::dns_config_change::DnsConfigChangeObserver;
use nrr_platform_api::error::PlatformError;
use nrr_platform_api::network_change::{NetworkChangeCallback, NetworkChangeSubscription};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Registry::{
    RegCloseKey, RegNotifyChangeKeyValue, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_NOTIFY,
    REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME,
};
use windows::Win32::System::Threading::{CreateEventW, SetEvent, WaitForMultipleObjects, INFINITE};

/// Machine-wide and per-interface TCP/IP parameters.
const PARAMETERS_KEY: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";

/// Production observer over [`PARAMETERS_KEY`].
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsDnsConfigChangeObserver;

impl DnsConfigChangeObserver for WindowsDnsConfigChangeObserver {
    fn subscribe(
        &self,
        on_change: NetworkChangeCallback,
    ) -> Result<NetworkChangeSubscription, PlatformError> {
        let watch = KeyWatch::start(HKEY_LOCAL_MACHINE, PARAMETERS_KEY, on_change)?;
        Ok(NetworkChangeSubscription::new(Box::new(watch)))
    }
}

/// A raw handle crossing into the watch thread. The thread is its only user
/// until the guard joins it.
#[derive(Clone, Copy)]
struct SendHandle(isize);

impl SendHandle {
    fn of(handle: HANDLE) -> Self {
        Self(handle.0 as isize)
    }
    fn get(self) -> HANDLE {
        HANDLE(self.0 as *mut core::ffi::c_void)
    }
}

/// Owns the stop event and the thread; dropping it retires the thread.
struct KeyWatch {
    stop: SendHandle,
    thread: Option<JoinHandle<()>>,
}

// SAFETY: `stop` is an event handle, usable from any thread; it is closed only
// in `Drop`, after the thread that waits on it has been joined.
unsafe impl Send for KeyWatch {}
unsafe impl Sync for KeyWatch {}

impl KeyWatch {
    fn start(
        hive: HKEY,
        path: &str,
        on_change: NetworkChangeCallback,
    ) -> Result<Self, PlatformError> {
        // SAFETY: no security attributes, no name; manual reset so a stop
        // signalled before the thread waits is still seen.
        let stop = unsafe { CreateEventW(None, true, false, PCWSTR::null()) }.map_err(|e| {
            PlatformError::Transient {
                operation: "dns_config_change.create_stop_event",
                detail: e.to_string(),
            }
        })?;
        let stop = SendHandle::of(stop);
        let hive = SendHandle(hive.0 as isize);
        let path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let spawned = std::thread::Builder::new()
            .name("nrr-dns-config-watch".to_string())
            .spawn(move || {
                let hive = HKEY(hive.0 as *mut core::ffi::c_void);
                watch_until_stopped(hive, &path, stop.get(), on_change, ready_tx);
            });
        let thread = match spawned {
            Ok(thread) => thread,
            Err(e) => {
                close(stop.get());
                return Err(PlatformError::Transient {
                    operation: "dns_config_change.spawn",
                    detail: e.to_string(),
                });
            }
        };
        // The registration happens on the thread (an asynchronous registry
        // notification belongs to the thread that asked for it); wait for its
        // verdict so a failure reaches the caller instead of a silent thread.
        let verdict = ready_rx.recv().unwrap_or_else(|_| {
            Err(PlatformError::Transient {
                operation: "dns_config_change.register",
                detail: "the watch thread exited before registering".to_string(),
            })
        });
        match verdict {
            Ok(()) => Ok(Self {
                stop,
                thread: Some(thread),
            }),
            Err(e) => {
                let _ = thread.join();
                close(stop.get());
                Err(e)
            }
        }
    }
}

impl Drop for KeyWatch {
    fn drop(&mut self) {
        // SAFETY: `stop` is the live event created in `start`.
        let _ = unsafe { SetEvent(self.stop.get()) };
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        close(self.stop.get());
    }
}

fn close(handle: HANDLE) {
    // SAFETY: every caller passes a handle it owns and does not use again.
    let _ = unsafe { CloseHandle(handle) };
}

fn register_failed(operation: &'static str, code: u32) -> PlatformError {
    PlatformError::Win32 {
        operation,
        code,
        message: format!("{operation} → Win32 error {code}"),
    }
}

/// Open the key, register, report, then wait: each change calls `on_change`
/// and registers again. Returns when `stop` is signalled or re-registration
/// fails.
fn watch_until_stopped(
    hive: HKEY,
    path: &[u16],
    stop: HANDLE,
    on_change: NetworkChangeCallback,
    ready: mpsc::SyncSender<Result<(), PlatformError>>,
) {
    let mut key = HKEY::default();
    // SAFETY: `path` is NUL-terminated UTF-16 outliving the call; `key` is a
    // fresh out-param; the hive is a predefined handle.
    let rc = unsafe { RegOpenKeyExW(hive, PCWSTR(path.as_ptr()), 0, KEY_NOTIFY, &mut key) };
    if rc != ERROR_SUCCESS {
        let _ = ready.send(Err(register_failed("RegOpenKeyExW", rc.0)));
        return;
    }
    // SAFETY: no security attributes, no name; auto-reset, one signal per change.
    let changed = match unsafe { CreateEventW(None, false, false, PCWSTR::null()) } {
        Ok(event) => event,
        Err(e) => {
            // SAFETY: `key` came from the successful open above.
            let _ = unsafe { RegCloseKey(key) };
            let _ = ready.send(Err(PlatformError::Transient {
                operation: "dns_config_change.create_change_event",
                detail: e.to_string(),
            }));
            return;
        }
    };
    let register = || {
        // SAFETY: `key` and `changed` are live for the whole loop.
        unsafe {
            RegNotifyChangeKeyValue(
                key,
                true,
                REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                changed,
                true,
            )
        }
    };
    let first = register();
    if first != ERROR_SUCCESS {
        let _ = ready.send(Err(register_failed("RegNotifyChangeKeyValue", first.0)));
    } else {
        let _ = ready.send(Ok(()));
        loop {
            // SAFETY: both handles are live events owned by this subscription.
            let woke = unsafe { WaitForMultipleObjects(&[changed, stop], false, INFINITE) };
            if woke != WAIT_OBJECT_0 {
                break;
            }
            // Register before the callback, so a change the callback's reader
            // races with is not lost between the two.
            let again = register();
            // A panic must not end the watch the service relies on.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| on_change()));
            if again != ERROR_SUCCESS {
                tracing::warn!(
                    target: "nrr::dns-redirect",
                    msg_key = "dns-config-watch-stopped",
                    code = again.0,
                    "the DNS settings watch stopped; changes are noticed only by the periodic check",
                );
                break;
            }
        }
    }
    close(changed);
    // SAFETY: `key` came from the successful open above.
    let _ = unsafe { RegCloseKey(key) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use windows::Win32::System::Registry::{
        RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW, HKEY_CURRENT_USER, KEY_ALL_ACCESS,
        REG_OPEN_CREATE_OPTIONS, REG_SZ,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// A per-user scratch key, so the test needs no elevation. Dropping it
    /// removes the whole tree under its first component.
    struct ScratchKey {
        path: String,
        root: String,
        key: HKEY,
    }

    impl ScratchKey {
        fn create(relative: &str) -> Self {
            let root = format!(
                r"Software\NrrTest-{}-{}",
                std::process::id(),
                relative.split('\\').next().unwrap_or(relative)
            );
            let path = format!(r"Software\NrrTest-{}-{relative}", std::process::id());
            let mut key = HKEY::default();
            // SAFETY: NUL-terminated path; fresh out-param.
            let rc = unsafe {
                RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    PCWSTR(wide(&path).as_ptr()),
                    0,
                    PCWSTR::null(),
                    REG_OPEN_CREATE_OPTIONS(0),
                    KEY_ALL_ACCESS,
                    None,
                    &mut key,
                    None,
                )
            };
            assert_eq!(rc, ERROR_SUCCESS, "scratch key");
            Self { path, root, key }
        }

        fn set(&self, name: &str, value: &str) {
            let data: Vec<u8> = wide(value).iter().flat_map(|c| c.to_le_bytes()).collect();
            // SAFETY: live key; NUL-terminated name; `data` outlives the call.
            let rc = unsafe {
                RegSetValueExW(
                    self.key,
                    PCWSTR(wide(name).as_ptr()),
                    0,
                    REG_SZ,
                    Some(&data),
                )
            };
            assert_eq!(rc, ERROR_SUCCESS, "set value");
        }
    }

    impl Drop for ScratchKey {
        fn drop(&mut self) {
            // SAFETY: the key is ours; the tree holds nothing but test keys.
            unsafe {
                let _ = RegCloseKey(self.key);
                let _ = RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(wide(&self.root).as_ptr()));
            }
        }
    }

    fn counting() -> (Arc<AtomicUsize>, NetworkChangeCallback) {
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        (
            hits,
            Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            }),
        )
    }

    fn wait_for(hits: &AtomicUsize, at_least: usize) -> usize {
        let deadline = Instant::now() + Duration::from_secs(5);
        while hits.load(Ordering::SeqCst) < at_least && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        hits.load(Ordering::SeqCst)
    }

    /// A value written anywhere below the key reaches the callback, and the
    /// watch keeps working after the first one.
    #[test]
    fn a_value_written_below_the_key_reaches_the_callback_every_time() {
        let scratch = ScratchKey::create("dns-config-watch");
        let child = ScratchKey::create(r"dns-config-watch\Interfaces\{guid}");
        let (hits, callback) = counting();
        let watch = KeyWatch::start(HKEY_CURRENT_USER, &scratch.path, callback).expect("watch");

        child.set("DhcpDomain", "corp.example");
        assert!(wait_for(&hits, 1) >= 1, "the first change arrived");
        let seen = hits.load(Ordering::SeqCst);
        child.set("DhcpDomain", "branch.corp.example");
        assert!(wait_for(&hits, seen + 1) > seen, "the watch re-registered");

        drop(watch);
        drop(child);
        drop(scratch);
    }

    /// Dropping the subscription retires the thread at once: it waits on no
    /// timer, so a missed stop would hang here.
    #[test]
    fn a_quiet_key_never_calls_and_drops_promptly() {
        let scratch = ScratchKey::create("dns-config-quiet");
        let (hits, callback) = counting();
        let watch = KeyWatch::start(HKEY_CURRENT_USER, &scratch.path, callback).expect("watch");
        std::thread::sleep(Duration::from_millis(100));
        let started = Instant::now();
        drop(watch);
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_missing_key_is_an_error_not_a_silent_thread() {
        let (_hits, callback) = counting();
        assert!(KeyWatch::start(
            HKEY_CURRENT_USER,
            r"Software\NrrTest\does-not-exist-ever",
            callback
        )
        .is_err());
    }

    /// The production key exists and can be watched without elevation.
    #[test]
    fn the_tcpip_parameters_can_be_watched() {
        let (_hits, callback) = counting();
        let subscription = WindowsDnsConfigChangeObserver
            .subscribe(callback)
            .expect("the key is readable by any user");
        drop(subscription);
    }
}
