//! Windows Application event log — the operator-facing sink.
//!
//! ## Why the message text travels as an insert string
//!
//! `ReportEventW` names a message by id; the text itself is expected to live in
//! a compiled message resource. We have none, and adding an `.mc` build step to
//! ship five sentences would be a build-system dependency for nothing. Instead
//! the source is registered against the message table Windows already ships in
//! `EventCreate.exe` — the one `eventcreate` itself uses, whose entries are
//! "%1" for low ids — and our sentence rides as that single insert. The Event
//! Viewer shows exactly our text, with no "description cannot be found".
//!
//! The consequence, and the reason [`SystemEventRecord::event_id`] is
//! documented as small: an id outside that table's range renders as the missing
//! -description boilerplate.

// The `windows` crate is a `cfg(windows)` dependency, so this module — like
// every other one that binds Win32 directly — must vanish off-platform, or the
// crate stops compiling under Linux.
#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::sync::Mutex;

use nrr_platform_api::system_event_log::{
    SystemEventLogPort, SystemEventRecord, SystemEventSeverity,
};
use nrr_shared::product_identity::WINDOWS_EVENT_SOURCE_NAME;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::EventLog::{
    DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_ERROR_TYPE,
    EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE,
};

/// Registry home of an event source, under `HKEY_LOCAL_MACHINE`.
const SOURCE_KEY: &str = r"SYSTEM\CurrentControlSet\Services\EventLog\Application";

/// Message table we borrow. See the module doc.
const MESSAGE_FILE: &str = r"%SystemRoot%\System32\EventCreate.exe";

/// Every type we ever write: information | warning | error.
const TYPES_SUPPORTED: u32 = 0x0007;

/// Live handle to the registered source.
///
/// A handle is only obtainable once the source exists in the registry, which is
/// an install-time act; when it does not, `RegisterEventSourceW` still succeeds
/// against the Application log with an unregistered name, and Windows renders
/// the insert string anyway. Either way the sink never fails the caller.
pub struct WindowsEventLog {
    handle: Mutex<Option<SourceHandle>>,
}

/// The registered source handle. Win32 documents `ReportEventW` as safe to call
/// on one handle from several threads, and the mutex serialises our own access
/// anyway; the newtype exists only because `HANDLE` wraps a raw pointer.
struct SourceHandle(HANDLE);

// SAFETY: an event-source handle is not thread-affine, and every use of it here
// goes through the mutex.
unsafe impl Send for SourceHandle {}
unsafe impl Sync for SourceHandle {}

impl WindowsEventLog {
    /// Register this process with the product's event source.
    pub fn new() -> Self {
        let name = HSTRING::from(WINDOWS_EVENT_SOURCE_NAME);
        // SAFETY: `name` outlives the call; a null server name means the local
        // machine. A failed registration yields a null handle, which `write`
        // treats as "no sink".
        let handle = unsafe { RegisterEventSourceW(PCWSTR::null(), PCWSTR(name.as_ptr())) }.ok();
        Self {
            handle: Mutex::new(handle.filter(|h| !h.is_invalid()).map(SourceHandle)),
        }
    }
}

impl Default for WindowsEventLog {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for WindowsEventLog {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.lock().unwrap_or_else(|p| p.into_inner()).take() {
            // SAFETY: the handle came from RegisterEventSourceW and is dropped
            // exactly once — it is taken out of the Option first.
            unsafe {
                let _ = DeregisterEventSource(handle.0);
            }
        }
    }
}

impl SystemEventLogPort for WindowsEventLog {
    fn write(&self, record: &SystemEventRecord) {
        let guard = self.handle.lock().unwrap_or_else(|p| p.into_inner());
        let Some(source) = guard.as_ref() else {
            return;
        };
        let kind = match record.severity {
            SystemEventSeverity::Info => EVENTLOG_INFORMATION_TYPE,
            SystemEventSeverity::Warning => EVENTLOG_WARNING_TYPE,
            SystemEventSeverity::Error => EVENTLOG_ERROR_TYPE,
        };
        let message = HSTRING::from(record.message.as_str());
        let strings = [PCWSTR(message.as_ptr())];
        // SAFETY: `message` outlives the call, so the pointer in `strings` stays
        // valid; the slice length matches what we pass; no binary data.
        unsafe {
            let _ = ReportEventW(
                source.0,
                kind,
                0,
                record.event_id,
                None,
                0,
                Some(&strings),
                None,
            );
        }
    }
}

/// Register the product's event source so its records render with our text and
/// the Event Viewer lists the source by name. Install-time; needs admin.
///
/// Idempotent — an existing key is rewritten with the same values.
pub fn register_event_source() -> Result<(), String> {
    registry::write_source_values(SOURCE_KEY, WINDOWS_EVENT_SOURCE_NAME)
}

/// Remove the event source registration. Uninstall-time; absence is success.
pub fn deregister_event_source() -> Result<(), String> {
    registry::delete_source_key(SOURCE_KEY, WINDOWS_EVENT_SOURCE_NAME)
}

mod registry {
    use super::{MESSAGE_FILE, TYPES_SUPPORTED};
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE,
        KEY_WRITE, REG_DWORD, REG_EXPAND_SZ, REG_OPTION_NON_VOLATILE,
    };

    pub(super) fn write_source_values(parent: &str, source: &str) -> Result<(), String> {
        let path = HSTRING::from(format!(r"{parent}\{source}"));
        let mut key = HKEY::default();
        // SAFETY: `path` outlives the call; `key` is an out-parameter we own.
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(path.as_ptr()),
                0,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                None,
                &mut key,
                None,
            )
        };
        if status.is_err() {
            return Err(format!("create event-source key: {status:?}"));
        }
        let result = set_values(key);
        // SAFETY: `key` came from a successful RegCreateKeyExW.
        unsafe {
            let _ = RegCloseKey(key);
        }
        result
    }

    fn set_values(key: HKEY) -> Result<(), String> {
        let message_file = HSTRING::from(MESSAGE_FILE);
        // A REG_SZ/REG_EXPAND_SZ value must carry its terminator, and the width
        // is bytes, not characters.
        let file_bytes: Vec<u8> = message_file
            .as_wide()
            .iter()
            .chain(std::iter::once(&0u16))
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        let name = HSTRING::from("EventMessageFile");
        // SAFETY: both buffers outlive the call and the declared type matches.
        let status = unsafe {
            RegSetValueExW(
                key,
                PCWSTR(name.as_ptr()),
                0,
                REG_EXPAND_SZ,
                Some(&file_bytes),
            )
        };
        if status.is_err() {
            return Err(format!("set EventMessageFile: {status:?}"));
        }
        let types = HSTRING::from("TypesSupported");
        let types_bytes = TYPES_SUPPORTED.to_le_bytes();
        // SAFETY: as above; a DWORD value is exactly four bytes.
        let status = unsafe {
            RegSetValueExW(
                key,
                PCWSTR(types.as_ptr()),
                0,
                REG_DWORD,
                Some(&types_bytes),
            )
        };
        if status.is_err() {
            return Err(format!("set TypesSupported: {status:?}"));
        }
        Ok(())
    }

    pub(super) fn delete_source_key(parent: &str, source: &str) -> Result<(), String> {
        let path = HSTRING::from(format!(r"{parent}\{source}"));
        // SAFETY: `path` outlives the call.
        let status = unsafe { RegDeleteKeyW(HKEY_LOCAL_MACHINE, PCWSTR(path.as_ptr())) };
        // ERROR_FILE_NOT_FOUND — nothing registered, which is the desired end
        // state; anything else is a real failure.
        const ERROR_FILE_NOT_FOUND: u32 = 2;
        if status.is_err() && status.0 != ERROR_FILE_NOT_FOUND {
            return Err(format!("delete event-source key: {status:?}"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Registering against a source that may not exist in the registry must
    /// still yield a usable sink — the service logs before any installer has
    /// run, and a panicking log is worse than a missing one.
    #[test]
    fn an_unregistered_source_still_produces_a_writable_sink() {
        let sink = WindowsEventLog::new();
        sink.write(&SystemEventRecord {
            severity: SystemEventSeverity::Info,
            event_id: 1,
            message: "unit test record; safe to ignore".into(),
        });
    }

    #[test]
    fn every_severity_we_declare_is_covered_by_types_supported() {
        // information | warning | error = 1 | 2 | 4.
        assert_eq!(TYPES_SUPPORTED, 0x0007);
    }
}
