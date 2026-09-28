//! One real-time ETW session: start it, enable one provider, pump its events on
//! a thread, stop it. Every ETW consumer in this crate goes through here, so the
//! start/stop sequence — and the buffer rules it took two defects to learn —
//! exists once.
//!
//! The consumer supplies a C-ABI record callback and a context; the callback
//! reaches the context through `EVENT_RECORD.UserContext` via
//! [`callback_context`].

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{GetLastError, WIN32_ERROR};
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW,
    CONTROLTRACE_HANDLE, ENABLE_TRACE_PARAMETERS, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, WNODE_FLAG_TRACED_GUID,
};

use crate::error::PlatformError;

pub(crate) type RecordCallback = unsafe extern "system" fn(*mut EVENT_RECORD);

/// What the header `TimeStamp` of every delivered record means.
#[derive(Clone, Copy)]
pub(crate) enum SessionClock {
    /// Performance-counter ticks: finest resolution, not wall clock.
    PerformanceCounter,
    /// FILETIME wall clock, at the system timer's resolution.
    SystemTime,
}

impl SessionClock {
    fn client_context(self) -> u32 {
        match self {
            Self::PerformanceCounter => 1,
            Self::SystemTime => 2,
        }
    }
}

/// The session's identity and delivery settings.
pub(crate) struct SessionConfig {
    /// Kernel-registered session name; one per consumer.
    pub name: &'static str,
    pub thread_name: &'static str,
    pub clock: SessionClock,
    /// Forced flush period in seconds; 0 leaves ETW's default (deliver when a
    /// buffer fills).
    pub flush_timer_secs: u32,
}

/// The one provider a session enables.
pub(crate) struct ProviderEnable {
    pub guid: GUID,
    pub level: u8,
    pub keywords: u64,
    /// `EVENT_ENABLE_PROPERTY_*` bits (e.g. the SID extended-data item).
    pub enable_property: u32,
}

/// A running session. Stops on [`Self::stop`] or drop, whichever comes first.
pub(crate) struct RealtimeSession {
    session_name: Vec<u16>,
    control_handle: CONTROLTRACE_HANDLE,
    process_handle: PROCESSTRACE_HANDLE,
    worker: Mutex<Option<JoinHandle<()>>>,
    stopped: AtomicBool,
    context: *const c_void,
    release_context: unsafe fn(*const c_void),
}

// SAFETY: the handles are touched only by `stop`, which `stopped` makes
// run-once; `context` is an `Arc<C>` with `C: Send + Sync`.
unsafe impl Send for RealtimeSession {}
unsafe impl Sync for RealtimeSession {}

/// Reclaims the `Arc` reference handed to the callback.
///
/// # Safety
/// `ptr` must come from `Arc::<C>::into_raw` and be released exactly once.
unsafe fn release_arc<C>(ptr: *const c_void) {
    drop(Arc::from_raw(ptr as *const C));
}

/// Allocate an `EVENT_TRACE_PROPERTIES` buffer for a real-time session, with
/// room for the struct, the logger name AND a log-file-name region: the kernel
/// writes both names back on Query/Stop, so a buffer sized for struct+name is
/// overrun when a STOP finds a stale session, and the following `StartTraceW`
/// then fails with `ERROR_BAD_LENGTH`. The STOP call and `StartTraceW` must
/// therefore never share one buffer.
fn alloc_trace_props(session_name: &[u16], clock: SessionClock, flush_timer_secs: u32) -> Vec<u8> {
    const LOGFILE_PAD_CHARS: usize = 1024;
    let name_bytes = std::mem::size_of_val(session_name);
    let pad_bytes = LOGFILE_PAD_CHARS * std::mem::size_of::<u16>();
    let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + name_bytes + pad_bytes;
    let mut buf: Vec<u8> = vec![0u8; props_size];
    let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    // SAFETY: `buf` is `props_size` bytes, at least size_of::<EVENT_TRACE_PROPERTIES>().
    unsafe {
        (*props).Wnode.BufferSize = props_size as u32;
        (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*props).Wnode.ClientContext = clock.client_context();
        (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*props).FlushTimer = flush_timer_secs;
        (*props).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    }
    buf
}

fn win32_error(operation: &'static str, code: u32, session: &str, what: &str) -> PlatformError {
    PlatformError::Win32 {
        operation,
        code,
        message: format!("{session}: {what}"),
    }
}

impl RealtimeSession {
    /// Start `config.name` (replacing a stale session of that name), enable
    /// `provider`, and spawn the `ProcessTrace` pump. Nothing is left running on
    /// any error.
    pub(crate) fn start<C: Send + Sync + 'static>(
        config: &SessionConfig,
        provider: &ProviderEnable,
        callback: RecordCallback,
        context: Arc<C>,
    ) -> Result<Self, PlatformError> {
        let session_name = wide(config.name);
        let mut stop_buf = alloc_trace_props(&session_name, config.clock, 0);
        let mut props_buf = alloc_trace_props(&session_name, config.clock, config.flush_timer_secs);
        let props = props_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        let stop_session = |handle: CONTROLTRACE_HANDLE| {
            let mut buf = alloc_trace_props(&session_name, config.clock, 0);
            // SAFETY: `buf` is sized for the Stop writeback and outlives the call.
            unsafe {
                let _ = ControlTraceW(
                    handle,
                    PCWSTR(session_name.as_ptr()),
                    buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
        };

        let mut control_handle = CONTROLTRACE_HANDLE::default();
        // SAFETY: stop a stale same-named session with its own scratch buffer,
        // then start fresh with the pristine one; both outlive the calls.
        let started = unsafe {
            let _ = ControlTraceW(
                CONTROLTRACE_HANDLE::default(),
                PCWSTR(session_name.as_ptr()),
                stop_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
                EVENT_TRACE_CONTROL_STOP,
            );
            StartTraceW(&mut control_handle, PCWSTR(session_name.as_ptr()), props)
        };
        if started != WIN32_ERROR(0) {
            return Err(win32_error(
                "StartTraceW",
                started.0,
                config.name,
                "failed to start the ETW session",
            ));
        }

        let enable_params = ENABLE_TRACE_PARAMETERS {
            Version: 2, // ENABLE_TRACE_PARAMETERS_VERSION_2
            EnableProperty: provider.enable_property,
            ..Default::default()
        };
        // SAFETY: `control_handle` is the session just started; the GUID and
        // `enable_params` outlive the call.
        let enabled = unsafe {
            EnableTraceEx2(
                control_handle,
                &provider.guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                provider.level,
                provider.keywords,
                0,
                0,
                Some(&enable_params),
            )
        };
        if enabled != WIN32_ERROR(0) {
            stop_session(control_handle);
            return Err(win32_error(
                "EnableTraceEx2",
                enabled.0,
                config.name,
                "failed to enable the ETW provider",
            ));
        }

        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: PWSTR(session_name.as_ptr() as *mut u16),
            ..Default::default()
        };
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(callback);
        // One reference travels with the callback; `stop` takes it back once
        // the pump has returned and no callback can run.
        let ctx = Arc::into_raw(context) as *const c_void;
        logfile.Context = ctx as *mut c_void;

        // SAFETY: `logfile` is fully initialised and the callback is a static fn.
        let process_handle = unsafe { OpenTraceW(&mut logfile) };
        // INVALID_PROCESSTRACE_HANDLE is all-ones.
        if process_handle.Value == u64::MAX {
            // SAFETY: reading the calling thread's last error.
            let err = unsafe { GetLastError() };
            // SAFETY: no trace was opened, so no callback holds `ctx`.
            unsafe { release_arc::<C>(ctx) };
            stop_session(control_handle);
            return Err(win32_error(
                "OpenTraceW",
                err.0,
                config.name,
                "failed to open the ETW trace",
            ));
        }

        let handle = process_handle;
        let spawned = std::thread::Builder::new()
            .name(config.thread_name.into())
            .spawn(move || {
                // SAFETY: `handle` stays a valid real-time trace handle until
                // `stop` closes it, which is what makes `ProcessTrace` return.
                let _ = unsafe { ProcessTrace(&[handle], None, None) };
            });
        let worker = match spawned {
            Ok(worker) => worker,
            Err(e) => {
                // SAFETY: close the trace nobody pumps; no callback ran or can.
                unsafe {
                    let _ = CloseTrace(process_handle);
                    release_arc::<C>(ctx);
                }
                stop_session(control_handle);
                return Err(PlatformError::Win32 {
                    operation: "spawn(etw pump)",
                    code: 0,
                    message: format!("{}: {e}", config.name),
                });
            }
        };

        Ok(Self {
            session_name,
            control_handle,
            process_handle,
            worker: Mutex::new(Some(worker)),
            stopped: AtomicBool::new(false),
            context: ctx,
            release_context: release_arc::<C>,
        })
    }

    /// Stop the session and join the pump, without waiting for `Drop`.
    ///
    /// A session is a KERNEL object registered by name: a process that exits
    /// without stopping it leaves it running, and the next start finds the
    /// name taken. `Drop` cannot be relied on for that when consumer threads
    /// hold their own `Arc` to the owner.
    pub(crate) fn stop(&self) {
        if self.stopped.swap(true, Ordering::AcqRel) {
            return;
        }
        let mut props_buf = alloc_trace_props(&self.session_name, SessionClock::SystemTime, 0);
        // SAFETY: stopping the session and closing the trace make ProcessTrace
        // return; `props_buf` is sized for the Stop writeback.
        unsafe {
            let _ = ControlTraceW(
                self.control_handle,
                PCWSTR(self.session_name.as_ptr()),
                props_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
                EVENT_TRACE_CONTROL_STOP,
            );
            let _ = CloseTrace(self.process_handle);
        }
        let worker = self.worker.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(worker) = worker {
            let _ = worker.join();
        }
        // SAFETY: the pump has returned (or died), so no callback holds the
        // context any more; `stopped` makes this the only release.
        unsafe { (self.release_context)(self.context) };
    }
}

impl Drop for RealtimeSession {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The context a session was started with, borrowed inside its callback.
///
/// # Safety
/// `record` must be delivered to a session started with a context of type `C`.
pub(crate) unsafe fn callback_context<C>(record: &EVENT_RECORD) -> Option<&C> {
    let ctx = record.UserContext as *const C;
    if ctx.is_null() {
        None
    } else {
        Some(&*ctx)
    }
}

/// The record's payload.
///
/// # Safety
/// `record` must be a record ETW delivered to a callback, still in scope.
pub(crate) unsafe fn user_data(record: &EVENT_RECORD) -> Option<&[u8]> {
    let data = record.UserData as *const u8;
    if data.is_null() {
        return None;
    }
    Some(std::slice::from_raw_parts(
        data,
        record.UserDataLength as usize,
    ))
}

/// NUL-terminated UTF-16 from a `&str`.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
