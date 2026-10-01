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
    CONTROLTRACE_HANDLE, ENABLE_TRACE_PARAMETERS, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    EVENT_FILTER_DESCRIPTOR, EVENT_FILTER_TYPE_EVENT_ID, EVENT_RECORD, EVENT_TRACE_CONTROL,
    EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW,
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, MAX_EVENT_FILTER_EVENT_ID_COUNT,
    PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
    WNODE_FLAG_TRACED_GUID,
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
    /// `None` leaves the buffer size and count to ETW.
    pub buffers: Option<BufferSizing>,
}

/// The session's buffer pool. Buffers are nonpaged kernel memory; ETW drops
/// events once every buffer is full and still awaiting delivery.
#[derive(Clone, Copy)]
pub(crate) struct BufferSizing {
    pub buffer_kb: u32,
    pub min_buffers: u32,
    pub max_buffers: u32,
}

/// The one provider a session enables.
pub(crate) struct ProviderEnable {
    pub guid: GUID,
    pub level: u8,
    pub keywords: u64,
    /// `EVENT_ENABLE_PROPERTY_*` bits (e.g. the SID extended-data item).
    pub enable_property: u32,
    /// Only these event ids are written to the session; empty lets through
    /// every event the keywords select.
    pub event_ids: &'static [u16],
}

/// Cumulative counts of what the session failed to deliver.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SessionLosses {
    /// Events dropped because no buffer was free.
    pub events: u32,
    /// Filled buffers the real-time consumer never received.
    pub realtime_buffers: u32,
}

/// At most one lost-events line per session per this period, carrying every
/// loss since the previous one.
const LOSS_REPORT_EVERY_MS: u64 = 60_000;

/// Losses reported in one line.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct LostSinceReport {
    pub events: u64,
    pub realtime_buffers: u64,
}

/// Turns the session's cumulative loss counters into at most one report per
/// [`LOSS_REPORT_EVERY_MS`], carrying everything lost since the previous one.
#[derive(Default)]
struct LossLedger {
    seen: SessionLosses,
    unreported: LostSinceReport,
    reported_unix_ms: Option<u64>,
}

impl LossLedger {
    fn observe(&mut self, totals: SessionLosses, now: u64) -> Option<LostSinceReport> {
        // The kernel counters are u32 and may wrap on a long session.
        self.unreported.events += u64::from(totals.events.wrapping_sub(self.seen.events));
        self.unreported.realtime_buffers += u64::from(
            totals
                .realtime_buffers
                .wrapping_sub(self.seen.realtime_buffers),
        );
        self.seen = totals;
        if self.unreported == LostSinceReport::default() {
            return None;
        }
        if self
            .reported_unix_ms
            .is_some_and(|at| now.saturating_sub(at) < LOSS_REPORT_EVERY_MS)
        {
            return None;
        }
        self.reported_unix_ms = Some(now);
        Some(std::mem::take(&mut self.unreported))
    }
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
    losses: Mutex<LossLedger>,
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
/// therefore never share one buffer. `u64` words keep the struct aligned.
fn alloc_trace_props(
    session_name: &[u16],
    clock: SessionClock,
    flush_timer_secs: u32,
    buffers: Option<BufferSizing>,
) -> Vec<u64> {
    const LOGFILE_PAD_CHARS: usize = 1024;
    let name_bytes = std::mem::size_of_val(session_name);
    let pad_bytes = LOGFILE_PAD_CHARS * std::mem::size_of::<u16>();
    let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + name_bytes + pad_bytes;
    let mut buf: Vec<u64> = vec![0u64; props_size.div_ceil(8)];
    let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    // SAFETY: `buf` is 8-aligned and at least size_of::<EVENT_TRACE_PROPERTIES>() bytes.
    unsafe {
        (*props).Wnode.BufferSize = (buf.len() * 8) as u32;
        (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*props).Wnode.ClientContext = clock.client_context();
        (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*props).FlushTimer = flush_timer_secs;
        (*props).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        if let Some(sizing) = buffers {
            (*props).BufferSize = sizing.buffer_kb;
            (*props).MinimumBuffers = sizing.min_buffers;
            (*props).MaximumBuffers = sizing.max_buffers;
        }
    }
    buf
}

/// `EVENT_FILTER_EVENT_ID` in `u16` units, the struct's own alignment:
/// `FilterIn` = TRUE and `Reserved` share the first unit, then `Count`, then
/// the ids. `None` for no ids, or more than ETW accepts in one filter.
fn event_id_filter(ids: &[u16]) -> Option<Vec<u16>> {
    if ids.is_empty() || ids.len() > MAX_EVENT_FILTER_EVENT_ID_COUNT as usize {
        return None;
    }
    let mut filter = Vec::with_capacity(2 + ids.len());
    filter.push(u16::from_le_bytes([1, 0]));
    filter.push(ids.len() as u16);
    filter.extend_from_slice(ids);
    Some(filter)
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
        let mut stop_buf = alloc_trace_props(&session_name, config.clock, 0, None);
        let mut props_buf = alloc_trace_props(
            &session_name,
            config.clock,
            config.flush_timer_secs,
            config.buffers,
        );
        let props = props_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        let stop_session = |handle: CONTROLTRACE_HANDLE| {
            let mut buf = alloc_trace_props(&session_name, config.clock, 0, None);
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

        let filter = event_id_filter(provider.event_ids);
        if filter.is_none() && !provider.event_ids.is_empty() {
            tracing::warn!(
                target: "nrr::etw",
                session = config.name,
                ids = provider.event_ids.len(),
                "too many event ids for one ETW filter; the session takes every event",
            );
        }
        let enable = |filter: Option<&[u16]>| {
            let mut descriptor = filter.map(|f| EVENT_FILTER_DESCRIPTOR {
                Ptr: f.as_ptr() as u64,
                Size: std::mem::size_of_val(f) as u32,
                Type: EVENT_FILTER_TYPE_EVENT_ID,
            });
            let enable_params = ENABLE_TRACE_PARAMETERS {
                Version: 2, // ENABLE_TRACE_PARAMETERS_VERSION_2
                EnableProperty: provider.enable_property,
                EnableFilterDesc: descriptor
                    .as_mut()
                    .map_or(std::ptr::null_mut(), std::ptr::from_mut),
                FilterDescCount: u32::from(descriptor.is_some()),
                ..Default::default()
            };
            // SAFETY: `control_handle` is the session just started; the GUID,
            // `enable_params`, the descriptor and the filter it points to all
            // outlive the call.
            unsafe {
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
            }
        };
        let mut enabled = enable(filter.as_deref());
        if enabled != WIN32_ERROR(0) && filter.is_some() {
            // The filter only spares the consumer work: a provider that refuses
            // it still delivers everything the callback needs.
            tracing::warn!(
                target: "nrr::etw",
                session = config.name,
                code = enabled.0,
                "the ETW provider refused the event-id filter; enabled without it",
            );
            enabled = enable(None);
        }
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
            losses: Mutex::new(LossLedger::default()),
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
        // SAFETY: stopping the session and closing the trace make ProcessTrace
        // return.
        unsafe {
            let _ = self.control(EVENT_TRACE_CONTROL_STOP);
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

    /// What the session lost since the last report, when a report is due:
    /// the caller logs it, and the ledger keeps that to one line per period.
    pub(crate) fn losses_to_report(&self) -> Option<LostSinceReport> {
        let totals = self.losses()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_millis() as u64;
        self.losses
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .observe(totals, now)
    }

    /// What the session has lost since it started; `None` once stopped or
    /// when the kernel does not answer.
    fn losses(&self) -> Option<SessionLosses> {
        if self.stopped.load(Ordering::Acquire) {
            return None;
        }
        // SAFETY: a query only reads the session's counters.
        let props = unsafe { self.control(EVENT_TRACE_CONTROL_QUERY) }?;
        Some(SessionLosses {
            events: props.EventsLost,
            realtime_buffers: props.RealTimeBuffersLost,
        })
    }

    /// Send `code` to this session; the properties it writes back on success.
    ///
    /// # Safety
    /// `code` must be a control that is sound on this session's handle.
    unsafe fn control(&self, code: EVENT_TRACE_CONTROL) -> Option<EVENT_TRACE_PROPERTIES> {
        // Sized for the name writeback; outlives the call.
        let mut buf = alloc_trace_props(&self.session_name, SessionClock::SystemTime, 0, None);
        let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        let rc = ControlTraceW(
            self.control_handle,
            PCWSTR(self.session_name.as_ptr()),
            props,
            code,
        );
        (rc == WIN32_ERROR(0)).then(|| *props)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn totals(events: u32, realtime_buffers: u32) -> SessionLosses {
        SessionLosses {
            events,
            realtime_buffers,
        }
    }

    fn lost(events: u64, realtime_buffers: u64) -> Option<LostSinceReport> {
        Some(LostSinceReport {
            events,
            realtime_buffers,
        })
    }

    #[test]
    fn losses_are_reported_at_once_then_at_most_once_a_period_with_nothing_dropped() {
        let mut ledger = LossLedger::default();
        assert_eq!(ledger.observe(totals(0, 0), 1_000), None, "nothing lost");
        assert_eq!(ledger.observe(totals(5, 1), 2_000), lost(5, 1));
        // Within the period: accumulated, not reported.
        assert_eq!(ledger.observe(totals(8, 1), 3_000), None);
        assert_eq!(ledger.observe(totals(10, 2), 4_000), None);
        let next = 2_000 + LOSS_REPORT_EVERY_MS;
        assert_eq!(ledger.observe(totals(10, 2), next), lost(5, 1));
        assert_eq!(
            ledger.observe(totals(10, 2), next + LOSS_REPORT_EVERY_MS),
            None
        );
    }

    #[test]
    fn a_wrapped_kernel_counter_still_counts_the_difference() {
        let mut ledger = LossLedger::default();
        let _ = ledger.observe(totals(u32::MAX - 1, 0), 1_000);
        let later = 1_000 + LOSS_REPORT_EVERY_MS;
        assert_eq!(ledger.observe(totals(2, 0), later), lost(4, 0));
    }

    #[test]
    fn the_event_id_filter_has_the_layout_etw_reads() {
        let filter = event_id_filter(&[12, 28, 13]).expect("filter");
        let bytes: Vec<u8> = filter.iter().flat_map(|u| u.to_le_bytes()).collect();
        // FilterIn, Reserved, Count, then the ids.
        assert_eq!(bytes, [1, 0, 3, 0, 12, 0, 28, 0, 13, 0]);
    }

    #[test]
    fn no_ids_or_too_many_means_no_filter() {
        assert_eq!(event_id_filter(&[]), None);
        let max = MAX_EVENT_FILTER_EVENT_ID_COUNT as usize;
        assert!(event_id_filter(&vec![1; max]).is_some());
        assert_eq!(event_id_filter(&vec![1; max + 1]), None);
    }

    #[test]
    fn trace_properties_are_aligned_and_carry_the_sizing() {
        let name = wide("NrrTest");
        let sizing = BufferSizing {
            buffer_kb: 32,
            min_buffers: 4,
            max_buffers: 64,
        };
        let buf = alloc_trace_props(&name, SessionClock::SystemTime, 1, Some(sizing));
        let ptr = buf.as_ptr() as *const EVENT_TRACE_PROPERTIES;
        assert!(ptr.is_aligned());
        // SAFETY: aligned and at least one struct long.
        let props = unsafe { *ptr };
        assert_eq!(props.Wnode.BufferSize as usize, buf.len() * 8);
        assert_eq!(
            (props.BufferSize, props.MinimumBuffers, props.MaximumBuffers),
            (32, 4, 64)
        );
        assert_eq!(props.FlushTimer, 1);

        let buf = alloc_trace_props(&name, SessionClock::SystemTime, 0, None);
        // SAFETY: as above.
        let props = unsafe { *(buf.as_ptr() as *const EVENT_TRACE_PROPERTIES) };
        assert_eq!(
            (props.BufferSize, props.MinimumBuffers, props.MaximumBuffers),
            (0, 0, 0),
            "left to ETW"
        );
    }
}
