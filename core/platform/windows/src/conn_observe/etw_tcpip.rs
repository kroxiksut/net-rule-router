//! Connection observation via the `Microsoft-Windows-Kernel-Network` ETW
//! provider — the guaranteed-capture fallback backend.
//!
//! Where [`super::wfp_events`] depends on WFP emitting `CLASSIFY_ALLOW` net
//! events (which need a permit filter to fire), the kernel TCP/IP provider
//! emits a **connect** event for *every* outbound TCP connection from *every*
//! process unconditionally — no filter, no engine option. So this backend is
//! the safety net when the WFP backend can't see permitted flows on a given
//! host. The session itself is [`crate::etw_session`]; only the provider, the
//! event ids and the payload parse live here.
//!
//! The event yields PID + 5-tuple (no SID, no allow/block verdict — those are
//! WFP's). The image path of a connect's process is resolved off the ETW
//! thread by [`PathResolver`], as soon as the connect is delivered, so a
//! process that exits before the drain still names its connects; the drain
//! looks up only what the resolver missed. The local (source) address in the
//! connect event is the egress interface's address, which is exactly what
//! [`super::egress`] needs.
//!
//! ## Verification status
//!
//! Like the DNS observer, the live ETW path is not unit-testable without a
//! Windows session emitting traffic; the payload parse, the resolver and the
//! pid naming ARE unit-tested. NOT yet hardware-verified.

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread::{JoinHandle, Thread};

use windows::core::GUID;
use windows::Win32::Foundation::{CloseHandle, FALSE, FILETIME};
use windows::Win32::System::Diagnostics::Etw::{EVENT_RECORD, TRACE_LEVEL_INFORMATION};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::{
    ConnectionObservation, ConnectionObservationSource, ConnectionProgress, ConnectionVerdict,
    TransportProtocol,
};
use crate::error::PlatformError;
use crate::etw_session::{
    callback_context, user_data, BufferSizing, ProviderEnable, RealtimeSession, SessionClock,
    SessionConfig,
};

/// `Microsoft-Windows-Kernel-Network` provider GUID.
const KERNEL_NETWORK_PROVIDER: GUID = GUID::from_u128(0x7dd42a49_5329_4832_8dfd_43d979153a88);

/// Keywords: collect IPv4 + IPv6 TCP/IP events
/// (`KERNEL_NETWORK_KEYWORD_IPV4` | `_IPV6`). They also select the per-segment
/// `datasent`/`datarecv` events, which [`SUBSCRIBED_EVENT_IDS`] keeps out of
/// the session.
const KEYWORD_IPV4: u64 = 0x10;
const KEYWORD_IPV6: u64 = 0x20;

/// Event ids for "TCP connection attempted" (outbound connect SYN). The IPv4 id
/// (12) is stable; the IPv6 id (28) is per the Kernel-Network manifest but NOT
/// hardware-verified. The payload parse length-guards, so a wrong id simply
/// yields no IPv6 connects — never garbage — and never affects IPv4.
const EVENT_ID_TCP_CONNECT_V4: u16 = 12;
const EVENT_ID_TCP_CONNECT_V6: u16 = 28;

/// Event ids for "connection torn down in order" and "segment sent again".
/// Both share the connect payload layout (the `TcpIp_TypeGroup1` shape), so the
/// same parsers read them. They answer "does this peer work over this link?" —
/// a resend means it was not acknowledging, an orderly close means it carried
/// traffic. Per-connection rather than per-segment, so they cost about what
/// connects do. Same caveat as the IPv6 connect id — manifest-derived, not
/// hardware-verified; a wrong id yields no events rather than garbage.
const EVENT_ID_TCP_DISCONNECT_V4: u16 = 13;
const EVENT_ID_TCP_DISCONNECT_V6: u16 = 29;
const EVENT_ID_TCP_RETRANSMIT_V4: u16 = 14;
const EVENT_ID_TCP_RETRANSMIT_V6: u16 = 30;

/// Every event the observer consumes, as `(id, is_v6, progress)`. Both the
/// session's event-id filter and [`classify_event`] read this one table.
const SUBSCRIBED_EVENTS: [(u16, bool, ConnectionProgress); 6] = [
    (EVENT_ID_TCP_CONNECT_V4, false, ConnectionProgress::Attempt),
    (EVENT_ID_TCP_CONNECT_V6, true, ConnectionProgress::Attempt),
    (
        EVENT_ID_TCP_DISCONNECT_V4,
        false,
        ConnectionProgress::ClosedInOrder,
    ),
    (
        EVENT_ID_TCP_DISCONNECT_V6,
        true,
        ConnectionProgress::ClosedInOrder,
    ),
    (
        EVENT_ID_TCP_RETRANSMIT_V4,
        false,
        ConnectionProgress::Retransmit,
    ),
    (
        EVENT_ID_TCP_RETRANSMIT_V6,
        true,
        ConnectionProgress::Retransmit,
    ),
];

/// The only ids the kernel writes into the session: without the filter every
/// sent or received segment would fill buffers the connects then miss.
const SUBSCRIBED_EVENT_IDS: [u16; SUBSCRIBED_EVENTS.len()] = {
    let mut ids = [0; SUBSCRIBED_EVENTS.len()];
    let mut i = 0;
    while i < ids.len() {
        ids[i] = SUBSCRIBED_EVENTS[i].0;
        i += 1;
    }
    ids
};

/// About 200 events per 32 KiB buffer. Idle, four buffers (ETW raises that to
/// two per CPU); at most 2 MiB of nonpaged memory absorbs roughly 12k events —
/// seconds of a connect storm — before ETW drops any.
const SESSION_BUFFERS: BufferSizing = BufferSizing {
    buffer_kb: 32,
    min_buffers: 4,
    max_buffers: 64,
};

/// With segments filtered out a buffer fills slowly; without a flush a quiet
/// machine's connects would wait in it past the drain.
const SESSION_FLUSH_SECS: u32 = 1;

/// Hard cap on buffered observations between drains.
const BUFFER_CAP: usize = 8192;

/// Connects awaiting the resolver. It pops them as they come, so the cap only
/// matters when it falls behind a storm; past it lookups are dropped, not
/// queued.
const LOOKUP_QUEUE_CAP: usize = 1024;

/// Resolved processes kept for the drain: a bound on memory under pid churn,
/// and an age past which no buffered connect can still need one.
const KNOWN_CAP: usize = 1024;
const KNOWN_RETAIN_MS: u64 = 60_000;
const KNOWN_PRUNE_EVERY_MS: u64 = 1_000;

/// What the ETW callback reaches.
struct CallbackContext {
    buffer: Mutex<Vec<ConnectionObservation>>,
    lookups: Arc<ResolverShared>,
}

/// A running real-time ETW consumer for kernel TCP/IP connect events.
pub struct EtwKernelNetworkObserver {
    context: Arc<CallbackContext>,
    // Declared before `resolver`: the pump stops feeding it first.
    session: RealtimeSession,
    resolver: PathResolver,
}

impl ConnectionObservationSource for EtwKernelNetworkObserver {
    fn drain(&self) -> Vec<ConnectionObservation> {
        let mut batch = match self.context.buffer.lock() {
            // Sized like the last interval, so the callback rarely reallocates.
            Ok(mut g) => {
                let capacity = g.len();
                std::mem::replace(&mut *g, Vec::with_capacity(capacity))
            }
            Err(_) => return Vec::new(),
        };
        self.report_losses();
        let dropped = self.resolver.shared.take_dropped();
        if dropped > 0 {
            tracing::debug!(
                target: "nrr::conn-observe",
                dropped,
                "process-path lookups dropped: the resolver queue was full",
            );
        }
        attach_process_paths(
            &mut batch,
            &lock(&self.resolver.shared.known),
            &mut SystemProcesses,
        );
        batch
    }
}

impl EtwKernelNetworkObserver {
    /// Start a real-time ETW session, enable the Kernel-Network provider for
    /// IPv4 + IPv6, and spawn the pump and the path resolver. Returns an error
    /// (and leaves nothing running) on any setup failure — the caller degrades
    /// to no observation.
    pub fn start() -> Result<Self, PlatformError> {
        let resolver = PathResolver::spawn(SystemProcesses)?;
        let context = Arc::new(CallbackContext {
            buffer: Mutex::new(Vec::new()),
            lookups: Arc::clone(&resolver.shared),
        });
        let session = RealtimeSession::start(
            &SessionConfig {
                name: "NrrConnObserve",
                thread_name: "nrr-conn-etw",
                clock: SessionClock::PerformanceCounter,
                flush_timer_secs: SESSION_FLUSH_SECS,
                buffers: Some(SESSION_BUFFERS),
            },
            &ProviderEnable {
                guid: KERNEL_NETWORK_PROVIDER,
                level: TRACE_LEVEL_INFORMATION as u8,
                keywords: KEYWORD_IPV4 | KEYWORD_IPV6,
                enable_property: 0,
                event_ids: &SUBSCRIBED_EVENT_IDS,
            },
            event_record_callback,
            Arc::clone(&context),
        )?;
        tracing::info!(
            target: "nrr::conn-observe",
            msg_key = "win-etw-conn-observer-started",
            "Kernel-Network ETW connection observer started",
        );
        Ok(Self {
            context,
            session,
            resolver,
        })
    }

    /// Stall detection rests on connects and resends; a session that lost
    /// some says so, rate-limited.
    fn report_losses(&self) {
        let Some(lost) = self.session.losses_to_report() else {
            return;
        };
        tracing::warn!(
            target: "nrr::conn-observe",
            msg_key = "win-etw-conn-events-lost",
            events = lost.events,
            buffers = lost.realtime_buffers,
            "Kernel-Network ETW session lost events; some connections went unobserved",
        );
    }

    /// Stop the trace session and join the pump and the resolver, without
    /// waiting for `Drop`: the consumer threads hold their own `Arc` to this
    /// source, and one still referenced at exit is never dropped (see
    /// [`RealtimeSession::stop`]).
    pub fn shutdown(&self) {
        self.session.stop();
        self.resolver.stop();
    }
}

/// Which of the subscribed events this record is: `(is_v6, progress)`, or
/// `None` for any other id, which reaches here only when the provider
/// refused the filter.
fn classify_event(event_id: u16) -> Option<(bool, ConnectionProgress)> {
    SUBSCRIBED_EVENTS
        .iter()
        .find(|(id, ..)| *id == event_id)
        .map(|&(_, is_v6, progress)| (is_v6, progress))
}

/// C-ABI ETW record callback. Parses the subscribed TCP events into a
/// [`ConnectionObservation`] and buffers it; a connect attempt is also handed
/// to the [`PathResolver`]. No syscall (bar waking an idle resolver) and no
/// allocation past the buffer's own growth: under a connect storm a slow
/// callback makes ETW drop events.
unsafe extern "system" fn event_record_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let rec = &*record;
    let event_id = rec.EventHeader.EventDescriptor.Id;
    let Some((is_v6, progress)) = classify_event(event_id) else {
        return;
    };
    let Some(context) = callback_context::<CallbackContext>(rec) else {
        return;
    };
    let Some(bytes) = user_data(rec) else {
        return;
    };
    let parsed = if is_v6 {
        parse_tcp_connect_v6(bytes).map(|(pid, l, r)| (pid, SocketAddr::V6(l), SocketAddr::V6(r)))
    } else {
        parse_tcp_connect_v4(bytes).map(|(pid, l, r)| (pid, SocketAddr::V4(l), SocketAddr::V4(r)))
    };
    let Some((pid, local, remote)) = parsed else {
        return;
    };
    // Stamped here: the buffer is drained on a timer, and an unstamped record
    // would carry the drain time. The system clock rather than the header
    // stamp, because the pid check compares it with process creation times,
    // and a performance-counter stamp converted from the session start drifts
    // from the system clock over a long session. User-mode read, no syscall.
    let observed_unix_ms = unix_now_ms();
    if progress == ConnectionProgress::Attempt && pid != 0 {
        if let Some(at) = observed_unix_ms {
            context.lookups.offer(pid, at);
        }
    }
    if let Ok(mut g) = context.buffer.lock() {
        if g.len() < BUFFER_CAP {
            g.push(ConnectionObservation {
                pid,
                process_path: None, // named at drain
                user_sid: None,
                protocol: TransportProtocol::Tcp,
                local,
                remote,
                verdict: ConnectionVerdict::Unknown, // kernel connect carries no verdict.
                drop_filter_id: None,                // ETW connects are not drops.
                blocked_by_nrr: None,
                nrr_drop_spec_id: None,
                observed_unix_ms,
                progress,
            });
        }
    }
}

fn unix_now_ms() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64)
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A live process as a lookup sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessImage {
    started_unix_ms: u64,
    path: String,
}

/// Looks a pid up among the processes alive now.
trait LiveProcessImages {
    fn image_of(&mut self, pid: u32) -> Option<ProcessImage>;
}

/// A connect whose process the resolver is to name.
#[derive(Debug, Clone, Copy)]
struct PendingLookup {
    pid: u32,
    at_unix_ms: u64,
}

/// A resolved process and the last moment it was seen holding its pid.
struct KnownImage {
    path: String,
    confirmed_unix_ms: u64,
}

/// Processes the resolver has named, keyed by pid and start time so that a
/// reused pid is a separate entry, never an overwrite.
#[derive(Default)]
struct KnownProcesses {
    images: BTreeMap<(u32, u64), KnownImage>,
    pruned_unix_ms: u64,
}

impl KnownProcesses {
    /// The process that held `pid` at `at`: started no later, and seen holding
    /// the pid no earlier. A process object keeps its pid while it exists, so
    /// between those two moments no other process can have had it.
    fn path_at(&self, pid: u32, at: u64) -> Option<&str> {
        let (_, image) = self.images.range((pid, 0)..=(pid, at)).next_back()?;
        (at <= image.confirmed_unix_ms).then_some(image.path.as_str())
    }

    /// `image` held `pid` at some moment no earlier than `now`.
    fn record(&mut self, pid: u32, image: ProcessImage, now: u64) {
        let entry = self
            .images
            .entry((pid, image.started_unix_ms))
            .or_insert(KnownImage {
                path: image.path,
                confirmed_unix_ms: now,
            });
        entry.confirmed_unix_ms = entry.confirmed_unix_ms.max(now);
        if self.images.len() > KNOWN_CAP
            || now.saturating_sub(self.pruned_unix_ms) >= KNOWN_PRUNE_EVERY_MS
        {
            self.prune(now);
        }
    }

    /// Forget what no buffered connect can still need, then the least recently
    /// confirmed past the cap.
    fn prune(&mut self, now: u64) {
        self.pruned_unix_ms = now;
        self.images
            .retain(|_, i| now.saturating_sub(i.confirmed_unix_ms) <= KNOWN_RETAIN_MS);
        let excess = self.images.len().saturating_sub(KNOWN_CAP);
        if excess == 0 {
            return;
        }
        let mut by_age: Vec<((u32, u64), u64)> = self
            .images
            .iter()
            .map(|(key, i)| (*key, i.confirmed_unix_ms))
            .collect();
        by_age.sort_unstable_by_key(|&(_, confirmed)| confirmed);
        for (key, _) in by_age.into_iter().take(excess) {
            self.images.remove(&key);
        }
    }
}

/// State shared by the ETW callback, the resolver thread and the drain.
struct ResolverShared {
    queue: Mutex<VecDeque<PendingLookup>>,
    dropped: AtomicU64,
    known: Mutex<KnownProcesses>,
    stopping: AtomicBool,
    worker: OnceLock<Thread>,
}

impl ResolverShared {
    fn new() -> Self {
        Self {
            queue: Mutex::new(VecDeque::with_capacity(LOOKUP_QUEUE_CAP)),
            dropped: AtomicU64::new(0),
            known: Mutex::new(KnownProcesses::default()),
            stopping: AtomicBool::new(false),
            worker: OnceLock::new(),
        }
    }

    /// Called from the ETW callback: never waits for room and never grows the
    /// queue past its preallocated capacity. The wake is a syscall only when
    /// the resolver is parked, i.e. idle — never while it works through a storm.
    fn offer(&self, pid: u32, at_unix_ms: u64) {
        let queued = {
            let mut queue = lock(&self.queue);
            let fits = queue.len() < LOOKUP_QUEUE_CAP;
            if fits {
                queue.push_back(PendingLookup { pid, at_unix_ms });
            }
            fits
        };
        if !queued {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        } else if let Some(worker) = self.worker.get() {
            worker.unpark();
        }
    }

    /// Lookups dropped since the previous call.
    fn take_dropped(&self) -> u64 {
        self.dropped.swap(0, Ordering::Relaxed)
    }
}

/// The thread that names a connect's process while it most likely still runs.
struct PathResolver {
    shared: Arc<ResolverShared>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl PathResolver {
    fn spawn<L: LiveProcessImages + Send + 'static>(live: L) -> Result<Self, PlatformError> {
        let shared = Arc::new(ResolverShared::new());
        let thread_shared = Arc::clone(&shared);
        let handle = std::thread::Builder::new()
            .name("nrr-conn-paths".into())
            .spawn(move || run_resolver(&thread_shared, live))
            .map_err(|e| PlatformError::Win32 {
                operation: "spawn(conn path resolver)",
                code: 0,
                message: e.to_string(),
            })?;
        let _ = shared.worker.set(handle.thread().clone());
        Ok(Self {
            shared,
            handle: Mutex::new(Some(handle)),
        })
    }

    /// Stop the thread and join it. Idempotent.
    fn stop(&self) {
        self.shared.stopping.store(true, Ordering::Release);
        let handle = lock(&self.handle).take();
        if let Some(handle) = handle {
            handle.thread().unpark();
            let _ = handle.join();
        }
    }
}

impl Drop for PathResolver {
    fn drop(&mut self) {
        self.stop();
    }
}

fn run_resolver(shared: &ResolverShared, mut live: impl LiveProcessImages) {
    let mut batch: Vec<PendingLookup> = Vec::with_capacity(LOOKUP_QUEUE_CAP);
    let mut looked_up = HashSet::new();
    while !shared.stopping.load(Ordering::Acquire) {
        batch.extend(lock(&shared.queue).drain(..));
        if batch.is_empty() {
            std::thread::park();
            continue;
        }
        // Taken after the batch, so it is no earlier than any connect in it.
        if let Some(now) = unix_now_ms() {
            resolve_batch(&batch, &shared.known, &mut live, now, &mut looked_up);
        }
        batch.clear();
    }
}

/// Name the process of each pending connect not already covered, at most one
/// lookup per pid per batch: a successful one covers every earlier connect of
/// that process, so a storm costs lookups per batch, not per connect.
fn resolve_batch(
    batch: &[PendingLookup],
    known: &Mutex<KnownProcesses>,
    live: &mut impl LiveProcessImages,
    now: u64,
    looked_up: &mut HashSet<u32>,
) {
    looked_up.clear();
    for pending in batch {
        if lock(known)
            .path_at(pending.pid, pending.at_unix_ms)
            .is_some()
            || !looked_up.insert(pending.pid)
        {
            continue;
        }
        // Recorded even when it started after the connect: it holds the pid
        // now and may own the next ones; `path_at` never lends it backwards.
        if let Some(image) = live.image_of(pending.pid) {
            lock(known).record(pending.pid, image, now);
        }
    }
}

/// Name the process behind every connect attempt in `batch`: from what the
/// resolver recorded, else by one lookup per distinct pid. A pid is only
/// trusted when its current process started no later than the event: one that
/// started after it reused the pid of a process that has since exited, and
/// naming it would blame the wrong program. Such an attempt, like one whose
/// process is gone, keeps no path.
fn attach_process_paths(
    batch: &mut [ConnectionObservation],
    known: &KnownProcesses,
    live: &mut impl LiveProcessImages,
) {
    let mut seen: HashMap<u32, Option<ProcessImage>> = HashMap::new();
    // Progress events never become trace rows: a lookup would buy nothing.
    for obs in batch
        .iter_mut()
        .filter(|o| o.progress == ConnectionProgress::Attempt && o.pid != 0)
    {
        let Some(at) = obs.observed_unix_ms else {
            obs.process_path = None;
            continue;
        };
        if let Some(path) = known.path_at(obs.pid, at) {
            obs.process_path = Some(path.to_owned());
            continue;
        }
        let image = seen
            .entry(obs.pid)
            .or_insert_with(|| live.image_of(obs.pid));
        obs.process_path = match image {
            Some(image) if image.started_unix_ms <= at => Some(image.path.clone()),
            _ => None,
        };
    }
}

/// The running system's processes, opened with query-only rights.
struct SystemProcesses;

impl LiveProcessImages for SystemProcesses {
    /// `None` for a process that has exited, or a protected/System pid
    /// `OpenProcess` cannot open.
    fn image_of(&mut self, pid: u32) -> Option<ProcessImage> {
        // SAFETY: a query-only handle on `pid`, closed on every path below;
        // the FILETIMEs outlive the call.
        let (handle, times, created) = unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid).ok()?;
            if handle.is_invalid() {
                return None;
            }
            let (mut created, mut exited, mut kernel, mut user) = (
                FILETIME::default(),
                FILETIME::default(),
                FILETIME::default(),
                FILETIME::default(),
            );
            let times = GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user);
            (handle, times, created)
        };
        let path = crate::win32_ffi::process::image_path_of(handle);
        // SAFETY: opened above and not used after this call.
        unsafe {
            let _ = CloseHandle(handle);
        }
        times.ok()?;
        let path = path.ok().filter(|path| !path.is_empty())?;
        Some(ProcessImage {
            started_unix_ms: filetime_to_unix_ms(&created)?,
            path,
        })
    }
}

/// `FILETIME` (100 ns ticks since 1601) as Unix ms; `None` before 1970.
fn filetime_to_unix_ms(ft: &FILETIME) -> Option<u64> {
    const UNIX_EPOCH_TICKS: u64 = 116_444_736_000_000_000;
    let ticks = (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime);
    ticks.checked_sub(UNIX_EPOCH_TICKS).map(|t| t / 10_000)
}

/// Parse the payload of `Microsoft-Windows-Kernel-Network` event 12 (TCP IPv4
/// connect). Returns `(pid, local = source addr:port, remote = dest addr:port)`.
///
/// Leading fixed layout (stable across Windows versions; the pointer-sized
/// `connid` that varies x86/x64 sits *after* these fields, so it never shifts
/// them): `u32 pid; u32 size; u32 daddr; u32 saddr; u16 dport; u16 sport; …`.
/// Addresses are stored as IPv4 in network byte order (read the 4 bytes as
/// octets); ports are network byte order (big-endian).
fn parse_tcp_connect_v4(d: &[u8]) -> Option<(u32, SocketAddrV4, SocketAddrV4)> {
    if d.len() < 20 {
        return None;
    }
    let pid = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
    let daddr = Ipv4Addr::new(d[8], d[9], d[10], d[11]);
    let saddr = Ipv4Addr::new(d[12], d[13], d[14], d[15]);
    let dport = u16::from_be_bytes([d[16], d[17]]);
    let sport = u16::from_be_bytes([d[18], d[19]]);
    let local = SocketAddrV4::new(saddr, sport);
    let remote = SocketAddrV4::new(daddr, dport);
    Some((pid, local, remote))
}

/// Parse the payload of `Microsoft-Windows-Kernel-Network` event 28 (TCP IPv6
/// connect). Same leading layout as v4 but with 16-byte addresses:
/// `u32 pid; u32 size; u8[16] daddr; u8[16] saddr; u16 dport; u16 sport; …`.
/// Addresses are the 16 octets in order; ports are network byte order.
fn parse_tcp_connect_v6(d: &[u8]) -> Option<(u32, SocketAddrV6, SocketAddrV6)> {
    if d.len() < 44 {
        return None;
    }
    let pid = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
    let daddr = Ipv6Addr::from(<[u8; 16]>::try_from(&d[8..24]).ok()?);
    let saddr = Ipv6Addr::from(<[u8; 16]>::try_from(&d[24..40]).ok()?);
    let dport = u16::from_be_bytes([d[40], d[41]]);
    let sport = u16::from_be_bytes([d[42], d[43]]);
    let local = SocketAddrV6::new(saddr, sport, 0, 0);
    let remote = SocketAddrV6::new(daddr, dport, 0, 0);
    Some((pid, local, remote))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_payload() {
        // pid=4242, size=0, daddr=203.0.113.162, saddr=10.8.0.6,
        // dport=443 (0x01BB), sport=50000 (0xC350) — both network order.
        let mut d = vec![0u8; 24];
        d[0..4].copy_from_slice(&4242u32.to_le_bytes());
        d[8..12].copy_from_slice(&[203, 0, 113, 162]); // daddr
        d[12..16].copy_from_slice(&[10, 8, 0, 6]); // saddr
        d[16..18].copy_from_slice(&443u16.to_be_bytes()); // dport
        d[18..20].copy_from_slice(&50000u16.to_be_bytes()); // sport

        let (pid, local, remote) = parse_tcp_connect_v4(&d).expect("parse");
        assert_eq!(pid, 4242);
        assert_eq!(local, SocketAddrV4::new(Ipv4Addr::new(10, 8, 0, 6), 50000));
        assert_eq!(
            remote,
            SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 162), 443)
        );
    }

    /// Processes alive at drain time, counting lookups.
    #[derive(Default)]
    struct FakeProcesses {
        alive: HashMap<u32, ProcessImage>,
        lookups: Vec<u32>,
    }

    impl FakeProcesses {
        fn with(mut self, pid: u32, started_unix_ms: u64, path: &str) -> Self {
            self.alive.insert(
                pid,
                ProcessImage {
                    started_unix_ms,
                    path: path.into(),
                },
            );
            self
        }
    }

    impl LiveProcessImages for FakeProcesses {
        fn image_of(&mut self, pid: u32) -> Option<ProcessImage> {
            self.lookups.push(pid);
            self.alive.get(&pid).cloned()
        }
    }

    fn event(pid: u32, at: Option<u64>, progress: ConnectionProgress) -> ConnectionObservation {
        let addr: SocketAddr = "192.0.2.1:443".parse().expect("addr");
        ConnectionObservation {
            pid,
            process_path: None,
            user_sid: None,
            protocol: TransportProtocol::Tcp,
            local: addr,
            remote: addr,
            verdict: ConnectionVerdict::Unknown,
            drop_filter_id: None,
            blocked_by_nrr: None,
            nrr_drop_spec_id: None,
            observed_unix_ms: at,
            progress,
        }
    }

    const APP: &str = r"C:\Apps\app.exe";

    #[test]
    fn a_connect_is_named_after_its_live_process() {
        let mut batch = vec![event(10, Some(5_000), ConnectionProgress::Attempt)];
        attach_process_paths(
            &mut batch,
            &KnownProcesses::default(),
            &mut FakeProcesses::default().with(10, 5_000, APP),
        );
        assert_eq!(batch[0].process_path.as_deref(), Some(APP));
    }

    #[test]
    fn a_pid_reused_after_the_event_names_nobody() {
        // The connecting process exited; a newer one got its pid before the drain.
        let mut batch = vec![
            event(10, Some(5_000), ConnectionProgress::Attempt),
            event(10, Some(9_000), ConnectionProgress::Attempt),
        ];
        attach_process_paths(
            &mut batch,
            &KnownProcesses::default(),
            &mut FakeProcesses::default().with(10, 7_000, APP),
        );
        assert_eq!(batch[0].process_path, None);
        assert_eq!(batch[1].process_path.as_deref(), Some(APP));
    }

    #[test]
    fn an_exited_process_or_an_unstamped_event_keeps_no_path() {
        let mut batch = vec![
            event(10, Some(5_000), ConnectionProgress::Attempt),
            event(11, None, ConnectionProgress::Attempt),
        ];
        attach_process_paths(
            &mut batch,
            &KnownProcesses::default(),
            &mut FakeProcesses::default().with(11, 1, APP),
        );
        assert!(batch.iter().all(|o| o.process_path.is_none()));
    }

    #[test]
    fn each_pid_is_looked_up_once_and_progress_events_never() {
        let mut batch = vec![
            event(10, Some(5_000), ConnectionProgress::Attempt),
            event(10, Some(5_001), ConnectionProgress::Attempt),
            event(12, Some(5_002), ConnectionProgress::Retransmit),
            event(13, Some(5_003), ConnectionProgress::ClosedInOrder),
            event(0, Some(5_004), ConnectionProgress::Attempt),
            event(14, Some(5_005), ConnectionProgress::Attempt),
        ];
        let mut live = FakeProcesses::default().with(10, 1, APP).with(12, 1, APP);
        attach_process_paths(&mut batch, &KnownProcesses::default(), &mut live);
        assert_eq!(live.lookups, vec![10, 14]);
        assert_eq!(batch[2].process_path, None);
    }

    const OTHER: &str = r"C:\Apps\other.exe";

    fn pending(pid: u32, at_unix_ms: u64) -> PendingLookup {
        PendingLookup { pid, at_unix_ms }
    }

    fn image(started_unix_ms: u64, path: &str) -> ProcessImage {
        ProcessImage {
            started_unix_ms,
            path: path.into(),
        }
    }

    fn wait_until(mut done: impl FnMut() -> bool) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if done() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        done()
    }

    #[test]
    fn a_short_lived_process_resolved_by_the_thread_keeps_its_path_after_exit() {
        let resolver = PathResolver::spawn(SystemProcesses).expect("spawn the resolver");
        // `cmd` reading commands from a pipe lives until the pipe closes.
        let mut child = std::process::Command::new("cmd")
            .arg("/q")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn cmd");
        let pid = child.id();
        let at = unix_now_ms().expect("clock");
        resolver.shared.offer(pid, at);
        let resolved = wait_until(|| lock(&resolver.shared.known).path_at(pid, at).is_some());
        drop(child.stdin.take());
        child.wait().expect("cmd exits");
        drop(child);
        assert!(resolved, "the resolver named the running process");

        // Nothing is alive at drain time: the path can only come from the resolver.
        let mut gone = FakeProcesses::default();
        let mut batch = vec![event(pid, Some(at), ConnectionProgress::Attempt)];
        attach_process_paths(&mut batch, &lock(&resolver.shared.known), &mut gone);
        let path = batch[0]
            .process_path
            .as_deref()
            .expect("path kept after exit");
        assert!(path.to_ascii_lowercase().ends_with("cmd.exe"), "{path}");
        assert!(gone.lookups.is_empty());
        resolver.stop();
    }

    #[test]
    fn a_reused_pid_seen_by_the_resolver_still_names_nobody() {
        let known = Mutex::new(KnownProcesses::default());
        let mut looked_up = HashSet::new();
        // A connects at 5_000 and is named at 5_100.
        let mut first = FakeProcesses::default().with(10, 1_000, APP);
        resolve_batch(
            &[pending(10, 5_000)],
            &known,
            &mut first,
            5_100,
            &mut looked_up,
        );
        // A exits; B takes pid 10 at 7_000 and connects at 8_000.
        let mut second = FakeProcesses::default().with(10, 7_000, OTHER);
        resolve_batch(
            &[pending(10, 8_000)],
            &known,
            &mut second,
            8_100,
            &mut looked_up,
        );
        // 6_000: after A was last seen, before B existed — either could not be proven.
        let mut batch = vec![
            event(10, Some(5_000), ConnectionProgress::Attempt),
            event(10, Some(6_000), ConnectionProgress::Attempt),
            event(10, Some(8_000), ConnectionProgress::Attempt),
        ];
        attach_process_paths(&mut batch, &lock(&known), &mut second);
        assert_eq!(batch[0].process_path.as_deref(), Some(APP));
        assert_eq!(batch[1].process_path, None);
        assert_eq!(batch[2].process_path.as_deref(), Some(OTHER));
    }

    #[test]
    fn a_pid_already_reused_when_the_resolver_looks_names_nobody() {
        let known = Mutex::new(KnownProcesses::default());
        let mut live = FakeProcesses::default().with(10, 7_000, OTHER);
        resolve_batch(
            &[pending(10, 5_000)],
            &known,
            &mut live,
            7_500,
            &mut HashSet::new(),
        );
        let mut batch = vec![event(10, Some(5_000), ConnectionProgress::Attempt)];
        attach_process_paths(&mut batch, &lock(&known), &mut live);
        assert_eq!(batch[0].process_path, None);
    }

    #[test]
    fn the_resolver_looks_a_pid_up_once_per_batch_and_skips_covered_connects() {
        let known = Mutex::new(KnownProcesses::default());
        let mut looked_up = HashSet::new();
        let mut live = FakeProcesses::default().with(10, 1, APP);
        let batch = [
            pending(10, 1_000),
            pending(10, 1_001),
            pending(11, 1_002),
            pending(11, 1_003),
        ];
        resolve_batch(&batch, &known, &mut live, 2_000, &mut looked_up);
        assert_eq!(live.lookups, vec![10, 11]);
        // Covered by the lookup at 2_000; a later connect needs a fresh one.
        resolve_batch(
            &[pending(10, 1_500)],
            &known,
            &mut live,
            2_500,
            &mut looked_up,
        );
        assert_eq!(live.lookups, vec![10, 11]);
        resolve_batch(
            &[pending(10, 2_100)],
            &known,
            &mut live,
            2_600,
            &mut looked_up,
        );
        assert_eq!(live.lookups, vec![10, 11, 10]);
    }

    #[test]
    fn a_full_queue_drops_without_waiting_and_counts_the_drops() {
        let shared = ResolverShared::new();
        let capacity = lock(&shared.queue).capacity();
        for pid in 1..=(LOOKUP_QUEUE_CAP as u32 + 5) {
            shared.offer(pid, 1_000);
        }
        let queue = lock(&shared.queue);
        assert_eq!(queue.len(), LOOKUP_QUEUE_CAP);
        assert_eq!(
            queue.capacity(),
            capacity,
            "the callback never grows the queue"
        );
        drop(queue);
        assert_eq!(shared.take_dropped(), 5);
        assert_eq!(shared.take_dropped(), 0);
    }

    #[test]
    fn stop_joins_the_resolver_thread() {
        let resolver = PathResolver::spawn(FakeProcesses::default()).expect("spawn");
        let shared = Arc::clone(&resolver.shared);
        resolver.stop();
        assert!(lock(&resolver.handle).is_none());
        // This test and the resolver; the thread's reference went with it.
        assert_eq!(Arc::strong_count(&shared), 2);
        resolver.stop();
        shared.offer(1, 1);
    }

    #[test]
    fn known_processes_are_pruned_by_age_and_by_size() {
        let mut known = KnownProcesses::default();
        known.record(1, image(1, APP), 1_000);
        let later = 1_000 + KNOWN_RETAIN_MS + KNOWN_PRUNE_EVERY_MS;
        known.record(2, image(1, APP), later);
        assert!(known.path_at(1, 1_000).is_none(), "aged out");
        assert!(known.path_at(2, later).is_some());

        let base = later + 1;
        for i in 0..(KNOWN_CAP as u64 + 10) {
            known.record(1_000 + i as u32, image(1, APP), base + i);
        }
        assert_eq!(known.images.len(), KNOWN_CAP);
        assert!(
            known.path_at(2, later).is_none(),
            "least recently confirmed goes first"
        );
        assert!(known.path_at(1_000, base).is_none());
        let newest = 1_000 + KNOWN_CAP as u32 + 9;
        assert!(known.path_at(newest, base).is_some());
    }

    #[test]
    fn filetime_before_1970_has_no_unix_time() {
        let at = |ticks: u64| FILETIME {
            dwLowDateTime: ticks as u32,
            dwHighDateTime: (ticks >> 32) as u32,
        };
        assert_eq!(filetime_to_unix_ms(&at(0)), None);
        assert_eq!(
            filetime_to_unix_ms(&at(116_444_736_000_000_000 + 12_340_000)),
            Some(1_234)
        );
    }

    #[test]
    fn our_own_process_is_named_with_its_start_time() {
        let image = SystemProcesses
            .image_of(std::process::id())
            .expect("the test process can open itself");
        assert!(image.path.to_ascii_lowercase().ends_with(".exe"));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        assert!(image.started_unix_ms <= now);
    }

    #[test]
    fn the_session_filter_admits_exactly_what_the_callback_classifies() {
        let classified: Vec<u16> = (0..=u16::MAX)
            .filter(|&id| classify_event(id).is_some())
            .collect();
        let mut filtered = SUBSCRIBED_EVENT_IDS.to_vec();
        filtered.sort_unstable();
        filtered.dedup();
        assert_eq!(filtered, classified);
        assert_eq!(
            filtered.len(),
            SUBSCRIBED_EVENT_IDS.len(),
            "no duplicate ids"
        );
        assert_eq!(
            classify_event(EVENT_ID_TCP_RETRANSMIT_V6),
            Some((true, ConnectionProgress::Retransmit))
        );
        // `datasent`/`datarecv` (v4 10/11, v6 26/27) stay out.
        for segment_event in [10, 11, 26, 27] {
            assert!(!SUBSCRIBED_EVENT_IDS.contains(&segment_event));
        }
    }

    #[test]
    fn rejects_short_payload() {
        assert!(parse_tcp_connect_v4(&[0u8; 8]).is_none());
        assert!(parse_tcp_connect_v6(&[0u8; 20]).is_none());
    }

    #[test]
    fn parses_v6_connect_payload() {
        // pid=7, daddr=2001:db8::1, saddr=fe80::2, dport=443, sport=50000.
        let mut d = vec![0u8; 48];
        d[0..4].copy_from_slice(&7u32.to_le_bytes());
        let daddr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let saddr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        d[8..24].copy_from_slice(&daddr.octets());
        d[24..40].copy_from_slice(&saddr.octets());
        d[40..42].copy_from_slice(&443u16.to_be_bytes());
        d[42..44].copy_from_slice(&50000u16.to_be_bytes());

        let (pid, local, remote) = parse_tcp_connect_v6(&d).expect("parse");
        assert_eq!(pid, 7);
        assert_eq!(local, SocketAddrV6::new(saddr, 50000, 0, 0));
        assert_eq!(remote, SocketAddrV6::new(daddr, 443, 0, 0));
    }
}
