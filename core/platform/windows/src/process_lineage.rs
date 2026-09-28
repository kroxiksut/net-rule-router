//! Windows mechanism behind [`ProcessLineagePort`]: process starts from the
//! `Microsoft-Windows-Kernel-Process` ETW provider feed the neutral start
//! record, and a Toolhelp snapshot answers for processes older than the
//! session.
//!
//! Off the packet path: the session only records starts and exits (a few per
//! second on a busy desktop), and the walk runs once per block notice.
//!
//! ## Verification status
//!
//! The payload decode is unit-tested from constructed byte layouts matching the
//! provider's published message ordinals (versions 0-3). The live session needs
//! an elevated process and is exercised only by a service run.

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use nrr_platform_api::process_lineage::{
    image_basename, resolve_ancestry, unix_ms, LineageCoverage, ProcessFacts, ProcessLineagePort,
    ProcessStartRing, ProcessTable,
};
use windows::core::GUID;
use windows::Win32::Foundation::{CloseHandle, FALSE, FILETIME};
use windows::Win32::System::Diagnostics::Etw::{
    EVENT_ENABLE_PROPERTY_SID, EVENT_HEADER_EXT_TYPE_SID, EVENT_RECORD, TRACE_LEVEL_INFORMATION,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::error::PlatformError;
use crate::etw_session::{
    callback_context, user_data, ProviderEnable, RealtimeSession, SessionClock, SessionConfig,
};

/// `Microsoft-Windows-Kernel-Process` provider GUID.
const KERNEL_PROCESS_PROVIDER: GUID = GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);

/// `WINEVENT_KEYWORD_PROCESS`: process start/stop only — no thread or image
/// events, which fire orders of magnitude more often.
const KEYWORD_PROCESS: u64 = 0x10;

const EVENT_ID_PROCESS_START: u16 = 1;
const EVENT_ID_PROCESS_STOP: u16 = 2;

/// The Unix epoch as a FILETIME (100 ns ticks since 1601).
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

type Ring = Mutex<ProcessStartRing>;

/// Recorded process starts plus the live table, behind the neutral port.
pub struct EtwProcessLineage {
    ring: Arc<Ring>,
    session: RealtimeSession,
}

impl EtwProcessLineage {
    /// Start the `NrrProcessLineage` session. Needs the privileges the service
    /// runs with; the caller degrades to no ancestry on error.
    pub fn start() -> Result<Self, PlatformError> {
        let ring: Arc<Ring> = Arc::new(Mutex::new(ProcessStartRing::default()));
        let session = RealtimeSession::start(
            &SessionConfig {
                name: "NrrProcessLineage",
                thread_name: "nrr-proc-etw",
                // Starts are compared with drop timestamps, which are wall clock.
                clock: SessionClock::SystemTime,
                // A notice is built seconds after the drop; a start still sitting
                // in a half-full buffer would miss it.
                flush_timer_secs: 1,
            },
            &ProviderEnable {
                guid: KERNEL_PROCESS_PROVIDER,
                level: TRACE_LEVEL_INFORMATION as u8,
                keywords: KEYWORD_PROCESS,
                enable_property: EVENT_ENABLE_PROPERTY_SID,
            },
            event_record_callback,
            Arc::clone(&ring),
        )?;
        tracing::info!(
            target: "nrr::block-notice",
            "process-start recorder started",
        );
        Ok(Self { ring, session })
    }
}

impl ProcessLineagePort for EtwProcessLineage {
    fn coverage(&self) -> LineageCoverage {
        LineageCoverage::History
    }

    fn ancestry_of(&self, image_path: &str, sid: Option<&str>, at: SystemTime) -> Vec<String> {
        let mut live = ToolhelpTable::default();
        // The recorder waits on this lock for the length of one walk — a
        // snapshot at worst — once per notice.
        let mut ring = self.ring.lock().unwrap_or_else(|p| p.into_inner());
        ring.prune(unix_ms(SystemTime::now()));
        resolve_ancestry(
            &mut [&mut *ring as &mut dyn ProcessTable, &mut live],
            image_path,
            sid,
            unix_ms(at),
        )
    }

    fn stop(&self) {
        self.session.stop();
    }
}

/// C-ABI record callback: starts and exits into the ring.
unsafe extern "system" fn event_record_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let rec = &*record;
    let id = rec.EventHeader.EventDescriptor.Id;
    if id != EVENT_ID_PROCESS_START && id != EVENT_ID_PROCESS_STOP {
        return;
    }
    let Some(ring) = callback_context::<Ring>(rec) else {
        return;
    };
    let Some(bytes) = user_data(rec) else {
        return;
    };
    // The session clock is wall time, so the header stamp is a FILETIME.
    let at_ms = filetime_to_unix_ms(rec.EventHeader.TimeStamp as u64);
    if id == EVENT_ID_PROCESS_STOP {
        if let Some(pid) = read_u32(bytes, 0) {
            ring.lock()
                .unwrap_or_else(|p| p.into_inner())
                .record_exit(pid, at_ms);
        }
        return;
    }
    let Some(start) = parse_process_start(rec.EventHeader.EventDescriptor.Version, bytes) else {
        return;
    };
    let sid = extended_sid(rec);
    ring.lock().unwrap_or_else(|p| p.into_inner()).record_start(
        start.pid,
        start.parent_pid,
        &start.image_name,
        at_ms,
        sid,
    );
}

/// The creator's SID from the `EVENT_ENABLE_PROPERTY_SID` extended item.
///
/// # Safety
/// `rec` must be a record ETW delivered to a callback, still in scope.
unsafe fn extended_sid(rec: &EVENT_RECORD) -> Option<String> {
    if rec.ExtendedData.is_null() {
        return None;
    }
    let items = std::slice::from_raw_parts(rec.ExtendedData, rec.ExtendedDataCount as usize);
    let item = items
        .iter()
        .find(|i| u32::from(i.ExtType) == EVENT_HEADER_EXT_TYPE_SID)?;
    let data = item.DataPtr as usize as *const u8;
    if data.is_null() {
        return None;
    }
    sid_to_string(std::slice::from_raw_parts(data, item.DataSize as usize))
}

/// What a ProcessStart record says, image reduced to its name.
#[derive(Debug, PartialEq, Eq)]
struct ProcessStart {
    pid: u32,
    parent_pid: u32,
    image_name: String,
}

/// Decode a ProcessStart (event 1) payload by manifest version.
///
/// v0: `pid u32, CreateTime u64, ParentPid u32, SessionId u32, ImageName`.
/// v1/v2: as v0 with `Flags u32` before `ImageName`.
/// v3: `pid u32, SeqNo u64, CreateTime u64, ParentPid u32, ParentSeqNo u64,
/// SessionId u32, Flags u32, ElevationType u32, IsElevated u32,
/// MandatoryLabel SID, ImageName, …`. A later version is read as v3: manifest
/// revisions append fields, and a mismatch fails the checks rather than
/// yielding a wrong name.
fn parse_process_start(version: u8, d: &[u8]) -> Option<ProcessStart> {
    let pid = read_u32(d, 0)?;
    let (parent_pid, image_at) = match version {
        0 => (read_u32(d, 12)?, 20),
        1 | 2 => (read_u32(d, 12)?, 24),
        _ => (read_u32(d, 20)?, 48 + sid_len(d.get(48..)?)?),
    };
    let image = read_utf16z(d.get(image_at..)?)?;
    let name = image_basename(&image);
    if name.is_empty() || name.chars().any(char::is_control) {
        return None;
    }
    Some(ProcessStart {
        pid,
        parent_pid,
        image_name: name.to_owned(),
    })
}

/// Byte length of the SID at the head of `d`, when one is there.
fn sid_len(d: &[u8]) -> Option<usize> {
    let (&revision, &count) = (d.first()?, d.get(1)?);
    if revision != 1 || count > 15 {
        return None;
    }
    let len = 8 + 4 * usize::from(count);
    (d.len() >= len).then_some(len)
}

/// `S-1-…` text of a binary SID.
fn sid_to_string(d: &[u8]) -> Option<String> {
    let len = sid_len(d)?;
    let authority = d[2..8]
        .iter()
        .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    let mut out = format!("S-1-{authority}");
    for chunk in d[8..len].chunks_exact(4) {
        let sub = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        out.push('-');
        out.push_str(&sub.to_string());
    }
    Some(out)
}

fn read_u32(d: &[u8], at: usize) -> Option<u32> {
    let b = d.get(at..at + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// NUL-terminated UTF-16LE at the head of `d`. A string that runs off the end
/// is rejected: the field is terminated in every version.
fn read_utf16z(d: &[u8]) -> Option<String> {
    let mut units = Vec::new();
    for pair in d.chunks_exact(2) {
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        if unit == 0 {
            return Some(String::from_utf16_lossy(&units));
        }
        units.push(unit);
    }
    None
}

fn filetime_to_unix_ms(ticks: u64) -> u64 {
    ticks.saturating_sub(FILETIME_UNIX_EPOCH) / 10_000
}

/// The live process table, snapshotted on first use and only when the start
/// record could not answer.
#[derive(Default)]
struct ToolhelpTable {
    entries: Option<Vec<LiveProcess>>,
}

struct LiveProcess {
    pid: u32,
    parent_pid: u32,
    image_name: String,
}

impl ToolhelpTable {
    fn entries(&mut self) -> &[LiveProcess] {
        self.entries.get_or_insert_with(snapshot_processes)
    }

    fn facts(p: &LiveProcess) -> ProcessFacts {
        ProcessFacts {
            pid: p.pid,
            parent_pid: Some(p.parent_pid),
            image_name: p.image_name.clone(),
            started_ms: creation_ms(p.pid),
        }
    }
}

impl ProcessTable for ToolhelpTable {
    // The owner is not read: that needs the process token, and a name plus a
    // start time bound already narrows it to the run the notice is about.
    fn latest_named(
        &mut self,
        image: &str,
        _sid: Option<&str>,
        at_ms: u64,
    ) -> Option<ProcessFacts> {
        self.entries()
            .iter()
            .filter(|p| p.image_name.eq_ignore_ascii_case(image))
            .map(Self::facts)
            .filter(|f| f.started_ms.is_some_and(|s| s <= at_ms))
            .max_by_key(|f| f.started_ms)
    }

    fn parent_candidate(
        &mut self,
        pid: u32,
        child_started_ms: Option<u64>,
    ) -> Option<ProcessFacts> {
        let facts = self
            .entries()
            .iter()
            .find(|p| p.pid == pid)
            .map(Self::facts)?;
        match (child_started_ms, facts.started_ms) {
            (Some(child), Some(started)) if started <= child => Some(facts),
            (None, _) => Some(facts),
            // Started after the child, or cannot tell: the pid was reused.
            _ => None,
        }
    }
}

/// Every running process: pid, parent pid, image name. Empty on failure.
fn snapshot_processes() -> Vec<LiveProcess> {
    let mut out = Vec::new();
    // SAFETY: the snapshot handle is closed on every path; `entry` is a
    // correctly sized PROCESSENTRY32W the iteration calls fill in place.
    unsafe {
        let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return out;
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut more = Process32FirstW(snapshot, &mut entry).is_ok();
        while more {
            let len = entry
                .szExeFile
                .iter()
                .position(|&u| u == 0)
                .unwrap_or(entry.szExeFile.len());
            out.push(LiveProcess {
                pid: entry.th32ProcessID,
                parent_pid: entry.th32ParentProcessID,
                image_name: String::from_utf16_lossy(&entry.szExeFile[..len]),
            });
            more = Process32NextW(snapshot, &mut entry).is_ok();
        }
        let _ = CloseHandle(snapshot);
    }
    out
}

/// Creation time of a live process, Unix ms. `None` when it cannot be opened
/// (exited, protected) — which the walk treats as "cannot vouch for it".
fn creation_ms(pid: u32) -> Option<u64> {
    if pid == 0 {
        return None;
    }
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: a query-only handle on `pid`, closed before returning; the four
    // FILETIMEs outlive the call.
    let ok = unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid).ok()?;
        let ok = GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user).is_ok();
        let _ = CloseHandle(handle);
        ok
    };
    if !ok {
        return None;
    }
    let ticks = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
    Some(filetime_to_unix_ms(ticks))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16z(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    /// `S-1-16-12288`: the High mandatory label the v3 layout carries.
    fn label_sid() -> Vec<u8> {
        let mut sid = vec![1, 1, 0, 0, 0, 0, 0, 16];
        sid.extend_from_slice(&12288u32.to_le_bytes());
        sid
    }

    const IMAGE: &str = r"\Device\HarddiskVolume3\Windows\System32\curl.exe";

    #[test]
    fn decodes_the_v0_layout() {
        let mut d = Vec::new();
        d.extend_from_slice(&4242u32.to_le_bytes());
        d.extend_from_slice(&0u64.to_le_bytes()); // CreateTime
        d.extend_from_slice(&1000u32.to_le_bytes()); // ParentProcessID
        d.extend_from_slice(&1u32.to_le_bytes()); // SessionID
        d.extend(utf16z(IMAGE));

        let got = parse_process_start(0, &d).expect("v0");
        assert_eq!(
            got,
            ProcessStart {
                pid: 4242,
                parent_pid: 1000,
                image_name: "curl.exe".into()
            }
        );
    }

    #[test]
    fn decodes_the_v2_layout() {
        let mut d = Vec::new();
        d.extend_from_slice(&7u32.to_le_bytes());
        d.extend_from_slice(&0u64.to_le_bytes());
        d.extend_from_slice(&6u32.to_le_bytes());
        d.extend_from_slice(&1u32.to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes()); // Flags
        d.extend(utf16z(IMAGE));
        d.extend_from_slice(&0u32.to_le_bytes()); // ImageChecksum

        let got = parse_process_start(2, &d).expect("v2");
        assert_eq!((got.pid, got.parent_pid), (7, 6));
        assert_eq!(got.image_name, "curl.exe");
    }

    fn v3_payload(sid: &[u8]) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&9000u32.to_le_bytes()); // ProcessID
        d.extend_from_slice(&1u64.to_le_bytes()); // ProcessSequenceNumber
        d.extend_from_slice(&0u64.to_le_bytes()); // CreateTime
        d.extend_from_slice(&8000u32.to_le_bytes()); // ParentProcessID
        d.extend_from_slice(&2u64.to_le_bytes()); // ParentProcessSequenceNumber
        d.extend_from_slice(&1u32.to_le_bytes()); // SessionID
        d.extend_from_slice(&0u32.to_le_bytes()); // Flags
        d.extend_from_slice(&1u32.to_le_bytes()); // ProcessTokenElevationType
        d.extend_from_slice(&0u32.to_le_bytes()); // ProcessTokenIsElevated
        d.extend_from_slice(sid); // MandatoryLabel
        d.extend(utf16z(IMAGE));
        d.extend_from_slice(&0u32.to_le_bytes()); // ImageChecksum
        d.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
        d.extend(utf16z("")); // PackageFullName
        d.extend(utf16z("")); // PackageRelativeAppId
        d
    }

    #[test]
    fn decodes_the_v3_layout_past_the_variable_length_label() {
        let got = parse_process_start(3, &v3_payload(&label_sid())).expect("v3");
        assert_eq!((got.pid, got.parent_pid), (9000, 8000));
        assert_eq!(got.image_name, "curl.exe");
    }

    #[test]
    fn a_newer_version_is_read_with_the_v3_layout() {
        let got = parse_process_start(4, &v3_payload(&label_sid())).expect("v4");
        assert_eq!(got.image_name, "curl.exe");
    }

    #[test]
    fn a_misplaced_label_fails_instead_of_naming_garbage() {
        let mut bad = label_sid();
        bad[0] = 7; // not a SID revision
        assert!(parse_process_start(3, &v3_payload(&bad)).is_none());
    }

    #[test]
    fn truncated_payloads_are_rejected() {
        assert!(parse_process_start(0, &[0u8; 10]).is_none());
        let full = v3_payload(&label_sid());
        // Cut inside the image name: no terminator, no answer.
        assert!(parse_process_start(3, &full[..70]).is_none());
    }

    #[test]
    fn binary_sids_render_as_text() {
        let system = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        assert_eq!(sid_to_string(&system).as_deref(), Some("S-1-5-18"));
        let mut user = vec![1, 2, 0, 0, 0, 0, 0, 5];
        user.extend_from_slice(&21u32.to_le_bytes());
        user.extend_from_slice(&1001u32.to_le_bytes());
        assert_eq!(sid_to_string(&user).as_deref(), Some("S-1-5-21-1001"));
        assert!(
            sid_to_string(&[1, 3, 0, 0]).is_none(),
            "shorter than it claims"
        );
    }

    #[test]
    fn filetime_converts_to_unix_ms() {
        assert_eq!(filetime_to_unix_ms(FILETIME_UNIX_EPOCH), 0);
        assert_eq!(
            filetime_to_unix_ms(FILETIME_UNIX_EPOCH + 10_000 * 1_234),
            1_234
        );
        assert_eq!(filetime_to_unix_ms(0), 0);
    }

    /// The live table must not vouch for a pid it cannot date: a process that
    /// cannot be opened answers no start time and so never parents a child.
    #[test]
    fn an_undatable_live_parent_is_refused() {
        let mut table = ToolhelpTable {
            entries: Some(vec![LiveProcess {
                pid: 0,
                parent_pid: 0,
                image_name: "ghost.exe".into(),
            }]),
        };
        assert!(table.parent_candidate(0, Some(1_000)).is_none());
    }
}
