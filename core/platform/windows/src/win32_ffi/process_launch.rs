//! Another process's start time, command line and working folder.
//!
//! The command line comes from `NtQueryInformationProcess` with
//! `ProcessCommandLineInformation`, which query rights allow. The working
//! folder lives only in the process parameters block, so it is read from the
//! process's memory and needs read rights as well; where those are refused it
//! is simply not known. Every pointer here belongs to the other process or to
//! the kernel's answer: none is dereferenced, each is checked against the
//! buffer it must lie in.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::sync::OnceLock;

use windows::core::{s, w};
use windows::Win32::Foundation::{CloseHandle, FALSE, FILETIME, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_READ,
};

type NtQueryInformationProcessFn =
    unsafe extern "system" fn(HANDLE, u32, *mut c_void, u32, *mut u32) -> i32;

const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;
const PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;
const STATUS_BUFFER_OVERFLOW: i32 = 0x8000_0005_u32 as i32;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023_u32 as i32;

/// A Windows command line is at most 32 767 UTF-16 units, plus its header.
const MAX_COMMAND_LINE_BUFFER: usize = 32_768 * 2 + 64;
const FIRST_COMMAND_LINE_BUFFER: usize = 2048;

/// `UNICODE_STRING`: two `u16` lengths, then the pointer at its alignment.
const UNICODE_STRING_BUFFER_AT: usize = std::mem::size_of::<usize>();
const UNICODE_STRING_BYTES: usize = UNICODE_STRING_BUFFER_AT * 2;

/// Looked up at run time: the export is not in the import libraries the
/// `windows` crate links.
fn nt_query_information_process() -> Option<NtQueryInformationProcessFn> {
    static RESOLVED: OnceLock<Option<NtQueryInformationProcessFn>> = OnceLock::new();
    *RESOLVED.get_or_init(|| {
        // SAFETY: a literal NUL-terminated module name; System32 only.
        let module = unsafe {
            LoadLibraryExW(
                w!("ntdll.dll"),
                HANDLE::default(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        }
        .ok()?;
        // SAFETY: a valid module handle and a literal NUL-terminated export name.
        let proc = unsafe { GetProcAddress(module, s!("NtQueryInformationProcess")) }?;
        // SAFETY: the export's documented signature is `NTSTATUS
        // NtQueryInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG,
        // PULONG)`, which this type spells (NTSTATUS is an i32, the class a
        // u32 enum).
        Some(unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, NtQueryInformationProcessFn>(
                proc,
            )
        })
    })
}

/// An open process handle, closed on drop.
pub struct OpenedProcess {
    handle: HANDLE,
    can_read_memory: bool,
}

impl OpenedProcess {
    /// `pid` with query rights, and memory read rights where granted.
    pub fn open(pid: u32) -> Option<Self> {
        if pid == 0 {
            return None;
        }
        if let Some(handle) = open_with(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ) {
            return Some(Self {
                handle,
                can_read_memory: true,
            });
        }
        open_with(pid, PROCESS_QUERY_LIMITED_INFORMATION).map(|handle| Self {
            handle,
            can_read_memory: false,
        })
    }
}

impl Drop for OpenedProcess {
    fn drop(&mut self) {
        // SAFETY: opened by `open_with` and not used after this.
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

fn open_with(pid: u32, rights: PROCESS_ACCESS_RIGHTS) -> Option<HANDLE> {
    // SAFETY: plain rights on a pid; the caller closes the handle.
    let handle = unsafe { OpenProcess(rights, FALSE, pid) }.ok()?;
    (!handle.is_invalid()).then_some(handle)
}

/// When `pid` was created, in `FILETIME` ticks.
pub fn creation_ticks(pid: u32) -> Option<u64> {
    let handle = open_with(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
    let process = OpenedProcess {
        handle,
        can_read_memory: false,
    };
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: a query handle and four FILETIMEs that outlive the call.
    unsafe {
        GetProcessTimes(
            process.handle,
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    }
    .ok()?;
    Some((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

/// The command line `process` holds.
pub fn command_line(process: &OpenedProcess) -> Option<String> {
    let query = nt_query_information_process()?;
    // `u64` words keep the header's pointer aligned.
    let mut words: Vec<u64> = vec![0; FIRST_COMMAND_LINE_BUFFER / 8];
    loop {
        let bytes = words.len() * 8;
        let mut needed: u32 = 0;
        // SAFETY: `words` is a writable buffer of `bytes` bytes and `needed`
        // a fresh out-parameter; the handle has query rights.
        let status = unsafe {
            query(
                process.handle,
                PROCESS_COMMAND_LINE_INFORMATION,
                words.as_mut_ptr().cast(),
                u32::try_from(bytes).ok()?,
                &mut needed,
            )
        };
        if matches!(
            status,
            STATUS_INFO_LENGTH_MISMATCH | STATUS_BUFFER_TOO_SMALL | STATUS_BUFFER_OVERFLOW
        ) {
            let needed = needed as usize;
            if needed <= bytes || needed > MAX_COMMAND_LINE_BUFFER {
                return None;
            }
            words.resize(needed.div_ceil(8), 0);
            continue;
        }
        if status < 0 {
            return None;
        }
        let base = words.as_ptr() as usize;
        let raw: Vec<u8> = words.iter().flat_map(|w| w.to_ne_bytes()).collect();
        return unicode_string_in(&raw, base);
    }
}

/// The text of the `UNICODE_STRING` heading `raw`, whose buffer the kernel
/// placed inside `raw` itself (`raw` was at address `base` when it did).
fn unicode_string_in(raw: &[u8], base: usize) -> Option<String> {
    let length = usize::from(u16::from_ne_bytes([*raw.first()?, *raw.get(1)?]));
    let pointer = read_usize(raw.get(UNICODE_STRING_BUFFER_AT..UNICODE_STRING_BYTES)?)?;
    let offset = pointer.checked_sub(base)?;
    let text = raw.get(offset..offset.checked_add(length)?)?;
    Some(utf16le(text))
}

/// The working folder of `process`, from its parameters block.
#[cfg(target_pointer_width = "64")]
pub fn current_directory(process: &OpenedProcess) -> Option<String> {
    /// `PEB::ProcessParameters` and `RTL_USER_PROCESS_PARAMETERS::
    /// CurrentDirectory.DosPath`, in a 64-bit process.
    const PEB_PROCESS_PARAMETERS: usize = 0x20;
    const PARAMETERS_CURRENT_DIRECTORY: usize = 0x38;
    if !process.can_read_memory {
        return None;
    }
    let query = nt_query_information_process()?;
    // PROCESS_BASIC_INFORMATION: the PEB address is its second word.
    let mut info = [0u64; 6];
    let mut needed: u32 = 0;
    // SAFETY: `info` is a writable 48-byte buffer, the structure's size.
    let status = unsafe {
        query(
            process.handle,
            PROCESS_BASIC_INFORMATION_CLASS,
            info.as_mut_ptr().cast(),
            48,
            &mut needed,
        )
    };
    if status < 0 {
        return None;
    }
    let peb = usize::try_from(info[1]).ok()?;
    let mut word = [0u8; 8];
    read_memory(process, peb.checked_add(PEB_PROCESS_PARAMETERS)?, &mut word)?;
    let parameters = usize::try_from(u64::from_ne_bytes(word)).ok()?;
    let mut dos_path = [0u8; 16];
    read_memory(
        process,
        parameters.checked_add(PARAMETERS_CURRENT_DIRECTORY)?,
        &mut dos_path,
    )?;
    let length = usize::from(u16::from_ne_bytes([dos_path[0], dos_path[1]]));
    if length == 0 || length > 32_767 * 2 {
        return None;
    }
    let mut pointer = [0u8; 8];
    pointer.copy_from_slice(&dos_path[8..16]);
    let buffer = usize::try_from(u64::from_ne_bytes(pointer)).ok()?;
    let mut text = vec![0u8; length];
    read_memory(process, buffer, &mut text)?;
    Some(utf16le(&text))
}

#[cfg(not(target_pointer_width = "64"))]
pub fn current_directory(_process: &OpenedProcess) -> Option<String> {
    None
}

/// Fills `out` from `address` in `process`; `None` unless all of it was read.
#[cfg(target_pointer_width = "64")]
fn read_memory(process: &OpenedProcess, address: usize, out: &mut [u8]) -> Option<()> {
    let mut read: usize = 0;
    // SAFETY: `out` is a writable buffer of `out.len()` bytes. `address` is in
    // the other process and is read by the kernel, never dereferenced here.
    unsafe {
        ReadProcessMemory(
            process.handle,
            address as *const c_void,
            out.as_mut_ptr().cast(),
            out.len(),
            Some(&mut read as *mut usize),
        )
    }
    .ok()?;
    (read == out.len()).then_some(())
}

fn read_usize(bytes: &[u8]) -> Option<usize> {
    const WORD: usize = std::mem::size_of::<usize>();
    let word: [u8; WORD] = bytes.get(..WORD)?.try_into().ok()?;
    Some(usize::from_ne_bytes(word))
}

fn utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_is_read_back() {
        let pid = std::process::id();
        let process = OpenedProcess::open(pid).expect("own process");
        let line = command_line(&process).expect("own command line");
        let exe = std::env::current_exe().expect("exe");
        let name = exe.file_stem().and_then(|n| n.to_str()).expect("name");
        assert!(line.contains(name), "{line}");
        let cwd = current_directory(&process).expect("own working folder");
        let here = std::env::current_dir().expect("cwd");
        assert_eq!(
            std::fs::canonicalize(&cwd).ok(),
            std::fs::canonicalize(&here).ok(),
            "{cwd}"
        );
        assert!(creation_ticks(pid).is_some());
        assert_eq!(creation_ticks(pid), creation_ticks(pid));
    }

    #[test]
    fn a_header_pointing_outside_its_buffer_reads_as_nothing() {
        let mut raw = vec![0u8; 64];
        raw[0] = 4;
        let base = 0x1000usize;
        raw[UNICODE_STRING_BUFFER_AT..UNICODE_STRING_BYTES]
            .copy_from_slice(&(base + 32).to_ne_bytes());
        raw[32..36].copy_from_slice(&[b'o', 0, b'k', 0]);
        assert_eq!(unicode_string_in(&raw, base).as_deref(), Some("ok"));
        raw[UNICODE_STRING_BUFFER_AT..UNICODE_STRING_BYTES]
            .copy_from_slice(&(base + 62).to_ne_bytes());
        assert_eq!(unicode_string_in(&raw, base), None);
        raw[UNICODE_STRING_BUFFER_AT..UNICODE_STRING_BYTES]
            .copy_from_slice(&(base - 8).to_ne_bytes());
        assert_eq!(unicode_string_in(&raw, base), None);
        assert_eq!(unicode_string_in(&[1, 0], base), None);
    }

    #[test]
    fn pid_zero_and_a_gone_process_are_not_opened() {
        assert!(OpenedProcess::open(0).is_none());
        assert_eq!(creation_ticks(0), None);
    }
}
