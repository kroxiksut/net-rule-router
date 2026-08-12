//! `FwpmGetAppIdFromFileName0` filename → NT-path
//! conversion for `FWPM_CONDITION_ALE_APP_ID`.
//!
//! WFP's app-id condition does **not** accept user-facing paths
//! (`C:\Path\app.exe`). It expects an NT-format byte blob produced
//! by the helper `FwpmGetAppIdFromFileName0`, which:
//!
//! 1. Verifies the file exists (returns `ERROR_FILE_NOT_FOUND` if not).
//! 2. Resolves any reparse points / junctions.
//! 3. Converts the result to a `\\Device\\HarddiskVolumeN\\…\\app.exe`
//!    NT path encoded as a null-terminated UTF-16 byte buffer.
//! 4. Allocates a `FWP_BYTE_BLOB` whose `data` is a pointer to that
//!    buffer.
//!
//! The caller owns the returned blob and must release it via
//! `FwpmFreeMemory0`. We copy `data[..size]` into an owned `Vec<u8>`
//! and free immediately — the resulting bytes are then handed to
//! `FWPM_CONDITION_ALE_APP_ID` filters at add time.
//!
//! `FwpmGetAppIdFromFileName0` opens the target file to resolve it, and
//! self-protecting software (antivirus self-defense: Kaspersky, Dr.Web,
//! ESET and the like) denies that open with `ERROR_ACCESS_DENIED` even
//! for read — leaving the per-app rule silently un-materializable. For
//! that case [`app_id_from_path`] falls back to deriving the NT path
//! without touching the file: the drive letter is mapped to its device
//! name via `QueryDosDeviceW` and the remainder of the path is appended
//! lowercased, matching the helper's own output format. The fallback
//! skips the helper's reparse-point resolution, which is acceptable for
//! the plainly-installed executables self-defense guards.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::{Component, Path, Prefix};

use windows::core::PCWSTR;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FWP_BYTE_BLOB,
};
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;

use crate::error::PlatformError;

const OPERATION: &str = "FwpmGetAppIdFromFileName0";
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_SHARING_VIOLATION: u32 = 32;

/// Resolve a Win32 file path into the NT-format byte blob expected by
/// `FWPM_CONDITION_ALE_APP_ID`.
///
/// Returns the blob bytes (variable length, ends with a wide NUL).
/// Errors map straight from the Win32 status code; common cases:
/// - `ERROR_FILE_NOT_FOUND` (2) — path doesn't exist on disk.
/// - `ERROR_ACCESS_DENIED` (5) — process lacks rights on the file. For
///   drive-letter paths this is retried via the no-open fallback above.
pub fn app_id_from_path(path: &Path) -> Result<Vec<u8>, PlatformError> {
    let primary = app_id_via_helper(path);
    if let Err(PlatformError::Win32 { code, .. }) = &primary {
        if matches!(*code, ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION) {
            if let Some(blob) = app_id_without_opening(path) {
                tracing::info!(
                    target: "nrr::wfp",
                    path = %path.display(),
                    code = *code,
                    "app-id derived without opening the executable (open denied — likely self-protected software)",
                );
                return Ok(blob);
            }
        }
    }
    // Unrecoverable (or fallback inapplicable): surface the helper's own
    // error so the apply layer still classifies the filter as
    // un-materializable and skips it under the best-effort policy.
    primary
}

fn app_id_via_helper(path: &Path) -> Result<Vec<u8>, PlatformError> {
    // Encode path as a null-terminated UTF-16 buffer for PCWSTR.
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);

    let mut blob_ptr: *mut FWP_BYTE_BLOB = std::ptr::null_mut();

    // SAFETY: `wide` is a valid null-terminated UTF-16 string; PCWSTR
    // wraps the pointer without taking ownership. `blob_ptr` is null
    // until Win32 writes a heap-owned `FWP_BYTE_BLOB*` on success.
    let code = unsafe { FwpmGetAppIdFromFileName0(PCWSTR(wide.as_ptr()), &mut blob_ptr) };
    if code != 0 {
        return Err(PlatformError::Win32 {
            operation: OPERATION,
            code,
            message: format!("Win32 error 0x{code:08X} for path {:?}", path),
        });
    }
    if blob_ptr.is_null() {
        return Err(PlatformError::Win32 {
            operation: OPERATION,
            code: 0,
            message: format!("null blob returned for path {:?}", path),
        });
    }

    // SAFETY: `blob_ptr` is non-null and points at a Win32-allocated
    // `FWP_BYTE_BLOB`. We read the header to learn `data` and `size`.
    let header = unsafe { *blob_ptr };
    let degenerate = header.data.is_null() || header.size == 0;
    let bytes: Vec<u8> = if degenerate {
        Vec::new()
    } else {
        // SAFETY: Win32 contract — `data` is valid for `size` bytes
        // until `FwpmFreeMemory0` releases the allocation.
        let slice = unsafe { std::slice::from_raw_parts(header.data, header.size as usize) };
        slice.to_vec()
    };

    // SAFETY: pointer was allocated by `FwpmGetAppIdFromFileName0`;
    // `FwpmFreeMemory0` is the matching deallocator. After this call
    // `blob_ptr` and the buffer it pointed at are dangling, but we no
    // longer use either.
    let mut as_void: *mut c_void = blob_ptr.cast();
    unsafe { FwpmFreeMemory0(&mut as_void) };

    // A zero-length / null app-id blob is NOT a success: handing it to
    // `FWPM_CONDITION_ALE_APP_ID` builds a degenerate condition that
    // `FwpmFilterAdd0` rejects with `FWP_E_CONDITION_NOT_FOUND`
    // (0x80320002), which — under the strict apply policy — rolls back
    // the user's ENTIRE revision. Surface it as a Win32 error in the
    // same `FwpmGetAppIdFromFileName0` family as "file not found" so the
    // apply layer treats the app rule as un-materializable (skip in
    // best-effort, abort in strict) instead of building an invalid
    // filter. `ERROR_INVALID_DATA` (13) is the closest fit.
    if bytes.is_empty() {
        return Err(PlatformError::Win32 {
            operation: OPERATION,
            code: 13, // ERROR_INVALID_DATA
            message: format!("empty app-id blob returned for path {:?}", path),
        });
    }

    Ok(bytes)
}

/// Derive the app-id blob for a drive-letter path without opening the
/// file: `C:\Dir\app.exe` → `\device\harddiskvolumeN\dir\app.exe` as a
/// null-terminated UTF-16LE byte buffer.
///
/// Returns `None` when the path shape is unsupported (no drive-letter
/// prefix — UNC and relative paths keep the helper's original error) or
/// the drive letter has no NT device mapping.
///
/// The output mirrors `FwpmGetAppIdFromFileName0`: the helper lowercases
/// the whole NT path (verified by the `fallback_matches_helper_output`
/// test against the live helper). Lowercasing is per-`char`, applied only
/// when it maps 1:1 so multi-char expansions never distort the path.
fn app_id_without_opening(path: &Path) -> Option<Vec<u8>> {
    let mut components = path.components();
    let drive = match components.next()? {
        Component::Prefix(p) => match p.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => letter,
            _ => return None,
        },
        _ => return None,
    };

    let device = nt_device_for_drive(drive)?;

    // Re-assemble the remainder of the path (everything after `C:\`).
    let mut nt_path = device;
    for component in components {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => {
                nt_path.push('\\');
                nt_path.extend(
                    char::decode_utf16(part.encode_wide()).map(|unit| match unit {
                        Ok(c) => lowercase_1to1(c),
                        // Unpaired surrogate — leave a replacement char; the
                        // helper would have failed on such a name anyway.
                        Err(_) => char::REPLACEMENT_CHARACTER,
                    }),
                );
            }
            // `.` / `..` never appear in the resolved rule paths the
            // codegen hands us; refuse rather than mis-derive.
            _ => return None,
        }
    }

    let mut bytes: Vec<u8> = Vec::with_capacity((nt_path.len() + 1) * 2);
    for unit in nt_path.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.extend_from_slice(&[0, 0]);
    Some(bytes)
}

/// Map a drive letter (`b'C'`) to its NT device name
/// (`\device\harddiskvolumeN`, lowercased), via `QueryDosDeviceW`.
fn nt_device_for_drive(letter: u8) -> Option<String> {
    let dos_name: Vec<u16> = [letter as u16, u16::from(b':'), 0].to_vec();
    // MSDN sizes device names well under MAX_PATH; 512 covers the
    // multi-string result (first entry is the current mapping).
    let mut buffer = [0u16; 512];
    // SAFETY: `dos_name` is a valid null-terminated UTF-16 string and
    // `buffer` is a writable array whose length is passed alongside.
    let written = unsafe { QueryDosDeviceW(PCWSTR(dos_name.as_ptr()), Some(&mut buffer)) };
    if written == 0 {
        return None;
    }
    let first_len = buffer.iter().position(|&u| u == 0)?;
    if first_len == 0 {
        return None;
    }
    let device: String = char::decode_utf16(buffer[..first_len].iter().copied())
        .map(|unit| match unit {
            Ok(c) => lowercase_1to1(c),
            Err(_) => char::REPLACEMENT_CHARACTER,
        })
        .collect();
    // Substed / network drives map to `\??\…` or the redirector — a blob
    // built on those never matches the kernel's volume-based app-id.
    device.starts_with("\\device\\").then_some(device)
}

/// Map an NT-device process path (`\device\harddiskvolumeN\dir\app.exe` — the
/// form a WFP app-id decodes to) back to a Win32 drive-letter path
/// (`C:\dir\app.exe`), via `QueryDosDeviceW` over the mounted drive letters.
///
/// The inverse of the app-id derivation above: connection observations sourced
/// from WFP events carry the kernel's NT-device form, but every consumer that
/// re-enters the enforcement layer (learned VPN-client app exemptions) needs
/// the Win32 form `FwpmGetAppIdFromFileName0` accepts. A path that already
/// carries a drive letter (ETW-sourced observations) is returned as-is.
/// Returns `None` when no mounted drive maps to the path's device prefix
/// (unmounted volume, UNC redirector, malformed input) — the caller must then
/// skip rather than guess.
pub fn win32_path_from_nt_path(path: &str) -> Option<std::path::PathBuf> {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Some(std::path::PathBuf::from(path));
    }
    let mut mappings: Vec<(String, u8)> = Vec::new();
    for letter in b'A'..=b'Z' {
        if let Some(device) = nt_device_for_drive(letter) {
            mappings.push((device, letter));
        }
    }
    map_device_prefix(path, &mappings).map(std::path::PathBuf::from)
}

/// Pure half of [`win32_path_from_nt_path`]: substitute the longest matching
/// `(nt device prefix → drive letter)` mapping. Prefixes in `mappings` are
/// expected lowercased (as [`nt_device_for_drive`] yields them); the match is
/// case-insensitive and must fall on a `\` component boundary so
/// `\device\harddiskvolume1x\...` never matches `harddiskvolume1`. Longest
/// prefix wins, so a nested device name cannot mis-map.
fn map_device_prefix(path: &str, mappings: &[(String, u8)]) -> Option<String> {
    let lower = path.to_ascii_lowercase();
    let mut best: Option<(usize, u8)> = None;
    for (device, letter) in mappings {
        if lower.starts_with(device.as_str())
            && lower.as_bytes().get(device.len()) == Some(&b'\\')
            && best.is_none_or(|(len, _)| device.len() > len)
        {
            best = Some((device.len(), *letter));
        }
    }
    let (prefix_len, letter) = best?;
    Some(format!("{}:{}", letter as char, &path[prefix_len..]))
}

/// Lowercase a char only when the mapping is 1:1, mirroring the kernel's
/// per-code-unit case folding (`RtlDowncaseUnicodeString` never changes
/// string length).
fn lowercase_1to1(c: char) -> char {
    let mut lowered = c.to_lowercase();
    match (lowered.next(), lowered.next()) {
        (Some(single), None) => single,
        _ => c,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: every Windows host has `C:\Windows\System32\kernel32.dll`.
    /// The helper must resolve it without admin rights.
    #[test]
    fn app_id_from_path_resolves_kernel32() {
        let path = Path::new(r"C:\Windows\System32\kernel32.dll");
        let blob = app_id_from_path(path).expect("kernel32.dll must resolve");
        assert!(!blob.is_empty(), "blob must contain wide NT path bytes");
        // NT paths begin with `\Device\HarddiskVolumeN\...`. The blob is
        // a UTF-16 null-terminated string; check the first wide char is
        // a backslash (`\\` = 0x005C 0x0000 in little-endian).
        assert_eq!(blob[0], 0x5C, "NT path must start with backslash");
        assert_eq!(blob[1], 0x00, "wide encoding: high byte zero for ASCII");
    }

    /// Non-existent path → Win32 returns either `ERROR_FILE_NOT_FOUND`
    /// (`2`) when the parent directory exists but the file does not,
    /// or `ERROR_PATH_NOT_FOUND` (`3`) when an intermediate directory
    /// is missing. We accept both — both are "no such executable".
    #[test]
    fn app_id_from_path_rejects_missing_file() {
        let path = Path::new(r"C:\Definitely\Does\Not\Exist\nrr-test.exe");
        let err = app_id_from_path(path).expect_err("missing file must error");
        match err {
            PlatformError::Win32 { code, .. } => {
                assert!(
                    code == 2 || code == 3,
                    "expected ERROR_FILE_NOT_FOUND (2) or ERROR_PATH_NOT_FOUND (3), got {code}"
                );
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    /// The no-open fallback must produce byte-identical blobs to the live
    /// helper — otherwise its filters would silently never match. Uses a
    /// mixed-case input to prove the lowercasing matches too.
    #[test]
    fn fallback_matches_helper_output() {
        let path = Path::new(r"C:\Windows\System32\Kernel32.DLL");
        let helper = app_id_via_helper(path).expect("kernel32.dll must resolve via helper");
        let fallback = app_id_without_opening(path).expect("fallback must handle a C:\\ path");
        assert_eq!(
            helper,
            fallback,
            "fallback blob must be byte-identical to FwpmGetAppIdFromFileName0 output\nhelper:   {}\nfallback: {}",
            String::from_utf16_lossy(
                &helper.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>()
            ),
            String::from_utf16_lossy(
                &fallback.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>()
            ),
        );
    }

    /// Unsupported path shapes must decline (→ caller keeps the helper's
    /// original error) instead of fabricating a non-matching blob.
    #[test]
    fn fallback_declines_unc_and_relative_paths() {
        assert!(app_id_without_opening(Path::new(r"\\server\share\app.exe")).is_none());
        assert!(app_id_without_opening(Path::new(r"relative\app.exe")).is_none());
    }

    /// Live round-trip: derive kernel32's NT path via the helper blob, then
    /// map it back to a drive-letter path. The result must name the same file
    /// (case-insensitively — the helper lowercases the NT form).
    #[test]
    fn win32_path_from_nt_path_round_trips_kernel32() {
        let original = r"C:\Windows\System32\kernel32.dll";
        let blob = app_id_via_helper(Path::new(original)).expect("kernel32 must resolve");
        let units: Vec<u16> = blob
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .collect();
        let nt = String::from_utf16_lossy(&units);
        assert!(
            nt.starts_with(r"\device\"),
            "helper yields an NT path: {nt}"
        );
        let back = win32_path_from_nt_path(&nt).expect("mounted volume must map back");
        assert!(
            back.to_string_lossy().eq_ignore_ascii_case(original),
            "round trip must reproduce the drive-letter path (got {back:?})"
        );
        assert!(back.is_file(), "the mapped path must exist on disk");
    }

    #[test]
    fn win32_path_from_nt_path_passes_drive_letter_paths_through() {
        let p = r"C:\Apps\client.exe";
        assert_eq!(
            win32_path_from_nt_path(p),
            Some(std::path::PathBuf::from(p))
        );
    }

    #[test]
    fn win32_path_from_nt_path_declines_unmapped_devices() {
        assert!(win32_path_from_nt_path(r"\device\nrr-no-such-volume-999\x.exe").is_none());
        assert!(win32_path_from_nt_path(r"\\server\share\app.exe").is_none());
        assert!(win32_path_from_nt_path("").is_none());
    }

    /// Pure prefix substitution: longest device prefix wins, boundaries are
    /// respected, and the suffix keeps its original casing.
    #[test]
    fn map_device_prefix_matches_longest_on_component_boundary() {
        let mappings = vec![
            (r"\device\harddiskvolume1".to_string(), b'C'),
            (r"\device\harddiskvolume12".to_string(), b'D'),
        ];
        assert_eq!(
            map_device_prefix(r"\device\harddiskvolume12\Dir\App.exe", &mappings),
            Some(r"D:\Dir\App.exe".to_string()),
            "longest prefix wins"
        );
        assert_eq!(
            map_device_prefix(r"\DEVICE\HardDiskVolume1\a.exe", &mappings),
            Some(r"C:\a.exe".to_string()),
            "match is case-insensitive; suffix keeps its casing"
        );
        assert_eq!(
            map_device_prefix(r"\device\harddiskvolume1x\a.exe", &mappings),
            None,
            "no match off a component boundary"
        );
        assert_eq!(
            map_device_prefix(r"\device\harddiskvolume1", &mappings),
            None
        );
    }
}
