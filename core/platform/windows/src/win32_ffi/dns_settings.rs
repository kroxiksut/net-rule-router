//! `SetDnsSettings` — the machine-wide DNS client settings, applied in place.
//!
//! The DNS client picks the new value up itself, which a bare registry write
//! does not achieve, and no child process is involved.

#![allow(unsafe_code)]

use std::sync::OnceLock;

use windows::core::{s, w, PWSTR};
use windows::Win32::Foundation::{HANDLE, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    DNS_SETTINGS, DNS_SETTINGS_VERSION1, DNS_SETTING_SEARCHLIST,
};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

use crate::error::PlatformError;

type SetDnsSettingsFn = unsafe extern "system" fn(*const DNS_SETTINGS) -> WIN32_ERROR;

/// Looked up at run time, never imported: the export exists from Windows 10
/// 2004 on, and a load-time import would stop the service starting on older
/// builds. The module stays loaded for the life of the process.
fn set_dns_settings_fn() -> Option<SetDnsSettingsFn> {
    static RESOLVED: OnceLock<Option<SetDnsSettingsFn>> = OnceLock::new();
    *RESOLVED.get_or_init(|| {
        // SAFETY: a literal NUL-terminated module name; System32 only, so a
        // planted DLL beside the binary is never considered.
        let module = unsafe {
            LoadLibraryExW(
                w!("iphlpapi.dll"),
                HANDLE::default(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        }
        .ok()?;
        // SAFETY: a valid module handle and a literal NUL-terminated export name.
        let proc = unsafe { GetProcAddress(module, s!("SetDnsSettings")) }?;
        // SAFETY: the export's documented signature is
        // `DWORD SetDnsSettings(const DNS_SETTINGS *)`, which this type spells.
        Some(unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, SetDnsSettingsFn>(proc)
        })
    })
}

/// Makes `comma_separated` the global suffix search list; empty clears it.
///
/// `None` when this Windows has no `SetDnsSettings`, so the caller can take
/// the slower route there.
pub fn set_global_search_list(comma_separated: &str) -> Option<Result<(), PlatformError>> {
    let set = set_dns_settings_fn()?;
    let mut list: Vec<u16> = comma_separated
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let settings = DNS_SETTINGS {
        Version: DNS_SETTINGS_VERSION1,
        Flags: u64::from(DNS_SETTING_SEARCHLIST),
        Hostname: PWSTR::null(),
        Domain: PWSTR::null(),
        SearchList: PWSTR(list.as_mut_ptr()),
    };
    // SAFETY: `settings` and the NUL-terminated `list` it points into outlive
    // the call; only the field the flag names is read.
    let code = unsafe { set(&settings) }.0;
    Some(if code == 0 {
        Ok(())
    } else {
        Err(PlatformError::Win32 {
            operation: "dns.search_list.write",
            code,
            message: format!("SetDnsSettings failed: Win32 error {code}"),
        })
    })
}
