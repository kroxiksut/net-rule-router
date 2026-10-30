//! Windows implementation of [`InstallerAgreementPort`].
//!
//! Both installers are per-machine and elevated, so the record lives under
//! HKLM, which only administrators can change: an ordinary account cannot
//! write one naming itself or anyone else. Nothing is read from HKCU.

use nrr_platform_api::installer_agreement::InstallerAgreementPort;
use nrr_shared::eula::InstallerAcceptance;

/// The key both installers write after their licence page, in the 64-bit view.
pub const AGREEMENT_KEY: &str = r"SOFTWARE\NetRuleRouter\Agreement";
/// `REG_DWORD`: the agreement revision the licence page showed.
pub const VERSION_VALUE: &str = "Version";
/// `REG_SZ`: the security identifier of the account the licence page ran as.
pub const ACCEPTED_BY_VALUE: &str = "AcceptedBy";

pub struct WindowsInstallerAgreement;

impl InstallerAgreementPort for WindowsInstallerAgreement {
    fn recorded(&self) -> Option<InstallerAcceptance> {
        #[cfg(windows)]
        {
            let version = machine_dword(AGREEMENT_KEY, VERSION_VALUE)?;
            let account = machine_string(AGREEMENT_KEY, ACCEPTED_BY_VALUE)?;
            InstallerAcceptance::new(version, &account)
        }
        #[cfg(not(windows))]
        {
            None
        }
    }

    fn current_account(&self) -> Option<String> {
        #[cfg(windows)]
        {
            crate::pinned_file::current_user_sid()
        }
        #[cfg(not(windows))]
        {
            None
        }
    }
}

/// A `REG_DWORD` under HKLM's 64-bit view; `None` on any failure or other type.
#[cfg(windows)]
#[allow(unsafe_code)]
fn machine_dword(subkey: &str, value: &str) -> Option<u32> {
    use std::ffi::c_void;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_SUBKEY_WOW6464KEY,
    };

    let subkey_w: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let value_w: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    let mut data: u32 = 0;
    let mut size = std::mem::size_of::<u32>() as u32;
    // SAFETY: NUL-terminated wide pointers outliving the call, and a
    // destination whose declared size matches the u32 passed.
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_w.as_ptr()),
            PCWSTR(value_w.as_ptr()),
            RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY,
            None,
            Some(std::ptr::addr_of_mut!(data).cast::<c_void>()),
            Some(&mut size),
        )
    };
    (rc == ERROR_SUCCESS).then_some(data)
}

/// A `REG_SZ` under HKLM's 64-bit view. Bounded: a value longer than any
/// account identifier fails the read instead of growing a buffer.
#[cfg(windows)]
#[allow(unsafe_code)]
fn machine_string(subkey: &str, value: &str) -> Option<String> {
    use std::ffi::c_void;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY,
    };

    let subkey_w: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let value_w: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    let mut buffer = [0u16; 256];
    let mut size = std::mem::size_of_val(&buffer) as u32;
    // SAFETY: NUL-terminated wide pointers, and a destination whose declared
    // size in bytes matches the buffer passed.
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_w.as_ptr()),
            PCWSTR(value_w.as_ptr()),
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
            None,
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            Some(&mut size),
        )
    };
    if rc != ERROR_SUCCESS {
        return None;
    }
    let units = (size as usize / std::mem::size_of::<u16>()).min(buffer.len());
    let text = String::from_utf16(&buffer[..units]).ok()?;
    Some(text.trim_end_matches('\0').to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packaging(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../packaging/windows")
            .join(name);
        std::fs::read_to_string(&path)
            .expect("a packaging file")
            .replace("\r\n", "\n")
    }

    /// An installer writing another key or value name than this reader reads
    /// would leave every installing person asked again, with nothing failing.
    #[test]
    fn both_installers_write_what_this_reads() {
        let iss = packaging("NetRuleRouter.iss");
        for needle in [AGREEMENT_KEY, VERSION_VALUE, ACCEPTED_BY_VALUE] {
            assert!(
                iss.lines().any(|line| line.starts_with("Root: HKLM64;")
                    && line.contains(&format!("\"{needle}\""))),
                "the EXE installer does not write {needle} under HKLM64"
            );
        }
        let wxs = packaging("NetRuleRouter.wxs");
        assert!(
            wxs.contains(&format!("Root=\"HKLM\" Key=\"{AGREEMENT_KEY}\"")),
            "the MSI does not write {AGREEMENT_KEY} under HKLM"
        );
        assert!(wxs.contains(&format!("Name=\"{VERSION_VALUE}\" Type=\"integer\"")));
        assert!(wxs.contains(&format!("Name=\"{ACCEPTED_BY_VALUE}\" Type=\"string\"")));
    }

    /// The account form this host reports must pass the record's own check, or
    /// an acceptance made in the installer could never be recognised.
    #[cfg(windows)]
    #[test]
    fn this_hosts_account_form_is_one_a_record_can_name() {
        let account = WindowsInstallerAgreement
            .current_account()
            .expect("the process token names its account");
        let record = InstallerAcceptance::new(nrr_shared::eula::CURRENT_EULA_VERSION, &account)
            .unwrap_or_else(|| panic!("{account} is not accepted as an account"));
        assert!(nrr_shared::eula::installer_acceptance_covers(
            Some(&record),
            Some(&account)
        ));
    }
}
