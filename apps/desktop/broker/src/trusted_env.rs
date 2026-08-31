//! Machine-scope environment for the elevated broker.
//!
//! The broker is started through `Start-Process -Verb RunAs`, so the elevated
//! process inherits the USER's environment — and a user can rewrite that
//! without any administrative right (`HKCU\Environment`). Every path the
//! elevated side then derives from `%PROGRAMDATA%` is the user's to choose,
//! including where `install` lays down state and ACLs. The machine hive under
//! `HKLM` needs administrative rights to write, so it is the one source an
//! elevated process may believe.

use std::path::PathBuf;

/// Variables an elevated child needs to run at all, plus the roots we derive
/// paths from. Anything not listed here is deliberately not passed on.
const FORWARDED: &[&str] = &[
    "ProgramData",
    "SystemRoot",
    "windir",
    "SystemDrive",
    "Path",
    "PATHEXT",
    "ComSpec",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
    "OS",
];

#[cfg(windows)]
// Two Win32 reads with no Rust-side alternative: the machine environment hive
// and the Windows directory. Both are read-only and bounded by a caller-owned
// buffer; the crate is where the product's Win32 `unsafe` already lives.
#[allow(unsafe_code)]
mod imp {
    use std::collections::BTreeMap;

    const MACHINE_ENVIRONMENT_KEY: &str =
        r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

    /// Reads the machine-scope environment block from `HKLM`.
    pub fn machine_environment() -> BTreeMap<String, String> {
        use windows::core::HSTRING;
        use windows::Win32::System::Registry::{
            RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ,
        };

        let mut out = BTreeMap::new();
        for name in super::FORWARDED {
            let subkey = HSTRING::from(MACHINE_ENVIRONMENT_KEY);
            let value = HSTRING::from(*name);
            let mut size: u32 = 0;
            // Two calls: the first sizes the buffer, the second fills it.
            let sized = unsafe {
                RegGetValueW(
                    HKEY_LOCAL_MACHINE,
                    &subkey,
                    &value,
                    RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
                    None,
                    None,
                    Some(&mut size),
                )
            };
            if sized.is_err() || size == 0 {
                continue;
            }
            let mut buffer = vec![0u16; (size as usize).div_ceil(2)];
            let read = unsafe {
                RegGetValueW(
                    HKEY_LOCAL_MACHINE,
                    &subkey,
                    &value,
                    RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
                    None,
                    Some(buffer.as_mut_ptr().cast()),
                    Some(&mut size),
                )
            };
            if read.is_err() {
                continue;
            }
            let len = buffer.iter().position(|c| *c == 0).unwrap_or(buffer.len());
            let text = String::from_utf16_lossy(&buffer[..len]);
            if !text.is_empty() {
                out.insert((*name).to_string(), text);
            }
        }
        // `ProgramData` and the Windows root are not in the environment key on
        // every build; both live beside it as fixed system values.
        out.entry("SystemRoot".to_string())
            .or_insert_with(system_directory_root);
        out.entry("windir".to_string())
            .or_insert_with(system_directory_root);
        out
    }

    /// `%SystemRoot%` read from the API rather than the environment.
    fn system_directory_root() -> String {
        use windows::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
        let mut buffer = [0u16; 260];
        let len = unsafe { GetSystemWindowsDirectoryW(Some(&mut buffer)) } as usize;
        String::from_utf16_lossy(&buffer[..len.min(buffer.len())])
    }
}

#[cfg(not(windows))]
mod imp {
    use std::collections::BTreeMap;

    pub fn machine_environment() -> BTreeMap<String, String> {
        // No per-user override of the machine environment to defend against.
        super::FORWARDED
            .iter()
            .filter_map(|name| std::env::var(name).ok().map(|v| ((*name).to_string(), v)))
            .collect()
    }
}

/// `%ProgramData%` as the MACHINE says it is, not as the user's environment
/// claims. `None` when the machine hive does not name it.
pub fn machine_program_data() -> Option<PathBuf> {
    imp::machine_environment()
        .get("ProgramData")
        .map(PathBuf::from)
}

/// Replaces a child process's environment with the machine-scope one.
///
/// `env_clear` on its own would leave the child with nothing — no `PATH`, no
/// `SystemRoot` — so the trusted values go back in explicitly.
pub fn apply_machine_environment(cmd: &mut std::process::Command) {
    cmd.env_clear();
    for (name, value) in imp::machine_environment() {
        cmd.env(name, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_child_never_inherits_the_users_environment() {
        // Set a variable the forwarding list does not name; the child must not
        // see it, whatever the parent's environment holds.
        std::env::set_var("NRR_TEST_USER_POISON", "1");
        let mut cmd = std::process::Command::new("cmd");
        apply_machine_environment(&mut cmd);
        let carried: Vec<_> = cmd
            .get_envs()
            .filter_map(|(k, v)| v.map(|_| k.to_string_lossy().into_owned()))
            .collect();
        assert!(!carried.iter().any(|k| k == "NRR_TEST_USER_POISON"));
        assert!(
            carried.iter().all(|k| FORWARDED.contains(&k.as_str())),
            "only the forwarded set may reach the child: {carried:?}"
        );
    }
}
