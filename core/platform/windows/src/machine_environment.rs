//! The machine-scope environment, for a process elevated on a user's behalf.
//!
//! An elevated process started through UAC inherits the USER's environment,
//! and a user can rewrite that without any administrative right
//! (`HKCU\Environment`). Every path the elevated side then derives from
//! `%PROGRAMDATA%` would be the user's to choose. The machine hive under `HKLM`
//! needs administrative rights to write, so it is the one source an elevated
//! process may believe.
#![allow(unsafe_code)]

use std::collections::BTreeMap;

use windows::core::HSTRING;
use windows::Win32::System::Registry::{
    RegGetValueW, HKEY_LOCAL_MACHINE, RRF_NOEXPAND, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ,
};
use windows::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;

/// Variables an elevated child needs to run at all, plus the roots we derive
/// paths from. Anything not listed here is deliberately not passed on.
pub const FORWARDED: &[&str] = &[
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

const MACHINE_ENVIRONMENT_KEY: &str =
    r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

/// The [`FORWARDED`] variables as the machine sets them.
pub fn machine_environment() -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let roots = MachineRoots::from_api();
    for name in FORWARDED {
        if let Some(text) = machine_value(name).and_then(|raw| roots.expand(name, &raw)) {
            out.insert((*name).to_string(), text);
        }
    }
    // The Windows root, `ProgramData` and the system drive are not in the
    // environment key: the shell composes them at logon, so each is asked of
    // the API instead.
    out.entry("SystemRoot".to_string())
        .or_insert_with(system_directory_root);
    out.entry("windir".to_string())
        .or_insert_with(system_directory_root);
    if let Some(dir) = crate::system_shell::program_data_directory() {
        out.entry("ProgramData".to_string())
            .or_insert_with(|| dir.to_string_lossy().into_owned());
    }
    let drive = out
        .get("SystemRoot")
        .and_then(|root| root.get(..2))
        .map(str::to_owned);
    if let Some(drive) = drive {
        out.entry("SystemDrive".to_string()).or_insert(drive);
    }
    out
}

/// Replaces a child process's environment with the machine-scope one.
/// `env_clear` alone would leave it with no `PATH` and no `SystemRoot`.
pub fn apply_machine_environment(cmd: &mut std::process::Command) {
    cmd.env_clear();
    for (name, value) in machine_environment() {
        cmd.env(name, value);
    }
}

/// The roots a `REG_EXPAND_SZ` machine value may refer to, each taken from
/// the API: the registry's own expansion would use THIS process's
/// environment, which under UAC is the user's, so `%SystemRoot%` in the
/// machine `Path` would point wherever the user said.
struct MachineRoots {
    system_root: String,
    system_drive: Option<String>,
    program_data: Option<String>,
}

impl MachineRoots {
    fn from_api() -> Self {
        let system_root = system_directory_root();
        let system_drive = system_root.get(..2).map(str::to_owned);
        let program_data = crate::system_shell::program_data_directory()
            .map(|dir| dir.to_string_lossy().into_owned());
        Self {
            system_root,
            system_drive,
            program_data,
        }
    }

    fn root(&self, reference: &str) -> Option<&str> {
        if reference.eq_ignore_ascii_case("SystemRoot") || reference.eq_ignore_ascii_case("windir")
        {
            Some(&self.system_root)
        } else if reference.eq_ignore_ascii_case("SystemDrive") {
            self.system_drive.as_deref()
        } else if reference.eq_ignore_ascii_case("ProgramData") {
            self.program_data.as_deref()
        } else {
            None
        }
    }

    /// `value` with every `%root%` replaced. A reference to anything else
    /// cannot be resolved from the machine alone: a `Path` segment holding
    /// one is dropped, any other value is withheld whole.
    fn expand(&self, name: &str, value: &str) -> Option<String> {
        if name.eq_ignore_ascii_case("Path") {
            let kept: Vec<String> = value
                .split(';')
                .filter(|segment| !segment.is_empty())
                .filter_map(|segment| self.expand_one(segment))
                .collect();
            return (!kept.is_empty()).then(|| kept.join(";"));
        }
        self.expand_one(value)
    }

    fn expand_one(&self, value: &str) -> Option<String> {
        let mut out = String::with_capacity(value.len());
        let mut rest = value;
        while let Some(start) = rest.find('%') {
            out.push_str(&rest[..start]);
            let after = &rest[start + 1..];
            let Some(end) = after.find('%') else {
                // A lone `%` is literal text.
                out.push_str(&rest[start..]);
                return Some(out);
            };
            out.push_str(self.root(&after[..end])?);
            rest = &after[end + 1..];
        }
        out.push_str(rest);
        Some(out)
    }
}

/// One value of the machine environment key, unexpanded. Two calls: the first
/// sizes the buffer, the second fills it.
fn machine_value(name: &str) -> Option<String> {
    let subkey = HSTRING::from(MACHINE_ENVIRONMENT_KEY);
    let value = HSTRING::from(name);
    let mut size: u32 = 0;
    // SAFETY: both strings outlive the call; no data buffer is passed, only
    // the size out-parameter.
    let sized = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            &subkey,
            &value,
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND,
            None,
            None,
            Some(&mut size),
        )
    };
    if sized.is_err() || size == 0 {
        return None;
    }
    let mut buffer = vec![0u16; (size as usize).div_ceil(2)];
    // SAFETY: `buffer` holds `size` bytes, the size the first call reported,
    // and `size` tells the API so.
    let read = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            &subkey,
            &value,
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND,
            None,
            Some(buffer.as_mut_ptr().cast()),
            Some(&mut size),
        )
    };
    if read.is_err() {
        return None;
    }
    let len = buffer.iter().position(|c| *c == 0).unwrap_or(buffer.len());
    let text = String::from_utf16_lossy(&buffer[..len]);
    (!text.is_empty()).then_some(text)
}

/// `%SystemRoot%` read from the API rather than the environment.
fn system_directory_root() -> String {
    let mut buffer = [0u16; 260];
    // SAFETY: the API writes at most `buffer.len()` characters into it.
    let len = unsafe { GetSystemWindowsDirectoryW(Some(&mut buffer)) } as usize;
    String::from_utf16_lossy(&buffer[..len.min(buffer.len())])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_child_never_inherits_the_users_environment() {
        let mut cmd = std::process::Command::new("cmd");
        cmd.env("NRR_TEST_USER_POISON", "1");
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

    /// The machine hive names neither; a child without `ProgramData` cannot
    /// resolve the service data root.
    #[test]
    fn program_data_and_system_drive_reach_the_child_even_when_the_hive_lacks_them() {
        let env = machine_environment();
        let program_data = env.get("ProgramData").expect("ProgramData");
        assert!(std::path::Path::new(program_data).is_absolute());
        let drive = env.get("SystemDrive").expect("SystemDrive");
        assert!(drive.len() == 2 && drive.ends_with(':'), "{drive}");
    }

    fn roots() -> MachineRoots {
        MachineRoots {
            system_root: r"C:\WINDOWS".into(),
            system_drive: Some("C:".into()),
            program_data: Some(r"C:\ProgramData".into()),
        }
    }

    /// The registry's own expansion reads this process's environment, which
    /// a user controls; the roots come from the API instead.
    #[test]
    fn machine_references_expand_from_the_api_not_the_environment() {
        let roots = roots();
        assert_eq!(
            roots
                .expand("ComSpec", r"%SystemRoot%\system32\cmd.exe")
                .as_deref(),
            Some(r"C:\WINDOWS\system32\cmd.exe")
        );
        assert_eq!(
            roots
                .expand(
                    "Path",
                    r"%SYSTEMROOT%\system32;%windir%;%ProgramData%\x;C:\Tools"
                )
                .as_deref(),
            Some(r"C:\WINDOWS\system32;C:\WINDOWS;C:\ProgramData\x;C:\Tools")
        );
        assert_eq!(
            roots.expand("OS", "Windows_NT").as_deref(),
            Some("Windows_NT")
        );
        assert_eq!(roots.expand("X", "50%").as_deref(), Some("50%"));
    }

    #[test]
    fn a_reference_the_machine_cannot_resolve_is_dropped_never_taken_from_the_user() {
        let roots = roots();
        assert_eq!(roots.expand("ComSpec", r"%USERPROFILE%\cmd.exe"), None);
        assert_eq!(
            roots
                .expand("Path", r"%SystemRoot%\system32;%JAVA_HOME%\bin;;C:\Tools")
                .as_deref(),
            Some(r"C:\WINDOWS\system32;C:\Tools")
        );
        assert_eq!(roots.expand("Path", r"%JAVA_HOME%\bin"), None);
    }

    #[test]
    fn the_forwarded_machine_values_carry_no_unexpanded_reference() {
        for (name, value) in machine_environment() {
            assert!(!value.contains('%'), "{name}={value}");
        }
    }
}
