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

#[cfg(windows)]
mod imp {
    pub use nrr_platform_windows::machine_environment::machine_environment;
}

#[cfg(not(windows))]
mod imp {
    use std::collections::BTreeMap;

    /// The variables the Windows build forwards; no per-user override of the
    /// machine environment exists here to defend against.
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

    pub fn machine_environment() -> BTreeMap<String, String> {
        FORWARDED
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
        let mut cmd = std::process::Command::new("cmd");
        cmd.env("NRR_TEST_USER_POISON", "1");
        apply_machine_environment(&mut cmd);
        let carried: Vec<_> = cmd
            .get_envs()
            .filter_map(|(k, v)| v.map(|_| k.to_string_lossy().into_owned()))
            .collect();
        assert!(!carried.iter().any(|k| k == "NRR_TEST_USER_POISON"));
    }
}
