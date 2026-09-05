//! Absolute path of the system PowerShell.

/// The bare name resolves through the process search path, which on Windows
/// includes the current directory. Callers here run as LocalSystem (the DNS
/// redirect) or raise a UAC prompt (the relaunch), so which binary answers to
/// the name is not a detail. `%SystemRoot%` names the one Windows means.
pub(crate) fn system_powershell() -> std::path::PathBuf {
    match std::env::var_os("SystemRoot") {
        Some(root) => std::path::PathBuf::from(root)
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe"),
        None => std::path::PathBuf::from("powershell.exe"),
    }
}
