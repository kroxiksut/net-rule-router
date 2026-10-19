//! Windows mechanism behind [`ProcessLaunchReader`]: how another process was
//! started.
//!
//! The command line and working folder come from the process itself (see
//! `win32_ffi::process_launch`), the start time from `GetProcessTimes`. A
//! process's environment is not read, so a Java main class found only
//! through `CLASSPATH` is not recognised here. Windows has no execute bit: a
//! file without a script extension runs by itself only with a `#!` line,
//! which launchers such as `py.exe` honour.

#![cfg(target_os = "windows")]

use std::io::Read;
use std::path::Path;

use nrr_platform_api::process_launch::{
    split_windows_command_line, ProcessLaunch, ProcessLaunchReader,
};

use crate::win32_ffi::process_launch::{
    command_line, creation_ticks, current_directory, OpenedProcess,
};

/// The running system's processes.
#[derive(Debug, Default)]
pub struct WindowsProcessLaunches;

impl ProcessLaunchReader for WindowsProcessLaunches {
    fn start_stamp(&self, pid: u32) -> Option<u64> {
        creation_ticks(pid)
    }

    fn launch(&self, pid: u32) -> Option<ProcessLaunch> {
        let process = OpenedProcess::open(pid)?;
        let raw = command_line(&process)?;
        Some(ProcessLaunch {
            args: split_windows_command_line(&raw),
            cwd: current_directory(&process),
            raw: Some(raw),
        })
    }

    fn runs_by_itself(&self, path: &str) -> bool {
        starts_with_shebang(Path::new(path))
    }
}

fn starts_with_shebang(path: &Path) -> bool {
    if !std::fs::metadata(path).is_ok_and(|m| m.is_file()) {
        return false;
    }
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut head = [0u8; 2];
    file.take(2).read_exact(&mut head).is_ok() && head == *b"#!"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_is_read_as_it_was_started() {
        let reader = WindowsProcessLaunches;
        let pid = std::process::id();
        let launch = reader.launch(pid).expect("own launch");
        let exe = std::env::current_exe().expect("exe");
        let name = exe.file_stem().and_then(|n| n.to_str()).expect("name");
        assert!(
            launch.args.first().is_some_and(|a| a.contains(name)),
            "{launch:?}"
        );
        assert!(launch.cwd.is_some());
        assert!(reader.start_stamp(pid).is_some());
        assert!(reader.launch(0).is_none());
    }

    #[test]
    fn only_a_file_with_a_shebang_runs_by_itself() {
        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("tool");
        std::fs::write(&script, b"#!/usr/bin/env python3\n").expect("write");
        let binary = dir.path().join("tool.exe");
        std::fs::write(&binary, b"MZ\x90\0").expect("write");
        let reader = WindowsProcessLaunches;
        assert!(reader.runs_by_itself(&script.to_string_lossy()));
        assert!(!reader.runs_by_itself(&binary.to_string_lossy()));
        assert!(!reader.runs_by_itself(&dir.path().to_string_lossy()));
        assert!(!reader.runs_by_itself(r"C:\nowhere\missing"));
    }
}
