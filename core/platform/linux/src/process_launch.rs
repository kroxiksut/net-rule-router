//! Linux mechanism behind [`ProcessLaunchReader`]: how another process was
//! started, from procfs.
//!
//! `cmdline` gives the arguments, the `cwd` link the working folder, field 22
//! of `stat` the start time that tells a reused pid apart, and `environ` the
//! class path of a Java main class. The daemon reads these for processes any
//! user started, and the process wrote all of them itself: every read is
//! bounded, and a failure reads as "nothing to say".

use std::io::Read;
use std::path::Path;

use nrr_platform_api::process_launch::{
    environ_value, split_nul_args, ProcessLaunch, ProcessLaunchReader, MAX_COMMAND_LINE_BYTES,
    MAX_ENVIRON_BYTES,
};

/// `stat` is one line of a few hundred bytes; a longer one is not read.
const MAX_STAT_BYTES: usize = 4096;

/// The live process table under `/proc`.
#[derive(Debug, Default)]
pub struct LinuxProcessLaunches;

impl ProcessLaunchReader for LinuxProcessLaunches {
    fn start_stamp(&self, pid: u32) -> Option<u64> {
        start_stamp_in(Path::new("/proc"), pid)
    }

    fn launch(&self, pid: u32) -> Option<ProcessLaunch> {
        launch_in(Path::new("/proc"), pid)
    }

    fn class_path(&self, pid: u32) -> Option<String> {
        class_path_in(Path::new("/proc"), pid)
    }

    fn runs_by_itself(&self, path: &str) -> bool {
        runs_by_itself(Path::new(path))
    }
}

fn start_stamp_in(root: &Path, pid: u32) -> Option<u64> {
    if pid == 0 {
        return None;
    }
    let stat = read_capped(&root.join(pid.to_string()).join("stat"), MAX_STAT_BYTES)?;
    start_ticks(&String::from_utf8_lossy(&stat))
}

fn launch_in(root: &Path, pid: u32) -> Option<ProcessLaunch> {
    if pid == 0 {
        return None;
    }
    let dir = root.join(pid.to_string());
    let cmdline = read_capped(&dir.join("cmdline"), MAX_COMMAND_LINE_BYTES)?;
    let cwd = std::fs::read_link(dir.join("cwd"))
        .ok()
        .and_then(|link| link.to_str().map(str::to_owned));
    Some(ProcessLaunch {
        args: split_nul_args(&cmdline),
        raw: None,
        cwd,
    })
}

fn class_path_in(root: &Path, pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    let environ = read_capped(
        &root.join(pid.to_string()).join("environ"),
        MAX_ENVIRON_BYTES,
    )?;
    environ_value(&environ, "CLASSPATH")
}

/// Field 22 of a `stat` line. The program name in field 2 is the process's
/// own choice and may hold spaces and `)`, so the fields are counted from the
/// last `)`.
fn start_ticks(stat: &str) -> Option<u64> {
    let close = stat.rfind(')')?;
    stat.get(close + 1..)?
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

/// A regular file with an execute bit or a `#!` line. Opened without blocking
/// and never as a controlling terminal: the path is in a folder its owner
/// writes, and what sits there may change between the look and the open.
fn runs_by_itself(path: &Path) -> bool {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    if meta.permissions().mode() & 0o111 != 0 {
        return true;
    }
    let Ok(file) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
    else {
        return false;
    };
    if !file.metadata().is_ok_and(|m| m.is_file()) {
        return false;
    }
    let mut head = [0u8; 2];
    file.take(2).read_exact(&mut head).is_ok() && head == *b"#!"
}

/// At most `cap` bytes of `path`; `None` when it cannot be read.
fn read_capped(path: &Path, cap: usize) -> Option<Vec<u8>> {
    let file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(cap).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .ok()?;
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn stat_line(pid: u32, comm: &str, start: u64) -> String {
        format!("{pid} ({comm}) S 1 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 {start} 0 0\n")
    }

    fn fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let proc_dir = dir.path().join("41");
        std::fs::create_dir(&proc_dir).expect("pid dir");
        std::fs::write(proc_dir.join("stat"), stat_line(41, "py) S 9 9 (x", 777)).expect("stat");
        std::fs::write(
            proc_dir.join("cmdline"),
            b"python3\0-u\0/opt/tools/sync.py\0",
        )
        .expect("cmdline");
        std::fs::write(
            proc_dir.join("environ"),
            b"HOME=/home/u\0CLASSPATH=/opt/tools/lib/*\0",
        )
        .expect("environ");
        std::os::unix::fs::symlink("/opt/tools", proc_dir.join("cwd")).expect("cwd");
        dir
    }

    #[test]
    fn a_process_is_read_from_its_procfs_entry() {
        let dir = fixture();
        assert_eq!(start_stamp_in(dir.path(), 41), Some(777));
        let launch = launch_in(dir.path(), 41).expect("launch");
        assert_eq!(launch.args, vec!["python3", "-u", "/opt/tools/sync.py"]);
        assert_eq!(launch.cwd.as_deref(), Some("/opt/tools"));
        assert_eq!(
            class_path_in(dir.path(), 41).as_deref(),
            Some("/opt/tools/lib/*")
        );
        assert_eq!(start_stamp_in(dir.path(), 42), None);
        assert!(launch_in(dir.path(), 42).is_none());
        assert_eq!(start_stamp_in(dir.path(), 0), None);
    }

    #[test]
    fn a_start_time_is_counted_past_a_hostile_program_name() {
        assert_eq!(start_ticks(&stat_line(1, ") ) ) 1 2 3", 55)), Some(55));
        assert_eq!(start_ticks("1 (x) S"), None);
        assert_eq!(start_ticks(""), None);
        assert_eq!(start_ticks(&"9".repeat(MAX_STAT_BYTES)), None);
    }

    #[test]
    fn only_a_regular_file_with_the_bit_or_a_shebang_runs_by_itself() {
        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("tool");
        std::fs::write(&script, b"#!/bin/sh\necho\n").expect("write");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o644)).expect("mode");
        assert!(runs_by_itself(&script));
        let binary = dir.path().join("bin");
        std::fs::write(&binary, b"\x7fELF").expect("write");
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).expect("mode");
        assert!(runs_by_itself(&binary));
        let notes = dir.path().join("notes");
        std::fs::write(&notes, b"plain text").expect("write");
        std::fs::set_permissions(&notes, std::fs::Permissions::from_mode(0o644)).expect("mode");
        assert!(!runs_by_itself(&notes));
        assert!(!runs_by_itself(dir.path()));
        assert!(!runs_by_itself(&dir.path().join("missing")));
    }
}
