//! Running an external program with a budget.
//!
//! Every helper this port shells out to — `loginctl`, `systemctl`, `nft` — was
//! called through `Command::output()`, which waits forever. `live_users()` runs
//! on EVERY enforcement tick, so one `loginctl` blocked on an unreachable D-Bus
//! stopped policy enforcement for good. The same lesson Windows learned from
//! the BFE incident, in the other port.

use std::collections::HashMap;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Where a system tool may live. The inherited `PATH` is never consulted: the
/// console and `pkexec` run with the user's environment, and a directory the
/// user controls ahead of these would run their `systemctl` in our place.
const BIN_FIRST: [&str; 4] = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];

/// Administration tools that distributions put under `sbin`.
const SBIN_FIRST: [&str; 4] = ["/usr/sbin", "/sbin", "/usr/bin", "/bin"];

fn search_order(name: &str) -> &'static [&'static str; 4] {
    match name {
        "ip" | "nft" | "resolvconf" => &SBIN_FIRST,
        _ => &BIN_FIRST,
    }
}

/// The first executable `name` under `root` in the tool's search order.
fn locate_under(root: &Path, name: &str) -> Option<PathBuf> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return None;
    }
    search_order(name)
        .iter()
        .map(|dir| root.join(dir.trim_start_matches('/')).join(name))
        .find(|path| is_executable_file(path))
}

pub(crate) fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.is_file() && meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        meta.is_file()
    }
}

/// The absolute path of the system tool `name`, looked up once per process.
///
/// A miss is not remembered — a package installed later is found on the next
/// call — and fails with the error a spawn of an absent program gives, so
/// callers classify it as they always have.
pub fn system_tool(name: &str) -> io::Result<PathBuf> {
    static FOUND: OnceLock<Mutex<HashMap<String, PathBuf>>> = OnceLock::new();
    let found = FOUND.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(path) = found.lock().unwrap_or_else(|p| p.into_inner()).get(name) {
        return Ok(path.clone());
    }
    let path = locate_under(Path::new("/"), name).ok_or_else(not_found)?;
    found
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(name.to_owned(), path.clone());
    Ok(path)
}

fn not_found() -> io::Error {
    #[cfg(target_os = "linux")]
    {
        io::Error::from_raw_os_error(libc::ENOENT)
    }
    #[cfg(not(target_os = "linux"))]
    {
        io::Error::from(io::ErrorKind::NotFound)
    }
}

/// `exe` as given when absolute — a path the caller located itself — else the
/// system tool of that name.
fn program_path(exe: &str) -> io::Result<PathBuf> {
    if Path::new(exe).is_absolute() {
        Ok(PathBuf::from(exe))
    } else {
        system_tool(exe)
    }
}

/// Default budget for a local helper that answers from kernel or systemd state.
/// Generous for a question that normally returns in milliseconds, short enough
/// that a wedged helper cannot outlive one enforcement tick by much.
pub const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

/// Runs `exe args…` and returns its output, killing it if the budget expires.
/// A bare `exe` is a [`system_tool`]; an absolute one runs as given.
///
/// The environment is forced to the C locale: several callers classify failures
/// by matching English text in `stderr`, and on a localised system a translated
/// "permission denied" turned an access refusal into an unclassified mechanism
/// error.
pub fn output_with_timeout(exe: &str, args: &[&str], timeout: Duration) -> io::Result<Output> {
    run_with_budget(exe, args, None, timeout)
}

/// [`output_with_timeout`] with `input` written to the child's stdin.
pub fn output_with_input(
    exe: &str,
    args: &[&str],
    input: &str,
    timeout: Duration,
) -> io::Result<Output> {
    run_with_budget(exe, args, Some(input.as_bytes().to_vec()), timeout)
}

fn run_with_budget(
    exe: &str,
    args: &[&str],
    input: Option<Vec<u8>>,
    timeout: Duration,
) -> io::Result<Output> {
    let mut child = Command::new(program_path(exe)?)
        .args(args)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // Written on its own thread and then closed: a child that reads its whole
    // input before answering waits for the end of it.
    if let (Some(bytes), Some(mut stdin)) = (input, child.stdin.take()) {
        std::thread::spawn(move || {
            use std::io::Write;
            let _ = stdin.write_all(&bytes);
        });
    }

    // Drained on their own threads: a child that fills a pipe buffer blocks on
    // the write, and a parent that only polls `try_wait` would then wait for a
    // child that is waiting for the parent.
    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();
    let stdout_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(pipe) = stdout_pipe.as_mut() {
            let _ = pipe.read_to_end(&mut buf);
        }
        buf
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(pipe) = stderr_pipe.as_mut() {
            let _ = pipe.read_to_end(&mut buf);
        }
        buf
    });

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{exe} did not answer within {}s", timeout.as_secs()),
                ));
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };

    let stdout = stdout_reader.join().unwrap_or_default();
    let stderr = stderr_reader.join().unwrap_or_default();
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

// The tests spawn POSIX tools (`sh`, `echo`, `sleep`). The crate itself
// compiles everywhere (the WSL2 workflow builds it from a Windows checkout),
// so the Windows gate would otherwise fail on the missing programs.
#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn a_command_that_never_returns_is_killed_at_the_budget() {
        let started = Instant::now();
        let result = output_with_timeout("sleep", &["30"], Duration::from_millis(200));

        assert!(
            result.is_err(),
            "the caller must not wait for a wedged helper"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn output_still_comes_back_whole() {
        let out = output_with_timeout("echo", &["hello"], DEFAULT_COMMAND_TIMEOUT).expect("echo");
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hello");
    }

    #[test]
    fn a_child_that_writes_more_than_a_pipe_buffer_does_not_deadlock() {
        // 1 MiB through the pipe: far past the 64 KiB buffer where a parent
        // that waits before reading would hang.
        let out = output_with_timeout(
            "sh",
            &["-c", "yes hello | head -c 1048576"],
            DEFAULT_COMMAND_TIMEOUT,
        )
        .expect("sh");
        assert_eq!(out.stdout.len(), 1_048_576);
    }

    #[test]
    fn input_reaches_the_child_and_ends() {
        let out = output_with_input(
            "cat",
            &[],
            "nameserver 192.0.2.1
",
            DEFAULT_COMMAND_TIMEOUT,
        )
        .expect("cat");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "nameserver 192.0.2.1
"
        );
    }

    #[test]
    fn the_child_speaks_the_c_locale() {
        // `service_control::classify_command_failure` matches English text in
        // stderr; that only holds if the helper is not localised.
        let out = output_with_timeout("sh", &["-c", "echo $LC_ALL"], DEFAULT_COMMAND_TIMEOUT)
            .expect("sh");
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "C");
    }

    fn place(root: &Path, dir: &str, name: &str, mode: u32) -> io::Result<PathBuf> {
        use std::os::unix::fs::PermissionsExt;
        let dir = root.join(dir);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(name);
        std::fs::write(&path, "#!/bin/sh\n")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
        Ok(path)
    }

    #[test]
    fn an_administration_tool_is_taken_from_sbin_first() {
        let root = tempfile::tempdir().expect("root");
        place(root.path(), "usr/bin", "ip", 0o755).expect("place");
        let sbin = place(root.path(), "usr/sbin", "ip", 0o755).expect("place");
        assert_eq!(locate_under(root.path(), "ip"), Some(sbin));
    }

    #[test]
    fn any_other_tool_is_taken_from_bin_first_then_sbin() {
        let root = tempfile::tempdir().expect("root");
        let usr_bin = place(root.path(), "usr/bin", "systemctl", 0o755).expect("place");
        place(root.path(), "bin", "systemctl", 0o755).expect("place");
        place(root.path(), "usr/sbin", "systemctl", 0o755).expect("place");
        assert_eq!(locate_under(root.path(), "systemctl"), Some(usr_bin));

        let only_sbin = place(root.path(), "sbin", "pkcheck", 0o755).expect("place");
        assert_eq!(locate_under(root.path(), "pkcheck"), Some(only_sbin));
    }

    #[test]
    fn a_file_that_cannot_run_or_a_directory_is_passed_over() {
        let root = tempfile::tempdir().expect("root");
        place(root.path(), "usr/bin", "resolvectl", 0o644).expect("place");
        std::fs::create_dir_all(root.path().join("bin/resolvectl")).expect("dir");
        let runnable = place(root.path(), "usr/sbin", "resolvectl", 0o755).expect("place");
        assert_eq!(locate_under(root.path(), "resolvectl"), Some(runnable));
    }

    #[test]
    fn a_name_that_is_a_path_or_absent_is_not_found() {
        let root = tempfile::tempdir().expect("root");
        place(root.path(), "usr/bin", "tool", 0o755).expect("place");
        place(root.path(), "usr", "escape", 0o755).expect("place");
        for name in ["", ".", "..", "../escape", "usr/bin/tool", "missing"] {
            assert_eq!(locate_under(root.path(), name), None, "{name:?}");
        }
    }

    /// Callers classify "not installed" by the spawn error; the lookup must
    /// fail the same way.
    #[test]
    fn a_missing_tool_fails_like_a_spawn_of_an_absent_program() {
        let spawned = Command::new("/nonexistent-nrr-dir/tool")
            .spawn()
            .expect_err("absent");
        let looked_up = system_tool("nrr-no-such-tool").expect_err("absent");
        assert_eq!(looked_up.kind(), io::ErrorKind::NotFound);
        assert_eq!(looked_up.to_string(), spawned.to_string());
        let run = output_with_timeout("nrr-no-such-tool", &[], DEFAULT_COMMAND_TIMEOUT)
            .expect_err("absent");
        assert_eq!(run.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn a_found_tool_is_absolute_and_stable() {
        let first = system_tool("sh").expect("sh");
        assert!(first.is_absolute());
        assert_eq!(system_tool("sh").expect("again"), first);
    }
}
