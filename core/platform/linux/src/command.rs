//! Running an external program with a budget.
//!
//! Every helper this port shells out to — `loginctl`, `systemctl`, `nft` — was
//! called through `Command::output()`, which waits forever. `live_users()` runs
//! on EVERY enforcement tick, so one `loginctl` blocked on an unreachable D-Bus
//! stopped policy enforcement for good. The same lesson Windows learned from
//! the BFE incident, in the other port.

use std::io::{self, Read};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Default budget for a local helper that answers from kernel or systemd state.
/// Generous for a question that normally returns in milliseconds, short enough
/// that a wedged helper cannot outlive one enforcement tick by much.
pub const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

/// Runs `exe args…` and returns its output, killing it if the budget expires.
///
/// The environment is forced to the C locale: several callers classify failures
/// by matching English text in `stderr`, and on a localised system a translated
/// "permission denied" turned an access refusal into an unclassified mechanism
/// error.
pub fn output_with_timeout(exe: &str, args: &[&str], timeout: Duration) -> io::Result<Output> {
    let mut child = Command::new(exe)
        .args(args)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

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
    fn the_child_speaks_the_c_locale() {
        // `service_control::classify_command_failure` matches English text in
        // stderr; that only holds if the helper is not localised.
        let out = output_with_timeout("sh", &["-c", "echo $LC_ALL"], DEFAULT_COMMAND_TIMEOUT)
            .expect("sh");
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "C");
    }
}
