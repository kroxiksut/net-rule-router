//! Running a system tool without letting it hang the caller.
//!
//! Every tool this crate runs sits on a boot, stop or recovery path, where an
//! unbounded wait turns into the failure the path exists to prevent. So the
//! child gets a budget and is killed past it, and both pipes are drained while
//! it runs: a child blocked on a full pipe never exits and would be killed for
//! our own failure to read.

use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// How often the child is checked while waiting.
const POLL: Duration = Duration::from_millis(50);

/// Runs `command` hidden, with no input, and returns its exit status and both
/// streams. `ErrorKind::TimedOut` once `budget` expires; the child is killed.
pub(crate) fn output_within(command: &mut Command, budget: Duration) -> std::io::Result<Output> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut child = command
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let deadline = Instant::now() + budget;
    let timed_out = || {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("the tool did not answer within {budget:?}"),
        )
    };
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(timed_out());
            }
            Ok(None) => std::thread::sleep(POLL),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        }
    };
    // Bounded too: a grandchild that inherited the pipe keeps it open after the
    // child itself is gone.
    let collect = |rx: mpsc::Receiver<Vec<u8>>| {
        rx.recv_timeout(deadline.saturating_duration_since(Instant::now()) + POLL)
            .map_err(|_| timed_out())
    };
    Ok(Output {
        status,
        stdout: collect(stdout)?,
        stderr: collect(stderr)?,
    })
}

/// Reads `pipe` to its end on a thread of its own. A missing pipe reads empty.
fn drain(pipe: Option<impl Read + Send + 'static>) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_end(&mut buf);
        }
        let _ = tx.send(buf);
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(arguments: &[&str]) -> Command {
        let mut command = Command::new(crate::system_shell::system32_exe("cmd.exe"));
        command.args(arguments);
        command
    }

    #[test]
    fn a_tool_that_never_answers_is_killed_at_the_budget() {
        let started = Instant::now();
        // `ping -n 30` waits about thirty seconds and reads no input.
        let result = output_within(
            &mut cmd(&["/c", "ping", "-n", "30", "127.0.0.1"]),
            Duration::from_millis(300),
        );
        assert_eq!(
            result.map(|_| ()).map_err(|e| e.kind()),
            Err(std::io::ErrorKind::TimedOut)
        );
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn a_tool_that_answers_in_time_hands_its_output_back() {
        let output = output_within(
            &mut cmd(&["/c", "echo", "refused", "1>&2", "&", "exit", "3"]),
            Duration::from_secs(10),
        )
        .expect("cmd answers");
        assert_eq!(output.status.code(), Some(3));
        assert!(String::from_utf8_lossy(&output.stderr).contains("refused"));
    }

    /// Far past any pipe buffer: without the drain the child blocks on its
    /// first full write and is killed at the budget instead of answering.
    #[test]
    fn output_far_larger_than_the_pipe_buffer_is_read_whole_within_the_budget() {
        const LINES: usize = 4000;
        let line = "x".repeat(60);
        let mut command = cmd(&["/c"]);
        std::os::windows::process::CommandExt::raw_arg(
            &mut command,
            format!("for /L %i in (1,1,{LINES}) do @echo {line}"),
        );
        let started = Instant::now();
        let output = output_within(&mut command, Duration::from_secs(20))
            .expect("a chatty child still answers");
        assert!(output.status.success());
        let text = String::from_utf8_lossy(&output.stdout);
        assert_eq!(text.lines().filter(|l| l.trim() == line).count(), LINES);
        assert!(output.stdout.len() > 64 * 1024, "{}", output.stdout.len());
        assert!(started.elapsed() < Duration::from_secs(20));
    }
}
