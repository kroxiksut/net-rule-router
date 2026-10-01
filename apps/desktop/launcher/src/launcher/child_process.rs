// No-console child spawn flag and the line-buffered stdout/stderr pump.

use std::io::{BufRead, BufReader, ErrorKind, Read};
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::sync::mpsc;
use std::thread;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub(super) fn apply_no_window(command: &mut Command) -> &mut Command {
    #[cfg(windows)]
    {
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
}

/// Longest child stdout line this pump will hold.
///
/// The lines that matter are the `NRR_PREFS_JSON:` payloads, and a whole
/// preferences document is far below this. A child that emits a line without a
/// newline — a wedged writer, a binary stream on the wrong pipe — would
/// otherwise grow one `String` until the process dies of it, and the reader is
/// the one part of the launcher that must survive a misbehaving child.
const MAX_CHILD_LINE_BYTES: usize = 4 * 1024 * 1024;

pub(super) fn spawn_line_reader<R>(reader: R, sender: mpsc::Sender<String>)
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        pump_lines(BufReader::new(reader), MAX_CHILD_LINE_BYTES, |line| {
            sender.send(line).is_ok()
        });
    });
}

/// Hand every line of `reader` to `deliver` until the stream ends, a read
/// fails or `deliver` returns `false`. A line longer than `cap` is dropped.
fn pump_lines<R: BufRead>(mut reader: R, cap: usize, mut deliver: impl FnMut(String) -> bool) {
    let mut line = Vec::with_capacity(256);
    loop {
        line.clear();
        // Byte-oriented and capped, rather than `lines()`: the cap is the
        // point, and a child is free to emit bytes that are not UTF-8.
        let mut limited = (&mut reader).take(cap as u64);
        match limited.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if line.len() == cap && !line.ends_with(b"\n") {
            if !skip_past_newline(&mut reader) {
                break;
            }
            continue;
        }
        while line.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
            line.pop();
        }
        if !deliver(String::from_utf8_lossy(&line).into_owned()) {
            break;
        }
    }
}

/// Consume through the next newline inside the reader's own buffer, so the rest
/// of an oversized line costs no memory however long it runs. `false` at end of
/// stream or on a read error.
fn skip_past_newline<R: BufRead>(reader: &mut R) -> bool {
    loop {
        let (used, found) = match reader.fill_buf() {
            Ok([]) => return false,
            Ok(chunk) => match chunk.iter().position(|b| *b == b'\n') {
                Some(end) => (end + 1, true),
                None => (chunk.len(), false),
            },
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return false,
        };
        reader.consume(used);
        if found {
            return true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `garbage` bytes with no newline, generated on demand, then `tail`.
    struct EndlessLine {
        garbage: u64,
        tail: &'static [u8],
    }

    impl Read for EndlessLine {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.garbage > 0 {
                let n = buf
                    .len()
                    .min(usize::try_from(self.garbage).unwrap_or(usize::MAX));
                buf[..n].fill(b'x');
                self.garbage -= n as u64;
                return Ok(n);
            }
            let n = buf.len().min(self.tail.len());
            buf[..n].copy_from_slice(&self.tail[..n]);
            self.tail = &self.tail[n..];
            Ok(n)
        }
    }

    fn pump(reader: EndlessLine, cap: usize) -> Vec<String> {
        let mut lines = Vec::new();
        pump_lines(BufReader::with_capacity(4096, reader), cap, |line| {
            lines.push(line);
            true
        });
        lines
    }

    #[test]
    fn a_newline_less_flood_is_skipped_and_the_next_line_is_read() {
        let lines = pump(
            EndlessLine {
                garbage: 64 * 1024 * 1024,
                tail: b"\nNRR_PREFS_JSON:{}\r\nlast",
            },
            1024,
        );
        assert_eq!(lines, ["NRR_PREFS_JSON:{}", "last"]);
    }

    #[test]
    fn a_stream_that_ends_inside_an_oversized_line_ends_the_pump() {
        let lines = pump(
            EndlessLine {
                garbage: 1024 * 1024,
                tail: b"",
            },
            1024,
        );
        assert!(lines.is_empty());
    }

    #[test]
    fn the_cap_counts_the_newline() {
        let lines = pump(
            EndlessLine {
                garbage: 0,
                tail: b"abc\nabcd\nok\n",
            },
            4,
        );
        assert_eq!(lines, ["abc", "ok"]);
    }
}
