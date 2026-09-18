// No-console child spawn flag, the line-buffered stdout/stderr pump, and the
// `file://` URL builder the context hand-off and icon resolution both use.

use std::io::{BufRead, BufReader, Read};
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::path::Path;
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
        let mut buffered = BufReader::new(reader);
        let mut line = Vec::with_capacity(256);
        loop {
            line.clear();
            // Byte-oriented and capped, rather than `lines()`: the cap is the
            // point, and a child is free to emit bytes that are not UTF-8.
            let mut limited = (&mut buffered).take(MAX_CHILD_LINE_BYTES as u64);
            match limited.read_until(b'\n', &mut line) {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => break,
            }
            // Nothing but a full cap and no terminator: the line is oversized,
            // so drop it and resynchronise on the next newline rather than
            // reassembling something no consumer can use.
            if line.len() == MAX_CHILD_LINE_BYTES && !line.ends_with(b"\n") {
                let mut discard = Vec::new();
                if buffered.read_until(b'\n', &mut discard).is_err() {
                    break;
                }
                continue;
            }
            while line.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
                line.pop();
            }
            if sender
                .send(String::from_utf8_lossy(&line).into_owned())
                .is_err()
            {
                break;
            }
        }
    });
}

pub fn path_to_file_url(path: &Path) -> String {
    let normalized = path.to_string_lossy().replace('\\', "/");
    if normalized.starts_with('/') {
        format!("file://{normalized}")
    } else {
        format!("file:///{normalized}")
    }
}
