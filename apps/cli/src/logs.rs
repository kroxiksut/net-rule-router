//! `diag logs` — the tail of the service's operational log.
//!
//! Reading a file, nothing more: no IPC, no policy, no interpretation. That is
//! what makes it useful exactly when the service is dead, which is when someone
//! asks for its log. The lines come out verbatim (NDJSON as written) so what a
//! user pastes into a bug report is the same text the service produced, not this
//! console's rendering of it.

use std::path::PathBuf;

use crate::exit;

/// Lines printed when `--tail` is not given. Enough to cover a startup or a
/// failure, short enough to read in a terminal without scrolling away.
pub const DEFAULT_TAIL: usize = 50;

/// Ceiling on `--tail`. Past this the answer is a file to attach, not a console
/// to scroll — and `diag export` is that answer.
pub const MAX_TAIL: usize = 2000;

/// What a log request found.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Lines, newest last (reading order).
    Lines(Vec<String>),
    /// The log directory is not declared for this platform.
    NoLogDirectory,
    /// The directory exists but holds no operational log yet.
    NoLogFile { directory: PathBuf },
    /// Access was refused — on a locked-down install this is the ordinary
    /// answer for a non-elevated console, not a fault, and elevation fixes it.
    Forbidden { directory: PathBuf, detail: String },
    /// The log could not be read for any other reason: the file is held open
    /// exclusively, the disk failed, the bytes are not text. Elevation changes
    /// none of those, and advising it sends the user off to prove it.
    Unreadable { directory: PathBuf, detail: String },
}

/// Split an I/O failure by what the user can actually do about it.
fn classify(directory: PathBuf, detail: String, kind: std::io::ErrorKind) -> Outcome {
    if kind == std::io::ErrorKind::PermissionDenied {
        Outcome::Forbidden { directory, detail }
    } else {
        Outcome::Unreadable { directory, detail }
    }
}

/// Read the tail of the newest operational log.
pub fn read_tail(directory: Option<PathBuf>, lines: usize) -> Outcome {
    let Some(directory) = directory else {
        return Outcome::NoLogDirectory;
    };
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(e) => {
            let kind = e.kind();
            return classify(directory, e.to_string(), kind);
        }
    };
    let names: Vec<String> = entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    let Some(newest) = newest_operational_log(&names) else {
        return Outcome::NoLogFile { directory };
    };
    let path = directory.join(newest);
    match read_tail_bytes(&path) {
        Ok(text) => Outcome::Lines(tail_lines(&text, lines)),
        Err(e) => {
            let kind = e.kind();
            classify(directory, format!("{}: {e}", path.display()), kind)
        }
    }
}

/// How much of the end of a log file is read to find the tail.
///
/// The whole file was read for it before, and retention allows fifty megabytes
/// — a hundred and fifty in memory once decoded, at the exact moment the
/// machine is already in trouble and someone is asking why. [`MAX_TAIL`] lines
/// of NDJSON fit in this comfortably; a line that does not fit is truncated at
/// its head, which is visible and harmless, unlike an allocation that is not.
const TAIL_WINDOW_BYTES: u64 = 4 * 1024 * 1024;

/// Read the last [`TAIL_WINDOW_BYTES`] of `path` as text.
///
/// The window is cut at a byte boundary, so its first line may start
/// mid-character; the leading partial line is dropped rather than rendered as
/// replacement characters. A file smaller than the window is read whole and
/// keeps its first line.
fn read_tail_bytes(path: &std::path::Path) -> std::io::Result<String> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len <= TAIL_WINDOW_BYTES {
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        return Ok(text);
    }
    file.seek(SeekFrom::Start(len - TAIL_WINDOW_BYTES))?;
    let mut buf = Vec::with_capacity(TAIL_WINDOW_BYTES as usize);
    file.read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf).into_owned();
    Ok(match text.find('\n') {
        Some(idx) => text[idx + 1..].to_string(),
        None => text,
    })
}

/// The newest operational log among the file names in a directory.
///
/// Names are `nrr_service_YYYYMMDD-N.ndjson`, so lexical order IS chronological
/// order — until the sequence number reaches two digits, where `-10` sorts
/// before `-9`. Hence the explicit (date, sequence) key rather than a plain
/// string sort. Audit files are never candidates: they are a different stream,
/// and this verb must not be a way to page through the security trail.
pub fn newest_operational_log(names: &[String]) -> Option<&String> {
    names
        .iter()
        .filter(|n| n.starts_with("nrr_service_") && n.ends_with(".ndjson"))
        .max_by_key(|n| log_sort_key(n))
}

/// `nrr_service_20260815-2.ndjson` → `(20260815, 2)`. Anything unparseable
/// sorts first, so a stray file never wins over a real log.
fn log_sort_key(name: &str) -> (u32, u32) {
    let stem = name
        .trim_start_matches("nrr_service_")
        .trim_end_matches(".ndjson");
    match stem.split_once('-') {
        Some((date, seq)) => (date.parse().unwrap_or(0), seq.parse().unwrap_or(0)),
        None => (stem.parse().unwrap_or(0), 0),
    }
}

/// The last `lines` non-empty lines, in reading order.
pub fn tail_lines(text: &str, lines: usize) -> Vec<String> {
    let mut all: Vec<String> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_string)
        .collect();
    if all.len() > lines {
        all.drain(..all.len() - lines);
    }
    all
}

/// Print an outcome and map it onto an exit code.
pub fn report(outcome: Outcome, exe: &str) -> u8 {
    match outcome {
        Outcome::Lines(lines) => {
            for line in lines {
                println!("{line}");
            }
            exit::SUCCESS
        }
        Outcome::NoLogDirectory => {
            eprintln!("This platform declares no service log directory.");
            exit::UNSUPPORTED
        }
        Outcome::NoLogFile { directory } => {
            println!("No operational log in {} yet.", directory.display());
            println!("The service writes one once it has started at least once.");
            exit::SUCCESS
        }
        Outcome::Forbidden { directory, detail } => {
            eprintln!("Could not read the log directory {}.", directory.display());
            eprintln!("  {detail}");
            eprintln!("The directory is readable by the service account; try an elevated console:");
            eprintln!("  {exe} diag logs");
            exit::NEEDS_PRIVILEGE
        }
        Outcome::Unreadable { directory, detail } => {
            eprintln!("Could not read the log in {}.", directory.display());
            eprintln!("  {detail}");
            exit::FAILED
        }
    }
}

/// The production log directory.
pub fn log_directory() -> Option<PathBuf> {
    nrr_platform_api::paths::production_logs_dir()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_newest_log_is_chosen_by_date_then_sequence() {
        let files = names(&[
            "nrr_service_20260814-1.ndjson",
            "nrr_service_20260815-1.ndjson",
            "nrr_service_20260815-2.ndjson",
        ]);
        assert_eq!(
            newest_operational_log(&files).map(String::as_str),
            Some("nrr_service_20260815-2.ndjson")
        );
    }

    #[test]
    fn a_two_digit_sequence_beats_a_single_digit_one() {
        // Lexical order would put `-9` after `-10` and hand back a stale file.
        let files = names(&[
            "nrr_service_20260815-9.ndjson",
            "nrr_service_20260815-10.ndjson",
        ]);
        assert_eq!(
            newest_operational_log(&files).map(String::as_str),
            Some("nrr_service_20260815-10.ndjson")
        );
    }

    #[test]
    fn the_audit_stream_is_never_a_candidate() {
        // Separate stream with its own retention and an append-only hash chain;
        // paging through it is not what this verb is for.
        let files = names(&[
            "nrr_audit_20260815-1.ndjson",
            "nrr_service_20260801-1.ndjson",
        ]);
        assert_eq!(
            newest_operational_log(&files).map(String::as_str),
            Some("nrr_service_20260801-1.ndjson")
        );
        assert!(newest_operational_log(&names(&["nrr_audit_20260815-1.ndjson"])).is_none());
    }

    #[test]
    fn the_tail_keeps_reading_order_and_drops_blank_lines() {
        let text = "one\n\ntwo\nthree\n";
        assert_eq!(tail_lines(text, 2), vec!["two".to_string(), "three".into()]);
        assert_eq!(
            tail_lines(text, 99),
            vec!["one".to_string(), "two".into(), "three".into()],
            "asking for more lines than exist yields everything, not an error"
        );
    }

    #[test]
    fn an_absent_log_directory_is_reported_as_unsupported_not_as_empty() {
        // "This OS has no such directory" and "the directory is empty" are
        // different answers, and a script has to be able to tell them apart.
        assert_eq!(read_tail(None, 10), Outcome::NoLogDirectory);
    }

    #[test]
    fn only_the_ndjson_stream_counts_as_a_log() {
        // `nrr_service_stderr.log` sits in the same directory and is a crash
        // capture, not the operational stream.
        assert!(newest_operational_log(&names(&["nrr_service_stderr.log"])).is_none());
    }
}
