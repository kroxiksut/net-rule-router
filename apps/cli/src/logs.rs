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
    /// The directory could not be read — on a locked-down install this is the
    /// ordinary answer for a non-elevated console, not a fault.
    Unreadable { directory: PathBuf, detail: String },
}

/// Read the tail of the newest operational log.
pub fn read_tail(directory: Option<PathBuf>, lines: usize) -> Outcome {
    let Some(directory) = directory else {
        return Outcome::NoLogDirectory;
    };
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(e) => {
            return Outcome::Unreadable {
                directory,
                detail: e.to_string(),
            }
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
    match std::fs::read_to_string(&path) {
        Ok(text) => Outcome::Lines(tail_lines(&text, lines)),
        Err(e) => Outcome::Unreadable {
            directory,
            detail: format!("{}: {e}", path.display()),
        },
    }
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
        Outcome::Unreadable { directory, detail } => {
            eprintln!("Could not read the log directory {}.", directory.display());
            eprintln!("  {detail}");
            eprintln!("The directory is readable by the service account; try an elevated console:");
            eprintln!("  {exe} diag logs");
            exit::NEEDS_PRIVILEGE
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
