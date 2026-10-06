//! `diag logs` — the tail of the service's operational log.
//!
//! Asked of the SERVICE, like every other diagnostics read: it knows who is
//! asking and answers with that caller's lines plus the machine's (all of them
//! for an elevated caller). The request carries no audience — the console could
//! not widen its answer if it tried.
//!
//! Only when the service is down does the console read the files itself, and it
//! says so first: the files are unscoped, so every user's lines may appear. The
//! filesystem still decides whether that read is possible — the log tree is
//! closed to ordinary users. Lines come out as NDJSON either way, one record per
//! line, so what lands in a bug report is a record, not this console's prose.

use std::path::PathBuf;

use nrr_ipc_client::{IpcClient, IpcClientError};
use nrr_shared::diagnostics_dto::LogEntryFilter;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{LogsListRequest, LogsListResponse};
use nrr_shared::pagination::{PaginationParams, MAX_PAGE_SIZE};
use nrr_shared::product_identity::PRODUCT_NAME;

use crate::exit;
use crate::link::Link;

/// Lines printed when `--tail` is not given. Enough to cover a startup or a
/// failure, short enough to read in a terminal without scrolling away.
pub const DEFAULT_TAIL: usize = 50;

/// Ceiling on `--tail`. Past this the answer is a file to attach, not a console
/// to scroll — and `diag export` is that answer.
pub const MAX_TAIL: usize = 2000;

/// What reading the log files found.
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

/// What a run prints, collected so the order of the two streams and the text
/// itself are testable.
#[derive(Debug, Default)]
pub struct Printed {
    pub out: String,
    pub err: String,
}

impl Printed {
    fn out(&mut self, line: impl AsRef<str>) {
        self.out.push_str(line.as_ref());
        self.out.push('\n');
    }

    fn err(&mut self, line: impl AsRef<str>) {
        self.err.push_str(line.as_ref());
        self.err.push('\n');
    }
}

/// `diag logs`: ask the service, or — only when it is down — read the files.
pub fn run(exe: &str, tail: usize) -> u8 {
    let (client, link) = crate::link::open();
    let mut printed = Printed::default();
    let code = tail_log(
        &client,
        &link,
        tail,
        || read_tail(log_directory(), tail),
        exe,
        &mut printed,
    );
    // The notice that the files are being read directly comes before the lines
    // it qualifies.
    eprint!("{}", printed.err);
    print!("{}", printed.out);
    code
}

/// The decision, with the service and the disk passed in. `disk` is called
/// only when the service is not reachable at all.
pub fn tail_log(
    client: &dyn IpcClient,
    link: &Link,
    tail: usize,
    disk: impl FnOnce() -> Outcome,
    exe: &str,
    printed: &mut Printed,
) -> u8 {
    let why = match link {
        Link::Connected => return from_service(client, tail, exe, printed),
        // The service is up and has answered; reading around it would be a
        // second opinion on who may see what.
        Link::Refused(reason) => {
            printed.err(format!(
                "The {PRODUCT_NAME} service refused this console: {reason}"
            ));
            return exit::FAILED;
        }
        Link::NotRunning => "not running",
        Link::NotAnswering => "not answering",
    };
    printed.err(format!(
        "The {PRODUCT_NAME} service is {why} - reading the log files directly; \
         lines of all users may be shown."
    ));
    report(disk(), exe, printed)
}

/// Why the service's answer could not be printed.
#[derive(Debug)]
enum FetchError {
    Ipc(IpcClientError),
    Unreadable(String),
}

/// The newest `tail` records the service will show this caller, in reading
/// order. Pages arrive newest-first, so they are gathered then turned round.
fn fetch(client: &dyn IpcClient, tail: usize) -> Result<Vec<String>, FetchError> {
    let timeout = nrr_ipc_client::ipc_operation_timeout(IpcOperationName::LogsList);
    let mut newest_first: Vec<String> = Vec::with_capacity(tail);
    let mut cursor = None;
    while newest_first.len() < tail {
        let wanted = tail - newest_first.len();
        let request = LogsListRequest {
            filter: LogEntryFilter::default(),
            pagination: PaginationParams {
                cursor: cursor.take(),
                page_size: u32::try_from(wanted).map_or(MAX_PAGE_SIZE, |n| n.min(MAX_PAGE_SIZE)),
            },
        };
        let payload =
            serde_json::to_value(&request).map_err(|e| FetchError::Unreadable(e.to_string()))?;
        let answer = client
            .call(IpcOperationName::LogsList, payload, timeout)
            .map_err(FetchError::Ipc)?;
        let page: LogsListResponse =
            serde_json::from_value(answer).map_err(|e| FetchError::Unreadable(e.to_string()))?;
        let last_page = page.items.is_empty() || page.next_cursor.is_none();
        for entry in page.items.into_iter().take(wanted) {
            newest_first.push(
                serde_json::to_string(&entry).map_err(|e| FetchError::Unreadable(e.to_string()))?,
            );
        }
        if last_page {
            break;
        }
        cursor = page.next_cursor;
    }
    newest_first.reverse();
    Ok(newest_first)
}

fn from_service(client: &dyn IpcClient, tail: usize, exe: &str, printed: &mut Printed) -> u8 {
    match fetch(client, tail) {
        Ok(lines) if lines.is_empty() => {
            printed.out("The service has no log lines to show you yet.");
            exit::SUCCESS
        }
        Ok(lines) => {
            for line in lines {
                printed.out(line);
            }
            exit::SUCCESS
        }
        Err(FetchError::Unreadable(detail)) => {
            printed.err(format!(
                "The service answered with something this console cannot read: {detail}"
            ));
            exit::FAILED
        }
        Err(FetchError::Ipc(IpcClientError::ServerError { code, message, .. })) => {
            // The service's own judgement; reported, not reinterpreted.
            printed.err(format!("The service refused the log request: {message}"));
            printed.err(format!("  code: {code:?}"));
            exit::FAILED
        }
        Err(FetchError::Ipc(IpcClientError::Timeout)) => {
            printed.err("The service did not answer the log request in time.");
            exit::NOT_RESPONDING
        }
        Err(FetchError::Ipc(other)) => {
            printed.err(format!("Could not reach the service: {other}"));
            printed.err(format!("Check that it is running: {exe} status"));
            exit::NOT_RESPONDING
        }
    }
}

/// Print a file-read outcome and map it onto an exit code.
pub fn report(outcome: Outcome, exe: &str, printed: &mut Printed) -> u8 {
    match outcome {
        Outcome::Lines(lines) => {
            for line in lines {
                printed.out(line);
            }
            exit::SUCCESS
        }
        Outcome::NoLogDirectory => {
            printed.err("This platform declares no service log directory.");
            exit::UNSUPPORTED
        }
        Outcome::NoLogFile { directory } => {
            printed.out(format!(
                "No operational log in {} yet.",
                directory.display()
            ));
            printed.out("The service writes one once it has started at least once.");
            exit::SUCCESS
        }
        // Reached only with the service down, so the way through is to bring
        // it back: it answers without administrator rights.
        Outcome::Forbidden { directory, detail } => {
            printed.err(format!(
                "Could not read the log directory {}.",
                directory.display()
            ));
            printed.err(format!("  {detail}"));
            printed.err("Only administrators and the service account may read the files.");
            printed.err(
                "Start the service and run this again; it answers without administrator rights:",
            );
            printed.err(format!("  {exe} start"));
            printed.err("Or run this from an administrator console.");
            exit::NEEDS_PRIVILEGE
        }
        Outcome::Unreadable { directory, detail } => {
            printed.err(format!(
                "Could not read the log in {}.",
                directory.display()
            ));
            printed.err(format!("  {detail}"));
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
    #![allow(clippy::expect_used)]
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

    use crate::link::testing::FakeService;
    use nrr_ipc_client::ConnectionStatus;
    use std::cell::Cell;

    fn entry(id: &str) -> serde_json::Value {
        serde_json::json!({
            "event_id": id,
            "created_at": 1,
            "level": "info",
            "category": "service",
            "kind": "service.started",
            "message_key": "",
            "has_payload": false,
            "correlation_summary": [],
        })
    }

    /// A page as the service sends it: newest first.
    fn page(ids: &[&str], next: Option<&str>) -> Result<serde_json::Value, IpcClientError> {
        Ok(serde_json::json!({
            "items": ids.iter().map(|id| entry(id)).collect::<Vec<_>>(),
            "next_cursor": next,
            "total_count": null,
            "stale": false,
        }))
    }

    fn run_with(service: &FakeService, link: Link, tail: usize) -> (u8, Printed, bool) {
        let disk_read = Cell::new(false);
        let mut printed = Printed::default();
        let code = tail_log(
            service,
            &link,
            tail,
            || {
                disk_read.set(true);
                Outcome::Lines(vec!["{\"from\":\"disk\"}".to_string()])
            },
            "nrr-cli",
            &mut printed,
        );
        (code, printed, disk_read.get())
    }

    fn event_ids(out: &str) -> Vec<String> {
        out.lines()
            .map(|line| {
                let value: serde_json::Value =
                    serde_json::from_str(line).expect("each line is one JSON record");
                value["event_id"].as_str().unwrap_or_default().to_string()
            })
            .collect()
    }

    #[test]
    fn a_running_service_is_asked_and_the_disk_is_not_touched() {
        let service = FakeService::new(ConnectionStatus::Connected).answer(page(&["b", "a"], None));
        let (code, printed, disk_read) = run_with(&service, Link::Connected, 10);
        assert_eq!(code, exit::SUCCESS);
        assert!(
            !disk_read,
            "the files must not be read while the service answers"
        );
        assert!(
            printed.err.is_empty(),
            "no fallback notice: {}",
            printed.err
        );
        assert_eq!(
            event_ids(&printed.out),
            ["a", "b"],
            "reading order, newest last"
        );
        let calls = service.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, IpcOperationName::LogsList);
    }

    #[test]
    fn a_long_tail_is_paged_until_it_is_full() {
        let service = FakeService::new(ConnectionStatus::Connected)
            .answer(page(&["d", "c"], Some("2|c")))
            .answer(page(&["b", "a"], Some("1|a")));
        let (code, printed, _) = run_with(&service, Link::Connected, 3);
        assert_eq!(code, exit::SUCCESS);
        assert_eq!(event_ids(&printed.out), ["b", "c", "d"]);
        let calls = service.calls();
        assert_eq!(calls.len(), 2, "a full tail asks for no further page");
        assert_eq!(calls[1].1["pagination"]["cursor"], "2|c");
        assert_eq!(calls[1].1["pagination"]["page_size"], 1);
    }

    #[test]
    fn the_console_never_names_an_audience() {
        // Whose lines come back is the service's decision, derived from the
        // connection. The request has nothing that could ask for more.
        let service = FakeService::new(ConnectionStatus::Connected).answer(page(&["a"], None));
        run_with(&service, Link::Connected, 5);
        let (_, payload) = &service.calls()[0];
        let mut keys: Vec<&str> = payload
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["filter", "pagination"]);
        let text = payload.to_string().to_ascii_lowercase();
        for word in ["audience", "principal", "sid", "machine"] {
            assert!(!text.contains(word), "`{word}` in {text}");
        }
    }

    #[test]
    fn a_stopped_service_falls_back_to_the_files_and_says_so_first() {
        for (link, why) in [
            (Link::NotRunning, "not running"),
            (Link::NotAnswering, "not answering"),
        ] {
            let service = FakeService::new(ConnectionStatus::ServiceStopped);
            let (code, printed, disk_read) = run_with(&service, link, 10);
            assert_eq!(code, exit::SUCCESS);
            assert!(disk_read);
            assert!(service.calls().is_empty());
            assert!(printed.err.contains(why), "{}", printed.err);
            assert!(
                printed
                    .err
                    .contains("reading the log files directly; lines of all users may be shown"),
                "{}",
                printed.err
            );
            assert_eq!(printed.out, "{\"from\":\"disk\"}\n");
        }
    }

    #[test]
    fn a_service_that_refused_the_console_is_not_read_around() {
        let service = FakeService::new(ConnectionStatus::Refused {
            reason: "no slot".into(),
        });
        let (code, _, disk_read) = run_with(&service, Link::Refused("no slot".into()), 10);
        assert_eq!(code, exit::FAILED);
        assert!(!disk_read);
    }

    #[test]
    fn a_refused_file_read_is_reported_and_offers_no_elevation() {
        let mut printed = Printed::default();
        let code = report(
            Outcome::Forbidden {
                directory: PathBuf::from("logs"),
                detail: "access denied".into(),
            },
            "nrr-cli",
            &mut printed,
        );
        assert_eq!(code, exit::NEEDS_PRIVILEGE);
        assert!(!printed.err.contains("--elevate"), "{}", printed.err);
        assert!(printed.err.contains("nrr-cli start"), "{}", printed.err);
    }

    #[test]
    fn only_the_ndjson_stream_counts_as_a_log() {
        // `nrr_service_stderr.log` sits in the same directory and is a crash
        // capture, not the operational stream.
        assert!(newest_operational_log(&names(&["nrr_service_stderr.log"])).is_none());
    }
}
