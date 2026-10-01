//! Operational log reader.
//!
//! Simple NDJSON file scanner for querying operational logs.
//! No hash chain verification (operational logs are not tamper-protected;
//! only the audit trail has a rolling hash chain).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::event::LogEvent;
use crate::facade::dto::DiagnosticsAudience;
use crate::taxonomy::{EventCategory, EventLevel};

// ── LogQueryFilter ────────────────────────────────────────────────────────────

/// Filter for operational log queries.
#[derive(Clone, Debug, Default)]
pub struct LogQueryFilter {
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
    pub level_min: Option<EventLevel>,
    pub category: Option<EventCategory>,
    /// Case-insensitive substring of the event kind.
    pub kind: Option<String>,
    pub decision_id: Option<String>,
    pub revision_id: Option<String>,
}

impl LogQueryFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_ms(mut self, ms: i64) -> Self {
        self.from_ms = Some(ms);
        self
    }
    pub fn to_ms(mut self, ms: i64) -> Self {
        self.to_ms = Some(ms);
        self
    }
    pub fn level_min(mut self, level: EventLevel) -> Self {
        self.level_min = Some(level);
        self
    }
    pub fn category(mut self, cat: EventCategory) -> Self {
        self.category = Some(cat);
        self
    }
    pub fn kind(mut self, kind: impl Into<String>) -> Self {
        self.kind = Some(kind.into());
        self
    }
    pub fn decision_id(mut self, id: impl Into<String>) -> Self {
        self.decision_id = Some(id.into());
        self
    }
    pub fn revision_id(mut self, id: impl Into<String>) -> Self {
        self.revision_id = Some(id.into());
        self
    }

    fn matches(&self, event: &LogEvent) -> bool {
        if let Some(from) = self.from_ms {
            if event.created_at < from {
                return false;
            }
        }
        if let Some(to) = self.to_ms {
            if event.created_at > to {
                return false;
            }
        }
        if let Some(min) = self.level_min {
            if event.level < min {
                return false;
            }
        }
        if let Some(cat) = self.category {
            if event.category != cat {
                return false;
            }
        }
        // A case-insensitive substring, because the Logs view offers a
        // free-text "event type" box and people type the part they remember
        // without matching the slug's exact case.
        if let Some(k) = &self.kind {
            if !ascii_ci_contains(&event.kind, k) {
                return false;
            }
        }
        // Correlation filters were declared and never applied: the user picked
        // a decision or a revision and got the whole log back, believing it
        // filtered. An event with no correlation cannot match one.
        if let Some(id) = &self.decision_id {
            if event.correlation.decision_id.as_deref() != Some(id.as_str()) {
                return false;
            }
        }
        if let Some(id) = &self.revision_id {
            if event.correlation.revision_id.as_deref() != Some(id.as_str()) {
                return false;
            }
        }
        true
    }
}

/// ASCII case-insensitive substring test. Event kinds are ASCII slugs
/// (`service.stopped`, `revision_activated`), so this skips the
/// per-event allocation a `to_ascii_lowercase()` on both sides would cost.
fn ascii_ci_contains(haystack: &str, needle: &str) -> bool {
    let (h, n) = (haystack.as_bytes(), needle.as_bytes());
    if n.is_empty() {
        return true;
    }
    if n.len() > h.len() {
        return false;
    }
    h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
}

// ── LogReader ─────────────────────────────────────────────────────────────────

/// Whether one raw NDJSON line may be shown to `owner`, and falls inside the
/// session window.
///
/// A line that cannot be parsed is dropped: it carries no owner, and a support
/// bundle is not the place to guess. `principal` absent means the line is about
/// the machine and belongs to everyone.
fn raw_line_is_visible(line: &str, owner: Option<&str>, from_ms: Option<i64>) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
        return false;
    };
    if let Some(cutoff) = from_ms {
        match value.get("created_at").and_then(serde_json::Value::as_i64) {
            Some(created_at) if created_at < cutoff => return false,
            None => return false,
            _ => {}
        }
    }
    let Some(owner) = owner else {
        return true;
    };
    match value.get("principal").and_then(serde_json::Value::as_str) {
        None => true,
        Some(line_owner) => line_owner == owner,
    }
}

/// One rotated service-log file's worth of raw lines.
///
/// The name is the file's own (`nrr_service_YYYYMMDD-N.ndjson`), so a bundle
/// reader sees the same layout the service writes and can tell which stretch of
/// the day a line came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawLogFile {
    /// File name as written on disk, no directory part.
    pub name: String,
    /// The lines this file contributed, oldest first.
    pub lines: Vec<String>,
}

/// One page of log events, newest first.
#[derive(Clone, Debug, Default)]
pub struct LogPage {
    pub events: Vec<LogEvent>,
    /// More events match past the last one on this page.
    pub has_more: bool,
}

/// Earliest and latest `created_at` in one file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TimeSpan {
    min: i64,
    max: i64,
}

/// `(length, modified)`: a rotated file never changes again, so only the one
/// being written is re-indexed.
type FileStamp = (u64, Option<std::time::SystemTime>);

/// Per-file time spans kept between page reads; `None` marks a file with no
/// readable event.
#[derive(Debug, Default)]
pub struct LogFileIndex {
    spans: Mutex<HashMap<PathBuf, (FileStamp, Option<TimeSpan>)>>,
}

impl LogFileIndex {
    pub fn new() -> Self {
        Self::default()
    }

    fn spans_of(&self, files: Vec<PathBuf>) -> Vec<(PathBuf, Option<TimeSpan>)> {
        // A poisoned lock only means a panic mid-update; spans are re-checked
        // against the file stamp anyway.
        let mut spans = match self.spans.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        spans.retain(|path, _| files.contains(path));
        files
            .into_iter()
            .map(|path| {
                let stamp = file_stamp(&path);
                let span = match spans.get(&path) {
                    Some((known, span)) if *known == stamp => *span,
                    _ => {
                        let span = time_span_of(&path);
                        spans.insert(path.clone(), (stamp, span));
                        span
                    }
                };
                (path, span)
            })
            .collect()
    }
}

fn file_stamp(path: &Path) -> FileStamp {
    let meta = std::fs::metadata(path).ok();
    (
        meta.as_ref().map(|m| m.len()).unwrap_or(0),
        meta.and_then(|m| m.modified().ok()),
    )
}

/// Reads only `created_at` from each line: far cheaper than a whole event.
fn time_span_of(path: &Path) -> Option<TimeSpan> {
    #[derive(serde::Deserialize)]
    struct Stamp {
        created_at: i64,
    }
    let content = std::fs::read_to_string(path).ok()?;
    content
        .lines()
        .filter_map(|line| serde_json::from_str::<Stamp>(line).ok())
        .fold(None, |span: Option<TimeSpan>, stamp| {
            let ts = stamp.created_at;
            Some(match span {
                None => TimeSpan { min: ts, max: ts },
                Some(s) => TimeSpan {
                    min: s.min.min(ts),
                    max: s.max.max(ts),
                },
            })
        })
}

/// Read-only accessor for operational NDJSON log files.
pub struct LogReader {
    logs_dir: PathBuf,
}

impl LogReader {
    pub fn new(logs_dir: impl Into<PathBuf>) -> Self {
        Self {
            logs_dir: logs_dir.into(),
        }
    }

    /// Returns log files sorted lexicographically (= chronologically).
    pub fn list_files(&self) -> Vec<PathBuf> {
        list_log_files(&self.logs_dir)
    }

    /// The newest `limit` events strictly older than `before` (the
    /// `(created_at, event_id)` a previous page ended on), newest first.
    ///
    /// Runs inside the service on every "Logs" page, so it parses only the
    /// files that can hold the page: `index` remembers each file's time span,
    /// and files are read newest-span-first until none left can outrank what
    /// is already kept. Ordering does not rely on file names, so a clock step
    /// back between rotations does not drop entries.
    ///
    /// The log is one machine-wide stream: a principal-scoped reader keeps the
    /// lines that belong to nobody (boot, adapters, service lifecycle) and its
    /// own. The audience is required so an unscoped read cannot be written.
    pub fn page_newest_first(
        &self,
        filter: &LogQueryFilter,
        audience: &DiagnosticsAudience,
        before: Option<(i64, &str)>,
        limit: usize,
        index: &LogFileIndex,
    ) -> LogPage {
        let owner = audience.principal();
        let before_ts = before.map(|(ts, _)| ts);
        let mut candidates: Vec<(PathBuf, TimeSpan)> = index
            .spans_of(self.list_files())
            .into_iter()
            .filter_map(|(path, span)| Some((path, span?)))
            .filter(|(_, span)| {
                filter.from_ms.is_none_or(|from| span.max >= from)
                    && filter.to_ms.is_none_or(|to| span.min <= to)
                    && before_ts.is_none_or(|ts| span.min <= ts)
            })
            .collect();
        candidates.sort_by_key(|(_, span)| std::cmp::Reverse(span.max));

        // One past the page, so `has_more` needs no second read.
        let want = limit.saturating_add(1);
        let mut kept: Vec<LogEvent> = Vec::new();
        for (path, span) in candidates {
            if kept.len() >= want && kept.last().is_some_and(|floor| span.max < floor.created_at) {
                break;
            }
            kept.extend(parse_events_from_file(&path).into_iter().filter(|event| {
                visible_to(owner, event)
                    && before.is_none_or(|b| (event.created_at, event.event_id.as_str()) < b)
                    && filter.matches(event)
            }));
            kept.sort_by(|a, b| {
                (b.created_at, b.event_id.as_str()).cmp(&(a.created_at, a.event_id.as_str()))
            });
            kept.truncate(want);
        }
        let has_more = kept.len() > limit;
        kept.truncate(limit);
        LogPage {
            events: kept,
            has_more,
        }
    }

    /// Raw NDJSON lines from the newest files, newest-first, within a byte
    /// budget — and only the ones `audience` may see.
    ///
    /// The archive ships these VERBATIM: the DTO listing drops payloads, and a
    /// support bundle without them describes symptoms with the evidence
    /// removed. A principal-scoped audience keeps the lines that belong to
    /// nobody (boot, adapters, service lifecycle) and its own. `from_ms` trims
    /// to a session window the same way the wire filter does.
    ///
    /// Walks files newest-first and stops as soon as the budget is met, so
    /// asking for the last few hundred KiB never pulls the whole retention cap
    /// into memory.
    pub fn recent_raw_lines_for(
        &self,
        max_bytes: usize,
        audience: &DiagnosticsAudience,
        from_ms: Option<i64>,
    ) -> Vec<String> {
        self.recent_raw_files_for(max_bytes, audience, from_ms)
            .into_iter()
            .flat_map(|file| file.lines)
            .collect()
    }

    /// The same lines, kept in the FILES they were written to.
    ///
    /// A day of service logs is several rotated files, and flattening them into
    /// one stream throws away the boundary a reader navigates by — which file,
    /// and therefore which stretch of the day, an event came from. The archive
    /// ships them as a directory for that reason; the flat form above is kept
    /// for callers that genuinely want one stream.
    ///
    /// Budget, scoping and ordering are unchanged: files are walked
    /// newest-first so the budget buys the freshest evidence, and what survives
    /// is handed back oldest-file-first with each file's own lines in the order
    /// they were written.
    pub fn recent_raw_files_for(
        &self,
        max_bytes: usize,
        audience: &DiagnosticsAudience,
        from_ms: Option<i64>,
    ) -> Vec<RawLogFile> {
        if max_bytes == 0 {
            return Vec::new();
        }
        let owner = audience.principal();
        let mut newest_first: Vec<RawLogFile> = Vec::new();
        let mut used: usize = 0;
        'files: for path in self.list_files().into_iter().rev() {
            let Ok(contents) = std::fs::read_to_string(&path) else {
                continue;
            };
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let mut lines: Vec<String> = Vec::new();
            for line in contents.lines().rev() {
                if line.trim().is_empty() {
                    continue;
                }
                if !raw_line_is_visible(line, owner, from_ms) {
                    continue;
                }
                let cost = line.len() + 1;
                // The newest kept line always fits, however long: a caller
                // asking for the tail must not get an empty answer.
                // Saturating: an unlimited caller passes `usize::MAX`, and
                // `used + cost` would overflow on the way to comparing.
                if !(newest_first.is_empty() && lines.is_empty())
                    && used.saturating_add(cost) > max_bytes
                {
                    // Keep what this file has already yielded before stopping.
                    if !lines.is_empty() {
                        lines.reverse();
                        newest_first.push(RawLogFile { name, lines });
                    }
                    break 'files;
                }
                used += cost;
                lines.push(line.to_string());
            }
            if !lines.is_empty() {
                lines.reverse();
                newest_first.push(RawLogFile { name, lines });
            }
        }
        // Newest-first is how the BUDGET is spent — walking back from the tail
        // is what keeps the freshest evidence. It is not how a log is read, so
        // the files come back oldest-first (their own lines were reversed as
        // each file closed above).
        newest_first.reverse();
        newest_first
    }

    /// Returns the number of corrupt (unparseable) lines across all files.
    pub fn count_corrupt_lines(&self) -> usize {
        self.list_files()
            .iter()
            .map(|p| count_corrupt_in_file(p))
            .sum()
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// A line with no `principal` is about the machine and belongs to everyone.
fn visible_to(owner: Option<&str>, event: &LogEvent) -> bool {
    match (owner, event.principal.as_deref()) {
        (Some(owner), Some(line_owner)) => owner == line_owner,
        _ => true,
    }
}

fn list_log_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("nrr_service_") && n.ends_with(".ndjson"))
                .unwrap_or(false)
        })
        .collect();
    crate::rotation::sort_chronologically(&mut files);
    files
}

fn parse_events_from_file(path: &Path) -> Vec<LogEvent> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

fn count_corrupt_in_file(path: &Path) -> usize {
    let Ok(content) = std::fs::read_to_string(path) else {
        return 0;
    };
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter(|l| serde_json::from_str::<LogEvent>(l).is_err())
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::reason;
    use crate::taxonomy::EventLevel;

    /// Writes NDJSON lines directly to a file — bypasses the writer filter so
    /// reader tests are not affected by allowlist/mode decisions.
    fn write_events_raw(dir: &Path, n: u32) {
        use std::io::Write;
        let date = crate::audit::writer::local_date_string(std::time::SystemTime::now());
        let path = dir.join(format!("nrr_service_{date}-1.ndjson"));
        let mut file = std::fs::File::create(&path).expect("create log file");
        for i in 1..=n {
            let event = crate::event::LogEvent::new(
                format!("evt-{i:04}"),
                1_745_000_000_000 + i as i64 * 1000,
                EventLevel::Info,
                reason::service::STARTED,
            );
            let line = event.to_ndjson().expect("serialize");
            writeln!(file, "{line}").expect("write");
        }
    }

    /// Writes one rotation's worth of raw lines under an explicit file name, so
    /// a test can lay out several rotations of a day.
    fn write_rotation(dir: &Path, name: &str, ids: &[&str]) {
        use std::io::Write;
        let mut file = std::fs::File::create(dir.join(name)).expect("create log file");
        for id in ids {
            let event = crate::event::LogEvent::new(
                (*id).to_string(),
                1_745_000_000_000,
                EventLevel::Info,
                reason::service::STARTED,
            );
            writeln!(file, "{}", event.to_ndjson().expect("serialize")).expect("write");
        }
    }

    /// Every matching event in one page, newest first.
    fn read_all(
        reader: &LogReader,
        filter: &LogQueryFilter,
        audience: &DiagnosticsAudience,
    ) -> Vec<LogEvent> {
        reader
            .page_newest_first(filter, audience, None, usize::MAX, &LogFileIndex::new())
            .events
    }

    fn ids_of(lines: &[String]) -> Vec<String> {
        lines
            .iter()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l).expect("json")["event_id"]
                    .as_str()
                    .expect("event_id")
                    .to_string()
            })
            .collect()
    }

    /// The archive ships the service's logs as the files they were written to,
    /// so the reader has to keep that boundary: rotations oldest-first, each
    /// one's own lines in writing order.
    #[test]
    fn raw_files_keep_each_rotation_separate_and_in_order() {
        let dir = tempfile::tempdir().expect("temp");
        write_rotation(dir.path(), "nrr_service_20260907-1.ndjson", &["a1", "a2"]);
        write_rotation(dir.path(), "nrr_service_20260907-2.ndjson", &["b1"]);

        let files = LogReader::new(dir.path()).recent_raw_files_for(
            usize::MAX,
            &DiagnosticsAudience::Machine,
            None,
        );

        assert_eq!(files.len(), 2);
        assert_eq!(files[0].name, "nrr_service_20260907-1.ndjson");
        assert_eq!(ids_of(&files[0].lines), vec!["a1", "a2"]);
        assert_eq!(files[1].name, "nrr_service_20260907-2.ndjson");
        assert_eq!(ids_of(&files[1].lines), vec!["b1"]);
    }

    /// The budget is spent from the newest end, so a tight one keeps the latest
    /// rotation and drops the earlier ones entirely.
    #[test]
    fn a_tight_budget_keeps_the_newest_rotation() {
        let dir = tempfile::tempdir().expect("temp");
        write_rotation(
            dir.path(),
            "nrr_service_20260907-1.ndjson",
            &["old1", "old2"],
        );
        write_rotation(dir.path(), "nrr_service_20260907-2.ndjson", &["new1"]);

        let files = LogReader::new(dir.path()).recent_raw_files_for(
            200,
            &DiagnosticsAudience::Machine,
            None,
        );

        assert_eq!(files.len(), 1, "{files:?}");
        assert_eq!(files[0].name, "nrr_service_20260907-2.ndjson");
        assert_eq!(ids_of(&files[0].lines), vec!["new1"]);
    }

    /// The archive's raw log section is read top to bottom by a human. It
    /// shipped backwards: newest-first is how the byte budget is spent, and
    /// nothing turned it back before writing, so its first line was the export
    /// itself. The audit twin has always reversed; there was no test here to
    /// notice this one did not.
    #[test]
    fn raw_lines_come_back_oldest_first() {
        let dir = tempfile::tempdir().expect("temp");
        write_events_raw(dir.path(), 5);
        let lines = LogReader::new(dir.path()).recent_raw_lines_for(
            usize::MAX,
            &DiagnosticsAudience::Machine,
            None,
        );
        assert_eq!(lines.len(), 5);

        let ids: Vec<String> = lines
            .iter()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l)
                    .expect("ndjson")
                    .get("event_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string()
            })
            .collect();
        let mut expected = ids.clone();
        expected.sort();
        assert_eq!(ids, expected, "the file must read forward in time");
    }

    /// An unlimited budget is what the archive asks for when the user set no cap
    /// of their own. Passing `usize::MAX` must not overflow the accumulator, and
    /// must not silently drop anything.
    #[test]
    fn an_unlimited_budget_keeps_every_line() {
        let dir = tempfile::tempdir().expect("temp");
        write_events_raw(dir.path(), 40);
        let all = LogReader::new(dir.path()).recent_raw_lines_for(
            usize::MAX,
            &DiagnosticsAudience::Machine,
            None,
        );
        assert_eq!(all.len(), 40);

        // Positive control for the budget itself: a small cap still trims, and
        // trims the OLD end, keeping the newest evidence.
        let trimmed = LogReader::new(dir.path()).recent_raw_lines_for(
            400,
            &DiagnosticsAudience::Machine,
            None,
        );
        assert!(trimmed.len() < all.len(), "a real budget still trims");
        assert_eq!(
            trimmed.last(),
            all.last(),
            "trimming drops the oldest, never the newest"
        );
    }

    /// Appends a single event to a new rotation file.
    fn append_event_raw(dir: &Path, event: crate::event::LogEvent) {
        use std::io::Write;
        let date = crate::audit::writer::local_date_string(std::time::SystemTime::now());
        let path = dir.join(format!("nrr_service_{date}-99.ndjson"));
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .expect("open");
        let line = event.to_ndjson().expect("serialize");
        writeln!(file, "{line}").expect("write");
    }

    #[test]
    fn list_files_empty_dir() {
        let dir = tempfile::tempdir().expect("temp");
        let reader = LogReader::new(dir.path());
        assert!(reader.list_files().is_empty());
    }

    #[test]
    fn list_files_after_writes() {
        let dir = tempfile::tempdir().expect("temp");
        write_events_raw(dir.path(), 3);
        let reader = LogReader::new(dir.path());
        assert_eq!(reader.list_files().len(), 1);
    }

    #[test]
    fn a_page_returns_all_events() {
        let dir = tempfile::tempdir().expect("temp");
        write_events_raw(dir.path(), 5);
        let reader = LogReader::new(dir.path());
        let events = read_all(
            &reader,
            &LogQueryFilter::new(),
            &DiagnosticsAudience::Machine,
        );
        assert_eq!(events.len(), 5);
    }

    #[test]
    fn a_page_filters_by_kind() {
        let dir = tempfile::tempdir().expect("temp");
        write_events_raw(dir.path(), 3); // all service.started

        // Add a service.stopped event directly.
        append_event_raw(
            dir.path(),
            crate::event::LogEvent::new(
                "evt-other",
                1_745_001_000_000,
                EventLevel::Info,
                reason::service::STOPPED,
            ),
        );

        let reader = LogReader::new(dir.path());
        let stopped = read_all(
            &reader,
            &LogQueryFilter::new().kind("service.stopped"),
            &DiagnosticsAudience::Machine,
        );
        assert_eq!(stopped.len(), 1);

        let part = read_all(
            &reader,
            &LogQueryFilter::new().kind("stop"),
            &DiagnosticsAudience::Machine,
        );
        assert_eq!(part.len(), 1, "a fragment of the kind must match");
        let every_service = read_all(
            &reader,
            &LogQueryFilter::new().kind("service."),
            &DiagnosticsAudience::Machine,
        );
        assert_eq!(every_service.len(), 4);
        let mismatched_case = read_all(
            &reader,
            &LogQueryFilter::new().kind("STOPPED"),
            &DiagnosticsAudience::Machine,
        );
        assert_eq!(mismatched_case.len(), 1, "the match is case-insensitive");
    }

    #[test]
    fn ascii_ci_contains_ignores_case_but_not_substance() {
        assert!(ascii_ci_contains("service.stopped", "STOPPED"));
        assert!(ascii_ci_contains("service.stopped", ""));
        assert!(!ascii_ci_contains("service.stopped", "started"));
        assert!(!ascii_ci_contains("short", "way too long"));
    }

    #[test]
    fn a_page_filters_by_time_range() {
        let dir = tempfile::tempdir().expect("temp");
        write_events_raw(dir.path(), 3);
        let reader = LogReader::new(dir.path());

        let late = read_all(
            &reader,
            &LogQueryFilter::new().from_ms(1_745_000_003_000),
            &DiagnosticsAudience::Machine,
        );
        assert_eq!(late.len(), 1, "only the last event is after ts cutoff");
    }

    #[test]
    fn files_sorted_lexicographically() {
        let dir = tempfile::tempdir().expect("temp");
        std::fs::write(dir.path().join("nrr_service_20260423-2.ndjson"), "").unwrap();
        std::fs::write(dir.path().join("nrr_service_20260423-1.ndjson"), "").unwrap();
        std::fs::write(dir.path().join("nrr_service_20260422-1.ndjson"), "").unwrap();

        let reader = LogReader::new(dir.path());
        let names: Vec<_> = reader
            .list_files()
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            [
                "nrr_service_20260422-1.ndjson",
                "nrr_service_20260423-1.ndjson",
                "nrr_service_20260423-2.ndjson",
            ]
        );
    }

    #[test]
    fn corrupt_lines_count() {
        let dir = tempfile::tempdir().expect("temp");
        std::fs::write(
            dir.path().join("nrr_service_20260423-1.ndjson"),
            "not json\n",
        )
        .unwrap();

        let reader = LogReader::new(dir.path());
        assert_eq!(reader.count_corrupt_lines(), 1);
    }

    #[test]
    fn a_correlation_filter_actually_filters() {
        let dir = tempfile::tempdir().expect("temp");
        for (id, decision, revision) in [
            ("evt-1", Some("d-aaa"), Some("rev-1")),
            ("evt-2", Some("d-bbb"), Some("rev-2")),
            ("evt-3", None, None),
        ] {
            let mut event = crate::event::LogEvent::new(
                id.to_string(),
                1_745_000_000_000,
                EventLevel::Info,
                reason::service::STARTED,
            );
            event.correlation.decision_id = decision.map(str::to_string);
            event.correlation.revision_id = revision.map(str::to_string);
            append_event_raw(dir.path(), event);
        }

        let reader = LogReader::new(dir.path());
        let by_decision = read_all(
            &reader,
            &LogQueryFilter::new().decision_id("d-aaa"),
            &DiagnosticsAudience::Machine,
        );
        assert_eq!(by_decision.len(), 1, "decision filter must narrow the list");
        assert_eq!(by_decision[0].event_id, "evt-1");

        let by_revision = read_all(
            &reader,
            &LogQueryFilter::new().revision_id("rev-2"),
            &DiagnosticsAudience::Machine,
        );
        assert_eq!(by_revision.len(), 1);
        assert_eq!(by_revision[0].event_id, "evt-2");
    }

    /// Both read paths are scoped by the reader itself: a principal sees the
    /// machine's lines and its own, the machine-wide reader sees everything.
    #[test]
    fn every_read_path_is_scoped_to_its_audience() {
        let dir = tempfile::tempdir().expect("temp");
        for (id, owner) in [
            ("machine", None),
            ("mine", Some("S-1-5-21-mine")),
            ("theirs", Some("S-1-5-21-theirs")),
        ] {
            let mut event = crate::event::LogEvent::new(
                id,
                1_745_000_000_000,
                EventLevel::Info,
                reason::service::STARTED,
            );
            event.principal = owner.map(str::to_string);
            append_event_raw(dir.path(), event);
        }
        let reader = LogReader::new(dir.path());
        let mine = DiagnosticsAudience::Principal("S-1-5-21-mine".into());

        let mut paged: Vec<_> = read_all(&reader, &LogQueryFilter::new(), &mine)
            .into_iter()
            .map(|e| e.event_id)
            .collect();
        paged.sort();
        assert_eq!(paged, ["machine", "mine"]);
        assert_eq!(
            ids_of(&reader.recent_raw_lines_for(usize::MAX, &mine, None)),
            ["machine", "mine"]
        );

        let machine = DiagnosticsAudience::Machine;
        assert_eq!(read_all(&reader, &LogQueryFilter::new(), &machine).len(), 3);
        assert_eq!(
            reader
                .recent_raw_lines_for(usize::MAX, &machine, None)
                .len(),
            3
        );
    }

    /// Writes `(event_id, created_at)` pairs under an explicit file name.
    fn write_stamped(dir: &Path, name: &str, events: &[(&str, i64)]) {
        use std::io::Write;
        let mut file = std::fs::File::create(dir.join(name)).expect("create log file");
        for (id, ts) in events {
            let event = crate::event::LogEvent::new(
                (*id).to_string(),
                *ts,
                EventLevel::Info,
                reason::service::STARTED,
            );
            writeln!(file, "{}", event.to_ndjson().expect("serialize")).expect("write");
        }
    }

    fn page_ids(events: &[crate::event::LogEvent]) -> Vec<&str> {
        events.iter().map(|e| e.event_id.as_str()).collect()
    }

    /// Every page walked to the end, the way the Logs view pages.
    fn walk_pages(reader: &LogReader, index: &LogFileIndex, limit: usize) -> Vec<Vec<String>> {
        let mut pages = Vec::new();
        let mut before: Option<(i64, String)> = None;
        for _ in 0..100 {
            let page = reader.page_newest_first(
                &LogQueryFilter::new(),
                &DiagnosticsAudience::Machine,
                before.as_ref().map(|(ts, id)| (*ts, id.as_str())),
                limit,
                index,
            );
            before = page
                .events
                .last()
                .map(|e| (e.created_at, e.event_id.clone()));
            pages.push(page.events.into_iter().map(|e| e.event_id).collect());
            if !page.has_more {
                return pages;
            }
        }
        panic!("paging did not terminate");
    }

    #[test]
    fn pages_walk_every_file_newest_first_without_gaps() {
        let dir = tempfile::tempdir().expect("temp");
        write_stamped(
            dir.path(),
            "nrr_service_20260101-1.ndjson",
            &[("a", 1), ("b", 2)],
        );
        write_stamped(
            dir.path(),
            "nrr_service_20260101-2.ndjson",
            &[("c", 3), ("d", 4)],
        );
        write_stamped(dir.path(), "nrr_service_20260102-1.ndjson", &[("e", 5)]);

        let pages = walk_pages(&LogReader::new(dir.path()), &LogFileIndex::new(), 2);

        assert_eq!(pages, [vec!["e", "d"], vec!["c", "b"], vec!["a"]]);
    }

    /// Rotation names follow the local date; a clock stepped back leaves a
    /// newer-named file holding older entries. Order follows the entries.
    #[test]
    fn pages_follow_timestamps_not_file_names() {
        let dir = tempfile::tempdir().expect("temp");
        write_stamped(dir.path(), "nrr_service_20260101-1.ndjson", &[("late", 50)]);
        write_stamped(
            dir.path(),
            "nrr_service_20260102-1.ndjson",
            &[("early", 10)],
        );

        let pages = walk_pages(&LogReader::new(dir.path()), &LogFileIndex::new(), 1);

        assert_eq!(pages, [vec!["late"], vec!["early"]]);
    }

    /// A page stops before a file that cannot outrank what it holds, and an
    /// unchanged file is not indexed again.
    #[test]
    fn a_page_skips_files_it_cannot_draw_from() {
        let dir = tempfile::tempdir().expect("temp");
        write_stamped(dir.path(), "nrr_service_20260101-1.ndjson", &[("old", 1)]);
        write_stamped(
            dir.path(),
            "nrr_service_20260102-1.ndjson",
            &[("x", 5), ("y", 6)],
        );
        let reader = LogReader::new(dir.path());
        let index = LogFileIndex::new();
        let first = reader.page_newest_first(
            &LogQueryFilter::new(),
            &DiagnosticsAudience::Machine,
            None,
            1,
            &index,
        );
        assert_eq!(page_ids(&first.events), ["y"]);
        assert!(first.has_more);

        // Rewrite the old file behind the index's back — same length and mtime,
        // now holding the newest entry. Only a page that reopened it, or an
        // index that re-read it, could surface that entry.
        let old = dir.path().join("nrr_service_20260101-1.ndjson");
        let meta = std::fs::metadata(&old).expect("meta");
        write_stamped(dir.path(), "nrr_service_20260101-1.ndjson", &[("new", 9)]);
        assert_eq!(std::fs::metadata(&old).expect("meta").len(), meta.len());
        std::fs::File::options()
            .write(true)
            .open(&old)
            .expect("reopen")
            .set_modified(meta.modified().expect("mtime"))
            .expect("restore mtime");

        let again = reader.page_newest_first(
            &LogQueryFilter::new(),
            &DiagnosticsAudience::Machine,
            None,
            1,
            &index,
        );
        assert_eq!(page_ids(&again.events), ["y"]);
    }

    #[test]
    fn a_page_honours_the_time_window_and_the_audience() {
        let dir = tempfile::tempdir().expect("temp");
        let name = "nrr_service_20260101-1.ndjson";
        write_stamped(dir.path(), name, &[("t1", 1), ("t2", 2)]);
        let mut theirs = crate::event::LogEvent::new(
            "theirs".to_string(),
            3,
            EventLevel::Info,
            reason::service::STARTED,
        );
        theirs.principal = Some("S-1-5-21-other".into());
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(dir.path().join(name))
                .expect("open");
            writeln!(file, "{}", theirs.to_ndjson().expect("serialize")).expect("write");
        }
        let reader = LogReader::new(dir.path());
        let index = LogFileIndex::new();

        let windowed = reader.page_newest_first(
            &LogQueryFilter::new().from_ms(2),
            &DiagnosticsAudience::Machine,
            None,
            10,
            &index,
        );
        assert_eq!(page_ids(&windowed.events), ["theirs", "t2"]);

        let mine = reader.page_newest_first(
            &LogQueryFilter::new(),
            &DiagnosticsAudience::Principal("S-1-5-21-mine".into()),
            None,
            10,
            &index,
        );
        assert_eq!(page_ids(&mine.events), ["t2", "t1"]);
        assert!(!mine.has_more);
    }
}
