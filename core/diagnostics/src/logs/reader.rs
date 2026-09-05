//! Operational log reader.
//!
//! Simple NDJSON file scanner for querying operational logs.
//! No hash chain verification (operational logs are not tamper-protected;
//! only the audit trail has a rolling hash chain).

use std::path::{Path, PathBuf};

use crate::event::LogEvent;
use crate::taxonomy::{EventCategory, EventLevel};

// ── LogQueryFilter ────────────────────────────────────────────────────────────

/// Filter for operational log queries.
#[derive(Clone, Debug, Default)]
pub struct LogQueryFilter {
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
    pub level_min: Option<EventLevel>,
    pub category: Option<EventCategory>,
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
        if let Some(k) = &self.kind {
            if &event.kind != k {
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

    /// Scans all log files and returns matching events.
    pub fn scan(&self, filter: &LogQueryFilter) -> Vec<LogEvent> {
        let mut results = Vec::new();
        for path in self.list_files() {
            for event in parse_events_from_file(&path) {
                if filter.matches(&event) {
                    results.push(event);
                }
            }
        }
        results
    }

    /// Raw NDJSON lines from the newest files, newest-first, within a byte
    /// budget — and only the ones `owner` may see.
    ///
    /// The archive ships these VERBATIM: the DTO listing drops payloads, and a
    /// support bundle without them describes symptoms with the evidence
    /// removed. `owner` is `None` for a reader entitled to the whole machine;
    /// otherwise a line is kept when it belongs to nobody (boot, adapters,
    /// service lifecycle) or to that principal. `from_ms` trims to a session
    /// window the same way the wire filter does.
    ///
    /// Walks files newest-first and stops as soon as the budget is met, so
    /// asking for the last few hundred KiB never pulls the whole retention cap
    /// into memory.
    pub fn recent_raw_lines_for(
        &self,
        max_bytes: usize,
        owner: Option<&str>,
        from_ms: Option<i64>,
    ) -> Vec<String> {
        if max_bytes == 0 {
            return Vec::new();
        }
        let mut newest_first: Vec<String> = Vec::new();
        let mut used: usize = 0;
        'files: for path in self.list_files().into_iter().rev() {
            let Ok(contents) = std::fs::read_to_string(&path) else {
                continue;
            };
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
                if !newest_first.is_empty() && used.saturating_add(cost) > max_bytes {
                    break 'files;
                }
                used += cost;
                newest_first.push(line.to_string());
            }
        }
        // Newest-first is how the BUDGET is spent — walking back from the tail
        // is what keeps the freshest evidence. It is not how a log is read.
        // Written out unreversed, the archive's `service-logs.ndjson` ran
        // backwards: its first line was the export itself and its last line the
        // oldest kept event. The audit twin (`AuditReader::recent_raw_lines`)
        // has always reversed here; this one forgot, and the two now agree.
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

    /// The archive's raw log section is read top to bottom by a human. It
    /// shipped backwards: newest-first is how the byte budget is spent, and
    /// nothing turned it back before writing, so the first line of
    /// `service-logs.ndjson` was the export itself. The audit twin has always
    /// reversed; there was no test here to notice this one did not.
    #[test]
    fn raw_lines_come_back_oldest_first() {
        let dir = tempfile::tempdir().expect("temp");
        write_events_raw(dir.path(), 5);
        let lines = LogReader::new(dir.path()).recent_raw_lines_for(usize::MAX, None, None);
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
        let all = LogReader::new(dir.path()).recent_raw_lines_for(usize::MAX, None, None);
        assert_eq!(all.len(), 40);

        // Positive control for the budget itself: a small cap still trims, and
        // trims the OLD end, keeping the newest evidence.
        let trimmed = LogReader::new(dir.path()).recent_raw_lines_for(400, None, None);
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
    fn scan_returns_all_events() {
        let dir = tempfile::tempdir().expect("temp");
        write_events_raw(dir.path(), 5);
        let reader = LogReader::new(dir.path());
        let events = reader.scan(&LogQueryFilter::new());
        assert_eq!(events.len(), 5);
    }

    #[test]
    fn scan_filters_by_kind() {
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
        let stopped = reader.scan(&LogQueryFilter::new().kind("service.stopped"));
        assert_eq!(stopped.len(), 1);
    }

    #[test]
    fn scan_filters_by_time_range() {
        let dir = tempfile::tempdir().expect("temp");
        write_events_raw(dir.path(), 3);
        let reader = LogReader::new(dir.path());

        let late = reader.scan(&LogQueryFilter::new().from_ms(1_745_000_003_000));
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
        let by_decision = reader.scan(&LogQueryFilter::new().decision_id("d-aaa"));
        assert_eq!(by_decision.len(), 1, "decision filter must narrow the list");
        assert_eq!(by_decision[0].event_id, "evt-1");

        let by_revision = reader.scan(&LogQueryFilter::new().revision_id("rev-2"));
        assert_eq!(by_revision.len(), 1);
        assert_eq!(by_revision[0].event_id, "evt-2");
    }
}
