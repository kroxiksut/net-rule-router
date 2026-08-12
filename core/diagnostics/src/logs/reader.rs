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
        true
    }
}

// ── LogReader ─────────────────────────────────────────────────────────────────

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
    files.sort();
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
}
