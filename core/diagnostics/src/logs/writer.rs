//! Operational NDJSON log writer with rotation and dropped-event tracking.
//!
//! # File naming
//!
//! Operational log files are stored in a `logs/` directory with names of the
//! form `nrr_service_YYYYMMDD-N.ndjson` (local date, `N` starting at 1).
//! Rotation is triggered when a file exceeds [`LogWriterConfig::max_file_size_bytes`].
//!
//! # Failure policy
//!
//! If writing to the log file fails, the event is silently dropped and the
//! `dropped_count` counter is incremented.  The service must not crash on log
//! write failure.  The dropped count is exposed via [`LogWriter::dropped_count`]
//! for inclusion in the service health status.
//!
//! # Filtering
//!
//! The writer delegates allow/deny decisions to [`LogFilter`].  Only events
//! that pass the filter are serialised and written.  Events rejected by the
//! filter are **not** counted as dropped.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::audit::writer::local_date_string;
use crate::event::LogEvent;
use crate::logs::filter::{LogFilter, LoggingMode};
use crate::sink::DiagnosticsSink;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Default maximum operational log file size before rotation (10 MiB).
pub const DEFAULT_LOG_MAX_FILE_SIZE_BYTES: u64 = 10 * 1024 * 1024;

/// Default gap between checks that the open file still exists on disk.
///
/// Deleting a file does not invalidate a handle already open on it —
/// neither on Windows (the delete is merely posted) nor on Unix (the
/// inode outlives the name). Writes keep succeeding into something
/// nobody can read, so without this probe a single deletion silences
/// the log for the rest of the session. One `stat` per second against
/// two syscalls per event is not measurable.
pub const DEFAULT_LOG_PRESENCE_PROBE_INTERVAL: Duration = Duration::from_secs(1);

// ── LogWriterConfig ───────────────────────────────────────────────────────────

/// Configuration for a [`LogWriter`].
#[derive(Clone, Debug)]
pub struct LogWriterConfig {
    /// Directory where `nrr_service_*.ndjson` files are stored.
    pub logs_dir: PathBuf,
    /// Rotate to a new file when the current exceeds this size (bytes).
    pub max_file_size_bytes: u64,
    /// Initial logging mode.
    pub initial_mode: LoggingMode,
    /// How often to re-check that the open file still exists.
    pub presence_probe_interval: Duration,
}

impl LogWriterConfig {
    pub fn new(logs_dir: impl Into<PathBuf>) -> Self {
        Self {
            logs_dir: logs_dir.into(),
            max_file_size_bytes: DEFAULT_LOG_MAX_FILE_SIZE_BYTES,
            initial_mode: LoggingMode::Default,
            presence_probe_interval: DEFAULT_LOG_PRESENCE_PROBE_INTERVAL,
        }
    }
}

// ── LogWriter internals ───────────────────────────────────────────────────────

/// What [`LogWriterInner::ensure_open`] had to do to hand back a usable
/// file. `Recreated` is the interesting one: it means the log the writer
/// was appending to disappeared from disk under it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OpenOutcome {
    Reused,
    Rotated,
    Recreated,
}

struct LogWriterInner {
    config: LogWriterConfig,
    current: Option<(File, PathBuf)>,
    current_size: u64,
    last_presence_probe: Option<Instant>,
}

// `expect()`s here are invariants/lock-poisoning — panic-worthy, not errors.
#[allow(clippy::expect_used)]
impl LogWriterInner {
    fn new(config: LogWriterConfig) -> Self {
        Self {
            config,
            current: None,
            current_size: 0,
            last_presence_probe: None,
        }
    }

    fn ensure_open(&mut self) -> Result<OpenOutcome, ()> {
        if self.current.is_none() || self.current_size >= self.config.max_file_size_bytes {
            self.rotate().map_err(|_| ())?;
            return Ok(OpenOutcome::Rotated);
        }
        if self.file_vanished() {
            self.rotate().map_err(|_| ())?;
            return Ok(OpenOutcome::Recreated);
        }
        Ok(OpenOutcome::Reused)
    }

    /// Throttled answer to "is the file we hold open still there?".
    /// Between probes the answer is assumed to be yes, which bounds a
    /// deletion to that much lost output instead of the whole session.
    fn file_vanished(&mut self) -> bool {
        let due = match self.last_presence_probe {
            Some(last) => last.elapsed() >= self.config.presence_probe_interval,
            None => true,
        };
        if !due {
            return false;
        }
        self.last_presence_probe = Some(Instant::now());
        match &self.current {
            Some((_, path)) => !path.exists(),
            None => false,
        }
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        self.current = None;
        let path = next_log_filename(&self.config.logs_dir);
        std::fs::create_dir_all(&self.config.logs_dir)?;
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        self.current_size = file.metadata().map(|m| m.len()).unwrap_or(0);
        self.current = Some((file, path));
        self.last_presence_probe = Some(Instant::now());
        Ok(())
    }

    /// Returns `Err(())` on write failure so the caller can increment dropped count.
    fn write_event(&mut self, event: &LogEvent) -> Result<OpenOutcome, ()> {
        let outcome = self.ensure_open()?;
        let line = event.to_ndjson().map_err(|_| ())?;
        let line_nl = format!("{line}\n");
        let (file, _) = self.current.as_mut().expect("open after ensure_open");
        file.write_all(line_nl.as_bytes()).map_err(|_| ())?;
        file.flush().map_err(|_| ())?;
        self.current_size += line_nl.len() as u64;
        Ok(outcome)
    }
}

// ── LogWriter ─────────────────────────────────────────────────────────────────

/// Thread-safe operational NDJSON log writer.
///
/// Implements [`DiagnosticsSink<LogEvent>`].  The writer applies [`LogFilter`]
/// before every write; only events that pass the filter are persisted.
pub struct LogWriter {
    inner: Mutex<LogWriterInner>,
    filter: Arc<LogFilter>,
    dropped: AtomicU64,
    recreated: AtomicU64,
}

impl LogWriter {
    /// Creates a writer using the given configuration.
    ///
    /// Does not open a file until the first qualifying event is emitted.
    pub fn open(config: LogWriterConfig) -> Self {
        let mode = config.initial_mode;
        Self {
            inner: Mutex::new(LogWriterInner::new(config)),
            filter: Arc::new(LogFilter::new(mode)),
            dropped: AtomicU64::new(0),
            recreated: AtomicU64::new(0),
        }
    }

    /// Returns a shared reference to the filter (for mode changes at runtime).
    pub fn filter(&self) -> &LogFilter {
        &self.filter
    }

    /// Number of events dropped since the writer was created due to write failures.
    ///
    /// Events rejected by the filter are **not** counted here.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// How many times the file the writer was appending to disappeared
    /// from disk and had to be opened anew. Non-zero means the log has a
    /// gap: something outside the service deleted the file mid-session.
    pub fn recreated_count(&self) -> u64 {
        self.recreated.load(Ordering::Relaxed)
    }
}

// Lock-poisoning `expect()` propagates a prior panic — not recoverable.
#[allow(clippy::expect_used)]
impl DiagnosticsSink for LogWriter {
    type Event = LogEvent;

    fn emit(&self, event: LogEvent) {
        // Apply filter first — no I/O if the event is not allowed.
        if !self
            .filter
            .should_emit(event.level, event.category, event.privacy_class)
        {
            return;
        }
        let mut inner = self.inner.lock().expect("LogWriter mutex");
        match inner.write_event(&event) {
            Ok(OpenOutcome::Recreated) => {
                self.recreated.fetch_add(1, Ordering::Relaxed);
            }
            Ok(_) => {}
            Err(()) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn flush(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            if let Some((file, _)) = inner.current.as_mut() {
                let _ = file.flush();
            }
        }
    }

    fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

// ── Filename policy ───────────────────────────────────────────────────────────

fn next_log_filename(dir: &Path) -> PathBuf {
    let date = local_date_string(std::time::SystemTime::now());
    let mut n = 1u32;
    loop {
        let name = format!("nrr_service_{date}-{n}.ndjson");
        let path = dir.join(&name);
        if !path.exists() {
            return path;
        }
        n += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::LOG_EVENT_SCHEMA_VERSION;
    use crate::reason;
    use crate::taxonomy::{EventCorrelation, EventLevel};

    fn info_event(id: &str) -> LogEvent {
        LogEvent::new(
            id,
            1_745_000_000_000,
            EventLevel::Info,
            reason::service::STARTED,
        )
    }

    fn debug_event(id: &str) -> LogEvent {
        LogEvent::new(id, 1_745_000_000_000, EventLevel::Debug, reason::cache::HIT)
    }

    fn decision_event(id: &str) -> LogEvent {
        LogEvent::new(
            id,
            1_745_000_000_000,
            EventLevel::Info,
            reason::decision::ROUTE_SELECTED,
        )
    }

    #[test]
    fn log_writer_creates_ndjson_file_on_first_emit() {
        let dir = tempfile::tempdir().expect("temp");
        let writer = LogWriter::open(LogWriterConfig::new(dir.path()));
        writer.emit(info_event("evt-001"));

        let files: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(files.len(), 1);
        let name = files[0].file_name().to_string_lossy().into_owned();
        assert!(name.starts_with("nrr_service_"), "prefix: {name}");
        assert!(name.ends_with(".ndjson"), "ext: {name}");
    }

    /// Deleting a log file does not invalidate the handle the writer
    /// holds on it, so every later write lands somewhere nobody can
    /// read. Observed for real: an operator cleared `logs/` after the
    /// service had started and the whole session went unlogged while
    /// `dropped_count` stayed at zero. The writer has to notice the file
    /// is gone and open a new one.
    #[test]
    fn log_writer_reopens_after_its_file_is_deleted_underneath_it() {
        let dir = tempfile::tempdir().expect("temp");
        let mut config = LogWriterConfig::new(dir.path());
        config.presence_probe_interval = Duration::ZERO; // probe every write
        let writer = LogWriter::open(config);

        writer.emit(info_event("before"));
        let first = std::fs::read_dir(dir.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        std::fs::remove_file(&first).expect("delete the open log file");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);

        writer.emit(info_event("after"));

        let files: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(files.len(), 1, "a fresh log file must appear");
        let content = std::fs::read_to_string(files[0].path()).unwrap();
        assert!(content.contains("after"), "post-deletion event: {content}");
        assert_eq!(writer.recreated_count(), 1);
        assert_eq!(writer.dropped_count(), 0, "the write itself succeeded");
    }

    #[test]
    fn log_writer_does_not_reopen_while_its_file_is_intact() {
        let dir = tempfile::tempdir().expect("temp");
        let mut config = LogWriterConfig::new(dir.path());
        config.presence_probe_interval = Duration::ZERO;
        let writer = LogWriter::open(config);

        writer.emit(info_event("e1"));
        writer.emit(info_event("e2"));
        writer.emit(info_event("e3"));

        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        assert_eq!(writer.recreated_count(), 0);
    }

    #[test]
    fn log_writer_appends_multiple_events() {
        let dir = tempfile::tempdir().expect("temp");
        let writer = LogWriter::open(LogWriterConfig::new(dir.path()));
        writer.emit(info_event("e1"));
        writer.emit(info_event("e2"));
        writer.emit(info_event("e3"));

        let path = std::fs::read_dir(dir.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let content = std::fs::read_to_string(path).unwrap();
        assert_eq!(content.lines().count(), 3);
    }

    #[test]
    fn log_writer_each_line_is_valid_json() {
        let dir = tempfile::tempdir().expect("temp");
        let writer = LogWriter::open(LogWriterConfig::new(dir.path()));
        writer.emit(
            info_event("e1").with_correlation(EventCorrelation::default().with_revision("rev-1")),
        );

        let path = std::fs::read_dir(dir.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        for line in std::fs::read_to_string(path).unwrap().lines() {
            let v: serde_json::Value = serde_json::from_str(line).expect("valid JSON");
            assert_eq!(v["schema_version"], LOG_EVENT_SCHEMA_VERSION as i64);
        }
    }

    #[test]
    fn log_writer_default_mode_filters_debug() {
        let dir = tempfile::tempdir().expect("temp");
        let writer = LogWriter::open(LogWriterConfig::new(dir.path()));
        writer.emit(debug_event("d1")); // Debug < Info — should be filtered.

        // No file should be created if all events were filtered.
        let count = std::fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(count, 0, "debug event must be filtered in default mode");
    }

    #[test]
    fn log_writer_default_mode_filters_decision_category() {
        // Decision events are rate-limited in Default mode; first few pass.
        // But the category itself needs to pass the filter too.
        let dir = tempfile::tempdir().expect("temp");
        let writer = LogWriter::open(LogWriterConfig::new(dir.path()));
        // Decision is in RATE_LIMITED_CATEGORIES and not in default allowlist
        // (it goes through rate limiting logic, but is NOT in default allowlist).
        // Let's verify: Decision is NOT in is_default_allowed().
        // Looking at filter.rs: is_default_allowed only allows Service, Security, Apply, Integrity, Diagnostics.
        // Decision is rate-limited but it's NOT in the allowlist either — so it's blocked.
        writer.emit(decision_event("d1"));
        let count = std::fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(
            count, 0,
            "decision event filtered in default mode (not in allowlist)"
        );
    }

    #[test]
    fn log_writer_diagnostic_mode_allows_decision() {
        let dir = tempfile::tempdir().expect("temp");
        let mut config = LogWriterConfig::new(dir.path());
        config.initial_mode = LoggingMode::Diagnostic;
        let writer = LogWriter::open(config);
        writer.emit(decision_event("d1"));

        let count = std::fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(
            count, 1,
            "decision event must be emitted in diagnostic mode"
        );
    }

    #[test]
    fn log_writer_rotates_when_size_exceeded() {
        let dir = tempfile::tempdir().expect("temp");
        let mut config = LogWriterConfig::new(dir.path());
        config.max_file_size_bytes = 1; // rotate after every event
        let writer = LogWriter::open(config);
        writer.emit(info_event("e1"));
        writer.emit(info_event("e2"));
        writer.emit(info_event("e3"));

        let count = std::fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(count, 3, "one file per event due to tiny max_size");
    }

    #[test]
    fn log_writer_dropped_count_zero_on_success() {
        let dir = tempfile::tempdir().expect("temp");
        let writer = LogWriter::open(LogWriterConfig::new(dir.path()));
        writer.emit(info_event("e1"));
        assert_eq!(writer.dropped_count(), 0);
    }

    #[test]
    fn log_writer_set_mode_dynamically() {
        let dir = tempfile::tempdir().expect("temp");
        let writer = LogWriter::open(LogWriterConfig::new(dir.path()));

        // Default: debug filtered.
        writer.emit(debug_event("d1"));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);

        // Switch to Diagnostic.
        writer.filter().set_mode(LoggingMode::Diagnostic);
        writer.emit(debug_event("d2"));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn log_writer_flush_does_not_panic() {
        let dir = tempfile::tempdir().expect("temp");
        let writer = LogWriter::open(LogWriterConfig::new(dir.path()));
        writer.emit(info_event("e1"));
        writer.flush(); // must not panic
    }

    #[test]
    fn log_writer_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LogWriter>();
    }

    #[test]
    fn filtered_events_not_counted_as_dropped() {
        let dir = tempfile::tempdir().expect("temp");
        let writer = LogWriter::open(LogWriterConfig::new(dir.path()));
        // Emit 10 events that are filtered (debug in default mode).
        for _ in 0..10 {
            writer.emit(debug_event("filtered"));
        }
        assert_eq!(
            writer.dropped_count(),
            0,
            "filtered events must not increment dropped count"
        );
    }
}
