//! Localize the diagnostic archive for the user.
//!
//! The service builds the archive in ITS data dir
//! (`C:\ProgramData\NetRuleRouter\archives`) — correct for a SYSTEM process
//! (it must never write into user-writable, symlink-plantable directories),
//! but hostile to the user: deleting the file needs elevation, and the
//! GUI-side launcher logs can never be collected there (the service must not
//! read user files either). So the LAUNCHER post-processes a successful
//! `diagnostics.export-archive` response:
//!
//! 1. copy the finished zip into the per-user diagnostics dir
//!    (`launcher::user_diagnostics_dir` — Windows `%TEMP%\NetRuleRouter`, Linux
//!    `$XDG_STATE_HOME/netrulerouter`), the same directory the launcher's own
//!    `launcher-{surface}.log` files live in;
//! 2. append those launcher logs into the copy (GUI-side diagnostics the
//!    service-side builder cannot see);
//! 3. rewrite the response's `archive-path` to the copy, keeping the
//!    original under `service-archive-path`.
//!
//! The service's own RAW log lines used to be step 3 here, read off disk —
//! which is why its log directory had to be readable by every account on the
//! machine, and why one user's bundle carried everyone's lines. The service
//! puts them in the archive itself now (the `service-logs/` directory, one
//! file per rotation), scoped to whoever asked for it.
//!
//! Both GUI export buttons then show a folder the user owns outright.
//! Everything is best-effort: any failure returns the response untouched
//! (the ProgramData original still exists and is still reported).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::SystemTime;

use chrono::{Datelike, Timelike};
use serde_json::Value;

/// GUI-side log files worth attaching, resolved against the launcher's own
/// log directory. Missing files are skipped silently (the tray may never
/// have run).
const LAUNCHER_LOG_ENTRIES: &[&str] = &["launcher-main.log", "launcher-tray.log"];

/// Default total byte budget for the raw service operational-log tail attached
/// to the archive, expressed in MiB. `0` means UNLIMITED — every in-window log
/// file is attached whole. NDJSON deflates an order of magnitude, so an
/// unbounded attachment is cheap in the zip and expensive only for a user who
/// deliberately kept months of verbose logs; that user can pick a cap in the
/// diagnostics panel instead of silently losing the evidence they came for.
const DEFAULT_SERVICE_LOG_BUDGET_MIB: u32 = 0;

/// Runtime mirror of the user's "log budget in the archive" preference, in MiB
/// (`0` = unlimited). The preference is persisted only when the UI process
/// exits, so an export mid-session must not re-read the file; the launcher
/// pushes each `NRR_PREFS_JSON:` payload through
/// [`observe_prefs_payload`] instead, and the export path reads the live value.
static SERVICE_LOG_BUDGET_MIB: AtomicU32 = AtomicU32::new(DEFAULT_SERVICE_LOG_BUDGET_MIB);

/// Record the user's chosen budget (MiB; `0` = unlimited) for subsequent
/// exports. Called once with the preferences loaded at startup and again for
/// every preferences round-trip the Qt host emits.
pub fn set_service_log_budget_mib(mib: u32) {
    SERVICE_LOG_BUDGET_MIB.store(mib, Ordering::Relaxed);
}

/// The live budget in BYTES for the export path. `0` = unlimited.
pub fn service_log_budget_bytes() -> u64 {
    u64::from(SERVICE_LOG_BUDGET_MIB.load(Ordering::Relaxed)) * 1024 * 1024
}

/// Pick the archive log budget out of a raw `NRR_PREFS_JSON:` payload and
/// publish it. A payload that is not an object, or that omits the key (an
/// older QML build), leaves the current value alone — additive by
/// construction, exactly like the serde-side `#[serde(default)]` on the field.
pub fn observe_prefs_payload(payload: &str) {
    let Ok(value) = serde_json::from_str::<Value>(payload) else {
        return;
    };
    if let Some(mib) = value.get("archiveLogBudgetMib").and_then(Value::as_u64) {
        set_service_log_budget_mib(u32::try_from(mib).unwrap_or(u32::MAX));
    }
}

/// The per-user destination directory — shared with `diag_log` in `launcher.rs`
/// by construction (`launcher::user_diagnostics_dir`): Windows
/// `%TEMP%\NetRuleRouter`, Linux `$XDG_STATE_HOME/netrulerouter`. The launcher
/// logs this module attaches live here, so the two must resolve identically.
fn user_archive_dir() -> PathBuf {
    crate::launcher::user_diagnostics_dir()
}

/// Post-process a successful `diagnostics.export-archive` response.
/// On success returns the response with `archive-path` rewritten to the
/// user-local copy; on any failure returns the input unchanged.
///
/// `logs_from_ms` mirrors the request's own `logs-from-ms` cutoff (UTC
/// milliseconds since the epoch) that trimmed the archive builder's merged
/// `logs.ndjson` to the current session — `None` means the export covers full
/// history. The launcher's own logs are trimmed to the same window, so a
/// "session" archive does not smuggle in an earlier run's tail.
pub fn localize_export_response(value: Value, logs_from_ms: Option<i64>) -> Value {
    let dir = user_archive_dir();
    localize_export_response_into(value, &dir, &dir, logs_from_ms)
}

/// Testable core: `dest_dir` receives the copy, `log_dir` is scanned for
/// [`LAUNCHER_LOG_ENTRIES`]. Production passes the same directory for both.
fn localize_export_response_into(
    value: Value,
    dest_dir: &Path,
    log_dir: &Path,
    logs_from_ms: Option<i64>,
) -> Value {
    let Some(src) = value.get("archive-path").and_then(Value::as_str) else {
        return value;
    };
    let src_path = Path::new(src);
    let Some(file_name) = src_path.file_name() else {
        return value;
    };
    if fs::create_dir_all(dest_dir).is_err() {
        return value;
    }
    let dest = dest_dir.join(file_name);
    if fs::copy(src_path, &dest).is_err() {
        // Most likely an ACL denial reading the ProgramData original from a
        // non-elevated process — keep the service path so the user still has
        // A path, just not a user-owned one.
        return value;
    }
    let logs_attached = append_attachments(&dest, log_dir, logs_from_ms);
    let original = src.to_string();
    let mut out = value;
    if let Value::Object(map) = &mut out {
        map.insert("service-archive-path".to_string(), Value::String(original));
        map.insert(
            "archive-path".to_string(),
            Value::String(dest.to_string_lossy().into_owned()),
        );
        map.insert(
            "launcher-logs-attached".to_string(),
            Value::Bool(logs_attached),
        );
    }
    out
}

/// Derives the rotated-previous-session sibling of a launcher log file name
/// (`launcher-main.log` -> `launcher-main.prev.log`), matching the naming
/// `rotate_session_log` in `launcher.rs` produces. Falls back to appending a
/// literal `.prev` suffix for a name without a recognizable extension —
/// never hit in practice since [`LAUNCHER_LOG_ENTRIES`] is a fixed list, but
/// keeps this total rather than panicking.
fn previous_session_log_name(name: &str) -> String {
    match Path::new(name).extension().and_then(|ext| ext.to_str()) {
        Some(extension) => Path::new(name)
            .with_extension(format!("prev.{extension}"))
            .to_string_lossy()
            .into_owned(),
        None => format!("{name}.prev"),
    }
}

/// Converts the request's `logs-from-ms` (UTC epoch milliseconds) into a
/// [`SystemTime`] usable for mtime comparisons. Negative/absent values yield
/// `None` (no cutoff, full history) rather than an underflowed duration.
fn cutoff_system_time(logs_from_ms: Option<i64>) -> Option<SystemTime> {
    let ms = logs_from_ms?;
    let ms = u64::try_from(ms).ok()?;
    Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(ms))
}

/// Converts a source file's modification time (falling back to the current
/// instant when unavailable) into a `zip::DateTime` carrying local wall-clock
/// values — the ZIP MS-DOS date/time fields have no timezone, so extractors
/// display whatever is stored as local time. Mirrors
/// `nrr_diagnostics::archive::builder::local_zip_timestamp`'s fallback chain
/// for the DOS year range ([1980, 2107]); falls back further to the zip
/// crate's own UTC-now/1980-epoch default when even that can't be
/// represented. chrono-only: `time::now_local` is unsound in a multithreaded
/// process.
fn local_zip_timestamp_for_source(mtime: Option<SystemTime>) -> zip::DateTime {
    let local = match mtime {
        Some(system_time) => {
            chrono::DateTime::<chrono::Utc>::from(system_time).with_timezone(&chrono::Local)
        }
        None => chrono::Local::now(),
    };
    zip::DateTime::from_date_and_time(
        match u16::try_from(local.year()) {
            Ok(year) => year,
            Err(_) => return zip::DateTime::default_for_write(),
        },
        local.month() as u8,
        local.day() as u8,
        local.hour() as u8,
        local.minute() as u8,
        local.second() as u8,
    )
    .unwrap_or_else(|_| zip::DateTime::default_for_write())
}

/// Zip write options for a copied-in file: same compression as the rest of
/// the archive, stamped with `path`'s own modification time (converted to
/// local wall-clock), not the moment the archive happens to be assembled.
fn zip_options_for_copied_file(path: &Path) -> zip::write::SimpleFileOptions {
    let mtime = fs::metadata(path).and_then(|meta| meta.modified()).ok();
    zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(local_zip_timestamp_for_source(mtime))
}

/// Append the GUI-side launcher logs into the (already-copied) zip. Returns
/// `true` when at least one entry was written. Best-effort: a failure
/// mid-append leaves the copy with whatever entries landed — still a valid zip
/// (`ZipWriter::finish` finalizes the central directory).
///
/// The service's own log lines are NOT read here any more: the service puts
/// them in the archive itself, scoped to whoever asked, which is what let its
/// log directory stop being readable by every account on the machine.
fn append_attachments(zip_path: &Path, log_dir: &Path, logs_from_ms: Option<i64>) -> bool {
    let Ok(file) = fs::OpenOptions::new().read(true).write(true).open(zip_path) else {
        return false;
    };
    let Ok(mut writer) = zip::ZipWriter::new_append(file) else {
        return false;
    };
    let mut any = false;
    let cutoff = cutoff_system_time(logs_from_ms);
    // GUI-side launcher logs, plus the previous session's rotated copy
    // (`launcher-main.prev.log` etc.) when one is present — the current file
    // only ever holds the session that is being archived (see
    // `rotate_session_log` in `launcher.rs`), so the prior session's tail
    // would otherwise be lost the moment a new process starts. Under a
    // session-scoped export the same cutoff that trims the raw service logs
    // applies here too: a rotated copy last written before the window is an
    // earlier session's tail, not context for this bundle (a .prev file from
    // a morning run otherwise reads as "the archive smuggled in old logs").
    for name in LAUNCHER_LOG_ENTRIES {
        for entry_name in [name.to_string(), previous_session_log_name(name)] {
            let source_path = log_dir.join(&entry_name);
            if let (Some(cutoff), Ok(mtime)) = (
                cutoff,
                fs::metadata(&source_path).and_then(|m| m.modified()),
            ) {
                if mtime < cutoff {
                    continue;
                }
            }
            let Ok(content) = fs::read(&source_path) else {
                continue;
            };
            let options = zip_options_for_copied_file(&source_path);
            let started = writer.start_file(entry_name, options).is_ok();
            if started && writer.write_all(&content).is_ok() {
                any = true;
            }
        }
    }
    if writer.finish().is_err() {
        return false;
    }
    any
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn unique_test_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "nrr-archive-localize-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("test dir");
        dir
    }

    fn write_source_zip(path: &Path) {
        let file = fs::File::create(path).expect("create zip");
        let mut w = zip::ZipWriter::new(file);
        w.start_file("manifest.json", zip::write::SimpleFileOptions::default())
            .expect("start entry");
        w.write_all(b"{\"ok\":true}").expect("write entry");
        w.finish().expect("finish zip");
    }

    #[test]
    fn localizes_copy_appends_logs_and_rewrites_path() {
        let src_dir = unique_test_dir("src");
        let dest_dir = unique_test_dir("dest");
        let src = src_dir.join("nrr-diagnostics-test.zip");
        write_source_zip(&src);
        fs::write(src_dir.join("launcher-main.log"), b"log line\n").expect("log");

        let resp = serde_json::json!({
            "archive-path": src.to_string_lossy(),
            "size-bytes": 42,
        });
        // log_dir = src_dir here (that's where the fake launcher log lives).
        let out = localize_export_response_into(resp, &dest_dir, &src_dir, None);

        let new_path = out["archive-path"].as_str().expect("path");
        assert!(
            new_path.starts_with(&*dest_dir.to_string_lossy()),
            "archive-path must point into the user dir, got {new_path}"
        );
        assert_eq!(
            out["service-archive-path"].as_str().expect("original"),
            src.to_string_lossy()
        );
        assert_eq!(out["launcher-logs-attached"], true);

        // The copy is a valid zip holding BOTH the original entry and the log.
        let copied = fs::File::open(new_path).expect("open copy");
        let mut archive = zip::ZipArchive::new(copied).expect("valid zip");
        let names: Vec<String> = (0..archive.len())
            .map(|i| archive.by_index(i).expect("entry").name().to_string())
            .collect();
        assert!(names.contains(&"manifest.json".to_string()));
        assert!(names.contains(&"launcher-main.log".to_string()));
        let mut log = String::new();
        archive
            .by_name("launcher-main.log")
            .expect("log entry")
            .read_to_string(&mut log)
            .expect("read log");
        assert_eq!(log, "log line\n");

        let _ = fs::remove_dir_all(src_dir);
        let _ = fs::remove_dir_all(dest_dir);
    }

    #[test]
    fn attaches_the_rotated_prev_log_alongside_the_current_one() {
        let src_dir = unique_test_dir("prev-src");
        let dest_dir = unique_test_dir("prev-dest");
        let src = src_dir.join("nrr-diagnostics-test.zip");
        write_source_zip(&src);
        fs::write(src_dir.join("launcher-main.log"), b"this session\n").expect("current log");
        fs::write(
            src_dir.join("launcher-main.prev.log"),
            b"previous session\n",
        )
        .expect("prev log");

        let resp = serde_json::json!({ "archive-path": src.to_string_lossy() });
        let out = localize_export_response_into(resp, &dest_dir, &src_dir, None);

        let new_path = out["archive-path"].as_str().expect("path");
        let copied = fs::File::open(new_path).expect("open copy");
        let mut archive = zip::ZipArchive::new(copied).expect("valid zip");
        let names: Vec<String> = (0..archive.len())
            .map(|i| archive.by_index(i).expect("entry").name().to_string())
            .collect();
        assert!(names.contains(&"launcher-main.log".to_string()));
        assert!(
            names.contains(&"launcher-main.prev.log".to_string()),
            "rotated previous-session log must be attached too, got {names:?}"
        );
        let mut prev_log = String::new();
        archive
            .by_name("launcher-main.prev.log")
            .expect("prev log entry")
            .read_to_string(&mut prev_log)
            .expect("read prev log");
        assert_eq!(prev_log, "previous session\n");

        let _ = fs::remove_dir_all(src_dir);
        let _ = fs::remove_dir_all(dest_dir);
    }

    #[test]
    fn session_scope_drops_a_prev_launcher_log_older_than_the_cutoff() {
        let src_dir = unique_test_dir("prev-scope-src");
        let dest_dir = unique_test_dir("prev-scope-dest");
        let src = src_dir.join("nrr-diagnostics-test.zip");
        write_source_zip(&src);
        fs::write(src_dir.join("launcher-main.log"), b"this session\n").expect("current log");
        let prev_path = src_dir.join("launcher-main.prev.log");
        fs::write(&prev_path, b"previous session\n").expect("prev log");
        // Age the rotated copy to two hours before the session cutoff.
        let two_hours_ago = SystemTime::now() - std::time::Duration::from_secs(2 * 3600);
        fs::OpenOptions::new()
            .append(true)
            .open(&prev_path)
            .expect("reopen prev")
            .set_modified(two_hours_ago)
            .expect("age prev log");
        let cutoff_ms = system_time_ms(SystemTime::now() - std::time::Duration::from_secs(3600));

        let resp = serde_json::json!({ "archive-path": src.to_string_lossy() });
        let out = localize_export_response_into(resp, &dest_dir, &src_dir, Some(cutoff_ms));

        let new_path = out["archive-path"].as_str().expect("path");
        let copied = fs::File::open(new_path).expect("open copy");
        let archive = zip::ZipArchive::new(copied).expect("valid zip");
        let names: Vec<String> = archive.file_names().map(str::to_string).collect();
        assert!(
            names.contains(&"launcher-main.log".to_string()),
            "the current session's launcher log stays, got {names:?}"
        );
        assert!(
            !names.contains(&"launcher-main.prev.log".to_string()),
            "a rotated copy older than the session cutoff must be dropped, got {names:?}"
        );

        let _ = fs::remove_dir_all(src_dir);
        let _ = fs::remove_dir_all(dest_dir);
    }

    fn system_time_ms(t: SystemTime) -> i64 {
        t.duration_since(SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_millis() as i64
    }

    #[test]
    fn copied_log_entries_are_stamped_with_local_wall_clock_time() {
        // Regression test for the copy path (`append_attachments`): unlike
        // the archive builder's GENERATED entries (manifest.json, health.json,
        // ...), these are COPIED files. Without the local-time stamping they'd
        // carry whatever default the zip crate picks (UTC "now" or the 1980
        // epoch), which reads as shifted on any machine whose local offset
        // isn't zero.
        let src_dir = unique_test_dir("ts-src");
        let dest_dir = unique_test_dir("ts-dest");
        let src = src_dir.join("nrr-diagnostics-test.zip");
        write_source_zip(&src);
        // Captured around the log file's own write so the assertion can't
        // flake near a wall-clock rollover (second, minute, midnight, ...).
        let before = chrono::Local::now();
        fs::write(src_dir.join("launcher-main.log"), b"log line\n").expect("log");
        let after = chrono::Local::now();

        let resp = serde_json::json!({ "archive-path": src.to_string_lossy() });
        let out = localize_export_response_into(resp, &dest_dir, &src_dir, None);

        let new_path = out["archive-path"].as_str().expect("path");
        let copied = fs::File::open(new_path).expect("open copy");
        let mut archive = zip::ZipArchive::new(copied).expect("valid zip");
        let entry = archive
            .by_name("launcher-main.log")
            .expect("log entry present");
        let mtime = entry
            .last_modified()
            .expect("entry carries a modified time");

        let entry_naive = chrono::NaiveDate::from_ymd_opt(
            mtime.year() as i32,
            mtime.month() as u32,
            mtime.day() as u32,
        )
        .and_then(|date| {
            date.and_hms_opt(
                mtime.hour() as u32,
                mtime.minute() as u32,
                mtime.second() as u32,
            )
        })
        .expect("zip entry stores a valid calendar date/time");

        // DOS timestamps have 2-second resolution and drop odd seconds, so
        // widen the [before, after] window by a few seconds on both ends.
        let tolerance = chrono::Duration::seconds(3);
        let lower = before.naive_local() - tolerance;
        let upper = after.naive_local() + tolerance;
        assert!(
            entry_naive >= lower && entry_naive <= upper,
            "expected copied-entry mtime {entry_naive:?} within [{lower:?}, {upper:?}] \
             (local time), got a value that looks UTC-shifted"
        );

        let _ = fs::remove_dir_all(src_dir);
        let _ = fs::remove_dir_all(dest_dir);
    }

    #[test]
    fn unreadable_source_leaves_response_untouched() {
        let dest_dir = unique_test_dir("dest2");
        let resp = serde_json::json!({
            "archive-path": dest_dir.join("does-not-exist.zip").to_string_lossy(),
        });
        let out = localize_export_response_into(resp.clone(), &dest_dir, &dest_dir, None);
        assert_eq!(out, resp, "a failed copy must not rewrite the response");
        let _ = fs::remove_dir_all(dest_dir);
    }

    #[test]
    fn prefs_payload_publishes_the_budget_and_ignores_an_absent_key() {
        set_service_log_budget_mib(DEFAULT_SERVICE_LOG_BUDGET_MIB);
        assert_eq!(service_log_budget_bytes(), 0, "default is unlimited");

        observe_prefs_payload("{\"archiveLogBudgetMib\":24,\"themeMode\":\"dark\"}");
        assert_eq!(service_log_budget_bytes(), 24 * 1024 * 1024);

        // An older QML build that omits the key must not reset the value.
        observe_prefs_payload("{\"themeMode\":\"light\"}");
        assert_eq!(service_log_budget_bytes(), 24 * 1024 * 1024);
        // Neither must a payload that is not JSON at all.
        observe_prefs_payload("not json");
        assert_eq!(service_log_budget_bytes(), 24 * 1024 * 1024);

        observe_prefs_payload("{\"archiveLogBudgetMib\":0}");
        assert_eq!(service_log_budget_bytes(), 0);
        set_service_log_budget_mib(DEFAULT_SERVICE_LOG_BUDGET_MIB);
    }

    #[test]
    fn response_without_archive_path_passes_through() {
        let dest_dir = unique_test_dir("dest3");
        let resp = serde_json::json!({ "unrelated": 1 });
        let out = localize_export_response_into(resp.clone(), &dest_dir, &dest_dir, None);
        assert_eq!(out, resp);
        let _ = fs::remove_dir_all(dest_dir);
    }
}
