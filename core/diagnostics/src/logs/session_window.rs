//! Session window for "current session only" archive exports.
//!
//! The GUI's session-only checkbox sends the local-midnight floor of its own
//! launch time as the log cutoff. That alone is too coarse: a machine used
//! all day carries morning work sessions the user does not want in an evening
//! support bundle. The refinement here narrows the cutoff to the start of the
//! current *service session cluster* — the chain of service runs separated by
//! less than [`SESSION_GAP_MIN_SECS`] of downtime — while never reaching back
//! past the requested (midnight) floor.
//!
//! In other words the effective cutoff is the most recent of two boundaries:
//! the start of the calendar day the GUI session began, and the first service
//! start that followed a pause of at least thirty minutes. A quick service
//! restart mid-test (crash recovery, settings that require a restart) does
//! not split the session; walking away for the evening does.
//!
//! The cluster is reconstructed from the rotated operational NDJSON files
//! themselves: a file's first record timestamps the run segment's start, its
//! modification time bounds the segment's end. Files are ordered by mtime —
//! rotation indices are not reliable for ordering because retention deletes
//! old files and the writer reuses freed numbers.
//!
//! Everything here fails open: any read/parse problem degrades to the
//! requested cutoff, never to a wider or empty archive.

use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Minimum service downtime that separates two sessions. A pause shorter than
/// this is treated as a restart *within* one working session.
pub const SESSION_GAP_MIN_SECS: u64 = 30 * 60;

/// How many leading bytes of an NDJSON file are read to find the first
/// record's timestamp. One operational record is well under this.
const FIRST_RECORD_PROBE_BYTES: usize = 16 * 1024;

/// Narrow `requested_ms` (the GUI's midnight-floor cutoff) to the start of
/// the current service session cluster, whichever is later.
///
/// Returns `requested_ms` unchanged when the log directory is unreadable,
/// empty, or the cluster cannot be reconstructed — the archive then simply
/// covers the whole day, which is the safe direction for a support bundle.
pub fn refine_session_cutoff_ms(logs_dir: &Path, requested_ms: i64) -> i64 {
    match current_cluster_start_ms(logs_dir) {
        Some(cluster_start_ms) => requested_ms.max(cluster_start_ms),
        None => requested_ms,
    }
}

/// First-record timestamp of the oldest file in the cluster that contains the
/// newest operational log file, or `None` when it cannot be determined.
fn current_cluster_start_ms(logs_dir: &Path) -> Option<i64> {
    let mut segments = operational_segments(logs_dir);
    if segments.is_empty() {
        return None;
    }
    // Oldest → newest by end time (mtime); ties broken by start time so two
    // files rotated within one mtime granule keep their true order.
    segments.sort_by_key(|s| (s.end_ms, s.start_ms));
    let gap_ms = (SESSION_GAP_MIN_SECS * 1000) as i64;
    let mut cluster_start = None;
    let mut previous_end: Option<i64> = None;
    for segment in segments {
        let is_boundary = match previous_end {
            None => true,
            Some(end) => segment.start_ms.saturating_sub(end) >= gap_ms,
        };
        if is_boundary {
            cluster_start = Some(segment.start_ms);
        }
        previous_end = Some(previous_end.unwrap_or(i64::MIN).max(segment.end_ms));
    }
    cluster_start
}

/// One rotated file reduced to its covered time span.
struct Segment {
    start_ms: i64,
    end_ms: i64,
}

/// All readable `nrr_service_*.ndjson` segments in `logs_dir`. Audit files
/// are excluded by the prefix; files whose first record or mtime cannot be
/// read are skipped rather than guessed.
fn operational_segments(logs_dir: &Path) -> Vec<Segment> {
    let Ok(entries) = fs::read_dir(logs_dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
            if !name.starts_with("nrr_service_") || !name.ends_with(".ndjson") {
                return None;
            }
            let mtime = entry.metadata().ok()?.modified().ok()?;
            let end_ms = system_time_to_ms(mtime)?;
            let start_ms = first_record_created_at_ms(&path)?;
            Some(Segment { start_ms, end_ms })
        })
        .collect()
}

fn system_time_to_ms(t: SystemTime) -> Option<i64> {
    t.duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| Duration::as_millis(&d) as i64)
}

/// `created_at` of the file's first NDJSON record, read from a bounded probe
/// of the file head (never the whole file — segments run to tens of MiB).
fn first_record_created_at_ms(path: &Path) -> Option<i64> {
    let mut file = fs::File::open(path).ok()?;
    let mut buf = vec![0u8; FIRST_RECORD_PROBE_BYTES];
    let mut filled = 0usize;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(_) => return None,
        }
    }
    let head = &buf[..filled];
    let line_end = head.iter().position(|&b| b == b'\n').unwrap_or(head.len());
    let line = std::str::from_utf8(&head[..line_end]).ok()?;
    let record: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    record.get("created_at").and_then(serde_json::Value::as_i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_segment(dir: &Path, name: &str, start_ms: i64, end: SystemTime) {
        let path = dir.join(name);
        let mut f = fs::File::create(&path).expect("create segment");
        writeln!(
            f,
            "{{\"schema_version\":1,\"created_at\":{start_ms},\"message\":\"boot\"}}"
        )
        .expect("write record");
        drop(f);
        // Encode the segment end as the file's mtime, exactly as production
        // rotation leaves it.
        let file = fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("reopen");
        file.set_modified(end).expect("set mtime");
    }

    fn ms(t: SystemTime) -> i64 {
        system_time_to_ms(t).expect("epoch ms")
    }

    #[test]
    fn missing_dir_keeps_requested_cutoff() {
        let requested = 1_700_000_000_000;
        assert_eq!(
            refine_session_cutoff_ms(Path::new("Z:/definitely/absent"), requested),
            requested
        );
    }

    #[test]
    fn short_restart_gap_keeps_one_cluster() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = SystemTime::now() - Duration::from_secs(4 * 3600);
        let s1_start = ms(base);
        // Segment 1 ends, segment 2 starts five minutes later: same session.
        write_segment(
            dir.path(),
            "nrr_service_20260725-1.ndjson",
            s1_start,
            base + Duration::from_secs(600),
        );
        write_segment(
            dir.path(),
            "nrr_service_20260725-2.ndjson",
            ms(base + Duration::from_secs(900)),
            base + Duration::from_secs(1800),
        );
        let requested = s1_start - 3_600_000; // midnight well before
        assert_eq!(
            refine_session_cutoff_ms(dir.path(), requested),
            s1_start,
            "a five-minute pause must not split the session"
        );
    }

    #[test]
    fn long_gap_starts_a_new_cluster() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = SystemTime::now() - Duration::from_secs(8 * 3600);
        write_segment(
            dir.path(),
            "nrr_service_20260725-1.ndjson",
            ms(base),
            base + Duration::from_secs(600),
        );
        // 2.5 hours of downtime → the second run opens a new session.
        let s2_start_t = base + Duration::from_secs(600 + 9000);
        let s2_start = ms(s2_start_t);
        write_segment(
            dir.path(),
            "nrr_service_20260725-2.ndjson",
            s2_start,
            s2_start_t + Duration::from_secs(600),
        );
        let requested = ms(base) - 3_600_000;
        assert_eq!(refine_session_cutoff_ms(dir.path(), requested), s2_start);
    }

    #[test]
    fn requested_midnight_wins_over_an_older_cluster_start() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = SystemTime::now() - Duration::from_secs(3600);
        let start = ms(base);
        write_segment(
            dir.path(),
            "nrr_service_20260725-1.ndjson",
            start,
            base + Duration::from_secs(600),
        );
        // "Midnight" after the cluster start (overnight session): the day
        // boundary is the later event and wins.
        let requested = start + 60_000;
        assert_eq!(refine_session_cutoff_ms(dir.path(), requested), requested);
    }

    #[test]
    fn ordering_uses_mtime_not_rotation_index() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = SystemTime::now() - Duration::from_secs(6 * 3600);
        // Retention freed low indices, the writer reused them: "-1" is the
        // NEWEST file despite its name, and follows a long gap.
        let old_start_t = base;
        write_segment(
            dir.path(),
            "nrr_service_20260725-6.ndjson",
            ms(old_start_t),
            old_start_t + Duration::from_secs(600),
        );
        let new_start_t = base + Duration::from_secs(600 + 7200);
        let new_start = ms(new_start_t);
        write_segment(
            dir.path(),
            "nrr_service_20260725-1.ndjson",
            new_start,
            new_start_t + Duration::from_secs(300),
        );
        let requested = ms(base) - 3_600_000;
        assert_eq!(refine_session_cutoff_ms(dir.path(), requested), new_start);
    }
}
