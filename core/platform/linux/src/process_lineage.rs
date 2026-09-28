//! Linux mechanism behind [`ProcessLineagePort`]: the live process table in
//! procfs.
//!
//! Live only: a program that exited before the notice was built — the typical
//! blocked one-shot — has no answer here. A start recorder over the kernel's
//! process-event connector would close that gap the way ETW does on Windows;
//! until then the coverage says so and the notice simply names no launcher.
//!
//! Plain procfs reads, no subprocess and nothing that waits on another process.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use nrr_platform_api::process_lineage::{
    image_basename, resolve_ancestry, unix_ms, LineageCoverage, ProcessFacts, ProcessLineagePort,
    ProcessTable,
};

/// Clock ticks per second in procfs times. The kernel reports these in
/// USER_HZ, which is 100 on every architecture this product targets.
const USER_HZ: u64 = 100;

/// Principal spelling of a Linux user, as the service stores it.
const UID_PRINCIPAL_PREFIX: &str = "unix:uid:";

pub struct ProcfsProcessLineage {
    root: PathBuf,
}

impl Default for ProcfsProcessLineage {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcfsProcessLineage {
    #[must_use]
    pub fn new() -> Self {
        Self::with_root("/proc")
    }

    /// A procfs mounted elsewhere; tests point this at a fixture tree.
    #[must_use]
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

impl ProcessLineagePort for ProcfsProcessLineage {
    fn coverage(&self) -> LineageCoverage {
        LineageCoverage::LiveOnly
    }

    fn ancestry_of(&self, image_path: &str, sid: Option<&str>, at: SystemTime) -> Vec<String> {
        let Some(boot_ms) = boot_time_ms(&self.root) else {
            return Vec::new();
        };
        let mut table = ProcfsTable {
            root: &self.root,
            boot_ms,
        };
        resolve_ancestry(&mut [&mut table], image_path, sid, unix_ms(at))
    }
}

struct ProcfsTable<'a> {
    root: &'a Path,
    boot_ms: u64,
}

struct ProcEntry {
    facts: ProcessFacts,
    uid: Option<u32>,
}

impl ProcfsTable<'_> {
    fn read(&self, pid: u32) -> Option<ProcEntry> {
        let dir = self.root.join(pid.to_string());
        let stat = parse_stat(&std::fs::read_to_string(dir.join("stat")).ok()?)?;
        // The executable's name, not `comm`: `comm` is cut at 15 bytes and a
        // program may rename it. Kernel threads have no executable.
        let image_name = std::fs::read_link(dir.join("exe"))
            .ok()
            .and_then(|p| {
                let text = p.to_string_lossy().into_owned();
                let name = image_basename(text.trim_end_matches(" (deleted)")).to_owned();
                (!name.is_empty()).then_some(name)
            })
            .unwrap_or(stat.comm);
        let uid = std::fs::read_to_string(dir.join("status"))
            .ok()
            .and_then(|s| parse_status_uid(&s));
        Some(ProcEntry {
            facts: ProcessFacts {
                pid,
                parent_pid: Some(stat.ppid),
                image_name,
                started_ms: Some(self.boot_ms + stat.start_ticks * 1000 / USER_HZ),
            },
            uid,
        })
    }

    fn pids(&self) -> Vec<u32> {
        std::fs::read_dir(self.root)
            .map(|dir| {
                dir.flatten()
                    .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse().ok()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl ProcessTable for ProcfsTable<'_> {
    fn latest_named(&mut self, image: &str, sid: Option<&str>, at_ms: u64) -> Option<ProcessFacts> {
        let owner = sid
            .and_then(|s| s.strip_prefix(UID_PRINCIPAL_PREFIX))
            .and_then(|uid| uid.parse::<u32>().ok());
        self.pids()
            .into_iter()
            .filter_map(|pid| self.read(pid))
            .filter(|e| e.facts.image_name.eq_ignore_ascii_case(image))
            .filter(|e| match (owner, e.uid) {
                (Some(want), Some(have)) => want == have,
                _ => true,
            })
            .map(|e| e.facts)
            .filter(|f| f.started_ms.is_some_and(|s| s <= at_ms))
            .max_by_key(|f| f.started_ms)
    }

    fn parent_candidate(
        &mut self,
        pid: u32,
        child_started_ms: Option<u64>,
    ) -> Option<ProcessFacts> {
        let facts = self.read(pid)?.facts;
        match (child_started_ms, facts.started_ms) {
            (Some(child), Some(started)) if started <= child => Some(facts),
            (None, _) => Some(facts),
            _ => None,
        }
    }
}

struct Stat {
    comm: String,
    ppid: u32,
    start_ticks: u64,
}

/// `/proc/<pid>/stat`. `comm` sits in parentheses and may itself contain
/// spaces or parentheses, so the fields are counted from the LAST `)`.
fn parse_stat(line: &str) -> Option<Stat> {
    let open = line.find('(')?;
    let close = line.rfind(')')?;
    let comm = line.get(open + 1..close)?.to_owned();
    let mut fields = line.get(close + 1..)?.split_whitespace();
    // Field 3 is the state, 4 the parent, 22 the start time.
    let ppid = fields.nth(1)?.parse().ok()?;
    let start_ticks = fields.nth(17)?.parse().ok()?;
    Some(Stat {
        comm,
        ppid,
        start_ticks,
    })
}

/// Real uid from `/proc/<pid>/status`.
fn parse_status_uid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|uid| uid.parse().ok())
}

/// Boot time from `/proc/stat` (`btime`, Unix seconds), in ms.
fn boot_time_ms(root: &Path) -> Option<u64> {
    std::fs::read_to_string(root.join("stat"))
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("btime "))
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|secs| secs * 1000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    const BOOT_SECS: u64 = 1_000_000;

    fn stat_line(pid: u32, comm: &str, ppid: u32, start_ticks: u64) -> String {
        format!("{pid} ({comm}) S {ppid} 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 {start_ticks} 0 0\n")
    }

    fn fixture(procs: &[(u32, &str, u32, u64, u32)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("stat"),
            format!("cpu 0 0\nbtime {BOOT_SECS}\n"),
        )
        .expect("stat");
        for &(pid, comm, ppid, ticks, uid) in procs {
            let p = dir.path().join(pid.to_string());
            std::fs::create_dir(&p).expect("pid dir");
            std::fs::write(p.join("stat"), stat_line(pid, comm, ppid, ticks)).expect("stat");
            std::fs::write(
                p.join("status"),
                format!("Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
            )
            .expect("status");
        }
        dir
    }

    fn at_ticks(ticks: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(BOOT_SECS * 1000 + ticks * 10)
    }

    #[test]
    fn a_running_program_is_named_by_its_live_parents() {
        let dir = fixture(&[
            (1, "systemd", 0, 1, 0),
            (500, "gnome-terminal-", 1, 100, 1000),
            (600, "bash", 500, 200, 1000),
            (700, "curl", 600, 300, 1000),
        ]);
        let port = ProcfsProcessLineage::with_root(dir.path());
        assert_eq!(port.coverage(), LineageCoverage::LiveOnly);
        assert_eq!(
            port.ancestry_of("/usr/bin/curl", Some("unix:uid:1000"), at_ticks(310)),
            vec!["bash", "gnome-terminal-", "systemd"]
        );
    }

    #[test]
    fn another_users_run_is_not_matched() {
        let dir = fixture(&[(600, "bash", 1, 200, 1000), (700, "curl", 600, 300, 1001)]);
        let port = ProcfsProcessLineage::with_root(dir.path());
        assert!(port
            .ancestry_of("curl", Some("unix:uid:1000"), at_ticks(310))
            .is_empty());
    }

    #[test]
    fn a_reused_parent_pid_is_not_named() {
        // Pid 600 now belongs to a process that started after curl.
        let dir = fixture(&[(600, "later", 1, 400, 1000), (700, "curl", 600, 300, 1000)]);
        let port = ProcfsProcessLineage::with_root(dir.path());
        assert!(port.ancestry_of("curl", None, at_ticks(500)).is_empty());
    }

    #[test]
    fn an_exited_program_has_no_answer() {
        let dir = fixture(&[(600, "bash", 1, 200, 1000)]);
        let port = ProcfsProcessLineage::with_root(dir.path());
        assert!(port.ancestry_of("curl", None, at_ticks(310)).is_empty());
    }

    #[test]
    fn a_missing_procfs_answers_nothing() {
        let port = ProcfsProcessLineage::with_root("/nonexistent-procfs-root");
        assert!(port.ancestry_of("curl", None, SystemTime::now()).is_empty());
    }

    #[test]
    fn stat_is_read_past_a_command_name_with_parentheses() {
        let s = parse_stat(&stat_line(9, "odd) (name", 42, 12345)).expect("parse");
        assert_eq!(
            (s.comm.as_str(), s.ppid, s.start_ticks),
            ("odd) (name", 42, 12345)
        );
        assert!(parse_stat("9 (short) S").is_none());
    }
}
