//! Who started a program: the ancestry a block notice names beside the app.
//!
//! A blocked `curl.exe` says little on its own; "started by powershell.exe,
//! explorer.exe" tells the user whether they typed it or a script did. The
//! block event carries the image and the user but no process id, and a
//! short-lived program is gone before the notice is built, so the answer comes
//! from a bounded record of process STARTS kept while the service runs, with
//! the live process table as the fallback for whatever started before it.
//!
//! Neutral here: the port, the start record and the walk over it. Only where
//! the starts and the live table come from is per-OS.
//!
//! Image names only, never a path or a command line — a command line can
//! carry a secret, and a notice is shown on screen.

use std::collections::{HashSet, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Ancestors named per notice. Past a handful the chain is the same for every
/// program on the desktop and only pushes the useful part off the line.
pub const MAX_ANCESTRY: usize = 5;

/// Starts remembered at once. A busy build machine starts a few thousand
/// processes in ten minutes; the record is only ever asked about the last few
/// seconds.
pub const START_RING_MAX_ENTRIES: usize = 4096;

/// How long a start is remembered. A notice is built seconds after the drop;
/// the rest of the window is for the parents, which started earlier.
pub const START_RING_MAX_AGE: Duration = Duration::from_secs(10 * 60);

/// Tolerance between the drop's clock reading and the start's. Both are wall
/// clock, but read at different layers with different granularity.
pub const MATCH_SLACK_MS: u64 = 2_000;

/// Hops walked at most, duplicates included — a guard against a table that
/// answers in a loop, not a limit anyone should reach.
const MAX_HOPS: usize = 32;

/// Where a walk ends, the name itself still shown: above the desktop shell,
/// the service host or the init process every program has the same ancestors,
/// and "started by the desktop" or "started by a service" is the answer.
const STOP_AT: &[&str] = &[
    "explorer.exe",
    "services.exe",
    "svchost.exe",
    "wininit.exe",
    "winlogon.exe",
    "userinit.exe",
    "smss.exe",
    "csrss.exe",
    "lsass.exe",
    "systemd",
    "init",
    "launchd",
];

/// Kernel pseudo-processes no user would recognise; the walk ends before them.
const HIDDEN: &[&str] = &[
    "system",
    "idle",
    "registry",
    "secure system",
    "memory compression",
    "[system process]",
    "kthreadd",
];

/// How much of the answer an implementation can give.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineageCoverage {
    /// Never answers.
    Unsupported,
    /// Only processes still running when asked: a program that exited before
    /// the notice was built — the typical blocked one-shot — has no answer.
    LiveOnly,
    /// Starts recorded while the service runs, plus the live table for
    /// anything older.
    History,
}

/// Ancestry of a blocked program. Off the packet path by contract: callers ask
/// once per notice, and an implementation may read the process table.
pub trait ProcessLineagePort: Send + Sync {
    fn coverage(&self) -> LineageCoverage;

    /// Image names of the processes that started the most recent `image_path`
    /// run at or before `at`, nearest parent first, at most [`MAX_ANCESTRY`].
    /// `sid` narrows the match to that user's runs where the source knows the
    /// owner. Empty when nothing is known — never an error.
    fn ancestry_of(&self, image_path: &str, sid: Option<&str>, at: SystemTime) -> Vec<String>;

    /// Release whatever the implementation holds in the OS. Idempotent.
    fn stop(&self) {}
}

/// Answers nothing: platforms without a mechanism, and tests.
pub struct NoopProcessLineage;

impl ProcessLineagePort for NoopProcessLineage {
    fn coverage(&self) -> LineageCoverage {
        LineageCoverage::Unsupported
    }

    fn ancestry_of(&self, _image_path: &str, _sid: Option<&str>, _at: SystemTime) -> Vec<String> {
        Vec::new()
    }
}

/// One process as a table knows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessFacts {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub image_name: String,
    /// Wall-clock Unix ms. `None` when the source cannot tell, which stops a
    /// walk from trusting it as anyone's parent.
    pub started_ms: Option<u64>,
}

/// A source of process facts the walk can ask.
pub trait ProcessTable {
    /// The most recent run of `image` (a basename, compared without case)
    /// started at or before `at_ms`, owned by `sid` when both sides know the
    /// owner.
    fn latest_named(&mut self, image: &str, sid: Option<&str>, at_ms: u64) -> Option<ProcessFacts>;

    /// The process under `pid` that could have started a child at
    /// `child_started_ms`: one that started no later than the child. A pid the
    /// OS handed out again after the parent exited must not answer.
    fn parent_candidate(&mut self, pid: u32, child_started_ms: Option<u64>)
        -> Option<ProcessFacts>;
}

/// Walk from the newest run of `image_path` up through its parents. Tables are
/// asked in order and the first answer wins, so a start record goes before the
/// live table.
pub fn resolve_ancestry(
    tables: &mut [&mut dyn ProcessTable],
    image_path: &str,
    sid: Option<&str>,
    at_ms: u64,
) -> Vec<String> {
    let image = image_basename(image_path);
    if image.is_empty() {
        return Vec::new();
    }
    let horizon = at_ms.saturating_add(MATCH_SLACK_MS);
    let Some(mut child) = tables
        .iter_mut()
        .find_map(|t| t.latest_named(image, sid, horizon))
    else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    let mut visited: HashSet<u32> = HashSet::from([child.pid]);
    for _ in 0..MAX_HOPS {
        if out.len() >= MAX_ANCESTRY {
            break;
        }
        let Some(ppid) = child.parent_pid.filter(|&p| p != 0 && p != child.pid) else {
            break;
        };
        if !visited.insert(ppid) {
            break;
        }
        let Some(parent) = tables
            .iter_mut()
            .find_map(|t| t.parent_candidate(ppid, child.started_ms))
        else {
            break;
        };
        // Checked again here so a table that ignores the bound cannot name a
        // process that took over the pid after the real parent exited.
        if let Some(child_started) = child.started_ms {
            match parent.started_ms {
                Some(p) if p <= child_started => {}
                _ => break,
            }
        }
        let name = image_basename(&parent.image_name);
        if name.is_empty() || is_named_in(HIDDEN, name) {
            break;
        }
        // A browser or a build tool spawns itself in layers; one mention says it.
        if out
            .last()
            .is_none_or(|last| !last.eq_ignore_ascii_case(name))
        {
            out.push(name.to_owned());
        }
        if is_named_in(STOP_AT, name) {
            break;
        }
        child = parent;
    }
    out
}

/// The file name of a path in either separator style; the input when it has
/// none.
#[must_use]
pub fn image_basename(path: &str) -> &str {
    let trimmed = path.trim();
    trimmed.rsplit(['\\', '/']).next().unwrap_or(trimmed).trim()
}

fn is_named_in(list: &[&str], name: &str) -> bool {
    list.iter().any(|n| n.eq_ignore_ascii_case(name))
}

/// Wall-clock Unix ms; zero before the epoch.
#[must_use]
pub fn unix_ms(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// One recorded start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessStartRecord {
    pub pid: u32,
    pub parent_pid: u32,
    /// Basename only; the full path is dropped at the door.
    pub image_name: String,
    pub started_ms: u64,
    /// Owner as the source reported it; `None` matches any user.
    pub sid: Option<String>,
    pub exited_ms: Option<u64>,
}

/// Process starts seen while the service runs, bounded by count and by age.
#[derive(Debug)]
pub struct ProcessStartRing {
    entries: VecDeque<ProcessStartRecord>,
    max_entries: usize,
    max_age_ms: u64,
}

impl Default for ProcessStartRing {
    fn default() -> Self {
        Self::new(START_RING_MAX_ENTRIES, START_RING_MAX_AGE)
    }
}

impl ProcessStartRing {
    #[must_use]
    pub fn new(max_entries: usize, max_age: Duration) -> Self {
        Self {
            entries: VecDeque::new(),
            max_entries: max_entries.max(1),
            max_age_ms: u64::try_from(max_age.as_millis()).unwrap_or(u64::MAX),
        }
    }

    /// Record one start. `image_path` may be a full path; only its basename is
    /// kept.
    pub fn record_start(
        &mut self,
        pid: u32,
        parent_pid: u32,
        image_path: &str,
        started_ms: u64,
        sid: Option<String>,
    ) {
        let image_name = image_basename(image_path);
        if image_name.is_empty() {
            return;
        }
        self.prune(started_ms);
        while self.entries.len() >= self.max_entries {
            self.entries.pop_front();
        }
        self.entries.push_back(ProcessStartRecord {
            pid,
            parent_pid,
            image_name: image_name.to_owned(),
            started_ms,
            sid,
            exited_ms: None,
        });
    }

    /// Mark the newest live run of `pid` as exited at `exited_ms`.
    pub fn record_exit(&mut self, pid: u32, exited_ms: u64) {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .rev()
            .find(|e| e.pid == pid && e.exited_ms.is_none())
        {
            entry.exited_ms = Some(exited_ms);
        }
    }

    /// Forget starts older than the age bound, measured back from `now_ms`.
    pub fn prune(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(self.max_age_ms);
        // Arrival order is start order up to the source's delivery jitter, so
        // a front sweep is enough; a rare late arrival ages out one sweep late.
        while self.entries.front().is_some_and(|e| e.started_ms < cutoff) {
            self.entries.pop_front();
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn facts(e: &ProcessStartRecord) -> ProcessFacts {
        ProcessFacts {
            pid: e.pid,
            parent_pid: Some(e.parent_pid),
            image_name: e.image_name.clone(),
            started_ms: Some(e.started_ms),
        }
    }
}

impl ProcessTable for ProcessStartRing {
    fn latest_named(&mut self, image: &str, sid: Option<&str>, at_ms: u64) -> Option<ProcessFacts> {
        self.entries
            .iter()
            .filter(|e| e.started_ms <= at_ms && e.image_name.eq_ignore_ascii_case(image))
            .filter(|e| match (sid, e.sid.as_deref()) {
                (Some(want), Some(have)) => want.eq_ignore_ascii_case(have),
                _ => true,
            })
            .max_by_key(|e| e.started_ms)
            .map(Self::facts)
    }

    fn parent_candidate(
        &mut self,
        pid: u32,
        child_started_ms: Option<u64>,
    ) -> Option<ProcessFacts> {
        self.entries
            .iter()
            .filter(|e| e.pid == pid)
            .filter(|e| match child_started_ms {
                // Started no later than the child and still alive when it did.
                Some(child) => e.started_ms <= child && e.exited_ms.is_none_or(|x| x >= child),
                None => true,
            })
            .max_by_key(|e| e.started_ms)
            .map(Self::facts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "S-1-5-21-1";
    const BOB: &str = "S-1-5-21-2";

    /// A live table stand-in: fixed facts, answers by pid or name.
    #[derive(Default)]
    struct FakeLive(Vec<ProcessFacts>);

    impl ProcessTable for FakeLive {
        fn latest_named(
            &mut self,
            image: &str,
            _sid: Option<&str>,
            at_ms: u64,
        ) -> Option<ProcessFacts> {
            self.0
                .iter()
                .filter(|p| p.image_name.eq_ignore_ascii_case(image))
                .filter(|p| p.started_ms.is_none_or(|s| s <= at_ms))
                .max_by_key(|p| p.started_ms)
                .cloned()
        }

        fn parent_candidate(&mut self, pid: u32, _child: Option<u64>) -> Option<ProcessFacts> {
            // Deliberately ignores the bound: the walk must reject reuse itself.
            self.0.iter().find(|p| p.pid == pid).cloned()
        }
    }

    fn walk(
        ring: &mut ProcessStartRing,
        live: &mut FakeLive,
        image: &str,
        sid: Option<&str>,
        at: u64,
    ) -> Vec<String> {
        resolve_ancestry(
            &mut [ring as &mut dyn ProcessTable, live as &mut dyn ProcessTable],
            image,
            sid,
            at,
        )
    }

    #[test]
    fn a_one_shot_program_is_named_by_its_recorded_parents() {
        let mut ring = ProcessStartRing::default();
        ring.record_start(
            100,
            50,
            r"\Device\HarddiskVolume3\Windows\explorer.exe",
            1_000,
            None,
        );
        ring.record_start(
            200,
            100,
            r"C:\Program Files\PowerShell\7\pwsh.exe",
            2_000,
            None,
        );
        ring.record_start(
            300,
            200,
            r"\Device\HarddiskVolume3\Windows\System32\curl.exe",
            3_000,
            None,
        );

        let got = walk(
            &mut ring,
            &mut FakeLive::default(),
            r"C:\Windows\System32\CURL.EXE",
            None,
            3_050,
        );
        assert_eq!(got, vec!["pwsh.exe", "explorer.exe"]);
    }

    #[test]
    fn a_parent_that_took_the_pid_after_the_child_started_is_rejected() {
        let mut ring = ProcessStartRing::default();
        ring.record_start(300, 200, "curl.exe", 3_000, None);
        // Pid 200 handed out again after curl started: not its parent.
        ring.record_start(200, 1, "notepad.exe", 4_000, None);
        let mut live = FakeLive(vec![ProcessFacts {
            pid: 200,
            parent_pid: Some(1),
            image_name: "notepad.exe".into(),
            started_ms: Some(4_000),
        }]);

        assert!(walk(&mut ring, &mut live, "curl.exe", None, 3_100).is_empty());
    }

    #[test]
    fn a_live_parent_without_a_start_time_is_not_trusted() {
        let mut ring = ProcessStartRing::default();
        ring.record_start(300, 200, "curl.exe", 3_000, None);
        let mut live = FakeLive(vec![ProcessFacts {
            pid: 200,
            parent_pid: Some(1),
            image_name: "cmd.exe".into(),
            started_ms: None,
        }]);

        assert!(walk(&mut ring, &mut live, "curl.exe", None, 3_100).is_empty());
    }

    #[test]
    fn a_parent_older_than_the_record_comes_from_the_live_table() {
        let mut ring = ProcessStartRing::default();
        ring.record_start(300, 200, "curl.exe", 3_000, None);
        let mut live = FakeLive(vec![
            ProcessFacts {
                pid: 200,
                parent_pid: Some(100),
                image_name: "cmd.exe".into(),
                started_ms: Some(500),
            },
            ProcessFacts {
                pid: 100,
                parent_pid: Some(4),
                image_name: "explorer.exe".into(),
                started_ms: Some(100),
            },
        ]);

        assert_eq!(
            walk(&mut ring, &mut live, "curl.exe", None, 3_100),
            vec!["cmd.exe", "explorer.exe"]
        );
    }

    #[test]
    fn a_parent_that_exited_before_the_child_started_is_not_its_parent() {
        let mut ring = ProcessStartRing::default();
        ring.record_start(200, 1, "old.exe", 1_000, None);
        ring.record_exit(200, 1_500);
        ring.record_start(300, 200, "curl.exe", 3_000, None);

        assert!(walk(&mut ring, &mut FakeLive::default(), "curl.exe", None, 3_100).is_empty());
    }

    #[test]
    fn the_walk_ends_at_the_desktop_shell_and_names_it() {
        let mut ring = ProcessStartRing::default();
        ring.record_start(10, 5, "winlogon.exe", 100, None);
        ring.record_start(20, 10, "userinit.exe", 200, None);
        ring.record_start(30, 20, "explorer.exe", 300, None);
        ring.record_start(40, 30, "cmd.exe", 400, None);
        ring.record_start(50, 40, "curl.exe", 500, None);

        assert_eq!(
            walk(&mut ring, &mut FakeLive::default(), "curl.exe", None, 500),
            vec!["cmd.exe", "explorer.exe"]
        );
    }

    #[test]
    fn kernel_pseudo_processes_are_never_named() {
        let mut ring = ProcessStartRing::default();
        ring.record_start(4, 0, "System", 10, None);
        ring.record_start(50, 4, "tool.exe", 500, None);
        ring.record_start(60, 50, "curl.exe", 600, None);

        assert_eq!(
            walk(&mut ring, &mut FakeLive::default(), "curl.exe", None, 600),
            vec!["tool.exe"]
        );
    }

    #[test]
    fn a_deep_chain_is_capped() {
        let mut ring = ProcessStartRing::default();
        for pid in 1..=10u32 {
            ring.record_start(
                pid,
                pid - 1,
                &format!("step{pid}.exe"),
                u64::from(pid) * 10,
                None,
            );
        }
        let got = walk(&mut ring, &mut FakeLive::default(), "step10.exe", None, 100);
        assert_eq!(got.len(), MAX_ANCESTRY);
        assert_eq!(got[0], "step9.exe");
    }

    #[test]
    fn a_self_spawning_parent_is_named_once() {
        let mut ring = ProcessStartRing::default();
        ring.record_start(10, 1, "explorer.exe", 100, None);
        ring.record_start(20, 10, "browser.exe", 200, None);
        ring.record_start(30, 20, "browser.exe", 300, None);
        ring.record_start(40, 30, "helper.exe", 400, None);

        assert_eq!(
            walk(&mut ring, &mut FakeLive::default(), "helper.exe", None, 400),
            vec!["browser.exe", "explorer.exe"]
        );
    }

    #[test]
    fn the_newest_run_before_the_drop_is_the_one_asked_about() {
        let mut ring = ProcessStartRing::default();
        ring.record_start(10, 1, "script-a.exe", 100, None);
        ring.record_start(20, 1, "script-b.exe", 100, None);
        ring.record_start(30, 10, "curl.exe", 1_000, None);
        ring.record_start(40, 20, "curl.exe", 10_000, None);
        // A run long after the drop (beyond the slack) is not a candidate.
        ring.record_start(50, 1, "curl.exe", 70_000, None);

        assert_eq!(
            walk(
                &mut ring,
                &mut FakeLive::default(),
                "curl.exe",
                None,
                10_100
            ),
            vec!["script-b.exe"]
        );
        assert_eq!(
            walk(&mut ring, &mut FakeLive::default(), "curl.exe", None, 1_100),
            vec!["script-a.exe"]
        );
    }

    #[test]
    fn another_users_run_is_not_matched_when_both_owners_are_known() {
        let mut ring = ProcessStartRing::default();
        ring.record_start(10, 1, "alice-shell.exe", 100, Some(ALICE.into()));
        ring.record_start(11, 1, "bob-shell.exe", 100, Some(BOB.into()));
        ring.record_start(30, 10, "curl.exe", 1_000, Some(ALICE.into()));
        ring.record_start(31, 11, "curl.exe", 1_500, Some(BOB.into()));

        assert_eq!(
            walk(
                &mut ring,
                &mut FakeLive::default(),
                "curl.exe",
                Some(ALICE),
                2_000
            ),
            vec!["alice-shell.exe"]
        );
        assert_eq!(
            walk(&mut ring, &mut FakeLive::default(), "curl.exe", None, 2_000),
            vec!["bob-shell.exe"]
        );
    }

    #[test]
    fn an_unknown_program_has_no_ancestry() {
        let mut ring = ProcessStartRing::default();
        ring.record_start(10, 1, "cmd.exe", 100, None);
        assert!(walk(&mut ring, &mut FakeLive::default(), "curl.exe", None, 200).is_empty());
        assert!(walk(&mut ring, &mut FakeLive::default(), "", None, 200).is_empty());
    }

    #[test]
    fn the_ring_drops_the_oldest_start_at_the_count_bound() {
        let mut ring = ProcessStartRing::new(3, START_RING_MAX_AGE);
        for pid in 1..=5u32 {
            ring.record_start(pid, 0, "p.exe", u64::from(pid), None);
        }
        assert_eq!(ring.len(), 3);
        assert!(ring.parent_candidate(1, None).is_none());
        assert!(ring.parent_candidate(2, None).is_none());
        assert!(ring.parent_candidate(5, None).is_some());
    }

    #[test]
    fn the_ring_forgets_starts_older_than_the_age_bound() {
        let mut ring = ProcessStartRing::new(100, Duration::from_secs(10));
        ring.record_start(1, 0, "old.exe", 1_000, None);
        ring.record_start(2, 0, "mid.exe", 5_000, None);
        ring.record_start(3, 0, "new.exe", 12_000, None);
        assert_eq!(
            ring.len(),
            2,
            "the start older than 10 s before the newest is gone"
        );
        assert!(ring.parent_candidate(1, None).is_none());

        ring.prune(16_000);
        assert_eq!(ring.len(), 1);
        assert!(ring.parent_candidate(3, None).is_some());
    }

    #[test]
    fn the_ring_keeps_only_the_basename() {
        let mut ring = ProcessStartRing::default();
        ring.record_start(1, 0, "/usr/bin/curl", 10, None);
        let facts = ring.latest_named("curl", None, 10).expect("recorded");
        assert_eq!(facts.image_name, "curl");
    }

    #[test]
    fn the_noop_port_answers_nothing() {
        let port = NoopProcessLineage;
        assert_eq!(port.coverage(), LineageCoverage::Unsupported);
        assert!(port
            .ancestry_of("curl.exe", None, SystemTime::now())
            .is_empty());
        port.stop();
    }

    #[test]
    fn basenames_are_taken_in_either_separator_style() {
        assert_eq!(image_basename(r"\Device\HarddiskVolume3\a\b.exe"), "b.exe");
        assert_eq!(image_basename("/usr/bin/curl"), "curl");
        assert_eq!(image_basename("curl.exe"), "curl.exe");
        assert_eq!(image_basename(""), "");
    }
}
