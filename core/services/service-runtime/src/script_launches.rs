//! Scripts recognised by the rule folder they run from.
//!
//! A rule by folder names programs where they live, and a script's process is
//! an interpreter that lives somewhere else. The observation pass asks here,
//! for a connecting process, which rule folders hold the file its command line
//! runs ([`nrr_platform_api::process_launch`] reads it); the store then keeps
//! the connection in those rules' buckets, as it does for their own programs.
//!
//! Off the traffic path by construction: a command line is read only while a
//! plan has asked about some rule by path, once per process (remembered by its
//! id and start), and the disk is asked about a file only when it lies in a
//! rule folder.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use nrr_platform_api::process_launch::{
    class_path_files, opens_files_it_names, read_launch, LaunchEvidence, Launched, LaunchedFile,
    ProcessLaunchReader,
};
use nrr_shared::app_path::PathStyle;

use crate::app_observation_lookup::AppObservationStore;

/// Processes whose reading is remembered. Only connecting processes are read,
/// and a desktop runs far fewer at once; the oldest gives way.
pub const LAUNCH_CACHE_CAP: usize = 2048;

/// Reads which rule folders the script a process runs lies in.
pub struct ScriptLaunches {
    reader: Arc<dyn ProcessLaunchReader>,
    style: PathStyle,
    cache: Mutex<LaunchCache>,
}

#[derive(Default)]
struct LaunchCache {
    by_pid: HashMap<u32, Started>,
    order: VecDeque<u32>,
}

/// One process's reading.
#[derive(Clone)]
struct Started {
    stamp: u64,
    files: Vec<Candidate>,
}

#[derive(Clone)]
struct Candidate {
    target: Launched,
    /// Counts only if the disk says it runs by itself.
    needs_disk: bool,
    /// The disk's answer, asked once.
    runs: Option<bool>,
}

impl ScriptLaunches {
    #[must_use]
    pub fn new(reader: Arc<dyn ProcessLaunchReader>) -> Self {
        Self {
            reader,
            style: nrr_domain::rules_file::HostPlatform::compiled().path_style(),
            cache: Mutex::new(LaunchCache::default()),
        }
    }

    /// Read command lines as `style` spells paths, so a test of another
    /// platform runs on any host.
    #[must_use]
    pub fn with_path_style(mut self, style: PathStyle) -> Self {
        self.style = style;
        self
    }

    /// The rule paths `store` watches that hold the script process `pid`
    /// (image `image`) runs. Empty while no rule names a path, for a process
    /// that is gone or cannot be read, and for a program that only opens the
    /// files it is given.
    pub fn rule_paths_run_by(
        &self,
        store: &AppObservationStore,
        pid: u32,
        image: &str,
    ) -> Vec<String> {
        if pid == 0 || !store.watches_paths() || opens_files_it_names(image) {
            return Vec::new();
        }
        let Some(stamp) = self.reader.start_stamp(pid) else {
            return Vec::new();
        };
        let Some(mut started) = self.cached(pid, stamp).or_else(|| self.read(pid, stamp)) else {
            return Vec::new();
        };
        let mut keys: Vec<String> = Vec::new();
        let mut asked_disk = false;
        for candidate in &mut started.files {
            let holding = store.rule_paths_holding(&candidate.target);
            if holding.is_empty() {
                continue;
            }
            if candidate.needs_disk {
                let runs = match (candidate.runs, &candidate.target) {
                    (Some(runs), _) => runs,
                    (None, Launched::File(path)) => {
                        asked_disk = true;
                        let runs = self.reader.runs_by_itself(path);
                        candidate.runs = Some(runs);
                        runs
                    }
                    (None, Launched::FilesIn(_)) => false,
                };
                if !runs {
                    continue;
                }
            }
            for key in holding {
                if !keys.contains(&key) {
                    keys.push(key);
                }
            }
        }
        if asked_disk {
            self.remember(pid, started);
        }
        keys
    }

    fn cached(&self, pid: u32, stamp: u64) -> Option<Started> {
        self.cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .by_pid
            .get(&pid)
            .filter(|started| started.stamp == stamp)
            .cloned()
    }

    /// Reads `pid` and remembers the answer, an empty one included, so a
    /// process that cannot be read is not asked again. `None` when the pid
    /// changed hands during the read.
    fn read(&self, pid: u32, stamp: u64) -> Option<Started> {
        let launch = self.reader.launch(pid);
        if self.reader.start_stamp(pid) != Some(stamp) {
            return None;
        }
        let mut files: Vec<LaunchedFile> = Vec::new();
        if let Some(launch) = launch.as_ref() {
            let reading = read_launch(launch, self.style);
            files = reading.files;
            if reading.wants_class_path {
                if let Some(value) = self.reader.class_path(pid) {
                    files.extend(class_path_files(&value, self.style, launch.cwd.as_deref()));
                }
            }
        }
        let started = Started {
            stamp,
            files: files
                .into_iter()
                .map(|file| Candidate {
                    needs_disk: file.evidence == LaunchEvidence::RunsByItself,
                    target: file.target,
                    runs: None,
                })
                .collect(),
        };
        self.remember(pid, started.clone());
        Some(started)
    }

    fn remember(&self, pid: u32, started: Started) {
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if cache.by_pid.insert(pid, started).is_none() {
            cache.order.push_back(pid);
        }
        while cache.order.len() > LAUNCH_CACHE_CAP {
            if let Some(oldest) = cache.order.pop_front() {
                cache.by_pid.remove(&oldest);
            }
        }
    }
}

#[cfg(test)]
mod tests;
