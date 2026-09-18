//! `AppPathResolver` platform port: exe name/glob → concrete paths.
//!
//! An `Application` rule names an executable by its file **name** or a filename
//! **glob** (`citymap.exe`, `DiskO*.exe`, `ab.exe`). But the WFP `ALE_APP_ID`
//! condition keys on a real, on-disk **file path** (`FwpmGetAppIdFromFileName0`),
//! not a name — so without a name→path bridge those rules are silently skipped.
//! This port turns a name/glob into the set of concrete exe paths present on the
//! machine so the WFP codegen (a separate worker) can emit one filter per path.
//!
//! Per the policy/mechanism seam (mirrors [`crate::dns_redirect`]):
//!
//! - The [`AppPathResolver`] trait is **neutral** and compiles everywhere; the
//!   decision "which paths does this name resolve to" is the only contract.
//! - [`NoopAppPathResolver`] is the off-Windows / disabled default (empty set).
//! - The real mechanism lives in [`WindowsAppPathResolver`]
//!   (`#[cfg(target_os = "windows")]`), which unions three OS sources behind
//!   small internal functions. The pure glue — the glob matcher, the
//!   case-insensitive union/dedup, and the resolve cache — is unit-testable
//!   without touching the registry, the process list, or the filesystem.
//!
//! Resolution is **never an error**: an app that is not installed / not found
//! simply resolves to an empty `Vec`. Every OS failure degrades to "this source
//! contributed nothing," never a panic or a propagated error.

// `HashMap` and `PathBuf` are used only by the Windows-only `ResolveCache`; gate
// them so non-Windows builds don't flag an unused import.
#[cfg(target_os = "windows")]
use std::collections::HashMap;
#[cfg(target_os = "windows")]
use std::path::PathBuf;

// The neutral `AppPathResolver` PORT + off-platform `NoopAppPathResolver`,
// the pure glob/union helpers (`glob_match` / `dedup_paths`), and the
// `MockAppPathResolver` test double all live in `nrr-platform-api`; re-export so
// `nrr_platform_windows::app_path_resolver::*` paths keep resolving unchanged. Only
// the Windows MECHANISM (`WindowsAppPathResolver` + its `ResolveCache`) stays here.
pub use nrr_platform_api::app_path_resolver::{
    dedup_paths, glob_match, AppPathResolver, MockAppPathResolver, NoopAppPathResolver,
};

// ── Resolve cache (neutral logic; only wired by the Windows impl) ─────────────
//
// Gated to Windows to avoid a dead-code warning on other OSes where no resolver
// consumes it. The clock is injected as an explicit `Instant` in the internal
// methods so the TTL logic is unit-testable with simulated time — the public
// wrapper stamps `Instant::now()`.

/// Short-lived name/glob → paths cache so `resolve` does not re-scan the
/// registry + running processes + filesystem on every policy recompute.
#[cfg(target_os = "windows")]
struct ResolveCache {
    ttl: std::time::Duration,
    entries: std::sync::Mutex<HashMap<String, CacheEntry>>,
}

#[cfg(target_os = "windows")]
struct CacheEntry {
    stored_at: std::time::Instant,
    paths: Vec<PathBuf>,
}

#[cfg(target_os = "windows")]
impl ResolveCache {
    fn new(ttl: std::time::Duration) -> Self {
        Self {
            ttl,
            entries: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Fresh cached value for `key` relative to `now`, or `None` if absent /
    /// expired. A poisoned lock degrades to a cache miss (never panics).
    fn get_at(&self, key: &str, now: std::time::Instant) -> Option<Vec<PathBuf>> {
        let entries = self.entries.lock().ok()?;
        let entry = entries.get(key)?;
        (now.saturating_duration_since(entry.stored_at) < self.ttl).then(|| entry.paths.clone())
    }

    fn put_at(&self, key: &str, paths: Vec<PathBuf>, now: std::time::Instant) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.insert(
                key.to_string(),
                CacheEntry {
                    stored_at: now,
                    paths,
                },
            );
        }
    }

    /// Return the cached value if fresh at `now`, else compute, store, return.
    fn get_or_compute_at<F: FnOnce() -> Vec<PathBuf>>(
        &self,
        key: &str,
        now: std::time::Instant,
        compute: F,
    ) -> Vec<PathBuf> {
        if let Some(hit) = self.get_at(key, now) {
            return hit;
        }
        let computed = compute();
        self.put_at(key, computed.clone(), now);
        computed
    }

    /// Production entry point — stamps the current instant.
    fn get_or_compute<F: FnOnce() -> Vec<PathBuf>>(&self, key: &str, compute: F) -> Vec<PathBuf> {
        self.get_or_compute_at(key, std::time::Instant::now(), compute)
    }

    fn remove(&self, key: &str) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.remove(key);
        }
    }
}

// ── Running-process images ────────────────────────────────────────────────────

/// Lists the image path of every running process.
#[cfg(target_os = "windows")]
type ScanFn = std::sync::Arc<dyn Fn() -> Vec<PathBuf> + Send + Sync>;

/// One process list for every name a pass resolves.
///
/// A recompute resolves its application rules one after another, and a list
/// taken per name opened every process once per rule: 75 rules over 310
/// processes cost 0.8 s on every pass. The list lives for a moment only, so an
/// application that just started is seen by the next pass.
#[cfg(target_os = "windows")]
struct ProcessImages {
    ttl: std::time::Duration,
    scan: ScanFn,
    last: std::sync::Mutex<Option<(std::time::Instant, std::sync::Arc<Vec<PathBuf>>)>>,
}

#[cfg(target_os = "windows")]
impl ProcessImages {
    fn new(scan: ScanFn, ttl: std::time::Duration) -> Self {
        Self {
            ttl,
            scan,
            last: std::sync::Mutex::new(None),
        }
    }

    /// The list taken within `ttl` of `now`, or a fresh one. The lock is held
    /// across the scan, so callers that arrive meanwhile share its result.
    fn at(&self, now: std::time::Instant) -> std::sync::Arc<Vec<PathBuf>> {
        let mut last = self.last.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((taken, images)) = last.as_ref() {
            if now.saturating_duration_since(*taken) < self.ttl {
                return std::sync::Arc::clone(images);
            }
        }
        let images = std::sync::Arc::new((self.scan)());
        *last = Some((now, std::sync::Arc::clone(&images)));
        images
    }
}

/// The images whose file name matches `query`.
#[cfg(target_os = "windows")]
fn matching_images(query: &str, images: &[PathBuf]) -> Vec<PathBuf> {
    images
        .iter()
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| glob_match(query, &name.to_string_lossy()))
        })
        .cloned()
        .collect()
}

// ── Background disk walks ─────────────────────────────────────────────────────

/// One bounded install-root walk for a name or glob.
#[cfg(target_os = "windows")]
type WalkFn = std::sync::Arc<dyn Fn(&str) -> WalkOutcome + Send + Sync>;

/// What one pattern's disk walk produced, and whether a budget cut it short.
///
/// Truncation is carried back rather than logged where it happens: a pass walks
/// every unresolved pattern, and a line per pattern buried the log under the
/// same sentence eighty times every time the cache expired.
#[cfg(target_os = "windows")]
#[derive(Default)]
pub(crate) struct WalkOutcome {
    paths: Vec<PathBuf>,
    /// The install-root walk ran out of budget. The Store walk is not folded in
    /// here: it has its own budget, its own message, and on a real machine it
    /// does not trip, so it still reports where it happens.
    install_root_truncated: bool,
}

/// Told which keys a finished walk answered differently from before.
#[cfg(target_os = "windows")]
type WalksChangedFn = std::sync::Arc<dyn Fn(&[String]) + Send + Sync>;

/// Disk walks served from memory and refreshed off the caller's thread.
///
/// A walk costs up to its file budget per pattern, and seventy-odd patterns for
/// applications that are not installed held the first enforcement pass after a
/// boot for ten seconds — and every pass that found the cache expired since.
/// The caller gets the last known answer at once (an expired one included, so
/// an application found by a walk keeps its filters while the walk repeats);
/// a key never walked answers empty until its first walk lands.
#[cfg(target_os = "windows")]
struct BackgroundWalks {
    shared: std::sync::Arc<WalkShared>,
}

#[cfg(target_os = "windows")]
struct WalkShared {
    walk: WalkFn,
    ttl: std::time::Duration,
    changed: WalksChangedFn,
    state: std::sync::Mutex<WalkState>,
}

#[cfg(target_os = "windows")]
#[derive(Default)]
struct WalkState {
    entries: HashMap<String, CacheEntry>,
    queue: std::collections::VecDeque<String>,
    queued: std::collections::HashSet<String>,
    worker_running: bool,
}

#[cfg(target_os = "windows")]
impl BackgroundWalks {
    fn new(walk: WalkFn, ttl: std::time::Duration, changed: WalksChangedFn) -> Self {
        Self {
            shared: std::sync::Arc::new(WalkShared {
                walk,
                ttl,
                changed,
                state: std::sync::Mutex::new(WalkState::default()),
            }),
        }
    }

    /// The last walk's answer for `key`; a missing or expired one is queued.
    fn known_at(&self, key: &str, now: std::time::Instant) -> Vec<PathBuf> {
        let mut state = self.shared.lock();
        let (paths, fresh) = match state.entries.get(key) {
            Some(entry) => (
                entry.paths.clone(),
                now.saturating_duration_since(entry.stored_at) < self.shared.ttl,
            ),
            None => (Vec::new(), false),
        };
        let mut start_worker = false;
        if !fresh && state.queued.insert(key.to_string()) {
            state.queue.push_back(key.to_string());
            start_worker = !state.worker_running;
            state.worker_running |= start_worker;
        }
        drop(state);
        if start_worker {
            let shared = std::sync::Arc::clone(&self.shared);
            let spawned = std::thread::Builder::new()
                .name("nrr-app-path-walk".into())
                .spawn(move || shared.drain());
            if spawned.is_err() {
                // The queue stays; the next ask tries to start a worker again.
                self.shared.lock().worker_running = false;
            }
        }
        paths
    }

    #[cfg(test)]
    fn wait_idle(&self) {
        while self.shared.lock().worker_running {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }
}

#[cfg(target_os = "windows")]
impl WalkShared {
    fn lock(&self) -> std::sync::MutexGuard<'_, WalkState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Walk every queued key, one at a time, then report what changed once.
    fn drain(&self) {
        let mut changed = Vec::new();
        let mut truncated: Vec<String> = Vec::new();
        loop {
            let key = {
                let mut state = self.lock();
                match state.queue.pop_front() {
                    Some(key) => key,
                    None => {
                        state.worker_running = false;
                        break;
                    }
                }
            };
            let outcome = (self.walk)(&key);
            let paths = outcome.paths;
            if outcome.install_root_truncated {
                truncated.push(key.clone());
            }
            let mut state = self.lock();
            state.queued.remove(&key);
            let previous = state.entries.insert(
                key.clone(),
                CacheEntry {
                    stored_at: std::time::Instant::now(),
                    paths: paths.clone(),
                },
            );
            // A first walk that found nothing changes nothing: the key already
            // answered empty.
            if previous.map_or(!paths.is_empty(), |entry| entry.paths != paths) {
                changed.push(key);
            }
        }
        // Truncation must not look like absence: a pattern whose binary sits
        // past the budget is not enforced, and that reads as a working rule
        // right up to the moment it is not. One line for the pass, not one per
        // pattern — the call sits outside the loop for exactly that reason.
        if let Some(report) = truncation_report(&truncated) {
            tracing::warn!(
                target: "nrr::app_path_resolver",
                patterns = report.patterns,
                sample = %report.sample,
                "install-root search hit its file budget — those applications may be missed, or found only in part, until they run",
            );
        }
        if !changed.is_empty() {
            (self.changed)(&changed);
        }
    }
}

/// What one pass says about the patterns its walks could not finish.
#[cfg(target_os = "windows")]
struct TruncationReport {
    patterns: usize,
    sample: String,
}

/// `None` when nothing was cut short. Otherwise the count plus the first few
/// names — enough to act on, without carrying eighty of them into one line.
#[cfg(target_os = "windows")]
fn truncation_report(patterns: &[String]) -> Option<TruncationReport> {
    const SHOWN: usize = 5;
    if patterns.is_empty() {
        return None;
    }
    let head = patterns
        .iter()
        .take(SHOWN)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    let sample = match patterns.len().checked_sub(SHOWN) {
        Some(rest) if rest > 0 => format!("{head} (+{rest})"),
        _ => head,
    };
    Some(TruncationReport {
        patterns: patterns.len(),
        sample,
    })
}

// ── Production impl (Win32) ───────────────────────────────────────────────────

/// File name of the image behind `pid`, for diagnostics that name a process
/// without exposing where it lives on disk.
#[cfg(target_os = "windows")]
#[must_use]
pub fn image_name_for_pid(pid: u32) -> Option<String> {
    windows_impl::process_image_path(pid).and_then(|p| {
        p.file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
    })
}

#[cfg(target_os = "windows")]
mod windows_impl;

#[cfg(target_os = "windows")]
pub use windows_impl::WindowsAppPathResolver;

// Only the Windows-only cache TTL logic is tested here; the pure glob / dedup /
// Noop / Mock tests live in `nrr-platform-api` with their code.
#[cfg(all(test, target_os = "windows"))]
mod tests;
