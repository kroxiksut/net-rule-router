//! Once-a-day GitHub release check, fetch side.
//!
//! Counterpart of `nrr_desktop_gui::update_check` (which owns the cache
//! shape/location and the version compare consumed at context build). This
//! module runs in the LAUNCHER as a detached background thread spawned at GUI
//! startup: it never blocks the launch path, times out fast, and only ever
//! writes the small cache file. The user sees the "new version" notification
//! on the app start AFTER a successful fetch — fine for a daily cadence.
//!
//! Network scope: one anonymous GET to the public GitHub API for this
//! repository's latest release. No telemetry, nothing sent beyond the
//! request itself; skipped entirely while the previous check is younger
//! than 24 h.

use nrr_desktop_gui::update_check::{
    cache_path, is_check_due, read_cache, UpdateCheckCache, RELEASES_REPO,
};

/// Spawn the daily check in a background thread (detached — the launcher
/// never joins it; worst case the process exits first and the cache write is
/// lost until the next start). Call once per GUI launch.
pub fn spawn_daily_release_check() {
    std::thread::spawn(|| {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        if !is_check_due(&read_cache(), now_ms) {
            return;
        }
        let Some((tag, url)) = fetch_latest_release() else {
            return;
        };
        let cache = UpdateCheckCache {
            checked_at_ms: now_ms,
            latest_tag: tag,
            html_url: url,
        };
        let path = cache_path();
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(serialized) = serde_json::to_string(&cache) {
            let _ = std::fs::write(path, serialized);
        }
    });
}

/// GET the latest-release `tag_name` + `html_url`. Best-effort: any HTTP or
/// parse failure returns `None` (and the cache keeps its previous content, so
/// a transient offline day never erases a known update).
fn fetch_latest_release() -> Option<(String, String)> {
    let api_url = format!("https://api.github.com/repos/{RELEASES_REPO}/releases/latest");
    let response = ureq::get(&api_url)
        // GitHub requires a UA; name the product honestly.
        .set("User-Agent", "NetRuleRouter-update-check")
        .set("Accept", "application/vnd.github+json")
        .timeout(std::time::Duration::from_secs(5))
        .call()
        .ok()?;
    let body: serde_json::Value = response.into_json().ok()?;
    let tag = body.get("tag_name")?.as_str()?.trim().to_string();
    if tag.is_empty() {
        return None;
    }
    let url = body
        .get("html_url")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    Some((tag, url))
}
