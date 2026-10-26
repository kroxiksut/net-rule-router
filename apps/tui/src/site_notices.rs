//! "A site does not open" in the feed, under the rule every surface keeps:
//! nothing once muted, one such notice per half hour, the same site once a
//! day unless the user answered it (`nrr_client_logic::site_notice`, the
//! tray's and the service's rule too).
//!
//! When each was told and answered is kept in `tui.json` under one section,
//! keyed as the tray's ledger keys it. The file is the user's to edit and
//! anybody's to break: it is read bounded, and whatever cannot be read is
//! forgotten, never a reason to stay silent.

use std::collections::HashMap;
use std::path::Path;

use nrr_client_logic::notice_mutes::SITE_NOT_OPENING_KIND;
use nrr_client_logic::site_notice::{site_notice_due, SAME_SITE_GAP_MS};
use serde_json::{Map, Value};

use crate::screens::settings::prefs;
use crate::state::AppState;

const SECTION: &str = "site-notices";
const SHOWN: &str = "shown";
const SHOWN_SITE: &str = "shown:";
const ANSWERED_SITE: &str = "answered:";
/// Sites remembered, as the service caps its own.
pub const MAX_SITES: usize = 1024;
const MAX_HOST_LEN: usize = 253;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Site {
    shown: Option<i64>,
    answered: Option<i64>,
}

impl Site {
    fn latest(self) -> i64 {
        self.shown.max(self.answered).unwrap_or(0)
    }
}

/// When a notice about a site that does not open was last told, and each
/// site's last notice and answer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SiteNoticeLog {
    shown: Option<i64>,
    sites: HashMap<String, Site>,
}

fn plain_host(host: &str) -> bool {
    !host.is_empty() && host.len() <= MAX_HOST_LEN && !host.chars().any(char::is_control)
}

impl SiteNoticeLog {
    /// Reads the section; a key or value it does not know is skipped.
    fn from_section(section: &Map<String, Value>) -> Self {
        let mut log = Self::default();
        for (key, value) in section {
            let Some(at) = value.as_i64() else { continue };
            if key == SHOWN {
                log.shown = Some(at);
            } else if let Some(host) = key.strip_prefix(SHOWN_SITE).filter(|h| plain_host(h)) {
                log.sites.entry(host.to_owned()).or_default().shown = Some(at);
            } else if let Some(host) = key.strip_prefix(ANSWERED_SITE).filter(|h| plain_host(h)) {
                log.sites.entry(host.to_owned()).or_default().answered = Some(at);
            }
        }
        log.keep_newest();
        log
    }

    fn to_section(&self) -> Map<String, Value> {
        let mut section = Map::new();
        if let Some(at) = self.shown {
            section.insert(SHOWN.to_owned(), Value::from(at));
        }
        for (host, site) in &self.sites {
            if let Some(at) = site.shown {
                section.insert(format!("{SHOWN_SITE}{host}"), Value::from(at));
            }
            if let Some(at) = site.answered {
                section.insert(format!("{ANSWERED_SITE}{host}"), Value::from(at));
            }
        }
        section
    }

    /// At most [`MAX_SITES`], the most recently touched kept.
    fn keep_newest(&mut self) {
        if self.sites.len() <= MAX_SITES {
            return;
        }
        let mut stamps: Vec<i64> = self.sites.values().map(|s| s.latest()).collect();
        stamps.sort_unstable_by(|a, b| b.cmp(a));
        let floor = stamps[MAX_SITES - 1];
        self.sites.retain(|_, s| s.latest() >= floor);
        // Ties at the floor may leave a few too many.
        while self.sites.len() > MAX_SITES {
            let Some(host) = self.sites.keys().next().cloned() else {
                break;
            };
            self.sites.remove(&host);
        }
    }

    /// Whether a notice about `host` may be told at `now_ms`.
    pub fn due(&self, host: &str, muted: bool, now_ms: i64) -> bool {
        let site = self.sites.get(host).copied().unwrap_or_default();
        let answered = match (site.answered, site.shown) {
            (Some(answered), Some(shown)) => answered >= shown,
            (Some(_), None) => true,
            _ => false,
        };
        site_notice_due(muted, self.shown, site.shown, answered, now_ms)
    }

    pub fn told(&mut self, host: &str, now_ms: i64) {
        self.shown = Some(now_ms);
        if plain_host(host) {
            self.forget_stale(now_ms);
            self.sites.entry(host.to_owned()).or_default().shown = Some(now_ms);
            self.keep_newest();
        }
    }

    pub fn answered(&mut self, host: &str, now_ms: i64) {
        if plain_host(host) {
            self.sites.entry(host.to_owned()).or_default().answered = Some(now_ms);
            self.keep_newest();
        }
    }

    /// Sites past their day hold nothing back any more.
    fn forget_stale(&mut self, now_ms: i64) {
        self.sites.retain(|_, s| {
            now_ms.saturating_sub(s.latest()) < SAME_SITE_GAP_MS || s.latest() > now_ms
        });
    }
}

/// The log kept in the file at `path`.
pub fn load(path: &Path) -> SiteNoticeLog {
    match prefs::read_object(path).get(SECTION) {
        Some(Value::Object(section)) => SiteNoticeLog::from_section(section),
        _ => SiteNoticeLog::default(),
    }
}

fn save(app: &AppState) {
    if let Some(path) = app.settings.prefs_path.as_deref() {
        let mut entries = Map::new();
        entries.insert(
            SECTION.to_owned(),
            Value::Object(app.site_notices.to_section()),
        );
        // Unsaved, it holds for this run; the next one may tell once more.
        let _ = prefs::write_merged(path, entries);
    }
}

/// Whether the feed may tell that `host` does not open, and if so, that it
/// was told.
pub fn tell(app: &mut AppState, host: &str) -> bool {
    let now = app.settings.clock.now();
    let muted = crate::notice_mutes::muted(app, SITE_NOT_OPENING_KIND);
    if !app.site_notices.due(host, muted, now) {
        return false;
    }
    app.site_notices.told(host, now);
    save(app);
    true
}

/// The user answered the notices about `hosts`: a rule now carries them.
pub fn answered(app: &mut AppState, hosts: &[String]) {
    if hosts.is_empty() {
        return;
    }
    let now = app.settings.clock.now();
    for host in hosts {
        app.site_notices.answered(host, now);
    }
    save(app);
}

#[cfg(test)]
mod tests;
