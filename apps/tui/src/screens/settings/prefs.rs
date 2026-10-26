//! The terminal interface's own settings: how it draws, nothing about routing.
//! A small file of its own under the user's configuration directory; the GUI's
//! preferences are never read or written from here.

use std::io;
use std::path::{Path, PathBuf};

use nrr_client_logic::conn_trace::TraceGrouping;
use serde_json::{json, Map, Value};

const FILE_NAME: &str = "tui.json";
/// Larger than any file this program writes: past it the file is not ours to
/// trust, and it reads as the defaults rather than as a stall.
pub(crate) const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// The file's top-level object; anything missing, oversized or broken is an
/// empty one. Another user or program may have written it.
pub(crate) fn read_object(path: &Path) -> Map<String, Value> {
    use std::io::Read;
    let Ok(file) = std::fs::File::open(path) else {
        return Map::new();
    };
    let mut raw = String::new();
    let read = file.take(MAX_FILE_BYTES + 1).read_to_string(&mut raw);
    if read.is_err() || raw.len() as u64 > MAX_FILE_BYTES {
        return Map::new();
    }
    match serde_json::from_str::<Value>(raw.trim_start_matches('\u{feff}')) {
        Ok(Value::Object(object)) => object,
        _ => Map::new(),
    }
}

/// Puts `entries` into the file, keeping what other parts of this program
/// wrote there, through a sibling file and a rename.
pub(crate) fn write_merged(path: &Path, entries: Map<String, Value>) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut object = read_object(path);
    object.extend(entries);
    let text = serde_json::to_string_pretty(&Value::Object(object)).map_err(io::Error::other)?;
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, text)?;
    std::fs::rename(&temporary, path)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TuiPrefs {
    /// Line mode for screen readers.
    pub plain: bool,
    pub no_color: bool,
    /// Plain characters instead of frame lines.
    pub ascii: bool,
    /// How the connection trace is grouped, as the GUI keeps its own choice.
    pub trace_grouping: TraceGrouping,
    /// The programs found for a route of their own were told once.
    pub app_groups_offer_told: bool,
    /// Block notices name no destination, as the GUI's own setting.
    pub hide_block_addresses: bool,
    /// The diagnostics archive takes every day's logs, not only this session's.
    /// The detail level is never kept: a raised one is chosen for one archive.
    pub archive_all_logs: bool,
    /// The archive's cap on raw logs, MiB; 0 is none.
    pub archive_log_budget_mib: u64,
}

/// Where the file lives for this user; `None` when the OS names no
/// configuration directory.
pub fn default_path() -> Option<PathBuf> {
    nrr_platform_api::paths::user_config_root().map(|root| root.join(FILE_NAME))
}

/// The saved settings. A missing or unreadable file is the defaults: a broken
/// file must not keep the program from starting.
pub fn load(path: &Path) -> TuiPrefs {
    let value = Value::Object(read_object(path));
    let flag = |name: &str| value.get(name).and_then(Value::as_bool).unwrap_or(false);
    TuiPrefs {
        plain: flag("plain"),
        no_color: flag("no-color"),
        ascii: flag("ascii"),
        app_groups_offer_told: flag("app-groups-offer-told"),
        hide_block_addresses: flag("hide-block-addresses"),
        archive_all_logs: flag("archive-all-logs"),
        archive_log_budget_mib: value
            .get("archive-log-budget-mib")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        trace_grouping: value
            .get("trace-grouping")
            .and_then(Value::as_str)
            .and_then(TraceGrouping::from_slug)
            .unwrap_or_default(),
    }
}

/// Writes through a sibling file and a rename, so an interrupted save leaves
/// the previous settings rather than half a file; what else the file keeps
/// stays.
pub fn save(path: &Path, prefs: TuiPrefs) -> io::Result<()> {
    let body = json!({
        "plain": prefs.plain,
        "no-color": prefs.no_color,
        "ascii": prefs.ascii,
        "trace-grouping": prefs.trace_grouping.slug(),
        "app-groups-offer-told": prefs.app_groups_offer_told,
        "hide-block-addresses": prefs.hide_block_addresses,
        "archive-all-logs": prefs.archive_all_logs,
        "archive-log-budget-mib": prefs.archive_log_budget_mib,
    });
    match body {
        Value::Object(entries) => write_merged(path, entries),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_settings_read_back_and_a_broken_file_is_the_defaults() {
        let dir = std::env::temp_dir().join(format!("nrr-tui-prefs-{}", std::process::id()));
        let path = dir.join(FILE_NAME);
        let prefs = TuiPrefs {
            plain: true,
            no_color: false,
            ascii: true,
            trace_grouping: TraceGrouping::Folder,
            app_groups_offer_told: true,
            hide_block_addresses: true,
            archive_all_logs: true,
            archive_log_budget_mib: 64,
        };
        save(&path, prefs).unwrap_or_else(|e| panic!("save: {e}"));
        assert_eq!(load(&path), prefs);
        std::fs::write(&path, "{ not json").unwrap_or_else(|e| panic!("write: {e}"));
        assert_eq!(load(&path), TuiPrefs::default());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
