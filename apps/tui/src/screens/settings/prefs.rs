//! The terminal interface's own settings: how it draws, nothing about routing.
//! A small file of its own under the user's configuration directory; the GUI's
//! preferences are never read or written from here.

use std::io;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

const FILE_NAME: &str = "tui.json";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TuiPrefs {
    /// Line mode for screen readers.
    pub plain: bool,
    pub no_color: bool,
    /// Plain characters instead of frame lines.
    pub ascii: bool,
}

/// Where the file lives for this user; `None` when the OS names no
/// configuration directory.
pub fn default_path() -> Option<PathBuf> {
    nrr_platform_api::paths::user_config_root().map(|root| root.join(FILE_NAME))
}

/// The saved settings. A missing or unreadable file is the defaults: a broken
/// file must not keep the program from starting.
pub fn load(path: &Path) -> TuiPrefs {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return TuiPrefs::default();
    };
    let Ok(value) = serde_json::from_str::<Value>(raw.trim_start_matches('\u{feff}')) else {
        return TuiPrefs::default();
    };
    let flag = |name: &str| value.get(name).and_then(Value::as_bool).unwrap_or(false);
    TuiPrefs {
        plain: flag("plain"),
        no_color: flag("no-color"),
        ascii: flag("ascii"),
    }
}

/// Writes through a sibling file and a rename, so an interrupted save leaves
/// the previous settings rather than half a file.
pub fn save(path: &Path, prefs: TuiPrefs) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let body = json!({
        "plain": prefs.plain,
        "no-color": prefs.no_color,
        "ascii": prefs.ascii,
    });
    let text = serde_json::to_string_pretty(&body).map_err(io::Error::other)?;
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, text)?;
    std::fs::rename(&temporary, path)
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
        };
        save(&path, prefs).unwrap_or_else(|e| panic!("save: {e}"));
        assert_eq!(load(&path), prefs);
        std::fs::write(&path, "{ not json").unwrap_or_else(|e| panic!("write: {e}"));
        assert_eq!(load(&path), TuiPrefs::default());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
