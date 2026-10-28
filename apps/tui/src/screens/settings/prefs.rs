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

/// The file is there and does not read. It is the user's to fix or free, so
/// nothing is written over it either way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Damaged {
    /// Another program holds it, or its permissions shut this user out: the
    /// content may be fine.
    Unreadable,
    /// Not text, over [`MAX_FILE_BYTES`], not JSON, or not an object.
    Malformed,
}

impl std::fmt::Display for Damaged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the settings file could not be read and is left as it is")
    }
}

impl std::error::Error for Damaged {}

/// The file's top-level object; a missing file is an empty one. Another user
/// or program may have written it.
fn read_file(path: &Path) -> Result<Map<String, Value>, Damaged> {
    use std::io::Read;
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Map::new()),
        Err(_) => return Err(Damaged::Unreadable),
    };
    let mut raw = String::new();
    match file.take(MAX_FILE_BYTES + 1).read_to_string(&mut raw) {
        Err(error) if error.kind() == io::ErrorKind::InvalidData => return Err(Damaged::Malformed),
        // A byte range another program locked.
        Err(_) => return Err(Damaged::Unreadable),
        Ok(_) if raw.len() as u64 > MAX_FILE_BYTES => return Err(Damaged::Malformed),
        Ok(_) => {}
    }
    match serde_json::from_str::<Value>(raw.trim_start_matches('\u{feff}')) {
        Ok(Value::Object(object)) => Ok(object),
        _ => Err(Damaged::Malformed),
    }
}

/// The file's top-level object; a damaged one reads as an empty one, so a
/// broken file never keeps the program from starting.
pub(crate) fn read_object(path: &Path) -> Map<String, Value> {
    read_file(path).unwrap_or_default()
}

/// Why the file there does not read; `None` when it reads or is absent.
pub(crate) fn damaged(path: &Path) -> Option<Damaged> {
    read_file(path).err()
}

/// Why a write was refused over the file there, if that was the reason.
pub(crate) fn damage_of(error: &io::Error) -> Option<Damaged> {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<Damaged>())
        .copied()
}

/// Puts `entries` into the file, keeping what other parts of this program
/// wrote there, through a sibling file and a rename. A damaged file is never
/// replaced: the error says so ([`damage_of`]).
pub(crate) fn write_merged(path: &Path, entries: Map<String, Value>) -> io::Result<()> {
    let mut object = read_file(path).map_err(io::Error::other)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
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

/// The saved settings. A missing or damaged file is the defaults: a broken
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

    /// Whatever made the file unreadable (another program, a bad hand edit, a
    /// disk error), the next save leaves it exactly as it is for the user to
    /// fix, and the run goes on with the defaults.
    #[test]
    fn a_damaged_file_survives_every_save_byte_for_byte() {
        let mut oversized = br#"{"plain": true, "pad": ""#.to_vec();
        oversized.resize(MAX_FILE_BYTES as usize + 16, b'a');
        oversized.extend_from_slice(br#""}"#);
        let damaged_files: [(&str, Vec<u8>); 5] = [
            ("not-json", b"{ \"plain\": true,".to_vec()),
            ("not-an-object", b"[true, false]".to_vec()),
            ("a-string", b"\"plain\"".to_vec()),
            ("not-text", vec![b'{', 0xff, 0xfe, b'}']),
            ("oversized", oversized),
        ];
        for (kind, bytes) in damaged_files {
            let dir = crate::testing::Scratch::new(&format!("prefs-damaged-{kind}"));
            let path = dir.path().join(FILE_NAME);
            std::fs::write(&path, &bytes).unwrap_or_else(|e| panic!("write: {e}"));

            assert_eq!(
                damaged(&path),
                Some(Damaged::Malformed),
                "{kind}: not seen as damaged"
            );
            assert_eq!(load(&path), TuiPrefs::default(), "{kind}");
            let saved = save(
                &path,
                TuiPrefs {
                    ascii: true,
                    ..TuiPrefs::default()
                },
            );
            assert!(
                saved.as_ref().err().and_then(damage_of) == Some(Damaged::Malformed),
                "{kind}: the save was not refused: {saved:?}"
            );
            let mut section = Map::new();
            section.insert("site-notices".to_owned(), json!({}));
            let merged = write_merged(&path, section);
            assert!(
                merged.as_ref().err().and_then(damage_of).is_some(),
                "{kind}: {merged:?}"
            );
            assert!(
                std::fs::read(&path).unwrap_or_else(|e| panic!("read: {e}")) == bytes,
                "{kind}: the damaged file was overwritten"
            );
        }
    }

    /// The first run has no file yet: that is no damage, and the first save
    /// creates it.
    #[test]
    fn a_missing_file_is_created_on_the_first_save() {
        let dir = crate::testing::Scratch::new("prefs-first-save");
        let path = dir.path().join("config").join(FILE_NAME);
        assert_eq!(damaged(&path), None);
        let prefs = TuiPrefs {
            ascii: true,
            ..TuiPrefs::default()
        };
        save(&path, prefs).unwrap_or_else(|e| panic!("save: {e}"));
        assert_eq!(load(&path), prefs);
    }

    /// A file an earlier build wrote reads back whole, and changing one option
    /// keeps every other value, the keys this build does not know included.
    /// Every release adds a sample of its own file; a released one is frozen.
    #[test]
    fn every_released_file_reads_whole_and_keeps_every_value_on_save() {
        let samples = [
            (
                "tui_json_oct18.json",
                include_str!("../../../tests/fixtures/tui_json_oct18.json"),
                TuiPrefs {
                    plain: true,
                    no_color: true,
                    ascii: true,
                    trace_grouping: TraceGrouping::Folder,
                    ..TuiPrefs::default()
                },
            ),
            (
                "tui_json_oct26.json",
                include_str!("../../../tests/fixtures/tui_json_oct26.json"),
                TuiPrefs {
                    plain: true,
                    no_color: true,
                    ascii: true,
                    trace_grouping: TraceGrouping::None,
                    app_groups_offer_told: true,
                    hide_block_addresses: true,
                    archive_all_logs: true,
                    archive_log_budget_mib: 64,
                },
            ),
        ];
        for (sample, text, expected) in samples {
            let dir = crate::testing::Scratch::new(sample);
            let path = dir.path().join(FILE_NAME);
            std::fs::write(&path, text).unwrap_or_else(|e| panic!("write: {e}"));

            let loaded = load(&path);
            assert_eq!(loaded, expected, "{sample}: an option was not read");

            save(
                &path,
                TuiPrefs {
                    plain: false,
                    ..loaded
                },
            )
            .unwrap_or_else(|e| panic!("save: {e}"));
            let mut want: Value =
                serde_json::from_str(text).unwrap_or_else(|e| panic!("{sample}: {e}"));
            let saved: Value = serde_json::from_str(
                &std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read: {e}")),
            )
            .unwrap_or_else(|e| panic!("saved: {e}"));
            want["plain"] = json!(false);
            // Options newer than the sample are written at their defaults.
            if let (Some(want), Some(saved)) = (want.as_object_mut(), saved.as_object()) {
                for (key, value) in saved {
                    want.entry(key.clone()).or_insert_with(|| value.clone());
                }
            }
            assert_eq!(saved, want, "{sample}: a value was lost or changed");
        }
    }
}
