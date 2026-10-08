//! The two rules files: read with the shared preset parser, written with the
//! GUI's writer, and the country rule sets shipped beside the program.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use nrr_client_logic::rules_table::{build_rules_file_text, RuleRow, RulesFileOptions};
use nrr_client_logic::Route;
use nrr_shared::platform_profile::PlatformProfile;
use nrr_shared::preset_parser::parse_canonical_rules;

use super::table::{row_from_parsed, Table};

/// The size cap the GUI's file read has.
const MAX_FILE_BYTES: u64 = 1024 * 1024;

pub fn file_name(route: Route) -> &'static str {
    match route {
        Route::Primary => "rules_primary.txt",
        Route::Secondary => "rules_secondary.txt",
    }
}

fn route_index(route: Route) -> usize {
    match route {
        Route::Primary => 0,
        Route::Secondary => 1,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadError {
    Io(String),
    NotUtf8,
    TooLarge,
}

/// What a rules-file folder held.
#[derive(Debug, Default)]
pub struct RuleSet {
    pub rows: Vec<RuleRow>,
    /// Sections this build reads but does not apply, per route file.
    pub passthrough: [BTreeMap<String, String>; 2],
    pub files: usize,
}

fn read_text(path: &Path) -> Result<Option<String>, ReadError> {
    let size = match std::fs::metadata(path) {
        Ok(meta) => meta.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(ReadError::Io(e.to_string())),
    };
    if size > MAX_FILE_BYTES {
        return Err(ReadError::TooLarge);
    }
    let bytes = std::fs::read(path).map_err(|e| ReadError::Io(e.to_string()))?;
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&bytes);
    String::from_utf8(bytes.to_vec())
        .map(Some)
        .map_err(|_| ReadError::NotUtf8)
}

/// Both files of `dir`; a missing one is not an error, a set with neither is
/// an empty one.
pub fn read_set(dir: &Path) -> Result<RuleSet, (PathBuf, ReadError)> {
    let mut set = RuleSet::default();
    for route in Route::ALL {
        let path = dir.join(file_name(route));
        let Some(text) = read_text(&path).map_err(|e| (path.clone(), e))? else {
            continue;
        };
        set.files += 1;
        let parsed = parse_canonical_rules(&text);
        set.rows
            .extend(parsed.rules.iter().map(|rule| row_from_parsed(rule, route)));
        for block in parsed.passthrough {
            set.passthrough[route_index(route)].insert(block.section_name, block.raw_text);
        }
    }
    Ok(set)
}

/// Whether writing to `dir` would replace a rules file.
pub fn set_exists(dir: &Path) -> bool {
    Route::ALL
        .into_iter()
        .any(|route| dir.join(file_name(route)).exists())
}

/// Both files from the rows on screen, as the GUI writes them.
pub fn write_set(dir: &Path, table: &Table, exported_at: &str) -> Result<(), (PathBuf, String)> {
    std::fs::create_dir_all(dir).map_err(|e| (dir.to_path_buf(), e.to_string()))?;
    let rows: Vec<RuleRow> = table.rows.iter().map(|r| r.rule.clone()).collect();
    for route in Route::ALL {
        let options = RulesFileOptions {
            include_comments: true,
            exported_at,
            passthrough: &table.passthrough[route_index(route)],
            os: PlatformProfile::current().os,
        };
        let path = dir.join(file_name(route));
        std::fs::write(&path, build_rules_file_text(&rows, route, &options))
            .map_err(|e| (path.clone(), e.to_string()))?;
    }
    Ok(())
}

/// A shipped rule set: `<country>/<pack>/` holding at least one rules file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preset {
    /// `<country>_<pack>`, the GUI's label.
    pub label: String,
    pub dir: PathBuf,
}

/// Beside the binary, then — in a development build only — the checkout;
/// never a parent directory, where another user could plant a folder.
fn presets_root() -> Option<PathBuf> {
    let beside = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("presets")));
    #[cfg(debug_assertions)]
    let checkout = Some(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../presets"));
    #[cfg(not(debug_assertions))]
    let checkout: Option<PathBuf> = None;
    beside.into_iter().chain(checkout).find(|dir| dir.is_dir())
}

fn sorted_dirs(dir: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect()
        })
        .unwrap_or_default();
    dirs.sort();
    dirs
}

pub fn presets() -> Vec<Preset> {
    presets_root().map_or_else(Vec::new, |root| presets_in(&root))
}

pub fn presets_in(root: &Path) -> Vec<Preset> {
    let name = |p: &Path| {
        p.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    };
    let mut out = Vec::new();
    for country in sorted_dirs(root) {
        for pack in sorted_dirs(&country) {
            if set_exists(&pack) {
                out.push(Preset {
                    label: format!("{}_{}", name(&country), name(&pack)),
                    dir: pack,
                });
            }
        }
    }
    out
}
