//! The two rules files: read with the shared preset parser, written with the
//! GUI's writer; the country rule sets shipped beside the program, and the
//! sets in the user's own folder, found where the GUI finds them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use nrr_client_logic::passthrough::add_passthrough_block;
use nrr_client_logic::rules_table::{build_rules_file_text, RuleRow, RulesFileOptions};
use nrr_client_logic::Route;
use nrr_shared::platform_profile::PlatformProfile;
use nrr_shared::preset_parser::{app_section_os_label, parse_canonical_rules};

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
    /// The file each route was read from, when the set has one.
    pub paths: [Option<PathBuf>; 2],
    /// Every such section as read, in file order, per route: the answers to
    /// [`RuleSet::questions`] are applied to these.
    pub blocks: [Vec<(String, String)>; 2],
    /// What the user decides before the set lands (the window's import review).
    pub questions: Vec<ReviewQuestion>,
    /// Known sections that appear more than once, with how often: their rules
    /// are all taken, which is only said.
    pub known_duplicates: Vec<(String, u32)>,
}

/// A decision the import asks for, as the window's review does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReviewQuestion {
    /// A section this build does not apply appears more than once.
    Duplicate { name: String, occurrences: u32 },
    /// A section that is neither a rule section nor another system's programs.
    Unknown { name: String, lines: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DuplicateChoice {
    KeepAll,
    LastOnly,
    Ignore,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnknownChoice {
    Keep,
    /// Its lines become rules of the section with this header.
    Refile(&'static str),
    Skip,
}

/// The application section of the system this runs on.
#[cfg(windows)]
pub const OWN_APP_SECTION: &str = "Windows";
#[cfg(target_os = "macos")]
pub const OWN_APP_SECTION: &str = "MacOS";
#[cfg(not(any(windows, target_os = "macos")))]
pub const OWN_APP_SECTION: &str = "Linux";

/// What an unknown section can be refiled as, in the window's order.
pub const REFILE_HEADERS: [&str; 6] = ["Zones", "Domains", "IP", "Ranges", "CIDR", OWN_APP_SECTION];

impl RuleSet {
    /// The answers to [`RuleSet::questions`]: which blocks stay as sections,
    /// which go, and which become rules. A section with no answer stays whole.
    pub fn apply_review(
        &mut self,
        duplicates: &BTreeMap<String, DuplicateChoice>,
        unknown: &BTreeMap<String, UnknownChoice>,
    ) {
        for route in Route::ALL {
            let at = route_index(route);
            let blocks = &self.blocks[at];
            let mut kept = Vec::new();
            for (i, (name, raw)) in blocks.iter().enumerate() {
                let later = blocks[i + 1..].iter().any(|(n, _)| n == name);
                match duplicates.get(name) {
                    Some(DuplicateChoice::Ignore) => continue,
                    Some(DuplicateChoice::LastOnly) if later => continue,
                    _ => {}
                }
                kept.push((name.clone(), raw.clone()));
            }
            let mut passthrough = BTreeMap::new();
            for (name, raw) in kept {
                match unknown.get(&name).copied().unwrap_or(UnknownChoice::Keep) {
                    UnknownChoice::Skip => {}
                    UnknownChoice::Refile(header) => {
                        let text = format!("--- {header}\n{raw}");
                        let parsed = parse_canonical_rules(&text);
                        self.rows
                            .extend(parsed.rules.iter().map(|rule| row_from_parsed(rule, route)));
                    }
                    UnknownChoice::Keep => add_block(&mut passthrough, name, &raw),
                }
            }
            self.passthrough[at] = passthrough;
        }
    }
}

/// Two sections of one name are kept as one, in file order: nothing of the
/// first is lost to the second.
fn add_block(passthrough: &mut BTreeMap<String, String>, name: String, raw: &str) {
    add_passthrough_block(passthrough, &name, raw);
}

pub fn read_text(path: &Path) -> Result<Option<String>, ReadError> {
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
        set.paths[route_index(route)] = Some(path);
        let parsed = parse_canonical_rules(&text);
        set.rows
            .extend(parsed.rules.iter().map(|rule| row_from_parsed(rule, route)));
        for duplicate in &parsed.duplicate_sections {
            let name = duplicate.section_name.clone();
            if duplicate.is_known_section {
                if !set.known_duplicates.iter().any(|(n, _)| *n == name) {
                    set.known_duplicates.push((name, duplicate.occurrences));
                }
            } else if !set
                .questions
                .iter()
                .any(|q| matches!(q, ReviewQuestion::Duplicate { name: n, .. } if *n == name))
            {
                set.questions.push(ReviewQuestion::Duplicate {
                    name,
                    occurrences: duplicate.occurrences,
                });
            }
        }
        for block in parsed.passthrough {
            let name = block.section_name;
            // Another system's programs are kept for it, never asked about.
            let asked = app_section_os_label(&name).is_none()
                && !set
                    .questions
                    .iter()
                    .any(|q| matches!(q, ReviewQuestion::Unknown { name: n, .. } if *n == name));
            if asked {
                set.questions.push(ReviewQuestion::Unknown {
                    name: name.clone(),
                    lines: block.content_lines,
                });
            }
            add_block(
                &mut set.passthrough[route_index(route)],
                name.clone(),
                &block.raw_text,
            );
            set.blocks[route_index(route)].push((name, block.raw_text));
        }
    }
    Ok(set)
}

/// Takes `route`'s passthrough sections from its bound file at `path`, so the
/// list shows what the file holds and a rewrite carries it, whoever wrote it.
/// A missing or unreadable file leaves the ones in memory.
pub fn take_passthrough_from(table: &mut Table, route: Route, path: &Path) {
    if let Ok(Some(text)) = read_text(path) {
        let mut passthrough = BTreeMap::new();
        for block in parse_canonical_rules(&text).passthrough {
            add_block(&mut passthrough, block.section_name, &block.raw_text);
        }
        table.passthrough[route_index(route)] = passthrough;
    }
}

/// [`take_passthrough_from`] for both bound files named in `settings_file`.
pub fn take_bound_passthrough(table: &mut Table, settings_file: Option<&Path>) {
    let Some(settings) = settings_file.and_then(|file| super::own_settings::read(file).ok()) else {
        return;
    };
    let bound = [settings.rules_files.primary, settings.rules_files.secondary];
    for (route, path) in Route::ALL.into_iter().zip(bound) {
        if !path.is_empty() {
            take_passthrough_from(table, route, Path::new(&path));
        }
    }
}

/// Whether writing to `dir` would replace a rules file.
pub fn set_exists(dir: &Path) -> bool {
    Route::ALL
        .into_iter()
        .any(|route| dir.join(file_name(route)).exists())
}

/// Both files from the rows on screen, as the GUI writes them. `hint` is the
/// translated syntax hint the files open with.
pub fn write_set(
    dir: &Path,
    table: &Table,
    hint: &[String],
    exported_at: &str,
) -> Result<(), (PathBuf, String)> {
    std::fs::create_dir_all(dir).map_err(|e| (dir.to_path_buf(), e.to_string()))?;
    for route in Route::ALL {
        write_route(&dir.join(file_name(route)), route, table, hint, exported_at)?;
    }
    Ok(())
}

/// The file of one route from the rows on screen, at `path`.
pub fn write_route(
    path: &Path,
    route: Route,
    table: &Table,
    hint: &[String],
    exported_at: &str,
) -> Result<(), (PathBuf, String)> {
    write_whole(path, route_text(route, table, hint, exported_at).as_bytes())
        .map_err(|e| (path.to_path_buf(), e.to_string()))
}

/// Replaces the file in one step: a failure mid-write leaves the old file, not
/// a truncated one (the window saves through `QSaveFile`).
fn write_whole(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".nrr-tmp");
    let temporary = PathBuf::from(temporary);
    let result = std::fs::write(&temporary, bytes).and_then(|()| std::fs::rename(&temporary, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn route_text(route: Route, table: &Table, hint: &[String], exported_at: &str) -> String {
    let rows: Vec<RuleRow> = table.rows.iter().map(|r| r.rule.clone()).collect();
    let options = RulesFileOptions {
        include_comments: true,
        exported_at,
        passthrough: &table.passthrough[route_index(route)],
        os: PlatformProfile::current().os,
        syntax_hint: hint,
    };
    build_rules_file_text(&rows, route, &options)
}

/// Whether the file at `path` says something else than the rows on screen
/// would write there. The leading `#` block is not compared: it carries the
/// time of writing (the GUI's `canonicalRulesBody`). An unreadable file
/// differs.
pub fn route_differs(path: &Path, route: Route, table: &Table, hint: &[String]) -> bool {
    match read_text(path) {
        Ok(Some(on_disk)) => {
            rules_body(&on_disk) != rules_body(&route_text(route, table, hint, ""))
        }
        Ok(None) => false,
        Err(_) => true,
    }
}

/// Past the leading blank and `#` lines, trailing blank lines dropped.
fn rules_body(text: &str) -> String {
    let lines: Vec<&str> = text.lines().map(str::trim_end).collect();
    let start = lines
        .iter()
        .position(|line| !line.is_empty() && !line.starts_with('#'))
        .unwrap_or(lines.len());
    let end = lines
        .iter()
        .rposition(|line| !line.is_empty())
        .map_or(start, |last| (last + 1).max(start));
    lines[start..end].join("\n")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetSource {
    /// The user's own rule-set folder.
    User,
    /// The sets shipped beside the program.
    Bundled,
}

/// A rule set: a folder holding at least one rules file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preset {
    /// The GUI's label: `<country>_<pack>` for a shipped set, the folder name
    /// for one of the user's own.
    pub label: String,
    pub dir: PathBuf,
    pub source: SetSource,
}

impl Preset {
    /// `<source>:<label>`, the GUI's form of the remembered choice: the two
    /// sources can hold sets with the same label.
    pub fn selection_key(&self) -> String {
        let source = match self.source {
            SetSource::User => "user",
            SetSource::Bundled => "bundled",
        };
        format!("{source}:{}", self.label)
    }
}

/// Beside the binary, then — in a development build only — the checkout;
/// never a parent directory, where another user could plant a folder.
pub fn presets_root() -> Option<PathBuf> {
    let beside = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("presets")));
    #[cfg(debug_assertions)]
    let checkout = Some(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../presets"));
    #[cfg(not(debug_assertions))]
    let checkout: Option<PathBuf> = None;
    beside.into_iter().chain(checkout).find(|dir| dir.is_dir())
}

/// The demo rule set the window's "Load demo rules" reads, in the reader's
/// language when it has one: shipped under `configs/presets`, found the way
/// [`presets_root`] finds the country sets.
pub fn demo_dir(russian: bool) -> Option<PathBuf> {
    let beside = std::env::current_exe().ok().and_then(|exe| {
        exe.parent()
            .map(|dir| dir.join("configs/presets/builtin-demo"))
    });
    #[cfg(debug_assertions)]
    let checkout =
        Some(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../configs/presets/builtin-demo"));
    #[cfg(not(debug_assertions))]
    let checkout: Option<PathBuf> = None;
    let root = beside
        .into_iter()
        .chain(checkout)
        .find(|dir| dir.is_dir())?;
    let translated = root.join("ru");
    Some(if russian && translated.is_dir() {
        translated
    } else {
        root
    })
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

fn dir_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

pub fn presets_in(root: &Path) -> Vec<Preset> {
    let mut out = Vec::new();
    for country in sorted_dirs(root) {
        for pack in sorted_dirs(&country) {
            if set_exists(&pack) {
                out.push(Preset {
                    label: format!("{}_{}", dir_name(&country), dir_name(&pack)),
                    dir: pack,
                    source: SetSource::Bundled,
                });
            }
        }
    }
    out
}

/// The sets in the user's folder, listed as the GUI lists them: each
/// subfolder with rules files; one level deeper, so a copy of the shipped
/// `<country>/<pack>/` tree lists too; and the folder itself when it holds the
/// files and nothing below does.
pub fn user_sets(root: &Path) -> Vec<Preset> {
    let mut out = Vec::new();
    for set in sorted_dirs(root) {
        if set_exists(&set) {
            out.push(Preset {
                label: dir_name(&set),
                dir: set,
                source: SetSource::User,
            });
            continue;
        }
        for pack in sorted_dirs(&set) {
            if set_exists(&pack) {
                out.push(Preset {
                    label: format!("{}_{}", dir_name(&set), dir_name(&pack)),
                    dir: pack,
                    source: SetSource::User,
                });
            }
        }
    }
    if out.is_empty() && set_exists(root) {
        let mut label = dir_name(root);
        if label.is_empty() {
            label = "rules".to_string();
        }
        out.push(Preset {
            label,
            dir: root.to_path_buf(),
            source: SetSource::User,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Scratch;
    use nrr_client_logic::rules_table::{TargetRoute, RULES_FILE_HINT_KEYS};

    /// Only what routes counts: a new time of writing in the header is the
    /// same file, a line added below it is not.
    #[test]
    fn a_file_differs_only_by_its_rules() {
        let dir = Scratch::new("files-differ");
        let app = crate::state::AppState::new(crate::screens::ScreenId::Rules, false);
        let (table, hint) = (&app.rules.table, &app.rules.file_hint);
        write_set(dir.path(), table, hint, "2026-01-01T00:00:00Z").expect("write");
        let path = dir.path().join(file_name(Route::Primary));
        assert!(!route_differs(&path, Route::Primary, table, hint));

        let text = std::fs::read_to_string(&path).expect("read");
        std::fs::write(&path, format!("# another header line\n{text}")).expect("write");
        assert!(!route_differs(&path, Route::Primary, table, hint));

        std::fs::write(&path, format!("{text}example.org\n")).expect("write");
        assert!(route_differs(&path, Route::Primary, table, hint));
        let gone = dir.path().join("absent.txt");
        assert!(!route_differs(&gone, Route::Primary, table, hint));
    }

    /// A rewrite replaces the file whole and leaves no temporary behind.
    #[test]
    fn a_rewrite_replaces_the_file_and_leaves_no_temporary() {
        let dir = Scratch::new("files-whole");
        let path = dir.path().join("rules_primary.txt");
        std::fs::write(&path, "old contents that are longer than the new ones").expect("seed");
        write_whole(&path, b"new").expect("write");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "new");
        assert_eq!(std::fs::read_dir(dir.path()).expect("dir").count(), 1);
    }

    /// The terminal writes the syntax hint the GUI writes, in the reader's
    /// language, and reads it back as nothing.
    #[test]
    fn a_written_file_opens_with_the_hint_and_reads_back_without_it() {
        let dir = Scratch::new("files-hint");
        let mut app = crate::state::AppState::new(crate::screens::ScreenId::Rules, false);
        super::super::on_texts(&mut app, &crate::testing::texts_en());
        assert_eq!(app.rules.file_hint.len(), RULES_FILE_HINT_KEYS.len());
        let hint = &app.rules.file_hint;
        let written = write_set(dir.path(), &app.rules.table, hint, "2026-01-01T00:00:00Z");
        written.expect("write");
        let path = dir.path().join(file_name(Route::Primary));
        let text = std::fs::read_to_string(path).expect("read");
        assert!(text.contains("\n\n#: --- Name"), "{text}");
        let set = read_set(dir.path()).expect("read back");
        assert!(set.rows.is_empty(), "{:?}", set.rows);
        assert!(set.passthrough.iter().all(BTreeMap::is_empty));
    }

    /// The terminal reads a deny the GUI way and writes it back as `!value`;
    /// a line in the retired spelling is no block and its verdict says so.
    #[test]
    fn a_deny_reads_as_a_block_and_is_written_back_before_the_value() {
        let dir = Scratch::new("files-deny");
        std::fs::write(
            dir.path().join(file_name(Route::Primary)),
            "--- Domains\n!ads.example\n# !off.example\nkept.example\nold.example +block\n",
        )
        .expect("write");
        let set = read_set(dir.path()).expect("read");
        let read: Vec<_> = set
            .rows
            .iter()
            .map(|r| (r.match_value.as_str(), r.enabled, r.target_route.clone()))
            .collect();
        assert_eq!(
            read,
            [
                ("ads.example", true, TargetRoute::Block),
                ("off.example", false, TargetRoute::Block),
                ("kept.example", true, TargetRoute::Primary),
                ("old.example +block", true, TargetRoute::Primary),
            ]
        );
        let row = &set.rows[3];
        let retired = super::super::table::Verdict::of(&row.rule_type, &row.match_value);
        assert_eq!(
            retired.message_key,
            "rules.validation.match-value-invalid.retired-block-flag"
        );

        let options = RulesFileOptions {
            include_comments: true,
            exported_at: "2026-01-01T00:00:00Z",
            passthrough: &BTreeMap::new(),
            os: "windows",
            syntax_hint: &[],
        };
        let secondary = build_rules_file_text(&set.rows, Route::Secondary, &options);
        assert!(
            secondary.contains("\n!ads.example\n# !off.example\n"),
            "{secondary}"
        );
        assert!(!secondary.contains("+block"), "{secondary}");
    }
}
