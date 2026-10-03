//! The `/proc` and XDG desktop-entry scans the discoveries share: one reader,
//! a classifier per caller. Every read is bounded and every failure reads as
//! "nothing found".

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

/// `comm` is at most 16 bytes; anything longer is not a `comm` file.
pub(crate) const MAX_COMM_BYTES: u64 = 256;
/// Desktop entries are a few KiB; a larger file is not one worth parsing.
pub(crate) const MAX_DESKTOP_ENTRY_BYTES: u64 = 64 * 1024;
/// Guards against a pathological directory (or `/proc`) listing.
pub(crate) const MAX_ENTRIES_PER_DIR: usize = 65_536;

/// Launchers whose path in `Exec=` is not the application's own executable.
/// Keeping them out of an exe path matters: the merges dedup by path, so every
/// Flatpak app would otherwise collapse into one row.
const EXEC_WRAPPERS: &[&str] = &["env", "flatpak", "sh", "bash", "snap"];

/// The system, Flatpak and Snap application dirs plus this user's own.
pub(crate) fn application_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = [
        "/usr/share/applications",
        "/usr/local/share/applications",
        "/var/lib/flatpak/exports/share/applications",
        "/var/lib/snapd/desktop/applications",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    if let Some(data_home) = user_data_home() {
        dirs.push(data_home.join("applications"));
        dirs.push(data_home.join("flatpak/exports/share/applications"));
    }
    dirs
}

/// `$XDG_DATA_HOME` when absolute (the spec ignores a relative one), else
/// `~/.local/share`.
fn user_data_home() -> Option<PathBuf> {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .map(|home| home.join(".local/share"))
        })
}

// ── Running processes ─────────────────────────────────────────────────────────

pub(crate) struct ProcessSeen {
    pub(crate) dir: PathBuf,
    /// Readable for this user's own processes only.
    pub(crate) exe: Option<PathBuf>,
    /// Truncated to 15 bytes by the kernel.
    pub(crate) comm: Option<String>,
}

impl ProcessSeen {
    pub(crate) fn exe_basename(&self) -> Option<&str> {
        self.exe
            .as_deref()
            .and_then(Path::file_name)
            .and_then(|n| n.to_str())
    }
}

pub(crate) fn running_processes(proc_root: &Path) -> Vec<ProcessSeen> {
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return Vec::new();
    };
    entries
        .flatten()
        .take(MAX_ENTRIES_PER_DIR)
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        })
        .filter_map(|entry| {
            let dir = entry.path();
            let exe = std::fs::read_link(dir.join("exe")).ok().map(|target| {
                // A replaced binary reads as `/path/app (deleted)`.
                let text = target.to_string_lossy();
                match text.strip_suffix(" (deleted)") {
                    Some(live) => PathBuf::from(live),
                    None => target,
                }
            });
            let comm = read_capped(&dir.join("comm"), MAX_COMM_BYTES)
                .map(|c| c.trim().to_string())
                .filter(|c| !c.is_empty());
            (exe.is_some() || comm.is_some()).then_some(ProcessSeen { dir, exe, comm })
        })
        .collect()
}

// ── Desktop entries ───────────────────────────────────────────────────────────

/// A launchable application entry (`Type=Application`, not hidden).
pub(crate) struct DesktopApp {
    /// The file name without `.desktop`; a Flatpak app id carries the app's name.
    pub(crate) stem: String,
    pub(crate) name: Option<String>,
    /// The program `Exec=` runs, as written there.
    pub(crate) program: Option<String>,
}

impl DesktopApp {
    pub(crate) fn program_name(&self) -> Option<&str> {
        self.program
            .as_deref()
            .and_then(|p| Path::new(p).file_name())
            .and_then(|n| n.to_str())
    }

    /// The strings a classifier tests, most telling first: `Name=`, the
    /// `Exec=` program, the file stem.
    pub(crate) fn labels(&self) -> impl Iterator<Item = &str> {
        [
            self.name.as_deref(),
            self.program_name(),
            Some(self.stem.as_str()),
        ]
        .into_iter()
        .flatten()
    }

    pub(crate) fn display_name(&self) -> String {
        self.name
            .clone()
            .or_else(|| self.program_name().map(str::to_string))
            .unwrap_or_else(|| self.stem.clone())
    }

    /// The `Exec=` program unless it is a launcher wrapper, whose path would
    /// merge unrelated apps.
    pub(crate) fn own_program(&self) -> Option<&str> {
        self.program_name()
            .filter(|n| !EXEC_WRAPPERS.contains(n))
            .and(self.program.as_deref())
    }

    /// [`Self::own_program`] when absolute: a relative one is resolved through
    /// `$PATH` at launch. `Exec=` is a Unix path whatever the host, so no
    /// `Path::is_absolute`.
    pub(crate) fn own_exe_path(&self) -> Option<&str> {
        self.own_program().filter(|p| p.starts_with('/'))
    }
}

/// The entries in `dir` and in its direct subdirectories: XDG allows vendor
/// folders (`kde4/`, `wine/`). One level only, which also rules out a loop.
pub(crate) fn desktop_apps_in(dir: &Path) -> Vec<DesktopApp> {
    let mut out = Vec::new();
    for subdir in desktop_apps_one_level(dir, &mut out) {
        desktop_apps_one_level(&subdir, &mut out);
    }
    out
}

/// Reads the entries directly in `dir` into `out`; returns its subdirectories.
fn desktop_apps_one_level(dir: &Path, out: &mut Vec<DesktopApp>) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut subdirs = Vec::new();
    for entry in entries.flatten().take(MAX_ENTRIES_PER_DIR) {
        let path = entry.path();
        if entry.file_type().is_ok_and(|t| t.is_dir()) {
            subdirs.push(path);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("desktop") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if let Some(app) =
            read_capped(&path, MAX_DESKTOP_ENTRY_BYTES).and_then(|text| desktop_app(stem, &text))
        {
            out.push(app);
        }
    }
    subdirs
}

fn desktop_app(stem: &str, text: &str) -> Option<DesktopApp> {
    let entry = parse_desktop_entry(text)?;
    if entry.hidden || entry.kind.as_deref().is_some_and(|k| k != "Application") {
        return None;
    }
    Some(DesktopApp {
        stem: stem.to_string(),
        name: entry.name,
        program: entry.exec.as_deref().and_then(exec_program),
    })
}

#[derive(Default)]
struct DesktopEntry {
    name: Option<String>,
    exec: Option<String>,
    kind: Option<String>,
    hidden: bool,
}

/// The unlocalized keys of the `[Desktop Entry]` group; other groups (actions)
/// and localized `Name[xx]=` keys are ignored.
fn parse_desktop_entry(text: &str) -> Option<DesktopEntry> {
    let mut entry = DesktopEntry::default();
    let mut in_main_group = false;
    let mut seen_main_group = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            in_main_group = line == "[Desktop Entry]";
            seen_main_group |= in_main_group;
            continue;
        }
        if !in_main_group {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "Name" if !value.is_empty() => entry.name = Some(value.to_string()),
            "Exec" if !value.is_empty() => entry.exec = Some(value.to_string()),
            "Type" => entry.kind = Some(value.to_string()),
            "Hidden" => entry.hidden = value == "true",
            _ => {}
        }
    }
    seen_main_group.then_some(entry)
}

/// The program an `Exec=` line runs: the first token after an optional
/// `env VAR=value …` prefix, with the spec's double-quote escaping undone.
fn exec_program(exec: &str) -> Option<String> {
    let mut tokens = exec_tokens(exec).into_iter().peekable();
    if tokens
        .peek()
        .is_some_and(|t| Path::new(t).file_name().and_then(|n| n.to_str()) == Some("env"))
    {
        tokens.next();
        while tokens
            .peek()
            .is_some_and(|t| t.contains('=') || t.starts_with('-'))
        {
            tokens.next();
        }
    }
    tokens.next().filter(|t| !t.is_empty())
}

fn exec_tokens(exec: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = exec.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => in_quotes = !in_quotes,
            '\\' if in_quotes => {
                if let Some(escaped) = chars.next() {
                    current.push(escaped);
                }
            }
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// The whole file as text, or `None` when unreadable or larger than `cap`.
pub(crate) fn read_capped(path: &Path, cap: u64) -> Option<String> {
    let mut bytes = Vec::new();
    File::open(path)
        .ok()?
        .take(cap + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= cap).then(|| String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_program_undoes_quoting_and_skips_env() {
        assert_eq!(
            exec_program(r#""/opt/My App/bin/app" --x"#).as_deref(),
            Some("/opt/My App/bin/app")
        );
        assert_eq!(
            exec_program("env LANG=C GDK_BACKEND=x11 qbittorrent %U").as_deref(),
            Some("qbittorrent")
        );
        assert_eq!(
            exec_program(r#""/opt/a\"b/app""#).as_deref(),
            Some("/opt/a\"b/app")
        );
        assert_eq!(exec_program("   "), None);
    }

    #[test]
    fn an_oversized_comm_is_not_read() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("comm");
        std::fs::write(&path, "x".repeat(MAX_COMM_BYTES as usize + 1)).expect("write");
        assert!(read_capped(&path, MAX_COMM_BYTES).is_none());
    }

    #[test]
    fn a_wrapper_or_relative_program_is_not_the_apps_own_exe() {
        let app = |program: &str| DesktopApp {
            stem: "x".into(),
            name: None,
            program: Some(program.into()),
        };
        assert_eq!(app("/usr/bin/flatpak").own_exe_path(), None);
        assert_eq!(app("client").own_exe_path(), None);
        assert_eq!(app("/opt/c/client").own_exe_path(), Some("/opt/c/client"));
    }
}
