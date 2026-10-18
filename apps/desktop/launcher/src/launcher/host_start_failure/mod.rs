//! The Qt host could not start because a library it links is missing or too
//! old. The launcher links no Qt, so it is the one left to tell the user, in
//! their language, instead of a system box or silence.
//!
//! Whether an exit is such a failure is decided here from fixed inputs (exit
//! code, the host's last stderr lines), the same on every OS; showing the
//! answer and keeping the OS's own box away are in `windows.rs` / `unix.rs`.

use std::collections::{BTreeMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use self::windows as os;
#[cfg(unix)]
mod unix;
#[cfg(unix)]
use self::unix as os;
#[cfg(not(any(windows, unix)))]
mod os {
    pub(crate) struct NothingSuppressed;
    pub(crate) fn suppress_loader_error_ui() -> NothingSuppressed {
        NothingSuppressed
    }
    pub(crate) fn show_notice(notice: &super::HostStartNotice) {
        eprintln!("{}: {}", notice.title, notice.body);
    }
}

pub(super) use os::suppress_loader_error_ui;

/// `STATUS_DLL_NOT_FOUND`: an imported DLL is nowhere on the search path.
const STATUS_DLL_NOT_FOUND: u32 = 0xC000_0135;
/// `STATUS_ENTRYPOINT_NOT_FOUND`: a DLL is there, without an export we import.
const STATUS_ENTRYPOINT_NOT_FOUND: u32 = 0xC000_0139;
/// What glibc's and musl's loaders exit with when they refuse a program.
const UNIX_LOADER_EXIT: i32 = 127;

/// Lines of host stderr kept for the verdict; a loader failure writes one.
pub(crate) const MAX_TAIL_LINES: usize = 32;
/// Bytes kept of one line. A loader line naming a library fits many times over.
pub(crate) const MAX_TAIL_LINE_BYTES: usize = 1024;
const MAX_LIBRARY_NAME_BYTES: usize = 128;
const MAX_VERSION_BYTES: usize = 64;

/// How an OS reports that its loader refused to start a program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LoaderConvention {
    /// An NTSTATUS exit code; nothing is written anywhere.
    WindowsNtStatus,
    /// Exit code 127 and one line on stderr naming what is wrong.
    UnixDynamicLoader,
}

impl LoaderConvention {
    pub(crate) const HOST: Self = if cfg!(windows) {
        Self::WindowsNtStatus
    } else {
        Self::UnixDynamicLoader
    };
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HostStartFailure {
    /// A library, or an entry point in one, is missing. `None` when the OS does
    /// not name it, or named it in a form we will not repeat.
    MissingLibrary { library: Option<String> },
    /// The library is there but older than this build needs.
    OutdatedLibrary { library: String, version: String },
}

/// The last lines the host wrote to stderr, each clipped. Bounded in lines and
/// bytes whatever the host writes: these are another process's bytes.
#[derive(Debug, Default)]
pub(crate) struct StderrTail {
    lines: VecDeque<String>,
}

pub(crate) type SharedStderrTail = Arc<Mutex<StderrTail>>;

impl StderrTail {
    pub(crate) fn shared() -> SharedStderrTail {
        Arc::new(Mutex::new(Self::default()))
    }

    pub(crate) fn push(&mut self, line: &str) {
        if self.lines.len() == MAX_TAIL_LINES {
            self.lines.pop_front();
        }
        self.lines
            .push_back(clip_to_bytes(line, MAX_TAIL_LINE_BYTES).to_owned());
    }

    pub(crate) fn lines(&self) -> impl DoubleEndedIterator<Item = &str> {
        self.lines.iter().map(String::as_str)
    }
}

/// Appends to a shared tail; a poisoned lock still holds usable lines.
pub(crate) fn record_stderr_line(tail: &SharedStderrTail, line: &str) {
    tail.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(line);
}

/// Is this host exit a library the loader could not provide? Every other
/// exit, a crash included, is `None`.
pub(crate) fn classify_host_exit(
    convention: LoaderConvention,
    exit_code: Option<i32>,
    stderr_tail: &StderrTail,
) -> Option<HostStartFailure> {
    let code = exit_code?;
    match convention {
        LoaderConvention::WindowsNtStatus => {
            let status = u32::from_ne_bytes(code.to_ne_bytes());
            matches!(status, STATUS_DLL_NOT_FOUND | STATUS_ENTRYPOINT_NOT_FOUND)
                .then_some(HostStartFailure::MissingLibrary { library: None })
        }
        LoaderConvention::UnixDynamicLoader if code == UNIX_LOADER_EXIT => {
            stderr_tail.lines().rev().find_map(parse_loader_line)
        }
        LoaderConvention::UnixDynamicLoader => None,
    }
}

/// One line of glibc's or musl's loader, or `None` for anything else.
fn parse_loader_line(line: &str) -> Option<HostStartFailure> {
    // glibc: `<prog>: error while loading shared libraries: <lib>: <reason>`
    if let Some((_, rest)) = line.split_once("error while loading shared libraries: ") {
        return Some(missing(rest.split(':').next()));
    }
    // musl: `Error loading shared library <lib>: <reason> (needed by <prog>)`
    if let Some((_, rest)) = line.split_once("Error loading shared library ") {
        return Some(missing(rest.split(':').next()));
    }
    // glibc: `<prog>: <path/lib>: version `<ver>' not found (required by <x>)`
    if let Some((before, after)) = line
        .split_once(": version `")
        .or_else(|| line.split_once(": version '"))
    {
        let (version, tail) = after.split_once('\'')?;
        if !tail.starts_with(" not found") {
            return None;
        }
        let path = before.rsplit(": ").next().unwrap_or(before);
        let library = path.rsplit('/').next().unwrap_or(path);
        return Some(
            match (
                safe_token(library, MAX_LIBRARY_NAME_BYTES, "._+-"),
                safe_token(version, MAX_VERSION_BYTES, "._-"),
            ) {
                (Some(library), Some(version)) => {
                    HostStartFailure::OutdatedLibrary { library, version }
                }
                (library, _) => HostStartFailure::MissingLibrary { library },
            },
        );
    }
    // glibc, lazy binding: the object named is the one that NEEDS the symbol,
    // so naming it would point at the wrong file.
    if line.contains("symbol lookup error: ") && line.contains("undefined symbol: ") {
        return Some(HostStartFailure::MissingLibrary { library: None });
    }
    None
}

/// A `DT_NEEDED` entry may be a path; the file name is what the user can act on.
fn missing(library: Option<&str>) -> HostStartFailure {
    let name = library.map(|raw| raw.rsplit('/').next().unwrap_or(raw));
    HostStartFailure::MissingLibrary {
        library: name.and_then(|name| safe_token(name, MAX_LIBRARY_NAME_BYTES, "._+-")),
    }
}

/// `raw` trimmed, if it is short and made only of ASCII alphanumerics and
/// `extra`. What reaches a dialog or a notification is never markup, a control
/// character or a wall of text.
fn safe_token(raw: &str, max_bytes: usize, extra: &str) -> Option<String> {
    let token = raw.trim();
    let valid = !token.is_empty()
        && token.len() <= max_bytes
        && token
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || extra.contains(ch));
    valid.then(|| token.to_owned())
}

/// The longest prefix of `text` within `max` bytes that ends on a character.
fn clip_to_bytes(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or_default()
}

/// What the user is shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HostStartNotice {
    pub(crate) title: String,
    pub(crate) body: String,
}

/// The notice in `language`, each key falling back to English, then to the
/// built-in text.
pub(crate) fn notice_text(
    failure: &HostStartFailure,
    catalog: &BTreeMap<String, BTreeMap<String, String>>,
    language: &str,
    log_path: &Path,
) -> HostStartNotice {
    let text = |key: &str, fallback: &str| {
        nrr_shared::resolve_catalog_text(catalog, language, key, fallback)
    };
    let title = text("dialog.host-start.title", "NetRuleRouter cannot start");
    let main = match failure {
        HostStartFailure::MissingLibrary { library: None } => text(
            "dialog.host-start.missing-library",
            "The installation is incomplete: reinstall the program.",
        ),
        HostStartFailure::MissingLibrary {
            library: Some(library),
        } => text(
            "dialog.host-start.missing-named-library",
            "The installation is incomplete: the library {library} is missing. Reinstall the program or install the library with your package manager.",
        )
        .replace("{library}", library),
        HostStartFailure::OutdatedLibrary { library, version } => text(
            "dialog.host-start.outdated-library",
            "The library {library} on this system is too old: the program needs version {version}. Update it with your package manager, or use the terminal interface: run nrr-tui.",
        )
        .replace("{library}", library)
        .replace("{version}", version),
    };
    // The path last: it is the one value that could itself contain braces.
    let log_hint = text(
        "dialog.host-start.log-hint",
        "Details are in the log: {log}",
    )
    .replace("{log}", &log_path.display().to_string());
    HostStartNotice {
        title,
        body: format!("{main}\n\n{log_hint}"),
    }
}

/// The verdict on this host's exit under this OS's convention.
pub(super) fn host_exit_failure(
    exit_code: Option<i32>,
    stderr_tail: &SharedStderrTail,
) -> Option<HostStartFailure> {
    let tail = stderr_tail.lock().unwrap_or_else(PoisonError::into_inner);
    classify_host_exit(LoaderConvention::HOST, exit_code, &tail)
}

/// Shows the notice; on Windows this blocks until the user closes it.
pub(super) fn tell_user(failure: &HostStartFailure, language: &str, log_path: &Path) {
    // Loaded only here: a host that started never pays for a second load.
    let catalog = nrr_shared::load_locale_catalog();
    os::show_notice(&notice_text(failure, &catalog, language, log_path));
}

#[cfg(test)]
mod tests;
