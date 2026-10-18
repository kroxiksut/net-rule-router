//! One reading of a path an application rule names, for every reader of one.
//!
//! An application rule names a program by its file name, a mask over names,
//! or where it lives: one file, the programs of one folder, or those of a
//! folder and every folder below it. The rules file, the wire, the protection
//! check and the matcher all read such a path; the reduction lives here once,
//! so they cannot disagree about which folder a rule names.
//!
//! Paths are text someone else shaped (a rules file, an IPC payload, the image
//! path the OS reports for another user's process): every reader here is
//! bounded in length and segments, runs in linear time and never panics.

/// How a platform spells and compares paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PathStyle {
    /// `C:\dir\app.exe`, `\\server\share\dir`; `/` separates too; case is
    /// ignored.
    Windows,
    /// `/opt/app/bin`; case matters.
    Linux,
    /// `/Applications/App.app`; case is ignored, as on the default volume.
    MacOS,
}

impl PathStyle {
    /// Whether two spellings differing only in case name one file.
    #[must_use]
    pub const fn case_insensitive(self) -> bool {
        matches!(self, Self::Windows | Self::MacOS)
    }

    /// The separator a canonical path is written with.
    #[must_use]
    pub const fn separator(self) -> char {
        match self {
            Self::Windows => '\\',
            Self::Linux | Self::MacOS => '/',
        }
    }

    /// Segments of the root itself: the drive (`c:`) or share on Windows,
    /// none on Unix.
    #[must_use]
    pub const fn root_len(self) -> usize {
        match self {
            Self::Windows => 1,
            Self::Linux | Self::MacOS => 0,
        }
    }

    fn is_separator(self, c: char) -> bool {
        match self {
            Self::Windows => matches!(c, '\\' | '/'),
            Self::Linux | Self::MacOS => c == '/',
        }
    }
}

/// Longest path, in bytes, read here; a longer one names nothing.
pub const MAX_PATH_BYTES: usize = 32 * 1024;

/// Most segments a path may have; a deeper one names nothing.
pub const MAX_PATH_SEGMENTS: usize = 256;

/// Longest application rule value written as a path, in bytes. A name keeps
/// the bound of every rule value; a deep folder, or one spelled in a script of
/// two bytes a letter, outgrows it.
pub const MAX_PATH_VALUE_BYTES: usize = 1024;

/// The byte bound of an application rule value as `style` reads it: a path's
/// or a name's.
#[must_use]
pub fn app_value_byte_limit(value: &str, style: PathStyle) -> usize {
    if is_path_value(value, style) {
        MAX_PATH_VALUE_BYTES
    } else {
        crate::rule_value_class::MAX_RULE_VALUE_BYTES
    }
}

/// The segments of an absolute path as `style` compares them; `None` for a
/// path that is not absolute, climbs with `..`, is oversized, holds a control
/// character, or (unless `pattern`) holds a `*`.
///
/// Windows: `\` and `/` are one separator, the `\\?\` and `\\.\` prefixes
/// are dropped, a drive is `c:`, a share `\\server\share`, and trailing dots
/// and spaces of a segment are dropped as Windows drops them.
#[must_use]
pub fn path_segments(path: &str, style: PathStyle, pattern: bool) -> Option<Vec<String>> {
    if path.len() > MAX_PATH_BYTES || path.chars().any(char::is_control) {
        return None;
    }
    let path = path.trim();
    let folded;
    let path = if style.case_insensitive() {
        folded = path.to_lowercase();
        folded.as_str()
    } else {
        path
    };
    let mut segments = Vec::new();
    let rest = match style {
        PathStyle::Windows => {
            let unified = path.replace('/', "\\");
            let unified = if let Some(unc) = unified.strip_prefix(r"\\?\unc\") {
                format!(r"\\{unc}")
            } else if let Some(local) = unified
                .strip_prefix(r"\\?\")
                .or_else(|| unified.strip_prefix(r"\\.\"))
            {
                local.to_string()
            } else {
                unified
            };
            if let Some(share) = unified.strip_prefix(r"\\") {
                let mut parts = share.split('\\').filter(|p| !p.is_empty());
                let server = parts.next()?;
                let name = parts.next()?;
                if [server, name]
                    .iter()
                    .any(|part| matches!(*part, "." | ".."))
                {
                    return None;
                }
                segments.push(format!(r"\\{server}\{name}"));
                parts.collect::<Vec<_>>().join("\\")
            } else {
                let bytes = unified.as_bytes();
                let drive = bytes.first().copied().filter(u8::is_ascii_alphabetic)?;
                if bytes.get(1) != Some(&b':') || !matches!(bytes.get(2), None | Some(b'\\')) {
                    return None;
                }
                segments.push(format!("{}:", char::from(drive)));
                unified.get(2..).unwrap_or_default().to_string()
            }
        }
        PathStyle::Linux | PathStyle::MacOS => path.strip_prefix('/')?.to_string(),
    };
    for raw in rest.split(style.separator()) {
        if raw.is_empty() || raw == "." {
            continue;
        }
        if raw == ".." {
            return None;
        }
        let segment = match style {
            PathStyle::Windows => {
                if raw.contains(':') {
                    return None;
                }
                let trimmed = raw.trim_end_matches(['.', ' ']);
                if trimmed.is_empty() {
                    return None;
                }
                trimmed
            }
            PathStyle::Linux | PathStyle::MacOS => raw,
        };
        if !pattern && segment.contains('*') {
            return None;
        }
        segments.push(segment.to_string());
        if segments.len() > MAX_PATH_SEGMENTS {
            return None;
        }
    }
    Some(segments)
}

/// Whether an application rule value is written as a path on `style`: it
/// holds a separator. Without one it is a name or a mask over names.
#[must_use]
pub fn is_path_value(raw: &str, style: PathStyle) -> bool {
    raw.chars().any(|c| style.is_separator(c))
}

/// Which programs a path rule names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AppPathKind {
    /// `C:\apps\app.exe`: one program.
    File,
    /// `C:\apps\` (or `C:\apps` on Windows): the programs directly in it.
    Folder,
    /// `C:\apps\*`: the programs in it and in every folder below it.
    FolderTree,
    /// `/opt/app` on Linux or macOS: a file or a folder, whichever is there
    /// when the rule is applied. Only a trailing `/` says "folder" there.
    FileOrFolder,
}

impl AppPathKind {
    /// The slug the client vectors and the JS twin use.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Folder => "folder",
            Self::FolderTree => "folder-tree",
            Self::FileOrFolder => "file-or-folder",
        }
    }
}

/// Why a value written as a path names no program. The slug reaches the
/// locale keys (`rules.validation.match-value-invalid.<slug>`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AppPathError {
    /// A `*` anywhere but as the whole last segment (`\*`, `/*`).
    StarNotLast,
    /// Does not start at a drive, a share or `/`.
    NotAbsolute,
    /// Climbs with `..`, holds a stray `:` or a control character, or is past
    /// the bounds.
    Malformed,
}

impl AppPathError {
    /// Every error, for exhaustive tables and locale checks.
    pub const ALL: [Self; 3] = [Self::StarNotLast, Self::NotAbsolute, Self::Malformed];

    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::StarNotLast => "path-star",
            Self::NotAbsolute => "path-not-absolute",
            Self::Malformed => "path-invalid",
        }
    }
}

impl core::fmt::Display for AppPathError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.slug())
    }
}

/// A path an application rule names, in its canonical spelling: case folded
/// where the platform ignores it, one separator, no `.` or empty segments, a
/// folder written with its trailing separator so it reads back as a folder on
/// every platform.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AppPath {
    style: PathStyle,
    kind: AppPathKind,
    /// The file, or the folder for the folder kinds.
    segments: Vec<String>,
    text: String,
}

impl AppPath {
    /// Reads `raw`, a value [`is_path_value`] says is a path, as `style`
    /// spells one.
    ///
    /// # Errors
    ///
    /// [`AppPathError`] when it names no program.
    pub fn parse(raw: &str, style: PathStyle) -> Result<Self, AppPathError> {
        if raw.len() > MAX_PATH_BYTES || raw.chars().any(char::is_control) {
            return Err(AppPathError::Malformed);
        }
        let trimmed = raw.trim();
        let tree_body = trimmed.strip_suffix('*').filter(|body| {
            body.chars()
                .next_back()
                .is_some_and(|c| style.is_separator(c))
        });
        let body = tree_body.unwrap_or(trimmed);
        if body.contains('*') {
            return Err(AppPathError::StarNotLast);
        }
        if !starts_absolute(body, style) {
            return Err(AppPathError::NotAbsolute);
        }
        let segments = path_segments(body, style, false).ok_or(AppPathError::Malformed)?;
        let trailing = body
            .chars()
            .next_back()
            .is_some_and(|c| style.is_separator(c));
        let kind = if tree_body.is_some() {
            AppPathKind::FolderTree
        } else if trailing || segments.len() <= style.root_len() {
            AppPathKind::Folder
        } else {
            match style {
                PathStyle::Windows => {
                    let file = segments.last().is_some_and(|last| last.ends_with(".exe"));
                    if file {
                        AppPathKind::File
                    } else {
                        AppPathKind::Folder
                    }
                }
                PathStyle::Linux | PathStyle::MacOS => AppPathKind::FileOrFolder,
            }
        };
        let text = render(style, kind, &segments);
        Ok(Self {
            style,
            kind,
            segments,
            text,
        })
    }

    /// The canonical spelling, as the rules file and the wire carry it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    #[must_use]
    pub const fn kind(&self) -> AppPathKind {
        self.kind
    }

    #[must_use]
    pub const fn style(&self) -> PathStyle {
        self.style
    }

    /// Segments below the root: how deep the file or folder sits. A deeper
    /// folder is the narrower rule.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.segments.len().saturating_sub(self.style.root_len())
    }

    /// The file or folder itself, without the `*` of a folder with
    /// subfolders: what a check of the place it names reads.
    #[must_use]
    pub fn place(&self) -> &str {
        self.text.strip_suffix('*').unwrap_or(&self.text)
    }

    /// This rule as the disk has it: the same form at `place`, the real path
    /// of its file or folder (behind junctions and links), with a path that
    /// waits for the disk decided by `is_folder`. Enforcement-only: a decided
    /// Unix file is spelled as written and reads back undecided, which
    /// matches the same images.
    ///
    /// # Errors
    ///
    /// [`AppPathError::Malformed`] when `place` is no absolute path.
    pub fn on_disk(&self, place: &str, is_folder: bool) -> Result<Self, AppPathError> {
        let segments = path_segments(place, self.style, false).ok_or(AppPathError::Malformed)?;
        if !starts_absolute(place.trim(), self.style) {
            return Err(AppPathError::Malformed);
        }
        let kind = match self.kind {
            AppPathKind::FileOrFolder if is_folder => AppPathKind::Folder,
            AppPathKind::FileOrFolder => AppPathKind::File,
            kind => kind,
        };
        let text = render(self.style, kind, &segments);
        Ok(Self {
            style: self.style,
            kind,
            segments,
            text,
        })
    }

    /// Whether the program whose image is `image` — a full path as the OS
    /// reports it — is one this path names, and how: as the file itself or
    /// as a program of the folder.
    #[must_use]
    pub fn match_image(&self, image: &str) -> Option<AppPathKind> {
        let observed = path_segments(image, self.style, false)?;
        let (_, folder) = observed.split_last()?;
        if folder.len() < self.style.root_len() {
            return None;
        }
        let file = observed == self.segments;
        let in_folder = folder == self.segments.as_slice();
        match self.kind {
            AppPathKind::File => file.then_some(AppPathKind::File),
            AppPathKind::Folder => in_folder.then_some(AppPathKind::Folder),
            AppPathKind::FolderTree => folder
                .starts_with(&self.segments)
                .then_some(AppPathKind::FolderTree),
            // Either matches only what the disk allows: a file has no
            // programs below it, and a folder is no program itself.
            AppPathKind::FileOrFolder => {
                if file {
                    Some(AppPathKind::File)
                } else {
                    in_folder.then_some(AppPathKind::Folder)
                }
            }
        }
    }
}

impl core::fmt::Display for AppPath {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.text)
    }
}

/// Starts at a drive, a share or `/`: anything else is relative.
fn starts_absolute(body: &str, style: PathStyle) -> bool {
    match style {
        PathStyle::Windows => {
            let bytes = body.as_bytes();
            let drive = bytes.first().is_some_and(u8::is_ascii_alphabetic)
                && bytes.get(1) == Some(&b':')
                && matches!(bytes.get(2), None | Some(b'\\' | b'/'));
            let share = matches!(bytes, [b'\\' | b'/', b'\\' | b'/', ..]);
            drive || share
        }
        PathStyle::Linux | PathStyle::MacOS => body.starts_with('/'),
    }
}

fn render(style: PathStyle, kind: AppPathKind, segments: &[String]) -> String {
    let sep = style.separator();
    let mut text = String::new();
    if style.root_len() == 0 {
        text.push(sep);
    }
    for (idx, segment) in segments.iter().enumerate() {
        if idx > 0 {
            text.push(sep);
        }
        text.push_str(segment);
    }
    let ends_in_separator = text.ends_with(sep);
    match kind {
        AppPathKind::File | AppPathKind::FileOrFolder => {}
        AppPathKind::Folder => {
            if !ends_in_separator {
                text.push(sep);
            }
        }
        AppPathKind::FolderTree => {
            if !ends_in_separator {
                text.push(sep);
            }
            text.push('*');
        }
    }
    text
}

#[cfg(test)]
mod tests;
