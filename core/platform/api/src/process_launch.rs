//! How another process was started, and which file from its command line it
//! runs as a script.
//!
//! A script's process is its interpreter: the image is `python.exe`, `bash` or
//! `java`, wherever that is installed, while the program the user means is the
//! file the command line hands it. A rule by folder follows such a script when
//! the command line runs a file from the folder: the first positional argument
//! is a script (by extension, or a file that runs by itself), a `-jar` file,
//! or a class-path entry. No list of interpreters decides it; the arguments do.
//!
//! The command line is set by the process itself, so it is read as hostile
//! text: bounded in bytes, arguments and class-path entries, linear, never
//! panics. Neutral here: the port, the parsers for each platform's form of a
//! command line, and the reading of which file runs. Reading another process
//! is per-OS.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use nrr_shared::app_path::{PathStyle, MAX_PATH_BYTES};

/// Command-line bytes read; past it the tail is not looked at. A script is
/// named near the start, and Windows caps a command line at 32 767 units.
pub const MAX_COMMAND_LINE_BYTES: usize = 64 * 1024;

/// Arguments read from one command line.
pub const MAX_ARGUMENTS: usize = 256;

/// Environment bytes read when the class path is looked for there.
pub const MAX_ENVIRON_BYTES: usize = 128 * 1024;

/// Class-path entries read from one class path.
pub const MAX_CLASS_PATH_ENTRIES: usize = 256;

/// Arguments looked at before the script position is given up on.
const MAX_SCANNED_ARGUMENTS: usize = 64;

/// Extensions of files an interpreter runs as a program.
pub const SCRIPT_EXTENSIONS: &[&str] = &[
    "ps1", "bat", "cmd", "vbs", "js", "wsf", "hta", "py", "pyw", "sh", "zsh", "bash", "fish", "pl",
    "rb", "php", "lua", "tcl", "r",
];

/// Programs that take a file to show, edit or copy it, never to run it. This
/// is no list of interpreters turned inside out: an unknown program with a
/// script as its first argument still counts, and these are the ones known to
/// connect while holding such a file (an editor's extensions, a copy to a
/// server).
const OPENS_FILES_IT_NAMES: &[&str] = &[
    "notepad",
    "notepad++",
    "wordpad",
    "write",
    "code",
    "code-insiders",
    "codium",
    "cursor",
    "windsurf",
    "zed",
    "subl",
    "sublime_text",
    "atom",
    "vim",
    "vi",
    "nvim",
    "gvim",
    "view",
    "vimdiff",
    "emacs",
    "emacsclient",
    "nano",
    "pico",
    "micro",
    "hx",
    "kak",
    "kate",
    "kwrite",
    "gedit",
    "gnome-text-editor",
    "mousepad",
    "pluma",
    "xed",
    "geany",
    "less",
    "more",
    "cat",
    "bat",
    "batcat",
    "head",
    "tail",
    "git",
    "hg",
    "svn",
    "scp",
    "sftp",
    "rsync",
    "rclone",
];

/// How a process was started, as its platform keeps it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcessLaunch {
    /// The arguments, the program's own name first.
    pub args: Vec<String>,
    /// The command line as one string, where the platform keeps it so (Windows):
    /// `cmd /c` reads its command from it, not from the split arguments.
    pub raw: Option<String>,
    /// The working folder, when readable: a relative script is found there.
    pub cwd: Option<String>,
}

/// A file a command line runs, or a folder whose files it loads.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Launched {
    /// `python C:\Tools\run.py`, `java -jar /opt/app/app.jar`.
    File(String),
    /// A class-path folder: `java -cp /opt/app/lib/*`.
    FilesIn(String),
}

/// Why a file from a command line counts as run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaunchEvidence {
    /// The script position holds a file with a script extension.
    ScriptExtension,
    /// A `-jar` file or a class-path entry.
    JavaOption,
    /// The script position holds a file without a script extension: it counts
    /// only if it runs by itself (a `#!` line or the execute bit), which only
    /// the disk can answer.
    RunsByItself,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchedFile {
    pub target: Launched,
    pub evidence: LaunchEvidence,
}

/// What a command line says it runs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LaunchReading {
    pub files: Vec<LaunchedFile>,
    /// A Java main class with no class path on the command line: the class
    /// path is in the process's `CLASSPATH`.
    pub wants_class_path: bool,
}

/// Reading another process's start. Every method is cheap enough for the
/// observation pass and none is ever called on the traffic path.
pub trait ProcessLaunchReader: Send + Sync {
    /// When `pid` started, in the platform's own units: with the pid, it names
    /// one process. `None` for a process that is gone or cannot be opened.
    fn start_stamp(&self, pid: u32) -> Option<u64>;

    /// How `pid` was started. `None` when it is gone or cannot be read.
    fn launch(&self, pid: u32) -> Option<ProcessLaunch>;

    /// The `CLASSPATH` `pid` runs with, where the platform lets it be read.
    fn class_path(&self, _pid: u32) -> Option<String> {
        None
    }

    /// Whether `path` is a regular file that runs by itself: a `#!` line, or
    /// the execute bit where the platform has one.
    fn runs_by_itself(&self, path: &str) -> bool;
}

/// A platform that cannot read other processes: no script is recognised.
#[derive(Debug, Default)]
pub struct NoProcessLaunches;

impl ProcessLaunchReader for NoProcessLaunches {
    fn start_stamp(&self, _pid: u32) -> Option<u64> {
        None
    }

    fn launch(&self, _pid: u32) -> Option<ProcessLaunch> {
        None
    }

    fn runs_by_itself(&self, _path: &str) -> bool {
        false
    }
}

/// Test double: processes, class paths and runnable files set by the test,
/// with a count of the launches read.
#[derive(Debug, Default)]
pub struct MockProcessLaunches {
    processes: Mutex<HashMap<u32, (u64, ProcessLaunch)>>,
    class_paths: Mutex<HashMap<u32, String>>,
    runnable: Mutex<HashSet<String>>,
    reads: Mutex<usize>,
}

impl MockProcessLaunches {
    pub fn set(&self, pid: u32, stamp: u64, launch: ProcessLaunch) {
        self.processes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(pid, (stamp, launch));
    }

    pub fn exit(&self, pid: u32) {
        self.processes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&pid);
    }

    pub fn set_class_path(&self, pid: u32, value: &str) {
        self.class_paths
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(pid, value.to_owned());
    }

    pub fn set_runnable(&self, path: &str) {
        self.runnable
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(path.to_owned());
    }

    /// How many times a launch was read.
    pub fn reads(&self) -> usize {
        *self.reads.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl ProcessLaunchReader for MockProcessLaunches {
    fn start_stamp(&self, pid: u32) -> Option<u64> {
        self.processes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&pid)
            .map(|(stamp, _)| *stamp)
    }

    fn launch(&self, pid: u32) -> Option<ProcessLaunch> {
        *self.reads.lock().unwrap_or_else(|p| p.into_inner()) += 1;
        self.processes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&pid)
            .map(|(_, launch)| launch.clone())
    }

    fn class_path(&self, pid: u32) -> Option<String> {
        self.class_paths
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&pid)
            .cloned()
    }

    fn runs_by_itself(&self, path: &str) -> bool {
        self.runnable
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains(path)
    }
}

// ── Command-line forms ───────────────────────────────────────────────────────

/// `line` cut to at most `max` bytes, at a character boundary.
fn capped(line: &str, max: usize) -> &str {
    if line.len() <= max {
        return line;
    }
    let mut end = max;
    while end > 0 && !line.is_char_boundary(end) {
        end -= 1;
    }
    line.get(..end).unwrap_or_default()
}

/// A Windows command line split as the C runtime splits it for `main`, which
/// is what an interpreter sees: the program name up to unquoted whitespace,
/// quotes without escapes; then `2n` backslashes before a quote are `n` and
/// the quote toggles quoting, `2n + 1` are `n` and a literal quote, other
/// backslashes are literal, and `""` inside quotes is one literal quote.
#[must_use]
pub fn split_windows_command_line(line: &str) -> Vec<String> {
    split_windows_with_ends(line)
        .into_iter()
        .map(|(arg, _)| arg)
        .collect()
}

/// [`split_windows_command_line`] with the byte offset each argument ends at.
fn split_windows_with_ends(line: &str) -> Vec<(String, usize)> {
    let line = capped(line, MAX_COMMAND_LINE_BYTES);
    let mut out: Vec<(String, usize)> = Vec::new();
    let mut chars = line.char_indices().peekable();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut end = line.len();
    for (at, c) in chars.by_ref() {
        match c {
            '"' => in_quotes = !in_quotes,
            ' ' | '\t' if !in_quotes => {
                end = at;
                break;
            }
            _ => cur.push(c),
        }
    }
    out.push((std::mem::take(&mut cur), end));
    while chars.next_if(|(_, c)| matches!(c, ' ' | '\t')).is_some() {}
    in_quotes = false;
    let mut started = false;
    while let Some((at, c)) = chars.next() {
        if out.len() >= MAX_ARGUMENTS {
            return out;
        }
        match c {
            ' ' | '\t' if !in_quotes => {
                out.push((std::mem::take(&mut cur), at));
                started = false;
                while chars.next_if(|(_, c)| matches!(c, ' ' | '\t')).is_some() {}
            }
            '\\' => {
                started = true;
                let mut run = 1usize;
                while chars.next_if(|(_, c)| *c == '\\').is_some() {
                    run += 1;
                }
                if chars.peek().is_some_and(|(_, c)| *c == '"') {
                    cur.extend(std::iter::repeat_n('\\', run / 2));
                    if run % 2 == 1 {
                        chars.next();
                        cur.push('"');
                    }
                } else {
                    cur.extend(std::iter::repeat_n('\\', run));
                }
            }
            '"' if in_quotes => {
                started = true;
                match chars.peek() {
                    Some((_, '"')) => {
                        cur.push('"');
                        chars.next();
                    }
                    Some(_) => in_quotes = false,
                    None => break,
                }
            }
            '"' => {
                started = true;
                in_quotes = true;
            }
            _ => {
                started = true;
                cur.push(c);
            }
        }
    }
    if (started || in_quotes || !cur.is_empty()) && out.len() < MAX_ARGUMENTS {
        out.push((cur, line.len()));
    }
    out
}

/// NUL-separated arguments, as Linux keeps `/proc/<pid>/cmdline` and macOS
/// the argument area: bytes past the bound and arguments past the count are
/// not read, and bytes that are not UTF-8 are replaced.
#[must_use]
pub fn split_nul_args(bytes: &[u8]) -> Vec<String> {
    let bytes = bytes.get(..MAX_COMMAND_LINE_BYTES).unwrap_or(bytes);
    let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    if bytes.is_empty() {
        return Vec::new();
    }
    bytes
        .split(|b| *b == 0)
        .take(MAX_ARGUMENTS)
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect()
}

/// The value of `name` in a NUL-separated environment block, within the
/// bound.
#[must_use]
pub fn environ_value(bytes: &[u8], name: &str) -> Option<String> {
    let bytes = bytes.get(..MAX_ENVIRON_BYTES).unwrap_or(bytes);
    bytes.split(|b| *b == 0).find_map(|entry| {
        let rest = entry.strip_prefix(name.as_bytes())?;
        let value = rest.strip_prefix(b"=")?;
        Some(String::from_utf8_lossy(value).into_owned())
    })
}

/// The arguments of a macOS `KERN_PROCARGS2` buffer, and the environment
/// block after them: a native-endian `argc`, the executable path, padding
/// NULs, then the arguments.
#[must_use]
pub fn split_procargs2(bytes: &[u8]) -> (Vec<String>, &[u8]) {
    let Some((head, rest)) = bytes.split_first_chunk::<4>() else {
        return (Vec::new(), &[]);
    };
    let argc = usize::try_from(i32::from_ne_bytes(*head))
        .unwrap_or(0)
        .min(MAX_ARGUMENTS);
    let rest = rest.get(..MAX_COMMAND_LINE_BYTES).unwrap_or(rest);
    let after_path = match rest.iter().position(|b| *b == 0) {
        Some(nul) => rest.get(nul..).unwrap_or_default(),
        None => return (Vec::new(), &[]),
    };
    let start = after_path
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(after_path.len());
    let mut area = after_path.get(start..).unwrap_or_default();
    let mut args = Vec::new();
    while args.len() < argc && !area.is_empty() {
        let end = area.iter().position(|b| *b == 0).unwrap_or(area.len());
        args.push(String::from_utf8_lossy(area.get(..end).unwrap_or_default()).into_owned());
        area = area.get(end + 1..).unwrap_or_default();
    }
    (args, area)
}

// ── Which file runs ──────────────────────────────────────────────────────────

/// Whether `image` is a program that opens the files its arguments name
/// without running them (an editor, a viewer, a copy to a server).
#[must_use]
pub fn opens_files_it_names(image: &str) -> bool {
    let name = image
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(image)
        .trim()
        .to_ascii_lowercase();
    // `notepad.exe`, Debian's `vim.basic`.
    let stem = name.split('.').next().unwrap_or(&name);
    OPENS_FILES_IT_NAMES.contains(&stem)
}

/// What `launch`'s command line runs, read as `style` spells paths.
#[must_use]
pub fn read_launch(launch: &ProcessLaunch, style: PathStyle) -> LaunchReading {
    let args = launch.args.get(..MAX_ARGUMENTS).unwrap_or(&launch.args);
    let cwd = launch.cwd.as_deref();
    let mut reading = LaunchReading::default();
    let mut after_option = false;
    let mut saw_class_path = false;
    let mut class_like = false;
    let mut cmd_quotes_kept = true;
    let mut idx = 1usize;
    while idx < args.len() && idx <= MAX_SCANNED_ARGUMENTS {
        let token = args[idx].trim();
        let lower = token.to_ascii_lowercase();
        if token == "--" {
            if let Some(next) = args.get(idx + 1) {
                push_script(&mut reading, next.trim(), style, cwd, true);
            }
            return reading;
        }
        if let Some(value) = lower
            .strip_prefix("--class-path=")
            .and_then(|_| token.get("--class-path=".len()..))
        {
            reading.files.extend(class_path_files(value, style, cwd));
            saw_class_path = true;
            idx += 1;
            continue;
        }
        if matches!(lower.as_str(), "-cp" | "-classpath" | "--class-path") {
            if let Some(value) = args.get(idx + 1) {
                reading.files.extend(class_path_files(value, style, cwd));
            }
            saw_class_path = true;
            after_option = false;
            idx += 2;
            continue;
        }
        if lower == "-jar" {
            if let Some(jar) = args
                .get(idx + 1)
                .and_then(|jar| resolve(jar.trim(), style, cwd))
            {
                reading.files.push(LaunchedFile {
                    target: Launched::File(jar),
                    evidence: LaunchEvidence::JavaOption,
                });
            }
            return reading;
        }
        if style == PathStyle::Windows && lower == "/s" {
            cmd_quotes_kept = false;
        }
        if style == PathStyle::Windows && matches!(lower.as_str(), "/c" | "/k" | "/r") {
            let command = launch
                .raw
                .as_deref()
                .and_then(|raw| raw_after_argument(raw, idx))
                .map(|rest| cmd_command_program(rest, cmd_quotes_kept))
                .or_else(|| args.get(idx + 1).map(|next| next.trim().to_string()));
            if let Some(program) = command {
                push_script(&mut reading, &program, style, cwd, false);
            }
            return reading;
        }
        if is_command_option(&lower) {
            // PowerShell joins the arguments after `-Command` into one
            // command; "Run with PowerShell" ends it with `& 'path'`.
            let command = args.get(idx + 1..).map(|rest| rest.join(" "));
            if let Some(script) = command.as_deref().and_then(called_script) {
                push_script(&mut reading, &script, style, cwd, false);
            }
            return reading;
        }
        if carries_code(&lower) {
            return reading;
        }
        if is_option(token, style) {
            after_option = !token.contains('=');
            idx += 1;
            continue;
        }
        let plain = !has_script_extension(token) && !is_pathy(token, style);
        if !plain || !after_option {
            if plain && looks_like_main_class(token) {
                reading.wants_class_path = !saw_class_path;
            } else {
                push_script(&mut reading, token, style, cwd, true);
            }
            return reading;
        }
        // A plain word after an option is most likely that option's value
        // (`-ExecutionPolicy Bypass`), or a Java main class after its options.
        class_like |= looks_like_main_class(token);
        after_option = false;
        idx += 1;
    }
    reading.wants_class_path = class_like && !saw_class_path;
    reading
}

/// The files a class path names, read as `style` separates and spells it.
#[must_use]
pub fn class_path_files(value: &str, style: PathStyle, cwd: Option<&str>) -> Vec<LaunchedFile> {
    let separator = match style {
        PathStyle::Windows => ';',
        PathStyle::Linux | PathStyle::MacOS => ':',
    };
    let value = capped(value, MAX_COMMAND_LINE_BYTES);
    value
        .split(separator)
        .take(MAX_CLASS_PATH_ENTRIES)
        .filter_map(|entry| {
            let entry = entry.trim();
            if entry.is_empty() {
                return None;
            }
            let lower = entry.to_ascii_lowercase();
            let target = if let Some(folder) = entry
                .strip_suffix('*')
                .filter(|body| body.ends_with(['/', '\\']) || body.is_empty())
            {
                let folder = if folder.is_empty() { "." } else { folder };
                Launched::FilesIn(resolve(folder, style, cwd)?)
            } else if lower.ends_with(".jar") || lower.ends_with(".zip") {
                Launched::File(resolve(entry, style, cwd)?)
            } else {
                Launched::FilesIn(resolve(entry, style, cwd)?)
            };
            Some(LaunchedFile {
                target,
                evidence: LaunchEvidence::JavaOption,
            })
        })
        .collect()
}

/// Puts the file at the script position into `reading`; `false` when
/// `token` cannot be one (no path from it).
fn push_script(
    reading: &mut LaunchReading,
    token: &str,
    style: PathStyle,
    cwd: Option<&str>,
    plain_word_allowed: bool,
) -> bool {
    let token = token.trim();
    if token.is_empty() || token == "-" {
        return false;
    }
    let by_extension = has_script_extension(token);
    if !by_extension && !plain_word_allowed && !is_pathy(token, style) {
        return false;
    }
    let Some(path) = resolve(token, style, cwd) else {
        return false;
    };
    reading.files.push(LaunchedFile {
        target: Launched::File(path),
        evidence: if by_extension {
            LaunchEvidence::ScriptExtension
        } else {
            LaunchEvidence::RunsByItself
        },
    });
    true
}

/// `-c` and PowerShell's `-Command` (any prefix of three letters or more):
/// code follows, and only one form of it names a script.
fn is_command_option(lower: &str) -> bool {
    lower == "-c" || (lower.len() >= 3 && "-command".starts_with(lower))
}

/// The script a command string ends by calling: its last statement is
/// `& 'path'` or `& "path"`, with nothing but `;` and spaces after it. Any
/// other command names no script, whatever files it mentions; a double-quoted
/// path that would expand (`$`, a backtick) is not read either.
fn called_script(command: &str) -> Option<String> {
    let body = capped(command, MAX_COMMAND_LINE_BYTES)
        .trim_end_matches(|c: char| c.is_whitespace() || c == ';');
    let mut search_end = body.len();
    while let Some(amp) = body.get(..search_end)?.rfind('&') {
        let before = body.get(..amp)?.trim_end();
        if before.is_empty() || before.ends_with([';', '}']) {
            if let Some(path) = body
                .get(amp + 1..)
                .and_then(|rest| quoted_literal(rest.trim_start()))
            {
                return Some(path);
            }
        }
        search_end = amp;
    }
    None
}

/// A PowerShell string literal that is the whole of `text`: `'…'` with `''`
/// for a quote, or `"…"` with nothing to expand.
fn quoted_literal(text: &str) -> Option<String> {
    let mut chars = text.chars().peekable();
    let quote = chars.next().filter(|c| matches!(c, '\'' | '"'))?;
    let mut out = String::new();
    while let Some(c) = chars.next() {
        if c == quote {
            if quote == '\'' && chars.next_if_eq(&'\'').is_some() {
                out.push('\'');
                continue;
            }
            return chars.next().is_none().then_some(out);
        }
        if quote == '"' && matches!(c, '`' | '$') {
            return None;
        }
        out.push(c);
    }
    None
}

/// Options that hand the interpreter code instead of a file (`-c`, `-e`,
/// `-Command`, a module with `-m`): nothing after them is the script, even a
/// file the code mentions.
fn carries_code(lower: &str) -> bool {
    if matches!(
        lower,
        "-c" | "-e"
            | "-r"
            | "-m"
            | "-p"
            | "-ec"
            | "-enc"
            | "--eval"
            | "--print"
            | "--command"
            | "--module"
    ) {
        return true;
    }
    // PowerShell takes any unambiguous prefix of a parameter name.
    let prefix_of = |word: &str| lower.len() >= 3 && word.starts_with(lower);
    if prefix_of("-command") || prefix_of("-encodedcommand") {
        return true;
    }
    // Short flags bundled with the code flag. Spelled out rather than
    // derived: `-exec` (ExecutionPolicy) and `-noe` (NoExit) end the same way.
    matches!(
        lower,
        "-lc"
            | "-ic"
            | "-ilc"
            | "-xc"
            | "-uc"
            | "-pe"
            | "-ne"
            | "-le"
            | "-lne"
            | "-lpe"
            | "-we"
            | "-wle"
    )
}

fn is_option(token: &str, style: PathStyle) -> bool {
    if token.len() < 2 {
        return false;
    }
    token.starts_with('-')
        || (style == PathStyle::Windows && token.starts_with('/') && !token.contains('\\'))
}

fn is_pathy(token: &str, style: PathStyle) -> bool {
    match style {
        PathStyle::Windows => token.contains(['\\', '/']),
        PathStyle::Linux | PathStyle::MacOS => token.contains('/'),
    }
}

fn has_script_extension(token: &str) -> bool {
    let name = token.rsplit(['\\', '/']).next().unwrap_or(token);
    name.rsplit_once('.').is_some_and(|(stem, ext)| {
        !stem.is_empty()
            && SCRIPT_EXTENSIONS
                .iter()
                .any(|known| known.eq_ignore_ascii_case(ext))
    })
}

/// `Main`, `org.example.Main`: a Java class, not a file.
fn looks_like_main_class(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    let identifier = |part: &&str| {
        let mut chars = part.chars();
        chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == '$')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
    };
    if !parts.iter().all(identifier) {
        return false;
    }
    parts.len() > 1 || token.chars().next().is_some_and(|c| c.is_ascii_uppercase())
}

/// The text of `raw` after the argument at `idx` (as
/// [`split_windows_command_line`] counts them).
fn raw_after_argument(raw: &str, idx: usize) -> Option<&str> {
    let raw = capped(raw, MAX_COMMAND_LINE_BYTES);
    let (_, end) = split_windows_with_ends(raw).get(idx).cloned()?;
    raw.get(end..)
}

/// The program `cmd /c` runs: its command string with cmd's own quote rule
/// applied, up to the first unquoted space or command separator. The outer
/// quotes stay only when there are exactly two, with a space and no special
/// character between them (and no `/s`); otherwise the first and the last
/// quote go.
fn cmd_command_program(rest: &str, quotes_kept: bool) -> String {
    let rest = rest.trim_start();
    let quotes = rest.matches('"').count();
    let keep = quotes_kept && quotes == 2 && {
        let inner = rest.split('"').nth(1).unwrap_or_default();
        inner.contains([' ', '\t']) && !inner.contains(['&', '<', '>', '(', ')', '@', '^', '|'])
    };
    let command: String = if !keep && rest.starts_with('"') {
        let body = rest.get(1..).unwrap_or_default();
        match body.rfind('"') {
            Some(last) => format!(
                "{}{}",
                body.get(..last).unwrap_or_default(),
                body.get(last + 1..).unwrap_or_default()
            ),
            None => body.to_string(),
        }
    } else {
        rest.to_string()
    };
    let command = command.trim_start();
    if let Some(quoted) = command.strip_prefix('"') {
        return quoted.split('"').next().unwrap_or_default().to_string();
    }
    command
        .split(|c: char| c.is_whitespace() || matches!(c, '&' | '|' | '<' | '>' | '(' | ')'))
        .next()
        .unwrap_or_default()
        .to_string()
}

/// `token` as an absolute path with `.` and `..` worked out, against `cwd`
/// when relative; `None` when it cannot be placed or climbs past its root.
fn resolve(token: &str, style: PathStyle, cwd: Option<&str>) -> Option<String> {
    let token = token.trim();
    if token.is_empty() || token.len() > MAX_PATH_BYTES || token.chars().any(char::is_control) {
        return None;
    }
    let joined = match style {
        PathStyle::Windows => {
            let bytes = token.as_bytes();
            let drive_absolute = bytes.first().is_some_and(u8::is_ascii_alphabetic)
                && bytes.get(1) == Some(&b':')
                && matches!(bytes.get(2), Some(b'\\' | b'/'));
            let share = matches!(bytes, [b'\\' | b'/', b'\\' | b'/', ..]);
            if drive_absolute || share {
                token.to_string()
            } else if bytes.get(1) == Some(&b':') {
                // `C:tool.py` is relative to that drive's own folder.
                return None;
            } else if matches!(bytes.first(), Some(b'\\' | b'/')) {
                let cwd = cwd?;
                let drive = cwd
                    .get(..2)
                    .filter(|d| d.as_bytes().get(1) == Some(&b':'))?;
                format!("{drive}{token}")
            } else {
                format!("{}\\{token}", cwd?)
            }
        }
        PathStyle::Linux | PathStyle::MacOS => {
            if token.starts_with('/') {
                token.to_string()
            } else {
                format!("{}/{token}", cwd?)
            }
        }
    };
    if joined.len() > MAX_PATH_BYTES {
        return None;
    }
    normalize(&joined, style)
}

/// `.` and `..` worked out without the disk.
fn normalize(path: &str, style: PathStyle) -> Option<String> {
    match style {
        PathStyle::Windows => {
            let unified = path.replace('/', "\\");
            let (root, rest) = if let Some(share) = unified.strip_prefix(r"\\") {
                let mut parts = share.splitn(3, '\\');
                let server = parts.next().filter(|p| !p.is_empty())?;
                let name = parts.next().filter(|p| !p.is_empty())?;
                (
                    format!(r"\\{server}\{name}"),
                    parts.next().unwrap_or_default().to_string(),
                )
            } else {
                (
                    unified.get(..2)?.to_string(),
                    unified.get(2..).unwrap_or_default().to_string(),
                )
            };
            let segments = climb(rest.split('\\'))?;
            Some(format!("{root}\\{}", segments.join("\\")))
        }
        PathStyle::Linux | PathStyle::MacOS => {
            let segments = climb(path.split('/'))?;
            Some(format!("/{}", segments.join("/")))
        }
    }
}

fn climb<'a>(parts: impl Iterator<Item = &'a str>) -> Option<Vec<&'a str>> {
    let mut segments: Vec<&str> = Vec::new();
    for part in parts {
        match part {
            "" | "." => {}
            ".." => {
                segments.pop()?;
            }
            _ => segments.push(part),
        }
    }
    Some(segments)
}

#[cfg(test)]
mod tests;
