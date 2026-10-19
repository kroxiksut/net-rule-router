//! Which system programs and folders a rule may not deny or send over the
//! additional route.
//!
//! Denying `svchost.exe` or routing `C:\Program Files\*` through a tunnel
//! breaks the machine, not one site. The decision is pure: the machine's own
//! folders arrive as [`ProtectedPlaces`], which the service builds through the
//! platform port; the per-OS lists here are the data that holds where the port
//! knows nothing better.
//!
//! The main route is the default path every program already takes, so it is
//! never refused for what it names. A deny and the additional route are.
//!
//! # Three verdicts
//!
//! - refused: a critical system process by name or mask; a folder rule on a
//!   system folder (anywhere inside it), on a shared folder or anything above
//!   one, or on a folder of the system search path; anything covering our own
//!   install folder or the disk root;
//! - warned: one file in a system folder (`System32\curl.exe`);
//! - allowed: everything else, a program's own folder inside a shared one
//!   included (`C:\Program Files\App\*`, `/usr/lib/firefox/*`).
//!
//! A refused rule written with `+override` asks to apply anyway. Only its
//! owner's confirmation, kept by the service, lifts the refusal, and never
//! for the disk root or our own programs ([`withhold_protected_unless`]).

use crate::canonical::{
    CanonicalAppPattern, CanonicalRule, CanonicalRuleBook, CanonicalRuleSet, RuleAction,
};
use crate::rules_file::HostPlatform;
use crate::{RouteRole, RuleId};
use nrr_shared::app_identity::app_match_key;
use nrr_shared::app_path::AppPathKind;
use nrr_shared::glob::glob_match;
use nrr_shared::product_identity::BinaryRole;

mod coverage;
pub use coverage::*;

// ── Effect and target ─────────────────────────────────────────────────────────

/// What a rule does to the programs it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RuleEffect {
    /// `!value`: their traffic is dropped.
    Deny,
    /// The main route — the path they take anyway.
    PrimaryRoute,
    /// The additional route.
    SecondaryRoute,
}

impl RuleEffect {
    /// The effect of a rule with `action` written in `role`'s file.
    #[must_use]
    pub const fn of(action: RuleAction, role: RouteRole) -> Self {
        match (action, role) {
            (RuleAction::Block, _) => Self::Deny,
            (RuleAction::Route | RuleAction::Verify, RouteRole::Primary) => Self::PrimaryRoute,
            (RuleAction::Route | RuleAction::Verify, RouteRole::Secondary) => Self::SecondaryRoute,
        }
    }

    /// The effect a rules-table route slug names (`primary`, `secondary`,
    /// `block`); `None` for any other slug.
    #[must_use]
    pub fn from_route_slug(slug: &str) -> Option<Self> {
        match slug {
            "primary" => Some(Self::PrimaryRoute),
            "secondary" => Some(Self::SecondaryRoute),
            "block" => Some(Self::Deny),
            _ => None,
        }
    }

    /// Whether this effect can break the programs it names.
    #[must_use]
    pub const fn guarded(self) -> bool {
        matches!(self, Self::Deny | Self::SecondaryRoute)
    }
}

/// The programs an application rule names. Paths are as written; the verdict
/// normalizes them for the platform of the [`ProtectedPlaces`] it is given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppTarget<'a> {
    /// A process file name (`svchost.exe`, `NetworkManager`).
    Name(&'a str),
    /// A mask over process file names (`svc*.exe`).
    NameGlob(&'a str),
    /// One executable by full path.
    File(&'a str),
    /// The programs directly in one folder.
    Folder(&'a str),
    /// The programs in one folder and every folder below it.
    FolderTree(&'a str),
    /// A file or a folder, whichever is there when the rule is applied
    /// (`/opt/app` on Linux or macOS): judged as both.
    FileOrFolder(&'a str),
}

impl<'a> AppTarget<'a> {
    /// The target a canonical application pattern names.
    #[must_use]
    pub fn of_pattern(pattern: &'a CanonicalAppPattern) -> Self {
        match pattern {
            CanonicalAppPattern::Exact(name) => Self::Name(name),
            CanonicalAppPattern::Glob(glob) => Self::NameGlob(glob),
            CanonicalAppPattern::Path(path) => Self::of_path(path),
        }
    }

    /// The target a path names, in the form it has: as written, or as the
    /// disk decided it.
    #[must_use]
    pub fn of_path(path: &'a nrr_shared::app_path::AppPath) -> Self {
        match path.kind() {
            AppPathKind::File => Self::File(path.place()),
            AppPathKind::Folder => Self::Folder(path.place()),
            AppPathKind::FolderTree => Self::FolderTree(path.place()),
            AppPathKind::FileOrFolder => Self::FileOrFolder(path.place()),
        }
    }
}

// ── Verdict ───────────────────────────────────────────────────────────────────

/// Why a target is protected. The slug is stable: it reaches the wire, the
/// log and the locale keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProtectionReason {
    /// A process the system needs for the network, sign-in or time.
    CriticalProcess,
    /// One of our own programs or the folder they are installed in.
    OwnProgram,
    /// The root of a disk or `/`.
    DiskRoot,
    /// A folder inside a system folder (`C:\Windows`, `/usr/bin`, `/etc`).
    SystemFolder,
    /// A folder many programs share (`C:\Program Files`, `/opt`, `/home/x`),
    /// or a folder above one.
    SharedFolder,
    /// A folder of the system search path, where unrelated programs sit side
    /// by side.
    SearchPathFolder,
    /// One file in a system folder or on the search path: a warning only.
    FileInSystemFolder,
    /// Not an absolute path in this platform's spelling, or one that climbs
    /// with `..`: nothing can say what it covers.
    NotAPlainPath,
    /// Not a protection: a rule by program path, which this platform cannot
    /// apply yet. Withheld the same way, so it is never a silent no-op.
    AppPathUnsupported,
}

impl ProtectionReason {
    /// Every reason, for exhaustive tables and locale checks.
    pub const ALL: [Self; 9] = [
        Self::CriticalProcess,
        Self::OwnProgram,
        Self::DiskRoot,
        Self::SystemFolder,
        Self::SharedFolder,
        Self::SearchPathFolder,
        Self::FileInSystemFolder,
        Self::NotAPlainPath,
        Self::AppPathUnsupported,
    ];

    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::CriticalProcess => "critical-process",
            Self::OwnProgram => "own-program",
            Self::DiskRoot => "disk-root",
            Self::SystemFolder => "system-folder",
            Self::SharedFolder => "shared-folder",
            Self::SearchPathFolder => "search-path-folder",
            Self::FileInSystemFolder => "file-in-system-folder",
            Self::NotAPlainPath => "not-a-plain-path",
            Self::AppPathUnsupported => "app-path-unsupported",
        }
    }

    /// The reason a slug names; `None` for an unknown one.
    #[must_use]
    pub fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|reason| reason.slug() == slug)
    }

    /// Whether a deliberate override may lift the refusal. The disk root and
    /// our own programs never: the first takes the whole machine, the second
    /// the product that would have to undo it.
    #[must_use]
    pub const fn overridable(self) -> bool {
        !matches!(
            self,
            Self::DiskRoot | Self::OwnProgram | Self::NotAPlainPath | Self::AppPathUnsupported
        )
    }
}

impl core::fmt::Display for ProtectionReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.slug())
    }
}

/// What may be done with a target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtectionVerdict {
    Allowed,
    /// Accepted, with a word to the user.
    Warn(ProtectionReason),
    /// Not accepted when submitted, not applied when stored.
    Refused(ProtectionReason),
}

impl ProtectionVerdict {
    #[must_use]
    pub const fn is_refused(self) -> bool {
        matches!(self, Self::Refused(_))
    }
}

// ── Protected places ──────────────────────────────────────────────────────────

/// Folders a value from the machine may name at most, per list; past it the
/// rest is ignored. A search path longer than this is not a real one.
pub const MAX_PLACES_PER_LIST: usize = 256;

/// Longest path, in bytes, and most segments the verdict reads; past either
/// it is refused.
pub use nrr_shared::app_path::{MAX_PATH_BYTES, MAX_PATH_SEGMENTS};

/// One folder of a list, as normalized segments; a segment may hold `*`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Place {
    segments: Vec<String>,
}

/// The protected folders of one machine, normalized for its platform.
///
/// [`Self::defaults`] holds the per-OS lists; the platform port adds what only
/// the machine knows (where Windows lives, the search path, our install
/// folder). Adding a path that does not normalize (relative, `..`, empty) is a
/// no-op: a search path may hold such entries, and they name no folder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectedPlaces {
    platform: HostPlatform,
    system: Vec<Place>,
    /// Inside a system folder, yet not part of it (`/usr/local` on macOS).
    carve_outs: Vec<Place>,
    shared: Vec<Place>,
    search_path: Vec<Place>,
    own: Vec<Place>,
}

impl ProtectedPlaces {
    /// No folder at all: a base for tests and for a port that builds every
    /// list itself.
    #[must_use]
    pub const fn empty(platform: HostPlatform) -> Self {
        Self {
            platform,
            system: Vec::new(),
            carve_outs: Vec::new(),
            shared: Vec::new(),
            search_path: Vec::new(),
            own: Vec::new(),
        }
    }

    /// The per-OS lists. Windows paths name drive `C:`: the port replaces
    /// them with the folders Windows registers, these hold only where it
    /// cannot ask.
    #[must_use]
    pub fn defaults(platform: HostPlatform) -> Self {
        let mut places = Self::empty(platform);
        let lists = default_lists(platform);
        for path in lists.system {
            places.add_system_folder(path);
        }
        for path in lists.carve_outs {
            places.add(Self::carve_outs_mut, path);
        }
        for path in lists.shared {
            places.add_shared_folder(path);
        }
        for path in lists.search_path {
            places.add_search_path_folder(path);
        }
        places
    }

    #[must_use]
    pub const fn platform(&self) -> HostPlatform {
        self.platform
    }

    /// A folder protected at any depth inside it.
    pub fn add_system_folder(&mut self, path: &str) {
        self.add(Self::system_mut, path);
    }

    /// A folder protected itself and from above; a folder inside is allowed.
    pub fn add_shared_folder(&mut self, path: &str) {
        self.add(Self::shared_mut, path);
    }

    /// A folder of the system search path.
    pub fn add_search_path_folder(&mut self, path: &str) {
        self.add(Self::search_path_mut, path);
    }

    /// Our own install folder: nothing inside or above it is accepted.
    pub fn add_own_folder(&mut self, path: &str) {
        self.add(Self::own_mut, path);
    }

    fn system_mut(&mut self) -> &mut Vec<Place> {
        &mut self.system
    }
    fn carve_outs_mut(&mut self) -> &mut Vec<Place> {
        &mut self.carve_outs
    }
    fn shared_mut(&mut self) -> &mut Vec<Place> {
        &mut self.shared
    }
    fn search_path_mut(&mut self) -> &mut Vec<Place> {
        &mut self.search_path
    }
    fn own_mut(&mut self) -> &mut Vec<Place> {
        &mut self.own
    }

    fn add(&mut self, list: fn(&mut Self) -> &mut Vec<Place>, path: &str) {
        let platform = self.platform;
        let Some(segments) = path_segments(path, platform, true) else {
            return;
        };
        let place = Place { segments };
        let list = list(self);
        if list.len() < MAX_PLACES_PER_LIST && !list.contains(&place) {
            list.push(place);
        }
    }

    fn in_system(&self, path: &[String]) -> bool {
        self.system.iter().any(|p| inside(path, &p.segments))
            && !self.carve_outs.iter().any(|p| inside(path, &p.segments))
    }
}

/// The static lists of one OS.
struct DefaultLists {
    system: &'static [&'static str],
    carve_outs: &'static [&'static str],
    shared: &'static [&'static str],
    search_path: &'static [&'static str],
}

fn default_lists(platform: HostPlatform) -> DefaultLists {
    match platform {
        HostPlatform::Windows => DefaultLists {
            system: &[
                r"C:\Windows",
                r"C:\Program Files\Windows Defender",
                r"C:\Program Files\Windows Defender Advanced Threat Protection",
                r"C:\ProgramData\Microsoft\Windows Defender",
                r"C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection",
            ],
            carve_outs: &[],
            shared: &[
                r"C:\Program Files",
                r"C:\Program Files (x86)",
                r"C:\ProgramData",
                r"C:\Users",
                r"C:\Users\*",
                r"C:\inetpub",
                r"C:\inetpub\wwwroot",
            ],
            search_path: &[
                r"C:\Windows\System32",
                r"C:\Windows",
                r"C:\Windows\System32\Wbem",
                r"C:\Windows\System32\WindowsPowerShell\v1.0",
                r"C:\Windows\System32\OpenSSH",
            ],
        },
        HostPlatform::Linux => DefaultLists {
            system: &[
                "/bin",
                "/sbin",
                "/usr/bin",
                "/usr/sbin",
                "/usr/local/bin",
                "/usr/local/sbin",
                "/usr/games",
                "/lib*/systemd",
                "/usr/lib*/systemd",
                "/usr/lib*/NetworkManager",
                "/etc",
                "/boot",
            ],
            carve_outs: &[],
            shared: &[
                "/*",
                "/usr/lib*",
                "/usr/libexec",
                "/usr/share",
                "/usr/local",
                "/usr/local/lib",
                "/home/*",
                "/var/www",
                "/srv/www",
                "/srv/http",
            ],
            search_path: &[
                "/usr/local/sbin",
                "/usr/local/bin",
                "/usr/sbin",
                "/usr/bin",
                "/sbin",
                "/bin",
                "/snap/bin",
            ],
        },
        HostPlatform::MacOS => DefaultLists {
            system: &["/System", "/bin", "/sbin", "/usr"],
            carve_outs: &["/usr/local"],
            shared: &[
                "/Applications",
                "/Library",
                "/Users",
                "/Users/*",
                "/Library/WebServer/Documents",
                "/usr/local",
                "/opt",
                "/opt/homebrew",
            ],
            search_path: &[
                "/usr/local/bin",
                "/usr/bin",
                "/bin",
                "/usr/sbin",
                "/sbin",
                "/opt/homebrew/bin",
            ],
        },
    }
}

// ── Critical processes ────────────────────────────────────────────────────────

/// Processes whose loss breaks the network, sign-in or time, as match keys
/// (file name, lower case, no `.exe`). A `*` entry names a family.
const fn critical_processes(platform: HostPlatform) -> &'static [&'static str] {
    match platform {
        HostPlatform::Windows => &[
            "svchost", "lsass", "services", "csrss", "wininit", "smss", "winlogon", "msmpeng",
        ],
        HostPlatform::Linux => &[
            "systemd*",
            "networkmanager",
            "nm-dispatcher",
            "nm-dhcp-helper",
            "dhclient",
            "dhcpcd",
            "wpa_supplicant",
            "chronyd",
            "ntpd",
            "init",
            "dnsmasq",
        ],
        HostPlatform::MacOS => &[
            "launchd",
            "mdnsresponder",
            "mdnsresponderhelper",
            "configd",
            "timed",
        ],
    }
}

/// Members of each critical family, so a mask is judged by what it would
/// catch: `system*` catches `systemd-resolved` though it names no entry.
const fn critical_family_members(platform: HostPlatform) -> &'static [&'static str] {
    match platform {
        HostPlatform::Linux => &[
            "systemd",
            "systemd-resolved",
            "systemd-networkd",
            "systemd-timesyncd",
            "systemd-logind",
            "systemd-journald",
            "systemd-udevd",
        ],
        HostPlatform::Windows | HostPlatform::MacOS => &[],
    }
}

/// Our own executables on `platform`, as match keys.
fn own_program_keys(platform: HostPlatform) -> impl Iterator<Item = String> {
    BinaryRole::ALL.iter().flat_map(move |role| {
        let names: [Option<&str>; 2] = match platform {
            HostPlatform::Windows => [Some(role.windows_file_name()), None],
            HostPlatform::Linux | HostPlatform::MacOS => {
                [Some(role.unix_file_name()), role.unix_alias()]
            }
        };
        names.into_iter().flatten().map(app_match_key)
    })
}

/// Why a name or mask is protected for a guarded effect, if it is.
fn name_refusal(text: &str, glob: bool, platform: HostPlatform) -> Option<ProtectionReason> {
    let key = app_match_key(text);
    if key.is_empty() {
        return None;
    }
    let catches = |name: &str| {
        if glob {
            glob_match(&key, name)
        } else {
            key == name
        }
    };
    if own_program_keys(platform).any(|own| catches(&own)) {
        return Some(ProtectionReason::OwnProgram);
    }
    let critical = critical_processes(platform);
    // An entry that is itself a family mask holds the name or mask when it
    // matches it as text; a mask is also judged by every concrete member.
    let named = critical.iter().any(|entry| glob_match(entry, &key));
    let caught = glob
        && critical
            .iter()
            .chain(critical_family_members(platform))
            .filter(|entry| !entry.contains('*'))
            .any(|entry| glob_match(&key, entry));
    (named || caught).then_some(ProtectionReason::CriticalProcess)
}

// ── Paths ─────────────────────────────────────────────────────────────────────

/// Segments of the root itself: the drive (`c:`) or share on Windows, none
/// on Unix.
const fn root_len(platform: HostPlatform) -> usize {
    platform.path_style().root_len()
}

/// The segments of an absolute path as `platform` compares them: the one
/// reading application rules share, see [`nrr_shared::app_path::path_segments`].
fn path_segments(path: &str, platform: HostPlatform, pattern: bool) -> Option<Vec<String>> {
    nrr_shared::app_path::path_segments(path, platform.path_style(), pattern)
}

/// `text` matches `pattern`, `*` the only wildcard, characters compared
/// exactly: both sides are already folded where the platform ignores case.
fn segment_matches(pattern: &str, text: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == text;
    }
    let (pat, txt): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    let (mut p, mut t) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    loop {
        if pat.get(p) == Some(&'*') {
            while pat.get(p) == Some(&'*') {
                p += 1;
            }
            if p == pat.len() {
                return true;
            }
            star = Some((p, t));
            continue;
        }
        if let (Some(pc), Some(tc)) = (pat.get(p), txt.get(t)) {
            if pc == tc {
                p += 1;
                t += 1;
                continue;
            }
        }
        if p == pat.len() && t == txt.len() {
            return true;
        }
        match star {
            Some((resume_p, resume_t)) if resume_t < txt.len() => {
                p = resume_p;
                t = resume_t + 1;
                star = Some((resume_p, t));
            }
            _ => return false,
        }
    }
}

/// `path` is `place` or inside it.
fn inside(path: &[String], place: &[String]) -> bool {
    place.len() <= path.len()
        && place
            .iter()
            .zip(path)
            .all(|(pattern, segment)| segment_matches(pattern, segment))
}

/// `path` is `place` itself.
fn same(path: &[String], place: &[String]) -> bool {
    path.len() == place.len() && inside(path, place)
}

/// `path` is `place` or above it.
fn above(path: &[String], place: &[String]) -> bool {
    path.len() <= place.len()
        && path
            .iter()
            .zip(place)
            .all(|(segment, pattern)| segment_matches(pattern, segment))
}

/// A folder rule on `path` reaches `place`: names it, or — with subfolders —
/// sits above it.
fn reaches(path: &[String], place: &[String], tree: bool) -> bool {
    if tree {
        above(path, place)
    } else {
        same(path, place)
    }
}

fn folder_verdict(path: &[String], tree: bool, places: &ProtectedPlaces) -> ProtectionVerdict {
    use ProtectionReason as R;
    if path.len() <= root_len(places.platform) {
        return ProtectionVerdict::Refused(R::DiskRoot);
    }
    let any = |list: &[Place], hit: &dyn Fn(&[String]) -> bool| {
        list.iter().any(|place| hit(&place.segments))
    };
    if any(&places.own, &|own: &[String]| {
        inside(path, own) || reaches(path, own, tree)
    }) {
        return ProtectionVerdict::Refused(R::OwnProgram);
    }
    if places.in_system(path) {
        return ProtectionVerdict::Refused(R::SystemFolder);
    }
    // A shared folder before a system one above which the rule sits: the
    // user wrote `Program Files`, not the Defender folder inside it.
    if any(&places.shared, &|shared: &[String]| {
        reaches(path, shared, tree)
    }) {
        return ProtectionVerdict::Refused(R::SharedFolder);
    }
    if tree && any(&places.system, &|system: &[String]| above(path, system)) {
        return ProtectionVerdict::Refused(R::SystemFolder);
    }
    if any(&places.search_path, &|dir: &[String]| {
        reaches(path, dir, tree)
    }) {
        return ProtectionVerdict::Refused(R::SearchPathFolder);
    }
    ProtectionVerdict::Allowed
}

fn file_verdict(path: &[String], places: &ProtectedPlaces) -> ProtectionVerdict {
    use ProtectionReason as R;
    let Some((name, folder)) = path
        .split_last()
        .filter(|(_, folder)| folder.len() >= root_len(places.platform))
    else {
        return ProtectionVerdict::Refused(R::NotAPlainPath);
    };
    if places.own.iter().any(|own| inside(path, &own.segments)) {
        return ProtectionVerdict::Refused(R::OwnProgram);
    }
    if let Some(reason) = name_refusal(name, false, places.platform) {
        return ProtectionVerdict::Refused(reason);
    }
    let on_search_path = places
        .search_path
        .iter()
        .any(|dir| same(folder, &dir.segments));
    if places.in_system(folder) || on_search_path {
        return ProtectionVerdict::Warn(R::FileInSystemFolder);
    }
    ProtectionVerdict::Allowed
}

// ── Entry points ──────────────────────────────────────────────────────────────

/// The verdict on a rule that does `effect` to `target`, on the machine
/// `places` describes. The one answer every surface reads: the Add dialog,
/// the rules table, the service's acceptance and its compile.
#[must_use]
pub fn protection_verdict(
    target: AppTarget<'_>,
    effect: RuleEffect,
    places: &ProtectedPlaces,
) -> ProtectionVerdict {
    let platform = places.platform;
    let path = |text: &str| path_segments(text, platform, false);
    let refused_name = |text: &str, glob: bool| {
        name_refusal(text, glob, platform)
            .map_or(ProtectionVerdict::Allowed, ProtectionVerdict::Refused)
    };
    match target {
        AppTarget::Name(_) | AppTarget::NameGlob(_) if !effect.guarded() => {
            ProtectionVerdict::Allowed
        }
        AppTarget::Name(name) => refused_name(name, false),
        AppTarget::NameGlob(glob) => refused_name(glob, true),
        AppTarget::File(text)
        | AppTarget::Folder(text)
        | AppTarget::FolderTree(text)
        | AppTarget::FileOrFolder(text) => {
            let Some(segments) = path(text) else {
                return ProtectionVerdict::Refused(ProtectionReason::NotAPlainPath);
            };
            if !effect.guarded() {
                return ProtectionVerdict::Allowed;
            }
            match target {
                AppTarget::File(_) => file_verdict(&segments, places),
                AppTarget::Folder(_) => folder_verdict(&segments, false, places),
                AppTarget::FileOrFolder(_) => undecided_verdict(&segments, places),
                _ => folder_verdict(&segments, true, places),
            }
        }
    }
}

/// A path that is a file or a folder by what is on disk (`/opt/app` on Linux
/// or macOS): judged as the folder when it names a protected folder itself or
/// one above it, and as a file deeper inside a system folder, where programs
/// sit (`/usr/bin/curl`). Enforcement judges the rule again once the disk has
/// decided its kind and its real place.
fn undecided_verdict(path: &[String], places: &ProtectedPlaces) -> ProtectionVerdict {
    let as_file = file_verdict(path, places);
    let as_folder = folder_verdict(path, false, places);
    let names_system_folder = places.system.iter().any(|p| same(path, &p.segments));
    if as_folder == ProtectionVerdict::Refused(ProtectionReason::SystemFolder)
        && !names_system_folder
    {
        return as_file;
    }
    stricter(as_file, as_folder)
}

/// The verdict that says more: a refusal over a warning over nothing.
fn stricter(a: ProtectionVerdict, b: ProtectionVerdict) -> ProtectionVerdict {
    let rank = |v: ProtectionVerdict| match v {
        ProtectionVerdict::Refused(_) => 2,
        ProtectionVerdict::Warn(_) => 1,
        ProtectionVerdict::Allowed => 0,
    };
    if rank(b) > rank(a) {
        b
    } else {
        a
    }
}

/// The verdict on one canonical rule written in `role`'s file. A rule that
/// names no application is not a question for this module.
#[must_use]
pub fn rule_protection(
    rule: &CanonicalRule,
    role: RouteRole,
    places: &ProtectedPlaces,
) -> ProtectionVerdict {
    rule.app_match
        .as_ref()
        .map_or(ProtectionVerdict::Allowed, |app| {
            protection_verdict(
                AppTarget::of_pattern(&app.pattern),
                RuleEffect::of(rule.action, role),
                places,
            )
        })
}

/// A stored rule the protection keeps from being applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectedRule {
    pub rule_id: RuleId,
    /// What the rule names, as the rules table shows it.
    pub value: String,
    pub effect: RuleEffect,
    pub reason: ProtectionReason,
    /// The rule asks to apply anyway (`+override`) and the protection allows
    /// that: it waits for its owner's confirmation rather than being refused.
    pub override_pending: bool,
}

// ── Deliberate overrides ──────────────────────────────────────────────────────

/// Critical processes one rule covers, at most: a rule naming more than this
/// is told by the first ones, and confirming it still binds them all.
pub const MAX_CRITICAL_NAMED: usize = 64;

/// A refused rule that asks to apply anyway, as a confirmation is weighed
/// against it: the rule's value as the table shows it, what it does, why it
/// is refused, and the critical processes it covers now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OverrideAsk<'a> {
    pub value: &'a str,
    pub effect: RuleEffect,
    pub reason: ProtectionReason,
    pub critical: &'a [String],
}

/// Whether a confirmation recorded for `critical_then` still covers what the
/// rule takes now: a critical process it did not name means the owner never
/// agreed to it, and the rule waits for a confirmation again.
#[must_use]
pub fn confirmation_still_covers(critical_then: &[String], critical_now: &[String]) -> bool {
    critical_now
        .iter()
        .all(|name| critical_then.iter().any(|then| then == name))
}

/// Whether `key` (a match key) is one of `platform`'s critical processes.
fn is_critical_key(key: &str, platform: HostPlatform) -> bool {
    !key.is_empty()
        && critical_processes(platform)
            .iter()
            .any(|entry| glob_match(entry, key))
}

/// The critical processes a rule on `target` takes, as match keys, sorted and
/// at most [`MAX_CRITICAL_NAMED`]: the ones a name or a mask catches, or — for
/// a rule by path — the ones among `programs`, the programs its place holds.
#[must_use]
pub fn critical_processes_covered<P: AsRef<str>>(
    target: AppTarget<'_>,
    programs: &[P],
    platform: HostPlatform,
) -> Vec<String> {
    let mut found: Vec<String> = match target {
        AppTarget::Name(name) => {
            let key = app_match_key(name);
            if is_critical_key(&key, platform) {
                vec![key]
            } else {
                Vec::new()
            }
        }
        AppTarget::NameGlob(glob) => {
            let key = app_match_key(glob);
            critical_processes(platform)
                .iter()
                .chain(critical_family_members(platform))
                .filter(|entry| glob_match(&key, entry) || glob_match(entry, &key))
                .map(|entry| (*entry).to_owned())
                .collect()
        }
        AppTarget::File(_)
        | AppTarget::Folder(_)
        | AppTarget::FolderTree(_)
        | AppTarget::FileOrFolder(_) => {
            // The key is the file name, whichever separator the path uses.
            let mut named: Vec<String> = programs
                .iter()
                .map(|program| app_match_key(program.as_ref()))
                .filter(|key| is_critical_key(key, platform))
                .collect();
            if let AppTarget::File(path) = target {
                let key = app_match_key(path);
                if is_critical_key(&key, platform) {
                    named.push(key);
                }
            }
            named
        }
    };
    found.sort_unstable();
    found.dedup();
    found.truncate(MAX_CRITICAL_NAMED);
    found
}

/// `book` without the rules the protection refuses, and those rules. Only
/// enabled ones are reported: a disabled rule applies nothing either way.
/// Enforcement-only, like the subdomain coverage: never stored or hashed, so
/// the rule stays in the user's book and in the rules table.
#[must_use]
pub fn withhold_protected(
    book: CanonicalRuleBook,
    places: &ProtectedPlaces,
) -> (CanonicalRuleBook, Vec<ProtectedRule>) {
    withhold_protected_unless(book, places, |_| false)
}

/// [`withhold_protected`], keeping a refused rule that asks to apply anyway
/// when `confirmed` says its owner confirmed it. Nothing else lifts a
/// refusal, and only a reason that [`ProtectionReason::overridable`] can be.
/// A rule by path is judged again where the disk names its programs.
#[must_use]
pub fn withhold_protected_unless(
    book: CanonicalRuleBook,
    places: &ProtectedPlaces,
    confirmed: impl Fn(&OverrideAsk<'_>) -> bool,
) -> (CanonicalRuleBook, Vec<ProtectedRule>) {
    withhold(book, |rule, role| {
        let verdict = rule_protection(rule, role, places);
        let ProtectionVerdict::Refused(reason) = verdict else {
            return verdict;
        };
        let Some(app) = rule.app_match.as_ref() else {
            return verdict;
        };
        if !(app.override_requested && reason.overridable()) {
            return verdict;
        }
        let target = AppTarget::of_pattern(&app.pattern);
        let critical = critical_processes_covered::<&str>(target, &[], places.platform);
        let ask = OverrideAsk {
            value: app.pattern.as_str(),
            effect: RuleEffect::of(rule.action, role),
            reason,
            critical: &critical,
        };
        if confirmed(&ask) {
            ProtectionVerdict::Allowed
        } else {
            verdict
        }
    })
}

/// `book` without its rules by program path, and those rules, for a platform
/// that cannot apply them yet. Enforcement-only, like [`withhold_protected`]:
/// the rule stays in the book and is reported, never a silent no-op.
#[must_use]
pub fn withhold_app_paths(book: CanonicalRuleBook) -> (CanonicalRuleBook, Vec<ProtectedRule>) {
    withhold(book, |rule, _| {
        let path = rule.app_match.as_ref().and_then(|app| app.pattern.path());
        if path.is_some() {
            ProtectionVerdict::Refused(ProtectionReason::AppPathUnsupported)
        } else {
            ProtectionVerdict::Allowed
        }
    })
}

/// `book` without the rules `judge` refuses, and those rules (enabled ones
/// only: a disabled rule applies nothing either way).
fn withhold(
    book: CanonicalRuleBook,
    judge: impl Fn(&CanonicalRule, RouteRole) -> ProtectionVerdict,
) -> (CanonicalRuleBook, Vec<ProtectedRule>) {
    let mut withheld = Vec::new();
    let mut keep = |set: CanonicalRuleSet, role: RouteRole| -> CanonicalRuleSet {
        let verdicts: Vec<ProtectionVerdict> =
            set.rules().iter().map(|rule| judge(rule, role)).collect();
        if !verdicts.iter().any(|verdict| verdict.is_refused()) {
            return set;
        }
        let mut kept = Vec::with_capacity(set.len());
        for (rule, verdict) in set.rules().iter().zip(verdicts) {
            match verdict {
                ProtectionVerdict::Refused(reason) => {
                    if rule.enabled {
                        let app = rule.app_match.as_ref();
                        withheld.push(ProtectedRule {
                            rule_id: rule.id.clone(),
                            value: app
                                .map(|app| app.pattern.as_str().to_string())
                                .unwrap_or_default(),
                            effect: RuleEffect::of(rule.action, role),
                            reason,
                            override_pending: reason.overridable()
                                && app.is_some_and(|app| app.override_requested),
                        });
                    }
                }
                ProtectionVerdict::Allowed | ProtectionVerdict::Warn(_) => kept.push(rule.clone()),
            }
        }
        CanonicalRuleSet::from_rules(kept)
    };
    let primary = keep(book.primary, RouteRole::Primary);
    let secondary = keep(book.secondary, RouteRole::Secondary);
    (CanonicalRuleBook { primary, secondary }, withheld)
}

#[cfg(test)]
mod tests;
