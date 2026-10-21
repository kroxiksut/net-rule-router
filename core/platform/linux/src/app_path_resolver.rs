//! Linux mechanism behind
//! [`nrr_platform_api::app_path_resolver::AppPathResolver`].
//!
//! ## The `.exe` a name may still carry
//!
//! A Linux rule is stored as the process is named, but one stored before
//! `.exe` became Windows-only, or typed with it, still reads `messenger.exe`.
//! This backend strips the suffix before looking, so both spellings find the
//! same file — and a genuinely `.exe`-named Wine program is tried as written.
//!
//! ## Where it looks
//!
//! `$PATH`, plus the export directories Flatpak and Snap publish into (usually
//! on `$PATH` already, listed so a service started with a bare environment
//! still finds them). An application installed outside them (`/opt/<vendor>`,
//! an unpacked bundle) is found through the `Exec=` of its desktop entry and
//! through the images of running processes, the Linux twins of the Windows
//! App Paths and process sources. Only regular files with an execute bit
//! count — a directory or a stray data file with a matching name is not an
//! application.
//!
//! Resolution is never an error: an app that is not installed resolves to an
//! empty vector, same as on Windows.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use nrr_platform_api::app_folders::{AppPath, PathPrograms, ProgramFolderIndex};
use nrr_platform_api::app_path_resolver::{dedup_paths, glob_match, AppPathResolver};

use crate::app_scan::{application_dirs, desktop_apps_in, running_processes};

/// How long one scan of `/proc` and the desktop entries answers every rule:
/// a plan resolves each application rule in turn, and one scan serves them all.
const ELSEWHERE_TTL: Duration = Duration::from_secs(5);

type ElsewhereCache = Arc<Mutex<Option<(Instant, Arc<Vec<PathBuf>>)>>>;

/// Production resolver over `$PATH`, the package-manager export dirs, desktop
/// entries and running processes.
///
/// No cache for names: this runs while an apply is being planned, not on the
/// traffic path, and a directory listing per candidate is cheap next to the
/// filter codegen that follows. Only the process and desktop-entry scan is
/// shared, for [`ELSEWHERE_TTL`]. Rules by path go through a watched index.
#[derive(Clone)]
pub struct LinuxAppPathResolver {
    folders: Arc<ProgramFolderIndex>,
    elsewhere: ElsewhereCache,
}

impl Default for LinuxAppPathResolver {
    fn default() -> Self {
        Self::with_program_folders(Arc::new(ProgramFolderIndex::new(Arc::new(
            crate::app_folders::LinuxProgramFolders::new(),
        ))))
    }
}

impl LinuxAppPathResolver {
    /// A resolver answering rules by path from `folders`, which the service
    /// shares to read its change number and hear of a changed folder.
    #[must_use]
    pub fn with_program_folders(folders: Arc<ProgramFolderIndex>) -> Self {
        Self {
            folders,
            elsewhere: Arc::default(),
        }
    }

    /// Executables seen outside the search directories, from one scan reused
    /// for [`ELSEWHERE_TTL`].
    fn located_elsewhere(&self) -> Arc<Vec<PathBuf>> {
        let now = Instant::now();
        let mut cached = self
            .elsewhere
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some((at, paths)) = cached.as_ref() {
            if now.duration_since(*at) < ELSEWHERE_TTL {
                return Arc::clone(paths);
            }
        }
        let paths = Arc::new(executables_located_elsewhere(
            Path::new("/proc"),
            &application_dirs(),
        ));
        *cached = Some((now, Arc::clone(&paths)));
        paths
    }
}

/// Running-process images and the absolute `Exec=` programs of desktop
/// entries. A wrapper (`flatpak`, `env`) is not the application's own file.
fn executables_located_elsewhere(proc_root: &Path, desktop_dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = running_processes(proc_root)
        .into_iter()
        .filter_map(|process| process.exe)
        .collect();
    for dir in desktop_dirs {
        out.extend(
            desktop_apps_in(dir)
                .iter()
                .filter_map(|app| app.own_exe_path())
                .map(PathBuf::from),
        );
    }
    dedup_paths(out)
}

/// The entries of `candidates` whose file name one of `patterns` matches.
fn matching_by_name(patterns: &[String], candidates: &[PathBuf]) -> Vec<PathBuf> {
    candidates
        .iter()
        .filter(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|name| patterns.iter().any(|p| glob_match(p, name)))
        })
        .cloned()
        .collect()
}

impl AppPathResolver for LinuxAppPathResolver {
    fn resolve(&self, name_or_glob: &str) -> Vec<PathBuf> {
        let patterns = candidate_patterns(name_or_glob);
        if patterns.is_empty() {
            return Vec::new();
        }
        let mut found = Vec::new();
        for directory in search_directories() {
            let Ok(entries) = std::fs::read_dir(&directory) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                if !patterns.iter().any(|p| glob_match(p, name)) {
                    continue;
                }
                if is_executable_file(&entry.path()) {
                    found.push(entry.path());
                }
            }
        }
        found.extend(
            matching_by_name(&patterns, &self.located_elsewhere())
                .into_iter()
                .filter(|path| is_executable_file(path)),
        );
        dedup_paths(found)
    }

    fn sibling_executables(&self, exe: &std::path::Path) -> Vec<PathBuf> {
        let Some(dir) = private_install_dir_of(exe) else {
            return Vec::new();
        };
        nrr_platform_api::app_path_resolver::executables_in_tree(
            &dir,
            SIBLING_WALK_MAX_DEPTH,
            SIBLING_WALK_MAX_FILES,
            &is_executable_file,
        )
        .into_iter()
        .filter(|p| p != exe)
        .take(SIBLING_MAX_PATHS)
        .collect()
    }

    fn is_protected_install(&self, exe: &std::path::Path) -> bool {
        root_owned(exe)
    }

    fn path_programs(&self, path: &AppPath, owner: &str) -> PathPrograms {
        self.folders.programs(path, owner)
    }

    fn writable_by_anyone(&self, path: &std::path::Path) -> bool {
        self.folders.writable_by_anyone(path)
    }
}

/// Root owns the file and the directory it sits in: what a package manager
/// leaves behind, and not what a user can drop into their own home.
#[cfg(target_os = "linux")]
fn root_owned(exe: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let owned = |path: &std::path::Path| std::fs::metadata(path).is_ok_and(|m| m.uid() == 0);
    owned(exe) && exe.parent().is_some_and(owned)
}

#[cfg(not(target_os = "linux"))]
fn root_owned(_exe: &std::path::Path) -> bool {
    false
}

/// Install-tree walk limits — same reasoning as the Windows backend: deep
/// enough for a bundled transport, capped at one product's worth of binaries.
const SIBLING_WALK_MAX_DEPTH: u32 = 3;
const SIBLING_WALK_MAX_FILES: u32 = 4000;
const SIBLING_MAX_PATHS: usize = 12;

/// The directory holding `exe` when that directory belongs to ONE product.
///
/// On Linux the usual install shape is the opposite of Windows: the binary
/// sits in a shared `bin` directory next to everything else on the system, and
/// its private files live elsewhere (`/opt/<vendor>`, `/usr/lib/<pkg>`). So the
/// shared directories are rejected outright and nothing is expanded from them —
/// a bundle under `/opt` is the case this answers.
fn private_install_dir_of(exe: &std::path::Path) -> Option<PathBuf> {
    let dir = exe.parent()?;
    // The filesystem root itself is never one product's directory.
    dir.parent()?;
    let shared = [
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/snap/bin",
        "/var/lib/flatpak/exports/bin",
    ];
    if shared.iter().any(|s| dir == std::path::Path::new(s)) {
        return None;
    }
    Some(dir.to_path_buf())
}

/// The names to look for on disk, given the neutral key.
///
/// The stripped spelling is what a Linux executable is actually called; the
/// original is kept as a second candidate so a genuinely `.exe`-named file
/// (a Wine-launched application) still resolves.
fn candidate_patterns(name_or_glob: &str) -> Vec<String> {
    let trimmed = name_or_glob.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let mut patterns = vec![trimmed.to_string()];
    if let Some(stripped) = trimmed.strip_suffix(".exe") {
        if !stripped.is_empty() {
            // Front of the list: on Linux this is the spelling that will match.
            patterns.insert(0, stripped.to_string());
        }
    }
    patterns
}

/// `$PATH` entries plus the export directories package managers publish into.
fn search_directories() -> Vec<PathBuf> {
    let mut directories: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect())
        .unwrap_or_default();
    // A service started by systemd can have a minimal PATH; these are where
    // desktop applications end up regardless of who started us.
    for extra in [
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/var/lib/flatpak/exports/bin",
        "/snap/bin",
    ] {
        let extra = PathBuf::from(extra);
        if !directories.contains(&extra) {
            directories.push(extra);
        }
    }
    directories
}

/// A regular file with at least one execute bit. A directory named like the
/// application, or a data file left next to it, is not something to route.
#[cfg(target_os = "linux")]
fn is_executable_file(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    // `metadata` follows symlinks on purpose: `/usr/bin/messenger` is usually a
    // link to the real binary, and the link is the path the user launches.
    match std::fs::metadata(path) {
        Ok(meta) => meta.is_file() && meta.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

// Off Linux there are no unix permission bits; the pure half above is what the
// cross-platform build compiles and tests.
#[cfg(not(target_os = "linux"))]
fn is_executable_file(path: &std::path::Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// On Linux the binary usually sits in a directory shared with the whole
    /// system, so expanding it would exempt everything installed. Only a
    /// bundle's own directory (`/opt/vendor`, `/usr/lib/pkg`) may expand.
    #[test]
    fn only_a_bundles_own_directory_expands() {
        assert_eq!(
            private_install_dir_of(std::path::Path::new("/opt/vendor-vpn/client")).as_deref(),
            Some(std::path::Path::new("/opt/vendor-vpn")),
        );
        for shared in [
            "/usr/bin/client",
            "/usr/local/bin/client",
            "/bin/client",
            "/snap/bin/client",
            "/client",
        ] {
            assert!(
                private_install_dir_of(std::path::Path::new(shared)).is_none(),
                "{shared} must not expand",
            );
        }
    }

    #[test]
    fn the_neutral_exe_suffix_is_stripped_for_the_lookup() {
        // Stored with the Windows spelling; on disk the file is `messenger`.
        let patterns = candidate_patterns("messenger.exe");
        assert_eq!(patterns.first().map(String::as_str), Some("messenger"));
        // The original spelling stays as a fallback for a Wine-launched app.
        assert!(patterns.iter().any(|p| p == "messenger.exe"));
    }

    #[test]
    fn a_glob_keeps_its_metacharacters_when_the_suffix_goes() {
        let patterns = candidate_patterns("disko*.exe");
        assert_eq!(patterns.first().map(String::as_str), Some("disko*"));
    }

    #[test]
    fn a_name_without_the_suffix_is_looked_up_as_written() {
        assert_eq!(
            candidate_patterns("messenger"),
            vec!["messenger".to_string()]
        );
    }

    #[test]
    fn nothing_to_look_for_resolves_to_nothing() {
        assert!(candidate_patterns("").is_empty());
        assert!(candidate_patterns("   ").is_empty());
        // `.exe` alone leaves no name behind, so only the original stands.
        assert_eq!(candidate_patterns(".exe"), vec![".exe".to_string()]);
        assert!(LinuxAppPathResolver::default().resolve("").is_empty());
    }

    #[test]
    fn the_search_never_loses_the_standard_directories() {
        // A service with a minimal PATH must still find desktop applications.
        let directories = search_directories();
        for expected in ["/usr/bin", "/snap/bin"] {
            assert!(
                directories.contains(&PathBuf::from(expected)),
                "{expected} missing from {directories:?}",
            );
        }
    }

    #[test]
    fn a_desktop_entry_names_an_application_installed_outside_path() {
        let root = tempfile::tempdir().expect("dir");
        let apps = root.path().join("applications");
        std::fs::create_dir_all(&apps).expect("apps dir");
        std::fs::write(
            apps.join("vendor-client.desktop"),
            "[Desktop Entry]\nType=Application\nName=Client\nExec=\"/opt/vendor/client\" %U\n",
        )
        .expect("entry");
        std::fs::write(
            apps.join("wrapped.desktop"),
            "[Desktop Entry]\nType=Application\nExec=/usr/bin/flatpak run org.example.App\n",
        )
        .expect("wrapped entry");
        let found = executables_located_elsewhere(&root.path().join("no-proc"), &[apps]);
        assert_eq!(found, vec![PathBuf::from("/opt/vendor/client")]);
    }

    #[test]
    fn only_the_queried_name_comes_back_from_the_other_sources() {
        let candidates = [
            PathBuf::from("/opt/vendor/client"),
            PathBuf::from("/opt/vendor/client-helper"),
            PathBuf::from("/opt/other/editor"),
        ];
        assert_eq!(
            matching_by_name(&candidate_patterns("client.exe"), &candidates),
            vec![PathBuf::from("/opt/vendor/client")],
        );
        assert_eq!(
            matching_by_name(&candidate_patterns("client*"), &candidates).len(),
            2
        );
        assert!(matching_by_name(&candidate_patterns("absent"), &candidates).is_empty());
    }

    /// A running program found through its process image, not through `$PATH`.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_running_process_image_is_a_source() {
        let root = tempfile::tempdir().expect("dir");
        let proc_root = root.path().join("proc");
        let bin = root.path().join("opt/vendor/client");
        std::fs::create_dir_all(bin.parent().expect("parent")).expect("bin dir");
        std::fs::write(&bin, "#!/bin/sh\n").expect("bin");
        std::fs::create_dir_all(proc_root.join("4242")).expect("pid dir");
        std::os::unix::fs::symlink(&bin, proc_root.join("4242/exe")).expect("exe link");
        // A kernel thread has no image and contributes nothing.
        std::fs::create_dir_all(proc_root.join("2")).expect("kthread dir");
        std::fs::create_dir_all(proc_root.join("self-not-a-pid")).expect("non-pid dir");
        assert_eq!(executables_located_elsewhere(&proc_root, &[]), vec![bin]);
    }

    /// The live half: every Linux host has a shell on `$PATH`, and a rule
    /// stored with the Windows spelling names it `sh.exe`.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_real_executable_resolves_through_the_neutral_spelling() {
        let paths = LinuxAppPathResolver::default().resolve("sh.exe");
        assert!(
            paths.iter().any(|p| p.file_name() == Some("sh".as_ref())),
            "expected a shell among {paths:?}",
        );
        assert!(paths.iter().all(|p| p.is_file()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_application_nobody_installed_resolves_to_nothing() {
        assert!(LinuxAppPathResolver::default()
            .resolve("nrr-no-such-application.exe")
            .is_empty());
    }
}
