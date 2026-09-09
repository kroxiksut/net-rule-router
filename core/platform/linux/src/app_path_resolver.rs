//! Linux mechanism behind
//! [`nrr_platform_api::app_path_resolver::AppPathResolver`].
//!
//! ## The `.exe` the neutral layer guarantees
//!
//! `nrr-domain` normalises every application name to a lowercase file name with
//! a `.exe` suffix, on every OS. That is not an accident to route around: both
//! sides of a match go through the same normaliser, so the key stays
//! self-consistent and one canonical spelling survives a rules file moving
//! between machines. The suffix only stops being true at the one place a name
//! meets a real filesystem — here. So this backend strips it before looking,
//! which is exactly what a mechanism layer is for: the neutral key in, this
//! OS's reality out.
//!
//! ## Where it looks
//!
//! `$PATH`, plus the export directories Flatpak and Snap publish into (usually
//! on `$PATH` already, listed so a service started with a bare environment
//! still finds them). Only regular files with an execute bit count — a
//! directory or a stray data file with a matching name is not an application.
//!
//! Resolution is never an error: an app that is not installed resolves to an
//! empty vector, same as on Windows.

use std::path::PathBuf;

use nrr_platform_api::app_path_resolver::{dedup_paths, glob_match, AppPathResolver};

/// Production resolver over `$PATH` and the package-manager export dirs.
///
/// No cache: this runs while an apply is being planned, not on the traffic
/// path, and a directory listing per candidate is cheap next to the filter
/// codegen that follows.
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxAppPathResolver;

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
        // The neutral layer guarantees `.exe`; on disk the file is `messenger`.
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
        assert!(LinuxAppPathResolver.resolve("").is_empty());
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

    /// The live half: every Linux host has a shell on `$PATH`, and the neutral
    /// layer would name it `sh.exe`. Resolving that to a real executable is the
    /// whole point of this backend.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_real_executable_resolves_through_the_neutral_spelling() {
        let paths = LinuxAppPathResolver.resolve("sh.exe");
        assert!(
            paths.iter().any(|p| p.file_name() == Some("sh".as_ref())),
            "expected a shell among {paths:?}",
        );
        assert!(paths.iter().all(|p| p.is_file()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_application_nobody_installed_resolves_to_nothing() {
        assert!(LinuxAppPathResolver
            .resolve("nrr-no-such-application.exe")
            .is_empty());
    }
}
