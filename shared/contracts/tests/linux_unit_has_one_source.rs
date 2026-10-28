#![allow(clippy::expect_used)]

//! The systemd unit has one definition, the one the daemon renders
//! (`platform/linux` `systemd.rs`). Every install path takes it from there: a
//! package from `nrr-serviced package-files`, an archive or a build tree from
//! `nrr-serviced install`. A unit file kept beside the scripts drifts: a
//! hardening line or a directory added to the daemon's never reaches the
//! package, and nothing at build time notices.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(relative: &str) -> String {
    std::fs::read_to_string(repo_root().join(relative))
        .unwrap_or_else(|e| panic!("{relative}: {e}"))
        .replace("\r\n", "\n")
}

fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("readable directory") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            files_under(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// A unit file, or a script or workflow that writes one (a heredoc, a
/// `printf`): nothing else under these folders names the `[Service]` section.
fn holds_a_unit(path: &Path, text: &str) -> bool {
    let named_like_one = path
        .extension()
        .is_some_and(|ext| ext == "service" || ext == "socket" || ext == "timer");
    named_like_one || text.contains("[Service]")
}

#[test]
fn no_unit_text_lives_outside_the_daemon() {
    let root = repo_root();
    let mut files = Vec::new();
    for dir in ["packaging", "scripts", ".github"] {
        files_under(&root.join(dir), &mut files);
    }
    let copies: Vec<String> = files
        .iter()
        .filter(|path| {
            let text = std::fs::read(path)
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                .unwrap_or_default();
            holds_a_unit(path, &text)
        })
        .map(|path| {
            path.strip_prefix(&root)
                .unwrap_or(path)
                .display()
                .to_string()
        })
        .collect();
    assert!(
        copies.is_empty(),
        "a second definition of the systemd unit, which will drift from the one \
         the daemon renders; ship what `nrr-serviced package-files` writes instead: {copies:?}"
    );
}

/// Quoted strings on the first line of `text` that starts with `lead`.
fn quoted_on(text: &str, lead: &str) -> Vec<String> {
    text.lines()
        .find(|line| line.starts_with(lead))
        .map(|line| {
            line.split('"')
                .skip(1)
                .step_by(2)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// The scripts that write or remove the unit outside a package manager.
const HAND_INSTALLS: [&str; 4] = [
    "scripts/install-service.sh",
    "scripts/uninstall-service.sh",
    "packaging/linux/tarball/install.sh",
    "packaging/linux/tarball/uninstall.sh",
];

/// Why a package unit and a hand-written one could end up on one machine, if
/// they could. `files` maps each of [`HAND_INSTALLS`], the daemon's
/// `systemd.rs`, `lib/service-paths.sh`, the .deb `preinst.in` and
/// `package-linux.sh` to its text.
fn second_owner_flaw(files: &dyn Fn(&str) -> String) -> Option<String> {
    let daemon_dirs = quoted_on(
        &files("core/platform/linux/src/systemd.rs"),
        "pub const PACKAGE_UNIT_DIRS",
    );
    if daemon_dirs.is_empty() {
        return Some("systemd.rs: no PACKAGE_UNIT_DIRS".into());
    }
    let script_dirs: Vec<String> = quoted_on(
        &files("scripts/lib/service-paths.sh"),
        "NRR_PACKAGE_UNIT_FILES=",
    )
    .iter()
    .map(|unit| unit.trim_end_matches("/$NRR_UNIT_NAME").to_owned())
    .collect();
    if script_dirs != daemon_dirs {
        return Some(format!(
            "the scripts look for a package unit in {script_dirs:?}, the daemon in {daemon_dirs:?}"
        ));
    }
    for script in HAND_INSTALLS {
        let text = files(script);
        let code: Vec<&str> = text
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .collect();
        let refusal = code
            .iter()
            .position(|line| line.starts_with("nrr_refuse_if_package_managed "));
        let first_change = code.iter().position(|line| {
            [
                "systemctl",
                "\" install",
                "\" uninstall",
                "rm -",
                "cp -",
                "mv -",
                "ln -s",
            ]
            .iter()
            .any(|needle| line.contains(needle))
        });
        match (refusal, first_change) {
            (None, _) => return Some(format!("{script} does not stand down for a package")),
            (Some(r), Some(c)) if c < r => {
                return Some(format!(
                    "{script} changes the system before it checks for a package"
                ))
            }
            _ => {}
        }
    }
    // A package installed over a hand install takes the unit over.
    let preinst = files("packaging/linux/maintainer/deb/preinst.in");
    let rpm = files("scripts/package-linux.sh");
    let rpm_pre = rpm.split("rpm_scriptlet '%pre'").nth(1).unwrap_or_default();
    for (name, text) in [("deb preinst", preinst.as_str()), ("rpm %pre", rpm_pre)] {
        let head = text.split("\n}").next().unwrap_or_default();
        let head = &head[..head.find("rpm_scriptlet").unwrap_or(head.len())];
        if !head.contains("nrr_pkg_take_over_hand_install") {
            return Some(format!("{name} leaves a hand-installed unit in place"));
        }
    }
    None
}

/// One owner per install: while a package owns the unit, the daemon refuses
/// `install` and `uninstall` (`service_control.rs`), the hand scripts stand
/// down, and a package installed over a hand install takes it over.
#[test]
fn a_package_and_a_hand_install_never_both_own_the_unit() {
    assert_eq!(second_owner_flaw(&read), None);
}

#[test]
fn each_second_owner_regression_is_seen() {
    let mutant = |path: &'static str, from: &'static str, to: &'static str| {
        move |asked: &str| {
            let text = read(asked);
            if asked != path {
                return text;
            }
            assert!(text.contains(from), "{path}: {from:?} is gone");
            text.replacen(from, to, 1)
        }
    };
    assert!(second_owner_flaw(&mutant(
        "scripts/lib/service-paths.sh",
        " \"/lib/systemd/system/$NRR_UNIT_NAME\"",
        "",
    ))
    .is_some());
    assert!(second_owner_flaw(&mutant(
        "packaging/linux/tarball/install.sh",
        "nrr_refuse_if_package_managed \"",
        ": \"",
    ))
    .is_some());
    let late = |asked: &str| {
        let text = read(asked);
        if asked != "packaging/linux/tarball/uninstall.sh" {
            return text;
        }
        let refusal =
            "nrr_refuse_if_package_managed \"apt remove / dnf remove the package instead.\"\n";
        assert!(text.contains(refusal));
        text.replacen(refusal, "", 1) + refusal
    };
    assert!(second_owner_flaw(&late).is_some());
    assert!(second_owner_flaw(&mutant(
        "packaging/linux/maintainer/deb/preinst.in",
        "nrr_pkg_take_over_hand_install",
        ":",
    ))
    .is_some());
    assert!(second_owner_flaw(&mutant(
        "scripts/package-linux.sh",
        "  nrr_pkg_take_over_hand_install\nfi'",
        "  :\nfi'",
    ))
    .is_some());
}

#[test]
fn every_package_takes_the_unit_the_daemon_renders() {
    let script = read("scripts/package-linux.sh");
    assert!(
        script.contains("\"$service_bin\" package-files \"$root\""),
        ".deb and .rpm must ship the unit `nrr-serviced package-files` writes"
    );
    let pkgbuild = read("packaging/linux/aur/netrulerouter-bin/PKGBUILD.in");
    assert!(
        pkgbuild.contains("/nrr-serviced\" package-files \"$pkgdir\""),
        "the AUR package must ship the unit `nrr-serviced package-files` writes"
    );
    let archive = read("packaging/linux/tarball/install.sh");
    assert!(
        archive.contains("\"$NRR_STAGED_SERVICE_BINARY\" install\n"),
        "an archive install must have the daemon write its own unit"
    );
}
