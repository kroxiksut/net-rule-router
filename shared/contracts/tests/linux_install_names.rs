#![allow(clippy::expect_used)]

//! On Linux the window and the tray carry their Unix names once installed,
//! though Cargo builds them under the Windows spelling: the service tells its
//! clients apart by the executable name, `nrr-cli diag doctor` looks for the
//! application by it, and the desktop entries launch it. The install scripts
//! assign those names, so they are held here to `product_identity`.

use std::path::{Path, PathBuf};

use nrr_shared::product_identity::{
    BinaryRole, PRODUCT_NAME, PRODUCT_NAME_UNIX, SYSTEMD_UNIT_NAME,
};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn repo_file(relative: &str) -> String {
    let path = repo_root().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .replace("\r\n", "\n")
}

/// The value of a top-level `NAME="value"` or `NAME=("a" "b")` assignment,
/// with `$VAR` references to earlier assignments expanded.
fn shell_value(script: &str, name: &str) -> Option<Vec<String>> {
    let mut known: Vec<(String, String)> = Vec::new();
    let mut found = None;
    for line in script.lines() {
        let Some((var, raw)) = line.split_once('=') else {
            continue;
        };
        if var.is_empty() || !var.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
            continue;
        }
        let words: Vec<String> = raw
            .split('"')
            .skip(1)
            .step_by(2)
            .map(|word| {
                known.iter().fold(word.to_owned(), |acc, (k, v)| {
                    acc.replace(&format!("${k}"), v)
                })
            })
            .collect();
        if let [single] = words.as_slice() {
            known.push((var.to_owned(), single.clone()));
            // Longest first, so `$NRR_X_UNIX` is not read as `$NRR_X` + `_UNIX`.
            known.sort_by_key(|(k, _)| std::cmp::Reverse(k.len()));
        }
        if var == name {
            found = Some(words);
        }
    }
    found
}

fn one(script: &str, name: &str) -> String {
    match shell_value(script, name).as_deref() {
        Some([value]) => value.clone(),
        other => panic!("{name}: expected one quoted value, got {other:?}"),
    }
}

/// The `[[bin]]` names a crate manifest declares.
fn cargo_bins(manifest: &str) -> Vec<String> {
    let mut bins = Vec::new();
    let mut in_bin = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_bin = line == "[[bin]]";
            continue;
        }
        if in_bin {
            if let Some(rest) = line.strip_prefix("name") {
                if let Some(value) = rest.split('"').nth(1) {
                    bins.push(value.to_owned());
                }
            }
        }
    }
    bins
}

/// Why an installed window or tray could carry a name other than the one the
/// service, the console and the desktop entries expect, if it could.
fn gui_name_flaw(desktop_paths: &str, package_script: &str, launcher: &str) -> Option<String> {
    let bins = cargo_bins(launcher);
    for (role, id_var, cargo_var) in [
        (
            BinaryRole::Gui,
            "NRR_DESKTOP_GUI_ID",
            "NRR_DESKTOP_GUI_CARGO_NAME",
        ),
        (
            BinaryRole::Tray,
            "NRR_DESKTOP_TRAY_ID",
            "NRR_DESKTOP_TRAY_CARGO_NAME",
        ),
    ] {
        let id = one(desktop_paths, id_var);
        if id != role.unix_file_name() {
            return Some(format!(
                "{id_var} is `{id}`, product_identity names {role:?} `{}`",
                role.unix_file_name()
            ));
        }
        let cargo = one(desktop_paths, cargo_var);
        if !bins.contains(&cargo) {
            return Some(format!(
                "{cargo_var} is `{cargo}`, the launcher builds {bins:?}"
            ));
        }
        // A copy under the Unix name: a link would leave the Cargo name in
        // /proc/<pid>/exe.
        let copy = format!("install -m 0755 \"$bin_dir/${cargo_var}\" \"$root$libexec/${id_var}\"");
        if !package_script.contains(&copy) {
            return Some(format!(
                "package-linux.sh no longer installs {cargo_var} as {id_var}: `{copy}`"
            ));
        }
    }
    None
}

/// Why the service scripts could stage or look for a binary under a name the
/// daemon does not have, if they could.
fn service_name_flaw(service_paths: &str) -> Option<String> {
    let expect = [
        ("NRR_PRODUCT_NAME", PRODUCT_NAME.to_owned()),
        ("NRR_PRODUCT_NAME_UNIX", PRODUCT_NAME_UNIX.to_owned()),
        ("NRR_UNIT_NAME", SYSTEMD_UNIT_NAME.to_owned()),
        (
            "NRR_SERVICE_EXE_NAME",
            BinaryRole::Service.unix_file_name().to_owned(),
        ),
        (
            "NRR_SERVICE_ALIAS_NAME",
            BinaryRole::Service
                .unix_alias()
                .expect("the daemon has an alias")
                .to_owned(),
        ),
    ];
    for (var, want) in expect {
        let got = one(service_paths, var);
        if got != want {
            return Some(format!("{var} is `{got}`, product_identity says `{want}`"));
        }
    }
    let consoles = shell_value(service_paths, "NRR_CONSOLE_EXE_NAMES").unwrap_or_default();
    let want = [BinaryRole::Console, BinaryRole::Tui].map(BinaryRole::unix_file_name);
    (consoles != want).then(|| format!("NRR_CONSOLE_EXE_NAMES is {consoles:?}, not {want:?}"))
}

#[test]
fn the_installed_window_and_tray_carry_their_unix_names() {
    assert_eq!(
        gui_name_flaw(
            &repo_file("scripts/lib/desktop-paths.sh"),
            &repo_file("scripts/package-linux.sh"),
            &repo_file("apps/desktop/launcher/Cargo.toml"),
        ),
        None
    );
}

#[test]
fn the_service_scripts_name_the_binaries_as_the_product_does() {
    assert_eq!(
        service_name_flaw(&repo_file("scripts/lib/service-paths.sh")),
        None
    );
}

/// The desktop entries launch the command the package links into /usr/bin.
#[test]
fn the_menu_entries_launch_the_unix_names() {
    for role in [BinaryRole::Gui, BinaryRole::Tray] {
        let name = role.unix_file_name();
        let entry = repo_file(&format!("packaging/linux/{name}.desktop"));
        assert!(
            entry.lines().any(|l| l == format!("Exec={name}")),
            "packaging/linux/{name}.desktop does not run `{name}`"
        );
    }
}

/// The checks above must see each break they exist for.
#[test]
fn each_naming_regression_is_seen() {
    let desktop = repo_file("scripts/lib/desktop-paths.sh");
    let script = repo_file("scripts/package-linux.sh");
    let launcher = repo_file("apps/desktop/launcher/Cargo.toml");
    let service = repo_file("scripts/lib/service-paths.sh");
    let edit = |text: &str, from: &str, to: &str| {
        assert!(text.contains(from), "{from:?} is gone");
        text.replacen(from, to, 1)
    };

    let capitalised = edit(
        &desktop,
        "NRR_DESKTOP_GUI_ID=\"netrulerouter\"",
        "NRR_DESKTOP_GUI_ID=\"NetRuleRouter\"",
    );
    assert!(gui_name_flaw(&capitalised, &script, &launcher).is_some());
    let renamed_bin = edit(
        &launcher,
        "name = \"NetRuleRouterTray\"",
        "name = \"nrr-tray\"",
    );
    assert!(gui_name_flaw(&desktop, &script, &renamed_bin).is_some());
    let cargo_name_shipped = edit(
        &script,
        "\"$root$libexec/$NRR_DESKTOP_TRAY_ID\"",
        "\"$root$libexec/$NRR_DESKTOP_TRAY_CARGO_NAME\"",
    );
    assert!(gui_name_flaw(&desktop, &cargo_name_shipped, &launcher).is_some());

    let other_daemon = edit(
        &service,
        "NRR_SERVICE_EXE_NAME=\"nrr-serviced\"",
        "NRR_SERVICE_EXE_NAME=\"nrr-service\"",
    );
    assert!(service_name_flaw(&other_daemon).is_some());
    let one_console = edit(
        &service,
        "NRR_CONSOLE_EXE_NAMES=(\"nrr-cli\" \"nrr-tui\")",
        "NRR_CONSOLE_EXE_NAMES=(\"nrr-cli\")",
    );
    assert!(service_name_flaw(&one_console).is_some());
}
