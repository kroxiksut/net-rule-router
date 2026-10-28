#![allow(clippy::expect_used)]

//! A Linux program never starts on a glibc older than the one it was built
//! against: the loader stops it before any of our code runs, so the window
//! started from a menu simply never appears. The .deb and .rpm are refused by
//! the package manager on such a system; the archive has no package manager,
//! so its own install.sh must refuse, naming the reason and the way out. The
//! floor it compares with is the one measured from the binaries as the archive
//! is built, never a number typed a second time.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn repo_file(relative: &str) -> String {
    let path = repo_root().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .replace("\r\n", "\n")
}

const FLOOR_FILE: &str = "lib/glibc-floor";
const CHECK: &str = "refuse_older_glibc";

/// The body of shell function `name`, up to its closing brace at column 0.
fn shell_function<'a>(script: &'a str, name: &str) -> &'a str {
    let head = format!("\n{name}() {{\n");
    let Some(at) = script.find(&head) else {
        return "";
    };
    let body = &script[at + head.len()..];
    &body[..body.find("\n}\n").unwrap_or(body.len())]
}

/// The text of each `build_tarball` call, continuation lines joined.
fn tarball_calls(script: &str) -> Vec<String> {
    let mut calls = Vec::new();
    let mut lines = script.lines();
    while let Some(line) = lines.next() {
        if !line.trim_start().starts_with("build_tarball \"") {
            continue;
        }
        let mut call = line.trim().to_owned();
        while call.ends_with('\\') {
            call.pop();
            match lines.next() {
                Some(next) => call.push_str(next.trim()),
                None => break,
            }
        }
        calls.push(call);
    }
    calls
}

/// The right-hand side of each assignment `name=...` in `script`.
fn assignments<'a>(script: &'a str, name: &str) -> impl Iterator<Item = &'a str> {
    let head = format!("{name}=");
    script
        .lines()
        .map(str::trim_start)
        .filter_map(move |line| line.strip_prefix(head.as_str()))
}

/// Why an archive could carry no floor, or one that leaves out a layer it
/// holds, so that its install.sh lets a system that cannot run it through.
fn packaging_flaw(script: &str, contents: &str) -> Option<String> {
    let body = shell_function(script, "build_tarball");
    if !body.contains(&format!("\"$glibc\" >\"$top/{FLOOR_FILE}\"")) {
        return Some(format!(
            "build_tarball does not write its measured glibc into {FLOOR_FILE}"
        ));
    }
    if !body.contains("[ -n \"$glibc\" ] || die") {
        return Some("build_tarball would write an empty floor".into());
    }
    let listed = contents.lines().any(|line| {
        let mut fields = line.split_whitespace();
        fields.next() == Some("archive") && fields.next() == Some(FLOOR_FILE)
    });
    if !listed {
        return Some(format!(
            "package-contents.txt does not hold every archive to carry {FLOOR_FILE}"
        ));
    }
    let measured = [
        (
            "$base_root",
            "glibc_base",
            "glibc_floor \"${base_elves[@]}\"",
        ),
        ("$gui_root", "glibc_gui", "glibc_floor \"${gui_elves[@]}\""),
    ];
    for (_, var, measure) in measured {
        if !assignments(script, var).any(|rhs| rhs.contains(measure)) {
            return Some(format!("{var} is not measured from the binaries"));
        }
    }
    let calls = tarball_calls(script);
    if calls.is_empty() {
        return Some("no build_tarball call".into());
    }
    for call in calls {
        // The floor is the argument right before the first staged root.
        let Some(roots_at) = call.find("\"$base_root\"") else {
            return Some(format!("an archive without the service: {call}"));
        };
        let Some(floor) = call[..roots_at].trim_end().rsplit(' ').next() else {
            return Some(format!("no floor in {call}"));
        };
        let floor_var = floor.trim_matches('"').trim_start_matches('$');
        for (root, var, _) in measured {
            let covered = floor_var == var
                || assignments(script, floor_var).any(|rhs| rhs.contains(&format!("${var}")));
            if call[roots_at..].contains(root) && !covered {
                return Some(format!(
                    "an archive with {root} records the floor {floor}, which leaves out {var}"
                ));
            }
        }
    }
    None
}

/// Why install.sh could put a program on a system whose glibc is too old to
/// start it, or refuse without saying what to do instead.
fn install_flaw(install: &str) -> Option<String> {
    let body = shell_function(install, CHECK);
    if !body.contains(FLOOR_FILE) {
        return Some(format!("install.sh has no {CHECK} reading {FLOOR_FILE}"));
    }
    let Some(called) = install.find(&format!("\n{CHECK}\n")) else {
        return Some(format!("install.sh never calls {CHECK}"));
    };
    let changes = [
        "systemctl stop",
        "cp -R",
        "rm -rf",
        "install -D",
        "ln -sfn",
        "\"$NRR_STAGED_SERVICE_BINARY\"",
    ];
    if let Some(change) = changes
        .iter()
        .filter(|change| install.find(*change).is_some_and(|at| at < called))
        .min_by_key(|change| install.find(*change))
    {
        return Some(format!("install.sh runs `{change}` before {CHECK}"));
    }
    // The way out: the same features without the window, or a newer system.
    for words in ["headless", "nrr-tui", "or newer"] {
        if !body.contains(words) {
            return Some(format!("{CHECK} never says `{words}`"));
        }
    }
    None
}

#[test]
fn an_archive_refuses_a_system_too_old_to_start_it_and_says_what_to_use() {
    let script = repo_file("scripts/package-linux.sh");
    let contents = repo_file("packaging/linux/package-contents.txt");
    let install = repo_file("packaging/linux/tarball/install.sh");
    assert_eq!(packaging_flaw(&script, &contents), None);
    assert_eq!(install_flaw(&install), None);
}

/// The checks above must see each break they exist for.
#[test]
fn each_archive_glibc_regression_is_seen() {
    let script = repo_file("scripts/package-linux.sh");
    let contents = repo_file("packaging/linux/package-contents.txt");
    let install = repo_file("packaging/linux/tarball/install.sh");
    let edit = |text: &str, from: &str, to: &str| {
        assert!(text.contains(from), "{from:?} is gone");
        text.replacen(from, to, 1)
    };

    let unwritten = edit(
        &script,
        "\"$glibc\" >\"$top/lib/glibc-floor\"",
        "\"$glibc\"",
    );
    assert!(packaging_flaw(&unwritten, &contents).is_some());
    let unguarded = edit(&script, "[ -n \"$glibc\" ] || die", ": ||");
    assert!(packaging_flaw(&unguarded, &contents).is_some());
    let unlisted = edit(&contents, "archive  lib/glibc-floor", "");
    assert!(packaging_flaw(&script, &unlisted).is_some());
    let typed = edit(
        &script,
        "glibc_gui=\"$(glibc_floor \"${gui_elves[@]}\")\"",
        "glibc_gui=\"2.41\"",
    );
    assert!(packaging_flaw(&typed, &contents).is_some());
    let window_left_out = edit(
        &script,
        "\"$newest_glibc\" \"$base_root\" \"$gui_root\"",
        "\"$glibc_base\" \"$base_root\" \"$gui_root\"",
    );
    assert!(packaging_flaw(&window_left_out, &contents).is_some());

    let never_called = edit(&install, &format!("\n{CHECK}\n"), "\n");
    assert!(install_flaw(&never_called).is_some());
    let too_late = edit(&install, &format!("\n{CHECK}\n"), "\n").replacen(
        "\nnrr_cyan \"==> register",
        &format!("\n{CHECK}\nnrr_cyan \"==> register"),
        1,
    );
    assert!(install_flaw(&too_late).is_some());
    let no_way_out = edit(&install, "nrr-tui", "the terminal");
    assert!(install_flaw(&no_way_out).is_some());
}
