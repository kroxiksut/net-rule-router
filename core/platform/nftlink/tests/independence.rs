//! The boundary that makes this crate separable, enforced rather than intended.
//!
//! `nftlink` is meant to leave this repository as its own published project.
//! That is only cheap while it has no dependency on the product around it — one
//! `nrr-*` type reached for "just this once" turns the split from a directory
//! move into a rewrite. Discipline does not hold a boundary for months; a
//! failing build does.

use std::path::{Component, Path, PathBuf};

/// Read our own manifest and refuse any product dependency.
///
/// Deliberately textual rather than a `cargo metadata` walk: the rule is about
/// what someone can WRITE in the manifest, and this catches it in the same edit
/// that introduces it, with no tooling to install.
#[test]
fn the_manifest_declares_no_dependency_on_the_product() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(crate_dir.join("Cargo.toml"))
        .expect("the crate manifest must be readable");
    let workspace = workspace_manifest(crate_dir);

    let found = violations(
        &text,
        crate_dir,
        workspace
            .as_ref()
            .map(|(dir, text)| (dir.as_path(), text.as_str())),
    );
    assert!(
        found.is_empty(),
        "nftlink must not depend on the product it currently lives in:\n{}\n\
         If this crate needs something from the application, the dependency \
         goes the other way — or it is time to split the crate out. See \
         CONTRIBUTING.md.",
        found.join("\n"),
    );
}

/// Positive control: each way around a name check is caught, and what the
/// crate legitimately writes is not.
#[test]
fn the_check_sees_a_renamed_or_relative_dependency() {
    let crate_dir = Path::new("/ws/core/platform/nftlink");
    let caught = |manifest: &str| !violations(manifest, crate_dir, None).is_empty();

    assert!(caught(
        "[dependencies]\nnrr-shared = { path = \"../../shared\" }\n"
    ));
    assert!(caught(
        "[dependencies]\napi = { package = \"nrr-platform-api\", version = \"0\" }\n"
    ));
    assert!(caught("[dependencies]\nlinux = { path = \"../linux\" }\n"));
    assert!(caught("[dependencies]\nlinux.path = \"../linux\"\n"));
    assert!(caught("[dependencies.linux]\npath = \"../linux\"\n"));
    assert!(caught(
        "[target.'cfg(unix)'.dev-dependencies]\nx = { path = \"/ws/core/domain\" }\n"
    ));
    assert!(caught(
        "[dependencies]\nx = { path = \"sub/../../linux\" }\n"
    ));

    assert!(!caught(
        "[lib]\npath = \"src/lib.rs\"\n[dependencies]\nlibc = \"0.2\"\n# nrr-x = no\n"
    ));
    assert!(!caught("[dependencies]\nhelper = { path = \"helper\" }\n"));

    // Inherited from the workspace: its declaration is what counts.
    let workspace = (
        Path::new("/ws"),
        "[workspace.dependencies]\nplat = { path = \"core/platform/api\" }\nlibc = \"0.2\"\n",
    );
    let inherits = |manifest: &str| !violations(manifest, crate_dir, Some(workspace)).is_empty();
    assert!(inherits("[dependencies]\nplat = { workspace = true }\n"));
    assert!(inherits("[dependencies]\nplat.workspace = true\n"));
    assert!(!inherits("[dependencies]\nlibc.workspace = true\n"));
}

/// Every product dependency `manifest` declares, as a readable line each.
/// `workspace` is the root manifest and its directory, for inherited entries.
fn violations(manifest: &str, crate_dir: &Path, workspace: Option<(&Path, &str)>) -> Vec<String> {
    let mut found = Vec::new();
    let mut section = String::new();
    for (number, line) in code_lines(manifest) {
        if let Some(header) = table_header(line) {
            section = header.to_string();
        }
        found.extend(
            line_violations(line, crate_dir, crate_dir)
                .map(|why| format!("Cargo.toml line {number}: `{line}` ({why})")),
        );
        if !section.contains("dependencies") || !inherits_from_workspace(line) {
            continue;
        }
        let name = dependency_name(&section, line);
        let Some((root, root_text)) = workspace else {
            continue;
        };
        for declared in workspace_entry(root_text, name) {
            found.extend(line_violations(declared, root, crate_dir).map(|why| {
                format!(
                    "Cargo.toml line {number}: `{name}` is inherited from the workspace, \
                     which declares `{declared}` ({why})"
                )
            }));
        }
    }
    found
}

/// Why `line` reaches the product: it names a product crate, or a `path`
/// resolved against `base` leaves `crate_dir`.
fn line_violations<'a>(
    line: &'a str,
    base: &'a Path,
    crate_dir: &'a Path,
) -> impl Iterator<Item = String> + 'a {
    let named = (line.contains("nrr-") || line.contains("nrr_"))
        .then(|| "names a product crate".to_string());
    let escaping = path_values(line)
        .into_iter()
        .filter(|value| !normalize(&base.join(value)).starts_with(normalize(crate_dir)))
        .map(|value| format!("`{value}` is outside the crate"));
    named.into_iter().chain(escaping)
}

/// Non-empty lines with comments removed, numbered from 1. A `#` inside a
/// quoted value is not a comment.
fn code_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines().enumerate().filter_map(|(index, line)| {
        let mut quoted = false;
        let end = line
            .char_indices()
            .find(|&(_, c)| {
                if c == '"' {
                    quoted = !quoted;
                }
                c == '#' && !quoted
            })
            .map_or(line.len(), |(at, _)| at);
        let code = line[..end].trim();
        (!code.is_empty()).then_some((index + 1, code))
    })
}

fn table_header(line: &str) -> Option<&str> {
    line.strip_prefix('[')?
        .strip_suffix(']')
        .map(|h| h.trim_matches(['[', ']']))
}

/// The value of every `path` key on the line, bare, dotted or inline.
fn path_values(line: &str) -> Vec<&str> {
    let mut values = Vec::new();
    let mut rest = line;
    while let Some(at) = rest.find("path") {
        let before = rest[..at].chars().next_back();
        let after = rest[at + 4..].trim_start();
        rest = &rest[at + 4..];
        if !before.is_none_or(|c| c.is_whitespace() || matches!(c, '{' | ',' | '.')) {
            continue;
        }
        let Some(value) = after.strip_prefix('=').map(str::trim_start) else {
            continue;
        };
        let Some(value) = value.strip_prefix('"') else {
            continue;
        };
        if let Some(end) = value.find('"') {
            values.push(&value[..end]);
        }
    }
    values
}

fn inherits_from_workspace(line: &str) -> bool {
    line.replace(' ', "").contains("workspace=true")
}

/// The dependency a line in `section` declares: the table's own name for
/// `[dependencies.x]`, otherwise the key.
fn dependency_name<'a>(section: &'a str, line: &'a str) -> &'a str {
    match section.split_once("dependencies.") {
        Some((_, name)) => name.trim_matches(['"', '\'']),
        None => line
            .split(['=', '.'])
            .next()
            .unwrap_or_default()
            .trim()
            .trim_matches(['"', '\'']),
    }
}

/// The root manifest's lines declaring `name` under `[workspace.dependencies]`.
fn workspace_entry<'a>(root: &'a str, name: &'a str) -> Vec<&'a str> {
    let mut lines = Vec::new();
    let mut section = "";
    for (_, line) in code_lines(root) {
        if let Some(header) = table_header(line) {
            section = header;
            continue;
        }
        let whole_table = section == format!("workspace.dependencies.{name}");
        let keyed = section == "workspace.dependencies" && dependency_name(section, line) == name;
        if whole_table || keyed {
            lines.push(line);
        }
    }
    lines
}

/// The nearest enclosing workspace manifest and its directory, if the crate
/// still lives in one.
fn workspace_manifest(crate_dir: &Path) -> Option<(PathBuf, String)> {
    crate_dir.ancestors().skip(1).find_map(|dir| {
        let text = std::fs::read_to_string(dir.join("Cargo.toml")).ok()?;
        let is_workspace = code_lines(&text).any(|(_, line)| line == "[workspace]");
        is_workspace.then(|| (dir.to_path_buf(), text))
    })
}

/// `..` and `.` resolved without touching the disk.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

/// The source must not name the product either — a re-export or a `use` would
/// slip past a manifest-only check if the dependency arrived transitively.
#[test]
fn no_source_file_names_the_product() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut checked = 0usize;
    for entry in std::fs::read_dir(&src).expect("src must exist") {
        let path = entry.expect("readable entry").path();
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("source must be readable");
        for (number, line) in text.lines().enumerate() {
            // The doc comments explain the rule and quote the forbidden prefix,
            // so only real code counts.
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                continue;
            }
            assert!(
                !trimmed.contains("nrr_"),
                "{} line {} references the product: `{trimmed}`",
                path.display(),
                number + 1,
            );
        }
        checked += 1;
    }
    assert!(
        checked > 0,
        "no source files were checked — the test is blind"
    );
}
