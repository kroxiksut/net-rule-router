//! Every field of the GUI shell contract must be read by the GUI.
//!
//! This crate used to declare 62 fields across three "contracts" describing the
//! window's information architecture. Eleven had a reader, and all eleven were
//! console printers with no caller; the QML shell built its navigation, its
//! rules table and its interface picker from its own declarations. A contract
//! only one side reads cannot drift from reality — it also cannot describe it,
//! and it is worse than no contract, because the next person rewriting the GUI
//! takes it for the truth.
//!
//! So the surviving contract is small, and this test is what keeps it that way:
//! a field nobody reads fails `cargo test` instead of quietly becoming
//! documentation. Same shape as `route_policy_wire_contract`, which pins the
//! wire defaults against `pure.js` — the only other gate here that checks two
//! sides against each other rather than one side against itself.

use std::path::{Path, PathBuf};

/// The emitter that turns the shell model into the QML context — the GUI half
/// of this contract.
const READER: &str = "../../apps/desktop/gui/src/ui_surface.rs";

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// Every `.rs` file of this crate, so the gate keeps working after the next
/// split. It used to read `src/lib.rs` alone, and moving the contract one file
/// sideways turned it into a test that passed by finding nothing.
fn crate_sources() -> Vec<String> {
    fn walk(dir: &Path, out: &mut Vec<String>) {
        let entries =
            std::fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()));
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(
                    std::fs::read_to_string(&path)
                        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display())),
                );
            }
        }
    }
    let mut out = Vec::new();
    walk(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut out);
    assert!(
        !out.is_empty(),
        "no source files found — the walk is broken"
    );
    out
}

/// Field names declared by `struct <name>` anywhere in this crate.
fn declared_fields(struct_name: &str) -> Vec<String> {
    let header = format!("pub struct {struct_name} {{");
    let src = crate_sources()
        .into_iter()
        .find(|s| s.contains(&header))
        .unwrap_or_else(|| panic!("{struct_name} is not declared in this crate"));
    let start = src.find(&header).unwrap_or_default() + header.len();
    let body = &src[start..];
    let end = body
        .find("\n}")
        .unwrap_or_else(|| panic!("{struct_name} has no closing brace"));
    body[..end]
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix("pub ")?;
            let name = rest.split(':').next()?.trim();
            (!name.is_empty()).then(|| name.to_owned())
        })
        .collect()
}

#[test]
fn every_main_window_shell_field_is_read_by_the_context_emitter() {
    let reader = repo_file(READER);
    let fields = declared_fields("MainWindowShellContract");
    assert!(!fields.is_empty(), "the contract declares nothing at all");
    for field in fields {
        let access = format!("main_window_shell.{field}");
        assert!(
            reader.contains(&access),
            "MainWindowShellContract::{field} has no reader — either wire it into \
             the QML context or drop it from the contract; a field only this \
             crate knows about describes nothing"
        );
    }
}

/// The contracts that described the rules table and the interfaces screen were
/// removed for having no reader. Re-adding one is a decision, not an accident:
/// this fails until the reader exists on the other side.
#[test]
fn the_removed_screen_contracts_stay_removed_until_something_reads_them() {
    let sources = crate_sources();
    for name in ["RulesContract", "InterfacesRoutesContract"] {
        let header = format!("pub struct {name} {{");
        let declared = sources.iter().any(|s| s.contains(&header));
        if !declared {
            continue;
        }
        let reader = repo_file(READER);
        let field = name.trim_end_matches("Contract").to_ascii_lowercase();
        assert!(
            reader.contains(&field),
            "{name} is declared again but {READER} still does not read it"
        );
    }
}
