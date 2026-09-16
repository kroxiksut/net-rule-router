//! An adapter is named to the user by its CONNECTION, never by its driver.
//!
//! The driver description ("WireGuard Tunnel", "TAP-Windows Adapter V9") is
//! shared by every tunnel of that kind; the connection name is the one the user
//! or their VPN client wrote. Two places had drifted to `description || name` —
//! the unroutable-secondary confirmation and the VPN-conflict line — so the
//! dialog asking a user to hand their additional route to an adapter named it
//! by the driver behind it, and they could not tell which VPN it was.
//!
//! The rule now lives once, in `pure.js::adapterDisplayName`. This gate is what
//! keeps it there: the shape that caused the defect fails `cargo test` rather
//! than a hardware run, because the same two-site drift is exactly what would
//! happen again the next time somebody needs an adapter label in a hurry.

use std::path::{Path, PathBuf};

/// `<name> || <something>.description` is fine — the connection leads. The
/// reverse is the defect.
const DESCRIPTION_FIRST: &str = "description ||";

fn qml_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../qml")
}

/// Every `.qml` / `.js` file under the QML tree, as (repo-relative path, body).
fn qml_sources() -> Vec<(String, String)> {
    fn walk(dir: &Path, out: &mut Vec<(String, String)>) {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) => panic!("cannot read {}: {e}", dir.display()),
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
                continue;
            }
            let is_source = path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e == "qml" || e == "js");
            if !is_source {
                continue;
            }
            let body = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            out.push((name, body));
        }
    }
    let mut out = Vec::new();
    walk(&qml_root(), &mut out);
    assert!(!out.is_empty(), "no QML sources found — the walk is broken");
    out
}

/// Lines that read a description with the connection name as the FALLBACK.
fn offenders(sources: &[(String, String)]) -> Vec<String> {
    let mut found = Vec::new();
    for (file, body) in sources {
        for (n, line) in body.lines().enumerate() {
            // Only what FOLLOWS the operator counts. The whole line is too
            // coarse: `String(r.name || r.description || "")` leads with the
            // connection and is exactly right, yet mentions both words, and so
            // does a line that merely compares a description to something.
            let Some((_, after)) = line.split_once(DESCRIPTION_FIRST) else {
                continue;
            };
            if after.contains("name") {
                found.push(format!("{file}:{}", n + 1));
            }
        }
    }
    found
}

#[test]
fn no_surface_names_an_adapter_by_its_driver_first() {
    let sources = qml_sources();
    let offenders = offenders(&sources);
    assert!(
        offenders.is_empty(),
        "these name an adapter by the driver description with the connection \
         name only as a fallback — use `Pure.adapterDisplayName(row)`, which \
         leads with the connection: {offenders:?}",
    );
}

/// The gate reads the tree it claims to read, and the rule it enforces is
/// actually declared. A guard that finds nothing because it looked nowhere
/// passes for the wrong reason.
#[test]
fn the_shared_rule_exists_and_the_gate_can_see_the_tree() {
    let sources = qml_sources();
    assert!(
        sources.iter().any(|(f, _)| f == "Main.qml"),
        "the walk missed Main.qml — it is not reading the QML tree",
    );
    let declared = sources
        .iter()
        .any(|(f, body)| f == "pure.js" && body.contains("function adapterDisplayName("));
    assert!(
        declared,
        "pure.js no longer declares the shared naming rule"
    );

    // Positive control: the gate must recognise the shape it exists to refuse.
    let probe = vec![(
        "probe.qml".to_string(),
        "    var label = String(r.description || r.name || \"\")\n".to_string(),
    )];
    assert_eq!(
        offenders(&probe).len(),
        1,
        "the gate no longer recognises the defect it was written for",
    );
}
