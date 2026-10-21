//! Every push event the service publishes has a reader on every client surface
//! that is meant to act on it: the main window, the tray and the terminal UI.
//!
//! A push nobody reads fails silently — the service is right, the log shows the
//! publish, and the user sees nothing. The slug list comes from serde's own
//! variant table, so a new `StatusUpdateEvent` variant joins this gate without
//! anyone remembering to add it; the table below then has to say, per surface,
//! whether the event is read, deliberately ignored (and why), or a known gap.
//! The known-gap entries can only shrink: closing one turns this red until the
//! entry becomes `Read`.

use std::path::{Path, PathBuf};

use nrr_shared::ipc_payloads::StatusUpdateEvent;

#[derive(Clone, Copy)]
enum Duty {
    /// The surface must handle the event.
    Read,
    /// The surface has nothing to do with it; the reason says why.
    Ignored(&'static str),
    /// The surface should read it and does not yet. A defect, listed so the
    /// gate is green today and turns red the moment the reader appears. None
    /// is open at the moment; the variant stays for the next one.
    #[allow(dead_code)]
    KnownGap(&'static str),
}

use Duty::{Ignored, KnownGap, Read};

struct Row {
    slug: &'static str,
    gui: Duty,
    tray: Duty,
    tui: Duty,
}

const NO_SETTINGS_IN_TRAY: Duty =
    Ignored("the tray shows no settings; the window and the terminal UI do");

/// Event × surface. One row per `StatusUpdateEvent` variant, plus the client's
/// own `push-gap` marker (see `CLIENT_MARKERS`).
const TABLE: &[Row] = &[
    Row {
        slug: "protection-coverage-changed",
        gui: Read,
        tray: Read,
        tui: Read,
    },
    Row {
        slug: "adapters-changed",
        gui: Read,
        tray: Read,
        tui: Read,
    },
    Row {
        slug: "security-alerts-changed",
        gui: Read,
        tray: Ignored("the tray has no alert list; alerts are read and acknowledged elsewhere"),
        tui: Read,
    },
    Row {
        slug: "revision-status-changed",
        gui: Read,
        tray: Read,
        tui: Read,
    },
    Row {
        slug: "routing-pause-state-changed",
        gui: Read,
        tray: Read,
        tui: Read,
    },
    Row {
        slug: "apply-failure-policy-changed",
        gui: Read,
        tray: NO_SETTINGS_IN_TRAY,
        tui: Read,
    },
    Row {
        slug: "autostart-state-changed",
        gui: Read,
        tray: NO_SETTINGS_IN_TRAY,
        tui: Ignored(
            "autostart starts the desktop app at sign-in; the terminal UI has no such setting",
        ),
    },
    Row {
        slug: "retention-settings-changed",
        gui: Read,
        tray: NO_SETTINGS_IN_TRAY,
        tui: Read,
    },
    Row {
        slug: "mutation-progress",
        gui: Read,
        tray: Read,
        tui: Read,
    },
    Row {
        slug: "auto-rule-candidates-changed",
        gui: Read,
        tray: Read,
        tui: Read,
    },
    Row {
        slug: "rule-duplicates-detected",
        gui: Read,
        tray: Read,
        tui: Read,
    },
    Row {
        slug: "system-dns-not-restored",
        gui: Read,
        tray: Read,
        tui: Read,
    },
    Row {
        slug: "host-unreachable-on-both-routes",
        gui: Read,
        tray: Ignored(
            "said in the window's notice list only, never as a popup: it is the site's outage",
        ),
        tui: Read,
    },
    Row {
        slug: "app-rule-learning-destinations",
        gui: Read,
        tray: Read,
        tui: Read,
    },
    Row {
        slug: "vpn-client-awaiting-confirmation",
        gui: Read,
        // The question is answered in the window; the tray only says it is
        // waiting there, while the window is not on screen.
        tray: Read,
        tui: Read,
    },
    Row {
        slug: "vpn-gateway-awaiting-confirmation",
        gui: Read,
        // As for the VPN-client question: answered in the window, announced by
        // the tray while the window is not on screen.
        tray: Read,
        tui: Read,
    },
    Row {
        slug: "secondary-external-address-observed",
        gui: Read,
        tray: Read,
        tui: Read,
    },
    Row {
        slug: "secondary-external-address-cleared",
        gui: Read,
        tray: Read,
        tui: Read,
    },
    Row {
        slug: "unassigned-tunnel-detected",
        gui: Read,
        tray: Read,
        tui: Read,
    },
    Row {
        slug: "local-network-too-wide",
        gui: Read,
        tray: Read,
        tui: Read,
    },
    Row {
        slug: "block-notice-raised",
        gui: Read,
        tray: Read,
        tui: Read,
    },
    Row {
        slug: "block-notice-mutes-changed",
        gui: Read,
        tray: Ignored(
            "the tray re-reads the mutes before every notice it raises (`_whenNoticeAllowed`)",
        ),
        tui: Read,
    },
    Row {
        slug: "verify-verdicts-changed",
        gui: Read,
        tray: Read,
        tui: Read,
    },
    Row {
        slug: "rule-overrides-changed",
        gui: Read,
        tray: Read,
        tui: Read,
    },
    Row {
        slug: "enforcement-status-changed",
        gui: Read,
        tray: Read,
        tui: Read,
    },
    Row {
        slug: "routes-held-by-another-user",
        gui: Read,
        tray: Read,
        tui: Read,
    },
    Row {
        slug: "traffic-carried-by-another-user",
        gui: Read,
        tray: Read,
        tui: Read,
    },
    Row {
        slug: "rules-book-unreadable",
        gui: Read,
        tray: Read,
        tui: Read,
    },
];

/// Markers with no variant: `push-gap` comes from the IPC client and from the
/// service's resync after a fall behind its ring. A surface ignores them at the
/// same cost.
const CLIENT_MARKERS: &[Row] = &[Row {
    slug: "push-gap",
    gui: Read,
    tray: Read,
    tui: Read,
}];

// ── Slugs, from the type ────────────────────────────────────────────────────

/// Every wire `type` of `StatusUpdateEvent`, as serde spells it. Asking serde
/// to read an unknown tag makes it list the variants it knows, renamed — the
/// one list that cannot fall behind the enum.
fn wire_slugs() -> Vec<String> {
    let probe = serde_json::json!({ "type": "zz-not-an-event" });
    let message = match serde_json::from_value::<StatusUpdateEvent>(probe) {
        Ok(event) => panic!("the probe tag parsed as {event:?}"),
        Err(e) => e.to_string(),
    };
    let expected = message
        .split_once("expected")
        .map(|(_, rest)| rest)
        .unwrap_or_else(|| panic!("serde no longer lists the variants: {message}"));
    let slugs: Vec<String> = expected
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect();
    assert!(
        slugs.len() > 2 && slugs.iter().any(|s| s == "mutation-progress"),
        "could not read the variant list out of serde's error: {message}"
    );
    slugs
}

/// `block-notice-raised` -> `BlockNoticeRaised`, the inverse of the enum's
/// `rename_all = "kebab-case"`.
fn variant_ident(slug: &str) -> String {
    slug.split('-')
        .map(|word| {
            let mut chars = word.chars();
            chars.next().map_or_else(String::new, |first| {
                first.to_ascii_uppercase().to_string() + chars.as_str()
            })
        })
        .collect()
}

// ── Surfaces ────────────────────────────────────────────────────────────────

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn walk(dir: &Path, keep: &dyn Fn(&Path) -> bool, out: &mut Vec<(PathBuf, String)>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, keep, out);
        } else if keep(&path) {
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            out.push((path, text));
        }
    }
}

fn file_name(path: &Path) -> &str {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
}

fn is_qml_or_js(path: &Path) -> bool {
    path.extension().is_some_and(|e| e == "qml" || e == "js")
}

/// The tray's own QML is `Tray.qml` and the windows only it opens (`Tray*.qml`).
fn is_tray_file(path: &Path) -> bool {
    file_name(path).starts_with("Tray")
}

fn is_shared_script(path: &Path) -> bool {
    path.extension().is_some_and(|e| e == "js")
}

struct Surfaces {
    gui: Vec<(PathBuf, String)>,
    tray: Vec<(PathBuf, String)>,
    tui: Vec<(PathBuf, String)>,
}

fn surfaces() -> Surfaces {
    let qml_root = repo_path("../../apps/desktop/qml");
    let mut gui = Vec::new();
    walk(
        &qml_root,
        &|p| is_qml_or_js(p) && !is_tray_file(p),
        &mut gui,
    );
    let mut tray = Vec::new();
    walk(
        &qml_root,
        &|p| is_qml_or_js(p) && (is_tray_file(p) || is_shared_script(p)),
        &mut tray,
    );
    let tui_root = repo_path("../../apps/tui/src");
    let mut tui = Vec::new();
    walk(
        &tui_root,
        &|p| {
            p.extension().is_some_and(|e| e == "rs")
                && !matches!(file_name(p), "tests.rs" | "testing.rs")
                && !p
                    .strip_prefix(&tui_root)
                    .unwrap_or(p)
                    .components()
                    .any(|c| c.as_os_str() == "tests")
        },
        &mut tui,
    );
    for text in tui.iter_mut().map(|(_, text)| text) {
        *text = without_inline_test_module(text);
    }

    for (name, files, anchor) in [
        ("main window", &gui, "Main.qml"),
        ("tray", &tray, "Tray.qml"),
        ("terminal UI", &tui, "state.rs"),
    ] {
        assert!(
            files.iter().any(|(p, _)| file_name(p) == anchor),
            "the {name} sources were not found ({anchor} missing) — the walk is broken"
        );
    }
    Surfaces { gui, tray, tui }
}

/// Production code only: an event named only by a test is not handled. Inline
/// test modules sit at the end of their file, so the file is cut there.
fn without_inline_test_module(text: &str) -> String {
    let mut search_from = 0;
    while let Some(found) = text[search_from..].find("#[cfg(test)]") {
        let at = search_from + found;
        let rest = text[at + "#[cfg(test)]".len()..].trim_start();
        let inline_module = rest
            .strip_prefix("mod ")
            .is_some_and(|r| r.find(['{', ';']).is_some_and(|i| r[i..].starts_with('{')));
        if inline_module {
            return text[..at].to_owned();
        }
        search_from = at + 1;
    }
    text.to_owned()
}

/// A QML/JS dispatcher compares the event's `type` against the slug.
fn qml_reads(files: &[(PathBuf, String)], slug: &str) -> bool {
    let patterns = [
        format!("case \"{slug}\""),
        format!("case '{slug}'"),
        format!("=== \"{slug}\""),
        format!("=== '{slug}'"),
        format!("== \"{slug}\""),
    ];
    files
        .iter()
        .any(|(_, text)| patterns.iter().any(|p| text.contains(p.as_str())))
}

/// The TUI names the variant (a match arm), or — for a client marker — the slug.
fn tui_reads(files: &[(PathBuf, String)], slug: &str) -> bool {
    let path = format!("StatusUpdateEvent::{}", variant_ident(slug));
    let quoted = format!("\"{slug}\"");
    files.iter().any(|(_, text)| {
        text.contains(&quoted)
            || text.match_indices(&path).any(|(i, m)| {
                !text[i + m.len()..]
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_')
            })
    })
}

fn check(surface: &str, slug: &str, duty: Duty, read: bool, problems: &mut Vec<String>) {
    match (duty, read) {
        (Read, false) => problems.push(format!(
            "{slug}: the {surface} has no reader — handle it, or mark it Ignored with the reason"
        )),
        (Ignored(why), true) => problems.push(format!(
            "{slug}: the {surface} reads it but the table says ignored ({why}) — mark it Read"
        )),
        (KnownGap(gap), true) => problems.push(format!(
            "{slug}: the {surface} reads it now — the known gap ({gap}) is closed, mark it Read"
        )),
        (Read, true) | (Ignored(_), false) | (KnownGap(_), false) => {}
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[test]
fn the_table_has_exactly_one_row_per_push_event() {
    let slugs = wire_slugs();
    let mut problems = Vec::new();
    for slug in &slugs {
        let rows = TABLE.iter().filter(|r| r.slug == slug).count();
        if rows != 1 {
            problems.push(format!(
                "{slug}: {rows} rows — every StatusUpdateEvent variant needs exactly one, \
                 saying per surface Read / Ignored(reason) / KnownGap(reason)"
            ));
        }
    }
    for row in TABLE {
        if !slugs.iter().any(|s| s == row.slug) {
            problems.push(format!(
                "{}: no such StatusUpdateEvent variant any more — drop the row",
                row.slug
            ));
        }
    }
    for marker in CLIENT_MARKERS {
        if slugs.iter().any(|s| s == marker.slug) {
            problems.push(format!(
                "{}: is a service event now — move it from CLIENT_MARKERS to TABLE",
                marker.slug
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The TUI reader is found by variant name; a slug that does not map back to a
/// variant would make every TUI check pass or fail for the wrong reason.
#[test]
fn every_slug_maps_back_to_its_variant_name() {
    let source = std::fs::read_to_string(repo_path("src/ipc_payloads.rs"))
        .unwrap_or_else(|e| panic!("cannot read ipc_payloads.rs: {e}"));
    let start = source
        .find("pub enum StatusUpdateEvent {")
        .unwrap_or_else(|| panic!("StatusUpdateEvent is not declared in ipc_payloads.rs"));
    let body = &source[start..];
    for slug in wire_slugs() {
        let ident = variant_ident(&slug);
        let declared = body.lines().any(|line| {
            let line = line.trim_start();
            line.strip_prefix(ident.as_str())
                .is_some_and(|rest| rest.starts_with([' ', ',', '{']) || rest.is_empty())
        });
        assert!(
            declared,
            "{slug} does not map to a declared variant `{ident}`"
        );
    }
}

#[test]
fn every_push_event_is_read_where_the_table_says() {
    let surfaces = surfaces();
    let mut problems = Vec::new();
    for row in TABLE.iter().chain(CLIENT_MARKERS) {
        check(
            "main window",
            row.slug,
            row.gui,
            qml_reads(&surfaces.gui, row.slug),
            &mut problems,
        );
        check(
            "tray",
            row.slug,
            row.tray,
            qml_reads(&surfaces.tray, row.slug),
            &mut problems,
        );
        check(
            "terminal UI",
            row.slug,
            row.tui,
            tui_reads(&surfaces.tui, row.slug),
            &mut problems,
        );
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The self-checks above only mean something if a reader is actually found
/// where one is known to exist and missed where none is.
#[test]
fn the_reader_search_finds_a_known_reader_and_misses_a_made_up_one() {
    let surfaces = surfaces();
    assert!(qml_reads(&surfaces.gui, "mutation-progress"));
    assert!(qml_reads(&surfaces.tray, "mutation-progress"));
    assert!(tui_reads(&surfaces.tui, "mutation-progress"));
    for files in [&surfaces.gui, &surfaces.tray] {
        assert!(!qml_reads(files, "zz-not-an-event"));
    }
    assert!(!tui_reads(&surfaces.tui, "zz-not-an-event"));
    assert_eq!(variant_ident("block-notice-raised"), "BlockNoticeRaised");
    assert_eq!(
        without_inline_test_module("fn a() {}\n#[cfg(test)]\nmod tests {\n fn b() {}\n}\n"),
        "fn a() {}\n"
    );
    assert_eq!(
        without_inline_test_module("#[cfg(test)]\nmod testing;\nfn a() {}\n"),
        "#[cfg(test)]\nmod testing;\nfn a() {}\n"
    );
}
