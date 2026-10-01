//! Every shipped pack goes through the real import: `validate_preset_bytes`
//! plus canonicalization, on each host platform. The lighter parser check in
//! `nrr-shared` only proves the text does not crash the parser.

#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use nrr_domain::{
    preset_canonicalize::canonicalize_preset_rules,
    preset_validation::validate_preset_bytes,
    rules_file::{HostPlatform, ParseOutcome},
    validation::ValidationWarning,
};
use nrr_shared::RouteRole;

fn presets_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../presets")
}

/// Every `rules_*.txt` under `presets/`, at any depth, `examples/` included.
fn shipped_rules_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
            let path = entry.expect("read dir entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("rules_") && n.ends_with(".txt"))
            {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(&presets_root(), &mut out);
    out.sort();
    out
}

fn route_of(path: &Path) -> RouteRole {
    match path.file_name().and_then(|n| n.to_str()) {
        Some("rules_secondary.txt") => RouteRole::Secondary,
        _ => RouteRole::Primary,
    }
}

fn shown(path: &Path) -> String {
    path.strip_prefix(presets_root())
        .unwrap_or(path)
        .display()
        .to_string()
}

/// A native-script zone or domain is stored as written and imported as
/// punycode: the one normalization a pack is allowed to trigger.
fn is_documented_idn(warning: &ValidationWarning) -> bool {
    matches!(
        warning,
        ValidationWarning::DomainNormalizedToAscii { original, .. } if !original.is_ascii()
    )
}

#[test]
fn every_shipped_pack_imports_cleanly_on_every_platform() {
    let files = shipped_rules_files();
    assert!(
        files.len() > 10,
        "positive control: the walk reaches the packs"
    );

    let mut problems = Vec::new();
    for path in &files {
        let bytes = fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let outcome = validate_preset_bytes(&bytes);
        if !outcome.is_accepted() || outcome.has_warnings() {
            problems.push(format!("{}: validation {outcome:?}", shown(path)));
            continue;
        }
        let parsed = outcome
            .parse_outcome()
            .expect("accepted outcome carries a parse");
        for platform in [HostPlatform::Windows, HostPlatform::Linux] {
            let canon = canonicalize_preset_rules(parsed, route_of(path), platform, false);
            if !canon.is_accepted() {
                problems.push(format!("{} on {platform:?}: {canon:?}", shown(path)));
                continue;
            }
            for warning in canon.warnings().iter().filter(|w| !is_documented_idn(w)) {
                problems.push(format!("{} on {platform:?}: {warning:?}", shown(path)));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "shipped packs must import without refusal or warning:\n  {}",
        problems.join("\n  ")
    );
}

/// What a file routes, ignoring its header and comments: each section with
/// its entries and their on/off state.
fn rule_content(parsed: &ParseOutcome) -> BTreeSet<(String, String, bool)> {
    let known = parsed
        .parsed
        .sections
        .iter()
        .flat_map(|s| s.entries.iter().map(move |e| (s.section.name(), e)));
    let unknown = parsed
        .unknown_sections
        .iter()
        .flat_map(|s| s.entries.iter().map(move |e| (s.name.as_str(), e)));
    known
        .chain(unknown)
        .map(|(section, e)| (section.to_string(), e.match_value.clone(), e.enabled))
        .collect()
}

/// Groups of packs whose `rules_secondary.txt` route exactly the same set.
fn packs_sharing_a_secondary_list() -> Vec<Vec<String>> {
    let mut by_content: BTreeMap<BTreeSet<(String, String, bool)>, Vec<String>> = BTreeMap::new();
    for path in shipped_rules_files()
        .iter()
        .filter(|p| route_of(p) == RouteRole::Secondary)
    {
        let bytes = fs::read(path).expect("read pack");
        let outcome = validate_preset_bytes(&bytes);
        let Some(parsed) = outcome.parse_outcome() else {
            continue;
        };
        let content = rule_content(parsed);
        // A country with nothing to route elsewhere ships an empty list; two of
        // those agree without either being a copy.
        if !content.iter().any(|(_, _, enabled)| *enabled) {
            continue;
        }
        by_content.entry(content).or_default().push(shown(path));
    }
    by_content.into_values().filter(|g| g.len() > 1).collect()
}

// What fails on the direct channel differs by country, so a copied list is
// one written for somewhere else.
#[test]
fn no_two_countries_share_a_secondary_list() {
    let groups = packs_sharing_a_secondary_list();
    assert!(
        groups.is_empty(),
        "packs with identical secondary routing:\n  {}",
        groups
            .iter()
            .map(|g| g.join(", "))
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}

#[test]
fn the_sharing_check_sees_through_headers_and_comments() {
    let a = validate_preset_bytes(
        b"# NetRuleRouter preset - version 1\n# name: A\n--- Domains\n*.example.com  # one\n",
    );
    let b = validate_preset_bytes(b"# name: B\n\n--- Domains\n*.example.com\n");
    let c = validate_preset_bytes(b"--- Domains\n# *.example.com\n");
    let content = |o: &nrr_domain::preset_validation::PresetFileValidationOutcome| {
        rule_content(o.parse_outcome().expect("accepted"))
    };
    assert_eq!(content(&a), content(&b));
    assert_ne!(content(&a), content(&c), "a disabled rule routes nothing");
}
