//! Sanity check: parse every shipped country-preset file and assert
//! the parser doesn't crash, doesn't lose entire sections, and surfaces
//! a sensible structural breakdown. These tests are intentionally
//! coarse — exact rule counts are not asserted because the preset
//! content evolves; we instead check invariants that must hold for any
//! well-formed preset.
//!
//! The fixtures are loaded from the repo's `presets/` tree (the same
//! files shipped to end users). If you add a new country preset and
//! this test starts failing, the parser has a regression — fix the
//! parser, not the test.

#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use nrr_shared::preset_parser::{parse_canonical_rules, ParsedRuleType};

/// Walk the `presets/` tree and return paths to every
/// `rules_primary.txt` / `rules_secondary.txt` we ship. The walk is
/// hand-rolled (no `walkdir` dep) because the structure is shallow —
/// `presets/<cc>/<variant>/rules_*.txt`.
fn discover_preset_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("presets"))
        .expect("workspace root has presets/");
    if !root.exists() {
        panic!("presets/ directory not found at {}", root.display());
    }
    let countries = fs::read_dir(&root).expect("read presets/");
    for cc_entry in countries {
        let cc_entry = cc_entry.expect("read country dir entry");
        if !cc_entry.file_type().expect("file_type").is_dir() {
            continue;
        }
        let variants = fs::read_dir(cc_entry.path()).expect("read variant dir");
        for variant_entry in variants {
            let variant_entry = variant_entry.expect("read variant entry");
            if !variant_entry.file_type().expect("file_type").is_dir() {
                continue;
            }
            for name in ["rules_primary.txt", "rules_secondary.txt"] {
                let candidate = variant_entry.path().join(name);
                if candidate.is_file() {
                    out.push(candidate);
                }
            }
        }
    }
    out.sort();
    out
}

#[test]
fn discovers_at_least_one_country_preset() {
    let files = discover_preset_files();
    assert!(
        !files.is_empty(),
        "expected at least one country-preset fixture under presets/"
    );
}

#[test]
fn every_country_preset_parses_without_panic() {
    let files = discover_preset_files();
    for path in &files {
        let text =
            fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        // The parser is total — it must never panic on real preset
        // text. If a country file breaks this, the parser has a
        // regression (or the file has an unanticipated structure).
        let _ = parse_canonical_rules(&text);
    }
}

#[test]
fn every_country_preset_emits_at_least_one_rule_or_passthrough() {
    // A preset that produces no rules and no passthrough is suspicious —
    // it would mean either the file is empty (shouldn't ship) or the
    // parser dropped everything. Each shipped preset should yield
    // SOMETHING actionable.
    let files = discover_preset_files();
    for path in &files {
        let text = fs::read_to_string(path).expect("read");
        let result = parse_canonical_rules(&text);
        let nonempty = !result.rules.is_empty() || !result.passthrough.is_empty();
        assert!(
            nonempty,
            "{} produced zero rules AND zero passthrough — \
             either the file is empty or the parser silently dropped \
             its content",
            path.display(),
        );
    }
}

#[test]
fn no_country_preset_has_duplicate_sections() {
    // The presets we ship are hand-curated; duplicate sections would
    // indicate a copy-paste mistake during editing.
    let files = discover_preset_files();
    let mut violations: Vec<(PathBuf, Vec<String>)> = Vec::new();
    for path in &files {
        let text = fs::read_to_string(path).expect("read");
        let result = parse_canonical_rules(&text);
        if !result.duplicate_sections.is_empty() {
            let names: Vec<String> = result
                .duplicate_sections
                .iter()
                .map(|d| d.section_name.clone())
                .collect();
            violations.push((path.clone(), names));
        }
    }
    if !violations.is_empty() {
        let detail: Vec<String> = violations
            .iter()
            .map(|(p, names)| format!("{}: [{}]", p.display(), names.join(", ")))
            .collect();
        panic!(
            "the following country presets contain duplicate section \
             headers — fix the file or revisit the parser's duplicate \
             detection:\n  {}",
            detail.join("\n  "),
        );
    }
}

#[test]
fn ru_primary_preserves_idn_zone_round_trip_intent() {
    // The RU primary preset is the canonical test for our Unicode↔
    // Punycode boundary policy: the file stores human-readable forms
    // (`рф`, `ru`, `su`) and the GUI handles boundary conversion on the
    // wire. Verify the parser extracts exactly the three documented
    // zones, plus several domain rules.
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| {
            p.join("presets")
                .join("ru")
                .join("osnovnoy-i-zarubezh")
                .join("rules_primary.txt")
        })
        .expect("ru primary preset");
    if !path.exists() {
        // CI may not ship the full tree; skip rather than fail when
        // fixtures are absent.
        return;
    }
    let text = fs::read_to_string(&path).expect("read RU primary");
    let result = parse_canonical_rules(&text);

    let zone_values: Vec<&str> = result
        .rules
        .iter()
        .filter(|r| r.rule_type == ParsedRuleType::Zone)
        .map(|r| r.match_value.as_str())
        .collect();
    // Expect at least the three RU zones, in any order, with
    // their Unicode/native forms.
    assert!(
        zone_values.contains(&"ru"),
        "RU primary should include zone `ru`, got: {zone_values:?}",
    );
    assert!(
        zone_values.contains(&"рф"),
        "RU primary should include zone `рф`, got: {zone_values:?}",
    );
    assert!(
        zone_values.contains(&"su"),
        "RU primary should include zone `su`, got: {zone_values:?}",
    );

    // Every zone in the RU primary carries an explanatory comment we
    // expect to surface.
    let rf_rule = result
        .rules
        .iter()
        .find(|r| r.match_value == "рф")
        .expect("`рф` rule");
    assert!(
        !rf_rule.comment.is_empty(),
        "`рф` zone should carry an inline Punycode comment per \
         block 16.QoL+0 RU-preset enrichment",
    );
}

#[test]
fn presets_with_foreign_os_sections_preserve_them_as_passthrough() {
    // At least one of our country presets should carry foreign-OS
    // (`--- Linux` / `--- MacOS`) sections (most do, since the
    // canonical format requires the sections to be present even if
    // empty per docs/en/rules-file-format.md Sections). Verify the parser surfaces them
    // as passthrough rather than dropping them.
    let files = discover_preset_files();
    let mut presets_with_passthrough = 0_usize;
    let mut total_linux_blocks = 0_usize;
    let mut total_macos_blocks = 0_usize;
    for path in &files {
        let text = fs::read_to_string(path).expect("read");
        let result = parse_canonical_rules(&text);
        if !result.passthrough.is_empty() {
            presets_with_passthrough += 1;
            for block in &result.passthrough {
                match block.section_name.as_str() {
                    "Linux" => total_linux_blocks += 1,
                    "MacOS" => total_macos_blocks += 1,
                    _ => {}
                }
            }
        }
    }
    // We don't know the exact numbers (depends on how many presets
    // ship with these sections) but we can assert at least one
    // foreign-OS block exists across the whole tree — otherwise the
    // passthrough mechanism is silently doing nothing.
    assert!(
        total_linux_blocks > 0 || total_macos_blocks > 0,
        "no country preset surfaced Linux or MacOS passthrough — \
         either no preset ships those sections (regression in the \
         country presets) or the parser dropped them",
    );
    assert!(
        presets_with_passthrough > 0,
        "no country preset has any passthrough at all",
    );
}
