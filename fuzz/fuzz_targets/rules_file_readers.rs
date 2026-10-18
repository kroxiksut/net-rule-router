#![no_main]
//! The two readers of one rules file, the service's and the clients', side by
//! side: in every section this host reads as rules, both must find the same
//! rules with the same value, state and marks, whatever the bytes.

use libfuzzer_sys::fuzz_target;
use nrr_domain::rules_file::parse_rules_file;
use nrr_shared::preset_parser::{classify_section_lenient, parse_canonical_rules};

/// A rules file is read whole; the import limit bounds it.
const MAX_FILE: usize = 1024 * 1024;

/// Section (lowercase), value, enabled, deny, check, comment.
type Rule = (String, String, bool, bool, bool, String);

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FILE {
        return;
    }
    let text = String::from_utf8_lossy(data);
    let mut service: Vec<Rule> = parse_rules_file(&text)
        .parsed
        .sections
        .iter()
        .filter(|s| classify_section_lenient(s.section.name()).is_some())
        .flat_map(|s| {
            s.entries.iter().map(move |e| {
                (
                    s.section.name().to_ascii_lowercase(),
                    e.match_value.clone(),
                    e.enabled,
                    e.blocked,
                    e.verify_primary,
                    e.inline_comment.clone().unwrap_or_default(),
                )
            })
        })
        .collect();
    let mut clients: Vec<Rule> = parse_canonical_rules(&text)
        .rules
        .into_iter()
        .map(|r| {
            (
                r.section_name.to_ascii_lowercase(),
                r.match_value,
                r.enabled,
                r.blocked,
                r.verify_primary,
                r.comment,
            )
        })
        .collect();
    // The service merges a repeated section into its first; the clients keep
    // file order. Neither order is a reading of the line.
    service.sort();
    clients.sort();
    assert_eq!(service, clients);
});
