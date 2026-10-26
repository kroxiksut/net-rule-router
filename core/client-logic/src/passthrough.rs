//! Sections this build does not apply, kept per name for the rewrite of a
//! rules file (`mergePassthroughBlocks`).

use std::collections::BTreeMap;

/// One section's text added under its name: a name already held keeps its
/// text and gets this one after it, so a section written twice loses nothing
/// of its first copy.
pub fn add_passthrough_block(sections: &mut BTreeMap<String, String>, name: &str, raw: &str) {
    if name.is_empty() {
        return;
    }
    let text = sections.entry(name.to_owned()).or_default();
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(raw);
}

/// `(name, raw text)` blocks in file order, merged per name.
pub fn merge_passthrough_blocks(blocks: &[(String, String)]) -> BTreeMap<String, String> {
    let mut sections = BTreeMap::new();
    for (name, raw) in blocks {
        add_passthrough_block(&mut sections, name, raw);
    }
    sections
}
