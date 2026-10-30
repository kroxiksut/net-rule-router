//! Sections this build does not apply, kept per name for the rewrite of a
//! rules file (`mergePassthroughBlocks`).

use std::collections::BTreeMap;

pub use nrr_shared::preset_parser::add_passthrough_block;

/// `(name, raw text)` blocks in file order, merged per name.
pub fn merge_passthrough_blocks(blocks: &[(String, String)]) -> BTreeMap<String, String> {
    let mut sections = BTreeMap::new();
    for (name, raw) in blocks {
        add_passthrough_block(&mut sections, name, raw);
    }
    sections
}
