//! Canonical txt preset parser.
//!
//! Replaces the JavaScript `_parseCanonicalRulesText` that used to live in
//! `Main.qml`. The Rust implementation is the source of truth for the
//! canonical txt format (docs/en/rules-file-format.md Rules File Format) and is reachable from QML via the
//! `preset.parse` local RPC opcode, and directly from the service side
//! without going through the GUI process.
//!
//! ## Format summary (see docs/en/rules-file-format.md Rules File Format for the full spec)
//!
//! * Sections are introduced by lines starting with `--- ` (exactly
//!   three hyphens, one space, then the section name). The name is
//!   case-sensitive.
//! * Known section names: `Zones`, `Domains`, `IP`, `Windows`, `Auto`, plus
//!   foreign-OS `Linux` / `MacOS` (preserved as passthrough on Windows
//!   hosts — see [`is_known_section`]).
//! * `--- Auto` holds rules the application authored on the user's behalf.
//!   Values follow the `Domains` grammar; each line's provenance is lifted out
//!   of the inline comment into [`ParsedRule::origin`] (docs/en/rules-file-format.md App-authored rules).
//! * Inside a known section, each non-blank, non-comment line is an
//!   active rule. A line starting with `# ` (or `#`, no space) is a
//!   disabled rule when its body is a single token (matches the
//!   round-trip semantics in the QML parser).
//! * Multi-word `# free text` is a documentation comment — skipped
//!   and not round-tripped through `rules`.
//! * A `+block` flag token after the match value (before any inline `#`)
//!   marks the rule as a hard block: matching traffic is dropped and the
//!   containing file (primary/secondary) is irrelevant for enforcement.
//!   See docs/en/rules-file-format.md Blocking destinations. Mirrors the documented `+children` convention.
//! * The first unescaped `#` past the value content starts an inline
//!   comment that becomes the rule's `comment` field.
//! * Lines preceding any `--- ` header are file-level prelude and are
//!   silently dropped (header preservation is out of scope for v1).
//!
//! ## Output shape
//!
//! [`PresetParseResult`] separates three concerns the GUI / service
//! cares about distinctly:
//!
//! 1. **`rules`** — what the routing engine actually consumes.
//! 2. **`passthrough`** — raw text of unknown sections. The sidecar
//!    DB stores these so an Export-to-file round-trip is byte-identical
//!    even for sections this build doesn't understand.
//! 3. **`duplicate_sections`** — names of sections that appeared more
//!    than once. The UI uses this to prompt the user for a merge
//!    policy in [`PresetImportReviewDialog`].
//!
//! Caller assigns final rule ids (`R-NNNN`) — the parser only emits
//! 1-based `id_hint` values so the GUI can offset them against
//! existing rules (`nextFreeRuleId`).

use serde::{Deserialize, Serialize};

mod rule_line;
mod sections;
mod state;
mod types;

pub use rule_line::*;
pub use sections::*;
use state::*;
pub use types::*;

#[cfg(test)]
mod tests;
