//! External rules file format types and preset metadata.
//!
//! Two separate files are used — one per route role (e.g.
//! `rules_primary.txt` and `rules_secondary.txt`, though the user may choose
//! any filename). A preset is the same format with optional metadata header
//! comments. Each file follows a sectioned text format:
//!
//! ```text
//! # NetRuleRouter rules file — version 4
//!
//! --- Zones
//! corp-network  # internal corporate zone
//!
//! --- Domains
//! updates.example.org  # vendor updates
//! # old.example.com    # disabled rule
//!
//! --- IP
//! 203.0.113.7
//!
//! --- Windows
//! browser.exe   # browser traffic
//! # powershell.exe
//!
//! --- Linux
//! # (reserved — not applied on Windows)
//!
//! --- MacOS
//! # (reserved — not applied on Windows)
//!
//! --- Auto
//! rr3.example-cdn.net  # auto:site-companion anchor:example.com added:
//! ```
//!
//! A preset file adds optional metadata header comments before the first section:
//!
//! ```text
//! # NetRuleRouter preset — version 4
//! # name: Corporate VPN Rules
//! # description: Routes corporate traffic via VPN
//! # author: Jane Doe
//! # preset_version: 1
//! ```
//!
//! # Syntax rules
//!
//! - `--- SectionName` — section header (names are technical keywords, never localized)
//! - `value` — active rule
//! - `value  # text` — active rule with inline comment (label in GUI)
//! - `# value` — disabled rule (GUI toggle-off maps to commenting the line)
//! - lines with only `#` text and no rule token — free comments, ignored by parser
//! - empty lines — ignored
//!
//! # Platform filtering
//!
//! On Windows, `--- Linux` and `--- MacOS` sections are parsed and preserved
//! but not applied. The GUI hides them by default; "Show rules for other
//! operating systems" makes them visible.
//!
//! # Evaluation priority
//!
//! See [`RulesFileEvaluationPriority`] for the fixed priority order.

use core::fmt;

use nrr_shared::auto_rule::{parse_provenance_comment, RuleOrigin};

// ── RulesFileSection ──────────────────────────────────────────────────────────

mod convert;
mod model;
mod parse;
mod version;
mod write;

pub use convert::*;
pub use model::*;
pub use parse::*;
pub use version::*;
pub use write::*;

/// Documents the invariant governing SQLite rule-cache lifecycle on file change.
///
/// This type carries no runtime behaviour — it exists to make the invariant
/// explicit and discoverable at the domain level.
///
/// # Invariant
///
/// When the user changes the configured path to a different rule file, the
/// SQLite operational rule cache **must** be cleared and fully reloaded from
/// the new file before the change takes effect. Partial reloads that leave
/// stale entries from the previous file are not permitted.
///
/// # Rationale
///
/// The file is the source of truth; SQLite is a derived index. When the source
/// of truth changes identity (different path → different rules), the derived
/// copy has no valid basis to retain prior entries.
///
/// # Enforcement point
///
/// The service layer enforces this invariant when processing a
/// "change rule file path" mutation command. This type is a domain-level
/// record of the requirement so it survives code reorganization.
pub struct RuleFileCachePolicy;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
