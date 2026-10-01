#![forbid(unsafe_code)]
//! GUI-side sidecar SQLite database.
//!
//! `nrr-storage-sidecar` persists data that lives strictly on the user's
//! machine and never crosses the IPC boundary to the service:
//!
//! * `rule_metadata` — user-typed comments keyed by `type|lower(value)|route`.
//!   The decision engine and audit log are deliberately blind to comments;
//!   they're free-form notes the user attaches to rules for personal
//!   reference. Stored here so the GUI can recover them across restarts
//!   without leaking them to the service-side audit trail.
//!
//! * `passthrough` — raw text of unknown sections (e.g. `--- Linux`,
//!   `--- MacOS`, `--- Ports`) captured at preset-import time. The GUI
//!   parses only its host-OS section but preserves the rest so an
//!   `Export to file…` round-trip is byte-identical for the foreign-OS
//!   blocks.
//!
//! * `pending_apply` — a one-row marker: the content hash of the parked
//!   rules plus a precomputed `{added, modified, removed}` summary, never
//!   the rules themselves. Written when the user chooses "Work without
//!   service"; read on the next successful connect to offer "Apply pending
//!   changes?". TTL is 7 days from the last modification.
//!
//! * `external_ip_cache` — last-known external (reflexive) IPv4
//!   address per adapter, written on every live snapshot that resolves
//!   one. Read back only to paint a muted "last known" hint when the
//!   service is unreachable; the GUI never probes on its own.
//!
//! # Crate boundaries
//!
//! `nrr-storage-sidecar` is GUI-only. **Forbidden** deps: `nrr-storage`
//! (service-owned), `nrr-shared` (wire schemas — sidecar has nothing to
//! do with the wire), `nrr-service-runtime`, `nrr-platform-windows`,
//! and any UI crate. Allowed: `rusqlite` (bundled), `thiserror` and the
//! leaf `nrr-sqlite-support`.
//!
//! # Threading model
//!
//! Synchronous `rusqlite` blocking API — same convention as
//! `nrr-storage`. WAL journal mode is enforced on open with
//! `busy_timeout = 5000 ms`. Two processes hold the file: the GUI launcher
//! and the tray launcher, one connection each, both serving `sidecar.*`
//! RPCs on their worker threads, never on the Qt event loop.
//!
//! # Storage location
//!
//! Default: `%LOCALAPPDATA%\NetRuleRouter\gui_metadata.db` on Windows,
//! `$XDG_DATA_HOME/NetRuleRouter/gui_metadata.db` elsewhere — per user, and
//! local rather than roaming because a WAL database must not travel.
//! The path is resolved by [`profile::resolve_path`]; tests and
//! headless drivers can override via the `NRR_SIDECAR_PATH` env var.
//!
//! # On corruption
//!
//! Sidecar contents are **rebuildable** — comments are user-typed
//! decoration, passthrough survives only as long as the user keeps
//! re-importing the source file, and `pending_apply` self-expires after
//! seven days. On schema-version mismatch we refuse to open and let the
//! user pick "Reset application data" from Settings; we never auto-
//! truncate a non-empty user-owned database.

pub mod db;
pub mod error;
pub mod migration;
pub mod profile;
mod schema;
pub mod vacuum;

pub mod external_ip_cache;
pub mod passthrough;
pub mod pending_apply;
pub mod rule_metadata;

pub use db::SidecarDb;
pub use error::{SidecarError, SidecarResult};
pub use migration::{MigrationSummary, LATEST_SCHEMA_VERSION};
pub use profile::{resolve_default_path, resolve_path, resolve_path_with, NRR_SIDECAR_PATH_ENV};

// Passthrough DAO lives on `SidecarDb` directly — see `passthrough.rs`.
pub use external_ip_cache::ExternalIpCacheEntry;
pub use pending_apply::{PendingApplyEntry, PendingApplySummary, PENDING_APPLY_TTL_SECONDS};
pub use rule_metadata::{sanitize_comment, RuleSignature, COMMENT_MAX_LEN};
