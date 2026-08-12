#![forbid(unsafe_code)]
//! GUI-side sidecar SQLite database — block 16.QoL+0.
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
//! * `pending_apply` — last `_buildRulesJson()` snapshot from the GUI
//!   plus a precomputed `{added, modified, removed}` summary. Written
//!   when the user chooses "Work without service" in the
//!   `ServiceNotRunningDialog`; read on the next successful connect to
//!   prompt "Apply pending changes?". TTL is 7 days from the last
//!   modification — stale state is treated as absent.
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
//! and any UI crate. The only allowed deps are `rusqlite` (bundled) and
//! `thiserror`.
//!
//! # Threading model
//!
//! Synchronous `rusqlite` blocking API — same convention as
//! `nrr-storage`. WAL journal mode is enforced on open with
//! `busy_timeout = 5000 ms`. Callers in async contexts (the GUI's
//! launcher subprocess) wrap calls in `tokio::task::spawn_blocking` if
//! they hold an async runtime; the Q_INVOKABLE bridge is called from
//! the Qt event loop and treats the calls as fast synchronous ops
//! (single-row reads/writes, all sub-millisecond on local SSDs).
//!
//! # Storage location
//!
//! Default: `%APPDATA%\NetRuleRouter\gui_metadata.db` (Windows) — per
//! user, so Alice and Bob get separate sidecars on a shared machine.
//! The path is resolved by [`profile::resolve_default_path`]; tests and
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
