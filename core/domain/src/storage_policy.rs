//! Versioned storage schema policy for all persistent stores.
//!
//! This module documents the version markers, compatibility policies, storage
//! topology, and migration strategies for each persistent store in
//! NetRuleRouter. It carries no runtime behaviour — its purpose is to make
//! all policy decisions explicit and co-located as a single authoritative
//! reference for real service integration.
//!
//! # Stores
//!
//! | Store                     | Owner        | Version constant                      |
//! |---------------------------|--------------|----------------------------------------|
//! | UI preferences file       | UI runtime   | `nrr_ui_support` `CURRENT_UI_PREFS_SCHEMA_VERSION` |
//! | Rules file (external)     | User / editor| [`CURRENT_RULES_FILE_FORMAT_VERSION`] |
//! | Service revision store    | Background service | last `MigrationDef` in `nrr-storage` `MIGRATIONS` |
//!
//! # Compatibility policy (all stores)
//!
//! See [`CompatibilityPolicy`] for the full rationale. In summary:
//!
//! - **Backward-compatible read**: the current build can always read files
//!   written by an older build, loading all known fields.
//! - **Additive-only new fields**: new schema versions add optional fields.
//!   Existing fields are never removed or renamed without a migration step.
//! - **Forward-graceful read**: a file from a newer build is read in degrade
//!   mode — known fields are loaded, unknown ones are kept and written back,
//!   and a diagnostic is emitted. No silent data loss.
//! - **Silent reset forbidden**: no migration may discard a user-configured
//!   value without explicit user action or a documented migration mapping.
//!
//! # Storage topology
//!
//! See [`StorageTopology`] for details. Short form:
//!
//! - **UI preferences**: `managed\ui-preferences.conf` under the per-user
//!   configuration root — `%APPDATA%\NetRuleRouter` on Windows,
//!   `$XDG_CONFIG_HOME/netrulerouter` (`~/.config/netrulerouter`) elsewhere
//!   (key=value text, schema_version field, managed by `nrr-ui-support`).
//! - **Rules files**: user-chosen paths; two files per configuration (primary
//!   + secondary). Text format with version header and section markers.
//! - **Service revision store**: SQLite database at a service-owned path.
//!   Holds canonical revisions, active pointer,
//!   last-known-good pointer, and integrity metadata.
//!
//! # Migration triggers
//!
//! See [`MigrationTrigger`]. UI preferences need no migration step: every
//! load reads the keys it knows and the next save stamps the current version.
//! The service revision store runs its pending schema steps on open, after a
//! pre-migration snapshot.

// ── Version constants (re-exported for discoverability) ──────────────────────

/// The rules file format version this build writes and fully understands.
pub use crate::rules_file::CURRENT_RULES_FILE_FORMAT_VERSION;

// ── Compatibility policy ──────────────────────────────────────────────────────

/// Documents the compatibility policy that all persistent stores must follow.
///
/// This type carries no runtime behaviour. Instantiate it with `let _ =
/// CompatibilityPolicy;` in a documentation comment or integration test to
/// make the dependency explicit and searchable.
///
/// # Rules
///
/// 1. **Backward-compatible read** (old file, new build): all known fields are
///    loaded without error — no panic, no silent reset of known values. In UI
///    preferences a key unknown to this build is kept verbatim and written back
///    when the file declares this schema version or newer (a setting from a
///    build that has it); in an older file it is the residue of a removed key
///    and is dropped.
///
/// 2. **Additive-only changes**: new schema versions may add fields. Existing
///    fields must not be removed or semantically changed without a migration
///    function and a schema version bump.
///
/// 3. **Forward-graceful read** (new file, old build): when the file's
///    schema version exceeds the build's `CURRENT_*_VERSION`, known fields are
///    still loaded and unknown ones carried through a save. A non-fatal
///    diagnostic (eprintln/tracing::warn) is emitted.
///    The file is **not** automatically downgraded — the caller decides whether
///    to overwrite.
///
/// 4. **Silent reset forbidden**: migrations must map every known field to its
///    equivalent in the new schema. Fields without a mapping must be preserved
///    at their previous value or explicitly dropped with user notification.
///
/// 5. **Version absent → legacy file**: a UI preferences file without a
///    `schema_version` line was written by a pre-versioning build. Its known
///    keys are read as they are, keys it lacks take their defaults, and keys
///    this build does not know are dropped; the next save stamps the current
///    version. There is no per-version mapping code.
pub struct CompatibilityPolicy;

// ── Storage topology ─────────────────────────────────────────────────────────

/// Documents where each store lives on disk and who owns each path.
///
/// This type carries no runtime behaviour; it exists as a single
/// authoritative reference for path ownership and I/O boundaries.
///
/// # UI preferences store
///
/// - **Path**: `managed\ui-preferences.conf` under the per-user configuration
///   root the OS declares (`nrr_shared::user_paths`): `%APPDATA%\NetRuleRouter`
///   on Windows, `$XDG_CONFIG_HOME/netrulerouter` elsewhere. Falls to the next
///   candidate when one cannot be created, ending at the temp directory.
///   Debug and release builds share it.
/// - **Format**: line-oriented `key=value` text with a `# comment` header and
///   a `schema_version=N` field on the first non-comment line.
/// - **Owner**: `nrr-ui-support` crate (`UiPreferencesStore`).
/// - **Migration trigger**: none; see rule 5 of [`CompatibilityPolicy`].
/// - **Failure mode**: on write failure, previous file is left intact (atomic
///   rename via `.tmp` → target); load falls back to `UiPreferences::default()`.
///
/// # Rules files (external format)
///
/// - **Path**: user-chosen; two files per Free configuration (`rules_primary.txt`
///   and `rules_secondary.txt` by convention, but any name is accepted).
/// - **Format**: sectioned text with `# version` preamble header and
///   `--- SectionName` markers. Parsed by
///   [`crate::rules_file::parse_rules_file`].
/// - **Owner**: user / external editor. The application reads but does not
///   own the file path — the user controls it.
/// - **Version detection**: `# NetRuleRouter rules file — version N` preamble.
///   Absent header → legacy file (no version check). Unknown version →
///   [`crate::rules_file::ParseWarning::UnknownFormatVersion`] warning.
///
/// # Service revision store
///
/// - **Path**: `nrr_service_state.db` under the service data root
///   (`nrr_platform_api::paths::production_data_root`).
/// - **Format**: SQLite database.
/// - **Owner**: the background service process only (`nrr-storage`, driven by
///   `nrr-service-runtime`). No other process writes to this store.
/// - **Contents**: canonical policy revisions, active revision pointer,
///   last-known-good pointer, per-revision integrity metadata (hash + signature
///   chain), import provenance, and audit events.
/// - **Migration trigger**: on open, when the recorded schema version (the
///   highest applied step in `schema_migrations`) is below the last
///   `MigrationDef` in `nrr-storage`'s `MIGRATIONS`. The file is first copied to
///   `<data dir>/backups/migrations`; a failed copy refuses the upgrade.
/// - **Failure mode**: every pending step runs in ONE immediate transaction,
///   so a failing step rolls the whole run back and the database stays at its
///   previous version; the open fails with `MigrationFailed`. Checksums of the
///   applied steps are verified on every open.
pub struct StorageTopology;

// ── Migration triggers ────────────────────────────────────────────────────────

/// Documents which migrations run automatically and which require explicit
/// operator intervention.
///
/// This type carries no runtime behaviour.
///
/// # Automatic migrations (run silently on startup, safe to repeat)
///
/// - **UI preferences**: nothing to run. A key added in a new build is not a
///   version bump; removing or re-meaning one is. `UiPreferencesStore::load()`
///   reads the keys it knows, and the next `save()` stamps
///   `CURRENT_UI_PREFS_SCHEMA_VERSION`.
///
/// # Semi-automatic migrations (require passing all integrity checks)
///
/// - **Service revision store schema upgrade**: on open, when the recorded
///   schema version is below the last `MigrationDef` in `MIGRATIONS`. The store
///   is snapshotted, then the pending steps run in one transaction. No user
///   interaction is required **unless** the upgrade fails — see failure mode in
///   [`StorageTopology`].
///
/// # Blocking migrations (require explicit administrator action)
///
/// - **Downgrade / unsupported version**: when the recorded schema version is
///   greater than the last step this build knows (a file from a newer build),
///   the open fails with `UnsupportedSchemaVersion` and policy load reports
///   recovery required; nothing is migrated down. The administrator must either
///   upgrade the service binary or restore a compatible snapshot.
/// - **Corrupted integrity metadata**: the service refuses to activate any
///   revision whose stored hash does not match the recomputed hash. Manual
///   investigation and explicit operator override are required.
pub struct MigrationTrigger;

// ── Active/pending/last-known-good pointer model ─────────────────────────────

/// Documents the lifecycle of revision pointers in the service store.
///
/// This type carries no runtime behaviour — documentation only. Any store
/// implementation must satisfy all invariants listed here.
///
/// # Pointer semantics
///
/// - **`active`**: the revision currently enforced by the routing engine.
///   There is always exactly one active revision (or `None` for a pristine
///   install before first-run). Switching `active` is the only way to change
///   the enforced policy.
/// - **`pending`**: a candidate revision that has been validated and
///   canonicalized but not yet confirmed by the user. At most one pending
///   revision exists at a time. Importing a new candidate replaces the
///   previous pending.
/// - **`last_known_good`**: the most recent revision that was active and
///   passed all integrity checks. Updated atomically whenever `active` is
///   promoted. Safe-rollback targets this pointer.
///
/// # Migration invariant
///
/// No migration step may leave the store without a valid `last_known_good`
/// pointer. If the migration cannot preserve the previous `last_known_good`,
/// it must capture a snapshot of the pre-migration `active` revision and
/// designate it as the new `last_known_good` before finalising.
///
/// # Pointer lifecycle on import
///
/// 1. External file → parse → validate/canonicalize → store as `pending`.
/// 2. User reviews diff and confirms → `pending` promoted to `active`;
///    previous `active` becomes `last_known_good`.
/// 3. Safe rollback → `active` set back to `last_known_good`; former `active`
///    is archived (not deleted — kept for diagnostics).
pub struct RevisionPointerModel;
