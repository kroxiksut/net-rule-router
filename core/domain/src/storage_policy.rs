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
//! | UI preferences file       | UI runtime   | [`UI_PREFS_CURRENT_SCHEMA_VERSION`]   |
//! | Rules file (external)     | User / editor| [`RULES_FILE_CURRENT_FORMAT_VERSION`] |
//! | Service revision store    | Background service | (implemented separately)         |
//!
//! # Compatibility policy (all stores)
//!
//! See [`CompatibilityPolicy`] for the full rationale. In summary:
//!
//! - **Backward-compatible read**: the current build can always read files
//!   written by an older build, loading all known fields and ignoring any
//!   unrecognised ones.
//! - **Additive-only new fields**: new schema versions add optional fields.
//!   Existing fields are never removed or renamed without a migration step.
//! - **Forward-graceful read**: a file from a newer build is read in degrade
//!   mode — known fields are loaded, unknown fields are silently ignored, and
//!   a diagnostic is emitted. No silent data loss.
//! - **Silent reset forbidden**: no migration may discard a user-configured
//!   value without explicit user action or a documented migration mapping.
//!
//! # Storage topology
//!
//! See [`StorageTopology`] for details. Short form:
//!
//! - **UI preferences**: `%APPDATA%\NetRuleRouter\managed\ui-preferences.conf`
//!   (key=value text, schema_version field, managed by `nrr-ui-support`).
//! - **Rules files**: user-chosen paths; two files per configuration (primary
//!   + secondary). Text format with version header and section markers.
//! - **Service revision store**: SQLite database at a service-owned path.
//!   Holds canonical revisions, active pointer,
//!   last-known-good pointer, and integrity metadata.
//!
//! # Migration triggers
//!
//! See [`MigrationTrigger`]. UI preferences are migrated automatically on
//! first load after an upgrade. The service revision store requires an explicit
//! migration step with pre-migration backup and post-migration verification.

// ── Version constants (re-exported for discoverability) ──────────────────────

/// The UI preferences schema version this build writes and fully understands.
///
/// Defined in `nrr-ui-support`; mirrored here as a domain-level constant for
/// cross-store version tracking and documentation purposes.
pub const UI_PREFS_CURRENT_SCHEMA_VERSION: u32 = 1;

/// The rules file format version this build writes and fully understands.
///
/// Defined in [`crate::rules_file::CURRENT_RULES_FILE_FORMAT_VERSION`];
/// mirrored here for cross-store documentation.
pub const RULES_FILE_CURRENT_FORMAT_VERSION: u32 = 1;

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
///    loaded without error. Unrecognised fields from a future schema are
///    silently dropped — no panic, no error, no silent reset of known values.
///
/// 2. **Additive-only changes**: new schema versions may add fields. Existing
///    fields must not be removed or semantically changed without a migration
///    function and a schema version bump.
///
/// 3. **Forward-graceful read** (new file, old build): when the file's
///    schema version exceeds the build's `CURRENT_*_VERSION`, known fields are
///    still loaded. A non-fatal diagnostic (eprintln/tracing::warn) is emitted.
///    The file is **not** automatically downgraded — the caller decides whether
///    to overwrite.
///
/// 4. **Silent reset forbidden**: migrations must map every known field to its
///    equivalent in the new schema. Fields without a mapping must be preserved
///    at their previous value or explicitly dropped with user notification.
///
/// 5. **Version absent → legacy v0**: a file without a `schema_version` header
///    was written by a pre-versioning build. It is loaded with the v0 → v1
///    field mapping (all v1 fields that exist in v0 are read directly; new
///    fields get their default values). On next save the file is upgraded to
///    the current version.
pub struct CompatibilityPolicy;

// ── Storage topology ─────────────────────────────────────────────────────────

/// Documents where each store lives on disk and who owns each path.
///
/// This type carries no runtime behaviour; it exists as a single
/// authoritative reference for path ownership and I/O boundaries.
///
/// # UI preferences store
///
/// - **Path**: `%APPDATA%\NetRuleRouter\managed\ui-preferences.conf`
///   (falls back to `%LOCALAPPDATA%`, then `%TEMP%` on write failure).
/// - **Format**: line-oriented `key=value` text with a `# comment` header and
///   a `schema_version=N` field on the first non-comment line.
/// - **Owner**: `nrr-ui-support` crate (`UiPreferencesStore`).
/// - **Migration trigger**: automatic on first `load()` after upgrade.
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
/// - **Path**: service-owned path, e.g.
///   `%ProgramData%\NetRuleRouter\revisions.db` (exact path TBD).
/// - **Format**: SQLite database.
/// - **Owner**: `nrr-windows-service` (background service process only). No
///   other crate may write to this store.
/// - **Contents**: canonical policy revisions, active revision pointer,
///   last-known-good pointer, per-revision integrity metadata (hash + signature
///   chain), import provenance, and audit events.
/// - **Migration trigger**: explicit migration step on service startup when
///   the stored `schema_version` is less than `SERVICE_STORE_CURRENT_VERSION`.
///   The service must take an exclusive lock, snapshot the current store, run
///   the migration, verify integrity, then swap the active pointer.
/// - **Failure mode**: if migration fails, the service reverts to the
///   pre-migration snapshot and enters read-only safe mode. It does **not**
///   silently activate the partially migrated store.
pub struct StorageTopology;

// ── Migration triggers ────────────────────────────────────────────────────────

/// Documents which migrations run automatically and which require explicit
/// operator intervention.
///
/// This type carries no runtime behaviour.
///
/// # Automatic migrations (run silently on startup, safe to repeat)
///
/// - **UI preferences v0 → v1**: triggered on first `UiPreferencesStore::load()`
///   after upgrade. All v1 fields that exist in v0 are mapped directly; new
///   fields receive their defaults. The upgraded file is written on the next
///   `save()` call.
/// - **Legacy filename migration**: `ui-preferences-v1.conf` → `ui-preferences.conf`
///   (already implemented in `UiPreferencesStore::try_migrate_legacy_file`).
///
/// # Semi-automatic migrations (require passing all integrity checks)
///
/// - **Service revision store schema upgrade**: triggered on service startup
///   when `stored_schema_version < SERVICE_STORE_CURRENT_VERSION`. The service
///   automatically takes a snapshot, runs the migration, verifies integrity,
///   and switches the active pointer. No user interaction is required **unless**
///   the migration fails — see failure mode in [`StorageTopology`].
///
/// # Blocking migrations (require explicit administrator action)
///
/// - **Downgrade / unsupported version**: when the stored schema version is
///   greater than the service's `SERVICE_STORE_CURRENT_VERSION` (file from a
///   newer build), the service refuses to start and emits a clear error. The
///   administrator must either upgrade the service binary or restore a
///   compatible snapshot.
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
