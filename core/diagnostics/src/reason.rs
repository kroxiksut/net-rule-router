//! Stable, namespaced reason codes.
//!
//! # Design
//!
//! [`ReasonCode`] is a `&'static str` newtype.  The **string value is the
//! persisted representation** — it appears verbatim in NDJSON log files and
//! audit exports.  The Rust constant name is an internal alias that can be
//! freely renamed; the string must not change without a compatibility mapping.
//!
//! # Namespace convention
//!
//! `<category>.<event_kind>` — lowercase snake_case throughout, e.g.
//! `"decision.route_selected"`, `"cache.hit"`, `"service.started"`.
//!
//! # Compatibility policy
//!
//! Existing reason code strings must not be renamed.  If a concept is
//! superseded, add a new code and mark the old one `#[deprecated]`.
//! The mapping from old to new alias is documented in the code comment.
//!
//! # Localization
//!
//! Each [`ReasonCode`] maps to a localization key via [`ReasonCodeMeta`].
//! The UI uses this key to display a human-readable description in the
//! user's language.  Core code must not hardcode user-visible text.

use crate::taxonomy::{EventCategory, EventLevel};

// ── ReasonCode ────────────────────────────────────────────────────────────────

/// A stable, namespaced reason code for diagnostic and audit events.
///
/// The string value is persisted in NDJSON files; never change it without
/// an alias mapping.  Use the typed constants in the sub-modules below.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReasonCode(pub &'static str);

impl ReasonCode {
    /// The raw string representation, used for NDJSON serialisation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

// ── ReasonCodeMeta ────────────────────────────────────────────────────────────

/// Metadata associated with a reason code.
///
/// Used to derive the log level, route to the correct event stream, and
/// build the localization key for GUI display without hardcoding UI text.
#[derive(Clone, Copy, Debug)]
pub struct ReasonCodeMeta {
    pub code: ReasonCode,
    /// Default severity level for operational logging.
    pub default_level: EventLevel,
    /// The event category / stream this code belongs to.
    pub category: EventCategory,
    /// Localization key for GUI display.
    ///
    /// Convention: `diag.<category>.<kind>.summary`
    pub ui_key: &'static str,
    /// Whether this code always triggers a security audit event.
    pub audit_required: bool,
}

// ── Reason code namespaces ────────────────────────────────────────────────────

/// Reason codes for routing decision events (`decision.*`).
pub mod decision {
    use super::ReasonCode;

    /// A routing rule matched and a non-default route was selected.
    pub const ROUTE_SELECTED: ReasonCode = ReasonCode("decision.route_selected");
    /// No rule matched; the configured default route was used.
    pub const DEFAULT_ROUTE: ReasonCode = ReasonCode("decision.default_route");
    /// Secondary was unavailable but Fail-Open allowed default-route fallback.
    pub const FAIL_OPEN: ReasonCode = ReasonCode("decision.fail_open");
    /// Secondary was unavailable; traffic was blocked (Fail-Closed).
    pub const FAIL_CLOSED: ReasonCode = ReasonCode("decision.fail_closed");
    /// A browser stub interception attempt was detected.
    pub const BROWSER_STUB_ATTEMPT: ReasonCode = ReasonCode("decision.browser_stub_attempt");
    /// Required decision input (hostname, app context) was absent.
    pub const MISSING_INPUT: ReasonCode = ReasonCode("decision.missing_input");
    /// Two rules of equal specificity conflict; a deterministic winner was chosen.
    pub const RULE_CONFLICT: ReasonCode = ReasonCode("decision.rule_conflict");
}

/// Reason codes for FQDN/IP cache events (`cache.*`).
pub mod cache {
    use super::ReasonCode;

    /// A fresh, usable cache entry was found.
    pub const HIT: ReasonCode = ReasonCode("cache.hit");
    /// No cache entry exists for the queried hostname/IP.
    pub const MISS: ReasonCode = ReasonCode("cache.miss");
    /// A stale entry was found and used (within usable-stale threshold).
    pub const STALE_USABLE: ReasonCode = ReasonCode("cache.stale_usable");
    /// A stale entry exists but is too old to use; treated as miss.
    pub const STALE_NOT_USABLE: ReasonCode = ReasonCode("cache.stale_not_usable");
    /// A negative-cache entry was hit (hostname confirmed to have no usable IPs).
    pub const NEGATIVE_CACHED: ReasonCode = ReasonCode("cache.negative_cached");
    /// The DNS lookup timed out; result could not be cached.
    pub const LOOKUP_TIMEOUT: ReasonCode = ReasonCode("cache.lookup_timeout");
    /// The DNS lookup failed with a resolver error.
    pub const LOOKUP_FAILED: ReasonCode = ReasonCode("cache.lookup_failed");
    /// An IP address maps to a different hostname than expected (conflict).
    pub const CONFLICTING_MAPPING: ReasonCode = ReasonCode("cache.conflicting_mapping");
    /// A native IPv6 address was presented; IPv6 ExactIp is Pro-only in Free.
    pub const UNSUPPORTED_ADDRESS_FAMILY: ReasonCode =
        ReasonCode("cache.unsupported_address_family");
}

/// Reason codes for route apply/enforcement events (`apply.*`).
pub mod apply {
    use super::ReasonCode;

    /// A route apply operation started.
    pub const STARTED: ReasonCode = ReasonCode("apply.started");
    /// A route apply operation completed successfully.
    pub const COMPLETED: ReasonCode = ReasonCode("apply.completed");
    /// A route apply operation failed.
    pub const FAILED: ReasonCode = ReasonCode("apply.failed");
    /// Post-apply verification of the routing table failed.
    pub const VERIFICATION_FAILED: ReasonCode = ReasonCode("apply.verification_failed");
    /// A rollback of a failed apply started.
    pub const ROLLBACK_STARTED: ReasonCode = ReasonCode("apply.rollback_started");
    /// A rollback completed successfully.
    pub const ROLLBACK_COMPLETED: ReasonCode = ReasonCode("apply.rollback_completed");
    /// A local block rule was installed (Fail-Closed enforcement).
    pub const BLOCK_INSTALLED: ReasonCode = ReasonCode("apply.block_installed");
    /// A local block rule was removed.
    pub const BLOCK_REMOVED: ReasonCode = ReasonCode("apply.block_removed");
}

/// Reason codes for import operations (`import.*`).
pub mod import {
    use super::ReasonCode;

    /// A configuration artifact was imported and a review candidate created.
    pub const CANDIDATE_CREATED: ReasonCode = ReasonCode("import.candidate_created");
    /// An imported artifact was identical to the active revision; no candidate.
    pub const IDENTICAL_TO_ACTIVE: ReasonCode = ReasonCode("import.identical_to_active");
    /// The import artifact failed validation.
    pub const VALIDATION_FAILED: ReasonCode = ReasonCode("import.validation_failed");
}

/// Reason codes for the review and approval flow (`review.*`).
pub mod review {
    use super::ReasonCode;

    /// A pending revision was approved and activated.
    pub const APPROVED: ReasonCode = ReasonCode("review.approved");
    /// A pending revision was rejected.
    pub const REJECTED: ReasonCode = ReasonCode("review.rejected");
    /// A revision was activated without explicit review (e.g., auto-approve).
    pub const AUTO_ACTIVATED: ReasonCode = ReasonCode("review.auto_activated");
}

/// Reason codes for integrity and recovery events (`integrity.*`).
pub mod integrity {
    use super::ReasonCode;

    /// The FQDN/IP cache was found corrupt but is rebuildable; rebuild started.
    pub const CACHE_CORRUPT_REBUILDABLE: ReasonCode =
        ReasonCode("integrity.cache_corrupt_rebuildable");
    /// The active policy revision failed integrity verification.
    pub const POLICY_INTEGRITY_FAILURE: ReasonCode =
        ReasonCode("integrity.policy_integrity_failure");
    /// A mismatch was detected in the audit NDJSON hash chain.
    pub const AUDIT_CHAIN_MISMATCH: ReasonCode = ReasonCode("integrity.audit_chain_mismatch");
    /// The audit hash chain warning threshold was reached.
    pub const AUDIT_CHAIN_WARNING: ReasonCode = ReasonCode("integrity.audit_chain_warning");
    /// An unsupported schema version was detected in a storage file.
    pub const UNSUPPORTED_SCHEMA: ReasonCode = ReasonCode("integrity.unsupported_schema");
    /// A migration was interrupted; service entered restore/recovery mode.
    pub const MIGRATION_RESTORE: ReasonCode = ReasonCode("integrity.migration_restore");
    /// A `revisions` row's stored `row_hmac` did not
    /// match a fresh recomputation at service load (external tampering
    /// or key rotation without re-signing).
    pub const DB_ROW_HMAC_MISMATCH: ReasonCode = ReasonCode("integrity.db_row_hmac_mismatch");
    /// The DB-MAC key file was absent at startup with
    /// a non-empty `revisions` table; a fresh key was generated and
    /// mutations are blocked pending user acknowledgement.
    pub const KEY_RESET_WITH_EXISTING_DATA: ReasonCode =
        ReasonCode("integrity.key_reset_with_existing_data");
    /// A revision that was active (or about to become active) failed the
    /// row-signature or Free rule-cap check — written into the database
    /// outside the app. It was not applied; the service rolled back to
    /// the last trusted revision.
    pub const UNTRUSTED_REVISION_REJECTED: ReasonCode =
        ReasonCode("integrity.untrusted_revision_rejected");
}

/// Reason codes for Windows Service lifecycle events (`service.*`).
pub mod service {
    use super::ReasonCode;

    /// The Windows Service started successfully.
    pub const STARTED: ReasonCode = ReasonCode("service.started");
    /// The Windows Service stopped cleanly.
    pub const STOPPED: ReasonCode = ReasonCode("service.stopped");
    /// The service entered a degraded operational mode.
    pub const DEGRADED_MODE: ReasonCode = ReasonCode("service.degraded_mode");
    /// A service-owned storage file became unavailable.
    pub const STORAGE_UNAVAILABLE: ReasonCode = ReasonCode("service.storage_unavailable");
    /// The IPC endpoint became unavailable.
    pub const IPC_UNAVAILABLE: ReasonCode = ReasonCode("service.ipc_unavailable");
    /// The aggregate service health status changed.
    pub const HEALTH_CHANGED: ReasonCode = ReasonCode("service.health_changed");
}

/// Reason codes for diagnostics subsystem events (`diagnostics.*`).
pub mod diagnostics {
    use super::ReasonCode;

    /// Explicit diagnostic mode was enabled by the user.
    pub const MODE_ENABLED: ReasonCode = ReasonCode("diagnostics.mode_enabled");
    /// Explicit diagnostic mode was disabled or expired.
    pub const MODE_DISABLED: ReasonCode = ReasonCode("diagnostics.mode_disabled");
    /// A diagnostic archive export was requested.
    pub const ARCHIVE_EXPORT_STARTED: ReasonCode = ReasonCode("diagnostics.archive_export_started");
    /// A diagnostic archive export completed.
    pub const ARCHIVE_EXPORT_COMPLETED: ReasonCode =
        ReasonCode("diagnostics.archive_export_completed");
    /// Operational logs were cleared by user action.
    pub const LOGS_CLEARED: ReasonCode = ReasonCode("diagnostics.logs_cleared");
    /// The log rotation triggered.
    pub const LOG_ROTATED: ReasonCode = ReasonCode("diagnostics.log_rotated");
}

// ── Metadata mapping ──────────────────────────────────────────────────────────

/// Returns metadata for a known reason code, or `None` if the code is not
/// in the canonical registry.
///
/// This is the authoritative mapping: reason code → level, category,
/// UI localization key, and audit requirement.  Keep this in sync with
/// `locales/en.json` and `locales/ru.json`.
#[must_use]
pub fn reason_code_meta(code: ReasonCode) -> Option<ReasonCodeMeta> {
    use EventCategory as Cat;
    use EventLevel as Lvl;

    let (default_level, category, ui_key, audit_required) = match code.0 {
        // decision.*
        "decision.route_selected" => (
            Lvl::Info,
            Cat::Decision,
            "diag.decision.route_selected.summary",
            false,
        ),
        "decision.default_route" => (
            Lvl::Info,
            Cat::Decision,
            "diag.decision.default_route.summary",
            false,
        ),
        "decision.fail_open" => (
            Lvl::Warn,
            Cat::Decision,
            "diag.decision.fail_open.summary",
            false,
        ),
        "decision.fail_closed" => (
            Lvl::Warn,
            Cat::Decision,
            "diag.decision.fail_closed.summary",
            false,
        ),
        "decision.browser_stub_attempt" => (
            Lvl::Info,
            Cat::Decision,
            "diag.decision.browser_stub_attempt.summary",
            false,
        ),
        "decision.missing_input" => (
            Lvl::Warn,
            Cat::Decision,
            "diag.decision.missing_input.summary",
            false,
        ),
        "decision.rule_conflict" => (
            Lvl::Warn,
            Cat::Decision,
            "diag.decision.rule_conflict.summary",
            false,
        ),
        // cache.*
        "cache.hit" => (Lvl::Trace, Cat::Cache, "diag.cache.hit.summary", false),
        "cache.miss" => (Lvl::Debug, Cat::Cache, "diag.cache.miss.summary", false),
        "cache.stale_usable" => (
            Lvl::Debug,
            Cat::Cache,
            "diag.cache.stale_usable.summary",
            false,
        ),
        "cache.stale_not_usable" => (
            Lvl::Info,
            Cat::Cache,
            "diag.cache.stale_not_usable.summary",
            false,
        ),
        "cache.negative_cached" => (
            Lvl::Debug,
            Cat::Cache,
            "diag.cache.negative_cached.summary",
            false,
        ),
        "cache.lookup_timeout" => (
            Lvl::Warn,
            Cat::Cache,
            "diag.cache.lookup_timeout.summary",
            false,
        ),
        "cache.lookup_failed" => (
            Lvl::Warn,
            Cat::Cache,
            "diag.cache.lookup_failed.summary",
            false,
        ),
        "cache.conflicting_mapping" => (
            Lvl::Warn,
            Cat::Cache,
            "diag.cache.conflicting_mapping.summary",
            false,
        ),
        "cache.unsupported_address_family" => (
            Lvl::Info,
            Cat::Cache,
            "diag.cache.unsupported_address_family.summary",
            false,
        ),
        // apply.*
        "apply.started" => (Lvl::Info, Cat::Apply, "diag.apply.started.summary", false),
        "apply.completed" => (Lvl::Info, Cat::Apply, "diag.apply.completed.summary", false),
        "apply.failed" => (Lvl::Error, Cat::Apply, "diag.apply.failed.summary", false),
        "apply.verification_failed" => (
            Lvl::Error,
            Cat::Apply,
            "diag.apply.verification_failed.summary",
            false,
        ),
        "apply.rollback_started" => (
            Lvl::Warn,
            Cat::Apply,
            "diag.apply.rollback_started.summary",
            false,
        ),
        "apply.rollback_completed" => (
            Lvl::Info,
            Cat::Apply,
            "diag.apply.rollback_completed.summary",
            false,
        ),
        "apply.block_installed" => (
            Lvl::Info,
            Cat::Apply,
            "diag.apply.block_installed.summary",
            false,
        ),
        "apply.block_removed" => (
            Lvl::Info,
            Cat::Apply,
            "diag.apply.block_removed.summary",
            false,
        ),
        // import.*
        "import.candidate_created" => (
            Lvl::Info,
            Cat::Import,
            "diag.import.candidate_created.summary",
            true,
        ),
        "import.identical_to_active" => (
            Lvl::Info,
            Cat::Import,
            "diag.import.identical_to_active.summary",
            false,
        ),
        "import.validation_failed" => (
            Lvl::Warn,
            Cat::Import,
            "diag.import.validation_failed.summary",
            false,
        ),
        // review.*
        "review.approved" => (Lvl::Info, Cat::Review, "diag.review.approved.summary", true),
        "review.rejected" => (Lvl::Info, Cat::Review, "diag.review.rejected.summary", true),
        "review.auto_activated" => (
            Lvl::Info,
            Cat::Review,
            "diag.review.auto_activated.summary",
            true,
        ),
        // integrity.*
        "integrity.cache_corrupt_rebuildable" => (
            Lvl::Warn,
            Cat::Integrity,
            "diag.integrity.cache_corrupt_rebuildable.summary",
            false,
        ),
        "integrity.policy_integrity_failure" => (
            Lvl::Error,
            Cat::Integrity,
            "diag.integrity.policy_integrity_failure.summary",
            true,
        ),
        "integrity.audit_chain_mismatch" => (
            Lvl::Error,
            Cat::Security,
            "diag.integrity.audit_chain_mismatch.summary",
            true,
        ),
        "integrity.audit_chain_warning" => (
            Lvl::Warn,
            Cat::Security,
            "diag.integrity.audit_chain_warning.summary",
            true,
        ),
        "integrity.unsupported_schema" => (
            Lvl::Error,
            Cat::Integrity,
            "diag.integrity.unsupported_schema.summary",
            false,
        ),
        "integrity.migration_restore" => (
            Lvl::Warn,
            Cat::Integrity,
            "diag.integrity.migration_restore.summary",
            true,
        ),
        "integrity.db_row_hmac_mismatch" => (
            Lvl::Error,
            Cat::Security,
            "diag.integrity.db_row_hmac_mismatch.summary",
            true,
        ),
        "integrity.key_reset_with_existing_data" => (
            Lvl::Error,
            Cat::Security,
            "diag.integrity.key_reset_with_existing_data.summary",
            true,
        ),
        "integrity.untrusted_revision_rejected" => (
            Lvl::Warn,
            Cat::Security,
            "diag.integrity.untrusted_revision_rejected.summary",
            true,
        ),
        // service.*
        "service.started" => (
            Lvl::Info,
            Cat::Service,
            "diag.service.started.summary",
            false,
        ),
        "service.stopped" => (
            Lvl::Info,
            Cat::Service,
            "diag.service.stopped.summary",
            false,
        ),
        "service.degraded_mode" => (
            Lvl::Warn,
            Cat::Service,
            "diag.service.degraded_mode.summary",
            false,
        ),
        "service.storage_unavailable" => (
            Lvl::Error,
            Cat::Service,
            "diag.service.storage_unavailable.summary",
            false,
        ),
        "service.ipc_unavailable" => (
            Lvl::Error,
            Cat::Service,
            "diag.service.ipc_unavailable.summary",
            false,
        ),
        "service.health_changed" => (
            Lvl::Info,
            Cat::Service,
            "diag.service.health_changed.summary",
            false,
        ),
        // diagnostics.*
        "diagnostics.mode_enabled" => (
            Lvl::Info,
            Cat::Diagnostics,
            "diag.diagnostics.mode_enabled.summary",
            false,
        ),
        "diagnostics.mode_disabled" => (
            Lvl::Info,
            Cat::Diagnostics,
            "diag.diagnostics.mode_disabled.summary",
            false,
        ),
        "diagnostics.archive_export_started" => (
            Lvl::Info,
            Cat::Diagnostics,
            "diag.diagnostics.archive_export_started.summary",
            false,
        ),
        "diagnostics.archive_export_completed" => (
            Lvl::Info,
            Cat::Diagnostics,
            "diag.diagnostics.archive_export_completed.summary",
            false,
        ),
        "diagnostics.logs_cleared" => (
            Lvl::Info,
            Cat::Diagnostics,
            "diag.diagnostics.logs_cleared.summary",
            false,
        ),
        "diagnostics.log_rotated" => (
            Lvl::Debug,
            Cat::Diagnostics,
            "diag.diagnostics.log_rotated.summary",
            false,
        ),
        _ => return None,
    };
    Some(ReasonCodeMeta {
        code,
        default_level,
        category,
        ui_key,
        audit_required,
    })
}

/// All canonical reason codes, in namespace order.
///
/// Used for generating documentation and verifying that every exported
/// constant is registered in [`reason_code_meta`].
pub const ALL_REASON_CODES: &[ReasonCode] = &[
    decision::ROUTE_SELECTED,
    decision::DEFAULT_ROUTE,
    decision::FAIL_OPEN,
    decision::FAIL_CLOSED,
    decision::BROWSER_STUB_ATTEMPT,
    decision::MISSING_INPUT,
    decision::RULE_CONFLICT,
    cache::HIT,
    cache::MISS,
    cache::STALE_USABLE,
    cache::STALE_NOT_USABLE,
    cache::NEGATIVE_CACHED,
    cache::LOOKUP_TIMEOUT,
    cache::LOOKUP_FAILED,
    cache::CONFLICTING_MAPPING,
    cache::UNSUPPORTED_ADDRESS_FAMILY,
    apply::STARTED,
    apply::COMPLETED,
    apply::FAILED,
    apply::VERIFICATION_FAILED,
    apply::ROLLBACK_STARTED,
    apply::ROLLBACK_COMPLETED,
    apply::BLOCK_INSTALLED,
    apply::BLOCK_REMOVED,
    import::CANDIDATE_CREATED,
    import::IDENTICAL_TO_ACTIVE,
    import::VALIDATION_FAILED,
    review::APPROVED,
    review::REJECTED,
    review::AUTO_ACTIVATED,
    integrity::CACHE_CORRUPT_REBUILDABLE,
    integrity::POLICY_INTEGRITY_FAILURE,
    integrity::AUDIT_CHAIN_MISMATCH,
    integrity::AUDIT_CHAIN_WARNING,
    integrity::UNSUPPORTED_SCHEMA,
    integrity::MIGRATION_RESTORE,
    integrity::DB_ROW_HMAC_MISMATCH,
    integrity::KEY_RESET_WITH_EXISTING_DATA,
    integrity::UNTRUSTED_REVISION_REJECTED,
    service::STARTED,
    service::STOPPED,
    service::DEGRADED_MODE,
    service::STORAGE_UNAVAILABLE,
    service::IPC_UNAVAILABLE,
    service::HEALTH_CHANGED,
    diagnostics::MODE_ENABLED,
    diagnostics::MODE_DISABLED,
    diagnostics::ARCHIVE_EXPORT_STARTED,
    diagnostics::ARCHIVE_EXPORT_COMPLETED,
    diagnostics::LOGS_CLEARED,
    diagnostics::LOG_ROTATED,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_code_display_equals_as_str() {
        assert_eq!(
            decision::ROUTE_SELECTED.to_string(),
            decision::ROUTE_SELECTED.as_str()
        );
    }

    #[test]
    fn all_reason_codes_have_correct_namespace_prefix() {
        for code in ALL_REASON_CODES {
            let s = code.as_str();
            assert!(s.contains('.'), "code must be namespaced: {s}");
            let ns = s.split('.').next().expect("has dot");
            assert!(
                matches!(
                    ns,
                    "decision"
                        | "cache"
                        | "apply"
                        | "import"
                        | "review"
                        | "integrity"
                        | "service"
                        | "diagnostics"
                ),
                "unknown namespace '{ns}' in '{s}'"
            );
        }
    }

    #[test]
    fn all_reason_codes_have_snake_case_kind() {
        for code in ALL_REASON_CODES {
            let s = code.as_str();
            let kind = s.split_once('.').map(|x| x.1).expect("has kind after dot");
            assert!(
                kind.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "kind '{kind}' in '{s}' must be lowercase snake_case"
            );
        }
    }

    #[test]
    fn all_reason_codes_are_registered_in_meta() {
        for code in ALL_REASON_CODES {
            assert!(
                reason_code_meta(*code).is_some(),
                "reason code '{}' is not registered in reason_code_meta()",
                code.as_str()
            );
        }
    }

    #[test]
    fn meta_category_matches_namespace() {
        for code in ALL_REASON_CODES {
            let meta = reason_code_meta(*code).expect("registered");
            let ns = code.as_str().split('.').next().expect("has ns");
            let expected_cat = match ns {
                "decision" => EventCategory::Decision,
                "cache" => EventCategory::Cache,
                "apply" => EventCategory::Apply,
                "import" => EventCategory::Import,
                "review" => EventCategory::Review,
                "integrity" => EventCategory::Integrity,
                "service" => EventCategory::Service,
                "diagnostics" => EventCategory::Diagnostics,
                other => panic!("unmapped ns '{other}'"),
            };
            // Integrity codes may route to Security (tamper events) — allow that.
            let cat_ok = meta.category == expected_cat
                || (ns == "integrity" && meta.category == EventCategory::Security);
            assert!(
                cat_ok,
                "category mismatch for '{}': expected {:?}, got {:?}",
                code.as_str(),
                expected_cat,
                meta.category
            );
        }
    }

    #[test]
    fn meta_ui_key_has_diag_prefix() {
        for code in ALL_REASON_CODES {
            let meta = reason_code_meta(*code).expect("registered");
            assert!(
                meta.ui_key.starts_with("diag."),
                "ui_key '{}' for '{}' must start with 'diag.'",
                meta.ui_key,
                code.as_str()
            );
        }
    }

    #[test]
    fn audit_required_for_security_significant_codes() {
        let audit_codes = [
            import::CANDIDATE_CREATED,
            review::APPROVED,
            review::REJECTED,
            review::AUTO_ACTIVATED,
            integrity::POLICY_INTEGRITY_FAILURE,
            integrity::AUDIT_CHAIN_MISMATCH,
            integrity::AUDIT_CHAIN_WARNING,
            integrity::MIGRATION_RESTORE,
        ];
        for code in audit_codes {
            let meta = reason_code_meta(code).expect("registered");
            assert!(
                meta.audit_required,
                "expected audit_required=true for '{}'",
                code.as_str()
            );
        }
    }

    #[test]
    fn no_duplicate_reason_code_strings() {
        let mut seen = std::collections::HashSet::new();
        for code in ALL_REASON_CODES {
            let inserted = seen.insert(code.as_str());
            assert!(inserted, "duplicate reason code: '{}'", code.as_str());
        }
    }

    #[test]
    fn stable_string_values_for_key_codes() {
        // These strings are persisted in NDJSON files — must never change.
        assert_eq!(decision::ROUTE_SELECTED.as_str(), "decision.route_selected");
        assert_eq!(decision::FAIL_CLOSED.as_str(), "decision.fail_closed");
        assert_eq!(cache::HIT.as_str(), "cache.hit");
        assert_eq!(cache::MISS.as_str(), "cache.miss");
        assert_eq!(apply::COMPLETED.as_str(), "apply.completed");
        assert_eq!(
            integrity::AUDIT_CHAIN_MISMATCH.as_str(),
            "integrity.audit_chain_mismatch"
        );
        assert_eq!(service::STARTED.as_str(), "service.started");
        assert_eq!(
            diagnostics::MODE_ENABLED.as_str(),
            "diagnostics.mode_enabled"
        );
    }
}
