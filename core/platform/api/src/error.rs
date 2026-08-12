//! Platform error type and error classification.
//!
//! Neutral shared vocabulary: the error type every platform backend returns and
//! the taxonomy the apply orchestrator reacts to. Lives in `nrr-platform-api` so
//! `service-runtime` and each per-OS backend (`windows` / `linux` / `macos`)
//! agree on one error shape. The `Win32`-flavoured variant + code classification
//! are how the WINDOWS backend populates it; other backends fill the same
//! variants from their own errno/HRESULT space (or add classification behind the
//! backend later). No OS-specific dependencies — just `std`.

use std::fmt;

/// Win32 / WFP result codes — the ONE table every module quotes from.
///
/// Values are copied verbatim from Microsoft's `winerror.h` ("WFP error
/// codes", `0x80320001`–`0x80320039`) and the classic Win32 range. HRESULT
/// layout: high bit = failure, `0x032` = FACILITY_FWP (Windows Filtering
/// Platform), low word = the specific error.
///
/// HARD RULE: never re-declare one of these numbers
/// locally. `wfp_sublayer.rs` once carried its own
/// `FWP_E_ALREADY_EXISTS = 0x8032_0001` — a correct NAME on the WRONG number
/// (that value is [`FWP_E_CALLOUT_NOT_FOUND`]) — which made `ensure_sublayer`
/// treat the real "already exists" (`0x…09`) as fatal. Combined with the
/// duplicate-add-is-success classification below, every filter add after the
/// sub-layer existed became a silent phantom "success": counted as installed,
/// never in WFP, no enforcement at all. The compiler cannot check a constant's
/// name against Microsoft's table — centralizing the numbers here is the only
/// structural defence.
pub mod win32_codes {
    /// `ERROR_ACCESS_DENIED` (5) — missing privilege; not recoverable inline.
    pub const ERROR_ACCESS_DENIED: u32 = 0x5;
    /// `ERROR_NOT_FOUND` (1168) — generic object-not-found → idempotent delete.
    pub const ERROR_NOT_FOUND: u32 = 0x490;
    /// `ERROR_DUPLICATE_TAG` (1500) — duplicate object on add.
    pub const ERROR_DUPLICATE_TAG: u32 = 0x5DC;
    /// `ERROR_OBJECT_ALREADY_EXISTS` (5010) — `CreateIpForwardEntry2` on a
    /// duplicate route.
    pub const ERROR_OBJECT_ALREADY_EXISTS: u32 = 0x1392;
    /// `ERROR_TRANSACTION_IN_PROGRESS` (6800) — retry after the other
    /// transaction settles.
    pub const ERROR_TRANSACTION_IN_PROGRESS: u32 = 0x1A90;

    /// `FWP_E_CALLOUT_NOT_FOUND` — NOT "already exists"! Kept in the table
    /// precisely because its number was once mistaken for
    /// [`FWP_E_ALREADY_EXISTS`] (the phantom-filter root cause).
    pub const FWP_E_CALLOUT_NOT_FOUND: u32 = 0x8032_0001;
    /// `FWP_E_CONDITION_NOT_FOUND` — a filter condition the layer does not
    /// expose (e.g. an ALE-only condition on a packet layer) or a degenerate
    /// condition value. Per-filter, not fatal to the batch.
    pub const FWP_E_CONDITION_NOT_FOUND: u32 = 0x8032_0002;
    /// `FWP_E_FILTER_NOT_FOUND` — delete of an absent filter → idempotent.
    pub const FWP_E_FILTER_NOT_FOUND: u32 = 0x8032_0003;
    /// `FWP_E_SUBLAYER_NOT_FOUND` — filter references a sub-layer missing
    /// from the engine.
    pub const FWP_E_SUBLAYER_NOT_FOUND: u32 = 0x8032_0007;
    /// `FWP_E_ALREADY_EXISTS` — the object (filter / sub-layer / provider)
    /// is already in the store. THE canonical duplicate-add result.
    pub const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;
    /// `FWP_E_DYNAMIC_SESSION_IN_PROGRESS` — operation not allowed from a
    /// dynamic session. This NUMBER was once misclassified under the name
    /// `FWP_E_TRANSACTION_IN_PROGRESS`, so the real transaction-collision code
    /// below was classified Fatal instead of Retryable. Kept Retryable to
    /// preserve the correct behaviour.
    pub const FWP_E_DYNAMIC_SESSION_IN_PROGRESS: u32 = 0x8032_000B;
    /// `FWP_E_TXN_IN_PROGRESS` — another WFP transaction is already open on
    /// this session (`FwpmTransactionBegin0` collision) → retryable.
    pub const FWP_E_TXN_IN_PROGRESS: u32 = 0x8032_000E;
}

/// Error returned by all platform-backed operations.
#[derive(Debug)]
pub enum PlatformError {
    /// Operation is defined but not yet implemented (skeleton phase).
    /// The `block` field indicates which block will implement it.
    NotYetImplemented { block: &'static str },
    /// Win32 API call failed. `code` is the raw Win32 error code.
    Win32 {
        operation: &'static str,
        code: u32,
        message: String,
    },
    /// Insufficient privileges to perform the operation.
    AccessDenied { operation: &'static str },
    /// Transient failure; a retry after a short delay may succeed.
    Transient {
        operation: &'static str,
        detail: String,
    },
    /// Persistent state corruption; manual recovery required.
    StateCorrupted { detail: String },
    /// Feature not supported (e.g. IPv6 is out-of-scope for this product).
    NotSupported { reason: &'static str },
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotYetImplemented { block } => {
                write!(f, "not yet implemented (planned in {block})")
            }
            Self::Win32 {
                operation,
                code,
                message,
            } => {
                write!(f, "Win32 error in {operation}: 0x{code:08X} — {message}")
            }
            Self::AccessDenied { operation } => {
                write!(
                    f,
                    "access denied for {operation}; check service privilege level"
                )
            }
            Self::Transient { operation, detail } => {
                write!(f, "transient error in {operation}: {detail}")
            }
            Self::StateCorrupted { detail } => {
                write!(f, "platform state corrupted: {detail}")
            }
            Self::NotSupported { reason } => {
                write!(f, "not supported: {reason}")
            }
        }
    }
}

impl std::error::Error for PlatformError {}

/// How the apply layer should handle a `PlatformError`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorClass {
    /// Short delay + retry is safe (e.g. `ERROR_FWP_TRANSACTION_IN_PROGRESS`).
    Retryable,
    /// Abort the current operation; rollback if mid-apply.
    Fatal,
    /// Filter/route already in the desired state; treat as success.
    Idempotent,
    /// A conflicting object exists with a different configuration.
    Conflict,
    /// Need elevated privileges; no automatic recovery.
    PrivilegeRequired,
}

impl PlatformError {
    /// True when this error means "the app rule's executable is not installed
    /// on this host" — `FwpmGetAppIdFromFileName0` returning
    /// `ERROR_FILE_NOT_FOUND` (2) or `ERROR_PATH_NOT_FOUND` (3). A block/route
    /// rule for an absent application is a no-op, so the apply layer SKIPS such
    /// a filter instead of failing the whole transaction — one uninstalled app
    /// in a shared preset must not roll back the user's entire policy (which
    /// would leave them with NO active revision and NO enforcement at all).
    pub fn is_app_not_installed(&self) -> bool {
        matches!(
            self,
            Self::Win32 {
                operation: "FwpmGetAppIdFromFileName0",
                code: 2 | 3,
                ..
            }
        )
    }

    /// True when this error means a **single filter cannot be
    /// materialized**, while the WFP engine and the surrounding
    /// transaction remain healthy. Such a filter is a candidate for the
    /// best-effort apply policy: skip it (with a recorded diagnostic) and
    /// keep the rest of the revision, instead of rolling back everything.
    ///
    /// Covers:
    /// - **any** failure to resolve an app rule's path via
    ///   `FwpmGetAppIdFromFileName0` — the executable is absent
    ///   (`ERROR_FILE/PATH_NOT_FOUND` 2/3), the pattern is not a valid path
    ///   such as a glob `disko*.exe` (`ERROR_INVALID_NAME` 123 — globs are a
    ///   Pro feature, not materializable as a single ALE_APP_ID filter), the
    ///   blob came back degenerate/empty (`ERROR_INVALID_DATA` 13), or the
    ///   file is unreadable. Failing to compute an app-id means this one app
    ///   filter cannot be built on this host — a per-rule condition, never a
    ///   system-wide failure;
    /// - `FwpmFilterAdd0` rejected a degenerate filter condition with
    ///   `FWP_E_CONDITION_NOT_FOUND` (0x80320002) — a malformed condition
    ///   value that the kernel will not register.
    ///
    /// Catastrophic errors (access denied / transaction / engine failures on
    /// the *add* path, unknown fatal codes) are deliberately NOT included:
    /// those mean the whole apply is doomed and must abort regardless of
    /// policy.
    pub fn is_unmaterializable_filter(&self) -> bool {
        matches!(
            self,
            // Any app-id resolution failure → this app filter is not
            // buildable on this host. Listing every Win32 code is brittle
            // (we hit 2/3, then 13, then 123 across test runs); the operation
            // itself is the reliable discriminator.
            Self::Win32 {
                operation: "FwpmGetAppIdFromFileName0",
                ..
            } | Self::Win32 {
                operation: "FwpmFilterAdd0",
                code: win32_codes::FWP_E_CONDITION_NOT_FOUND,
                ..
            }
        )
    }

    /// True when the error came from the **sub-layer registration step**
    /// (`FwpmSubLayerAdd0`) that runs before every filter add — as opposed to
    /// the filter add itself.
    ///
    /// A failure at this stage means NO filter in the
    /// batch can install, so the apply layer must ABORT. It must never be
    /// folded into the "duplicate filter → idempotent success" handling: the
    /// Win32 code alone (`FWP_E_ALREADY_EXISTS` → [`ErrorClass::Conflict`])
    /// cannot distinguish "this filter is already installed" (success) from
    /// "the sub-layer step failed" (nothing was installed), and conflating
    /// them silently produced phantom filters — counted as installed, absent
    /// from WFP, zero enforcement.
    ///
    /// The operation string is the Windows backend's `FwpmSubLayerAdd0`; the
    /// Linux backend has no pre-add registration step today, and a future one
    /// must add its operation name here.
    pub fn is_sublayer_registration_failure(&self) -> bool {
        matches!(
            self,
            Self::Win32 {
                operation: "FwpmSubLayerAdd0",
                ..
            }
        )
    }

    /// Classify the error so the apply orchestrator knows how to react.
    pub fn classify(&self) -> ErrorClass {
        match self {
            Self::NotYetImplemented { .. } => ErrorClass::Fatal,
            Self::Win32 { code, .. } => classify_win32_error(*code),
            Self::AccessDenied { .. } => ErrorClass::PrivilegeRequired,
            Self::Transient { .. } => ErrorClass::Retryable,
            Self::StateCorrupted { .. } => ErrorClass::Fatal,
            Self::NotSupported { .. } => ErrorClass::Fatal,
        }
    }
}

/// Map well-known Win32 error codes to their classification.
///
/// Every number comes from the [`win32_codes`] table — never quote a raw
/// hex code here (see the table's HARD RULE).
fn classify_win32_error(code: u32) -> ErrorClass {
    use win32_codes::{
        ERROR_ACCESS_DENIED, ERROR_DUPLICATE_TAG, ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS,
        ERROR_TRANSACTION_IN_PROGRESS, FWP_E_ALREADY_EXISTS, FWP_E_DYNAMIC_SESSION_IN_PROGRESS,
        FWP_E_FILTER_NOT_FOUND, FWP_E_TXN_IN_PROGRESS,
    };
    match code {
        // A delete that reports the object is already gone is success for an
        // idempotent reconcile. `FwpmFilterDeleteByKey0` returns
        // `FWP_E_FILTER_NOT_FOUND` (0x80320003) — NOT the generic
        // `ERROR_NOT_FOUND` (0x490) — so it must be listed explicitly, or a
        // remove-then-install recompile aborts the whole revision when a
        // previously-recorded filter id is already absent (observed in the
        // field: "remove for SID: FwpmFilterDeleteByKey0 0x80320003").
        ERROR_NOT_FOUND | FWP_E_FILTER_NOT_FOUND => ErrorClass::Idempotent,
        ERROR_DUPLICATE_TAG | ERROR_OBJECT_ALREADY_EXISTS | FWP_E_ALREADY_EXISTS => {
            ErrorClass::Conflict
        }
        ERROR_ACCESS_DENIED => ErrorClass::PrivilegeRequired,
        ERROR_TRANSACTION_IN_PROGRESS
        | FWP_E_TXN_IN_PROGRESS
        | FWP_E_DYNAMIC_SESSION_IN_PROGRESS => ErrorClass::Retryable,
        _ => ErrorClass::Fatal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win32(operation: &'static str, code: u32) -> PlatformError {
        PlatformError::Win32 {
            operation,
            code,
            message: format!("Win32 error 0x{code:08X}"),
        }
    }

    #[test]
    fn unmaterializable_covers_app_not_installed() {
        assert!(win32("FwpmGetAppIdFromFileName0", 2).is_unmaterializable_filter());
        assert!(win32("FwpmGetAppIdFromFileName0", 3).is_unmaterializable_filter());
    }

    #[test]
    fn unmaterializable_covers_empty_app_id_blob() {
        // ERROR_INVALID_DATA (13) on the app-id op = degenerate blob.
        assert!(win32("FwpmGetAppIdFromFileName0", 13).is_unmaterializable_filter());
    }

    #[test]
    fn unmaterializable_covers_invalid_app_path_glob() {
        // ERROR_INVALID_NAME (123) — e.g. a glob pattern `disko*.exe` that
        // FwpmGetAppIdFromFileName0 cannot resolve to a concrete path.
        assert!(win32("FwpmGetAppIdFromFileName0", 123).is_unmaterializable_filter());
        // And any other app-id failure code is treated the same way.
        assert!(win32("FwpmGetAppIdFromFileName0", 5).is_unmaterializable_filter());
    }

    #[test]
    fn unmaterializable_covers_condition_not_found_on_add() {
        // FWP_E_CONDITION_NOT_FOUND from the filter-add itself.
        assert!(win32("FwpmFilterAdd0", 0x8032_0002).is_unmaterializable_filter());
    }

    #[test]
    fn unmaterializable_excludes_catastrophic_errors() {
        // Access denied / unknown fatal must NOT be skippable — those mean
        // the whole apply is doomed.
        assert!(!PlatformError::AccessDenied {
            operation: "FwpmFilterAdd0"
        }
        .is_unmaterializable_filter());
        assert!(!win32("FwpmFilterAdd0", 0x5).is_unmaterializable_filter());
        // CONDITION_NOT_FOUND on a *different* op is not our skip case.
        assert!(!win32("FwpmTransactionCommit0", 0x8032_0002).is_unmaterializable_filter());
    }

    #[test]
    fn already_exists_classifies_as_conflict_not_fatal() {
        assert_eq!(
            win32("FwpmFilterAdd0", 0x8032_0009).classify(),
            ErrorClass::Conflict
        );
    }

    #[test]
    fn duplicate_route_add_classifies_as_conflict_not_fatal() {
        // CreateIpForwardEntry2 on a route whose key already exists returns
        // ERROR_OBJECT_ALREADY_EXISTS (0x1392 = 5010). Must be Conflict (which
        // AddRoute treats as success), not Fatal — otherwise the mode-B overlay
        // colliding with a redirect-gateway VPN's own /1 would fail the whole
        // route reconcile.
        assert_eq!(
            win32("CreateIpForwardEntry2", 0x1392).classify(),
            ErrorClass::Conflict
        );
    }

    #[test]
    fn filter_not_found_on_delete_is_idempotent_not_fatal() {
        // FWP_E_FILTER_NOT_FOUND (0x80320003) from FwpmFilterDeleteByKey0 means
        // the filter is already gone — success for an idempotent reconcile.
        // Must NOT be Fatal (else a remove-then-install recompile aborts the
        // whole revision when a recorded filter id is already absent).
        assert_eq!(
            win32("FwpmFilterDeleteByKey0", 0x8032_0003).classify(),
            ErrorClass::Idempotent
        );
    }

    /// Pin: the FWP table values must match winerror.h
    /// verbatim. `FWP_E_ALREADY_EXISTS` was once locally re-declared as
    /// `0x8032_0001` (actually CALLOUT_NOT_FOUND) in `wfp_sublayer.rs`, which
    /// silently turned every filter add into a phantom success. Rust cannot
    /// check a constant's NAME against Microsoft's table — this test pins the
    /// numbers so an accidental edit at least fails loudly.
    #[test]
    fn win32_code_table_matches_winerror_h() {
        use win32_codes::*;
        assert_eq!(FWP_E_CALLOUT_NOT_FOUND, 0x8032_0001);
        assert_eq!(FWP_E_CONDITION_NOT_FOUND, 0x8032_0002);
        assert_eq!(FWP_E_FILTER_NOT_FOUND, 0x8032_0003);
        assert_eq!(FWP_E_SUBLAYER_NOT_FOUND, 0x8032_0007);
        assert_eq!(FWP_E_ALREADY_EXISTS, 0x8032_0009);
        assert_eq!(FWP_E_DYNAMIC_SESSION_IN_PROGRESS, 0x8032_000B);
        assert_eq!(FWP_E_TXN_IN_PROGRESS, 0x8032_000E);
        assert_eq!(ERROR_ACCESS_DENIED, 5);
        assert_eq!(ERROR_NOT_FOUND, 1168);
        assert_eq!(ERROR_DUPLICATE_TAG, 1500);
        assert_eq!(ERROR_OBJECT_ALREADY_EXISTS, 5010);
        assert_eq!(ERROR_TRANSACTION_IN_PROGRESS, 6800);
    }

    /// The sub-layer registration stage must be distinguishable from a
    /// duplicate FILTER add carrying the same Win32 code — conflating them is
    /// exactly the phantom-filter bug.
    #[test]
    fn sublayer_registration_failure_is_detected_by_operation_not_code() {
        // Same code, different stage:
        let sublayer = win32("FwpmSubLayerAdd0", win32_codes::FWP_E_ALREADY_EXISTS);
        let filter = win32("FwpmFilterAdd0", win32_codes::FWP_E_ALREADY_EXISTS);
        assert!(sublayer.is_sublayer_registration_failure());
        assert!(!filter.is_sublayer_registration_failure());
        // Any sub-layer stage failure counts, whatever the code:
        assert!(win32("FwpmSubLayerAdd0", win32_codes::ERROR_ACCESS_DENIED)
            .is_sublayer_registration_failure());
        // Non-Win32 variants never match.
        assert!(!PlatformError::AccessDenied {
            operation: "FwpmSubLayerAdd0"
        }
        .is_sublayer_registration_failure());
    }
}
