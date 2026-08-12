//! Stable Win32 constants for the apply layer.
//!
//! ## WFP object identity
//!
//! WFP providers, sub-layers, and filters are identified by GUIDs.
//! These GUIDs must be **stable across service restarts and updates**
//! so that the cleanup path (`FwpmFilterEnum0` + bulk delete by provider GUID)
//! can find and remove all filters we have ever added, including those left
//! by a crashed service instance.
//!
//! The GUIDs below are product-specific constants baked into the binary.
//! They were allocated once and will never change.
//!
//! ## WFP session lifecycle
//!
//! The service holds ONE long-lived WFP engine session for its lifetime
//! (opened at startup, closed at stop). The session is **non-dynamic**:
//! filters are NOT auto-removed when the engine handle closes — they persist
//! until an explicit delete or a reboot. Orphan cleanup is therefore
//! **explicit**, not automatic:
//! - graceful stop strips every filter
//!   (`PerSidApplyOrchestrator::cleanup_wfp` — robust delete-by-tracked-id plus
//!   an enumerate sweep);
//! - service startup strips any block filter a hard-killed prior instance left
//!   behind (`cleanup_wfp_blocks_only`) so an orphaned kill-switch can never
//!   lock the user out.
//!
//! (Historical note: an earlier design used per-apply dynamic sessions with
//! auto-cleanup on close; that is no longer how it works — do not rely on
//! session-close to remove filters.)
//!
//! See `WfpSession` in `wfp/mod.rs` for the RAII wrapper.
//!
//! ## WFP filter weights
//!
//! `SUBLAYER_WEIGHT` positions our sub-layer above Windows built-in sub-layers
//! (FWPM_SUBLAYER_MPSSVC_WSH = 0xFFFF, FWPM_SUBLAYER_TEREDO = 0xFFFE) so our
//! Fail-Closed blocks take effect even when Defender Firewall has an allow rule.
//!
//! `FILTER_WEIGHT_BASE` is the base for per-rule filter weights. Each rule's
//! filter weight = `FILTER_WEIGHT_BASE + canonical_position_index` (from the
//! canonical rule book ordering). This ensures deterministic
//! evaluation order within our sub-layer.
//!
//! ## Operations manual
//!
//! ### Route table (IPv4 only; IPv6 out-of-scope — see `strategy.rs`)
//!
//! | Operation | Win32 API | Notes |
//! |-----------|-----------|-------|
//! | Enumerate current routes | `GetIpForwardTable2(AF_INET, &table)` | Caller must `FreeMibTable(table)` |
//! | Add route | `CreateIpForwardEntry2(&row)` | Requires admin token |
//! | Delete route | `DeleteIpForwardEntry2(&row)` | Requires admin token |
//! | Subscribe to changes | `NotifyRouteChange2(AF_INET, callback, ctx, false, &handle)` | |
//! | Cancel subscription | `CancelMibChangeNotify2(handle)` | |
//!
//! ### WFP (Windows Filtering Platform)
//!
//! | Operation | Win32 API | Notes |
//! |-----------|-----------|-------|
//! | Open engine session | `FwpmEngineOpen0(NULL, WINNT, NULL, NULL, &handle)` | Requires admin |
//! | Close session | `FwpmEngineClose0(handle)` | Non-dynamic session — does NOT remove filters; they persist until explicit delete/reboot |
//! | Begin transaction | `FwpmTransactionBegin0(handle, 0)` | Explicit read-write transaction |
//! | Commit transaction | `FwpmTransactionCommit0(handle)` | Atomic — all-or-nothing |
//! | Abort transaction | `FwpmTransactionAbort0(handle)` | Undo all uncommitted changes |
//! | Register provider | `FwpmProviderAdd0(handle, &provider, NULL)` | Once per install; idempotent |
//! | Register sub-layer | `FwpmSubLayerAdd0(handle, &sublayer, NULL)` | Once per install; idempotent |
//! | Add filter | `FwpmFilterAdd0(handle, &filter, NULL, &id)` | Returns uint64 filter id |
//! | Delete filter | `FwpmFilterDeleteByKey0(handle, &key)` | key = filter GUID |
//! | Enumerate filters | `FwpmFilterCreateEnumHandle0` + `FwpmFilterEnum0` + `FwpmFilterDestroyEnumHandle0` | By provider GUID |
//!
//! ## Privilege requirements
//!
//! Both route-table modification and WFP filter management require an
//! **elevated admin token** on Windows Vista+. `NT AUTHORITY\LocalService`
//! is insufficient for both operations. The service must run as
//! `NT AUTHORITY\LocalSystem` or as a dedicated account in the Administrators
//! group. See `service_lifecycle::PRIVILEGE_MATRIX` and
//! `service_lifecycle::required_service_identity()`.

// ── WFP Provider GUID ─────────────────────────────────────────────────────────

/// Stable GUID for our WFP provider (`FWPM_PROVIDER0.providerKey`).
///
/// Allocated once; never regenerated at runtime. All filters, sub-layers,
/// and callouts belong to this provider. The cleanup path enumerates by
/// this GUID to find and remove any orphaned objects after a service crash.
///
/// Value: `{B4E0D8A2-3F7C-4E1B-9D5F-6C2A8B0E1F3D}`
///
/// The byte-array WFP identity GUIDs are the SSOT in
/// `nrr_platform_api::types` (the neutral `snapshot` hashing logic references
/// them); re-exported here so `crate::constants::WFP_PROVIDER_GUID` and the
/// win32_ffi sublayer registration keep resolving unchanged.
pub use nrr_platform_api::types::WFP_PROVIDER_GUID;

/// Human-readable provider name surfaced in Windows Firewall with Advanced
/// Security and `netsh wfp` diagnostics.
pub const WFP_PROVIDER_NAME: &str = "NetRuleRouter Policy Engine";

pub const WFP_PROVIDER_DESCRIPTION: &str =
    "NetRuleRouter network routing policy enforcement provider";

// ── WFP Sub-layer GUID ────────────────────────────────────────────────────────

pub use nrr_platform_api::types::WFP_SUBLAYER_GUID;

pub const WFP_SUBLAYER_NAME: &str = "NetRuleRouter Routing Policy";

pub const WFP_SUBLAYER_DESCRIPTION: &str =
    "NetRuleRouter Fail-Closed blocking filters for secondary-route enforcement";

// ── WFP weights ───────────────────────────────────────────────────────────────

/// Weight of our WFP sub-layer.
///
/// `FWPM_SUBLAYER0.weight` is a `UINT16`, so `0xFFFF` (65535) is the maximum
/// representable value and ties the highest Windows built-in sub-layers:
/// - `FWPM_SUBLAYER_MPSSVC_WSH` = 0xFFFF  (Windows Defender Firewall)
/// - `FWPM_SUBLAYER_TEREDO` = 0xFFFE
/// - `FWPM_SUBLAYER_IPSEC_TUNNEL` = 0xFFFD
///
/// A sub-layer can therefore never be registered *strictly above* the
/// firewall by weight alone. The earlier value `0x10000` was a latent bug:
/// it silently truncated to `0` (the LOWEST priority) when written to the
/// UINT16 field, so system allow rules overrode our Fail-Closed blocks and
/// e.g. ICMP leaked while the kill-switch was nominally armed. Sitting at
/// the top tier is necessary but not sufficient — our authority over a
/// system soft-permit comes from tagging every BLOCK filter with
/// `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` (a hard block), the standard WFP
/// kill-switch pattern. See `win32_ffi::wfp_filter` / `win32_ffi::wfp_sublayer`.
pub const WFP_SUBLAYER_WEIGHT: u32 = 0xFFFF;

/// Base weight for individual filters within our sub-layer.
///
/// Each filter's weight = `FILTER_WEIGHT_BASE + canonical_position_index`.
/// `canonical_position_index` comes from the rule's position in the
/// canonically ordered rule book, ensuring deterministic
/// evaluation order within the sub-layer.
pub use nrr_platform_api::types::FILTER_WEIGHT_BASE;

// ── Named pipe ────────────────────────────────────────────────────────────────

/// Name of the local named pipe used for GUI/tray ↔ service IPC.
/// Full path: `\\.\pipe\NrrService`
pub const IPC_PIPE_NAME: &str = r"\\.\pipe\NrrService";

// ── Timeouts and limits ───────────────────────────────────────────────────────

/// Maximum number of WFP filters per transaction. Prevents
/// `FwpmTransactionCommit0` from timing out on very large rule sets.
/// Apply plans larger than this are split into multiple transactions.
///
/// The neutral batching cap lives with the WFP session logic in
/// `nrr-platform-api` (`nrr_platform_api::wfp`); re-exported here so
/// `crate::constants::MAX_FILTERS_PER_TRANSACTION` keeps resolving unchanged.
pub use nrr_platform_api::wfp::MAX_FILTERS_PER_TRANSACTION;

/// Maximum time (seconds) the apply phase may take before the apply
/// orchestrator aborts and transitions to `FailedRequiresManualAction`.
pub const APPLY_TIMEOUT_SECS: u64 = 60;

/// Maximum time (seconds) allowed for post-apply verification.
pub const VERIFY_TIMEOUT_SECS: u64 = 10;

/// Maximum time (seconds) for a rollback attempt.
pub const ROLLBACK_TIMEOUT_SECS: u64 = 30;

/// Minimum quiet period (seconds) before a debounced adapter change event
/// is emitted to the service runtime.
pub const ADAPTER_DEBOUNCE_SECS: u64 = 0; // 500ms expressed as sub-second; handled in code

/// Maximum number of block notifications kept in the ring buffer.
pub const BLOCK_NOTIFICATION_RING_CAPACITY: usize = 50;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    // These tests deliberately lock invariants between compile-time constants.
    #![allow(clippy::assertions_on_constants)]
    use super::*;

    #[test]
    fn provider_guid_is_16_bytes() {
        assert_eq!(WFP_PROVIDER_GUID.len(), 16);
    }

    #[test]
    fn sublayer_guid_is_16_bytes() {
        assert_eq!(WFP_SUBLAYER_GUID.len(), 16);
    }

    #[test]
    fn provider_and_sublayer_guids_are_distinct() {
        assert_ne!(WFP_PROVIDER_GUID, WFP_SUBLAYER_GUID);
    }

    #[test]
    fn sublayer_weight_saturates_u16_ceiling_without_truncation() {
        // `FWPM_SUBLAYER0.weight` is UINT16, so 0xFFFF (MPSSVC_WSH, the top
        // Windows built-in sub-layer) is the ceiling — we cannot register
        // strictly above the firewall by weight. We sit exactly at the
        // ceiling and rely on hard-veto BLOCK filters for override.
        const MPSSVC_WSH_WEIGHT: u32 = 0xFFFF;
        assert_eq!(
            WFP_SUBLAYER_WEIGHT, MPSSVC_WSH_WEIGHT,
            "sub-layer weight must sit at the u16 ceiling (0xFFFF), tying the \
             top Windows sub-layer"
        );
        // Regression guard for the truncation bug: the value that actually
        // reaches the Win32 UINT16 field must be the top priority, NOT 0.
        // `0x10000 & 0xFFFF` silently became 0 (lowest priority) and
        // neutralised every block filter.
        assert_eq!(
            (WFP_SUBLAYER_WEIGHT & 0xFFFF) as u16,
            0xFFFF_u16,
            "truncated u16 weight must stay at the ceiling, not wrap to 0"
        );
    }

    #[test]
    fn filter_weight_base_is_above_sublayer_weight() {
        // Filter weights are u64; sublayer weight is u32.
        assert!(FILTER_WEIGHT_BASE > WFP_SUBLAYER_WEIGHT as u64);
    }

    #[test]
    fn apply_timeout_is_larger_than_verify_and_rollback() {
        assert!(APPLY_TIMEOUT_SECS > VERIFY_TIMEOUT_SECS);
        assert!(APPLY_TIMEOUT_SECS >= ROLLBACK_TIMEOUT_SECS);
    }

    #[test]
    fn max_filters_per_transaction_is_sane() {
        // Must be > 0 and reasonable.
        assert!(MAX_FILTERS_PER_TRANSACTION > 0);
        assert!(MAX_FILTERS_PER_TRANSACTION <= 10_000);
    }
}
