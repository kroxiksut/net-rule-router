//! How long the client waits for each operation's answer. One table for every
//! caller — GUI, tray, console and broker — so a budget is decided once.

use std::time::Duration;

use nrr_shared::ipc::IpcOperationName;

/// Budget for a two-phase operation's confirm pass, shared by every
/// operation whose confirm phase drives a full policy activation
/// (parse + canonicalise + persist + apply) before answering — currently
/// `MutationSubmit` and `RollbackRequest`. One constant so neither retypes
/// the other's number. The GUI's wait is derived from this table by the
/// launcher (`host_answer_deadlines`), never retyped.
const CONFIRM_PHASE_BUDGET: Duration = Duration::from_secs(30);

/// Per-operation timeout matrix.
///
/// `SnapshotInterfaces` and `InterfacesRefresh` carry the same 5-second
/// budget because force-refresh blocks on the adapter monitor; the
/// service guarantees a response within that window or returns a
/// degraded snapshot.
pub fn ipc_operation_timeout(op: IpcOperationName) -> Duration {
    match op {
        IpcOperationName::ContractNegotiate => Duration::from_secs(2),
        IpcOperationName::ServiceHealthGet => Duration::from_secs(1),
        IpcOperationName::SnapshotInitialGet => Duration::from_secs(3),
        IpcOperationName::SnapshotInterfacesGet => Duration::from_secs(5),
        IpcOperationName::SnapshotDiagnosticsGet => Duration::from_secs(2),
        IpcOperationName::LogsList | IpcOperationName::AuditList => Duration::from_secs(5),
        IpcOperationName::SecurityAlertsList => Duration::from_secs(1),
        // `rules.list` shares the state-DB connection mutex with the mutation
        // executor; right after an activation the GUI's refetch contends for
        // that lock while the heavy preset-import is still committing, so a
        // short budget can time the refetch out (lost response → empty
        // table). 5s covers the contention window.
        IpcOperationName::RulesList => Duration::from_secs(5),
        // MutationSubmit confirm does the real work — parse + canonicalise
        // a preset, persist the revision, and apply per-SID WFP filters.
        // For a large rule set on a debug build this routinely exceeds a 5s
        // budget, so a shorter timeout can fire while the service keeps
        // going (active revision committed server-side but the GUI lost the
        // response → no refetch, divergence).
        IpcOperationName::MutationSubmit => CONFIRM_PHASE_BUDGET,
        IpcOperationName::OperationStatusGet => Duration::from_secs(1),
        // Both read live adapters and the route table before answering, the
        // same enumeration the interfaces snapshot budgets 5s for.
        IpcOperationName::LocalNetworksGet | IpcOperationName::LocalNetworksSet => {
            Duration::from_secs(5)
        }
        // Accepting a probe pass only reads the pending list and starts a
        // thread — the pass itself never holds this reply open.
        IpcOperationName::AutoRuleCandidatesProbe => Duration::from_secs(2),
        // One small per-SID row write plus a read-back.
        IpcOperationName::RefusingAnchorSet => Duration::from_secs(2),
        // The confirm phase runs `rollback_to` with a full activation before
        // answering — the same shape of work `MutationSubmit`'s confirm phase
        // does, so it shares that budget. The dry-run phase (mints the
        // confirmation token) is cheap, but this table keys off the
        // operation alone, not the phase — `MutationSubmit` does not split
        // that either.
        IpcOperationName::RollbackRequest => CONFIRM_PHASE_BUDGET,
        IpcOperationName::InterfacesRefreshRequest => Duration::from_secs(5),
        IpcOperationName::ProductImpactDisableTemporary => Duration::from_secs(5),
        IpcOperationName::StatusUpdatesPoll | IpcOperationName::StatusUpdatesSubscribe => {
            Duration::from_secs(2)
        }
        // Per-SID configuration writes. NOT "one SQLite write": they are
        // user-scoped configuration, so they enter the single-writer mutation
        // queue and then trigger a recompile. A one-second budget therefore
        // timed out whenever anything else was mid-apply — observed as
        // "add automatically" failing with `timeout` while a preset import was
        // still committing, leaving the setting unchanged and the user with no
        // explanation. Ten seconds covers the queue without turning a stuck
        // service into a frozen dialog.
        IpcOperationName::RoutePolicyUpdate | IpcOperationName::RouteLinkProviderSet => {
            Duration::from_secs(10)
        }
        // Migration ledger: genuinely one row read/write.
        IpcOperationName::MigrationStatusGet
        | IpcOperationName::MigrationMarkComplete => Duration::from_secs(1),
        // Settings reads/writes. Singleton row + simple validation for the
        // four 'Set' ops; routing-pause writes also poke the apply layer
        // through the coordinator. 2 s budget covers the apply step.
        IpcOperationName::RetentionSettingsGet
        | IpcOperationName::ApplyFailurePolicyGet
        | IpcOperationName::RoutingPauseGet
        // Log/audit retention config get/set (singleton row).
        | IpcOperationName::LogRetentionConfigGet
        | IpcOperationName::AutostartGet => Duration::from_secs(1),
        IpcOperationName::RetentionSettingsSet
        | IpcOperationName::ApplyFailurePolicySet
        | IpcOperationName::LogRetentionConfigSet
        | IpcOperationName::AutostartToggle => Duration::from_secs(1),
        IpcOperationName::RoutingPauseToggle => Duration::from_secs(2),
        // Storage scan walks `%ProgramData%`, deliberately on-demand —
        // 5 s covers cold-disk worst-case.
        IpcOperationName::StorageUsageGet => Duration::from_secs(5),
        // Explain runs the decision engine plus an audit lookup; pure CPU +
        // one indexed SQLite read. 2 s budget matches diagnostics snapshot.
        IpcOperationName::ExplainGet => Duration::from_secs(2),
        // Archive build scans logs/audit directories + zips. Cold-disk
        // worst-case can be a few seconds for large log volumes; 10 s
        // is the upper guard.
        IpcOperationName::DiagnosticsExportArchive => Duration::from_secs(10),
        // Singleton-row reads/writes.
        IpcOperationName::ServiceStabilityConfigGet
        | IpcOperationName::ServiceStabilityConfigSet => Duration::from_secs(1),
        // LogsClear walks the rotated NDJSON file list and unlinks
        // each one. Bound by the number of files (capped by the
        // retention policy); 10 s mirrors the archive-build ceiling.
        IpcOperationName::LogsClear => Duration::from_secs(10),
        // CacheClear runs one SQLite transaction that deletes all cache
        // rows (or a stats read on dry-run). Bounded by row count; 10 s
        // is a conservative upper guard.
        IpcOperationName::CacheClear => Duration::from_secs(10),
        // CacheEntriesList runs one bounded indexed SELECT (page-sized).
        // 5 s mirrors the other paginated reads (LogsList / AuditList).
        IpcOperationName::CacheEntriesList => Duration::from_secs(5),
        // Read active revision + canonicalize + write_rules_file + SHA-256 +
        // base64 wrap. Pure CPU, single indexed SQLite read; 5 s is the
        // conservative upper bound even for a full `FREE_MAX_RULES` revision.
        IpcOperationName::PresetExportGet => Duration::from_secs(5),
        // Assemble YAML from route_bindings + behavior mode + per-user UI
        // prefs paths (paths only, no file contents). Three singleton-row
        // reads + serde_yaml emit. 3 s is generous.
        IpcOperationName::SettingsExportFull => Duration::from_secs(3),
        // Merge preview: one indexed state-DB read + parse + canonicalize
        // both file texts + merge + encode. Pure CPU on top of a single
        // read; 5 s matches the other rules reads under lock contention.
        IpcOperationName::RulesMergePreview => Duration::from_secs(5),
        // One bounded in-memory ring snapshot (page-sized). As cheap as the
        // cache read; 5 s mirrors the other paginated reads.
        IpcOperationName::ConnTraceEntriesList | IpcOperationName::ConnTraceOutageBlocksList => {
            Duration::from_secs(5)
        }
        // Hashes a ~400 KiB DLL and verifies its signature; the signature
        // check can touch the certificate store, so give it more room than a
        // pure in-memory read.
        IpcOperationName::ThirdPartyComponentsList => Duration::from_secs(10),
        // DoH resolver baseline list read/replace. One bounded SELECT / one
        // delete+insert transaction (~100 rows). 2 s is generous.
        IpcOperationName::DohResolversGet | IpcOperationName::DohResolversSet => {
            Duration::from_secs(2)
        }
        // Traffic-stats read is a couple of indexed SQLite reads plus
        // in-memory session totals; the write is one singleton-row upsert. 2 s.
        IpcOperationName::TrafficStatsGet
        | IpcOperationName::TrafficStatsSet
        | IpcOperationName::TrafficStatsClear
        // Answering the merge question is one row written into the same store.
        | IpcOperationName::TrafficHistoryMergeSet => Duration::from_secs(2),
        // Kicks off the async browser-history seed and returns immediately;
        // the read+resolve happens on a service worker thread.
        IpcOperationName::SeedFromBrowserHistory => Duration::from_secs(2),
        // Companion-domain suggestions. The list is an in-memory registry
        // read and the refusal is one SQLite upsert, so both are trivial.
        // Accepting authors rules and drives a full activation, which is the
        // same work `MutationSubmit` does — it gets the same budget, or the
        // tray would time out while the service was still applying.
        IpcOperationName::AutoRuleCandidatesList
        | IpcOperationName::AutoRuleCandidatesDismiss => Duration::from_secs(2),
        IpcOperationName::AutoRuleCandidatesAccept => Duration::from_secs(30),
        // Reviewing/restoring past refusals is the same shape as list/dismiss:
        // an indexed SQLite read and a single-row delete.
        // Restoring re-parks the stored offer and erasing deletes rows: still
        // in-memory work plus one small write.
        IpcOperationName::AutoRuleDismissedList
        | IpcOperationName::AutoRuleDismissedRestore
        | IpcOperationName::AutoRuleCandidatesForget => Duration::from_secs(2),
        // Block-notice mutes: an indexed per-SID read and single-row
        // upsert/delete — same trivial shape as the companion-domain
        // refusal ops above.
        IpcOperationName::BlockNoticeJournalList
        | IpcOperationName::BlockNoticeJournalAck
        | IpcOperationName::BlockNoticeMutesList
        | IpcOperationName::BlockNoticeMutesSet
        | IpcOperationName::BlockNoticeMutesRemove
        | IpcOperationName::BlockNoticeMutesClear => Duration::from_secs(2),
        // Authors a rule and drives a full activation — same work
        // `AutoRuleCandidatesAccept` does, same budget.
        IpcOperationName::BlockNoticeRouteToSecondary => Duration::from_secs(30),
        // Nine bounded per-SID DELETEs in one transaction — small row counts,
        // same tier as the other maintenance transactions above.
        IpcOperationName::PrincipalDataPurge => Duration::from_secs(5),
        IpcOperationName::PrincipalDataCount => Duration::from_secs(2),
        // Verdicts live in memory; accepting authors rules and drives an
        // activation, the same work `AutoRuleCandidatesAccept` does.
        IpcOperationName::VerifyVerdictsList | IpcOperationName::VerifyVerdictsDismiss => {
            Duration::from_secs(2)
        }
        IpcOperationName::VerifyVerdictsAccept => Duration::from_secs(30),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_matrix_covers_every_operation_in_catalog() {
        for op in IpcOperationName::ALL {
            let t = ipc_operation_timeout(op);
            assert!(t >= Duration::from_secs(1), "{} too small", op.slug());
            // Upper guard is 30 s: MutationSubmit's confirm phase does the
            // real parse+canonicalise+persist+WFP-apply work, and the broker
            // relays no service call longer than that.
            assert!(t <= Duration::from_secs(30), "{} too large", op.slug());
        }
    }

    #[test]
    fn timeout_matrix_matches_spec_values() {
        assert_eq!(
            ipc_operation_timeout(IpcOperationName::ContractNegotiate),
            Duration::from_secs(2)
        );
        assert_eq!(
            ipc_operation_timeout(IpcOperationName::ServiceHealthGet),
            Duration::from_secs(1)
        );
        assert_eq!(
            ipc_operation_timeout(IpcOperationName::SnapshotInitialGet),
            Duration::from_secs(3)
        );
        assert_eq!(
            ipc_operation_timeout(IpcOperationName::SnapshotInterfacesGet),
            Duration::from_secs(5)
        );
        assert_eq!(
            ipc_operation_timeout(IpcOperationName::SnapshotDiagnosticsGet),
            Duration::from_secs(2)
        );
        assert_eq!(
            ipc_operation_timeout(IpcOperationName::LogsList),
            Duration::from_secs(5)
        );
        assert_eq!(
            ipc_operation_timeout(IpcOperationName::AuditList),
            Duration::from_secs(5)
        );
        assert_eq!(
            ipc_operation_timeout(IpcOperationName::SecurityAlertsList),
            Duration::from_secs(1)
        );
        // rules.list contends for the state-DB lock right after an
        // activation, hence the 5s budget.
        assert_eq!(
            ipc_operation_timeout(IpcOperationName::RulesList),
            Duration::from_secs(5)
        );
        assert_eq!(
            ipc_operation_timeout(IpcOperationName::OperationStatusGet),
            Duration::from_secs(1)
        );
        // Confirm phase drives a full activation like `MutationSubmit`'s
        // confirm phase; same budget, same constant.
        assert_eq!(
            ipc_operation_timeout(IpcOperationName::RollbackRequest),
            ipc_operation_timeout(IpcOperationName::MutationSubmit)
        );
        assert_eq!(
            ipc_operation_timeout(IpcOperationName::InterfacesRefreshRequest),
            Duration::from_secs(5)
        );
    }
}
