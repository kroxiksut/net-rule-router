//! IPC operation handlers for the running service.
//!
//! `MutationSubmitHandler` over the named pipe is the ONLY sanctioned
//! mutation channel. A file watcher would open a second, unaudited one
//! and must not be added.
//!
//! Every operation in [`IpcOperationName::ALL`] has a registered handler:
//! operations whose real implementation is not yet wired resolve to
//! [`UnimplementedHandler`], which surfaces `RecoveryRequired` to the
//! client. The pseudo "logs.list" / "audit.list" / "security.alerts.list" /
//! "rules.list" operations are not in `IpcOperationName::ALL` — they are
//! exposed as in-process handlers callable directly during composition.
//!
//! ## Module layout
//!
//! | Submodule                  | Responsibility                                   |
//! |----------------------------|--------------------------------------------------|
//! | [`payloads`]               | Wire-format request/response types (serde)       |
//! | [`providers`]              | Trait abstractions for service-internal sources  |
//! | [`stub`]                   | `UnimplementedHandler` placeholder               |
//! | `contract_negotiate`       | `ContractNegotiate` handshake                    |
//! | `service_health`           | `ServiceHealthGet`                               |
//! | `snapshot_interfaces`      | `SnapshotInterfacesGet`                          |
//! | `snapshot_diagnostics`     | `SnapshotDiagnosticsGet`                         |
//! | `snapshot_initial`         | `SnapshotInitialGet` — bundles the above three   |
//! | `logs_list` / `audit_list` | Paginated log/audit reads (used by composer)     |
//! | `security_alerts`          | Active security alerts read (used by composer)   |
//! | `rules_list`               | Rules table read (used by composer)              |

use std::sync::Arc;

use nrr_diagnostics::facade::service::DiagnosticsFacade;
use nrr_shared::ipc::IpcOperationName;

use crate::ipc::{IpcAuditEmitter, IpcHandlerRegistry};
use crate::managers::{HealthReporter, PolicyManager};

pub mod payloads;
pub mod providers;
pub mod stub;

pub mod event_bus;
pub mod mutation_token_store;
pub mod operation_status_store;

pub mod audit_list;
pub mod auto_rules_handlers;
pub mod block_notice_handlers;
pub mod contract_negotiate;
pub mod diagnostics_handlers;
pub mod doh_resolvers;
pub mod interfaces_refresh;
pub mod logs_list;
pub mod merge_preview;
pub mod migration_mark_complete;
pub mod migration_status_get;
pub mod mutation_submit;
pub mod operation_status;
pub mod preset_handlers;
pub mod principal_data_handlers;
pub mod product_impact_disable;
pub mod rollback;
pub mod route_link_provider_set;
pub mod route_policy_update;
pub mod rules_list;
pub mod security_alerts;
pub mod seed_browser_history;
pub mod service_health;
pub mod service_stability_handlers;
pub mod settings_handlers;
pub mod snapshot_diagnostics;
pub mod snapshot_initial;
pub mod snapshot_interfaces;
pub mod status_updates_poll;
pub mod status_updates_subscribe;
pub mod third_party_handlers;

#[cfg(test)]
pub(crate) mod test_fakes;

pub use audit_list::AuditListHandler;
pub use auto_rules_handlers::{
    AutoRuleCandidatesAcceptHandler, AutoRuleCandidatesDismissHandler,
    AutoRuleCandidatesForgetHandler, AutoRuleCandidatesListHandler, AutoRuleDismissedListHandler,
    AutoRuleDismissedRestoreHandler,
};
pub use block_notice_handlers::{
    BlockNoticeJournalAckHandler, BlockNoticeJournalListHandler, BlockNoticeMutesClearHandler,
    BlockNoticeMutesListHandler, BlockNoticeMutesRemoveHandler, BlockNoticeMutesSetHandler,
    BlockNoticeRouteToSecondaryHandler,
};
pub use contract_negotiate::{
    service_binary_version, set_service_binary_version, ContractNegotiateHandler,
    MIN_SUPPORTED_CLIENT_VERSION,
};
pub use diagnostics_handlers::{
    CacheClearHandler, CacheEntriesListHandler, DiagnosticsExportArchiveHandler, ExplainGetHandler,
    LogsClearHandler,
};
pub use doh_resolvers::{DohResolverListStore, DohResolversGetHandler, DohResolversSetHandler};
pub use event_bus::{
    EventBus, EventEntry, SubscribeOutcome, SubscriberState, EVENT_BUFFER_CAPACITY,
};
pub use interfaces_refresh::InterfacesRefreshHandler;
pub use logs_list::LogsListHandler;
pub use merge_preview::RulesMergePreviewHandler;
pub use migration_mark_complete::MigrationMarkCompleteHandler;
pub use migration_status_get::MigrationStatusGetHandler;
pub use mutation_submit::MutationSubmitHandler;
pub use mutation_token_store::{
    ConsumeError, MutationTokenStore, StoredMutation, DEFAULT_MUTATION_TOKEN_TTL,
};
pub use operation_status::OperationStatusHandler;
pub use operation_status_store::{
    OperationError, OperationRecord, OperationState, OperationStatusStore,
    DEFAULT_OPERATION_RETENTION,
};
pub use principal_data_handlers::{PrincipalDataCountHandler, PrincipalDataPurgeHandler};
pub use product_impact_disable::ProductImpactDisableTemporaryHandler;
pub use providers::{
    review_risk_level, AdaptersSnapshotProvider, ApplyFailurePolicyProvider,
    ApplyFailurePolicyWriter, AutostartProvider, AutostartWriter, LogRetentionConfigProvider,
    LogRetentionConfigWriter, MigrationCompletionRecord, MigrationCompletionWriter,
    MigrationStatusProvider, MutationExecutor, MutationOutcome, PrincipalDataPurger,
    RetentionSettingsProvider, RetentionSettingsWriter, RoutePolicyProvider, RoutePolicyWriteError,
    RoutePolicyWriter, RoutingPauseProvider, RoutingPauseWriter, RulesSnapshotProvider,
    ServiceStabilityConfigProvider, ServiceStabilityConfigWriter, SettingsWriteError,
    StorageUsageProvider, TrafficStatsProvider, TrafficStatsWriter,
};
pub use rollback::RollbackHandler;
pub use route_link_provider_set::RouteLinkProviderSetHandler;
pub use route_policy_update::RoutePolicyUpdateHandler;
pub use rules_list::RulesListHandler;
pub use security_alerts::SecurityAlertsHandler;
pub use seed_browser_history::SeedFromBrowserHistoryHandler;
pub use service_health::{
    build_service_health_response, service_state_slug, severity_slug, FakeIpDatapathProbe,
    ServiceHealthHandler,
};
pub use service_stability_handlers::{
    ServiceStabilityConfigGetHandler, ServiceStabilityConfigSetHandler,
};
pub use settings_handlers::{
    ApplyFailurePolicyGetHandler, ApplyFailurePolicySetHandler, AutoRuleCandidatesProbeHandler,
    AutostartGetHandler, AutostartToggleHandler, LocalNetworksGetHandler, LocalNetworksSetHandler,
    LogRetentionConfigGetHandler, LogRetentionConfigSetHandler, RefusingAnchorSetHandler,
    RetentionSettingsGetHandler, RetentionSettingsSetHandler, RoutingPauseGetHandler,
    RoutingPauseToggleHandler, StorageUsageGetHandler, TrafficHistoryMergeSetHandler,
    TrafficStatsClearHandler, TrafficStatsGetHandler, TrafficStatsSetHandler,
};
pub use snapshot_diagnostics::SnapshotDiagnosticsHandler;
pub use snapshot_initial::SnapshotInitialHandler;
pub use snapshot_interfaces::SnapshotInterfacesHandler;
pub use status_updates_poll::{StatusUpdatesPollHandler, STATUS_UPDATES_POLL_DEPRECATION_MESSAGE};
pub use status_updates_subscribe::StatusUpdatesSubscribeHandler;
pub use stub::UnimplementedHandler;

mod deps;
mod registration;

pub use deps::IpcHandlerDeps;
pub use registration::register_production_handlers;
