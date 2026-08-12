//! production implementations for the 9 settings provider/writer traits.
//!
//! Each impl wraps an `Arc<Mutex<Connection>>` (or, for autostart, an
//! `AutostartHelper`) and translates between `nrr-shared` DTOs and the
//! storage-layer records. Errors map to `SettingsWriteError::{Invalid,
//! Storage, AccessDenied}` per the contract documented in the trait.
//!
//! Push-event emission for the corresponding `StatusUpdateEvent`
//! variants is **not** wired here — that requires `EventBus` access
//! plumbed through these structs and will land in a future phase.
//! Settings writes are
//! still durably persisted; the GUI sees them on the next
//! `SnapshotInitial` round-trip until push events go live.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use nrr_shared::ipc_payloads::StatusUpdateEvent;
use nrr_storage::{
    AutostartLastKnownState, AutostartStateRecord, AutostartStateRepository, LogRetentionConfig,
    LogRetentionConfigRepository, RetentionSettings, RetentionSettingsRepository,
    RoutingPauseStateRepository,
};
use rusqlite::Connection;

use crate::ipc_handlers::event_bus::EventBus;

use crate::ipc_handlers::payloads::{
    ApplyFailurePolicyDto, AutostartDto, LogRetentionConfigDto, LogRetentionConfigSetRequest,
    RetentionSettingsDto, RetentionSettingsSetRequest, RoutingPauseDto, StorageUsageDto,
};
use crate::ipc_handlers::providers::{
    ApplyFailurePolicyProvider, ApplyFailurePolicyWriter, AutostartProvider, AutostartWriter,
    LogRetentionConfigProvider, LogRetentionConfigWriter, RetentionSettingsProvider,
    RetentionSettingsWriter, RoutingPauseProvider, RoutingPauseWriter, SettingsWriteError,
    StorageUsageProvider,
};
use crate::routing_pause::RoutingPauseCoordinator;

fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Production `Clock` impl backed by `SystemTime::now`. Used by
/// `RoutingPauseCoordinator` (and, in phase 2, `ActivationCoordinator`).
pub struct SystemClock;

impl crate::activation_coordinator::Clock for SystemClock {
    fn now_secs(&self) -> i64 {
        now_secs()
    }
}

/// no-op `PauseDispatcher`. Persists pause state
/// to SQL but does NOT install/remove platform filters. Phase 2 swaps
/// this for [`OrchestratorPauseDispatcher`]. Kept around for tests and
/// the recovery path where the orchestrator may not be available.
pub struct NoopPauseDispatcher;

impl crate::routing_pause::PauseDispatcher for NoopPauseDispatcher {
    fn install_for_sid(&self, _sid: &str) -> Result<(), String> {
        Ok(())
    }
    fn remove_for_sid(&self, _sid: &str) -> Result<(), String> {
        Ok(())
    }
}

/// production `PauseDispatcher` wrapping
/// [`crate::per_sid_orchestrator::PerSidApplyOrchestrator`]. The
/// adapter forwards `install_for_sid` / `remove_for_sid` directly. The
/// orchestrator's idempotency (re-install on already-installed SID
/// succeeds) carries through, so the `PauseDispatcher` contract is
/// preserved without extra bookkeeping.
pub struct OrchestratorPauseDispatcher {
    orchestrator: Arc<crate::per_sid_orchestrator::PerSidApplyOrchestrator>,
}

impl OrchestratorPauseDispatcher {
    pub fn new(orchestrator: Arc<crate::per_sid_orchestrator::PerSidApplyOrchestrator>) -> Self {
        Self { orchestrator }
    }
}

impl crate::routing_pause::PauseDispatcher for OrchestratorPauseDispatcher {
    fn install_for_sid(&self, sid: &str) -> Result<(), String> {
        self.orchestrator
            .install_for_sid(sid)
            .map(|_count| ())
            .map_err(|e| format!("install_for_sid failed: {e:?}"))
    }

    fn remove_for_sid(&self, sid: &str) -> Result<(), String> {
        self.orchestrator
            .remove_for_sid(sid)
            .map(|_count| ())
            .map_err(|e| format!("remove_for_sid failed: {e:?}"))
    }
}

fn lock_conn<'a>(
    conn: &'a Mutex<Connection>,
) -> Result<std::sync::MutexGuard<'a, Connection>, SettingsWriteError> {
    conn.lock()
        .map_err(|_| SettingsWriteError::Storage("connection mutex poisoned".into()))
}

// ── Retention ────────────────────────────────────────────────────────────────

pub struct ProductionRetentionSettings {
    conn: Arc<Mutex<Connection>>,
    /// Phase 2: optional `EventBus` so successful writes publish a
    /// `RetentionSettingsChanged` push event. `None` skips the publish
    /// (e.g. when the bus has not been wired yet during partial bring-up).
    event_bus: Option<Arc<EventBus>>,
}

impl ProductionRetentionSettings {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self {
            conn,
            event_bus: None,
        }
    }

    pub fn with_event_bus(mut self, bus: Arc<EventBus>) -> Self {
        self.event_bus = Some(bus);
        self
    }

    fn record_to_dto(rec: RetentionSettings) -> RetentionSettingsDto {
        RetentionSettingsDto {
            superseded_days: rec.superseded_days,
            superseded_count_cap: rec.superseded_count_cap,
            rejected_days: rec.rejected_days,
            rolledback_days: rec.rolledback_days,
            rolledback_count_cap: rec.rolledback_count_cap,
            pin_lkg: rec.pin_lkg,
            last_cleanup_at: rec.last_cleanup_at.map(|v| v as u64),
            updated_at: rec.updated_at as u64,
        }
    }
}

impl RetentionSettingsProvider for ProductionRetentionSettings {
    fn get(&self) -> RetentionSettingsDto {
        // On lock failure or storage error, fall back to the documented
        // defaults rather than crash — the GUI gets the safe baseline.
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return Self::record_to_dto(RetentionSettings::DEFAULT),
        };
        let repo = RetentionSettingsRepository::new(&conn);
        match repo.get_or_default() {
            Ok(rec) => Self::record_to_dto(rec),
            Err(_) => Self::record_to_dto(RetentionSettings::DEFAULT),
        }
    }
}

impl RetentionSettingsWriter for ProductionRetentionSettings {
    fn set(
        &self,
        request: &RetentionSettingsSetRequest,
    ) -> Result<RetentionSettingsDto, SettingsWriteError> {
        let now = now_secs();
        let payload = RetentionSettings {
            superseded_days: request.superseded_days,
            superseded_count_cap: request.superseded_count_cap,
            rejected_days: request.rejected_days,
            rolledback_days: request.rolledback_days,
            rolledback_count_cap: request.rolledback_count_cap,
            pin_lkg: request.pin_lkg,
            last_cleanup_at: None,
            updated_at: now,
        };
        if let Err(e) = payload.validate() {
            return Err(SettingsWriteError::Invalid(e.to_string()));
        }
        let conn = lock_conn(&self.conn)?;
        let repo = RetentionSettingsRepository::new(&conn);
        repo.set(&payload, now)
            .map_err(|e| SettingsWriteError::Storage(e.to_string()))?;
        let written = repo
            .get_or_default()
            .map_err(|e| SettingsWriteError::Storage(e.to_string()))?;
        if let Some(bus) = self.event_bus.as_ref() {
            bus.publish(StatusUpdateEvent::RetentionSettingsChanged);
        }
        Ok(Self::record_to_dto(written))
    }
}

// ── Log/audit retention config (#20) ─────────────────────────────────────────

/// Singleton `log_retention_config` provider + writer. No push event: the GUI
/// re-fetches on demand (the settings panel loads it on open). Falls back to
/// documented defaults on lock/storage failure so the GUI always gets a value.
pub struct ProductionLogRetentionConfig {
    conn: Arc<Mutex<Connection>>,
}

impl ProductionLogRetentionConfig {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }

    fn record_to_dto(rec: LogRetentionConfig) -> LogRetentionConfigDto {
        LogRetentionConfigDto {
            log_max_age_days: rec.log_max_age_days,
            log_max_size_bytes: rec.log_max_size_bytes,
            audit_max_age_days: rec.audit_max_age_days,
            audit_max_size_bytes: rec.audit_max_size_bytes,
            updated_at: rec.updated_at as u64,
        }
    }
}

impl LogRetentionConfigProvider for ProductionLogRetentionConfig {
    fn get(&self) -> LogRetentionConfigDto {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return Self::record_to_dto(LogRetentionConfig::DEFAULT),
        };
        let repo = LogRetentionConfigRepository::new(&conn);
        match repo.get_or_default() {
            Ok(rec) => Self::record_to_dto(rec),
            Err(_) => Self::record_to_dto(LogRetentionConfig::DEFAULT),
        }
    }
}

impl LogRetentionConfigWriter for ProductionLogRetentionConfig {
    fn set(
        &self,
        request: &LogRetentionConfigSetRequest,
    ) -> Result<LogRetentionConfigDto, SettingsWriteError> {
        let now = now_secs();
        let payload = LogRetentionConfig {
            log_max_age_days: request.log_max_age_days,
            log_max_size_bytes: request.log_max_size_bytes,
            audit_max_age_days: request.audit_max_age_days,
            audit_max_size_bytes: request.audit_max_size_bytes,
            updated_at: now,
        };
        if let Err(e) = payload.validate() {
            return Err(SettingsWriteError::Invalid(e.to_string()));
        }
        let conn = lock_conn(&self.conn)?;
        let repo = LogRetentionConfigRepository::new(&conn);
        repo.set(&payload, now)
            .map_err(|e| SettingsWriteError::Storage(e.to_string()))?;
        let written = repo
            .get_or_default()
            .map_err(|e| SettingsWriteError::Storage(e.to_string()))?;
        Ok(Self::record_to_dto(written))
    }
}

// ── Apply failure policy ─────────────────────────────────────────────────────

pub struct ProductionApplyFailurePolicy {
    conn: Arc<Mutex<Connection>>,
    /// forwards persisted policy changes to the
    /// running coordinator so the next activation uses the new mode
    /// without waiting for service restart.
    coordinator: Option<Arc<crate::activation_coordinator::ActivationCoordinator>>,
    event_bus: Option<Arc<EventBus>>,
}

impl ProductionApplyFailurePolicy {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self {
            conn,
            coordinator: None,
            event_bus: None,
        }
    }

    pub fn with_coordinator(
        mut self,
        coordinator: Arc<crate::activation_coordinator::ActivationCoordinator>,
    ) -> Self {
        self.coordinator = Some(coordinator);
        self
    }

    pub fn with_event_bus(mut self, bus: Arc<EventBus>) -> Self {
        self.event_bus = Some(bus);
        self
    }

    fn record_to_dto(rec: nrr_storage::ApplyFailurePolicyRecord) -> ApplyFailurePolicyDto {
        ApplyFailurePolicyDto {
            policy: rec.policy,
            updated_at: rec.set_at as u64,
            set_by_sid: rec.set_by_sid,
        }
    }
}

impl ApplyFailurePolicyProvider for ProductionApplyFailurePolicy {
    fn get(&self) -> ApplyFailurePolicyDto {
        let default = ApplyFailurePolicyDto {
            policy: nrr_storage::DEFAULT_POLICY_SLUG.to_string(),
            updated_at: 0,
            set_by_sid: None,
        };
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return default,
        };
        let repo = nrr_storage::ApplyFailurePolicySettingsRepository::new(&conn);
        match repo.get_or_default() {
            Ok(rec) => Self::record_to_dto(rec),
            Err(_) => default,
        }
    }
}

impl ApplyFailurePolicyWriter for ProductionApplyFailurePolicy {
    fn set(
        &self,
        slug: &str,
        sid: Option<&str>,
    ) -> Result<ApplyFailurePolicyDto, SettingsWriteError> {
        if !nrr_storage::VALID_POLICY_SLUGS.contains(&slug) {
            return Err(SettingsWriteError::Invalid(format!(
                "unknown policy slug '{slug}'"
            )));
        }
        let now = now_secs();
        let conn = lock_conn(&self.conn)?;
        let repo = nrr_storage::ApplyFailurePolicySettingsRepository::new(&conn);
        repo.set(slug, sid, now)
            .map_err(|e| SettingsWriteError::Storage(e.to_string()))?;
        let written = repo
            .get_or_default()
            .map_err(|e| SettingsWriteError::Storage(e.to_string()))?;
        drop(conn);
        // forward to the live coordinator so the
        // next activation uses the new mode immediately. Phase 1 had a
        // gap here (eventual consistency via re-read on next activate);
        // phase 2 closes it.
        if let Some(coord) = self.coordinator.as_ref() {
            if let Some(parsed) = parse_apply_failure_policy(slug) {
                coord.set_failure_policy(parsed);
            }
        }
        if let Some(bus) = self.event_bus.as_ref() {
            bus.publish(StatusUpdateEvent::ApplyFailurePolicyChanged {
                policy: slug.to_string(),
            });
        }
        Ok(Self::record_to_dto(written))
    }
}

fn parse_apply_failure_policy(
    slug: &str,
) -> Option<crate::activation_coordinator::ApplyFailurePolicy> {
    use crate::activation_coordinator::ApplyFailurePolicy;
    match slug {
        "all-or-nothing" => Some(ApplyFailurePolicy::AllOrNothing),
        "best-effort" => Some(ApplyFailurePolicy::BestEffort),
        "pre-flight-then-all-or-nothing" => Some(ApplyFailurePolicy::PreFlightThenAllOrNothing),
        _ => None,
    }
}

// ── Storage usage ────────────────────────────────────────────────────────────

/// Files measured by the storage-usage walk. Each entry is checked for
/// existence; missing files report `None`. The probe runs synchronously
/// in the IPC handler thread; spec'd 5-second timeout (`backend_facade_impl::timeout_for`)
/// is generous for typical `%ProgramData%` size.
pub struct ProductionStorageUsage {
    state_db_path: PathBuf,
    cache_db_path: PathBuf,
    logs_dir: PathBuf,
}

impl ProductionStorageUsage {
    pub fn new(state_db_path: PathBuf, cache_db_path: PathBuf, logs_dir: PathBuf) -> Self {
        Self {
            state_db_path,
            cache_db_path,
            logs_dir,
        }
    }

    fn file_size(path: &std::path::Path) -> Option<u64> {
        std::fs::metadata(path).ok().map(|m| m.len())
    }

    /// Sums sizes of all NDJSON files in `logs_dir` whose name matches
    /// the given prefix. Returns 0 when the directory does not exist.
    fn ndjson_total_for_prefix(dir: &std::path::Path, prefix: &str) -> u64 {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return 0,
        };
        let mut total: u64 = 0;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = match name.to_str() {
                Some(n) => n,
                None => continue,
            };
            if name.starts_with(prefix) && name.ends_with(".ndjson") {
                if let Ok(meta) = entry.metadata() {
                    total = total.saturating_add(meta.len());
                }
            }
        }
        total
    }
}

impl StorageUsageProvider for ProductionStorageUsage {
    fn measure(&self) -> StorageUsageDto {
        let state_db = Self::file_size(&self.state_db_path);
        let cache_db = Self::file_size(&self.cache_db_path);
        let operational = Self::ndjson_total_for_prefix(&self.logs_dir, "nrr_service_");
        let audit = Self::ndjson_total_for_prefix(&self.logs_dir, "nrr_audit_");
        let total = state_db.unwrap_or(0) + cache_db.unwrap_or(0) + operational + audit;
        StorageUsageDto {
            state_db_bytes: state_db,
            cache_db_bytes: cache_db,
            operational_logs_bytes: operational,
            audit_logs_bytes: audit,
            total_bytes: total,
            scanned_at: now_secs() as u64,
        }
    }
}

// ── Routing pause ────────────────────────────────────────────────────────────

pub struct ProductionRoutingPause {
    conn: Arc<Mutex<Connection>>,
    coordinator: Arc<RoutingPauseCoordinator>,
    event_bus: Option<Arc<EventBus>>,
}

impl ProductionRoutingPause {
    pub fn new(conn: Arc<Mutex<Connection>>, coordinator: Arc<RoutingPauseCoordinator>) -> Self {
        Self {
            conn,
            coordinator,
            event_bus: None,
        }
    }

    pub fn with_event_bus(mut self, bus: Arc<EventBus>) -> Self {
        self.event_bus = Some(bus);
        self
    }

    fn record_to_dto(rec: nrr_storage::RoutingPauseRecord) -> RoutingPauseDto {
        RoutingPauseDto {
            sid: rec.sid,
            paused: rec.paused,
            paused_at: rec.paused_at.map(|v| v as u64),
            pause_reason: rec.pause_reason,
            updated_at: rec.updated_at as u64,
        }
    }

    fn read_for_sid(&self, sid: &str) -> RoutingPauseDto {
        let now = now_secs();
        let default = RoutingPauseDto {
            sid: sid.to_string(),
            paused: false,
            paused_at: None,
            pause_reason: None,
            updated_at: now as u64,
        };
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return default,
        };
        let repo = RoutingPauseStateRepository::new(&conn);
        match repo.get(sid) {
            Ok(Some(rec)) => Self::record_to_dto(rec),
            _ => default,
        }
    }
}

impl RoutingPauseProvider for ProductionRoutingPause {
    fn get(&self, sid: &str) -> RoutingPauseDto {
        self.read_for_sid(sid)
    }
}

impl RoutingPauseWriter for ProductionRoutingPause {
    fn toggle(
        &self,
        sid: &str,
        paused: bool,
        reason: Option<&str>,
    ) -> Result<RoutingPauseDto, SettingsWriteError> {
        if sid.is_empty() {
            return Err(SettingsWriteError::AccessDenied(
                "caller SID required".into(),
            ));
        }
        let outcome = if paused {
            self.coordinator.pause(sid, reason)
        } else {
            self.coordinator.resume(sid)
        };
        outcome.map_err(|e| SettingsWriteError::Storage(format!("{e:?}")))?;
        if let Some(bus) = self.event_bus.as_ref() {
            bus.publish(StatusUpdateEvent::RoutingPauseStateChanged {
                sid: sid.to_string(),
                paused,
            });
        }
        Ok(self.read_for_sid(sid))
    }
}

// ── Autostart ────────────────────────────────────────────────────────────────

pub struct ProductionAutostart<P>
where
    P: nrr_platform_api::autostart::AutostartRegistryPort + Send + Sync + 'static,
{
    conn: Arc<Mutex<Connection>>,
    helper: Arc<nrr_platform_api::autostart::AutostartHelper<P>>,
    tray_binary_path: PathBuf,
    event_bus: Option<Arc<EventBus>>,
}

impl<P> ProductionAutostart<P>
where
    P: nrr_platform_api::autostart::AutostartRegistryPort + Send + Sync + 'static,
{
    pub fn new(
        conn: Arc<Mutex<Connection>>,
        helper: Arc<nrr_platform_api::autostart::AutostartHelper<P>>,
        tray_binary_path: PathBuf,
    ) -> Self {
        Self {
            conn,
            helper,
            tray_binary_path,
            event_bus: None,
        }
    }

    pub fn with_event_bus(mut self, bus: Arc<EventBus>) -> Self {
        self.event_bus = Some(bus);
        self
    }

    fn record_to_dto(rec: AutostartStateRecord) -> AutostartDto {
        AutostartDto {
            enabled: rec.enabled,
            last_known_state: rec
                .last_known_state
                .map(|s| s.as_slug().to_string())
                .unwrap_or_else(|| "absent".to_string()),
            overridden_value: None,
            updated_at: rec.updated_at as u64,
        }
    }

    fn merge_observation(
        rec: AutostartStateRecord,
        observed: nrr_platform_api::autostart::AutostartCurrentState,
    ) -> AutostartDto {
        use nrr_platform_api::autostart::AutostartCurrentState;
        let (last_known, overridden) = match observed {
            AutostartCurrentState::Enabled { matches_ours, .. } => {
                if matches_ours {
                    ("enabled".to_string(), None)
                } else {
                    ("overridden-externally".to_string(), Some(String::new()))
                }
            }
            AutostartCurrentState::Disabled => ("disabled".to_string(), None),
            AutostartCurrentState::OverriddenExternally { value } => {
                ("overridden-externally".to_string(), Some(value))
            }
        };
        AutostartDto {
            enabled: rec.enabled,
            last_known_state: last_known,
            overridden_value: overridden,
            updated_at: rec.updated_at as u64,
        }
    }
}

impl<P> AutostartProvider for ProductionAutostart<P>
where
    P: nrr_platform_api::autostart::AutostartRegistryPort + Send + Sync + 'static,
{
    fn get(&self) -> AutostartDto {
        // Re-probe registry on every read so the GUI sees an external
        // override quickly. Cheap: HKCU registry hit + tiny string.
        let observed = self.helper.get_state(&self.tray_binary_path);
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => {
                return AutostartDto {
                    enabled: false,
                    last_known_state: "absent".into(),
                    overridden_value: None,
                    updated_at: 0,
                };
            }
        };
        let repo = AutostartStateRepository::new(&conn);
        let rec = repo.get_or_default().unwrap_or(AutostartStateRecord {
            enabled: false,
            last_known_state: None,
            updated_at: 0,
        });
        match observed {
            Ok(state) => Self::merge_observation(rec, state),
            Err(_) => Self::record_to_dto(rec),
        }
    }
}

impl<P> AutostartWriter for ProductionAutostart<P>
where
    P: nrr_platform_api::autostart::AutostartRegistryPort + Send + Sync + 'static,
{
    fn toggle(&self, enabled: bool) -> Result<AutostartDto, SettingsWriteError> {
        let helper_outcome = if enabled {
            self.helper.set_enabled(&self.tray_binary_path)
        } else {
            self.helper.clear()
        };
        helper_outcome.map_err(|e| match e {
            nrr_platform_api::autostart::AutostartError::InvalidPath => {
                SettingsWriteError::Invalid("autostart binary path is invalid".into())
            }
            nrr_platform_api::autostart::AutostartError::RegistryAccess { code, message } => {
                SettingsWriteError::Storage(format!(
                    "registry access failed (code={code}): {message}"
                ))
            }
        })?;

        // Persist intent in the singleton row + record observed state.
        let observed = self
            .helper
            .get_state(&self.tray_binary_path)
            .map_err(|e| SettingsWriteError::Storage(format!("autostart probe failed: {e:?}")))?;
        let now = now_secs();
        let last_known = match &observed {
            nrr_platform_api::autostart::AutostartCurrentState::Enabled {
                matches_ours, ..
            } => {
                if *matches_ours {
                    Some(AutostartLastKnownState::Enabled)
                } else {
                    Some(AutostartLastKnownState::OverriddenExternally)
                }
            }
            nrr_platform_api::autostart::AutostartCurrentState::Disabled => {
                Some(AutostartLastKnownState::Disabled)
            }
            nrr_platform_api::autostart::AutostartCurrentState::OverriddenExternally { .. } => {
                Some(AutostartLastKnownState::OverriddenExternally)
            }
        };
        let conn = lock_conn(&self.conn)?;
        let repo = AutostartStateRepository::new(&conn);
        repo.set(enabled, last_known, now)
            .map_err(|e| SettingsWriteError::Storage(e.to_string()))?;
        let rec = repo
            .get_or_default()
            .map_err(|e| SettingsWriteError::Storage(e.to_string()))?;
        let dto = Self::merge_observation(rec, observed);
        if let Some(bus) = self.event_bus.as_ref() {
            bus.publish(StatusUpdateEvent::AutostartStateChanged {
                enabled: dto.enabled,
                last_known_state: dto.last_known_state.clone(),
            });
        }
        Ok(dto)
    }
}

// ── Once-per-startup autostart probe ─────────────────────────────────────────

/// Reads the current `HKCU\…\Run` value via `helper.get_state` and
/// persists the observation through `record_observation`. Called at
/// service startup so the GUI sees an up-to-date `last_known_state`
/// (incl. external overrides) without waiting for the user to open
/// settings. Errors are logged via `tracing` and swallowed — the probe
/// is best-effort.
pub fn run_autostart_startup_probe<P>(
    conn: &Mutex<Connection>,
    helper: &nrr_platform_api::autostart::AutostartHelper<P>,
    tray_binary_path: &std::path::Path,
) where
    P: nrr_platform_api::autostart::AutostartRegistryPort + Send + Sync,
{
    use nrr_platform_api::autostart::AutostartCurrentState;
    let observed = match helper.get_state(tray_binary_path) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(target: "nrr::autostart", error = ?e, "autostart startup probe failed");
            return;
        }
    };
    let last_known = match observed {
        AutostartCurrentState::Enabled { matches_ours, .. } => {
            if matches_ours {
                AutostartLastKnownState::Enabled
            } else {
                AutostartLastKnownState::OverriddenExternally
            }
        }
        AutostartCurrentState::Disabled => AutostartLastKnownState::Disabled,
        AutostartCurrentState::OverriddenExternally { .. } => {
            AutostartLastKnownState::OverriddenExternally
        }
    };
    let conn = match conn.lock() {
        Ok(c) => c,
        Err(_) => return,
    };
    let repo = AutostartStateRepository::new(&conn);
    let now = now_secs();
    if let Err(e) = repo.record_observation(last_known, now) {
        tracing::warn!(
            target: "nrr::autostart",
            error = %e,
            "autostart observation persist failed",
        );
    }
}

// ── Service stability config ──────────────────────────────────────────────────

use crate::ipc_handlers::providers::{
    ServiceStabilityConfigProvider, ServiceStabilityConfigWriter,
};
use nrr_domain::enforcement_mode::EnforcementMode;
use nrr_shared::ipc_payloads::{IpcAcceptFailurePolicyDto, ServiceStabilityConfigDto};
use nrr_storage::service_stability_config::{
    validate_recoverable_params, IpcAcceptPolicyRecord, IpcAcceptPolicyWrite, RoutingStopPolicy,
    ServiceStabilityConfigRepository,
};

/// Production wiring of the singleton `service_stability_config`
/// reader/writer. Wraps `nrr_storage::ServiceStabilityConfigRepository`
/// behind the shared connection lock and converts between the
/// storage `IpcAcceptPolicyRecord` enum and the wire-shaped
/// `IpcAcceptFailurePolicyDto`.
///
/// carry-over (now delivered in 16.13.S1): the IPC
/// handler was previously stubbed; setting the config requires admin
/// elevation per `IpcOperationSpec::requires_service_mutation_privilege`
/// upstream, so the writer trusts the caller has been gated already.
pub struct ProductionServiceStability {
    conn: Arc<Mutex<Connection>>,
    /// the shared liveness tracker whose window this
    /// setting drives. When `Some`, a `set()` applies the new window LIVE (no
    /// service restart). `None` in tests / when the route path isn't wired.
    liveness_tracker: Option<Arc<crate::secondary_liveness::SecondaryLivenessTracker>>,
    /// the shared DNS-resolver controller. When
    /// `Some`, a `set()` starts/stops the local resolver to match the new
    /// `enforcement_mode` WITHOUT a service restart. `None` in tests / when the
    /// platform factory isn't wired (the mode still persists; takes effect next
    /// restart).
    resolver_controller: Option<Arc<crate::dns_resolver_service::DnsResolverController>>,
    /// P3 — the boot-time tracing-reload seam. When `Some`,
    /// a `set()` flips the running process's `EnvFilter` to match the new
    /// `verbose_logging` value WITHOUT a service restart. `None` in tests /
    /// on a degraded boot (the value still persists; takes effect next
    /// restart, same as before this change).
    verbosity_control: Option<Arc<dyn crate::verbosity_control::VerbosityControl>>,
    /// Block D (S4.7) — the fake-IP live-apply seam. When `Some`, a `set()`
    /// reconciles the fake-IP stack to `fake_ip_enabled && mode == Resolver`
    /// WITHOUT a service restart. The hook must be async/best-effort (driver
    /// load takes seconds; never stall the IPC reply). `None` in tests / when
    /// the platform factory isn't wired (the toggle still persists; takes
    /// effect next restart).
    ///
    /// The hook runs on EVERY write — the idempotent re-apply is what keeps
    /// the runtime stack converged with the DB even after a restart or a
    /// missed apply. The request additionally reports which resolve-affecting
    /// values actually changed (`dns_flush_reasons`) so the hook can gate its
    /// OS DNS-cache flush on a real transition instead of flushing on every
    /// unrelated settings save.
    fake_ip_apply: Option<Arc<dyn Fn(FakeIpApplyRequest) + Send + Sync>>,
    /// DNS-over-secondary — the live gate the upstream DNS path
    /// consults per query. When `Some`, a `set()` stores the persisted value
    /// into the shared flag so the running resolver/seeder/forward paths flip
    /// WITHOUT a service restart. `None` in tests / when the path isn't wired
    /// (the toggle still persists; takes effect next restart).
    dns_via_secondary_flag: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// Fast DNS answers — the live gate the Mode-B resolver
    /// consults per query. Same contract as `dns_via_secondary_flag`: when
    /// `Some`, a `set()` stores the persisted value so the running resolver
    /// flips WITHOUT a service restart; `None` in tests / unwired boots
    /// (the toggle still persists; takes effect next restart).
    dns_fast_answers_flag: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// Fake-IP UDP relay — the live-apply seam for the pool
    /// permit's UDP handling. Unlike `dns_fast_answers_flag` (a per-query read
    /// with nothing to recompute), this flag feeds `ks-fakeip-pool` WFP filter
    /// generation, so a `set()` must also REPLAN the active SIDs' filter sets —
    /// same contract as `fake_ip_apply`. `None` in tests / when the replan seam
    /// isn't wired (the toggle still persists; takes effect on the next
    /// unrelated recompute).
    udp_relay_apply: Option<Arc<dyn Fn(bool) + Send + Sync>>,
    /// Fake-IP instant reset — the live gate the relay's dial
    /// path consults per dial. Unlike `udp_relay_apply` (which feeds WFP
    /// filter generation), this flag changes ONLY which code path a failed
    /// dial takes — no filter set changes, so a `set()` just stores the
    /// persisted value into the shared flag, same lightweight contract as
    /// `dns_fast_answers_flag`. `None` in tests / unwired boots (the toggle
    /// still persists; takes effect next restart).
    instant_rst_flag: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// ISP block-page rule candidates — the live gate the
    /// auto-rules engine consults per candidate. Same contract as `instant_rst_flag`.
    isp_block_candidates_flag: Option<Arc<std::sync::atomic::AtomicBool>>,
}

/// Argument to the fake-IP live-apply hook (`with_fake_ip_apply`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeIpApplyRequest {
    /// Desired stack state: `fake_ip_enabled && enforcement_mode == Resolver`.
    pub desired: bool,
    /// DTO field names of the resolve-affecting values whose persisted state
    /// actually changed in this write. Non-empty means cached OS answers may
    /// describe the previous resolve world and the hook must flush the OS DNS
    /// resolver cache ONCE after the stack transition. Empty means no flush:
    /// re-saving an unchanged config, or flipping flow-behavior toggles (UDP
    /// relay, instant reset — they change how already-established flows
    /// behave, never which addresses names resolve to), does not invalidate
    /// cached answers, and every needless flush costs a machine-wide
    /// re-resolve wave.
    pub dns_flush_reasons: Vec<&'static str>,
}

impl ProductionServiceStability {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self {
            conn,
            liveness_tracker: None,
            resolver_controller: None,
            verbosity_control: None,
            fake_ip_apply: None,
            dns_via_secondary_flag: None,
            dns_fast_answers_flag: None,
            udp_relay_apply: None,
            instant_rst_flag: None,
            isp_block_candidates_flag: None,
        }
    }

    /// Attaches the DNS-over-secondary live gate so a toggle takes effect
    /// live (no restart). Chain after `new`.
    pub fn with_dns_via_secondary_flag(mut self, flag: Arc<std::sync::atomic::AtomicBool>) -> Self {
        self.dns_via_secondary_flag = Some(flag);
        self
    }

    /// Attaches the fast-DNS-answers live gate so a toggle takes effect
    /// live (no restart). Chain after `new`.
    pub fn with_dns_fast_answers_flag(mut self, flag: Arc<std::sync::atomic::AtomicBool>) -> Self {
        self.dns_fast_answers_flag = Some(flag);
        self
    }

    /// Attaches the fake-IP UDP-relay live-apply hook so a toggle flips the
    /// process-wide flag AND replans the active SIDs' WFP filter sets live (no
    /// restart) — mirrors `with_fake_ip_apply`. Chain after `new`.
    pub fn with_udp_relay_apply(mut self, apply: Arc<dyn Fn(bool) + Send + Sync>) -> Self {
        self.udp_relay_apply = Some(apply);
        self
    }

    /// Attaches the fake-IP instant-reset live gate so a toggle takes effect
    /// live (no restart) — no replan needed, unlike `with_udp_relay_apply`:
    /// the flag only changes which branch a failed relay dial takes, never
    /// the emitted WFP filter set. Chain after `new`.
    pub fn with_instant_rst_flag(mut self, flag: Arc<std::sync::atomic::AtomicBool>) -> Self {
        self.instant_rst_flag = Some(flag);
        self
    }

    /// Attaches the ISP block-page rule-candidates live gate, same no-replan
    /// contract as `with_instant_rst_flag`. Chain after `new`.
    pub fn with_isp_block_candidates_flag(
        mut self,
        flag: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        self.isp_block_candidates_flag = Some(flag);
        self
    }

    /// Block D (S4.7) — attaches the fake-IP live-apply hook so a toggle (or a
    /// mode flip) reconciles the stack live (no restart). Chain after `new`.
    pub fn with_fake_ip_apply(
        mut self,
        apply: Arc<dyn Fn(FakeIpApplyRequest) + Send + Sync>,
    ) -> Self {
        self.fake_ip_apply = Some(apply);
        self
    }

    /// Attaches the Track-1 liveness tracker so a window change takes effect
    /// live (no restart). Chain after `new`.
    pub fn with_liveness_tracker(
        mut self,
        tracker: Arc<crate::secondary_liveness::SecondaryLivenessTracker>,
    ) -> Self {
        self.liveness_tracker = Some(tracker);
        self
    }

    /// Attaches the Mode-B resolver controller so an `enforcement_mode` change
    /// starts/stops the local DNS resolver live (no restart). Chain after `new`.
    pub fn with_resolver_controller(
        mut self,
        controller: Arc<crate::dns_resolver_service::DnsResolverController>,
    ) -> Self {
        self.resolver_controller = Some(controller);
        self
    }

    /// Attaches the live tracing-verbosity seam so a `verbose_logging`
    /// change takes effect live (no restart). Chain after `new`.
    pub fn with_verbosity_control(
        mut self,
        control: Arc<dyn crate::verbosity_control::VerbosityControl>,
    ) -> Self {
        self.verbosity_control = Some(control);
        self
    }

    fn record_to_dto(rec: &IpcAcceptPolicyRecord) -> IpcAcceptFailurePolicyDto {
        match *rec {
            IpcAcceptPolicyRecord::Recoverable {
                max_restarts,
                backoff_base_ms,
                backoff_cap_ms,
            } => IpcAcceptFailurePolicyDto::Recoverable {
                max_restarts,
                backoff_base_ms,
                backoff_cap_ms,
            },
            IpcAcceptPolicyRecord::Critical => IpcAcceptFailurePolicyDto::Critical,
        }
    }

    fn dto_to_write(
        dto: &IpcAcceptFailurePolicyDto,
    ) -> Result<IpcAcceptPolicyWrite, SettingsWriteError> {
        match *dto {
            IpcAcceptFailurePolicyDto::Recoverable {
                max_restarts,
                backoff_base_ms,
                backoff_cap_ms,
            } => {
                if let Err(reason) =
                    validate_recoverable_params(max_restarts, backoff_base_ms, backoff_cap_ms)
                {
                    return Err(SettingsWriteError::Invalid(reason.to_string()));
                }
                Ok(IpcAcceptPolicyWrite::Recoverable {
                    max_restarts,
                    backoff_base_ms,
                    backoff_cap_ms,
                })
            }
            IpcAcceptFailurePolicyDto::Critical => Ok(IpcAcceptPolicyWrite::Critical),
        }
    }
}

impl ServiceStabilityConfigProvider for ProductionServiceStability {
    fn get(&self) -> ServiceStabilityConfigDto {
        let default = ServiceStabilityConfigDto::default();
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return default,
        };
        let repo = ServiceStabilityConfigRepository::new(&conn);
        match repo.get_or_default() {
            Ok(rec) => ServiceStabilityConfigDto {
                ipc_accept_policy: Self::record_to_dto(&rec.ipc_accept_policy),
                verbose_logging: rec.verbose_logging,
                conn_trace_ndjson: rec.conn_trace_ndjson,
                conn_trace_gui: rec.conn_trace_gui,
                rule_scope_service_driven: rec.rule_scope_service_driven,
                routing_stop_policy: rec.routing_stop_policy.as_slug().to_string(),
                cache_refresh_interval_secs: rec.cache_refresh_interval_secs,
                enforcement_mode: rec.enforcement_mode.as_slug().to_string(),
                secondary_liveness_window_secs: rec.secondary_liveness_window_secs,
                fake_ip_enabled: rec.fake_ip_enabled,
                dns_via_secondary: rec.dns_via_secondary,
                dns_fast_answers: rec.dns_fast_answers,
                fake_ip_udp_relay: rec.fake_ip_udp_relay,
                fake_ip_instant_rst: rec.fake_ip_instant_rst,
                // A Get always answers with an opinion; `None` on the wire is
                // reserved for "a client is not asking to change this".
                allow_user_rule_edits: Some(rec.allow_user_rule_edits),
                isp_block_candidates_enabled: rec.isp_block_candidates_enabled,
            },
            Err(_) => default,
        }
    }
}

impl ServiceStabilityConfigWriter for ProductionServiceStability {
    fn set(
        &self,
        dto: &ServiceStabilityConfigDto,
        set_by_sid: Option<&str>,
    ) -> Result<ServiceStabilityConfigDto, SettingsWriteError> {
        let write = Self::dto_to_write(&dto.ipc_accept_policy)?;
        // Parse the routing-stop-policy slug at the write boundary. Any
        // unrecognised value (incl. an empty string from an older/degraded
        // client) falls back to the safe `Teardown` default rather than being
        // rejected — teardown never leaves routing/blocks stranded.
        let routing_stop_policy =
            RoutingStopPolicy::from_slug(&dto.routing_stop_policy).unwrap_or_default();
        // Parse the enforcement-mode slug at the write boundary. Any unrecognised
        // value (older/degraded client, manual edit) falls back to the safe
        // `Reactive` default rather than being rejected or silently switching the
        // machine to the invasive resolver mode.
        let enforcement_mode =
            EnforcementMode::from_slug(&dto.enforcement_mode).unwrap_or_default();
        let conn = lock_conn(&self.conn)?;
        let repo = ServiceStabilityConfigRepository::new(&conn);
        // the previous enforcement mode, for the transition log below.
        // The 0714 HW run showed the GUI displaying Mode B while the service ran
        // Mode A with ZERO log evidence of why; a one-line write log makes every
        // future "did my toggle reach the service?" diagnosable from the NDJSON.
        //
        // P2 — same rationale for `verbose_logging`: the 0716 run saved
        // the "Verbose service logging" toggle and the row never left `0`. A
        // symmetric prior→written log line (below, target `nrr::stability`)
        // means the next run can tell in one grep whether the write reached
        // storage at all, instead of only being able to query the DB after
        // the fact.
        let prior_record = repo.get_or_default().ok();
        let prior_mode = prior_record
            .as_ref()
            .map(|r| r.enforcement_mode)
            .unwrap_or_default();
        let prior_verbose = prior_record
            .as_ref()
            .map(|r| r.verbose_logging)
            .unwrap_or(false);
        // Same rationale for the two routing-critical toggles: a  run
        // ended with the GUI showing fake-IP OFF while the service kept the
        // stack alive to shutdown — with no way to tell from the NDJSON whether
        // an OFF write ever arrived. Log prior→written for both, always.
        let prior_fake_ip = prior_record
            .as_ref()
            .map(|r| r.fake_ip_enabled)
            .unwrap_or(false);
        let prior_dns_via_secondary = prior_record
            .as_ref()
            .map(|r| r.dns_via_secondary)
            .unwrap_or(false);
        let prior_dns_fast_answers = prior_record
            .as_ref()
            .map(|r| r.dns_fast_answers)
            .unwrap_or(true);
        let prior_udp_relay = prior_record
            .as_ref()
            .map(|r| r.fake_ip_udp_relay)
            .unwrap_or(false);
        let prior_instant_rst = prior_record
            .as_ref()
            .map(|r| r.fake_ip_instant_rst)
            .unwrap_or(true);
        // The administrative rules lock is the one field whose absence means
        // "do not touch it". Every other field here is replaced wholesale by
        // the full-row Set, which is exactly why this one cannot be: a client
        // saving an unrelated toggle must not be able to lift or impose a lock
        // it never mentioned.
        let prior_allow_user_rule_edits = prior_record
            .as_ref()
            .map(|r| r.allow_user_rule_edits)
            .unwrap_or(true);
        let allow_user_rule_edits = dto
            .allow_user_rule_edits
            .unwrap_or(prior_allow_user_rule_edits);
        // Convert seconds → milliseconds is not needed: schema column
        // already stores milliseconds for both base+cap; seconds-only
        // is the docs-side display unit, not the wire/storage unit.
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        repo.set(
            &write,
            dto.verbose_logging,
            dto.conn_trace_ndjson,
            dto.conn_trace_gui,
            dto.rule_scope_service_driven,
            routing_stop_policy,
            dto.cache_refresh_interval_secs,
            enforcement_mode,
            dto.secondary_liveness_window_secs,
            dto.fake_ip_enabled,
            dto.dns_via_secondary,
            dto.dns_fast_answers,
            dto.fake_ip_udp_relay,
            dto.fake_ip_instant_rst,
            allow_user_rule_edits,
            dto.isp_block_candidates_enabled,
            set_by_sid,
            now_ms,
        )
        .map_err(|e| SettingsWriteError::Storage(e.to_string()))?;
        let written = repo
            .get_or_default()
            .map_err(|e| SettingsWriteError::Storage(e.to_string()))?;
        // apply the (clamped, persisted) liveness window
        // to the live tracker so the change takes effect WITHOUT a service
        // restart. Uses `written` — the value the storage layer actually clamped
        // and persisted — so the tracker and the DB can never disagree.
        if let Some(tracker) = &self.liveness_tracker {
            tracker.set_window_secs(written.secondary_liveness_window_secs as u64);
        }
        // Release the DB lock BEFORE the (potentially slow) resolver start/stop:
        // arming spawns a thread and runs NRPT PowerShell, tearing down joins the
        // serve loop — a few seconds — and holding the settings lock across that
        // would stall other settings RPCs. Mirrors the drop-before-forward
        // pattern the apply-failure-policy writer uses.
        drop(conn);
        // always log the persisted enforcement mode on a config write
        // (info: this is a rare, admin-gated mutation). `resolver_live` says
        // whether the live re-arm below can act at all — `false` here plus a
        // resolver-mode write is the "Mode B stored but cannot arm" smoking gun.
        tracing::info!(
            target: "nrr::dns-resolver",
            prior = prior_mode.as_slug(),
            written = written.enforcement_mode.as_slug(),
            changed = prior_mode != written.enforcement_mode,
            resolver_live = self.resolver_controller.is_some(),
            "service-stability config written (enforcement mode)",
        );
        // P3 — same write, logged for the verbose-logging field.
        // Unlike the P2-era comment this superseded: the EnvFilter is now
        // ALSO reloaded live below when `self.verbosity_control` is wired
        // (`live_reload = true`), so `changed = true` together with
        // `live_reload = true` means the running process's log level just
        // flipped, with no restart required. `live_reload = false` (control
        // not wired — tests / degraded boot) keeps the old behaviour: the
        // preference persists and takes effect on the next service start.
        tracing::info!(
            target: "nrr::stability",
            prior = prior_verbose,
            written = written.verbose_logging,
            changed = prior_verbose != written.verbose_logging,
            live_reload = self.verbosity_control.is_some(),
            "service-stability config written (verbose logging)",
        );
        // P3 — flip the LIVE tracing filter to match the persisted
        // value WITHOUT a service restart. Unconditional (not gated on
        // `changed`) to mirror the resolver-controller call below: applying
        // the current value is idempotent and keeps this call site simple,
        // matching the established pattern for the other two live-apply
        // fields on this struct. Best-effort by construction — see
        // `TracingVerbosityHandle::set_verbose` doc — logging verbosity is
        // never allowed to fail a settings write.
        if let Some(control) = &self.verbosity_control {
            control.set_verbose(written.verbose_logging);
        }
        // start/stop the local DNS resolver to
        // match the persisted enforcement mode WITHOUT a service restart. The
        // controller is idempotent: a redundant Save with the same mode is a
        // no-op and never flaps system DNS. Uses `written.enforcement_mode` (the
        // clamped/persisted value) so runtime and DB never disagree.
        // ASYNC: arming runs NRPT PowerShell (seconds),
        // disarming joins the serve loop; doing it inline held this write's
        // IPC reply past the GUI's 30 s deadline. The write is already
        // persisted at this point — the reply reports the durable state, the
        // resolver reconciles to it in the background (racing writes converge
        // on the last desired mode; see `apply_async`).
        if let Some(controller) = &self.resolver_controller {
            controller.apply_async(written.enforcement_mode);
        }
        // The two routing-critical toggles get the same prior→written line as
        // enforcement mode / verbose: one grep answers "did the toggle reach
        // the service, and did the value actually change?".
        tracing::info!(
            target: "nrr::fake-ip",
            prior = prior_fake_ip,
            written = written.fake_ip_enabled,
            changed = prior_fake_ip != written.fake_ip_enabled,
            "service-stability config written (fake-IP)",
        );
        tracing::info!(
            target: "nrr::dns-resolver",
            prior = prior_dns_via_secondary,
            written = written.dns_via_secondary,
            changed = prior_dns_via_secondary != written.dns_via_secondary,
            "service-stability config written (DNS-over-secondary)",
        );
        // DNS-over-secondary — store the persisted value into the shared live
        // gate. The upstream DNS paths read the flag per query, so this is the
        // whole live apply: no rebuild, no restart, inherently idempotent.
        if let Some(flag) = &self.dns_via_secondary_flag {
            flag.store(
                written.dns_via_secondary,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        tracing::info!(
            target: "nrr::dns-resolver",
            prior = prior_dns_fast_answers,
            written = written.dns_fast_answers,
            changed = prior_dns_fast_answers != written.dns_fast_answers,
            "service-stability config written (fast DNS answers)",
        );
        // Fast DNS answers — same per-query live gate contract as
        // DNS-over-secondary above.
        if let Some(flag) = &self.dns_fast_answers_flag {
            flag.store(
                written.dns_fast_answers,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        // Block D (S4.7) — reconcile the fake-IP stack to the persisted state
        // WITHOUT a service restart, same live-apply contract as the resolver
        // controller above. Desired = toggle ON *and* the resolver mode: the
        // fake answers ride the Mode-B resolver, so a mode flip away from
        // Resolver tears the stack down even while the toggle stays saved.
        // The hook itself is async/best-effort by construction (driver load
        // can take seconds and must never stall this IPC reply).
        //
        // The hook still runs on every write (idempotent re-apply keeps the
        // runtime converged with the DB), but the request also reports which
        // resolve-affecting values REALLY changed so the hook flushes the OS
        // DNS cache only on a genuine transition — a redundant save, or a
        // flow-behavior toggle (UDP relay / instant reset), never changes what
        // names resolve to and must not cost a machine-wide re-resolve wave.
        // The fake-IP trigger compares the EFFECTIVE stack state (toggle AND
        // resolver mode), matching what the stack itself reconciles to: a
        // mode flip away from Resolver with the toggle still saved DOES leave
        // pool addresses cached and unreachable, while flipping the toggle in
        // Reactive mode transitions nothing.
        // Invoked after the DNS live-flag stores above so a flush can never
        // race ahead of the flag values the re-queried answers depend on.
        let prior_fake_ip_effective = prior_fake_ip && prior_mode == EnforcementMode::Resolver;
        let written_fake_ip_effective =
            written.fake_ip_enabled && written.enforcement_mode == EnforcementMode::Resolver;
        let mut dns_flush_reasons: Vec<&'static str> = Vec::new();
        if prior_fake_ip_effective != written_fake_ip_effective {
            dns_flush_reasons.push("fake_ip_enabled");
        }
        if prior_dns_via_secondary != written.dns_via_secondary {
            dns_flush_reasons.push("dns_via_secondary");
        }
        if prior_dns_fast_answers != written.dns_fast_answers {
            dns_flush_reasons.push("dns_fast_answers");
        }
        if let Some(apply) = &self.fake_ip_apply {
            apply(FakeIpApplyRequest {
                desired: written_fake_ip_effective,
                dns_flush_reasons,
            });
        }
        tracing::info!(
            target: "nrr::fake-ip",
            prior = prior_udp_relay,
            written = written.fake_ip_udp_relay,
            changed = prior_udp_relay != written.fake_ip_udp_relay,
            "service-stability config written (fake-IP UDP relay)",
        );
        // Fake-IP UDP relay — unlike the flag-only toggles above, this
        // changes the emitted `ks-fakeip-pool` WFP filters, so the hook must
        // also replan the active SIDs (mirrors `fake_ip_apply`). Applied
        // unconditionally (not gated on `changed`) — idempotent, matches the
        // established pattern for every other live-apply field here.
        if let Some(apply) = &self.udp_relay_apply {
            apply(written.fake_ip_udp_relay);
        }
        // The lock gets the same prior→written line as every other
        // routing-critical toggle: one grep answers "was it lifted, and by
        // which Save?" — the question an administrator asks first when a
        // restricted account starts editing rules again.
        tracing::info!(
            target: "nrr::stability",
            prior = prior_allow_user_rule_edits,
            written = written.allow_user_rule_edits,
            changed = prior_allow_user_rule_edits != written.allow_user_rule_edits,
            requested = ?dto.allow_user_rule_edits,
            "service-stability config written (administrative rules lock)",
        );
        tracing::info!(
            target: "nrr::fake-ip",
            prior = prior_instant_rst,
            written = written.fake_ip_instant_rst,
            changed = prior_instant_rst != written.fake_ip_instant_rst,
            "service-stability config written (fake-IP instant reset)",
        );
        // Fake-IP instant reset — same lightweight live-flag contract as
        // `dns_fast_answers_flag` above: the relay dial path reads this flag
        // fresh per dial, so storing the new value is the whole live apply.
        // No replan (unlike `udp_relay_apply`): the flag never changes the
        // emitted WFP filter set, only which branch a failed dial takes.
        if let Some(flag) = &self.instant_rst_flag {
            flag.store(
                written.fake_ip_instant_rst,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        // ISP block-page rule candidates — same lightweight live-flag
        // contract: the engine reads it fresh per candidate.
        if let Some(flag) = &self.isp_block_candidates_flag {
            flag.store(
                written.isp_block_candidates_enabled,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        Ok(ServiceStabilityConfigDto {
            ipc_accept_policy: Self::record_to_dto(&written.ipc_accept_policy),
            verbose_logging: written.verbose_logging,
            conn_trace_ndjson: written.conn_trace_ndjson,
            conn_trace_gui: written.conn_trace_gui,
            rule_scope_service_driven: written.rule_scope_service_driven,
            routing_stop_policy: written.routing_stop_policy.as_slug().to_string(),
            cache_refresh_interval_secs: written.cache_refresh_interval_secs,
            enforcement_mode: written.enforcement_mode.as_slug().to_string(),
            secondary_liveness_window_secs: written.secondary_liveness_window_secs,
            fake_ip_enabled: written.fake_ip_enabled,
            dns_via_secondary: written.dns_via_secondary,
            dns_fast_answers: written.dns_fast_answers,
            fake_ip_udp_relay: written.fake_ip_udp_relay,
            fake_ip_instant_rst: written.fake_ip_instant_rst,
            allow_user_rule_edits: Some(written.allow_user_rule_edits),
            isp_block_candidates_enabled: written.isp_block_candidates_enabled,
        })
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────
//
// P2 — regression coverage for the "verbose service logging"
// toggle chain. The 0716 HW run saved the toggle and `service_stability_config
// .verbose_logging` never left `0`. The diagnosed root cause (TASKS_RU §16.
// P0.4a) was a lost-update race in the GUI: `ServiceStabilityConfigSet`
// has no sparse-update wire shape (every Set replaces the full row), and two
// panels each doing their own stale Get→Set could clobber each other's field.
// The QML-side fix serialises every patch through one queue
// (`Main.qml::_stabilityPatchQueue`); these tests exercise the storage-boundary
// contract that fix depends on, against the REAL `ProductionServiceStability`
// writer/provider (not the fakes in `service_stability_handlers.rs` tests) —
// there was previously no test in this crate that round-tripped
// `ProductionServiceStability` through real SQLite at all.
#[cfg(test)]
mod service_stability_tests {
    use super::*;
    use nrr_storage::{open_connection, repository::MigrationRunner, SqliteMigrationRunner};
    use tempfile::TempDir;

    /// Opens + migrates a fresh state DB and wraps it the same way
    /// `runtime_deps.rs` wires `ProductionServiceStability` in production.
    fn fresh_conn() -> (TempDir, Arc<Mutex<Connection>>) {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("nrr_service_state.db");
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        (dir, Arc::new(Mutex::new(runner.into_connection())))
    }

    #[test]
    fn verbose_logging_persists_through_production_writer() {
        let (_dir, conn) = fresh_conn();
        let stab = ProductionServiceStability::new(Arc::clone(&conn));

        let base = ServiceStabilityConfigProvider::get(&stab);
        assert!(!base.verbose_logging, "default must be off");

        let mut dto = base;
        dto.verbose_logging = true;
        let written = ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST"))
            .expect("set must succeed");
        assert!(written.verbose_logging, "Set must echo verbose=true");

        let readback = ServiceStabilityConfigProvider::get(&stab);
        assert!(
            readback.verbose_logging,
            "verbose_logging must be durably persisted to service_stability_config"
        );
    }

    /// Proves the get-merge-set contract the QML patch queue relies on: as
    /// long as each Set is preceded by a fresh Get of the PREVIOUS writer's
    /// result (never a stale/concurrent base), two different "panels" writing
    /// disjoint fields in sequence never clobber each other.
    #[test]
    fn sequential_get_merge_set_round_trips_do_not_clobber_each_other() {
        let (_dir, conn) = fresh_conn();
        let stab = ProductionServiceStability::new(Arc::clone(&conn));

        // "Diagnostics" panel: Get → flip verbose_logging only → Set.
        let mut after_diag = ServiceStabilityConfigProvider::get(&stab);
        after_diag.verbose_logging = true;
        let written_diag = ServiceStabilityConfigWriter::set(&stab, &after_diag, Some("S-DIAG"))
            .expect("diagnostics set");
        assert!(written_diag.verbose_logging);
        assert_eq!(written_diag.enforcement_mode, "resolver");

        // "Routing" panel: Get (must observe the diagnostics write) → flip
        // enforcement_mode only → Set.
        let mut after_routing = ServiceStabilityConfigProvider::get(&stab);
        assert!(
            after_routing.verbose_logging,
            "routing panel's Get must see the diagnostics panel's prior Set"
        );
        // Flip AWAY from the default: writing the value the row already holds
        // would pass even if the write were dropped entirely.
        after_routing.enforcement_mode = "reactive".to_string();
        let written_routing =
            ServiceStabilityConfigWriter::set(&stab, &after_routing, Some("S-ROUTE"))
                .expect("routing set");
        assert!(
            written_routing.verbose_logging,
            "routing panel's Set must not clobber the diagnostics panel's verbose flag"
        );
        assert_eq!(written_routing.enforcement_mode, "reactive");

        let final_state = ServiceStabilityConfigProvider::get(&stab);
        assert!(final_state.verbose_logging);
        assert_eq!(final_state.enforcement_mode, "reactive");
    }

    /// P3 — proves `set()` drives the live tracing-reload
    /// seam through `VerbosityControl::set_verbose`, using a fake recorder
    /// instead of a real `tracing_subscriber` reload handle (that path is
    /// covered separately in `nrr_diagnostics::logs::tracing_layer`'s own
    /// tests). Records every call so both the "turn on" and "turn off"
    /// directions — and the exact value forwarded — are asserted, not just
    /// "was called at least once".
    #[test]
    fn verbose_logging_set_drives_live_reload() {
        use crate::verbosity_control::VerbosityControl;
        use std::sync::Mutex as StdMutex;

        #[derive(Default)]
        struct FakeVerbosityControl {
            calls: StdMutex<Vec<bool>>,
        }

        impl VerbosityControl for FakeVerbosityControl {
            fn set_verbose(&self, verbose: bool) {
                self.calls
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push(verbose);
            }
        }

        let (_dir, conn) = fresh_conn();
        let fake = Arc::new(FakeVerbosityControl::default());
        let stab = ProductionServiceStability::new(Arc::clone(&conn))
            .with_verbosity_control(Arc::clone(&fake) as Arc<dyn VerbosityControl>);

        let mut dto = ServiceStabilityConfigProvider::get(&stab);
        assert!(!dto.verbose_logging, "default must be off");

        // Flip on.
        dto.verbose_logging = true;
        ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST"))
            .expect("set on must succeed");
        assert_eq!(
            *fake.calls.lock().unwrap(),
            vec![true],
            "set(verbose=true) must drive VerbosityControl::set_verbose(true)"
        );

        // A redundant Save with the SAME value still drives the (idempotent)
        // live-apply call — mirrors the unconditional resolver-controller
        // pattern this seam was modelled on.
        ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST"))
            .expect("redundant set must succeed");
        assert_eq!(*fake.calls.lock().unwrap(), vec![true, true]);

        // Flip off.
        dto.verbose_logging = false;
        ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST"))
            .expect("set off must succeed");
        assert_eq!(
            *fake.calls.lock().unwrap(),
            vec![true, true, false],
            "set(verbose=false) must drive VerbosityControl::set_verbose(false)"
        );
    }

    /// Without a wired `VerbosityControl` (tests / degraded boot), `set()`
    /// must still succeed and persist — the live-apply seam is additive,
    /// never a precondition for the settings write itself.
    #[test]
    fn verbose_logging_set_succeeds_without_verbosity_control_wired() {
        let (_dir, conn) = fresh_conn();
        let stab = ProductionServiceStability::new(Arc::clone(&conn));

        let mut dto = ServiceStabilityConfigProvider::get(&stab);
        dto.verbose_logging = true;
        let written = ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST"))
            .expect("set must succeed with no VerbosityControl wired");
        assert!(written.verbose_logging);
    }

    /// Fake-IP UDP relay — proves `set()` drives the live-apply
    /// hook with the persisted value, same contract proof as the verbose-
    /// logging test above but for `with_udp_relay_apply`.
    #[test]
    fn udp_relay_set_drives_live_apply_with_persisted_value() {
        use std::sync::Mutex as StdMutex;

        let (_dir, conn) = fresh_conn();
        let calls: Arc<StdMutex<Vec<bool>>> = Arc::new(StdMutex::new(Vec::new()));
        let stab = ProductionServiceStability::new(Arc::clone(&conn)).with_udp_relay_apply({
            let calls = Arc::clone(&calls);
            Arc::new(move |desired: bool| {
                calls
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push(desired);
            })
        });

        let base = ServiceStabilityConfigProvider::get(&stab);
        assert!(!base.fake_ip_udp_relay, "default must be off");

        let mut dto = base;
        dto.fake_ip_udp_relay = true;
        let written = ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST"))
            .expect("set on must succeed");
        assert!(written.fake_ip_udp_relay);
        assert_eq!(*calls.lock().unwrap(), vec![true]);

        dto.fake_ip_udp_relay = false;
        ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST"))
            .expect("set off must succeed");
        assert_eq!(*calls.lock().unwrap(), vec![true, false]);

        let readback = ServiceStabilityConfigProvider::get(&stab);
        assert!(!readback.fake_ip_udp_relay, "off must be durably persisted");
    }

    /// The administrative rules lock defaults to permissive and round-trips
    /// through the real writer/provider pair.
    #[test]
    fn rules_lock_defaults_to_allowed_and_round_trips() {
        let (_dir, conn) = fresh_conn();
        let stab = ProductionServiceStability::new(Arc::clone(&conn));

        let base = ServiceStabilityConfigProvider::get(&stab);
        assert_eq!(
            base.allow_user_rule_edits,
            Some(true),
            "a machine nobody configured must let its users edit rules"
        );

        let mut dto = base;
        dto.allow_user_rule_edits = Some(false);
        let written =
            ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-ADMIN")).expect("lock");
        assert_eq!(written.allow_user_rule_edits, Some(false));
        assert_eq!(
            ServiceStabilityConfigProvider::get(&stab).allow_user_rule_edits,
            Some(false),
            "the lock must be durably persisted"
        );

        dto.allow_user_rule_edits = Some(true);
        ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-ADMIN")).expect("unlock");
        assert_eq!(
            ServiceStabilityConfigProvider::get(&stab).allow_user_rule_edits,
            Some(true),
            "an administrator must be able to lift the lock again"
        );
    }

    /// The full-row Set replaces every other field wholesale, which is why
    /// this one is an `Option`: a client saving an unrelated toggle without
    /// mentioning the lock must leave it exactly where the administrator put
    /// it — in BOTH directions, so neither a silent unlock nor a silent lock
    /// can arrive as a side effect.
    #[test]
    fn a_set_that_omits_the_rules_lock_preserves_it() {
        let (_dir, conn) = fresh_conn();
        let stab = ProductionServiceStability::new(Arc::clone(&conn));

        let mut dto = ServiceStabilityConfigProvider::get(&stab);
        dto.allow_user_rule_edits = Some(false);
        ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-ADMIN")).expect("lock");

        // A different panel saves an unrelated toggle with no opinion on the
        // lock (the shape an older client sends).
        dto.allow_user_rule_edits = None;
        dto.verbose_logging = true;
        let written =
            ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-OTHER")).expect("unrelated set");
        assert!(written.verbose_logging, "the unrelated field must be saved");
        assert_eq!(
            written.allow_user_rule_edits,
            Some(false),
            "an omitted lock must never lift an administrator's lock"
        );

        // Same in the other direction: an omitted field must not impose a lock
        // on a machine that never had one.
        let (_dir2, conn2) = fresh_conn();
        let stab2 = ProductionServiceStability::new(Arc::clone(&conn2));
        let mut open = ServiceStabilityConfigProvider::get(&stab2);
        open.allow_user_rule_edits = None;
        let written2 =
            ServiceStabilityConfigWriter::set(&stab2, &open, Some("S-OTHER")).expect("set");
        assert_eq!(written2.allow_user_rule_edits, Some(true));
    }

    /// Without a wired live-apply hook (tests / degraded boot), `set()` must
    /// still succeed and persist — the seam is additive, never a precondition.
    #[test]
    fn udp_relay_set_succeeds_without_apply_hook_wired() {
        let (_dir, conn) = fresh_conn();
        let stab = ProductionServiceStability::new(Arc::clone(&conn));

        let mut dto = ServiceStabilityConfigProvider::get(&stab);
        dto.fake_ip_udp_relay = true;
        let written = ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST"))
            .expect("set must succeed with no udp-relay apply hook wired");
        assert!(written.fake_ip_udp_relay);
    }

    /// Fake-IP instant reset — proves `set()` drives the live
    /// flag with the persisted value, same contract proof as the UDP-relay
    /// test above but for `with_instant_rst_flag` (a stored `AtomicBool`, not
    /// a replan closure — see the field doc on `instant_rst_flag`).
    #[test]
    fn instant_rst_set_drives_live_flag_with_persisted_value() {
        let (_dir, conn) = fresh_conn();
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let stab = ProductionServiceStability::new(Arc::clone(&conn))
            .with_instant_rst_flag(Arc::clone(&flag));

        let base = ServiceStabilityConfigProvider::get(&stab);
        assert!(base.fake_ip_instant_rst, "default must be on");

        let mut dto = base;
        dto.fake_ip_instant_rst = false;
        let written = ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST"))
            .expect("set off must succeed");
        assert!(!written.fake_ip_instant_rst);
        assert!(
            !flag.load(std::sync::atomic::Ordering::Relaxed),
            "the live flag must observe the OFF write immediately"
        );

        dto.fake_ip_instant_rst = true;
        ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST"))
            .expect("set on must succeed");
        assert!(flag.load(std::sync::atomic::Ordering::Relaxed));

        let readback = ServiceStabilityConfigProvider::get(&stab);
        assert!(readback.fake_ip_instant_rst, "on must be durably persisted");
    }

    /// Without a wired live-flag seam (tests / degraded boot), `set()` must
    /// still succeed and persist — the seam is additive, never a precondition.
    #[test]
    fn instant_rst_set_succeeds_without_flag_wired() {
        let (_dir, conn) = fresh_conn();
        let stab = ProductionServiceStability::new(Arc::clone(&conn));

        let mut dto = ServiceStabilityConfigProvider::get(&stab);
        dto.fake_ip_instant_rst = false;
        let written = ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST"))
            .expect("set must succeed with no instant-rst flag wired");
        assert!(!written.fake_ip_instant_rst);
    }

    /// One `(desired, dns_flush_reasons)` entry per `set()` observed by the
    /// recording fake-IP apply hook.
    type FakeIpHookCalls = Arc<Mutex<Vec<(bool, Vec<&'static str>)>>>;

    /// Wires a recording fake-IP apply hook and returns the shared call log
    /// of `(desired, dns_flush_reasons)` per `set()`.
    fn stab_with_recording_fake_ip_hook(
        conn: &Arc<Mutex<Connection>>,
    ) -> (ProductionServiceStability, FakeIpHookCalls) {
        let calls: FakeIpHookCalls = Arc::new(Mutex::new(Vec::new()));
        let stab = ProductionServiceStability::new(Arc::clone(conn)).with_fake_ip_apply({
            let calls = Arc::clone(&calls);
            Arc::new(move |req: FakeIpApplyRequest| {
                calls
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push((req.desired, req.dns_flush_reasons));
            })
        });
        (stab, calls)
    }

    /// A redundant save (no value changed) must still drive the live-apply
    /// hook (runtime/DB convergence contract) but must NOT request an OS DNS
    /// cache flush — flushing on every unrelated settings write forces a
    /// machine-wide re-resolve wave for nothing.
    #[test]
    fn redundant_set_requests_no_dns_cache_flush() {
        let (_dir, conn) = fresh_conn();
        let (stab, calls) = stab_with_recording_fake_ip_hook(&conn);

        let dto = ServiceStabilityConfigProvider::get(&stab);
        ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST"))
            .expect("redundant set must succeed");

        let calls = calls.lock().unwrap();
        assert_eq!(
            calls.len(),
            1,
            "the live-apply hook must still run on a redundant save"
        );
        assert!(
            calls[0].1.is_empty(),
            "no resolve-affecting value changed — no flush must be requested"
        );
    }

    /// Flow-behavior toggles (UDP relay, instant reset) change how existing
    /// flows behave, never which addresses names resolve to — flipping them
    /// must not request a flush.
    #[test]
    fn relay_and_instant_rst_changes_request_no_dns_cache_flush() {
        let (_dir, conn) = fresh_conn();
        let (stab, calls) = stab_with_recording_fake_ip_hook(&conn);

        let mut dto = ServiceStabilityConfigProvider::get(&stab);
        dto.fake_ip_udp_relay = !dto.fake_ip_udp_relay;
        dto.fake_ip_instant_rst = !dto.fake_ip_instant_rst;
        ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST")).expect("set must succeed");

        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(
            calls[0].1.is_empty(),
            "relay/instant-rst flips are flow-behavior only — no flush"
        );
    }

    /// An effective fake-IP transition (toggle flip while the resolver mode is
    /// active) must request exactly one flush, attributed to the toggle; the
    /// same toggle flipped in Reactive mode transitions nothing and must not.
    #[test]
    fn fake_ip_enabled_change_requests_dns_cache_flush() {
        let (_dir, conn) = fresh_conn();
        let (stab, calls) = stab_with_recording_fake_ip_hook(&conn);

        // Enable: reactive/off -> resolver/on is an effective false -> true.
        let mut dto = ServiceStabilityConfigProvider::get(&stab);
        dto.enforcement_mode = "resolver".to_string();
        dto.fake_ip_enabled = true;
        ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST")).expect("set on");
        assert_eq!(
            *calls.lock().unwrap(),
            vec![(true, vec!["fake_ip_enabled"])],
            "an effective enable must request a flush attributed to the toggle"
        );

        // Disable the toggle only: effective true -> false, flush again.
        dto.fake_ip_enabled = false;
        ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST")).expect("set off");
        assert_eq!(
            calls.lock().unwrap()[1],
            (false, vec!["fake_ip_enabled"]),
            "an effective disable must request a flush too"
        );

        // Back to Reactive first, then flip the toggle: the stack never runs
        // in Reactive, so neither write after the mode change transitions it.
        dto.enforcement_mode = "reactive".to_string();
        ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST")).expect("set reactive");
        dto.fake_ip_enabled = true;
        ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST")).expect("toggle in reactive");
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 4);
        assert!(
            calls[2].1.is_empty() && calls[3].1.is_empty(),
            "no effective stack transition in Reactive mode — no flush"
        );
    }

    /// The client-resolve DNS toggles request a flush when (and only when)
    /// their persisted value changes; several changes in one write coalesce
    /// into ONE hook call carrying every trigger — one flush per Set.
    #[test]
    fn dns_toggle_changes_request_single_flush_with_reasons() {
        let (_dir, conn) = fresh_conn();
        let (stab, calls) = stab_with_recording_fake_ip_hook(&conn);

        let mut dto = ServiceStabilityConfigProvider::get(&stab);
        dto.dns_via_secondary = !dto.dns_via_secondary;
        dto.dns_fast_answers = !dto.dns_fast_answers;
        ServiceStabilityConfigWriter::set(&stab, &dto, Some("S-TEST")).expect("set must succeed");

        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "one Set — one hook call, one flush");
        assert_eq!(
            calls[0].1,
            vec!["dns_via_secondary", "dns_fast_answers"],
            "both changed toggles must be reported as the flush reason"
        );
    }
}
