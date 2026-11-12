//! Bounded, owner-scoped TLS confirmation outside traffic handling.

use crate::boot_clock::BootInstant;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use nrr_platform_api::conn_observe::egress::EgressRole;
use nrr_platform_api::conn_observe::{ConnectionObservation, ConnectionProgress};

use crate::auto_rules::{AutoRulesEngine, DiscoveryDecision};
use crate::observed_host_names::{HostNameResolution, ObservedHostNames};
use crate::path_probe::{PathProbe, PathVerdict, ProbeLimits};
use crate::per_sid_orchestrator::RulesProvider;
use crate::production_auto_rule_probe::EgressSources;
use crate::service_tasks::AutoProbeCadence;

const MAX_FLOWS: usize = 4096;
const MAX_RECENT: usize = 1024;
const FLOW_TTL: Duration = Duration::from_secs(120);
const MAX_WORKERS: usize = 2;
type FlowKey = (SocketAddr, SocketAddr);
type ProbeKey = (String, String);

mod dispatch;
mod http;
mod scheduler;
use scheduler::{Bucket, Lease, Pending, Recent};

pub fn stored_probe_limits(
    state: Arc<Mutex<rusqlite::Connection>>,
) -> Arc<dyn Fn(&str) -> ProbeLimits + Send + Sync> {
    Arc::new(move |owner| {
        let guard = state.lock().unwrap_or_else(|p| p.into_inner());
        match nrr_storage::route_bindings::RouteBindingsRepository::new(&guard).load_for_sid(owner)
        {
            Ok(record) => ProbeLimits::new(
                Duration::from_millis(u64::from(record.primary_probe_timeout_ms)),
                record.primary_probe_max_targets as usize,
                Duration::from_secs(u64::from(record.primary_probe_repeat_secs)),
            ),
            Err(_) => ProbeLimits::default(),
        }
    })
}

pub fn stored_primary_default(
    state: Arc<Mutex<rusqlite::Connection>>,
) -> Arc<dyn Fn(&str) -> bool + Send + Sync> {
    Arc::new(move |owner| {
        let guard = state.lock().unwrap_or_else(|p| p.into_inner());
        nrr_storage::route_bindings::RouteBindingsRepository::new(&guard)
            .load_for_sid(owner)
            .is_ok_and(|record| {
                record.mode == nrr_storage::route_bindings::BehaviorMode::PreferPrimary
                    && !crate::production_rules_provider::keeps_names_off_main(&record)
            })
    })
}

pub fn stored_primary_probe_guard(
    state: Arc<Mutex<rusqlite::Connection>>,
) -> crate::production_auto_rule_probe::PrimaryProbeGuard {
    let primary = stored_primary_default(Arc::clone(&state));
    let rules = crate::production_rules_provider::ProductionRulesProvider::new(state);
    Arc::new(move |owner, host, address| {
        if !primary(owner) {
            return false;
        }
        let Some(snapshot) = rules.active_rules_for(owner) else {
            return false;
        };
        match nrr_domain::decision_engine_input::match_sample(
            &snapshot.rule_book,
            Some(host),
            Some(address.into()),
            None,
            nrr_domain::decision_matching::ZonePriorityPolicy::default(),
            nrr_domain::RouteBehaviorMode::PreferPrimary,
        ) {
            nrr_domain::decision_matching::RequestedRouteDecision::MatchedRoute { candidate } => {
                candidate.route_role == nrr_shared::RouteRole::Primary
                    && candidate.action == nrr_domain::RuleAction::Route
            }
            nrr_domain::decision_matching::RequestedRouteDecision::DefaultRoute { .. } => !snapshot
                .rule_book
                .primary
                .rules()
                .iter()
                .chain(snapshot.rule_book.secondary.rules())
                .any(|rule| rule.enabled && rule.app_match.is_some()),
        }
    })
}

struct Flow {
    owner: String,
    ours: bool,
    at: BootInstant,
    role: EgressRole,
    process: Option<String>,
    pid: u32,
}

#[derive(Default)]
struct Memory {
    flows: HashMap<FlowKey, Flow>,
    recent: HashMap<ProbeKey, Recent>,
    budgets: HashMap<String, Bucket>,
    pending: VecDeque<Pending>,
    in_flight: HashMap<ProbeKey, BootInstant>,
    sequence: u64,
    global_budget: Option<Bucket>,
    last_owner: Option<String>,
    probe_started: HashMap<ProbeKey, i64>,
}

#[derive(Clone)]
struct Reservation {
    owner: String,
    hostname: String,
    started_at: BootInstant,
    owns_worker: bool,
    repeat: Duration,
    pending: Option<Pending>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReservationRefusal {
    Cooldown,
    BudgetExhausted,
    MemoryLimit,
    WorkersBusy,
}

impl ReservationRefusal {
    fn reason(self) -> &'static str {
        match self {
            Self::Cooldown => "probe-cooldown",
            Self::BudgetExhausted => "probe-budget-exhausted",
            Self::MemoryLimit => "probe-memory-limit",
            Self::WorkersBusy => "probe-workers-busy",
        }
    }
}

/// The existing policy, route and network ports shared by both compositions.
pub struct DiscoveryObservationWiring {
    pub engine: Arc<AutoRulesEngine>,
    pub rules: Arc<dyn RulesProvider>,
    pub names: Arc<ObservedHostNames>,
    pub egress: Arc<dyn EgressSources>,
    pub probe: Arc<dyn PathProbe>,
    pub cadence: Arc<dyn Fn(&str) -> AutoProbeCadence + Send + Sync>,
    pub limits: Arc<dyn Fn(&str) -> ProbeLimits + Send + Sync>,
    pub primary_default: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    pub passive_reset_available: bool,
    pub os_cache_available: bool,
}

pub struct DiscoveryObservationPipeline {
    wiring: Arc<DiscoveryObservationWiring>,
    memory: Arc<Mutex<Memory>>,
    workers: Arc<AtomicUsize>,
    pumping: Arc<AtomicBool>,
    queue_source_attached: Arc<AtomicBool>,
    https: Option<Arc<dyn crate::site_check::HttpsHead>>,
}

#[derive(Clone)]
struct Confirmation {
    owner: String,
    host: String,
    destination: String,
    target: Ipv4Addr,
    source: Ipv4Addr,
    secondary: Option<Ipv4Addr>,
    timeout: Duration,
    process: Option<String>,
    shared_address: bool,
}

enum ConfirmationOutcome {
    Finished,
    RulesUnavailable,
}

impl ConfirmationOutcome {
    fn refused(reason: &str) -> Self {
        if reason == "rules-unavailable" {
            Self::RulesUnavailable
        } else {
            Self::Finished
        }
    }
}

impl DiscoveryObservationPipeline {
    fn shared(&self) -> Self {
        Self {
            wiring: Arc::clone(&self.wiring),
            memory: Arc::clone(&self.memory),
            workers: Arc::clone(&self.workers),
            pumping: Arc::clone(&self.pumping),
            queue_source_attached: Arc::clone(&self.queue_source_attached),
            https: self.https.clone(),
        }
    }
    pub fn name_for_owner(&self, owner: Option<&str>, address: Ipv4Addr) -> Option<String> {
        match self.wiring.names.resolve_for(owner?, address) {
            HostNameResolution::Unique(host) => Some(host),
            _ => None,
        }
    }

    pub fn new(wiring: DiscoveryObservationWiring) -> Self {
        let mut limitations = Vec::new();
        if !wiring.passive_reset_available {
            limitations.push("passive-reset-unavailable");
        }
        if !wiring.os_cache_available {
            limitations.push("os-dns-cache-unavailable");
        }
        wiring.engine.set_discovery_limitations(&limitations);
        Self {
            wiring: Arc::new(wiring),
            memory: Arc::new(Mutex::new(Memory::default())),
            workers: Arc::new(AtomicUsize::new(0)),
            pumping: Arc::new(AtomicBool::new(false)),
            queue_source_attached: Arc::new(AtomicBool::new(false)),
            https: None,
        }
    }

    /// Optional application-response capability; an absent client never proves an HTTP answer.
    #[must_use]
    pub fn with_https(mut self, https: Option<Arc<dyn crate::site_check::HttpsHead>>) -> Self {
        self.https = https;
        self
    }

    fn attach_queue_source(&self) {
        if self.queue_source_attached.swap(true, Ordering::AcqRel) {
            return;
        }
        let pipeline = self;
        let wiring = Arc::downgrade(&pipeline.wiring);
        let memory = Arc::clone(&pipeline.memory);
        let workers = Arc::clone(&pipeline.workers);
        let needs_secondary = pipeline.https.is_some();
        pipeline.wiring.engine.set_discovery_queue_source(Arc::new(move |owner| {
            let Some(wiring) = wiring.upgrade() else { return HashMap::new() };
            let cadence = (wiring.cadence)(owner);
            if !wiring.engine.learns_for(owner) || !cadence.enabled || !(wiring.primary_default)(owner) {
                return HashMap::new();
            }
            let pending: Vec<_> = memory.lock().unwrap_or_else(|p| p.into_inner()).pending.iter()
                .filter(|entry| entry.confirmation.owner == owner).cloned().collect();
            if pending.is_empty() { return HashMap::new(); }
            let (primary, secondary) = wiring.egress.egress_source_ips(owner);
            let rules = wiring.rules.active_rules_for(owner);
            let mut valid: HashMap<_, _> = pending.into_iter().filter(|entry| {
                let value = &entry.confirmation;
                let independent = needs_secondary || value.shared_address || !matches!(wiring.names.resolve_for(owner, value.target), HostNameResolution::Unique(ref host) if host == &value.host);
                primary.is_some()
                    && (!independent || (secondary.is_some() && secondary != primary))
                    && value.process.is_some()
                    && matches!(Self::rules_refusal(rules.as_ref(), &value.host, value.target.into(), value.process.as_deref()), None | Some("rules-unavailable"))
                    && wiring.names.probe_names_for(owner, value.target).contains(&value.host)
            }).map(|entry| (entry.confirmation.host.clone(), entry)).collect();
            let identity = valid.iter().map(|(host, entry)| (host.clone(), (entry.sequence, entry.version))).collect();
            let snapshot = {
                let mut guard = memory.lock().unwrap_or_else(|p| p.into_inner());
                guard.update_repeat(owner, cadence.repeat);
                guard.queue_snapshot(owner, BootInstant::now(), workers.load(Ordering::Acquire), &identity)
            };
            snapshot.into_iter().filter_map(|(host, mut status)| valid.remove(&host).map(|entry| {
                if rules.is_none() {
                    status.wait_kind = nrr_shared::ipc_payloads::ProbeQueueWaitKindDto::Rules;
                    status.queued_ahead = 0;
                    status.eligible_in_ms = None;
                }
                (host, crate::auto_rules::QueuedProbeSnapshot {
                    status, destination: entry.confirmation.destination,
                    first_seen_unix_ms: entry.queued_unix_ms,
                    last_seen_unix_ms: entry.witnessed_unix_ms,
                    sequence: entry.sequence,
                })
            })).collect()
        }));
    }

    pub fn observe(&self, observation: &ConnectionObservation, role: EgressRole) {
        self.observe_inner(observation, role, true);
    }

    pub(crate) fn enqueue_observation(
        &self,
        observation: &ConnectionObservation,
        role: EgressRole,
    ) {
        self.observe_inner(observation, role, false);
    }

    fn observe_inner(&self, observation: &ConnectionObservation, role: EgressRole, dispatch: bool) {
        if crate::app_observation_lookup::is_own_process(observation.pid) {
            return;
        }
        self.attach_queue_source();
        if observation.protocol != nrr_platform_api::conn_observe::TransportProtocol::Tcp {
            return;
        }
        let now = BootInstant::now();
        let key = (observation.local, observation.remote);
        let mut memory = self.memory.lock().unwrap_or_else(|p| p.into_inner());
        memory
            .flows
            .retain(|_, flow| now.saturating_duration_since(flow.at) < FLOW_TTL);
        if observation
            .user_sid
            .as_deref()
            .is_some_and(nrr_platform_api::types::is_service_account_sid)
        {
            memory.flows.remove(&key);
            return;
        }
        let explicit = observation
            .user_sid
            .as_deref()
            .filter(|sid| !sid.is_empty() && !nrr_platform_api::types::is_service_account_sid(sid));
        if memory.flows.get(&key).is_some_and(|flow| {
            explicit.is_some_and(|owner| owner != flow.owner)
                || (observation.pid != 0 && flow.pid != 0 && observation.pid != flow.pid)
        }) {
            memory.flows.remove(&key);
        }
        if observation.progress == ConnectionProgress::Attempt {
            memory.flows.remove(&key);
            if let Some(owner) = explicit {
                if memory.flows.len() >= MAX_FLOWS && !memory.flows.contains_key(&key) {
                    if let Some(oldest) = memory
                        .flows
                        .iter()
                        .min_by_key(|(_, flow)| flow.at)
                        .map(|(key, _)| *key)
                    {
                        memory.flows.remove(&oldest);
                    }
                }
                let ours = observation.blocked_by_nrr == Some(true);
                let process = observation.process_path.clone();
                memory.flows.insert(
                    key,
                    Flow {
                        owner: owner.to_owned(),
                        ours,
                        at: now,
                        role,
                        process,
                        pid: observation.pid,
                    },
                );
            }
        }
        let Some(owner) = explicit
            .map(str::to_owned)
            .or_else(|| memory.flows.get(&key).map(|flow| flow.owner.clone()))
        else {
            return;
        };
        let ours = observation.blocked_by_nrr == Some(true)
            || memory.flows.get(&key).is_some_and(|flow| flow.ours)
            || crate::own_flow_resets::global_own_flow_resets()
                .contains(observation.local, observation.remote);
        let mut role = memory.flows.get(&key).map_or(role, |flow| flow.role);
        let process = observation
            .process_path
            .clone()
            .or_else(|| memory.flows.get(&key).and_then(|flow| flow.process.clone()));
        if matches!(
            observation.progress,
            ConnectionProgress::ClosedUnknown
                | ConnectionProgress::Reset
                | ConnectionProgress::ClosedInOrder
        ) {
            memory.flows.remove(&key);
        }
        drop(memory);
        if matches!(role, EgressRole::Unknown | EgressRole::Other) {
            let (primary, _) = self.wiring.egress.egress_source_ips(&owner);
            if primary.is_some_and(|ip| observation.local.ip() == IpAddr::V4(ip)) {
                role = EgressRole::Primary;
            }
        }
        let destination = format!("{} -> {}", observation.local, observation.remote);
        let resolution = match observation.remote.ip() {
            IpAddr::V4(ip) => self.wiring.names.resolve_for(&owner, ip),
            IpAddr::V6(_) => HostNameResolution::Unknown,
        };
        let hostname = match &resolution {
            HostNameResolution::Unique(host) => Some(host.as_str()),
            _ => None,
        };
        let note = |stage, state, reason| {
            self.wiring.engine.note_discovery(
                &owner,
                hostname,
                Some(&destination),
                DiscoveryDecision::new(stage, state, reason),
                SystemTime::now(),
            )
        };
        if ours {
            note("health", "hidden", "own-block");
            return;
        }
        if role != EgressRole::Primary {
            return;
        }
        if !self.wiring.engine.learns_for(&owner) {
            note("candidate", "not-created", "discovery-disabled");
            return;
        }
        match &resolution {
            HostNameResolution::Unknown => {
                note("name", "not-created", "name-unknown");
                return;
            }
            HostNameResolution::Ambiguous => {
                note("name", "not-created", "name-ambiguous");
                self.investigate_shared(observation, &owner, &destination, process, now, dispatch);
                return;
            }
            HostNameResolution::Unique(_) => {}
        }
        let Some(hostname) = hostname else {
            return;
        };
        match observation.progress {
            ConnectionProgress::Reset => note("health", "deferred", "connection-reset"),
            ConnectionProgress::ClosedUnknown => note("health", "deferred", "close-unknown"),
            _ => {
                note("health", "deferred", "insufficient-evidence");
                return;
            }
        }
        if observation.remote.port() != 443 {
            return;
        }
        let cadence = (self.wiring.cadence)(&owner);
        if !cadence.enabled {
            note("probe", "not-created", "auto-probe-disabled");
            return;
        }
        if let Some(reason) = Self::confirmation_refusal(
            &self.wiring,
            &owner,
            hostname,
            observation.remote.ip(),
            process.as_deref(),
        ) {
            note("candidate", Self::refusal_state(reason), reason);
            if reason != "rules-unavailable" {
                return;
            }
        }
        let (Some(source), secondary) = self.wiring.egress.egress_source_ips(&owner) else {
            note("probe", "deferred", "probe-inconclusive");
            return;
        };
        let limits = (self.wiring.limits)(&owner);
        let IpAddr::V4(target) = observation.remote.ip() else {
            note("probe", "not-created", "probe-inconclusive");
            return;
        };
        let hostname = hostname.to_owned();
        self.enqueue_confirmation(
            Confirmation {
                owner,
                host: hostname,
                destination,
                target,
                source,
                secondary,
                timeout: limits.timeout,
                process,
                shared_address: false,
            },
            now,
        );
        if dispatch {
            self.pump();
        }
    }

    fn investigate_shared(
        &self,
        observation: &ConnectionObservation,
        owner: &str,
        destination: &str,
        process: Option<String>,
        now: BootInstant,
        dispatch: bool,
    ) {
        if observation.remote.port() != 443
            || !matches!(
                observation.progress,
                ConnectionProgress::Attempt
                    | ConnectionProgress::Reset
                    | ConnectionProgress::ClosedUnknown
            )
        {
            return;
        }
        let IpAddr::V4(target) = observation.remote.ip() else {
            return;
        };
        let cadence = (self.wiring.cadence)(owner);
        if !cadence.enabled {
            self.wiring.engine.note_discovery(
                owner,
                None,
                Some(destination),
                DiscoveryDecision::new("probe", "not-created", "auto-probe-disabled"),
                SystemTime::now(),
            );
            return;
        }
        let (Some(source), secondary) = self.wiring.egress.egress_source_ips(owner) else {
            self.wiring.engine.note_discovery(
                owner,
                None,
                Some(destination),
                DiscoveryDecision::new("probe", "deferred", "probe-inconclusive"),
                SystemTime::now(),
            );
            return;
        };
        if secondary.is_none() || secondary == Some(source) {
            let reason = if secondary.is_none() {
                "secondary-unavailable"
            } else {
                "probe-inconclusive"
            };
            self.wiring.engine.note_discovery(
                owner,
                None,
                Some(destination),
                DiscoveryDecision::new("probe", "deferred", reason),
                SystemTime::now(),
            );
            return;
        }
        let limits = (self.wiring.limits)(owner);
        for host in self.wiring.names.probe_names_for(owner, target) {
            let refusal = Self::confirmation_refusal(
                &self.wiring,
                owner,
                &host,
                target.into(),
                process.as_deref(),
            );
            if let Some(reason) = refusal {
                self.wiring.engine.note_discovery(
                    owner,
                    Some(&host),
                    Some(destination),
                    DiscoveryDecision::new("candidate", Self::refusal_state(reason), reason),
                    SystemTime::now(),
                );
                if reason != "rules-unavailable" {
                    continue;
                }
            }
            self.enqueue_confirmation(
                Confirmation {
                    owner: owner.to_owned(),
                    host,
                    destination: destination.to_owned(),
                    target,
                    source,
                    secondary,
                    timeout: limits.timeout,
                    process: process.clone(),
                    shared_address: true,
                },
                now,
            );
        }
        if dispatch {
            self.pump();
        }
    }

    fn enqueue_confirmation(&self, confirmation: Confirmation, now: BootInstant) {
        let owner = confirmation.owner.clone();
        let host = confirmation.host.clone();
        let destination = confirmation.destination.clone();
        let unix_ms = crate::conn_observation_consumer::now_unix_ms()
            .try_into()
            .unwrap_or(i64::MAX);
        let result = self
            .memory
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .enqueue(confirmation, now, unix_ms);
        let (state, reason) = match result {
            Ok(()) => ("deferred", "probe-queued"),
            Err(ReservationRefusal::MemoryLimit) => ("not-created", "probe-memory-limit"),
            Err(reason) => ("deferred", reason.reason()),
        };
        self.wiring.engine.note_discovery(
            &owner,
            Some(&host),
            Some(&destination),
            DiscoveryDecision::new("probe", state, reason),
            SystemTime::now(),
        );
    }

    fn note_pending(&self, pending: &Pending, state: &'static str, reason: &'static str) {
        let confirmation = &pending.confirmation;
        self.wiring.engine.note_discovery(
            &confirmation.owner,
            Some(&confirmation.host),
            Some(&confirmation.destination),
            DiscoveryDecision::new("probe", state, reason),
            SystemTime::now(),
        );
    }

    #[cfg(test)]
    fn start_confirmation(
        &self,
        confirmation: Confirmation,
        reservation: Reservation,
        spawn: impl FnOnce(Box<dyn FnOnce() + Send>) -> std::io::Result<std::thread::JoinHandle<()>>,
    ) {
        self.start_confirmations(vec![(confirmation, reservation)], spawn);
    }

    #[cfg(test)]
    fn start_confirmations(
        &self,
        batch: Vec<(Confirmation, Reservation)>,
        spawn: impl FnOnce(Box<dyn FnOnce() + Send>) -> std::io::Result<std::thread::JoinHandle<()>>,
    ) {
        self.start_confirmations_with_check(batch, None, spawn);
    }

    fn start_confirmations_with_check(
        &self,
        batch: Vec<(Confirmation, Reservation)>,
        check: Option<Arc<dispatch::Check>>,
        spawn: impl FnOnce(Box<dyn FnOnce() + Send>) -> std::io::Result<std::thread::JoinHandle<()>>,
    ) {
        if batch.is_empty() {
            return;
        }
        struct Release(Arc<AtomicUsize>);
        impl Drop for Release {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::AcqRel);
            }
        }
        let worker = Release(Arc::clone(&self.workers));
        let failed: Vec<_> = batch
            .iter()
            .map(|(confirmation, reservation)| {
                (reservation.clone(), confirmation.destination.clone())
            })
            .collect();
        let wiring = Arc::clone(&self.wiring);
        let https = self.https.clone();
        let pipeline = self.shared();
        let memory = Arc::clone(&self.memory);
        let work: Vec<_> = batch
            .into_iter()
            .map(|(confirmation, reservation)| {
                (confirmation, Lease::new(Arc::clone(&memory), reservation))
            })
            .collect();
        #[cfg(test)]
        let simulated_sleep = crate::boot_clock::simulated_sleep();
        let spawned = spawn(Box::new(move || {
            #[cfg(test)]
            crate::boot_clock::simulate_sleep(simulated_sleep);
            let _release = worker;
            let mut work: VecDeque<_> = work.into();
            while let Some((confirmation, mut lease)) = work.pop_front() {
                let owner = confirmation.owner.clone();
                let host = confirmation.host.clone();
                let destination = confirmation.destination.clone();
                let start = || {
                    wiring.engine.note_discovery(
                        &owner,
                        Some(&host),
                        Some(&destination),
                        DiscoveryDecision::new("probe", "deferred", "probe-pending"),
                        SystemTime::now(),
                    );
                    lease.started();
                };
                let outcome = if let Some(https) = https.as_deref() {
                    Self::confirm_http(&wiring, confirmation, https, start)
                } else {
                    Self::confirm_with_start(&wiring, confirmation, start)
                };
                let measured = lease.has_started();
                if matches!(outcome, ConfirmationOutcome::RulesUnavailable) {
                    lease.defer_for_rules();
                } else {
                    lease.finish(true);
                }
                if let Some(check) = &check {
                    if !measured {
                        check.refund(&owner);
                    }
                    if let Some((confirmation, reservation)) =
                        pipeline.next_confirmation(check, false)
                    {
                        work.push_back((
                            confirmation,
                            Lease::new(Arc::clone(&memory), reservation),
                        ));
                    }
                }
            }
        }));
        if let Err(error) = spawned {
            for (reservation, destination) in failed {
                let retained = reservation.pending.is_some();
                self.wiring.engine.note_discovery(
                    &reservation.owner,
                    Some(&reservation.hostname),
                    Some(&destination),
                    DiscoveryDecision::new(
                        "probe",
                        if retained { "deferred" } else { "not-created" },
                        if retained {
                            "probe-queued"
                        } else {
                            "probe-start-failed"
                        },
                    ),
                    SystemTime::now(),
                );
                tracing::warn!(target: "nrr::auto-rules", msg_key = "prod-autorule-probe-spawn-failed", sid = %reservation.owner, error = %error, "could not start the main-link probe pass");
            }
        }
    }

    fn confirmation_refusal(
        wiring: &DiscoveryObservationWiring,
        owner: &str,
        hostname: &str,
        ip: IpAddr,
        process: Option<&str>,
    ) -> Option<&'static str> {
        if !wiring.engine.learns_for(owner) {
            return Some("discovery-disabled");
        }
        if !(wiring.primary_default)(owner) {
            return Some("already-covered");
        }
        if process.is_none() {
            return Some("probe-inconclusive");
        }
        let snapshot = wiring.rules.active_rules_for(owner);
        Self::rules_refusal(snapshot.as_ref(), hostname, ip, process)
    }

    fn rules_refusal(
        snapshot: Option<&crate::per_sid_orchestrator::ActiveRulesSnapshot>,
        hostname: &str,
        ip: IpAddr,
        process: Option<&str>,
    ) -> Option<&'static str> {
        let Some(snapshot) = snapshot else {
            return Some("rules-unavailable");
        };
        if snapshot
            .rule_book
            .primary
            .rules()
            .iter()
            .chain(snapshot.rule_book.secondary.rules())
            .any(|rule| {
                rule.enabled
                    && rule
                        .app_match
                        .as_ref()
                        .is_some_and(|app| app.include_child_processes)
            })
        {
            return Some("probe-inconclusive");
        }
        (!matches!(
            nrr_domain::decision_engine_input::match_sample(
                &snapshot.rule_book,
                Some(hostname),
                Some(ip),
                process,
                nrr_domain::decision_matching::ZonePriorityPolicy::default(),
                nrr_domain::RouteBehaviorMode::PreferPrimary
            ),
            nrr_domain::decision_matching::RequestedRouteDecision::DefaultRoute { .. }
        ))
        .then_some("already-covered")
    }

    fn refusal_state(reason: &str) -> &'static str {
        match reason {
            "discovery-disabled" | "auto-probe-disabled" => "not-created",
            "probe-inconclusive" | "rules-unavailable" => "deferred",
            _ => "hidden",
        }
    }

    #[cfg(test)]
    fn reserve(
        &self,
        owner: &str,
        hostname: &str,
        repeat: Duration,
        now: BootInstant,
    ) -> Result<Reservation, ReservationRefusal> {
        self.reserve_for_batch(owner, hostname, repeat, now, true)
    }

    fn reserve_for_batch(
        &self,
        owner: &str,
        hostname: &str,
        repeat: Duration,
        now: BootInstant,
        acquire_worker: bool,
    ) -> Result<Reservation, ReservationRefusal> {
        if acquire_worker
            && self
                .workers
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    (count < MAX_WORKERS).then_some(count + 1)
                })
                .is_err()
        {
            return Err(ReservationRefusal::WorkersBusy);
        }
        let result = self
            .memory
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .reserve(owner, hostname, repeat, now);
        if let Err(reason) = result {
            if acquire_worker {
                self.workers.fetch_sub(1, Ordering::AcqRel);
            }
            return Err(reason);
        }
        Ok(Reservation {
            owner: owner.to_owned(),
            hostname: hostname.to_owned(),
            started_at: now,
            owns_worker: acquire_worker,
            repeat,
            pending: None,
        })
    }

    fn rollback_reservation(&self, reservation: Reservation) {
        self.memory
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .release(&reservation, false, BootInstant::now(), true);
        if reservation.owns_worker {
            self.workers.fetch_sub(1, Ordering::AcqRel);
        }
    }

    #[cfg(test)]
    fn confirm(wiring: &DiscoveryObservationWiring, confirmation: Confirmation) {
        Self::confirm_with_start(wiring, confirmation, || {});
    }

    fn confirm_with_start(
        wiring: &DiscoveryObservationWiring,
        confirmation: Confirmation,
        start: impl FnOnce(),
    ) -> ConfirmationOutcome {
        let Confirmation {
            owner,
            host,
            destination,
            target,
            source,
            secondary,
            timeout,
            process,
            shared_address,
        } = confirmation;
        let (owner, host, destination) = (owner.as_str(), host.as_str(), destination.as_str());
        let note = |state, reason| {
            wiring.engine.note_discovery(
                owner,
                Some(host),
                Some(destination),
                DiscoveryDecision::new("probe", state, reason),
                SystemTime::now(),
            )
        };
        let refusal = || {
            (!(wiring.cadence)(owner).enabled)
                .then_some("auto-probe-disabled")
                .or_else(|| {
                    Self::confirmation_refusal(
                        wiring,
                        owner,
                        host,
                        target.into(),
                        process.as_deref(),
                    )
                })
                .or_else(|| {
                    (wiring.egress.egress_source_ips(owner) != (Some(source), secondary)
                        || !wiring
                            .names
                            .probe_names_for(owner, target)
                            .iter()
                            .any(|name| name == host))
                    .then_some("probe-inconclusive")
                })
        };
        let independent = || {
            shared_address
                || !matches!(wiring.names.resolve_for(owner, target),
            HostNameResolution::Unique(ref name) if name == host)
        };
        if let Some(reason) = refusal() {
            note(Self::refusal_state(reason), reason);
            return ConfirmationOutcome::refused(reason);
        }
        if !(wiring.cadence)(owner).enabled {
            note("not-created", "auto-probe-disabled");
            return ConfirmationOutcome::Finished;
        }
        start();
        let verdict = wiring.probe.probe_tls(target, host, Some(source), timeout);
        if let Some(reason) = refusal() {
            note(Self::refusal_state(reason), reason);
            return ConfirmationOutcome::refused(reason);
        }
        if !wiring.engine.learns_for(owner) {
            note("not-created", "discovery-disabled");
            return ConfirmationOutcome::Finished;
        }
        match verdict {
            PathVerdict::Answered => {
                if let Some(reason) = refusal() {
                    note(Self::refusal_state(reason), reason);
                    return ConfirmationOutcome::refused(reason);
                }
                if independent() {
                    wiring.engine.withdraw_shared_address_reachability(
                        owner,
                        host,
                        SystemTime::now(),
                    );
                    note("not-created", "primary-responds");
                    return ConfirmationOutcome::Finished;
                }
                note("deferred", "https-unconfirmed");
                return ConfirmationOutcome::Finished;
            }
            PathVerdict::Indeterminate => {
                note("deferred", "probe-inconclusive");
                return ConfirmationOutcome::Finished;
            }
            PathVerdict::Silent => {}
        }
        for _ in 0..2 {
            if let Some(reason) = refusal() {
                note(Self::refusal_state(reason), reason);
                return ConfirmationOutcome::refused(reason);
            }
            if !(wiring.cadence)(owner).enabled {
                note("not-created", "auto-probe-disabled");
                return ConfirmationOutcome::Finished;
            }
            let verdict = wiring.probe.probe_tls(target, host, Some(source), timeout);
            if let Some(reason) = refusal() {
                note(Self::refusal_state(reason), reason);
                return ConfirmationOutcome::refused(reason);
            }
            if !wiring.engine.learns_for(owner) {
                note("not-created", "discovery-disabled");
                return ConfirmationOutcome::Finished;
            }
            if verdict != PathVerdict::Silent {
                if independent() && verdict == PathVerdict::Answered {
                    if let Some(reason) = refusal() {
                        note(Self::refusal_state(reason), reason);
                        return ConfirmationOutcome::refused(reason);
                    }
                    wiring.engine.withdraw_shared_address_reachability(
                        owner,
                        host,
                        SystemTime::now(),
                    );
                    note("not-created", "primary-responds");
                    return ConfirmationOutcome::Finished;
                }
                note("deferred", "probe-inconclusive");
                return ConfirmationOutcome::Finished;
            }
        }
        let Some(secondary) = secondary else {
            note("deferred", "secondary-unavailable");
            return ConfirmationOutcome::Finished;
        };
        if let Some(reason) = refusal() {
            note(Self::refusal_state(reason), reason);
            return ConfirmationOutcome::refused(reason);
        }
        if !(wiring.cadence)(owner).enabled {
            note("not-created", "auto-probe-disabled");
            return ConfirmationOutcome::Finished;
        }
        let verdict = wiring
            .probe
            .probe_tls(target, host, Some(secondary), timeout);
        if let Some(reason) = refusal() {
            note(Self::refusal_state(reason), reason);
            return ConfirmationOutcome::refused(reason);
        }
        if !wiring.engine.learns_for(owner) {
            note("not-created", "discovery-disabled");
            return ConfirmationOutcome::Finished;
        }
        match verdict {
            PathVerdict::Answered => {
                if let Some(reason) = refusal() {
                    note(Self::refusal_state(reason), reason);
                    return ConfirmationOutcome::refused(reason);
                }
                if !(wiring.cadence)(owner).enabled {
                    note("not-created", "auto-probe-disabled");
                    return ConfirmationOutcome::Finished;
                }
                if independent() {
                    wiring
                        .engine
                        .note_shared_address_reachability(owner, host, SystemTime::now());
                    return ConfirmationOutcome::Finished;
                }
                use nrr_domain::companion_affinity::PrimaryHealthEvent;
                let stalls = crate::primary_stall_registry::global_primary_stalls();
                if let Some(report) = stalls.note_verified_tls(owner, host, false, 3) {
                    crate::primary_stall_registry::log_report(owner, &report);
                }
                for _ in 0..3 {
                    wiring
                        .engine
                        .note_primary_health(owner, host, PrimaryHealthEvent::Stalled);
                }
                let navigation = crate::navigation_registry::global_navigation();
                navigation.sweep(crate::conn_observation_consumer::now_unix_ms());
                let reached = navigation.counts_of(Some(owner), host);
                let now = SystemTime::now();
                if wiring
                    .engine
                    .note_main_link_blocked_host(owner, host, reached, now)
                {
                    wiring.engine.note_secondary_reach(owner, host, true, now);
                }
            }
            PathVerdict::Silent => {
                if independent() {
                    wiring.engine.withdraw_shared_address_reachability(
                        owner,
                        host,
                        SystemTime::now(),
                    );
                }
                note("not-created", "secondary-failed");
            }
            PathVerdict::Indeterminate => note("deferred", "probe-inconclusive"),
        }
        ConfirmationOutcome::Finished
    }
}

#[cfg(test)]
mod tests;
