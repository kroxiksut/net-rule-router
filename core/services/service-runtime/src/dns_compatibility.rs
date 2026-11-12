//! Current owner-scoped DNS evidence; closing a notification never resolves it.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

use nrr_domain::dns_compatibility::{Ledger, Observation};
use nrr_shared::ipc_payloads::{
    DnsCompatibilityDto, DnsCompatibilityIssueDto, DnsCompatibilityStatus, DnsResolverReadinessDto,
    StatusUpdateEvent,
};

const MAX_PRINCIPALS: usize = 16;
const MAX_PRINCIPAL_BYTES: usize = 256;
const MAX_SEQUENCE: u64 = 9_007_199_254_740_991;

pub(crate) fn now_ms() -> u64 {
    u64::try_from(crate::timed_window::now_ms()).unwrap_or(0)
}

#[derive(Debug, Default)]
struct PrincipalState {
    sequence: u64,
    ledger: Ledger,
    last_seen_ms: u64,
    last_checked_ms: Option<u64>,
    verified_at: Option<u64>,
    verified_program: Option<String>,
    verified_route: Option<nrr_shared::RouteRole>,
    clock_invalidated: bool,
    network_invalidated: bool,
    recovery_pending: bool,
    recheck_active: bool,
    resolver: DnsResolverReadinessDto,
    last_push_ms: Option<u64>,
    push_pending: bool,
    push_spawn_failed_at: Option<Instant>,
    last_recheck: Option<Instant>,
    browser_settings: Vec<nrr_shared::browser_dns_settings::BrowserDnsSettingsDto>,
    secondary_ready: Option<bool>,
    confirmation_started: Option<Instant>,
}

pub type SecondaryStatus = Arc<dyn Fn(&str) -> Option<bool> + Send + Sync>;
pub type ProgramNormalizer = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

#[derive(Default)]
pub struct DnsCompatibilityCenter {
    network_watch_available: AtomicBool,
    network_generation: AtomicU64,
    instance_id: std::sync::OnceLock<String>,
    sequence: AtomicU64,
    principals: Mutex<BTreeMap<String, PrincipalState>>,
    resolver: RwLock<Option<Weak<crate::dns_resolver_service::DnsResolverController>>>,
    events: RwLock<Option<Arc<crate::ipc_handlers::event_bus::EventBus>>>,
    last_recovery: Mutex<Option<Instant>>,
    browser_settings:
        RwLock<Option<Arc<dyn nrr_platform_api::browser_dns_settings::BrowserDnsSettingsPort>>>,
    secondary_status: RwLock<Option<SecondaryStatus>>,
    known_resolvers: std::sync::OnceLock<crate::own_resolver_watch::KnownResolvers>,
    program_normalizer: RwLock<Option<ProgramNormalizer>>,
}

impl DnsCompatibilityCenter {
    pub(crate) fn set_network_watch_available(&self, available: bool) {
        self.invalidate_network_with_watch(Some(available));
    }

    pub(crate) fn invalidate_network(&self) {
        self.invalidate_network_with_watch(None);
    }

    fn invalidate_network_with_watch(&self, available: Option<bool>) {
        let at_ms = now_ms();
        let owners = {
            let mut states = self.principals.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(available) = available {
                self.network_watch_available
                    .store(available, Ordering::Relaxed);
            }
            self.network_generation.fetch_add(1, Ordering::Relaxed);
            for state in states.values_mut() {
                state.network_invalidated = true;
                state.resolver = DnsResolverReadinessDto::default();
                state.secondary_ready = None;
                state.verified_at = None;
                state.verified_program = None;
                state.verified_route = None;
                state.confirmation_started = None;
                state.ledger.invalidate_path_proofs();
                state.recovery_pending = false;
                state.last_seen_ms = state.last_seen_ms.max(at_ms);
                state.sequence = self.next_sequence();
            }
            states.keys().cloned().collect::<Vec<_>>()
        };
        for owner in owners {
            self.publish(&owner, at_ms);
        }
    }

    fn awaiting_browser_confirmation(&self) -> bool {
        self.principals
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .any(|state| {
                state.confirmation_started.is_some_and(|at| {
                    at.elapsed()
                        <= Duration::from_millis(
                            nrr_domain::dns_compatibility::BROWSER_CONFIRMATION_MS,
                        )
                })
            })
    }

    pub fn arm_browser_confirmation(
        &self,
        principal: &str,
        host: &str,
        route: nrr_shared::RouteRole,
    ) -> bool {
        if principal.is_empty()
            || principal.len() > MAX_PRINCIPAL_BYTES
            || crate::site_check::normalise_host(host).as_deref() != Some(host)
        {
            return false;
        }
        let at_ms = now_ms();
        let mut principals = self.principals.lock().unwrap_or_else(|p| p.into_inner());
        if principals.len() >= MAX_PRINCIPALS && !principals.contains_key(principal) {
            return false;
        }
        let state = principals.entry(principal.to_owned()).or_default();
        if !state
            .ledger
            .request_browser_confirmation(host, route, at_ms)
        {
            return false;
        }
        state.confirmation_started = Some(Instant::now());
        state.verified_at = None;
        state.verified_program = None;
        state.verified_route = None;
        state.last_seen_ms = state.last_seen_ms.max(at_ms);
        state.sequence = self.next_sequence();
        drop(principals);
        self.publish(principal, at_ms);
        true
    }

    #[cfg(test)]
    fn confirm_browser_path(
        &self,
        principal: &str,
        program: &str,
        host: &str,
        route: nrr_shared::RouteRole,
        at_ms: u64,
    ) -> bool {
        self.confirm_browser_path_in_generation(
            principal,
            program,
            host,
            route,
            at_ms,
            self.network_generation.load(Ordering::Relaxed),
        )
    }

    fn confirm_browser_path_in_generation(
        &self,
        principal: &str,
        program: &str,
        host: &str,
        route: nrr_shared::RouteRole,
        at_ms: u64,
        generation: u64,
    ) -> bool {
        let Some(identity) = self.program_identity(program) else {
            return false;
        };
        let mut principals = self.principals.lock().unwrap_or_else(|p| p.into_inner());
        if self.network_generation.load(Ordering::Relaxed) != generation
            || !self.network_watch_available.load(Ordering::Relaxed)
        {
            return false;
        }
        let Some(state) = principals.get_mut(principal) else {
            return false;
        };
        if !state.confirmation_started.is_some_and(|at| {
            at.elapsed()
                <= Duration::from_millis(nrr_domain::dns_compatibility::BROWSER_CONFIRMATION_MS)
        }) {
            return false;
        }
        if !state
            .ledger
            .confirm_browser_path(&identity, host, route, at_ms)
        {
            return false;
        }
        state.verified_at = Some(at_ms);
        state.verified_program = Some(identity.into_owned());
        state.verified_route = Some(route);
        state.clock_invalidated = false;
        state.network_invalidated = false;
        if route == nrr_shared::RouteRole::Secondary
            && state.last_checked_ms.is_none_or(|at| at <= at_ms)
        {
            state.secondary_ready = Some(true);
        }
        state.last_seen_ms = state.last_seen_ms.max(at_ms);
        state.sequence = self.next_sequence();
        drop(principals);
        self.publish(principal, now_ms());
        true
    }

    fn instance_id(&self) -> &str {
        self.instance_id.get_or_init(|| {
            let mut bytes = [0_u8; 16];
            if getrandom::fill(&mut bytes).is_err() {
                return String::new();
            }
            let hex = b"0123456789abcdef";
            bytes
                .into_iter()
                .flat_map(|byte| {
                    [
                        char::from(hex[usize::from(byte >> 4)]),
                        char::from(hex[usize::from(byte & 15)]),
                    ]
                })
                .collect()
        })
    }

    fn next_sequence(&self) -> u64 {
        self.sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_add(1).min(MAX_SEQUENCE))
            })
            .unwrap_or(MAX_SEQUENCE)
            .saturating_add(1)
            .min(MAX_SEQUENCE)
    }

    fn program_identity<'a>(&self, program: &'a str) -> Option<std::borrow::Cow<'a, str>> {
        use std::borrow::Cow;
        if program.is_empty() || program.len() > nrr_domain::dns_compatibility::MAX_PROGRAM_BYTES {
            return None;
        }
        let normalize = self
            .program_normalizer
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let normalized = match normalize {
            Some(normalize) => Cow::Owned(normalize(program)?),
            None => Cow::Borrowed(program),
        };
        (!normalized.is_empty()
            && normalized.len() <= nrr_domain::dns_compatibility::MAX_PROGRAM_BYTES)
            .then_some(normalized)
    }

    pub fn observe_connection(
        self: &Arc<Self>,
        record: &crate::conn_observation_consumer::ConnectionTraceRecord,
        now_ms: u64,
    ) {
        let Some(principal) = record
            .user_sid
            .as_deref()
            .filter(|sid| !sid.is_empty() && !nrr_platform_api::types::is_service_account_sid(sid))
        else {
            return;
        };
        let Some(program) = record.process_path.as_deref() else {
            return;
        };
        let confirmed_block =
            record.blocked_by_nrr == Some(true) && record.nrr_block_reason == Some("dns-lockdown");
        let known = self
            .known_resolvers
            .get_or_init(crate::own_resolver_watch::KnownResolvers::builtin);
        let contact =
            nrr_domain::own_resolver::is_resolver_contact(record.remote, known.lists(record));
        let reason = if confirmed_block {
            nrr_domain::dns_compatibility::Reason::OurDnsBlock
        } else if contact {
            nrr_domain::dns_compatibility::Reason::ResolverContact
        } else {
            return;
        };
        let accepted = self.observe_received(
            principal,
            program,
            Observation::Problem(reason),
            record.observed_unix_ms.unwrap_or(now_ms),
            now_ms,
        );
        if accepted && confirmed_block {
            self.request_recheck(principal);
        }
    }

    pub fn observe(
        self: &Arc<Self>,
        principal: &str,
        program: &str,
        observation: Observation,
        now_ms: u64,
    ) {
        self.observe_received(principal, program, observation, now_ms, now_ms);
    }

    fn observe_received(
        self: &Arc<Self>,
        principal: &str,
        program: &str,
        observation: Observation,
        now_ms: u64,
        received_ms: u64,
    ) -> bool {
        if principal.is_empty()
            || principal.len() > MAX_PRINCIPAL_BYTES
            || program.is_empty()
            || program.len() > nrr_domain::dns_compatibility::MAX_PROGRAM_BYTES
        {
            return false;
        }
        let Some(identity) = self.program_identity(program) else {
            return false;
        };
        let program = identity.as_ref();
        let mut principals = self.principals.lock().unwrap_or_else(|p| p.into_inner());
        if !matches!(observation, Observation::Problem(_)) && !principals.contains_key(principal) {
            return false;
        }
        if !principals.contains_key(principal) && principals.len() >= MAX_PRINCIPALS {
            let oldest = principals
                .iter()
                .filter(|(_, p)| !p.recheck_active && !p.push_pending)
                .min_by_key(|(_, p)| p.last_seen_ms)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                principals.remove(&oldest);
            } else {
                return false;
            }
        }
        let state = principals.entry(principal.to_owned()).or_default();
        if !matches!(observation, Observation::Problem(_))
            && !state
                .ledger
                .snapshot(now_ms)
                .iter()
                .any(|row| row.program == program)
        {
            return false;
        }
        let was_verified = state.verified_at.is_some();
        let evidence_current = now_ms >= state.last_seen_ms;
        if !state
            .ledger
            .observe_received(program, observation, now_ms, received_ms)
        {
            return false;
        }
        state.last_seen_ms = state.last_seen_ms.max(received_ms);
        match observation {
            Observation::Problem(_) | Observation::BrowserSystemDnsVerified => {
                state.verified_at = None;
                state.verified_program = None;
                state.verified_route = None;
            }
            Observation::BrowserPathVerified if evidence_current => {
                state.verified_at = Some(now_ms);
                state.verified_program = Some(program.to_owned());
                state.verified_route = None;
            }
            _ => {}
        }
        state.sequence = self.next_sequence();
        let publish = was_verified
            || !matches!(observation, Observation::Problem(_))
            || state
                .last_push_ms
                .is_none_or(|at| received_ms < at || received_ms - at >= 1000);
        let schedule = !publish
            && !state.push_pending
            && state
                .push_spawn_failed_at
                .is_none_or(|at| at.elapsed() >= Duration::from_secs(1))
            && self
                .events
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .is_some();
        let delay = Duration::from_millis(
            1000_u64.saturating_sub(
                state
                    .last_push_ms
                    .map_or(0, |at| received_ms.saturating_sub(at)),
            ),
        );
        if publish {
            state.last_push_ms = Some(received_ms);
        }
        if schedule {
            state.push_pending = true;
        }
        drop(principals);
        if publish {
            self.publish(principal, received_ms);
        }
        if schedule {
            self.schedule_push(principal, delay);
        }
        true
    }

    fn schedule_push(self: &Arc<Self>, principal: &str, delay: Duration) {
        let center = Arc::downgrade(self);
        let principal = principal.to_owned();
        let failed = principal.clone();
        if std::thread::Builder::new()
            .name("nrr-dns-compatibility-push".to_owned())
            .spawn(move || {
                std::thread::sleep(delay);
                if let Some(center) = center.upgrade() {
                    center.flush_pending_push(&principal);
                }
            })
            .is_err()
        {
            if let Some(state) = self
                .principals
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get_mut(&failed)
            {
                state.push_spawn_failed_at = Some(Instant::now());
            }
            self.flush_pending_push(&failed);
        }
    }

    fn flush_pending_push(&self, principal: &str) {
        let at_ms = now_ms();
        let mut principals = self.principals.lock().unwrap_or_else(|p| p.into_inner());
        let Some(state) = principals.get_mut(principal) else {
            return;
        };
        if !state.push_pending {
            return;
        }
        state.push_pending = false;
        state.last_push_ms = Some(at_ms);
        drop(principals);
        self.publish(principal, at_ms);
    }

    pub fn attach_resolver(
        &self,
        controller: Arc<crate::dns_resolver_service::DnsResolverController>,
    ) {
        *self.resolver.write().unwrap_or_else(|p| p.into_inner()) =
            Some(Arc::downgrade(&controller));
    }

    pub fn attach_browser_settings(
        &self,
        port: Arc<dyn nrr_platform_api::browser_dns_settings::BrowserDnsSettingsPort>,
    ) {
        *self
            .browser_settings
            .write()
            .unwrap_or_else(|p| p.into_inner()) = Some(port);
    }

    pub fn attach_secondary_status(&self, status: SecondaryStatus) {
        *self
            .secondary_status
            .write()
            .unwrap_or_else(|p| p.into_inner()) = Some(status);
    }

    pub fn attach_program_normalizer(&self, normalizer: ProgramNormalizer) {
        *self
            .program_normalizer
            .write()
            .unwrap_or_else(|p| p.into_inner()) = Some(normalizer);
    }

    pub fn attach_events(&self, events: Arc<crate::ipc_handlers::event_bus::EventBus>) {
        *self.events.write().unwrap_or_else(|p| p.into_inner()) = Some(events);
    }

    fn publish(&self, principal: &str, now_ms: u64) {
        let events = self
            .events
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        if let Some(events) = events {
            events.publish_for(
                principal,
                StatusUpdateEvent::DnsCompatibilityChanged {
                    sid: principal.to_owned(),
                    state: self.snapshot(Some(principal), now_ms),
                },
            );
        }
    }

    pub fn request_recheck(self: &Arc<Self>, principal: &str) -> bool {
        if principal.is_empty() || principal.len() > MAX_PRINCIPAL_BYTES {
            return false;
        }
        let principal = principal.to_owned();
        let generation;
        {
            let mut states = self.principals.lock().unwrap_or_else(|p| p.into_inner());
            if states.len() >= MAX_PRINCIPALS && !states.contains_key(&principal) {
                return false;
            }
            let state = states.entry(principal.clone()).or_default();
            generation = self.network_generation.load(Ordering::Relaxed);
            if state.recheck_active
                || state
                    .last_recheck
                    .is_some_and(|at| at.elapsed() < Duration::from_secs(30))
            {
                return false;
            }
            state.last_recheck = Some(Instant::now());
            state.recovery_pending = true;
            state.recheck_active = true;
            state.sequence = self.next_sequence();
        }
        self.publish(&principal, now_ms());
        let center = Arc::clone(self);
        let failed = principal.clone();
        if std::thread::Builder::new()
            .name("nrr-dns-compatibility-check".to_owned())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let controller = center
                        .resolver
                        .read()
                        .unwrap_or_else(|p| p.into_inner())
                        .as_ref()
                        .and_then(Weak::upgrade);
                    let resolver = match controller {
                        Some(controller) => {
                            let first = controller.inspect_readiness();
                            if first.listener == "unavailable" {
                                let mut last = center
                                    .last_recovery
                                    .lock()
                                    .unwrap_or_else(|p| p.into_inner());
                                if last.is_none_or(|at| at.elapsed() >= Duration::from_secs(30)) {
                                    *last = Some(Instant::now());
                                    drop(last);
                                    controller.try_tick();
                                    for delay in [100, 250, 500] {
                                        std::thread::sleep(Duration::from_millis(delay));
                                        if controller.inspect_readiness().listener != "unavailable"
                                        {
                                            break;
                                        }
                                    }
                                }
                            }
                            controller.inspect_readiness()
                        }
                        None => DnsResolverReadinessDto::default(),
                    };
                    let browser = center
                        .browser_settings
                        .read()
                        .unwrap_or_else(|p| p.into_inner())
                        .clone();
                    let settings = browser.map_or_else(Vec::new, |port| {
                        port.inspect(&principal).into_iter().take(3).collect()
                    });
                    let secondary = center
                        .secondary_status
                        .read()
                        .unwrap_or_else(|p| p.into_inner())
                        .clone();
                    let secondary = secondary.and_then(|read| read(&principal));
                    (resolver, settings, secondary)
                }))
                .unwrap_or_default();
                center.finish_recheck(&principal, generation, result.0, result.1, result.2);
            })
            .is_err()
        {
            self.finish_recheck(
                &failed,
                generation,
                DnsResolverReadinessDto::default(),
                Vec::new(),
                None,
            );
        }
        true
    }

    fn finish_recheck(
        &self,
        principal: &str,
        generation: u64,
        result: DnsResolverReadinessDto,
        browser_settings: Vec<nrr_shared::browser_dns_settings::BrowserDnsSettingsDto>,
        secondary: Option<bool>,
    ) {
        let now_ms = now_ms();
        {
            let mut states = self.principals.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(state) = states.get_mut(principal) {
                state.recheck_active = false;
            }
            if self.network_generation.load(Ordering::Relaxed) != generation {
                return;
            }
            let watched = self.network_watch_available.load(Ordering::Relaxed);
            let result = if watched {
                result
            } else {
                DnsResolverReadinessDto::default()
            };
            let secondary = secondary.filter(|_| watched);
            if let Some(state) = states.get_mut(principal) {
                let programs = state.ledger.snapshot(now_ms);
                for program in programs {
                    if result.listener == "unavailable"
                        || result.redirect == "unavailable"
                        || result.upstream == "unavailable"
                    {
                        state.ledger.observe(
                            &program.program,
                            Observation::Problem(
                                nrr_domain::dns_compatibility::Reason::LocalResolverUnavailable,
                            ),
                            now_ms,
                        );
                    } else if result.listener == "ready"
                        && result.redirect == "ready"
                        && result.upstream == "ready"
                    {
                        state
                            .ledger
                            .observe(&program.program, Observation::SystemDnsReady, now_ms);
                    }
                }
                state.resolver = result;
                state.network_invalidated = !watched;
                state.browser_settings = browser_settings;
                state.secondary_ready = secondary;
                state.last_checked_ms = Some(now_ms);
                state.recovery_pending = false;
                state.last_seen_ms = now_ms;
                state.sequence = self.next_sequence();
            }
        }
        self.publish(principal, now_ms);
    }

    #[must_use]
    pub fn snapshot(&self, principal: Option<&str>, now_ms: u64) -> DnsCompatibilityDto {
        let mut principals = self.principals.lock().unwrap_or_else(|p| p.into_inner());
        let Some(state) = principal.and_then(|key| principals.get_mut(key)) else {
            return DnsCompatibilityDto::default();
        };
        if now_ms < state.last_seen_ms && !state.clock_invalidated {
            state.clock_invalidated = true;
            state.sequence = self.next_sequence();
        }
        let programs = state.ledger.snapshot(now_ms);
        let mut issues = Vec::new();
        for row in programs {
            for issue in row.issues {
                issues.push(DnsCompatibilityIssueDto {
                    program: row.program.clone(),
                    reason: issue.reason.slug().to_owned(),
                    evidence: if issue.reason.confirmed() {
                        "confirmed"
                    } else {
                        "suspected"
                    }
                    .to_owned(),
                    first_seen_ms: issue.first_seen_ms,
                    last_seen_ms: issue.last_seen_ms,
                    attempts: issue.attempts,
                    needs_recheck: row.needs_recheck,
                });
            }
        }
        let network_unchecked =
            state.network_invalidated || !self.network_watch_available.load(Ordering::Relaxed);
        let verified = state.verified_at.is_some_and(|at| {
            now_ms
                .checked_sub(at)
                .is_some_and(|age| age <= nrr_domain::dns_compatibility::RECHECK_AFTER_MS)
        }) && !state.clock_invalidated
            && !network_unchecked
            && (state.verified_route != Some(nrr_shared::RouteRole::Secondary)
                || state.secondary_ready != Some(false))
            && state
                .verified_program
                .as_ref()
                .is_some_and(|program| state.ledger.has_current_path_proof(program))
            && !self.instance_id().is_empty()
            && state.sequence < MAX_SEQUENCE;
        let stale_check = state.last_checked_ms.is_some_and(|at| {
            now_ms
                .checked_sub(at)
                .is_none_or(|age| age > nrr_domain::dns_compatibility::RECHECK_AFTER_MS)
        });
        let status = if stale_check || state.clock_invalidated || network_unchecked {
            DnsCompatibilityStatus::NeedsRecheck
        } else if state.resolver.listener == "unavailable"
            || state.resolver.redirect == "unavailable"
            || state.resolver.upstream == "unavailable"
        {
            DnsCompatibilityStatus::Limited
        } else if issues.iter().any(|issue| issue.needs_recheck) {
            DnsCompatibilityStatus::NeedsRecheck
        } else if issues.iter().any(|issue| issue.evidence == "confirmed") {
            DnsCompatibilityStatus::Limited
        } else if issues.is_empty() && verified {
            DnsCompatibilityStatus::Verified
        } else {
            DnsCompatibilityStatus::Unchecked
        };
        DnsCompatibilityDto {
            status,
            issues,
            last_checked_ms: state.last_checked_ms,
            instance_id: self.instance_id().to_owned(),
            sequence: state.sequence,
            history_incomplete: false,
            verified_program: state
                .verified_program
                .as_ref()
                .filter(|_| verified && !stale_check)
                .cloned(),
            recovery_pending: state.recovery_pending,
            resolver: if stale_check || state.clock_invalidated || network_unchecked {
                DnsResolverReadinessDto::default()
            } else {
                state.resolver.clone()
            },
            browser_settings: state.browser_settings.clone(),
            secondary_readiness: match state
                .secondary_ready
                .filter(|_| !stale_check && !state.clock_invalidated && !network_unchecked)
            {
                Some(true) => "ready",
                Some(false) => "unavailable",
                None => "unchecked",
            }
            .to_owned(),
            available_actions: nrr_shared::ipc_payloads::dns_compatibility_actions(),
        }
    }
}

/// Receives successful relay dials, never the client's local TCP handshake.
pub struct DnsCompatibilityFlowObserver {
    pub center: Arc<DnsCompatibilityCenter>,
    pub owners: Arc<dyn nrr_platform_api::FlowOwnerLookup>,
    pub routing: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    pub served: crate::fake_ip::ServedPrincipalsFn,
    pub sources: Arc<dyn crate::production_auto_rule_probe::EgressSources>,
}

impl crate::fake_ip::FlowObserver for DnsCompatibilityFlowObserver {
    fn network_generation(&self) -> Option<u64> {
        Some(self.center.network_generation.load(Ordering::Relaxed))
    }

    fn on_flow_opened(
        &self,
        _: std::net::SocketAddr,
        _: std::net::SocketAddr,
        _: &str,
        _: Option<&str>,
    ) {
    }

    fn on_upstream_connected(
        &self,
        client: std::net::SocketAddr,
        fake: std::net::SocketAddr,
        target: &crate::fake_ip::dialer::UpstreamTarget,
        generation: Option<u64>,
        actual_source: Option<std::net::IpAddr>,
    ) {
        let Some(generation) = generation else {
            return;
        };
        if !self.center.awaiting_browser_confirmation() {
            return;
        }
        let connected_at_ms = now_ms();
        let Some((principal, program)) = self.owners.owner_identity(client, fake) else {
            return;
        };
        if nrr_platform_api::types::is_service_account_sid(&principal)
            || !(self.served)().iter().any(|sid| sid == &principal)
        {
            return;
        }
        let carried_for = target.owner.clone().or_else(|| (self.routing)());
        if carried_for.as_deref() != Some(principal.as_str())
            || target.book_route != Some(target.route)
        {
            return;
        }
        let (primary, secondary) = self.sources.egress_source_ips(&principal);
        let source = match target.route {
            nrr_shared::RouteRole::Primary => primary,
            nrr_shared::RouteRole::Secondary => secondary,
        };
        if source.is_none() || source.map(std::net::IpAddr::V4) != actual_source {
            return;
        }
        self.center.confirm_browser_path_in_generation(
            &principal,
            &program,
            &target.hostname,
            target.route,
            connected_at_ms,
            generation,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_domain::dns_compatibility::Reason;

    #[derive(Default)]
    struct NetworkChange(Mutex<Option<nrr_platform_api::network_change::NetworkChangeCallback>>);

    impl nrr_platform_api::network_change::NetworkChangeObserver for NetworkChange {
        fn subscribe(
            &self,
            callback: nrr_platform_api::network_change::NetworkChangeCallback,
        ) -> Result<
            nrr_platform_api::network_change::NetworkChangeSubscription,
            nrr_platform_api::error::PlatformError,
        > {
            *self.0.lock().expect("network observer") = Some(callback);
            Ok(nrr_platform_api::network_change::NetworkChangeSubscription::inert())
        }
    }

    impl NetworkChange {
        fn fire(&self) {
            let callback = self
                .0
                .lock()
                .expect("network observer")
                .clone()
                .expect("callback");
            callback();
        }
    }

    fn watch_network(
        center: &Arc<DnsCompatibilityCenter>,
    ) -> (
        NetworkChange,
        nrr_platform_api::network_change::NetworkChangeSubscription,
    ) {
        let network = NetworkChange::default();
        let pool = Arc::new(crate::dns_upstream::UpstreamDnsPool::fixed(
            "127.0.0.1:53".parse().expect("address"),
        ));
        let watch = crate::dns_stack::close_upstream_sockets_on_change(
            &network,
            &pool,
            Some(Arc::downgrade(center)),
        )
        .expect("network watch");
        (network, watch)
    }

    fn ready_dns() -> DnsResolverReadinessDto {
        DnsResolverReadinessDto {
            listener: "ready".to_owned(),
            redirect: "ready".to_owned(),
            upstream: "ready".to_owned(),
        }
    }

    #[test]
    fn retaining_dns_diagnostics_cannot_keep_the_runtime_network_subscription_alive() {
        struct SubscriptionLease(std::sync::mpsc::Sender<std::thread::ThreadId>);
        impl Drop for SubscriptionLease {
            fn drop(&mut self) {
                let _ = self.0.send(std::thread::current().id());
            }
        }
        let center = Arc::new(DnsCompatibilityCenter::default());
        let (_initial_network, _initial_watch) = watch_network(&center);
        let controller = Arc::new(crate::dns_resolver_service::DnsResolverController::default());
        let (released, receipt) = std::sync::mpsc::channel();
        let lease = SubscriptionLease(released);
        controller.set_factory(Arc::new(move || {
            let _held = &lease;
            Err(crate::dns_resolver_service::ArmRefusal::Unavailable)
        }));
        center.attach_resolver(Arc::clone(&controller));

        drop(controller);

        assert_eq!(
            receipt.recv_timeout(Duration::from_secs(1)).expect(
                "runtime release must cancel its subscription while diagnostics remain alive"
            ),
            std::thread::current().id()
        );
        assert_eq!(
            center.snapshot(Some("owner"), now_ms()).status,
            DnsCompatibilityStatus::Unchecked
        );
    }

    #[test]
    fn a_failed_network_subscription_cannot_publish_dns_ready_or_browser_verified() {
        struct RefusedNetwork;
        impl nrr_platform_api::network_change::NetworkChangeObserver for RefusedNetwork {
            fn subscribe(
                &self,
                _: nrr_platform_api::network_change::NetworkChangeCallback,
            ) -> Result<
                nrr_platform_api::network_change::NetworkChangeSubscription,
                nrr_platform_api::error::PlatformError,
            > {
                Err(nrr_platform_api::error::PlatformError::Transient {
                    operation: "subscribe",
                    detail: "registration refused".to_owned(),
                })
            }
        }
        let center = Arc::new(DnsCompatibilityCenter::default());
        let (_initial_network, _initial_watch) = watch_network(&center);
        let pool = Arc::new(crate::dns_upstream::UpstreamDnsPool::fixed(
            "127.0.0.1:53".parse().expect("address"),
        ));
        center.observe(
            "owner",
            "browser",
            Observation::Problem(Reason::LocalResolverUnavailable),
            now_ms(),
        );
        assert!(crate::dns_stack::close_upstream_sockets_on_change(
            &RefusedNetwork,
            &pool,
            Some(Arc::downgrade(&center))
        )
        .is_none());
        assert!(center.arm_browser_confirmation(
            "owner",
            "site.example",
            nrr_shared::RouteRole::Secondary
        ));
        center.finish_recheck(
            "owner",
            center.network_generation.load(Ordering::Relaxed),
            ready_dns(),
            Vec::new(),
            Some(true),
        );

        let state = center.snapshot(Some("owner"), now_ms());
        assert_eq!(
            state.resolver.upstream, "unchecked",
            "without change notifications a cached result cannot promise current readiness"
        );
        assert!(
            state
                .issues
                .iter()
                .any(|issue| issue.reason == "local-resolver-unavailable"),
            "an unwatched recheck must retain the resolver failure evidence"
        );
        assert!(!center.confirm_browser_path(
            "owner",
            "browser",
            "site.example",
            nrr_shared::RouteRole::Secondary,
            now_ms()
        ));
        let (_network, _watch) = watch_network(&center);
        assert!(center.arm_browser_confirmation(
            "owner",
            "site.example",
            nrr_shared::RouteRole::Secondary
        ));
        assert!(center.confirm_browser_path(
            "owner",
            "browser",
            "site.example",
            nrr_shared::RouteRole::Secondary,
            now_ms()
        ));
    }

    #[test]
    fn browser_recovery_without_any_network_watch_stays_unverified() {
        let center = Arc::new(DnsCompatibilityCenter::default());
        assert!(center.arm_browser_confirmation(
            "owner",
            "site.example",
            nrr_shared::RouteRole::Secondary
        ));
        assert!(
            !center.confirm_browser_path(
                "owner",
                "browser",
                "site.example",
                nrr_shared::RouteRole::Secondary,
                now_ms()
            ),
            "an unwired observer cannot certify a network-dependent result"
        );
    }

    #[test]
    fn a_socket_on_the_previous_adapter_cannot_certify_the_new_selected_route() {
        use crate::fake_ip::FlowObserver;
        let center = Arc::new(DnsCompatibilityCenter::default());
        let (_network, _watch) = watch_network(&center);
        let observer = DnsCompatibilityFlowObserver {
            center: Arc::clone(&center),
            owners: Arc::new(Identity(Some(("owner".to_owned(), "browser".to_owned())))),
            routing: Arc::new(|| Some("owner".to_owned())),
            served: Arc::new(|| vec!["owner".to_owned()]),
            sources: Arc::new(Sources),
        };
        let target = crate::fake_ip::UpstreamTarget::at(
            "site.example".to_owned(),
            "192.0.2.1:443".parse().expect("target"),
            nrr_shared::RouteRole::Secondary,
        );
        let client = "127.0.0.1:40000".parse().expect("client");
        let fake = "198.18.0.1:443".parse().expect("fake");
        assert!(center.arm_browser_confirmation(
            "owner",
            "site.example",
            nrr_shared::RouteRole::Secondary
        ));
        for source in [Some("10.7.0.2".parse().expect("old source")), None] {
            observer.on_upstream_connected(
                client,
                fake,
                &target,
                observer.network_generation(),
                source,
            );
            assert_ne!(
                center.snapshot(Some("owner"), now_ms()).status,
                DnsCompatibilityStatus::Verified,
                "an old or unknown socket source cannot prove the selected adapter"
            );
        }
        observer.on_upstream_connected(
            client,
            fake,
            &target,
            observer.network_generation(),
            Some("10.8.0.2".parse().expect("current source")),
        );
        assert_eq!(
            center.snapshot(Some("owner"), now_ms()).status,
            DnsCompatibilityStatus::Verified
        );
    }

    #[test]
    fn a_vpn_address_change_revokes_the_old_dns_readiness_and_browser_proof_at_once() {
        let center = Arc::new(DnsCompatibilityCenter::default());
        let (_initial_network, _initial_watch) = watch_network(&center);
        let events = Arc::new(crate::ipc_handlers::event_bus::EventBus::new());
        let subscription = events.subscribe_as("gui".to_owned(), Some("owner".to_owned()), None);
        center.attach_events(Arc::clone(&events));
        let (network, _watch) = watch_network(&center);
        assert!(center.arm_browser_confirmation(
            "owner",
            "site.example",
            nrr_shared::RouteRole::Secondary
        ));
        center.finish_recheck(
            "owner",
            center.network_generation.load(Ordering::Relaxed),
            ready_dns(),
            Vec::new(),
            Some(true),
        );
        assert!(center.confirm_browser_path(
            "owner",
            "browser",
            "site.example",
            nrr_shared::RouteRole::Secondary,
            now_ms()
        ));
        let before = center.snapshot(Some("owner"), now_ms());
        assert_eq!(before.status, DnsCompatibilityStatus::Verified);

        network.fire();

        let after = center.snapshot(Some("owner"), now_ms());
        assert_eq!(
            after.status,
            DnsCompatibilityStatus::NeedsRecheck,
            "a verified connection on the old VPN address cannot certify the new network"
        );
        assert_eq!(after.resolver.upstream, "unchecked");
        assert_eq!(after.secondary_readiness, "unchecked");
        assert!(after.verified_program.is_none());
        assert!(after.sequence > before.sequence);
        let pushed = events.peek_pending_for(&subscription.subscription_id, 20);
        assert!(
            matches!(pushed.last().map(|event| &event.event), Some(StatusUpdateEvent::DnsCompatibilityChanged { state, .. }) if state.status == DnsCompatibilityStatus::NeedsRecheck)
        );
    }

    #[test]
    fn a_pending_site_confirmation_cannot_cross_a_vpn_address_change() {
        let center = Arc::new(DnsCompatibilityCenter::default());
        let (network, _watch) = watch_network(&center);
        assert!(center.arm_browser_confirmation(
            "owner",
            "site.example",
            nrr_shared::RouteRole::Secondary
        ));
        network.fire();
        assert!(
            !center.confirm_browser_path(
                "owner",
                "browser",
                "site.example",
                nrr_shared::RouteRole::Secondary,
                now_ms()
            ),
            "a request from the previous network must be repeated before certifying a browser"
        );
        assert!(center.arm_browser_confirmation(
            "owner",
            "site.example",
            nrr_shared::RouteRole::Secondary
        ));
        assert!(center.confirm_browser_path(
            "owner",
            "browser",
            "site.example",
            nrr_shared::RouteRole::Secondary,
            now_ms()
        ));
        assert_eq!(
            center.snapshot(Some("owner"), now_ms()).status,
            DnsCompatibilityStatus::Verified
        );
    }

    #[test]
    fn a_recheck_from_the_old_vpn_cannot_finish_the_new_networks_pending_check() {
        let center = Arc::new(DnsCompatibilityCenter::default());
        let (network, _watch) = watch_network(&center);
        assert!(center.arm_browser_confirmation(
            "owner",
            "site.example",
            nrr_shared::RouteRole::Secondary
        ));
        let old_generation = center.network_generation.load(Ordering::Relaxed);
        network.fire();
        {
            let mut states = center.principals.lock().expect("principals");
            states.get_mut("owner").expect("owner").recovery_pending = true;
        }
        center.finish_recheck("owner", old_generation, ready_dns(), Vec::new(), Some(true));
        let state = center.snapshot(Some("owner"), now_ms());
        assert!(
            state.recovery_pending,
            "the old worker cannot complete the new check"
        );
        assert_eq!(state.resolver.upstream, "unchecked");
        assert_eq!(state.secondary_readiness, "unchecked");
    }

    #[test]
    fn an_old_vpn_dial_cannot_certify_a_new_request_for_the_same_browser_and_site() {
        use crate::fake_ip::FlowObserver;
        let center = Arc::new(DnsCompatibilityCenter::default());
        let (network, _watch) = watch_network(&center);
        let observer = crate::fake_ip::production_ports::CompositeFlowObserver::new(vec![
            Arc::new(crate::fake_ip::NoopFlowObserver),
            Arc::new(DnsCompatibilityFlowObserver {
                center: Arc::clone(&center),
                owners: Arc::new(Identity(Some(("owner".to_owned(), "browser".to_owned())))),
                routing: Arc::new(|| Some("owner".to_owned())),
                served: Arc::new(|| vec!["owner".to_owned()]),
                sources: Arc::new(Sources),
            }),
        ]);
        let target = crate::fake_ip::UpstreamTarget::at(
            "site.example".to_owned(),
            "192.0.2.1:443".parse().expect("target"),
            nrr_shared::RouteRole::Secondary,
        );
        let client = "127.0.0.1:40000".parse().expect("client");
        let fake = "198.18.0.1:443".parse().expect("fake");
        assert!(center.arm_browser_confirmation(
            "owner",
            "site.example",
            nrr_shared::RouteRole::Secondary
        ));
        let old_dial_generation = observer.network_generation();
        network.fire();
        assert!(center.arm_browser_confirmation(
            "owner",
            "site.example",
            nrr_shared::RouteRole::Secondary
        ));
        observer.on_upstream_connected(
            client,
            fake,
            &target,
            old_dial_generation,
            Some("10.8.0.2".parse().expect("source")),
        );
        assert_ne!(
            center.snapshot(Some("owner"), now_ms()).status,
            DnsCompatibilityStatus::Verified,
            "a socket dialed on the old network cannot satisfy a new browser check"
        );
        observer.on_upstream_connected(
            client,
            fake,
            &target,
            None,
            Some("10.8.0.2".parse().expect("source")),
        );
        assert_ne!(
            center.snapshot(Some("owner"), now_ms()).status,
            DnsCompatibilityStatus::Verified
        );
        observer.on_upstream_connected(
            client,
            fake,
            &target,
            observer.network_generation(),
            Some("10.8.0.2".parse().expect("source")),
        );
        assert_eq!(
            center.snapshot(Some("owner"), now_ms()).status,
            DnsCompatibilityStatus::Verified
        );
    }

    #[test]
    fn network_flaps_cannot_start_a_second_recheck_while_the_browser_port_is_stuck() {
        struct BlockedSettings {
            entered: std::sync::mpsc::Sender<()>,
            release: Mutex<std::sync::mpsc::Receiver<()>>,
        }
        impl nrr_platform_api::browser_dns_settings::BrowserDnsSettingsPort for BlockedSettings {
            fn inspect(
                &self,
                _: &str,
            ) -> Vec<nrr_shared::browser_dns_settings::BrowserDnsSettingsDto> {
                let _ = self.entered.send(());
                let _ = self
                    .release
                    .lock()
                    .expect("release")
                    .recv_timeout(Duration::from_secs(5));
                Vec::new()
            }
        }
        let center = Arc::new(DnsCompatibilityCenter::default());
        let (network, _watch) = watch_network(&center);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        center.attach_browser_settings(Arc::new(BlockedSettings {
            entered: entered_tx,
            release: Mutex::new(release_rx),
        }));
        assert!(center.request_recheck("owner"));
        entered_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("first worker entered the blocked port");
        network.fire();
        {
            let mut states = center.principals.lock().expect("principals");
            states.get_mut("owner").expect("owner").last_recheck =
                Some(Instant::now() - Duration::from_secs(31));
        }
        let second_started = center.request_recheck("owner");
        let _ = release_tx.send(());
        let _ = release_tx.send(());
        assert!(!second_started, "a network change and elapsed cooldown cannot stack workers behind a stuck browser port");
        let deadline = Instant::now() + Duration::from_secs(3);
        while Arc::strong_count(&center) != 1 {
            assert!(Instant::now() < deadline, "the old worker did not finish");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            center.request_recheck("owner"),
            "the old worker releases its permit after actually finishing"
        );
        let _ = release_tx.send(());
    }

    #[test]
    fn another_user_and_an_anonymous_client_never_read_the_browsers_conflict() {
        let center = Arc::new(DnsCompatibilityCenter::default());
        let (_initial_network, _initial_watch) = watch_network(&center);
        center.observe(
            "owner",
            "browser",
            Observation::Problem(Reason::OurDnsBlock),
            10,
        );
        assert_eq!(center.snapshot(Some("owner"), 11).issues.len(), 1);
        assert!(center.snapshot(Some("other"), 11).issues.is_empty());
        assert!(center.snapshot(None, 11).issues.is_empty());
        assert_eq!(
            center.snapshot(None, 11).status,
            DnsCompatibilityStatus::Unchecked
        );
    }

    #[test]
    fn a_resolver_contact_alone_never_claims_the_programs_connection_is_broken() {
        let center = Arc::new(DnsCompatibilityCenter::default());
        let (_initial_network, _initial_watch) = watch_network(&center);
        center.observe(
            "owner",
            "browser",
            Observation::Problem(Reason::ResolverContact),
            10,
        );
        assert_eq!(
            center.snapshot(Some("owner"), 11).status,
            DnsCompatibilityStatus::Unchecked
        );
    }

    #[test]
    fn a_new_failure_immediately_after_recovery_never_leaves_the_client_showing_verified() {
        let center = Arc::new(DnsCompatibilityCenter::default());
        let (_initial_network, _initial_watch) = watch_network(&center);
        let events = Arc::new(crate::ipc_handlers::event_bus::EventBus::new());
        let subscription = events.subscribe_as("gui".to_owned(), Some("owner".to_owned()), None);
        center.attach_events(Arc::clone(&events));
        center.observe(
            "owner",
            "browser",
            Observation::Problem(Reason::OurDnsBlock),
            10,
        );
        center.observe("owner", "browser", Observation::BrowserPathVerified, 20);
        center.observe(
            "owner",
            "browser",
            Observation::Problem(Reason::OurDnsBlock),
            21,
        );
        let pushed = events.peek_pending_for(&subscription.subscription_id, 10);
        let states: Vec<_> = pushed
            .iter()
            .filter_map(|event| match &event.event {
                StatusUpdateEvent::DnsCompatibilityChanged { state, .. } => Some(state.status),
                _ => None,
            })
            .collect();
        assert_eq!(states.last(), Some(&DnsCompatibilityStatus::Limited),
            "a new confirmed failure must revoke the client's verified state even inside the notification throttle");
    }

    #[test]
    fn a_single_new_program_inside_the_push_window_is_eventually_published() {
        let center = Arc::new(DnsCompatibilityCenter::default());
        let (_initial_network, _initial_watch) = watch_network(&center);
        let events = Arc::new(crate::ipc_handlers::event_bus::EventBus::new());
        let subscription = events.subscribe_as("gui".to_owned(), Some("owner".to_owned()), None);
        center.attach_events(Arc::clone(&events));
        let at = now_ms();
        center.observe(
            "owner",
            "first-browser",
            Observation::Problem(Reason::OurDnsBlock),
            at,
        );
        center.observe(
            "owner",
            "second-browser",
            Observation::Problem(Reason::OurDnsBlock),
            at,
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let pending = events.peek_pending_for(&subscription.subscription_id, 20);
            if pending.iter().any(|event| {
                matches!(&event.event,
                StatusUpdateEvent::DnsCompatibilityChanged { state, .. }
                    if state.issues.iter().any(|issue| issue.program == "second-browser"))
            }) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "a one-shot program failure cannot disappear inside the notification throttle"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn a_success_in_another_program_is_not_a_verified_browser_recovery() {
        let center = Arc::new(DnsCompatibilityCenter::default());
        let (_initial_network, _initial_watch) = watch_network(&center);
        center.observe(
            "owner",
            "other-program",
            Observation::BrowserPathVerified,
            10,
        );
        assert_eq!(
            center.snapshot(Some("owner"), 11).status,
            DnsCompatibilityStatus::Unchecked
        );
        center.observe(
            "owner",
            "browser",
            Observation::Problem(Reason::OurDnsBlock),
            20,
        );
        center.observe(
            "owner",
            "other-program",
            Observation::BrowserPathVerified,
            30,
        );
        assert_eq!(center.snapshot(Some("owner"), 31).issues.len(), 1);
    }

    #[test]
    fn a_service_restart_starts_unchecked_and_users_do_not_share_a_recheck_budget() {
        let center = Arc::new(DnsCompatibilityCenter::default());
        let (_initial_network, _initial_watch) = watch_network(&center);
        assert_eq!(
            center.snapshot(Some("owner"), 10).status,
            DnsCompatibilityStatus::Unchecked
        );
        assert!(center.request_recheck("owner"));
        assert!(!center.request_recheck("owner"));
        assert!(center.request_recheck("another-owner"));
    }

    struct Identity(Option<(String, String)>);
    impl nrr_platform_api::FlowOwnerLookup for Identity {
        fn owner_image_name(
            &self,
            _: std::net::SocketAddr,
            _: std::net::SocketAddr,
        ) -> Option<String> {
            None
        }
        fn owner_identity(
            &self,
            _: std::net::SocketAddr,
            _: std::net::SocketAddr,
        ) -> Option<(String, String)> {
            self.0.clone()
        }
    }

    struct Sources;
    impl crate::production_auto_rule_probe::EgressSources for Sources {
        fn egress_source_ips(
            &self,
            _: &str,
        ) -> (Option<std::net::Ipv4Addr>, Option<std::net::Ipv4Addr>) {
            (None, Some(std::net::Ipv4Addr::new(10, 8, 0, 2)))
        }
    }

    #[test]
    fn an_unrequested_background_connection_does_not_resolve_the_browsers_dns_issue() {
        use crate::fake_ip::FlowObserver;
        let center = Arc::new(DnsCompatibilityCenter::default());
        let (_initial_network, _initial_watch) = watch_network(&center);
        let program = "/browser/chrome";
        center.observe(
            "owner",
            program,
            Observation::Problem(Reason::OurDnsBlock),
            now_ms(),
        );
        let observer = DnsCompatibilityFlowObserver {
            center: Arc::clone(&center),
            owners: Arc::new(Identity(Some(("owner".to_owned(), program.to_owned())))),
            routing: Arc::new(|| Some("owner".to_owned())),
            served: Arc::new(|| vec!["owner".to_owned()]),
            sources: Arc::new(Sources),
        };
        let target = crate::fake_ip::UpstreamTarget::at(
            "background.example".to_owned(),
            "192.0.2.1:443".parse().expect("upstream"),
            nrr_shared::RouteRole::Secondary,
        );
        observer.on_upstream_connected(
            "127.0.0.1:40000".parse().expect("client"),
            "198.18.0.1:443".parse().expect("fake"),
            &target,
            observer.network_generation(),
            Some("10.8.0.2".parse().expect("source")),
        );
        let state = center.snapshot(Some("owner"), now_ms());
        assert!(
            state
                .issues
                .iter()
                .any(|issue| issue.program == program && issue.reason == "our-dns-block"),
            "an unrelated background connection cannot establish recovery of the requested site"
        );
        assert_ne!(state.status, DnsCompatibilityStatus::Verified);
    }

    #[test]
    fn a_local_accept_an_unknown_owner_and_a_wrong_route_never_clear_a_browser_failure() {
        use crate::fake_ip::FlowObserver;
        let center = Arc::new(DnsCompatibilityCenter::default());
        let (_initial_network, _initial_watch) = watch_network(&center);
        let program = "/browser/chrome";
        center.observe(
            "owner",
            program,
            Observation::Problem(Reason::OurDnsBlock),
            now_ms(),
        );
        center.arm_browser_confirmation("owner", "site.example", nrr_shared::RouteRole::Secondary);
        let mut observer = DnsCompatibilityFlowObserver {
            center: Arc::clone(&center),
            owners: Arc::new(Identity(None)),
            routing: Arc::new(|| Some("owner".to_owned())),
            served: Arc::new(|| vec!["owner".to_owned()]),
            sources: Arc::new(Sources),
        };
        let client = "127.0.0.1:40000".parse().expect("client");
        let fake = "198.18.0.1:443".parse().expect("fake");
        let mut target = crate::fake_ip::UpstreamTarget::at(
            "site.example".to_owned(),
            "192.0.2.1:443".parse().expect("upstream"),
            nrr_shared::RouteRole::Secondary,
        );
        observer.on_flow_opened(client, fake, "site.example", None);
        observer.on_upstream_connected(
            client,
            fake,
            &target,
            observer.network_generation(),
            Some("10.8.0.2".parse().expect("source")),
        );
        assert_eq!(center.snapshot(Some("owner"), now_ms()).issues.len(), 1);
        observer.owners = Arc::new(Identity(Some(("owner".to_owned(), program.to_owned()))));
        target.book_route = Some(nrr_shared::RouteRole::Primary);
        observer.on_upstream_connected(
            client,
            fake,
            &target,
            observer.network_generation(),
            Some("10.8.0.2".parse().expect("source")),
        );
        assert_eq!(center.snapshot(Some("owner"), now_ms()).issues.len(), 1);
        target.book_route = Some(nrr_shared::RouteRole::Secondary);
        observer.on_upstream_connected(
            client,
            fake,
            &target,
            observer.network_generation(),
            Some("10.8.0.2".parse().expect("source")),
        );
        assert_eq!(
            center.snapshot(Some("owner"), now_ms()).status,
            DnsCompatibilityStatus::Verified
        );
    }

    #[test]
    fn a_requested_site_confirms_only_its_exact_host_route_and_actual_program() {
        let center = Arc::new(DnsCompatibilityCenter::default());
        let (_initial_network, _initial_watch) = watch_network(&center);
        center.observe(
            "owner",
            "/browser/chrome",
            Observation::Problem(Reason::OurDnsBlock),
            now_ms(),
        );
        center.observe(
            "owner",
            "/browser/firefox",
            Observation::Problem(Reason::OurDnsBlock),
            now_ms(),
        );
        assert!(center.arm_browser_confirmation(
            "owner",
            "site.example",
            nrr_shared::RouteRole::Secondary
        ));
        assert!(!center.confirm_browser_path(
            "owner",
            "/browser/chrome",
            "background.example",
            nrr_shared::RouteRole::Secondary,
            now_ms()
        ));
        assert!(!center.confirm_browser_path(
            "owner",
            "/browser/chrome",
            "site.example",
            nrr_shared::RouteRole::Primary,
            now_ms()
        ));
        assert!(!center.confirm_browser_path(
            "another-owner",
            "/browser/chrome",
            "site.example",
            nrr_shared::RouteRole::Secondary,
            now_ms()
        ));
        assert!(center.confirm_browser_path(
            "owner",
            "/browser/chrome",
            "site.example",
            nrr_shared::RouteRole::Secondary,
            now_ms()
        ));
        let state = center.snapshot(Some("owner"), now_ms());
        assert_eq!(state.issues.len(), 1);
        assert_eq!(state.issues[0].program, "/browser/firefox");
        assert_eq!(state.verified_program.as_deref(), Some("/browser/chrome"));
    }

    #[test]
    fn a_site_confirmation_after_restart_publishes_context_before_its_actual_program_proof() {
        let center = Arc::new(DnsCompatibilityCenter::default());
        let (_initial_network, _initial_watch) = watch_network(&center);
        let events = Arc::new(crate::ipc_handlers::event_bus::EventBus::new());
        let subscription = events.subscribe_as("gui".to_owned(), Some("owner".to_owned()), None);
        center.attach_events(Arc::clone(&events));
        assert!(center.arm_browser_confirmation(
            "owner",
            "site.example",
            nrr_shared::RouteRole::Secondary
        ));
        let pending = center.snapshot(Some("owner"), now_ms());
        assert_eq!(pending.status, DnsCompatibilityStatus::Unchecked);
        assert!(!pending.instance_id.is_empty());
        assert!(center.confirm_browser_path(
            "owner",
            "/browser/chrome",
            "site.example",
            nrr_shared::RouteRole::Secondary,
            now_ms()
        ));
        let ready = center.snapshot(Some("owner"), now_ms());
        assert_eq!(ready.status, DnsCompatibilityStatus::Verified);
        assert_eq!(ready.verified_program.as_deref(), Some("/browser/chrome"));
        assert!(ready.sequence > pending.sequence);
        let pushed = events.peek_pending_for(&subscription.subscription_id, 10);
        let states: Vec<_> = pushed
            .iter()
            .filter_map(|event| match &event.event {
                StatusUpdateEvent::DnsCompatibilityChanged { state, .. } => Some(state.status),
                _ => None,
            })
            .collect();
        assert_eq!(
            states,
            vec![
                DnsCompatibilityStatus::Unchecked,
                DnsCompatibilityStatus::Verified
            ]
        );
    }

    #[test]
    fn a_cached_requested_site_connection_does_not_erase_a_strict_browser_mode() {
        let center = Arc::new(DnsCompatibilityCenter::default());
        let (_initial_network, _initial_watch) = watch_network(&center);
        center.observe(
            "owner",
            "/browser/chrome",
            Observation::Problem(Reason::StrictBrowserDns),
            now_ms(),
        );
        center.arm_browser_confirmation("owner", "site.example", nrr_shared::RouteRole::Secondary);
        assert!(center.confirm_browser_path(
            "owner",
            "/browser/chrome",
            "site.example",
            nrr_shared::RouteRole::Secondary,
            now_ms()
        ));
        let state = center.snapshot(Some("owner"), now_ms());
        assert_eq!(state.status, DnsCompatibilityStatus::Limited);
        assert_eq!(state.issues[0].reason, "strict-browser-dns");
    }

    fn blocked_browser_row() -> crate::conn_observation_consumer::ConnectionTraceRecord {
        use nrr_platform_api::conn_observe::egress::{EgressInterface, EgressRole};
        use nrr_platform_api::conn_observe::{ConnectionVerdict, TransportProtocol};
        crate::conn_observation_consumer::ConnectionTraceRecord {
            process_path: Some("/browser/chrome".to_owned()),
            user_sid: Some("owner".to_owned()),
            protocol: TransportProtocol::Tcp,
            local: "192.0.2.2:40000".parse().expect("local"),
            remote: "1.1.1.1:443".parse().expect("remote"),
            egress: EgressInterface {
                ifindex: 1,
                role: EgressRole::Primary,
            },
            verdict: ConnectionVerdict::Block,
            blocked_by_nrr: Some(true),
            nrr_drop_spec_id: Some(42),
            nrr_block_reason: Some("dns-lockdown"),
            observed_unix_ms: Some(now_ms()),
            remote_names: None,
        }
    }

    #[test]
    fn a_queued_old_dns_block_does_not_erase_a_newer_browser_path_proof() {
        let center = Arc::new(DnsCompatibilityCenter::default());
        let (_initial_network, _initial_watch) = watch_network(&center);
        let at = now_ms();
        center.observe(
            "owner",
            "/browser/chrome",
            Observation::Problem(Reason::OurDnsBlock),
            at - 30,
        );
        center.observe(
            "owner",
            "/browser/chrome",
            Observation::BrowserPathVerified,
            at - 20,
        );
        let mut queued = blocked_browser_row();
        queued.observed_unix_ms = Some(at - 25);
        center.observe_connection(&queued, at);
        assert_eq!(
            center.snapshot(Some("owner"), now_ms()).status,
            DnsCompatibilityStatus::Verified,
            "a queued block older than the successful browser connection cannot revoke that proof"
        );
    }

    #[test]
    fn a_clock_rollback_never_repaints_old_browser_proof_when_the_clock_catches_up() {
        let center = Arc::new(DnsCompatibilityCenter::default());
        let (_initial_network, _initial_watch) = watch_network(&center);
        let at = now_ms();
        center.observe(
            "owner",
            "/browser/chrome",
            Observation::Problem(Reason::OurDnsBlock),
            at - 10,
        );
        center.observe(
            "owner",
            "/browser/chrome",
            Observation::BrowserPathVerified,
            at,
        );
        let first = center.snapshot(Some("owner"), at);
        let rolled_back = center.snapshot(Some("owner"), at - 1);
        assert_eq!(rolled_back.status, DnsCompatibilityStatus::NeedsRecheck);
        assert!(rolled_back.sequence > first.sequence);
        let caught_up = center.snapshot(Some("owner"), at + 1);
        assert_eq!(caught_up.status, DnsCompatibilityStatus::NeedsRecheck);
        assert_eq!(caught_up.sequence, rolled_back.sequence);
        center.arm_browser_confirmation("owner", "site.example", nrr_shared::RouteRole::Secondary);
        assert!(center.confirm_browser_path(
            "owner",
            "/browser/chrome",
            "site.example",
            nrr_shared::RouteRole::Secondary,
            now_ms()
        ));
        assert_eq!(
            center.snapshot(Some("owner"), now_ms()).status,
            DnsCompatibilityStatus::Verified
        );
        let after_proof = now_ms();
        center.observe(
            "owner",
            "/browser/chrome",
            Observation::Problem(Reason::OurDnsBlock),
            after_proof.saturating_sub(60_000),
        );
        assert_eq!(
            center.snapshot(Some("owner"), after_proof + 1).status,
            DnsCompatibilityStatus::NeedsRecheck
        );
    }

    #[test]
    fn muting_the_popup_keeps_the_owner_scoped_full_program_issue_and_its_push() {
        use nrr_domain::block_notice::{BlockAttempt, BlockReason, Mute, MuteScope};
        let events = Arc::new(crate::ipc_handlers::event_bus::EventBus::new());
        let subscription = events.subscribe_as("gui".to_owned(), Some("owner".to_owned()), None);
        let notices = crate::block_notice_center::BlockNoticeCenter::new()
            .with_event_bus(Arc::clone(&events))
            .with_mute_loader(Arc::new(|_| vec![Mute::forever(MuteScope::All)]));
        let center = notices.dns_compatibility();
        let ring = crate::conn_observation_consumer::ConnectionTraceRing::new(8);
        ring.attach_dns_compatibility(Arc::clone(&center));
        notices.record(
            "owner",
            &BlockAttempt {
                host: None,
                dest: "1.1.1.1".to_owned(),
                app: Some("chrome".to_owned()),
                reason: BlockReason::DnsLockdown,
            },
        );
        notices.reload_mutes("owner");
        ring.push(blocked_browser_row());
        let state = center.snapshot(Some("owner"), now_ms());
        assert_eq!(state.issues.len(), 1);
        assert_eq!(state.issues[0].program, "/browser/chrome");
        assert_eq!(state.issues[0].reason, "our-dns-block");
        assert!(center
            .snapshot(Some("another-owner"), now_ms())
            .issues
            .is_empty());
        let pushed = events.peek_pending_for(&subscription.subscription_id, 20);
        assert!(pushed.iter().any(|event| matches!(
            &event.event,
            StatusUpdateEvent::DnsCompatibilityChanged { .. }
        )));
        assert!(!pushed
            .iter()
            .any(|event| matches!(&event.event, StatusUpdateEvent::BlockNoticeRaised { .. })));
        let mut anonymous = blocked_browser_row();
        anonymous.user_sid = None;
        ring.push(anonymous);
        assert!(center.snapshot(None, now_ms()).issues.is_empty());
    }

    #[test]
    fn a_known_resolvers_shared_https_address_proves_no_browser_failure() {
        let center = Arc::new(DnsCompatibilityCenter::default());
        let (_initial_network, _initial_watch) = watch_network(&center);
        let mut record = blocked_browser_row();
        record.blocked_by_nrr = None;
        record.nrr_block_reason = None;
        record.verdict = nrr_platform_api::conn_observe::ConnectionVerdict::Unknown;
        center.observe_connection(&record, now_ms());
        let state = center.snapshot(Some("owner"), now_ms());
        assert_eq!(state.status, DnsCompatibilityStatus::Unchecked);
        assert_eq!(state.issues[0].evidence, "suspected");
    }

    #[test]
    fn an_evicted_principals_next_episode_cannot_reuse_an_older_snapshot_sequence() {
        let center = Arc::new(DnsCompatibilityCenter::default());
        let (_initial_network, _initial_watch) = watch_network(&center);
        center.observe(
            "owner",
            "browser",
            Observation::Problem(Reason::OurDnsBlock),
            1,
        );
        let first = center.snapshot(Some("owner"), 1);
        for index in 0..MAX_PRINCIPALS {
            center.observe(
                &format!("other-{index}"),
                "browser",
                Observation::Problem(Reason::OurDnsBlock),
                2 + index as u64,
            );
        }
        center.observe(
            "owner",
            "browser",
            Observation::Problem(Reason::OurDnsBlock),
            100,
        );
        let next = center.snapshot(Some("owner"), 100);
        assert_eq!(first.instance_id, next.instance_id);
        assert!(next.sequence > first.sequence);
    }

    #[test]
    fn unavailable_entropy_never_certifies_a_browser_recovery() {
        let center = Arc::new(DnsCompatibilityCenter::default());
        let (_initial_network, _initial_watch) = watch_network(&center);
        center
            .instance_id
            .set(String::new())
            .expect("uninitialized identity");
        center.observe(
            "owner",
            "browser",
            Observation::Problem(Reason::OurDnsBlock),
            10,
        );
        center.observe("owner", "browser", Observation::BrowserPathVerified, 20);
        assert_ne!(
            center.snapshot(Some("owner"), 20).status,
            DnsCompatibilityStatus::Verified
        );
    }

    #[test]
    fn successful_system_dns_and_a_saved_off_preference_do_not_certify_the_browser() {
        use nrr_shared::browser_dns_settings::{
            BrowserDnsBrowser, BrowserDnsMode, BrowserDnsSettingsDto,
        };
        let center = Arc::new(DnsCompatibilityCenter::default());
        let (_initial_network, _initial_watch) = watch_network(&center);
        center.observe(
            "owner",
            "browser",
            Observation::Problem(Reason::OurDnsBlock),
            now_ms(),
        );
        let mut browser = BrowserDnsSettingsDto::unavailable(BrowserDnsBrowser::Chrome);
        browser.configured_mode = BrowserDnsMode::Off;
        center.finish_recheck(
            "owner",
            center.network_generation.load(Ordering::Relaxed),
            DnsResolverReadinessDto {
                listener: "ready".to_owned(),
                redirect: "ready".to_owned(),
                upstream: "ready".to_owned(),
            },
            vec![browser],
            Some(true),
        );
        let state = center.snapshot(Some("owner"), now_ms());
        assert!(state
            .issues
            .iter()
            .any(|issue| issue.reason == "our-dns-block"));
        assert_ne!(state.status, DnsCompatibilityStatus::Verified);
    }
}
