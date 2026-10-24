//! Liveness of every long-lived task, supervised or not, folded into health.
//!
//! The supervisor hears a task end; nothing heard a task hang, and nothing at
//! all heard a thread outside the supervisor — the local DNS resolver among
//! them, whose death while it intercepts leaves the machine's DNS pointed at
//! nothing with health still green.
//!
//! Three kinds of evidence, each a pair of atomics the loop already passes:
//!
//! - a **pulse** of a supervised task: the supervisor marks each tick's start
//!   and end, so a tick that runs past its deadline is a hang;
//! - a **lease** an own-thread task holds: dropped without `finish`, the
//!   thread ended by a panic; finished with [`ThreadExit::Stopped`], nothing
//!   is said; its [`Watch`] says what counts as a hang;
//! - a [`TickWatch`] on a loop that waits inside its tick (the IPC acceptor):
//!   the hang watchdog pokes it, so a tick that still does not end is a hang.
//!
//! The health-aggregator tick calls [`TaskLiveness::audit`]; everything else
//! is recorded at the moment it happens. Verdicts go through one named voice
//! on the aggregator, so clearing them never erases what another writer said.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::health::{HealthAggregator, HealthComponent};
use crate::service_tasks::{ServiceTaskKind, TaskHealth};
use crate::state::ServiceHealthSeverity;

/// The aggregator voice every liveness verdict is recorded under.
pub const LIVENESS_SOURCE: &str = "liveness";

/// The aggregator voice for the resolver's upstream trouble.
const DNS_UPSTREAM_SOURCE: &str = "dns-upstream";

/// A supervised tick longer than this is a hang. Generous: the longest honest
/// tick (a cold DNS refresh batch) stays well under it.
pub const DEFAULT_TICK_DEADLINE: Duration = Duration::from_secs(120);

/// What counts as a hang for an own-thread task.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Watch {
    /// The loop beats at least this often while alive (a periodic worker).
    Beats(Duration),
    /// One unit of work in flight longer than this (a queue worker).
    Work(Duration),
    /// Only its exit is seen: the loop blocks for as long as it likes.
    None,
}

/// How an own-thread task ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ThreadExit {
    /// Asked to stop; nothing to report.
    Stopped,
    /// Ended for the reason given; reported at the registry's severity.
    Ended(String),
    /// Ended leaving the machine in a state the task was holding safe;
    /// reported at least `Degraded`, never `Blocking`: the user must still be
    /// able to reach the action that repairs it.
    Broken(String),
}

/// What a task that ended broken has to tell the clients. Only the resolver
/// can end that way today: its exit is the one that may leave the system DNS
/// pointed at a resolver that is gone.
fn broken_news(kind: ServiceTaskKind) -> Option<nrr_shared::ipc_payloads::StatusUpdateEvent> {
    (kind == ServiceTaskKind::DnsResolver)
        .then_some(nrr_shared::ipc_payloads::StatusUpdateEvent::SystemDnsNotRestored)
}

/// How long one accept tick may stay open while the hang watchdog pokes the
/// listener every 15 s: four pokes that all went unanswered.
pub const ACCEPT_TICK_DEADLINE: Duration = Duration::from_secs(60);

/// One task's sign of life. Shared between the thread that touches it and the
/// audit that reads it; two atomics, no lock.
pub struct Pulse {
    kind: ServiceTaskKind,
    /// Milliseconds since the board's epoch of the last sign of life.
    last_seen: AtomicU64,
    busy: AtomicBool,
    watch: Watch,
}

impl Pulse {
    fn touch(&self, board: &TaskLiveness, busy: bool) {
        self.last_seen.store(board.now_ms(), Ordering::Relaxed);
        self.busy.store(busy, Ordering::Relaxed);
    }

    /// Whether the pulse shows a hang at `now_ms`, and for how long.
    fn hang(&self, now_ms: u64) -> Option<(Duration, &'static str)> {
        let since = now_ms.saturating_sub(self.last_seen.load(Ordering::Relaxed));
        let busy = self.busy.load(Ordering::Relaxed);
        let (deadline, what) = match self.watch {
            Watch::Beats(d) if !busy => (d, "gave no sign of life"),
            Watch::Beats(d) | Watch::Work(d) if busy => (d, "has been working"),
            _ => return None,
        };
        let deadline_ms = u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX);
        (since > deadline_ms).then(|| (Duration::from_millis(since), what))
    }
}

/// Marks one unit of work in flight for as long as it lives.
pub struct WorkGuard<'a> {
    board: &'a TaskLiveness,
    pulse: &'a Pulse,
}

impl Drop for WorkGuard<'_> {
    fn drop(&mut self) {
        self.pulse.touch(self.board, false);
    }
}

/// The ticks of a loop that waits inside its tick by design (the IPC acceptor
/// waits there for a client), so the supervisor gives it no deadline. The hang
/// watchdog pokes such a loop from outside; a tick still open past the
/// deadline is then a hang. Idle between ticks (a retry backoff) is not.
#[derive(Clone)]
pub struct TickWatch {
    board: Arc<TaskLiveness>,
    pulse: Arc<Pulse>,
}

impl TickWatch {
    /// A tick starts; it ends when the guard drops.
    pub fn tick(&self) -> WorkGuard<'_> {
        self.board.tick_begins(&self.pulse)
    }
}

/// An own-thread task's registration. Take it on the thread, `finish` it on
/// the way out; dropping it unfinished says the thread died.
pub struct ThreadLease {
    board: Arc<TaskLiveness>,
    pulse: Arc<Pulse>,
    name: String,
    finished: bool,
}

impl ThreadLease {
    /// The loop is alive and idle.
    pub fn beat(&self) {
        self.pulse.touch(&self.board, false);
    }

    /// One unit of work begins; it ends when the guard drops.
    pub fn work(&self) -> WorkGuard<'_> {
        self.pulse.touch(&self.board, true);
        WorkGuard {
            board: &self.board,
            pulse: &self.pulse,
        }
    }

    pub fn finish(mut self, exit: ThreadExit) {
        self.finished = true;
        let kind = self.pulse.kind;
        match exit {
            ThreadExit::Stopped => self.board.thread_stopped(&self.name),
            ThreadExit::Ended(why) => self.board.thread_gone(&self.name, kind, why, false),
            ThreadExit::Broken(why) => self.board.thread_gone(&self.name, kind, why, true),
        }
    }
}

impl Drop for ThreadLease {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let why = if std::thread::panicking() {
            "the thread panicked"
        } else {
            "the thread ended without saying why"
        };
        self.board
            .thread_gone(&self.name, self.pulse.kind, why.to_owned(), false);
    }
}

struct Gone {
    kind: ServiceTaskKind,
    why: String,
    broken: bool,
}

#[derive(Default)]
struct Inner {
    /// Live pulses by task name.
    pulses: BTreeMap<String, Arc<Pulse>>,
    /// Tasks gone for good, until the same name is leased again.
    gone: BTreeMap<String, Gone>,
    /// Names last found hung, with how long and what they were doing.
    hung: BTreeMap<String, (Duration, &'static str)>,
}

/// The board every task reports to. One per runtime, beside the aggregator.
pub struct TaskLiveness {
    health: Arc<HealthAggregator>,
    epoch: Instant,
    inner: Mutex<Inner>,
    /// Where a broken exit's news goes; `None` keeps it in health alone.
    events: Option<Arc<crate::ipc_handlers::event_bus::EventBus>>,
}

impl TaskLiveness {
    pub fn new(health: Arc<HealthAggregator>) -> Self {
        Self {
            health,
            epoch: Instant::now(),
            inner: Mutex::new(Inner::default()),
            events: None,
        }
    }

    /// Tell the clients when a task ends leaving the machine worse off: health
    /// is read when someone asks, and this needs saying at once.
    #[must_use]
    pub fn with_event_bus(mut self, events: Arc<crate::ipc_handlers::event_bus::EventBus>) -> Self {
        self.events = Some(events);
        self
    }

    /// Never 0, so an untouched pulse reads as "seen at the epoch".
    fn now_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis())
            .unwrap_or(u64::MAX)
            .max(1)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Register a supervised task's pulse; `None` for an id the registry does
    /// not know or a task that opted out of a deadline. The supervisor wraps
    /// every tick in [`Pulse`] work marks through [`Self::tick_begins`].
    pub fn supervised(&self, id: &str, deadline: Option<Duration>) -> Option<Arc<Pulse>> {
        let kind = ServiceTaskKind::from_id(id)?;
        let watch = Watch::Work(deadline?);
        let pulse = Arc::new(Pulse {
            kind,
            last_seen: AtomicU64::new(self.now_ms()),
            busy: AtomicBool::new(false),
            watch,
        });
        self.lock().pulses.insert(id.to_owned(), Arc::clone(&pulse));
        Some(pulse)
    }

    /// Watch the ticks of a loop the supervisor gives no deadline. Named
    /// `<kind>:<label>`, so it never displaces a pulse of the supervisor's.
    pub fn tick_watch(
        self: &Arc<Self>,
        kind: ServiceTaskKind,
        label: &str,
        deadline: Duration,
    ) -> TickWatch {
        let pulse = Arc::new(Pulse {
            kind,
            last_seen: AtomicU64::new(self.now_ms()),
            busy: AtomicBool::new(false),
            watch: Watch::Work(deadline),
        });
        self.lock()
            .pulses
            .insert(format!("{}:{label}", kind.id()), Arc::clone(&pulse));
        TickWatch {
            board: Arc::clone(self),
            pulse,
        }
    }

    /// A supervised tick starts; the guard ends it.
    pub fn tick_begins<'a>(&'a self, pulse: &'a Pulse) -> WorkGuard<'a> {
        pulse.touch(self, true);
        WorkGuard { board: self, pulse }
    }

    /// A supervised task's loop ended; the failure sink has already said where.
    pub fn supervised_ended(&self, id: &str) {
        let mut inner = self.lock();
        inner.pulses.remove(id);
        if inner.hung.remove(id).is_some() {
            self.publish(&inner);
        }
    }

    /// Take a lease for an own-thread task. `label` tells apart several
    /// threads of one kind (the debounce workers); a lease taken again under a
    /// name that was reported gone lifts that verdict.
    pub fn lease(
        self: &Arc<Self>,
        kind: ServiceTaskKind,
        label: Option<&str>,
        watch: Watch,
    ) -> ThreadLease {
        let name = match label {
            Some(label) => format!("{}:{label}", kind.id()),
            None => kind.id().to_owned(),
        };
        let pulse = Arc::new(Pulse {
            kind,
            last_seen: AtomicU64::new(self.now_ms()),
            busy: AtomicBool::new(false),
            watch,
        });
        {
            let mut inner = self.lock();
            inner.pulses.insert(name.clone(), Arc::clone(&pulse));
            let was_gone = inner.gone.remove(&name).is_some();
            let was_hung = inner.hung.remove(&name).is_some();
            if was_gone || was_hung {
                tracing::info!(
                    target: "nrr::supervisor",
                    msg_key = "supervised-thread-back",
                    task = name.as_str(),
                    "task running again",
                );
                self.publish(&inner);
            }
        }
        ThreadLease {
            board: Arc::clone(self),
            pulse,
            name,
            finished: false,
        }
    }

    fn thread_stopped(&self, name: &str) {
        let mut inner = self.lock();
        inner.pulses.remove(name);
        if inner.hung.remove(name).is_some() {
            self.publish(&inner);
        }
    }

    fn thread_gone(&self, name: &str, kind: ServiceTaskKind, why: String, broken: bool) {
        tracing::error!(
            target: "nrr::supervisor",
            msg_key = "supervised-thread-gone",
            task = name,
            error = why.as_str(),
            "task ended while the service runs",
        );
        let mut inner = self.lock();
        inner.pulses.remove(name);
        inner.hung.remove(name);
        inner
            .gone
            .insert(name.to_owned(), Gone { kind, why, broken });
        self.publish(&inner);
        drop(inner);
        if let (true, Some(events), Some(news)) = (broken, self.events.as_ref(), broken_news(kind))
        {
            events.publish(news);
        }
    }

    /// Compare every pulse with its deadline; called from the health tick.
    pub fn audit(&self) {
        let now = self.now_ms();
        let mut inner = self.lock();
        let mut hung = BTreeMap::new();
        for (name, pulse) in &inner.pulses {
            if let Some(found) = pulse.hang(now) {
                hung.insert(name.clone(), found);
            }
        }
        if hung.keys().eq(inner.hung.keys()) {
            inner.hung = hung;
            return;
        }
        for (name, (for_how_long, what)) in &hung {
            if !inner.hung.contains_key(name) {
                tracing::warn!(
                    target: "nrr::supervisor",
                    msg_key = "supervised-task-hung",
                    task = name.as_str(),
                    seconds = for_how_long.as_secs(),
                    what = *what,
                    "task past its deadline",
                );
            }
        }
        for name in inner.hung.keys() {
            if !hung.contains_key(name) {
                tracing::info!(
                    target: "nrr::supervisor",
                    msg_key = "supervised-task-responsive",
                    task = name.as_str(),
                    "task responsive again",
                );
            }
        }
        inner.hung = hung;
        self.publish(&inner);
    }

    /// The resolver's standing trouble with its upstream, or `None` once over.
    /// Its own voice: neither a task verdict nor another writer's `adapters`
    /// state is touched.
    pub fn say_dns_upstream(&self, trouble: Option<&str>) {
        match trouble {
            Some(message) => self.health.record_as(
                DNS_UPSTREAM_SOURCE,
                HealthComponent::Adapters,
                ServiceHealthSeverity::Degraded,
                message,
            ),
            None => self
                .health
                .clear_as(DNS_UPSTREAM_SOURCE, HealthComponent::Adapters),
        }
    }

    /// Names reported gone or hung right now; for tests and the status log.
    pub fn troubled(&self) -> Vec<String> {
        let inner = self.lock();
        inner
            .gone
            .keys()
            .chain(inner.hung.keys())
            .cloned()
            .collect()
    }

    /// The first task of `kinds` hung for at least `threshold`, and for how
    /// long. Read by the hang watchdog, which shares no lock with the work.
    pub fn hung_past(
        &self,
        kinds: &[ServiceTaskKind],
        threshold: Duration,
    ) -> Option<(String, Duration)> {
        self.hung_past_at(kinds, threshold, self.now_ms())
    }

    /// [`Self::hung_past`] at `now_ms` on the board's clock.
    fn hung_past_at(
        &self,
        kinds: &[ServiceTaskKind],
        threshold: Duration,
        now_ms: u64,
    ) -> Option<(String, Duration)> {
        let inner = self.lock();
        inner
            .pulses
            .iter()
            .filter(|(_, pulse)| kinds.contains(&pulse.kind))
            .find_map(|(name, pulse)| {
                pulse
                    .hang(now_ms)
                    .filter(|(for_how_long, _)| *for_how_long >= threshold)
                    .map(|(for_how_long, _)| (name.clone(), for_how_long))
            })
    }

    /// Record, per component, the worst thing known; clear the rest.
    fn publish(&self, inner: &Inner) {
        let mut worst: BTreeMap<HealthComponent, (ServiceHealthSeverity, String)> = BTreeMap::new();
        for (name, gone) in &inner.gone {
            let TaskHealth::Reports {
                component,
                severity,
            } = gone.kind.health()
            else {
                continue;
            };
            // Never Blocking: that refuses the very IPC the user needs to lift the redirect.
            let severity = if gone.broken {
                severity.max(ServiceHealthSeverity::Degraded)
            } else {
                severity
            };
            note(
                &mut worst,
                component,
                severity,
                format!("task '{name}' ended: {}", gone.why),
            );
        }
        for (name, (for_how_long, what)) in &inner.hung {
            let Some(kind) = inner.pulses.get(name).map(|p| p.kind) else {
                continue;
            };
            let TaskHealth::Reports {
                component,
                severity,
            } = kind.health()
            else {
                continue;
            };
            // A Blocking verdict would refuse the first client that does get
            // through a slow acceptor; the watchdog acts on a real hang.
            let severity = if kind == ServiceTaskKind::IpcAcceptLoop {
                severity.min(ServiceHealthSeverity::Degraded)
            } else {
                severity
            };
            note(
                &mut worst,
                component,
                severity,
                format!(
                    "task '{name}' {what} for {} s past its deadline",
                    for_how_long.as_secs()
                ),
            );
        }
        for component in REPORTED_COMPONENTS {
            match worst.get(&component) {
                Some((severity, message)) => {
                    self.health
                        .record_as(LIVENESS_SOURCE, component, *severity, message.clone());
                }
                None => self.health.clear_as(LIVENESS_SOURCE, component),
            }
        }
    }
}

/// Keep the worse of what is already noted for `component` and this.
fn note(
    worst: &mut BTreeMap<HealthComponent, (ServiceHealthSeverity, String)>,
    component: HealthComponent,
    severity: ServiceHealthSeverity,
    message: String,
) {
    match worst.get(&component) {
        Some((current, _)) if *current >= severity => {}
        _ => {
            worst.insert(component, (severity, message));
        }
    }
}

/// Tasks whose hang leaves the machine without working DNS or with the pass
/// that enforces policy stuck: the resolver and its reconcile worker, and the
/// periodic passes, which wait on the same locks any pass does. And the
/// acceptor, seen through its [`TickWatch`]: hung, no client can reach the
/// service to repair anything.
pub const RESTART_ON_HANG: &[ServiceTaskKind] = &[
    ServiceTaskKind::DnsResolver,
    ServiceTaskKind::DnsReconcileWorker,
    ServiceTaskKind::RouteReconcileSafety,
    ServiceTaskKind::PrincipalEnforcement,
    ServiceTaskKind::IpcAcceptLoop,
];

/// How long the watchdog must itself see one of [`RESTART_ON_HANG`] past its
/// own deadline before the service gives up on it: past every honest pass,
/// short of a user giving up on the network.
pub const HANG_RESTART_AFTER: Duration = Duration::from_secs(180);

/// How often the hang watchdog looks.
const HANG_WATCH_EVERY: Duration = Duration::from_secs(15);

/// A gap between two looks longer than this is a sleep or a stall of the
/// watchdog's own: the ages it then reads say nothing, so watching restarts.
const HANG_WATCH_GAP: Duration = Duration::from_secs(60);

/// What the watchdog does about a hang: the name of the task and how long it
/// was seen hung. Expected not to return (it ends the process).
pub type OnHang = Arc<dyn Fn(&str, Duration) + Send + Sync>;

/// Makes a waiting acceptor finish its tick (a connection to its own listener).
/// Must not block.
pub type Poke = Arc<dyn Fn() + Send + Sync>;

/// The watchdog's memory between looks. A hang counts only for the time the
/// watchdog itself saw it, look after look: a pulse's age alone also grows
/// through a suspend, and a tick caught mid-flight by one would read as hung.
#[derive(Default)]
struct HangWatch {
    last_look_ms: Option<u64>,
    /// The task seen hung at the last look and for how long so far.
    suspect: Option<(String, Duration)>,
}

impl HangWatch {
    /// One look at `now_ms` on the board's clock; the task to give up on, if
    /// any. Nothing while the stop runs: the stop has its own limit.
    fn look(
        &mut self,
        board: &TaskLiveness,
        now_ms: u64,
        stopping: bool,
    ) -> Option<(String, Duration)> {
        let gap = self
            .last_look_ms
            .map(|last| Duration::from_millis(now_ms.saturating_sub(last)));
        self.last_look_ms = Some(now_ms);
        if stopping || gap.is_none_or(|gap| gap > HANG_WATCH_GAP) {
            self.suspect = None;
            return None;
        }
        let gap = gap.unwrap_or_default();
        let Some((name, _)) = board.hung_past_at(RESTART_ON_HANG, Duration::ZERO, now_ms) else {
            self.suspect = None;
            return None;
        };
        let seen = match self.suspect.take() {
            Some((suspect, seen)) if suspect == name => seen + gap,
            _ => Duration::ZERO,
        };
        if seen >= HANG_RESTART_AFTER {
            return Some((name, seen));
        }
        self.suspect = Some((name, seen));
        None
    }
}

/// Start the hang watchdog on a thread of its own, outside every pass and
/// lock it watches: a hang inside the service is noticed by health alone
/// otherwise, which nobody reads while every request waits on the same lock.
///
/// `poke` runs before every wait: an idle acceptor sits in its tick until a
/// client comes, so a live one must be made to turn once per look.
pub fn spawn_hang_watchdog(
    board: Arc<TaskLiveness>,
    poke: Option<Poke>,
    on_hang: OnHang,
) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("nrr-hang-watchdog".to_owned())
        .spawn(move || {
            let mut watch = HangWatch::default();
            loop {
                if let Some(poke) = poke.as_ref() {
                    poke();
                }
                std::thread::sleep(HANG_WATCH_EVERY);
                let stopping = crate::lifecycle::teardown_in_progress();
                if let Some((name, seen)) = watch.look(&board, board.now_ms(), stopping) {
                    tracing::error!(
                        target: "nrr::supervisor",
                        msg_key = "supervised-hang-watchdog-fired",
                        task = name.as_str(),
                        seconds = seen.as_secs(),
                        "a task the network depends on is hung; handing DNS back and restarting the service",
                    );
                    on_hang(&name, seen);
                }
            }
        })
        .map(|_| ())
}

/// Every component a registry entry can name.
const REPORTED_COMPONENTS: [HealthComponent; 5] = [
    HealthComponent::Ipc,
    HealthComponent::Apply,
    HealthComponent::Adapters,
    HealthComponent::BackgroundTasks,
    HealthComponent::Integrity,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ServiceRuntimeState;

    fn board() -> (Arc<TaskLiveness>, Arc<HealthAggregator>) {
        let health = Arc::new(HealthAggregator::new());
        health.clear_lifecycle_override();
        (Arc::new(TaskLiveness::new(Arc::clone(&health))), health)
    }

    #[test]
    fn the_resolvers_upstream_trouble_degrades_adapters_and_clears_with_it() {
        let (liveness, health) = board();
        liveness.say_dns_upstream(Some("only another VPN's DNS server answers"));
        let (severity, message) = component(&health, HealthComponent::Adapters).expect("said");
        assert_eq!(severity, ServiceHealthSeverity::Degraded);
        assert!(message.starts_with(nrr_shared::ipc_payloads::DNS_ONLY_FOREIGN_RESOLVER));
        assert_eq!(health.snapshot().state, ServiceRuntimeState::Degraded);
        liveness.say_dns_upstream(None);
        assert!(component(&health, HealthComponent::Adapters)
            .is_none_or(|(severity, _)| severity < ServiceHealthSeverity::Degraded));
    }

    fn component(
        health: &HealthAggregator,
        component: HealthComponent,
    ) -> Option<(ServiceHealthSeverity, String)> {
        health
            .snapshot()
            .components
            .into_iter()
            .find(|c| c.component == component)
            .map(|c| (c.severity, c.message))
    }

    #[test]
    fn a_lease_dropped_unfinished_reports_the_registry_verdict() {
        let (board, health) = board();
        let lease = board.lease(ServiceTaskKind::DnsResolver, None, Watch::None);
        drop(lease);
        let (severity, message) = component(&health, HealthComponent::Apply).expect("apply");
        assert_eq!(severity, ServiceHealthSeverity::Degraded);
        assert!(message.contains("dns-resolver"), "{message}");
        assert_eq!(health.snapshot().state, ServiceRuntimeState::Degraded);
    }

    #[test]
    fn a_deliberate_stop_says_nothing_and_a_broken_exit_only_degrades() {
        let (board, health) = board();
        board
            .lease(ServiceTaskKind::DnsResolver, None, Watch::None)
            .finish(ThreadExit::Stopped);
        assert_eq!(component(&health, HealthComponent::Apply), None);
        board
            .lease(ServiceTaskKind::DnsResolver, None, Watch::None)
            .finish(ThreadExit::Broken("system DNS not restored".into()));
        let (severity, message) = component(&health, HealthComponent::Apply).expect("apply");
        assert_eq!(severity, ServiceHealthSeverity::Degraded);
        assert!(message.contains("system DNS not restored"), "{message}");
        assert_eq!(health.snapshot().state, ServiceRuntimeState::Degraded);
    }

    #[test]
    fn a_resolver_that_could_not_restore_dns_tells_the_clients_at_once() {
        use crate::ipc_handlers::event_bus::EventBus;
        use nrr_shared::ipc_payloads::StatusUpdateEvent;
        let health = Arc::new(HealthAggregator::new());
        let bus = Arc::new(EventBus::new());
        let board =
            Arc::new(TaskLiveness::new(Arc::clone(&health)).with_event_bus(Arc::clone(&bus)));
        let listener = bus.subscribe("gui".into(), Some(0));

        board
            .lease(ServiceTaskKind::DnsResolver, None, Watch::None)
            .finish(ThreadExit::Ended("serve loop ended".into()));
        board
            .lease(ServiceTaskKind::FcrdnsLearner, None, Watch::None)
            .finish(ThreadExit::Broken("not the resolver".into()));
        assert!(
            bus.peek_pending_for(&listener.subscription_id, 8)
                .is_empty(),
            "only the resolver's broken exit is news",
        );

        board
            .lease(ServiceTaskKind::DnsResolver, None, Watch::None)
            .finish(ThreadExit::Broken("system DNS not restored".into()));
        let pending = bus.peek_pending_for(&listener.subscription_id, 8);
        assert_eq!(pending.len(), 1, "{pending:?}");
        assert!(matches!(
            pending[0].event,
            StatusUpdateEvent::SystemDnsNotRestored
        ));
    }

    #[test]
    fn leasing_the_same_name_again_lifts_the_verdict() {
        let (board, health) = board();
        board
            .lease(ServiceTaskKind::FcrdnsLearner, None, Watch::None)
            .finish(ThreadExit::Ended("queue closed".into()));
        assert_eq!(
            component(&health, HealthComponent::BackgroundTasks).map(|c| c.0),
            Some(ServiceHealthSeverity::Degraded)
        );
        let _again = board.lease(ServiceTaskKind::FcrdnsLearner, None, Watch::None);
        assert_eq!(component(&health, HealthComponent::BackgroundTasks), None);
        assert!(board.troubled().is_empty());
    }

    #[test]
    fn work_past_its_deadline_is_a_hang_and_its_end_is_a_recovery() {
        let (board, health) = board();
        let lease = board.lease(
            ServiceTaskKind::DnsReconcileWorker,
            None,
            Watch::Work(Duration::from_millis(20)),
        );
        let work = lease.work();
        std::thread::sleep(Duration::from_millis(60));
        board.audit();
        let (severity, message) = component(&health, HealthComponent::Apply).expect("apply");
        assert_eq!(severity, ServiceHealthSeverity::Degraded);
        assert!(message.contains("dns-reconcile-worker"), "{message}");
        drop(work);
        board.audit();
        assert_eq!(component(&health, HealthComponent::Apply), None);
    }

    #[test]
    fn a_silent_beating_loop_is_a_hang_but_idle_work_is_not() {
        let (board, health) = board();
        let beating = board.lease(
            ServiceTaskKind::FakeIpWatchdog,
            None,
            Watch::Beats(Duration::from_millis(20)),
        );
        let _queue = board.lease(
            ServiceTaskKind::FcrdnsLearner,
            None,
            Watch::Work(Duration::from_millis(20)),
        );
        std::thread::sleep(Duration::from_millis(60));
        board.audit();
        assert_eq!(board.troubled(), vec!["fake-ip-watchdog".to_owned()]);
        beating.beat();
        board.audit();
        assert!(board.troubled().is_empty());
        assert_eq!(component(&health, HealthComponent::BackgroundTasks), None);
    }

    #[test]
    fn a_supervised_tick_past_its_deadline_degrades_where_the_registry_says() {
        let (board, health) = board();
        let id = ServiceTaskKind::PrincipalEnforcement.id();
        let pulse = board
            .supervised(id, Some(Duration::from_millis(20)))
            .expect("known task");
        let tick = board.tick_begins(&pulse);
        std::thread::sleep(Duration::from_millis(60));
        board.audit();
        assert_eq!(
            component(&health, HealthComponent::Apply).map(|c| c.0),
            Some(ServiceHealthSeverity::Degraded)
        );
        drop(tick);
        board.supervised_ended(id);
        assert_eq!(component(&health, HealthComponent::Apply), None);
        assert!(board.supervised("no-such-task", None).is_none());
    }

    #[test]
    fn labelled_leases_of_one_kind_are_told_apart() {
        let (board, _health) = board();
        let network = board.lease(
            ServiceTaskKind::NetChangeDebounce,
            Some("network"),
            Watch::None,
        );
        board
            .lease(
                ServiceTaskKind::NetChangeDebounce,
                Some("power"),
                Watch::None,
            )
            .finish(ThreadExit::Ended("died".into()));
        assert_eq!(
            board.troubled(),
            vec!["net-change-debounce:power".to_owned()]
        );
        network.finish(ThreadExit::Stopped);
        assert_eq!(
            board.troubled(),
            vec!["net-change-debounce:power".to_owned()]
        );
    }

    /// On a fake clock: a pass wedged in a tick, or a silent resolver, is
    /// given up on once the watchdog has seen it hung for the limit, look
    /// after look; not for a task the network does not depend on, not across
    /// a sleep, and not while the stop runs.
    #[test]
    fn the_hang_watchdog_gives_up_on_a_hung_pass_or_resolver_it_saw_for_the_limit() {
        let (board, _health) = board();
        let start = board.now_ms();
        let at = |s: u64| start + s * 1_000;
        let every = HANG_WATCH_EVERY.as_secs();
        let looks_to_fire = HANG_RESTART_AFTER.as_secs() / every;

        // A non-critical worker hung for ten minutes is health's business.
        let learner = board.lease(
            ServiceTaskKind::FcrdnsLearner,
            None,
            Watch::Work(Duration::from_secs(1)),
        );
        let learner_work = learner.work();
        let mut watch = HangWatch::default();
        for n in 0..=40 {
            assert_eq!(watch.look(&board, at(n * every), false), None);
        }
        drop(learner_work);

        // The periodic pass, wedged inside a tick from the start.
        let pulse = board
            .supervised(
                ServiceTaskKind::RouteReconcileSafety.id(),
                Some(DEFAULT_TICK_DEADLINE),
            )
            .expect("pulse");
        let tick = board.tick_begins(&pulse);
        let first_hung = DEFAULT_TICK_DEADLINE.as_secs() + every;
        let mut watch = HangWatch::default();
        assert_eq!(watch.look(&board, at(first_hung - every), false), None);
        for n in 0..looks_to_fire {
            assert_eq!(
                watch.look(&board, at(first_hung + n * every), false),
                None,
                "look {n}"
            );
        }
        let fired = watch.look(&board, at(first_hung + looks_to_fire * every), false);
        assert_eq!(
            fired.map(|(name, _)| name),
            Some(ServiceTaskKind::RouteReconcileSafety.id().to_owned())
        );

        // The same hang across a sleep starts over, and the stop silences it.
        let mut watch = HangWatch::default();
        assert_eq!(watch.look(&board, at(1_000), false), None);
        assert_eq!(watch.look(&board, at(1_000 + 3_600), false), None);
        for n in 1..=looks_to_fire {
            assert_eq!(
                watch.look(&board, at(4_600 + n * every), false),
                None,
                "after sleep {n}"
            );
        }
        let would_fire = at(4_600 + (looks_to_fire + 1) * every);
        assert_eq!(watch.look(&board, would_fire, true), None);
        assert_eq!(watch.look(&board, would_fire + every * 1_000, false), None);
        drop(tick);

        // The resolver's serve loop gone silent.
        let resolver = board.lease(
            ServiceTaskKind::DnsResolver,
            None,
            Watch::Beats(Duration::from_secs(60)),
        );
        let silent_from = board.now_ms() + 61_000;
        let mut watch = HangWatch::default();
        let mut fired = None;
        for n in 0..=looks_to_fire + 1 {
            fired = fired.or(watch.look(&board, silent_from + n * every * 1_000, false));
        }
        assert_eq!(
            fired.map(|(name, _)| name),
            Some(ServiceTaskKind::DnsResolver.id().to_owned())
        );
        resolver.finish(ThreadExit::Stopped);
        learner.finish(ThreadExit::Stopped);
    }

    /// On a fake clock: an acceptor idle between ticks (a backoff) or whose
    /// ticks the pokes keep finishing is left alone; a tick no poke finishes
    /// is given up on once past its deadline and seen hung for the limit.
    #[test]
    fn the_hang_watchdog_gives_up_on_an_accept_tick_no_poke_finishes() {
        let (board, _health) = board();
        let accept = board.tick_watch(
            ServiceTaskKind::IpcAcceptLoop,
            "accept",
            ACCEPT_TICK_DEADLINE,
        );
        let start = board.now_ms() + 10_000;
        let every_ms = HANG_WATCH_EVERY.as_secs() * 1_000;
        let at = |n: u64| start + n * every_ms;
        let enough = (ACCEPT_TICK_DEADLINE + HANG_RESTART_AFTER).as_secs() * 1_000 / every_ms + 4;

        let mut watch = HangWatch::default();
        for n in 0..=enough {
            assert_eq!(watch.look(&board, at(n), false), None, "idle {n}");
        }

        // Each poke ended a tick; the next one began a moment before the look.
        let mut watch = HangWatch::default();
        for n in 0..=enough {
            let _tick = accept.tick();
            accept
                .pulse
                .last_seen
                .store(at(n) - 1_000, Ordering::Relaxed);
            assert_eq!(watch.look(&board, at(n), false), None, "poked {n}");
        }

        // One tick no poke ends.
        let wedged_from = at(enough + 1);
        let _tick = accept.tick();
        accept.pulse.last_seen.store(wedged_from, Ordering::Relaxed);
        let mut watch = HangWatch::default();
        let fired = (1..=2 * enough).find_map(|n| {
            watch
                .look(&board, wedged_from + n * every_ms, false)
                .map(|found| (n, found))
        });
        let (n, (name, seen)) = fired.expect("a wedged accept tick is given up on");
        assert_eq!(name, "ipc-accept-loop:accept");
        assert!(seen >= HANG_RESTART_AFTER);
        assert!(
            Duration::from_millis(n * every_ms) > ACCEPT_TICK_DEADLINE + HANG_RESTART_AFTER,
            "not before the deadline plus the limit (look {n})"
        );
    }

    #[test]
    fn a_hung_accept_tick_degrades_ipc_but_never_blocks_it() {
        let (board, health) = board();
        let accept = board.tick_watch(
            ServiceTaskKind::IpcAcceptLoop,
            "accept",
            Duration::from_millis(20),
        );
        let tick = accept.tick();
        std::thread::sleep(Duration::from_millis(60));
        board.audit();
        assert_eq!(
            component(&health, HealthComponent::Ipc).map(|c| c.0),
            Some(ServiceHealthSeverity::Degraded)
        );
        drop(tick);
        board.audit();
        assert_eq!(component(&health, HealthComponent::Ipc), None);
    }
}
