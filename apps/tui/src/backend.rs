//! The service side of the interface, on its own thread: every IPC call blocks,
//! so none of them runs on the thread that reads keys and draws. Results and
//! push events reach the interface over one channel.

use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use nrr_ipc_client::{ipc_operation_timeout, IpcClient};
use nrr_platform_api::authorization::TerminalPromptAgent;
use nrr_platform_api::service_control::ServiceControlPort;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    SnapshotInitialResponse, StatusUpdateEvent, StatusUpdatesSubscribeRequest,
};
use serde_json::Value;

use crate::elevation_prompt::{PromptRequest, PromptingClient};
use crate::link::{tui_command, Link};

/// How often the connection is re-checked while it is settled. The design's
/// "retry every 2 s": the client reconnects on its own, this only reports it.
pub const SETTLED_TICK: Duration = Duration::from_secs(2);
/// While a connect is in flight, so the first screen does not sit on
/// "connecting" for a whole tick after the service has answered.
const CONNECTING_TICK: Duration = Duration::from_millis(200);
/// A client that has just started reports "no answer" before its first
/// attempt; that is still connecting, not a service that is down.
const STARTUP_GRACE: Duration = Duration::from_secs(3);

pub enum Command {
    /// Re-read the snapshot: a push said it changed, or the stream has a hole.
    Refresh,
    Shutdown,
}

#[derive(Debug)]
pub enum BackendEvent {
    Link(Link),
    Snapshot(Box<SnapshotInitialResponse>),
    /// The snapshot could not be read; the text is the client's own detail.
    FetchFailed(String),
    Push(PushEvent),
    /// A screen's job finished.
    Reply(Reply),
}

/// A screen's own IPC work. It runs on the jobs thread, in the order asked,
/// so a slow call (an archive export) never holds up the connection check.
pub type Job = Box<dyn FnOnce(&dyn IpcClient) -> Reply + Send>;

/// What a job's answer changes, applied on the interface thread.
pub struct Reply(pub Box<dyn FnOnce(&mut crate::state::AppState) + Send>);

impl Reply {
    pub fn new(apply: impl FnOnce(&mut crate::state::AppState) + Send + 'static) -> Self {
        Self(Box::new(apply))
    }
}

impl std::fmt::Debug for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Reply")
    }
}

/// Jobs a key or an answer asked for; the loop that owns the backend sends
/// them, so the state never holds the backend itself.
#[derive(Default)]
pub struct Outbox {
    now: Vec<Job>,
    later: Vec<(Duration, Job)>,
}

impl Outbox {
    pub fn push(&mut self, job: Job) {
        self.now.push(job);
    }

    /// A job queued only after `delay`: a poll that must not hold up the
    /// jobs thread while it waits.
    pub fn push_after(&mut self, delay: Duration, job: Job) {
        self.later.push((delay, job));
    }

    pub fn take(&mut self) -> Vec<Job> {
        std::mem::take(&mut self.now)
    }

    pub fn take_delayed(&mut self) -> Vec<(Duration, Job)> {
        std::mem::take(&mut self.later)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.now.len() + self.later.len()
    }
}

impl std::fmt::Debug for Outbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Outbox({} + {} later)", self.now.len(), self.later.len())
    }
}

#[derive(Debug)]
pub enum PushEvent {
    Status(Box<StatusUpdateEvent>),
    /// The client dropped at least one event: what was derived from pushes may
    /// be behind.
    Gap,
}

/// The service-manager probe, built on the backend thread: a port need not be
/// `Send`, and it is only ever asked from there.
pub type RegistrationProbe = fn() -> Option<Box<dyn ServiceControlPort>>;

pub struct Backend {
    commands: Sender<Command>,
    jobs: Sender<Job>,
    prompts: Receiver<PromptRequest>,
}

impl Backend {
    #[cfg(test)]
    pub fn spawn(
        client: Arc<dyn IpcClient>,
        probe: RegistrationProbe,
        events: Sender<BackendEvent>,
    ) -> std::io::Result<Self> {
        Self::spawn_with_prompt_agent(client, probe, events, None)
    }

    /// [`Self::spawn`], with the agent that asks an administrator's password
    /// in this terminal when the service could ask nobody. The screen is
    /// handed over through [`Self::take_prompt_request`].
    pub fn spawn_with_prompt_agent(
        client: Arc<dyn IpcClient>,
        probe: RegistrationProbe,
        events: Sender<BackendEvent>,
        agent: Option<Box<dyn TerminalPromptAgent>>,
    ) -> std::io::Result<Self> {
        let (jobs, queue) = std::sync::mpsc::channel::<Job>();
        let (prompt_tx, prompts) = std::sync::mpsc::channel();
        let job_client = PromptingClient::new(client.clone(), agent, prompt_tx);
        let job_events = events.clone();
        // Ends when the backend is dropped and the queue closes.
        let _jobs = thread::Builder::new()
            .name("nrr-tui-jobs".into())
            .spawn(move || {
                while let Ok(job) = queue.recv() {
                    // A panic in one job costs that job, not every later one.
                    let run = std::panic::AssertUnwindSafe(|| job(&job_client));
                    let Ok(reply) = std::panic::catch_unwind(run) else {
                        continue;
                    };
                    if job_events.send(BackendEvent::Reply(reply)).is_err() {
                        return;
                    }
                }
            })?;
        let (commands, inbox) = std::sync::mpsc::channel();
        let _detached = thread::Builder::new()
            .name("nrr-tui-backend".into())
            .spawn(move || run(&client, probe, &events, &inbox))?;
        Ok(Self {
            commands,
            jobs,
            prompts,
        })
    }

    /// A job waiting for the screen to type a password in, if one is.
    pub fn take_prompt_request(&self) -> Option<PromptRequest> {
        self.prompts.try_recv().ok()
    }

    pub fn send(&self, command: Command) {
        // A gone backend has nothing left to do the command for.
        let _ = self.commands.send(command);
    }

    pub fn run_job(&self, job: Job) {
        let _ = self.jobs.send(job);
    }

    pub fn send_outbox(&self, outbox: &mut Outbox) {
        for job in outbox.take() {
            self.run_job(job);
        }
        for (delay, job) in outbox.take_delayed() {
            let jobs = self.jobs.clone();
            // Without a thread the poll is lost, as a failed call would be.
            let _ = thread::Builder::new()
                .name("nrr-tui-timer".into())
                .spawn(move || {
                    thread::sleep(delay);
                    let _ = jobs.send(job);
                });
        }
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.send(Command::Shutdown);
    }
}

fn run(
    client: &Arc<dyn IpcClient>,
    probe: RegistrationProbe,
    events: &Sender<BackendEvent>,
    inbox: &Receiver<Command>,
) {
    let registration = probe();
    let started = Instant::now();
    let mut last: Option<Link> = None;
    let mut subscribed = false;
    let mut told_skew = None;
    loop {
        let status = client.connection_status();
        let starting = started.elapsed() < STARTUP_GRACE;
        let link = if !Link::wants_registration(&status) {
            Link::from_status(status, None)
        } else if starting {
            Link::Connecting
        } else {
            let report = registration.as_ref().and_then(|port| port.query().ok());
            Link::from_status(status, report)
        };
        let became_connected = link.is_connected() && last.as_ref() != Some(&Link::Connected);
        if last.as_ref() != Some(&link) {
            if events.send(BackendEvent::Link(link.clone())).is_err() {
                return;
            }
            last = Some(link.clone());
        }
        if became_connected {
            let skew = client
                .negotiate_info()
                .and_then(|info| info.contract_skew());
            if skew != told_skew {
                told_skew = skew;
                let told = BackendEvent::Reply(Reply::new(move |app| app.contract_skew = skew));
                if events.send(told).is_err() {
                    return;
                }
            }
            // The client replays an accepted subscription on every reconnect,
            // so one success lasts the whole session.
            if !subscribed {
                subscribed = subscribe(client, events);
            }
            fetch_snapshot(&**client, events);
        } else if link.is_connected() && !subscribed {
            // A refused subscription is asked again while the link lives:
            // without it the screen would stop following the service.
            subscribed = subscribe(client, events);
            if subscribed {
                fetch_snapshot(&**client, events);
            }
        }

        let tick = if starting || matches!(link, Link::Connecting) {
            CONNECTING_TICK
        } else {
            SETTLED_TICK
        };
        match inbox.recv_timeout(tick) {
            Ok(Command::Refresh) => {
                // A burst of pushes asks once.
                let mut shutdown = false;
                while let Ok(next) = inbox.try_recv() {
                    shutdown |= matches!(next, Command::Shutdown);
                }
                if shutdown {
                    return;
                }
                if link.is_connected() {
                    fetch_snapshot(&**client, events);
                }
            }
            Ok(Command::Shutdown) | Err(RecvTimeoutError::Disconnected) => return,
            Err(RecvTimeoutError::Timeout) => {}
        }
    }
}

fn fetch_snapshot(client: &dyn IpcClient, events: &Sender<BackendEvent>) {
    let op = IpcOperationName::SnapshotInitialGet;
    let event = match client
        .call(
            op,
            Value::Object(Default::default()),
            ipc_operation_timeout(op),
        )
        .map_err(|e| e.to_string())
        .and_then(|v| {
            serde_json::from_value::<SnapshotInitialResponse>(v).map_err(|e| e.to_string())
        }) {
        Ok(snapshot) => BackendEvent::Snapshot(Box::new(snapshot)),
        Err(error) => BackendEvent::FetchFailed(error),
    };
    let _ = events.send(event);
}

/// Subscribe to push events. The channel is prepared before the call and put in
/// force only once the service accepted, as the client's hand-over requires.
fn subscribe(client: &Arc<dyn IpcClient>, events: &Sender<BackendEvent>) -> bool {
    let Some(pushes) = client.subscribe_push() else {
        // A client without push support: nothing to subscribe to, ever.
        return true;
    };
    let op = IpcOperationName::StatusUpdatesSubscribe;
    let request = StatusUpdatesSubscribeRequest {
        client_id: format!("{}-{}", tui_command(), std::process::id()),
        last_seen_event_id: None,
    };
    let accepted = serde_json::to_value(&request)
        .ok()
        .is_some_and(|payload| client.call(op, payload, ipc_operation_timeout(op)).is_ok());
    if !accepted {
        client.abandon_push();
        return false;
    }
    client.commit_push();
    let events = events.clone();
    // Without the forwarder the interface still shows the snapshot, so a
    // failed spawn is not fatal.
    let _ = thread::Builder::new()
        .name("nrr-tui-push".into())
        .spawn(move || {
            while let Ok(frame) = pushes.recv() {
                if let Some(event) = parse_push(&frame) {
                    if events.send(BackendEvent::Push(event)).is_err() {
                        return;
                    }
                }
            }
        });
    true
}

/// One push frame: `{ "event-id", "event": { "type", … } }`, or the client's
/// gap marker, which the service also sends to a subscriber that fell behind
/// its event ring. An event this build cannot read (a newer service's kind or
/// value) still says something changed, so it reads as a gap: what the screen
/// derived from pushes is read again instead of silently falling behind.
pub fn parse_push(frame: &Value) -> Option<PushEvent> {
    let event = frame.get("event")?;
    if event.get("type").and_then(Value::as_str) == Some("push-gap") {
        return Some(PushEvent::Gap);
    }
    Some(
        serde_json::from_value::<StatusUpdateEvent>(event.clone())
            .map_or(PushEvent::Gap, |e| PushEvent::Status(Box::new(e))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{snapshot_json, FakeService, Fixture};
    use nrr_ipc_client::ConnectionStatus;

    fn no_probe() -> Option<Box<dyn ServiceControlPort>> {
        None
    }

    fn next(rx: &Receiver<BackendEvent>) -> BackendEvent {
        rx.recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|e| panic!("no backend event: {e}"))
    }

    #[test]
    fn a_connected_service_is_reported_subscribed_and_read() {
        let fake = Arc::new(FakeService::new(ConnectionStatus::Connected));
        fake.answer(
            IpcOperationName::SnapshotInitialGet,
            snapshot_json(&Fixture::healthy()),
        );
        let (tx, rx) = std::sync::mpsc::channel();
        let client: Arc<dyn IpcClient> = fake.clone();
        let backend = Backend::spawn(client, no_probe, tx).unwrap_or_else(|e| panic!("{e}"));

        assert!(matches!(next(&rx), BackendEvent::Link(Link::Connected)));
        match next(&rx) {
            BackendEvent::Snapshot(s) => assert!(s.route_policy.is_some()),
            other => panic!("expected a snapshot, got {other:?}"),
        }

        fake.push(serde_json::json!({
            "event-id": 7,
            "event": { "type": "routing-pause-state-changed", "sid": "S", "paused": true }
        }));
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match next(&rx) {
                BackendEvent::Push(PushEvent::Status(e)) => {
                    assert!(matches!(
                        *e,
                        StatusUpdateEvent::RoutingPauseStateChanged { paused: true, .. }
                    ));
                    break;
                }
                _ if Instant::now() < deadline => {}
                other => panic!("expected the push, got {other:?}"),
            }
        }
        let ops = fake.operations();
        assert!(
            ops.contains(&IpcOperationName::StatusUpdatesSubscribe),
            "{ops:?}"
        );
        drop(backend);
    }

    #[test]
    fn a_job_that_panics_does_not_end_the_jobs_after_it() {
        let fake = Arc::new(FakeService::new(ConnectionStatus::Connected));
        let (tx, rx) = std::sync::mpsc::channel();
        let client: Arc<dyn IpcClient> = fake.clone();
        let backend = Backend::spawn(client, no_probe, tx).unwrap_or_else(|e| panic!("{e}"));
        backend.run_job(Box::new(|_| panic!("a job that goes wrong")));
        let (done_tx, done) = std::sync::mpsc::channel();
        backend.run_job(Box::new(move |_| {
            let _ = done_tx.send(());
            Reply::new(|_| {})
        }));
        assert!(
            done.recv_timeout(Duration::from_secs(5)).is_ok(),
            "the next job still runs"
        );
        drop((backend, rx));
    }

    /// The service went into "additional connection down" before this
    /// interface started; the snapshot carries it, and the screen says so.
    #[test]
    fn a_standing_enforcement_report_reaches_the_interface_through_the_snapshot() {
        let fake = Arc::new(FakeService::new(ConnectionStatus::Connected));
        let mut snapshot = snapshot_json(&Fixture::healthy());
        snapshot["enforcement-status"] = serde_json::json!([
            { "status": "secondary-down", "role": "secondary" }
        ]);
        fake.answer(IpcOperationName::SnapshotInitialGet, snapshot);
        let (tx, rx) = std::sync::mpsc::channel();
        let client: Arc<dyn IpcClient> = fake.clone();
        let backend = Backend::spawn(client, no_probe, tx).unwrap_or_else(|e| panic!("{e}"));

        let texts = crate::testing::texts_en();
        let mut app = crate::state::AppState::new(crate::screens::ScreenId::Status, false);
        let deadline = Instant::now() + Duration::from_secs(5);
        while app.snapshot.is_none() {
            assert!(Instant::now() < deadline, "no snapshot arrived");
            app.apply(next(&rx), &texts, Instant::now());
        }
        assert_eq!(
            app.routing_state(),
            crate::state::RoutingState::Limited,
            "rules not in force are not shown as applied"
        );
        assert_eq!(
            app.enforcement_down
                .get("secondary")
                .map(|d| d.status.as_str()),
            Some("secondary-down")
        );
        drop(backend);
    }

    #[test]
    fn push_frames_parse_or_drop() {
        assert!(matches!(
            parse_push(&serde_json::json!({ "event": { "type": "push-gap" } })),
            Some(PushEvent::Gap)
        ));
        // The service's own marker carries an event id besides.
        assert!(matches!(
            parse_push(&serde_json::json!({ "event-id": 42, "event": { "type": "push-gap" } })),
            Some(PushEvent::Gap)
        ));
        assert!(parse_push(&serde_json::json!({})).is_none());
    }

    /// A newer service's event, or a known one carrying a value this build
    /// cannot read, is not dropped silently: the screen reads the state again.
    #[test]
    fn an_event_this_build_cannot_read_asks_for_a_fresh_read() {
        for event in [
            serde_json::json!({ "type": "from-the-future", "sid": "S-1" }),
            serde_json::json!({ "type": "routing-pause-state-changed", "sid": "S-1", "paused": "soon" }),
        ] {
            assert!(
                matches!(
                    parse_push(&serde_json::json!({ "event-id": 7, "event": event })),
                    Some(PushEvent::Gap)
                ),
                "{event}"
            );
        }
        assert!(matches!(
            parse_push(&serde_json::json!({ "event": {
                "type": "routing-pause-state-changed", "sid": "S-1", "paused": true
            } })),
            Some(PushEvent::Status(_))
        ));
    }
}
