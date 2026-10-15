//! A bounded pool of worker threads for upstream dials.
//!
//! A dial blocks for up to the connect timeout, so it never runs on the poll
//! thread. One thread per dial bounded the count by nothing a client could not
//! defeat: a SYN followed by a reset frees the flow slot while its dial lingers
//! for the full timeout, so a loop of them grew threads without limit. Here
//! the workers are capped, the backlog is capped, and past both the dial is
//! refused — the flow fails like any other dial failure, and the poll thread
//! never pays for a thread the OS would not give it.
//!
//! Workers are lazy: one is started only when a job arrives and nobody is
//! idle, and one that sits idle past [`DialPool::idle_timeout`] exits, so a
//! quiet stack holds no dial threads at all.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};

use super::guard;

/// Work a dial pool runs on one of its workers.
pub(super) type DialJob = Box<dyn FnOnce() + Send>;

/// Why a dial was not accepted. Either way the flow fails at once; the
/// distinction is for the log.
#[derive(Debug)]
pub(super) enum DialRefusal {
    /// Every worker is busy and the backlog is full.
    QueueFull,
    /// The OS refused a thread and no worker exists to run the job later.
    NoWorker(std::io::Error),
    /// The stack that owned the pool is gone.
    Closed,
}

impl std::fmt::Display for DialRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QueueFull => f.write_str("dial backlog is full"),
            Self::NoWorker(error) => write!(f, "no dial worker could be started: {error}"),
            Self::Closed => f.write_str("dial pool is closed"),
        }
    }
}

struct PoolState {
    queue: VecDeque<DialJob>,
    /// Workers alive, idle or busy.
    live: usize,
    /// Workers parked on the condvar. A submit that finds one only notifies.
    idle: usize,
    closed: bool,
}

pub(super) struct DialPool {
    state: Mutex<PoolState>,
    wake: Condvar,
    max_workers: usize,
    queue_cap: usize,
    idle_timeout: std::time::Duration,
    health: Arc<super::super::health::FakeIpHealth>,
    /// Test hook: make every thread start fail the way an exhausted OS does.
    refuse_spawns: AtomicBool,
}

impl DialPool {
    pub(super) fn new(
        max_workers: usize,
        queue_cap: usize,
        idle_timeout: std::time::Duration,
        health: Arc<super::super::health::FakeIpHealth>,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(PoolState {
                queue: VecDeque::new(),
                live: 0,
                idle: 0,
                closed: false,
            }),
            wake: Condvar::new(),
            max_workers: max_workers.max(1),
            queue_cap: queue_cap.max(1),
            idle_timeout,
            health,
            refuse_spawns: AtomicBool::new(false),
        })
    }

    /// Queue a dial. Called from the poll thread only, which is what lets a
    /// job that no worker can ever run be taken straight back off the queue.
    pub(super) fn submit(self: &Arc<Self>, job: DialJob) -> Result<(), DialRefusal> {
        let mut state = guard(&self.state);
        if state.closed {
            return Err(DialRefusal::Closed);
        }
        if state.queue.len() >= self.queue_cap {
            return Err(DialRefusal::QueueFull);
        }
        state.queue.push_back(job);
        // `idle` drops only once a woken worker runs, so a burst submitted
        // before that would all queue behind it; a job past the idle count
        // gets a worker of its own.
        if state.queue.len() <= state.idle || state.live >= self.max_workers {
            drop(state);
            self.wake.notify_one();
            return Ok(());
        }
        state.live += 1;
        drop(state);
        match self.spawn_worker() {
            Ok(()) => Ok(()),
            Err(error) => {
                self.health.record_worker_spawn_failed();
                let mut state = guard(&self.state);
                state.live -= 1;
                if state.live == 0 {
                    // Nobody will ever pick it up; refuse rather than strand it.
                    state.queue.pop_back();
                    return Err(DialRefusal::NoWorker(error));
                }
                // A busy worker drains the queue before idling, so the job
                // still runs — just later.
                Ok(())
            }
        }
    }

    /// Stop accepting work, drop the backlog and let every worker exit once
    /// its current dial returns.
    pub(super) fn close(&self) {
        let mut state = guard(&self.state);
        state.closed = true;
        state.queue.clear();
        drop(state);
        self.wake.notify_all();
    }

    #[cfg(test)]
    pub(super) fn live_workers(&self) -> usize {
        guard(&self.state).live
    }

    #[cfg(test)]
    pub(super) fn queued(&self) -> usize {
        guard(&self.state).queue.len()
    }

    #[cfg(test)]
    pub(super) fn set_refuse_spawns(&self, refuse: bool) {
        self.refuse_spawns.store(refuse, Ordering::SeqCst);
    }

    fn spawn_worker(self: &Arc<Self>) -> std::io::Result<()> {
        if self.refuse_spawns.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("thread start refused (test hook)"));
        }
        let pool = Arc::clone(self);
        std::thread::Builder::new()
            .name("nrr-fakeip-dial".to_string())
            .spawn(move || pool.worker_loop())
            .map(drop)
    }

    /// Drain the queue, park when it is empty, exit when idle too long or
    /// closed. A job that panics costs that dial, not the worker: the job's
    /// own drop guard reports the failure to its flow.
    fn worker_loop(&self) {
        let mut state = guard(&self.state);
        loop {
            if state.closed {
                state.live -= 1;
                return;
            }
            if let Some(job) = state.queue.pop_front() {
                drop(state);
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
                state = guard(&self.state);
                continue;
            }
            state.idle += 1;
            let (next, timeout) = self
                .wake
                .wait_timeout(state, self.idle_timeout)
                .unwrap_or_else(PoisonError::into_inner);
            state = next;
            state.idle -= 1;
            if timeout.timed_out() && state.queue.is_empty() {
                state.live -= 1;
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use super::*;

    fn pool(max_workers: usize) -> Arc<DialPool> {
        DialPool::new(
            max_workers,
            64,
            Duration::from_secs(10),
            Arc::new(super::super::super::health::FakeIpHealth::new()),
        )
    }

    /// A page opens its connections at once. With one worker parked, the
    /// burst must not queue behind it: each dial past the idle count gets a
    /// worker of its own, so the burst takes one dial's time, not the sum.
    #[test]
    fn a_burst_after_an_idle_worker_dials_in_parallel() {
        let pool = pool(8);
        let (done, finished) = mpsc::channel();
        let first = done.clone();
        pool.submit(Box::new(move || first.send(()).expect("send")))
            .expect("first dial");
        finished
            .recv_timeout(Duration::from_secs(5))
            .expect("first dial ran");
        let deadline = Instant::now() + Duration::from_secs(5);
        while guard(&pool.state).idle == 0 {
            assert!(Instant::now() < deadline, "the worker never parked");
            std::thread::sleep(Duration::from_millis(5));
        }

        let started = Instant::now();
        for _ in 0..4 {
            let done = done.clone();
            pool.submit(Box::new(move || {
                std::thread::sleep(Duration::from_millis(300));
                done.send(()).expect("send");
            }))
            .expect("burst dial");
        }
        for _ in 0..4 {
            finished
                .recv_timeout(Duration::from_secs(5))
                .expect("burst dial ran");
        }
        assert!(
            started.elapsed() < Duration::from_millis(900),
            "the burst ran one after another: {:?}",
            started.elapsed()
        );
        assert!(pool.live_workers() <= 8);
        pool.close();
    }
}
