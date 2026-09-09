//! Where a periodic pass actually spends its time.
//!
//! The enforcement recompute was measured at a 10 s median over 497 runs in one
//! day, with requests queueing behind it — but "10 s" is a number nobody can
//! act on. What decides whether a phase belongs on a periodic path is its own
//! cost, so the pass reports its phases and the log carries the breakdown.
//!
//! Deliberately dumb: a start instant, a mark per phase, and a rendered line.
//! No histograms, no percentiles, no background aggregation — the NDJSON log is
//! already the place those get computed from, and a measurement that needs its
//! own infrastructure is one nobody keeps.

use std::time::{Duration, Instant};

/// Phase-by-phase durations of one pass.
pub struct PhaseTimings {
    started: Instant,
    last: Instant,
    phases: Vec<(&'static str, Duration)>,
}

impl PhaseTimings {
    /// Begin timing. The first [`mark`](Self::mark) measures from here.
    #[must_use]
    pub fn start() -> Self {
        let now = Instant::now();
        Self {
            started: now,
            last: now,
            phases: Vec::new(),
        }
    }

    /// Close the phase that ended just now and name it.
    ///
    /// A phase that is skipped this time round is simply never marked: an
    /// absent name in the rendered line says "did not run", which is different
    /// from `0ms` ("ran, cost nothing") and worth telling apart.
    pub fn mark(&mut self, phase: &'static str) {
        let now = Instant::now();
        self.phases
            .push((phase, now.saturating_duration_since(self.last)));
        self.last = now;
    }

    /// Total elapsed since [`start`](Self::start), including time in phases
    /// that were never marked.
    #[must_use]
    pub fn total(&self) -> Duration {
        self.started.elapsed()
    }

    /// `true` when the pass took at least `threshold` — the gate for logging,
    /// so a healthy fast pass stays silent.
    #[must_use]
    pub fn exceeded(&self, threshold: Duration) -> bool {
        self.total() >= threshold
    }

    /// One line: `seed=120ms routes=800ms filters=8400ms`, in the order the
    /// phases were marked. Millisecond resolution — a phase measured in
    /// microseconds is not the one making a pass take ten seconds.
    #[must_use]
    pub fn render(&self) -> String {
        self.phases
            .iter()
            .map(|(name, took)| format!("{name}={}ms", took.as_millis()))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Log a pass that ran long, naming what it spent the time on; stay silent
/// otherwise.
///
/// One place rather than one per caller: the threshold and the target are what
/// make these lines findable, and a second copy of them drifts.
pub fn report_if_slow(timings: &PhaseTimings, pass: &str, threshold: Duration) {
    if !timings.exceeded(threshold) {
        return;
    }
    tracing::info!(
        target: "nrr::enforcement-cost",
        pass = %pass,
        total_ms = timings.total().as_millis(),
        phases = %timings.render(),
        "enforcement pass was slow — this is what it spent the time on",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phases_are_rendered_in_the_order_they_were_marked() {
        let mut t = PhaseTimings::start();
        t.mark("seed");
        t.mark("routes");
        t.mark("filters");
        let line = t.render();
        let order: Vec<&str> = line
            .split(' ')
            .filter_map(|p| p.split('=').next())
            .collect();
        assert_eq!(order, ["seed", "routes", "filters"]);
    }

    #[test]
    fn a_phase_that_never_ran_is_absent_rather_than_zero() {
        // "did not run" and "ran, cost nothing" are different facts, and a
        // breakdown that renders both as `0ms` cannot be used to decide what to
        // take off the periodic path.
        let mut t = PhaseTimings::start();
        t.mark("routes");
        assert!(!t.render().contains("seed"));
    }

    #[test]
    fn the_threshold_gate_is_inclusive_and_measures_the_whole_pass() {
        let t = PhaseTimings::start();
        assert!(t.exceeded(Duration::ZERO), "any pass is at least zero long");
        assert!(!t.exceeded(Duration::from_secs(3600)));
    }
}
