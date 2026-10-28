//! How many forwarded push frames get a trace line of their own.

use std::sync::atomic::{AtomicU64, Ordering};

/// The first few frames are traced one by one: they are what tells a silent
/// surface from a silent service. After that only a running count now and
/// then, so a storm of pushes is not a line per frame.
#[derive(Debug, Default)]
pub struct FrameTraceBudget {
    seen: AtomicU64,
}

impl FrameTraceBudget {
    const ONE_BY_ONE: u64 = 16;
    const COUNT_EVERY: u64 = 500;

    /// Count one frame; `Some(n)` (its number) when it is worth a line.
    pub fn note(&self) -> Option<u64> {
        let n = self.seen.fetch_add(1, Ordering::Relaxed) + 1;
        (n <= Self::ONE_BY_ONE || n.is_multiple_of(Self::COUNT_EVERY)).then_some(n)
    }

    /// Frames counted so far.
    pub fn seen(&self) -> u64 {
        self.seen.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::FrameTraceBudget;

    /// A block storm forwards hundreds of frames a second; one stderr line
    /// each filled the launcher log and spent the forwarder's time on it.
    #[test]
    fn a_storm_of_push_frames_traces_a_bounded_number_of_lines() {
        let budget = FrameTraceBudget::default();
        let traced = (0..10_000).filter(|_| budget.note().is_some()).count();
        assert!(traced <= 64, "{traced} lines for 10000 frames");
        assert_eq!(budget.seen(), 10_000);
        let fresh = FrameTraceBudget::default();
        assert!((0..8).all(|_| fresh.note().is_some()));
    }
}
