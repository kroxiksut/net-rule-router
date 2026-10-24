//! Standing enforcement filters on the machine, every principal together.
//!
//! The Windows filtering service (BFE) has crashed the machine (bugcheck 0xEF)
//! after hours under ~3700 standing filters, and every signed-in user's set
//! counts towards that. A per-user count cannot see two users who are each
//! below the line while the machine is above it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// What the machine total did with the last recorded set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MachineEdge {
    /// Above the line and higher than any total reported since it was crossed.
    Rising { total: usize, previous_peak: usize },
    /// Back under the line.
    Recovered { total: usize },
    /// Nothing worth a line in the log.
    Steady,
}

#[derive(Default)]
struct Board {
    by_principal: HashMap<String, usize>,
    /// The highest total reported above the line; 0 while under it.
    alarmed_peak: usize,
}

/// Per-principal standing filter counts and the machine-wide alarm.
#[derive(Default)]
pub struct StandingVolume {
    board: Mutex<Board>,
}

impl StandingVolume {
    /// Record `principal`'s standing set and say what the total did. `line` is
    /// the platform's alarm line; `None` (a platform with no such limit) never
    /// alarms.
    pub fn record(&self, principal: &str, filters: usize, line: Option<usize>) -> MachineEdge {
        let mut board = self.board.lock().unwrap_or_else(|p| p.into_inner());
        board.by_principal.insert(principal.to_string(), filters);
        Self::edge(&mut board, line)
    }

    /// Drop a principal whose enforcement is gone.
    pub fn forget(&self, principal: &str, line: Option<usize>) -> MachineEdge {
        let mut board = self.board.lock().unwrap_or_else(|p| p.into_inner());
        board.by_principal.remove(principal);
        Self::edge(&mut board, line)
    }

    /// Filters standing on the machine.
    pub fn total(&self) -> usize {
        let board = self.board.lock().unwrap_or_else(|p| p.into_inner());
        board.by_principal.values().sum()
    }

    /// Whether the machine total is above `line`.
    pub fn is_high(&self, line: Option<usize>) -> bool {
        line.is_some_and(|line| self.total() > line)
    }

    fn edge(board: &mut Board, line: Option<usize>) -> MachineEdge {
        let total: usize = board.by_principal.values().sum();
        let Some(line) = line else {
            return MachineEdge::Steady;
        };
        if total > line {
            // Re-armed at each new high: the climb after the first crossing is
            // what the alarm exists to report.
            if total > board.alarmed_peak {
                let previous_peak = std::mem::replace(&mut board.alarmed_peak, total);
                return MachineEdge::Rising {
                    total,
                    previous_peak,
                };
            }
            MachineEdge::Steady
        } else if board.alarmed_peak > 0 {
            board.alarmed_peak = 0;
            MachineEdge::Recovered { total }
        } else {
            MachineEdge::Steady
        }
    }
}

/// Process-wide board: the orchestrator writes it, the snapshot reads it, and
/// they are built in different composition scopes.
pub fn global_standing_volume() -> Arc<StandingVolume> {
    static GLOBAL: OnceLock<Arc<StandingVolume>> = OnceLock::new();
    Arc::clone(GLOBAL.get_or_init(Arc::default))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINE: Option<usize> = Some(3200);

    /// Two users each under the line put the machine over it: the alarm is
    /// about what the machine holds, which neither user's count shows.
    #[test]
    fn two_users_under_the_line_each_alarm_the_machine_together() {
        let board = StandingVolume::default();
        assert_eq!(board.record("S-A", 2000, LINE), MachineEdge::Steady);
        assert_eq!(
            board.record("S-B", 2000, LINE),
            MachineEdge::Rising {
                total: 4000,
                previous_peak: 0
            }
        );
        assert!(board.is_high(LINE));
    }

    /// A user who signs out takes their filters off the machine and out of the
    /// total; the alarm says the machine is back under the line.
    #[test]
    fn a_user_who_leaves_takes_their_filters_out_of_the_total() {
        let board = StandingVolume::default();
        board.record("S-A", 2000, LINE);
        board.record("S-B", 2000, LINE);
        assert_eq!(
            board.forget("S-B", LINE),
            MachineEdge::Recovered { total: 2000 }
        );
        assert!(!board.is_high(LINE));
    }

    /// Each new high speaks once; a total that holds or falls back above the
    /// line stays quiet.
    #[test]
    fn the_alarm_speaks_at_each_new_high_only() {
        let board = StandingVolume::default();
        board.record("S-A", 3300, LINE);
        assert_eq!(board.record("S-A", 3250, LINE), MachineEdge::Steady);
        assert_eq!(
            board.record("S-A", 3400, LINE),
            MachineEdge::Rising {
                total: 3400,
                previous_peak: 3300
            }
        );
    }

    /// A platform with no limit never alarms, whatever the count.
    #[test]
    fn a_platform_without_a_limit_never_alarms() {
        let board = StandingVolume::default();
        assert_eq!(board.record("S-A", 100_000, None), MachineEdge::Steady);
        assert!(!board.is_high(None));
    }
}
