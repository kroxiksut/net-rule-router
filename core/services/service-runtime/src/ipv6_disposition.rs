//! The IPv6 disposition each principal's last applied plan was computed under.
//!
//! The DNS path decides per AAAA query whether a rule host's IPv6 may be
//! answered, and reading the adapters there would put an enumeration on every
//! lookup. The plan pass already resolved the answer; this is where it leaves it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use crate::enforcement_planner::Ipv6Guard;

#[derive(Default)]
pub struct Ipv6Dispositions(Mutex<HashMap<String, Ipv6Guard>>);

impl Ipv6Dispositions {
    pub fn set(&self, sid: &str, guard: Ipv6Guard) {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(sid.to_string(), guard);
    }

    /// `Off` for a principal no plan was applied for: nothing is known to carry
    /// the family, so nothing may be answered as if it did.
    #[must_use]
    pub fn of(&self, sid: &str) -> Ipv6Guard {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .copied()
            .unwrap_or(Ipv6Guard::Off)
    }

    pub fn forget(&self, sid: &str) {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).remove(sid);
    }
}

/// Process-wide board: the orchestrator writes it, the DNS listener reads it,
/// and they are built in different composition scopes.
pub fn global_ipv6_dispositions() -> Arc<Ipv6Dispositions> {
    static GLOBAL: OnceLock<Arc<Ipv6Dispositions>> = OnceLock::new();
    Arc::clone(GLOBAL.get_or_init(|| Arc::new(Ipv6Dispositions::default())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_principal_reads_off_and_a_forgotten_one_goes_back_to_off() {
        let board = Ipv6Dispositions::default();
        assert_eq!(board.of("S-1"), Ipv6Guard::Off);
        board.set("S-1", Ipv6Guard::FiltersAndRoutes);
        assert_eq!(board.of("S-1"), Ipv6Guard::FiltersAndRoutes);
        assert_eq!(board.of("S-2"), Ipv6Guard::Off, "per principal");
        board.forget("S-1");
        assert_eq!(board.of("S-1"), Ipv6Guard::Off);
    }
}
