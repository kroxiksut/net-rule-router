//! The IPv6 disposition each principal's last applied plan was computed under.
//!
//! The DNS path decides per AAAA query whether a rule host's IPv6 may be
//! answered, and reading the adapters there would put an enumeration on every
//! lookup. The plan pass already resolved the answer; this is where it leaves it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::enforcement_planner::Ipv6Guard;

#[derive(Default)]
pub struct Ipv6Dispositions {
    by_principal: Mutex<HashMap<String, Ipv6Guard>>,
    /// A planner publishes here, so a principal with no entry is one whose
    /// first plan has not landed yet rather than one nothing will ever plan.
    plans_expected: AtomicBool,
}

impl Ipv6Dispositions {
    /// Declared by the composition whose planner calls [`Self::set`].
    pub fn expect_plans(&self) {
        self.plans_expected.store(true, Ordering::Relaxed);
    }

    pub fn set(&self, sid: &str, guard: Ipv6Guard) {
        self.by_principal
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(sid.to_string(), guard);
    }

    /// `None` while a principal's first plan is still to come: nothing routes
    /// or pins its IPv6 yet. Without a planner, an unknown principal is `Off`:
    /// nothing is known to carry the family, so nothing may be answered as if
    /// it did.
    #[must_use]
    pub fn of(&self, sid: &str) -> Option<Ipv6Guard> {
        let known = self
            .by_principal
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .copied();
        match known {
            Some(guard) => Some(guard),
            None if self.plans_expected.load(Ordering::Relaxed) => None,
            None => Some(Ipv6Guard::Off),
        }
    }

    /// The principal's enforcement is gone: it reads `Off`, not "first plan
    /// pending". One entry per principal ever planned, so this stays tiny.
    pub fn forget(&self, sid: &str) {
        self.set(sid, Ipv6Guard::Off);
    }

    /// Whether `sid`'s plan pins or routes IPv6, so learning a rule host's IPv6
    /// addresses is worth a query. A first plan still pending is not.
    #[must_use]
    pub fn names_ipv6(&self, sid: &str) -> bool {
        self.of(sid).is_some_and(names_ipv6)
    }

    /// [`Self::names_ipv6`] for anyone at all: the machine-wide cache refresh
    /// serves every principal's hosts.
    #[must_use]
    pub fn any_names_ipv6(&self) -> bool {
        self.by_principal
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .any(|guard| names_ipv6(*guard))
    }
}

fn names_ipv6(guard: Ipv6Guard) -> bool {
    matches!(guard, Ipv6Guard::FiltersOnly | Ipv6Guard::FiltersAndRoutes)
}

/// Process-wide board: the orchestrator writes it, the DNS listener reads it,
/// and they are built in different composition scopes.
pub fn global_ipv6_dispositions() -> Arc<Ipv6Dispositions> {
    static GLOBAL: OnceLock<Arc<Ipv6Dispositions>> = OnceLock::new();
    Arc::clone(GLOBAL.get_or_init(|| Arc::new(Ipv6Dispositions::default())))
}

/// The board the cache learners read. A unit test gets an empty one of its
/// own: the process-wide board is written by every planner test in the binary.
pub(crate) fn learning_ipv6_dispositions() -> Arc<Ipv6Dispositions> {
    #[cfg(test)]
    {
        Arc::default()
    }
    #[cfg(not(test))]
    {
        global_ipv6_dispositions()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_principal_reads_off_and_a_forgotten_one_goes_back_to_off() {
        let board = Ipv6Dispositions::default();
        assert_eq!(board.of("S-1"), Some(Ipv6Guard::Off));
        board.set("S-1", Ipv6Guard::FiltersAndRoutes);
        assert_eq!(board.of("S-1"), Some(Ipv6Guard::FiltersAndRoutes));
        assert_eq!(board.of("S-2"), Some(Ipv6Guard::Off), "per principal");
        board.forget("S-1");
        assert_eq!(board.of("S-1"), Some(Ipv6Guard::Off));
    }

    #[test]
    fn under_a_planner_a_principal_not_yet_planned_reads_pending_until_its_plan_lands() {
        let board = Ipv6Dispositions::default();
        board.expect_plans();
        assert_eq!(board.of("S-1"), None, "first plan still to come");
        board.set("S-1", Ipv6Guard::FiltersOnly);
        assert_eq!(board.of("S-1"), Some(Ipv6Guard::FiltersOnly));
        assert_eq!(board.of("S-2"), None, "per principal");
        board.forget("S-1");
        assert_eq!(
            board.of("S-1"),
            Some(Ipv6Guard::Off),
            "a withdrawn enforcement is not a pending one"
        );
    }

    #[test]
    fn ipv6_is_worth_learning_only_while_a_plan_pins_or_routes_it() {
        let board = Ipv6Dispositions::default();
        board.expect_plans();
        assert!(!board.names_ipv6("S-1"), "first plan pending");
        assert!(!board.any_names_ipv6());
        board.set("S-1", Ipv6Guard::Off);
        assert!(!board.names_ipv6("S-1"));
        board.set("S-2", Ipv6Guard::FiltersOnly);
        assert!(board.names_ipv6("S-2"));
        assert!(!board.names_ipv6("S-1"), "per principal");
        assert!(board.any_names_ipv6());
        board.set("S-2", Ipv6Guard::FiltersAndRoutes);
        assert!(board.names_ipv6("S-2"));
        board.forget("S-2");
        assert!(!board.any_names_ipv6());
    }
}
