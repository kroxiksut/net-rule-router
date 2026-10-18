//! Whose routes the machine's own traffic follows.
//!
//! Each present user's routes steer only that user's traffic, but the service
//! accounts — the resolver, daemons, the service's own probes — belong to
//! nobody. They follow one present user: the owner chosen here. Where the
//! kernel cannot route per user, the owner's routes are the only ones installed.

use std::sync::{Arc, Mutex};

use nrr_platform_api::active_principals::PresentPrincipal;
use nrr_platform_api::enforcement::UserPrincipal;

/// Whoever signed in first, as on every platform: someone sitting down later
/// never takes the system's traffic from a user already working (over SSH, say).
/// Only between equal sign-in times does the person at a seat win; with no
/// times at all, the first the authority named.
pub fn choose_route_table_owner(present: &[PresentPrincipal]) -> Option<&UserPrincipal> {
    earliest(present.iter()).map(|p| &p.principal)
}

/// `min_by_key` keeps the first of equals, so remaining ties follow the
/// authority's order; an unknown time sorts after every known one.
fn earliest<'a>(
    candidates: impl Iterator<Item = &'a PresentPrincipal>,
) -> Option<&'a PresentPrincipal> {
    candidates.min_by_key(|p| (p.signed_in_at.is_none(), p.signed_in_at, !p.at_seat))
}

/// The owner the last enforcement pass chose, shared with whatever must act for
/// the same user. The pass records it before handing plans to the enforcer, so
/// an enforcer reading [`Self::current`] inside that call sees this pass's owner.
#[derive(Default)]
pub struct RouteTableOwner {
    owner: Mutex<Option<UserPrincipal>>,
    /// Everyone the same pass served, owner first.
    served: Mutex<Vec<UserPrincipal>>,
}

pub type RouteTableOwnerReader = Arc<dyn Fn() -> Option<UserPrincipal> + Send + Sync>;

impl RouteTableOwner {
    pub fn current(&self) -> Option<UserPrincipal> {
        self.lock().clone()
    }

    /// Everyone the last pass served, owner first: whoever the local resolver
    /// answers for, since a query carries no trace of who asked.
    pub fn served(&self) -> Vec<UserPrincipal> {
        self.served
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Record who this pass served.
    pub fn record_served(&self, served: &[UserPrincipal]) {
        let owner = self.current();
        let mut ordered: Vec<UserPrincipal> = owner.iter().cloned().collect();
        ordered.extend(
            served
                .iter()
                .filter(|p| Some(*p) != owner.as_ref())
                .cloned(),
        );
        *self.served.lock().unwrap_or_else(|p| p.into_inner()) = ordered;
    }

    /// A reader for a consumer that should not depend on this type.
    pub fn reader(self: &Arc<Self>) -> RouteTableOwnerReader {
        let owner = Arc::clone(self);
        Arc::new(move || owner.current())
    }

    /// Record this pass's choice. Returns whether the owner changed.
    pub fn record(&self, owner: Option<&UserPrincipal>) -> bool {
        let mut current = self.lock();
        if current.as_ref() == owner {
            return false;
        }
        *current = owner.cloned();
        match owner {
            Some(owner) => tracing::info!(
                target: "nrr::routes",
                msg_key = "route-table-owner-changed",
                sid = owner.as_stored(),
                "the system's own traffic now follows this user's routes",
            ),
            None => tracing::info!(
                target: "nrr::routes",
                msg_key = "route-table-owner-none",
                "nobody is signed in: the system's own traffic follows no user's routes",
            ),
        }
        true
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<UserPrincipal>> {
        self.owner.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(uid: u32, at_seat: bool, signed_in_at: Option<u64>) -> PresentPrincipal {
        PresentPrincipal {
            principal: UserPrincipal::from_linux_uid(uid),
            at_seat,
            signed_in_at,
        }
    }

    fn owner_uid(present: &[PresentPrincipal]) -> Option<u32> {
        choose_route_table_owner(present).and_then(UserPrincipal::as_unix_uid)
    }

    #[test]
    fn the_served_list_names_everyone_owner_first() {
        let owner = RouteTableOwner::default();
        let (a, b) = (
            UserPrincipal::from_linux_uid(1000),
            UserPrincipal::from_linux_uid(1001),
        );
        owner.record(Some(&b));
        owner.record_served(&[a.clone(), b.clone()]);
        assert_eq!(owner.served(), vec![b, a]);
        owner.record(None);
        owner.record_served(&[]);
        assert!(owner.served().is_empty());
    }

    #[test]
    fn whoever_signed_in_first_keeps_it_when_someone_sits_down_later() {
        let present = [user(1000, false, Some(10)), user(1001, true, Some(90))];
        assert_eq!(owner_uid(&present), Some(1000));
    }

    #[test]
    fn the_seat_wins_only_between_equal_sign_in_times() {
        let present = [user(1000, false, Some(10)), user(1001, true, Some(10))];
        assert_eq!(owner_uid(&present), Some(1001));
    }

    #[test]
    fn with_nobody_at_a_seat_the_earliest_sign_in_owns_it() {
        let present = [
            user(1000, false, Some(50)),
            user(1001, false, Some(20)),
            user(1002, false, None),
        ];
        assert_eq!(owner_uid(&present), Some(1001));
    }

    #[test]
    fn several_seats_never_outrank_an_earlier_sign_in() {
        let present = [
            user(1000, false, Some(1)),
            user(1001, true, Some(40)),
            user(1002, true, Some(30)),
        ];
        assert_eq!(owner_uid(&present), Some(1000));
    }

    #[test]
    fn without_times_the_authority_s_order_decides() {
        let present = [user(1001, false, None), user(1000, false, None)];
        assert_eq!(owner_uid(&present), Some(1001));
        let tied = [user(1001, false, Some(5)), user(1000, false, Some(5))];
        assert_eq!(owner_uid(&tied), Some(1001));
    }

    #[test]
    fn when_the_owner_leaves_the_next_one_takes_over() {
        let mut present = vec![user(1000, false, Some(10)), user(1001, true, Some(30))];
        assert_eq!(owner_uid(&present), Some(1000));
        present.remove(0);
        assert_eq!(owner_uid(&present), Some(1001));
    }

    #[test]
    fn nobody_present_means_no_owner() {
        assert_eq!(choose_route_table_owner(&[]), None);
    }

    #[test]
    fn a_change_is_reported_once_and_read_back() {
        let tracker = Arc::new(RouteTableOwner::default());
        let read = tracker.reader();
        let a = UserPrincipal::from_linux_uid(1000);
        let b = UserPrincipal::from_linux_uid(1001);

        assert!(tracker.record(Some(&a)));
        assert!(!tracker.record(Some(&a)), "same owner, no change");
        assert_eq!(read(), Some(a.clone()));

        assert!(tracker.record(Some(&b)));
        assert_eq!(read(), Some(b));
        assert!(tracker.record(None));
        assert_eq!(read(), None);
    }
}
