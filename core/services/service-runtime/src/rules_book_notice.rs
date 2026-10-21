//! Whose stored rule book cannot be read, told to that user alone.
//!
//! Several rules providers read the same books, each with its own memory of
//! what failed; the notice is the user's, so one registry per service decides
//! when it is news. A push goes out when a user's book stops reading and when
//! it reads again, to that user's connections only; the snapshot carries the
//! standing state for a client that connects later.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use nrr_shared::ipc_payloads::StatusUpdateEvent;
use nrr_storage::BASELINE_PRINCIPAL;

use crate::ipc_handlers::event_bus::EventBus;

/// The users whose book does not read, and where their news goes.
#[derive(Default)]
pub struct RulesBookNotices {
    unreadable: Mutex<HashSet<String>>,
    /// Mirrors the set's size: a read that succeeds asks on the traffic path,
    /// and while nobody is listed the answer costs no lock.
    listed: AtomicUsize,
    events: OnceLock<Arc<EventBus>>,
}

impl RulesBookNotices {
    pub fn new() -> Self {
        Self::default()
    }

    /// Where the pushes go. The first bus stays.
    pub fn attach_events(&self, events: Arc<EventBus>) {
        let _ = self.events.set(events);
    }

    /// `principal`'s book could not be read; pushed only when that is new.
    pub fn raise(&self, principal: &str) {
        // The baseline has no connections of its own: each user reading
        // through it is raised under their own SID.
        if principal.is_empty() || principal == BASELINE_PRINCIPAL {
            return;
        }
        let added = {
            let mut set = self
                .unreadable
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let added = set.insert(principal.to_owned());
            self.listed.store(set.len(), Ordering::Release);
            added
        };
        if added {
            self.publish(principal, true);
        }
    }

    /// `principal`'s book reads; pushed only when it was listed.
    pub fn clear(&self, principal: &str) {
        if !self.any() {
            return;
        }
        let removed = {
            let mut set = self
                .unreadable
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let removed = set.remove(principal);
            self.listed.store(set.len(), Ordering::Release);
            removed
        };
        if removed {
            self.publish(principal, false);
        }
    }

    /// Whether anyone's book is listed; no lock.
    pub fn any(&self) -> bool {
        self.listed.load(Ordering::Acquire) > 0
    }

    /// Whether `principal`'s own book is listed. Never answers for another.
    pub fn unreadable_for(&self, principal: &str) -> bool {
        self.any()
            && self
                .unreadable
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(principal)
    }

    fn publish(&self, principal: &str, unreadable: bool) {
        if let Some(bus) = self.events.get() {
            bus.publish_for(
                principal,
                StatusUpdateEvent::RulesBookUnreadable {
                    sid: principal.to_owned(),
                    unreadable,
                },
            );
        }
    }
}

static SERVICE: OnceLock<Arc<RulesBookNotices>> = OnceLock::new();

/// The service's registry, which every production rules provider reports to.
pub fn service() -> &'static Arc<RulesBookNotices> {
    SERVICE.get_or_init(|| Arc::new(RulesBookNotices::new()))
}

/// Send the service registry's news over `events`.
pub fn attach_events(events: Arc<EventBus>) {
    service().attach_events(events);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notices(bus: &EventBus, sub: &str) -> Vec<(String, bool)> {
        bus.peek_pending_for(sub, 64)
            .into_iter()
            .filter_map(|e| match e.event {
                StatusUpdateEvent::RulesBookUnreadable { sid, unreadable } => {
                    Some((sid, unreadable))
                }
                _ => None,
            })
            .collect()
    }

    /// Told once per occurrence, to its own user only; the end is news too.
    #[test]
    fn only_the_affected_user_is_told_once_and_when_it_reads_again() {
        let bus = Arc::new(EventBus::new());
        let mine = bus
            .subscribe_as("mine".into(), Some("S-1-5-21-7001".into()), None)
            .subscription_id;
        let other = bus
            .subscribe_as("other".into(), Some("S-1-5-21-7002".into()), None)
            .subscription_id;
        let registry = RulesBookNotices::new();
        registry.attach_events(Arc::clone(&bus));

        registry.raise("S-1-5-21-7001");
        registry.raise("S-1-5-21-7001");
        assert_eq!(notices(&bus, &mine), vec![("S-1-5-21-7001".into(), true)]);
        assert!(notices(&bus, &other).is_empty());
        assert!(registry.unreadable_for("S-1-5-21-7001"));
        assert!(!registry.unreadable_for("S-1-5-21-7002"));

        registry.clear("S-1-5-21-7002");
        registry.clear("S-1-5-21-7001");
        registry.clear("S-1-5-21-7001");
        assert_eq!(
            notices(&bus, &mine),
            vec![
                ("S-1-5-21-7001".into(), true),
                ("S-1-5-21-7001".into(), false)
            ]
        );
        assert!(notices(&bus, &other).is_empty());
        assert!(!registry.any());
    }

    #[test]
    fn the_baseline_itself_is_nobodys_notice() {
        let registry = RulesBookNotices::new();
        registry.raise(BASELINE_PRINCIPAL);
        registry.raise("");
        assert!(!registry.any());
    }
}
