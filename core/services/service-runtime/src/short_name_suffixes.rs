//! The domain each user named for completing short names, as last written.
//!
//! Asked on every unanswered single-label name, while the settings row behind
//! it changes only when the user saves: the write publishes, and the answer
//! path reads memory instead of the settings database. A principal nothing was
//! published for has no suffix.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock, RwLock};

use nrr_storage::route_bindings::{RouteBindingsRepository, RoutePolicyRecord};
use nrr_storage::StorageResult;
use rusqlite::Connection;

use crate::dns_resolver_service::NamespaceRecheck;

#[derive(Default)]
pub struct UserShortNameSuffixes {
    by_principal: RwLock<HashMap<String, String>>,
    /// Raised when a suffix changes: the DNS guard writes it into the OS
    /// search list, and reads it only when told to.
    on_change: Option<NamespaceRecheck>,
}

impl UserShortNameSuffixes {
    pub fn raising(on_change: NamespaceRecheck) -> Self {
        Self {
            by_principal: RwLock::default(),
            on_change: Some(on_change),
        }
    }

    /// Record what `policy` says for `principal`. Called with the settings
    /// connection still held, so a concurrent reload cannot land in between
    /// the write and its publication.
    pub fn publish(&self, principal: &str, policy: &RoutePolicyRecord) {
        let mut map = self.by_principal.write().unwrap_or_else(|p| p.into_inner());
        let before = match suffix_of(policy) {
            Some(suffix) => map.insert(principal.to_string(), suffix),
            None => map.remove(principal),
        };
        if before.as_ref() != map.get(principal) {
            self.raise();
        }
    }

    pub fn forget(&self, principal: &str) {
        let removed = self
            .by_principal
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .remove(principal);
        if removed.is_some() {
            self.raise();
        }
    }

    fn raise(&self) {
        if let Some(flag) = &self.on_change {
            flag.store(true, Ordering::SeqCst);
        }
    }

    /// Replace everything with what `conn` holds. A failed read keeps the
    /// previous snapshot: nothing new is known, and nothing is widened.
    pub fn reload(&self, conn: &Connection) -> StorageResult<()> {
        let repo = RouteBindingsRepository::new(conn);
        let mut fresh = HashMap::new();
        for principal in nrr_storage::principals_with_state(conn)? {
            if let Some(suffix) = suffix_of(&repo.load_for_sid(&principal)?) {
                fresh.insert(principal, suffix);
            }
        }
        *self.by_principal.write().unwrap_or_else(|p| p.into_inner()) = fresh;
        Ok(())
    }

    pub fn of(&self, principal: &str) -> Option<String> {
        self.by_principal
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(principal)
            .cloned()
    }
}

fn suffix_of(policy: &RoutePolicyRecord) -> Option<String> {
    (policy.short_name_completion && !policy.short_name_suffix.is_empty())
        .then(|| policy.short_name_suffix.clone())
}

/// One per process: the settings writer and the resolver are built on paths
/// that never meet.
pub fn global_user_short_name_suffixes() -> &'static UserShortNameSuffixes {
    static GLOBAL: OnceLock<UserShortNameSuffixes> = OnceLock::new();
    GLOBAL.get_or_init(|| {
        UserShortNameSuffixes::raising(Arc::clone(crate::dns_stack::namespace_recheck()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_storage::route_bindings::BindingSource;
    use std::sync::atomic::AtomicBool;

    fn policy(suffix: &str) -> RoutePolicyRecord {
        let mut policy = RoutePolicyRecord::empty(BindingSource::UserAssigned);
        policy.short_name_completion = !suffix.is_empty();
        policy.short_name_suffix = suffix.to_string();
        policy
    }

    /// Only a changed suffix wakes the guard: every other policy save
    /// publishes too, and must cost it nothing.
    #[test]
    fn only_a_changed_suffix_raises_the_recheck() {
        let flag: NamespaceRecheck = Arc::new(AtomicBool::new(false));
        let suffixes = UserShortNameSuffixes::raising(Arc::clone(&flag));
        let raised = || flag.swap(false, Ordering::SeqCst);

        suffixes.publish("S-1", &policy("corp.example"));
        assert!(raised(), "a new suffix");
        suffixes.publish("S-1", &policy("corp.example"));
        assert!(!raised(), "the same suffix saved again");
        suffixes.publish("S-1", &policy("lab.example"));
        assert!(raised(), "another suffix");
        suffixes.publish("S-1", &policy(""));
        assert!(raised(), "switched off");
        suffixes.publish("S-1", &policy(""));
        assert!(!raised(), "still off");

        suffixes.publish("S-1", &policy("corp.example"));
        raised();
        suffixes.forget("S-1");
        assert!(raised(), "forgotten");
        suffixes.forget("S-1");
        assert!(!raised(), "nothing left to forget");
    }
}
