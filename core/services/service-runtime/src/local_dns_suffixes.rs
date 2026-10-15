//! The machine-wide list of home and local network suffixes, as last written,
//! and what the DNS guard found out about it on its last read.
//!
//! Read by the guard on every namespace read and by the settings read-back;
//! written by the settings handler and at start-up. One per process, like the
//! short-name suffixes: the writer and the guard are built on paths that
//! never meet.

use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock, RwLock};

use nrr_platform_api::dns_scope::OfferedSuffix;
use nrr_storage::local_dns_suffixes::LocalDnsSuffixesRepository;
use nrr_storage::StorageResult;
use rusqlite::Connection;

use crate::dns_resolver_service::NamespaceRecheck;

#[derive(Default)]
pub struct MachineLocalDnsSuffixes {
    list: RwLock<Arc<[String]>>,
    /// What the main link offered on the guard's last read.
    offered: RwLock<Arc<[OfferedSuffix]>>,
    /// Raised when the list changes: the guard rewrites the namespaces, and
    /// reads the list only when told to.
    on_change: Option<NamespaceRecheck>,
}

impl MachineLocalDnsSuffixes {
    pub fn raising(on_change: NamespaceRecheck) -> Self {
        Self {
            list: RwLock::default(),
            offered: RwLock::default(),
            on_change: Some(on_change),
        }
    }

    /// Replace the list with what `conn` holds. A failed read keeps the
    /// previous snapshot: nothing new is known, and nothing is widened.
    pub fn reload(&self, conn: &Connection) -> StorageResult<()> {
        let fresh = LocalDnsSuffixesRepository::new(conn).load_all()?;
        self.publish(fresh);
        Ok(())
    }

    /// Record a list just written. Raises the guard only on a change.
    pub fn publish(&self, list: Vec<String>) {
        let fresh: Arc<[String]> = list.into();
        let changed = {
            let mut current = self.list.write().unwrap_or_else(|p| p.into_inner());
            let changed = *current != fresh;
            *current = fresh;
            changed
        };
        if changed {
            if let Some(flag) = &self.on_change {
                flag.store(true, Ordering::SeqCst);
            }
        }
    }

    pub fn current(&self) -> Arc<[String]> {
        Arc::clone(&self.list.read().unwrap_or_else(|p| p.into_inner()))
    }

    /// What the guard found the main link offering.
    pub fn publish_offered(&self, offered: Vec<OfferedSuffix>) {
        *self.offered.write().unwrap_or_else(|p| p.into_inner()) = offered.into();
    }

    pub fn offered(&self) -> Arc<[OfferedSuffix]> {
        Arc::clone(&self.offered.read().unwrap_or_else(|p| p.into_inner()))
    }
}

/// One per process: the settings writer and the resolver are built on paths
/// that never meet.
pub fn global_local_dns_suffixes() -> &'static MachineLocalDnsSuffixes {
    static GLOBAL: OnceLock<MachineLocalDnsSuffixes> = OnceLock::new();
    GLOBAL.get_or_init(|| {
        MachineLocalDnsSuffixes::raising(Arc::clone(crate::dns_stack::namespace_recheck()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    /// Only a changed list wakes the guard: every save publishes, and an
    /// unchanged one must cost it nothing.
    #[test]
    fn only_a_changed_list_raises_the_recheck() {
        let flag: NamespaceRecheck = Arc::new(AtomicBool::new(false));
        let suffixes = MachineLocalDnsSuffixes::raising(Arc::clone(&flag));
        let raised = || flag.swap(false, Ordering::SeqCst);

        suffixes.publish(vec!["lan".into()]);
        assert!(raised(), "a new list");
        suffixes.publish(vec!["lan".into()]);
        assert!(!raised(), "the same list saved again");
        suffixes.publish(vec![]);
        assert!(raised(), "emptied");
        assert!(suffixes.current().is_empty());
    }

    #[test]
    fn reload_takes_the_seeded_list_from_the_store() {
        let runner = nrr_storage::migration::SqliteMigrationRunner::for_state_db(
            Connection::open_in_memory().expect("in-memory"),
        );
        nrr_storage::repository::MigrationRunner::run_pending_migrations(&runner).expect("migrate");
        let conn = runner.into_connection();
        let suffixes = MachineLocalDnsSuffixes::default();
        suffixes.reload(&conn).expect("reload");
        assert_eq!(
            &*suffixes.current(),
            ["fritz.box", "home.arpa", "lan", "local"]
        );
    }
}
