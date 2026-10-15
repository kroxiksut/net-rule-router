//! The home-network suffix list over the state DB, and what the read-back
//! adds to it from the DNS guard and the caller's rules.

use std::sync::{Arc, Mutex};

use nrr_shared::ipc_payloads::OfferedDnsSuffixDto;
use nrr_storage::local_dns_suffixes::LocalDnsSuffixesRepository;
use rusqlite::Connection;

use crate::ipc_handlers::local_dns_suffixes::{LocalDnsSuffixContext, LocalDnsSuffixStore};
use crate::ipc_handlers::providers::RoutePolicyWriteError;
use crate::local_dns_suffixes::global_local_dns_suffixes;
use crate::per_sid_orchestrator::RulesProvider;

pub struct ProductionLocalDnsSuffixStore {
    conn: Arc<Mutex<Connection>>,
}

impl ProductionLocalDnsSuffixStore {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

impl LocalDnsSuffixStore for ProductionLocalDnsSuffixStore {
    fn get_all(&self) -> Result<Vec<String>, RoutePolicyWriteError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| RoutePolicyWriteError::Storage("connection mutex poisoned".into()))?;
        LocalDnsSuffixesRepository::new(&conn)
            .load_all()
            .map_err(|e| RoutePolicyWriteError::Storage(format!("{e:?}")))
    }

    /// Written and published under the one lock, so the guard never reads a
    /// list the store does not hold.
    fn replace_all(&self, suffixes: &[String]) -> Result<Vec<String>, RoutePolicyWriteError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| RoutePolicyWriteError::Storage("connection mutex poisoned".into()))?;
        let repo = LocalDnsSuffixesRepository::new(&conn);
        repo.replace_all(suffixes, now_secs())
            .map_err(|e| RoutePolicyWriteError::Storage(format!("{e:?}")))?;
        let stored = repo
            .load_all()
            .map_err(|e| RoutePolicyWriteError::Storage(format!("{e:?}")))?;
        global_local_dns_suffixes().publish(stored.clone());
        Ok(stored)
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The offers the guard last saw, and the caller's own rule hosts.
pub struct ProductionLocalDnsSuffixContext {
    rules: Arc<dyn RulesProvider>,
}

impl ProductionLocalDnsSuffixContext {
    pub fn new(rules: Arc<dyn RulesProvider>) -> Self {
        Self { rules }
    }
}

impl LocalDnsSuffixContext for ProductionLocalDnsSuffixContext {
    fn offered(&self) -> Vec<OfferedDnsSuffixDto> {
        global_local_dns_suffixes()
            .offered()
            .iter()
            .map(|offer| OfferedDnsSuffixDto {
                suffix: offer.suffix.clone(),
                link: offer.link.clone(),
            })
            .collect()
    }

    fn rule_hosts(&self, sid: &str) -> Vec<String> {
        if sid.is_empty() {
            return Vec::new();
        }
        self.rules
            .active_rules_for(sid)
            .map(|snapshot| crate::rule_book_facts::rule_host_names(&snapshot.rule_book))
            .unwrap_or_default()
    }
}
