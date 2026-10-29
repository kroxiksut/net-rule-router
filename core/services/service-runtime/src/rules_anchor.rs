//! The record of which rules are active, kept outside the state database.
//!
//! Every revision row is signed on its own, so a deleted active row, or a whole
//! earlier copy of the database, still verifies row by row. This record names
//! per principal the active revision and its content hash, is signed with the
//! revision key and lives beside it in the key store, under the key's
//! protection. The service rewrites it around every commit of rules; the boot
//! compares the database with it, and a disagreement raises a blocking alert.
//!
//! A commit marks its principals pending before it runs: a crash between the
//! database commit and the rewrite then leaves a record that says so, and the
//! boot takes what the database holds for those principals only.
//!
//! The format and the comparison are neutral; the storage is the platform's
//! [`KeyStore`].

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};

use nrr_platform_api::key_store::KeyStore;
use nrr_storage::revision_hmac::{
    compute_rules_anchor_hmac, verify_rules_anchor, HmacVerification, HMAC_BYTE_LEN,
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

/// A record larger than this is not one the service wrote.
const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;

/// The format version inside the signed payload.
const RECORD_VERSION: u32 = 1;

/// One principal's active rules as the record names them.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ActiveRules {
    pub revision: String,
    pub hash: String,
}

/// What every principal has active, by principal.
pub type ActiveSet = BTreeMap<String, ActiveRules>;

/// The signed record.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorRecord {
    version: u32,
    /// Moves by one on every rewrite.
    pub generation: u64,
    /// Principals with a commit under way.
    pub pending: BTreeSet<String>,
    /// A commit under way that may touch every principal.
    pub pending_all: bool,
    pub active: ActiveSet,
}

impl AnchorRecord {
    #[must_use]
    pub fn of(active: ActiveSet) -> Self {
        Self {
            version: RECORD_VERSION,
            generation: 1,
            active,
            ..Self::default()
        }
    }

    /// Tag, then the payload it covers.
    #[must_use]
    pub fn encode(&self, key: &[u8]) -> Vec<u8> {
        let payload = serde_json::to_vec(self).unwrap_or_default();
        let mut out = compute_rules_anchor_hmac(&payload, key).to_vec();
        out.extend_from_slice(&payload);
        out
    }

    /// `None` for anything this key did not sign, whatever its shape.
    #[must_use]
    pub fn decode(bytes: &[u8], key: &[u8]) -> Option<Self> {
        if bytes.len() <= HMAC_BYTE_LEN || bytes.len() > MAX_RECORD_BYTES {
            return None;
        }
        let (tag, payload) = bytes.split_at(HMAC_BYTE_LEN);
        if verify_rules_anchor(payload, tag, key) != HmacVerification::Verified {
            return None;
        }
        serde_json::from_slice::<Self>(payload)
            .ok()
            .filter(|r| r.version == RECORD_VERSION)
    }

    fn is_pending(&self, principal: &str) -> bool {
        self.pending_all || self.pending.contains(principal)
    }
}

/// One principal whose active rules are not the ones recorded.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Disagreement {
    pub principal: String,
    pub recorded: Option<ActiveRules>,
    pub found: Option<ActiveRules>,
}

/// Every principal, not pending, whose active rules differ from `record`:
/// a row gone, another revision active, or one the record never named.
#[must_use]
pub fn disagreements(record: &AnchorRecord, found: &ActiveSet) -> Vec<Disagreement> {
    let principals: BTreeSet<&String> = record.active.keys().chain(found.keys()).collect();
    principals
        .into_iter()
        .filter(|p| !record.is_pending(p))
        .filter_map(|p| {
            let (recorded, now) = (record.active.get(p), found.get(p));
            (recorded != now).then(|| Disagreement {
                principal: p.clone(),
                recorded: recorded.cloned(),
                found: now.cloned(),
            })
        })
        .collect()
}

/// What the boot found when it compared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnchorAlert {
    Disagrees(Vec<Disagreement>),
    /// A record is there, but not one this key signed.
    Unverifiable {
        fingerprint: String,
    },
}

impl AnchorAlert {
    /// Stable while the incident is the same, so a restart does not raise it
    /// twice; a new incident gets a new id.
    #[must_use]
    pub fn alert_id(&self) -> String {
        use sha2::{Digest, Sha256};
        match self {
            Self::Disagrees(found) => {
                let mut h = Sha256::new();
                for d in found {
                    for part in [
                        Some(d.principal.as_str()),
                        d.recorded.as_ref().map(|r| r.revision.as_str()),
                        d.recorded.as_ref().map(|r| r.hash.as_str()),
                        d.found.as_ref().map(|r| r.revision.as_str()),
                        d.found.as_ref().map(|r| r.hash.as_str()),
                    ] {
                        let part = part.unwrap_or("").as_bytes();
                        h.update((part.len() as u64).to_be_bytes());
                        h.update(part);
                    }
                }
                format!("alt-rules-store-{}", short_hex(&h.finalize()))
            }
            Self::Unverifiable { fingerprint } => format!("alt-rules-record-{fingerprint}"),
        }
    }
}

fn short_hex(digest: &[u8]) -> String {
    digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// The boot's verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootCheck {
    /// The record the service keeps from here; `None` until an administrator
    /// acknowledges a record that does not verify.
    pub start: Option<AnchorRecord>,
    /// `start` differs from what is stored and must be written.
    pub rewrite: bool,
    pub alert: Option<AnchorAlert>,
}

/// Compares the database with the stored record. No record at all is an
/// install from before the record existed: it is written from the database.
/// A disagreeing principal keeps its recorded rules, so the alert stands
/// until acknowledged.
#[must_use]
pub fn check_at_boot(found: &ActiveSet, stored: Option<&[u8]>, key: &[u8]) -> BootCheck {
    let Some(bytes) = stored else {
        return BootCheck {
            start: Some(AnchorRecord::of(found.clone())),
            rewrite: true,
            alert: None,
        };
    };
    let Some(mut record) = AnchorRecord::decode(bytes, key) else {
        use sha2::{Digest, Sha256};
        return BootCheck {
            start: None,
            rewrite: false,
            alert: Some(AnchorAlert::Unverifiable {
                fingerprint: short_hex(&Sha256::digest(bytes)),
            }),
        };
    };
    let disagree = disagreements(&record, found);
    let rewrite = record.pending_all || !record.pending.is_empty();
    if rewrite {
        let settled: Vec<String> = if record.pending_all {
            record.active.keys().chain(found.keys()).cloned().collect()
        } else {
            record.pending.iter().cloned().collect()
        };
        for principal in settled {
            match found.get(&principal) {
                Some(rules) => record.active.insert(principal, rules.clone()),
                None => record.active.remove(&principal),
            };
        }
        record.pending.clear();
        record.pending_all = false;
        record.generation += 1;
    }
    BootCheck {
        start: Some(record),
        rewrite,
        alert: (!disagree.is_empty()).then_some(AnchorAlert::Disagrees(disagree)),
    }
}

/// What every principal has active in `conn`.
pub fn active_set(conn: &Connection) -> Result<ActiveSet, nrr_storage::StorageError> {
    Ok(nrr_storage::revisions::RevisionsRepository::new(conn)
        .active_identities()?
        .into_iter()
        .map(|(principal, revision, hash)| (principal, ActiveRules { revision, hash }))
        .collect())
}

/// The principals a commit may change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnchorScope {
    Of(Vec<String>),
    Every,
}

impl AnchorScope {
    #[must_use]
    pub fn one(principal: &str) -> Self {
        Self::Of(vec![principal.to_owned()])
    }
}

#[derive(Default)]
struct State {
    /// `None` while no trusted record exists this start.
    record: Option<AnchorRecord>,
    in_flight: BTreeMap<String, u32>,
    every_in_flight: u32,
}

/// The live record: rewritten around the service's own commits only, so a
/// change made past the service is never written into it.
pub struct RulesAnchor {
    key_store: Arc<dyn KeyStore>,
    key: Vec<u8>,
    state: Mutex<State>,
}

impl RulesAnchor {
    #[must_use]
    pub fn new(key_store: Arc<dyn KeyStore>, key: Vec<u8>, start: Option<AnchorRecord>) -> Self {
        Self {
            key_store,
            key,
            state: Mutex::new(State {
                record: start,
                ..State::default()
            }),
        }
    }

    /// Runs `commit` with `scope` marked pending in the stored record, then
    /// records what the database holds for `scope`. Locks the record before
    /// the database: `commit` must release the database before it returns.
    pub fn change<T>(
        &self,
        conn: &Mutex<Connection>,
        scope: &AnchorScope,
        commit: impl FnOnce() -> T,
    ) -> T {
        {
            let mut state = self.lock();
            match scope {
                AnchorScope::Of(principals) => {
                    for p in principals {
                        *state.in_flight.entry(p.clone()).or_default() += 1;
                    }
                }
                AnchorScope::Every => state.every_in_flight += 1,
            }
            self.write(&mut state);
        }
        let out = commit();
        let mut state = self.lock();
        match scope {
            AnchorScope::Of(principals) => {
                for p in principals {
                    if let Some(n) = state.in_flight.get_mut(p) {
                        *n -= 1;
                        if *n == 0 {
                            state.in_flight.remove(p);
                        }
                    }
                }
            }
            AnchorScope::Every => state.every_in_flight -= 1,
        }
        match read_active(conn) {
            Ok(found) => {
                if let Some(record) = state.record.as_mut() {
                    let touched: Vec<String> = match scope {
                        AnchorScope::Of(principals) => principals.clone(),
                        AnchorScope::Every => {
                            record.active.keys().chain(found.keys()).cloned().collect()
                        }
                    };
                    for p in touched {
                        match found.get(&p) {
                            Some(rules) => record.active.insert(p, rules.clone()),
                            None => record.active.remove(&p),
                        };
                    }
                }
            }
            // Left pending in the stored record: the next boot takes the
            // database's word for these principals.
            Err(e) => {
                tracing::warn!(
                    target: "nrr::tamper",
                    error = %e,
                    "could not read the active rules after a commit; the record keeps them pending",
                );
                return out;
            }
        }
        self.write(&mut state);
        out
    }

    /// Records the database as it is now, for every principal: what an
    /// administrator's acknowledgement accepts.
    pub fn re_record(&self, conn: &Mutex<Connection>) -> Result<(), String> {
        let mut state = self.lock();
        let found = read_active(conn).map_err(|e| e.to_string())?;
        let generation = state.record.as_ref().map_or(0, |r| r.generation);
        let mut record = AnchorRecord::of(found);
        record.generation = generation;
        state.record = Some(record);
        self.try_write(&mut state)
    }

    /// Principals whose active rules moved since the service last recorded
    /// them. Empty without a trusted record.
    pub fn disagreements_now(&self, conn: &Mutex<Connection>) -> Vec<Disagreement> {
        let state = self.lock();
        let Some(record) = state.record.as_ref() else {
            return Vec::new();
        };
        let mut view = record.clone();
        view.pending.extend(state.in_flight.keys().cloned());
        view.pending_all |= state.every_in_flight > 0;
        match read_active(conn) {
            Ok(found) => disagreements(&view, &found),
            Err(_) => Vec::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self, state: &mut State) {
        if let Err(e) = self.try_write(state) {
            tracing::warn!(
                target: "nrr::tamper",
                error = %e,
                "could not save the record of the active rules; the next start may raise an alert",
            );
        }
    }

    fn try_write(&self, state: &mut State) -> Result<(), String> {
        let pending: BTreeSet<String> = state.in_flight.keys().cloned().collect();
        let pending_all = state.every_in_flight > 0;
        let Some(record) = state.record.as_mut() else {
            return Ok(());
        };
        record.generation += 1;
        record.pending = pending;
        record.pending_all = pending_all;
        self.key_store
            .save_rules_anchor(&record.encode(&self.key))
            .map_err(|e| e.to_string())
    }
}

fn read_active(conn: &Mutex<Connection>) -> Result<ActiveSet, nrr_storage::StorageError> {
    let guard = conn.lock().unwrap_or_else(PoisonError::into_inner);
    active_set(&guard)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
