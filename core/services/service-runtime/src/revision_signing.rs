//! Row signing for the `revisions` table, assembled one way on every platform:
//! the key from the platform's store, the boot verification, a coordinator
//! that signs what it writes, and the live recheck.
//!
//! Only the key store differs between services; everything a service would
//! otherwise rewrite in its own composition root — the order of the steps
//! above all — lives here, so a second platform cannot sign revisions while
//! skipping the check that makes the signature mean anything.

use std::sync::{Arc, Mutex};

use nrr_diagnostics::audit::alert::SecurityAlertsRepository;
use nrr_platform_api::key_store::KeyStore;
use rusqlite::Connection;

use crate::activation_coordinator::ActivationCoordinator;
use crate::boot_integrity::{AuditTrail, BootIntegrity};
use crate::health::HealthAggregator;
use crate::ipc_handlers::mutation_submit::OtherPrincipalsHoldRevisionsFn;
use crate::revision_watch::{OutsideWrites, RevisionWatch};
use crate::tamper_bootstrap::{raise_tamper_alerts, TamperBootstrapOutcome};

/// What one service start established about its signing key.
pub struct RevisionSigning {
    conn: Arc<Mutex<Connection>>,
    key_store: Arc<dyn KeyStore>,
    alerts: Arc<dyn SecurityAlertsRepository>,
    audit: Option<Arc<AuditTrail>>,
    health: Arc<HealthAggregator>,
    now_ms: i64,
    /// `None`: no key this start, the outage already reported.
    bootstrap: Option<TamperBootstrapOutcome>,
}

impl RevisionSigning {
    /// Loads or creates the key and verifies the stored rows against it.
    ///
    /// Runs before any coordinator exists and before the IPC server listens:
    /// the verification has to see rows exactly as the previous run signed
    /// them. A failure degrades to unsigned operation, reported by
    /// [`BootIntegrity::bootstrap`].
    pub fn bootstrap(
        conn: &Arc<Mutex<Connection>>,
        key_store: Arc<dyn KeyStore>,
        alerts: Arc<dyn SecurityAlertsRepository>,
        audit: Option<Arc<AuditTrail>>,
        health: Arc<HealthAggregator>,
        now_ms: i64,
    ) -> Self {
        let mut signing = Self {
            conn: Arc::clone(conn),
            key_store,
            alerts,
            audit,
            health,
            now_ms,
            bootstrap: None,
        };
        signing.bootstrap = signing.report().bootstrap(conn, signing.key_store.as_ref());
        // Signed candidates a hard kill orphaned can be rejected only with the
        // key: re-signing keeps their `row_hmac` consistent with the new status.
        if let Some(outcome) = signing.bootstrap.as_ref() {
            crate::bootstrap::sweep_signed_orphaned_candidates(conn, &outcome.signing_key);
        }
        signing
    }

    /// The key revisions are signed with this start, if any.
    #[must_use]
    pub fn signing_key(&self) -> Option<&[u8]> {
        self.bootstrap.as_ref().map(|o| o.signing_key.as_slice())
    }

    /// Makes `coordinator` sign every row it writes and lets an acknowledged
    /// key reset clear its marker. Without a key it is returned unchanged.
    #[must_use]
    pub fn sign(&self, coordinator: ActivationCoordinator) -> ActivationCoordinator {
        match self.bootstrap.as_ref() {
            Some(outcome) => coordinator
                .with_signing_key(outcome.signing_key.clone())
                .with_key_store(Arc::clone(&self.key_store)),
            None => coordinator,
        }
    }

    /// Rolls back every active revision that fails verification, raises the
    /// tamper alerts the boot found, then hands back the task that repeats the
    /// check after an outside write.
    ///
    /// Call before any enforcement reads the rules: a row that reached
    /// `revisions` outside the app must never be enforced as-is. `coordinator`
    /// must be the one [`Self::sign`] returned, over the connection given to
    /// [`Self::bootstrap`]; without one nothing can be rolled back, and the
    /// alerts name the rows as found. `None` without a key or a coordinator.
    #[must_use]
    pub fn enforce_and_watch(
        &self,
        coordinator: Option<&Arc<ActivationCoordinator>>,
    ) -> Option<RevisionWatch> {
        let bootstrap = self.bootstrap.as_ref()?;
        let Some(coordinator) = coordinator else {
            raise_tamper_alerts(
                &self.alerts,
                &bootstrap.pending_tamper_alerts,
                None,
                self.now_ms,
            );
            return None;
        };
        self.report().enforce_active(coordinator, bootstrap);
        Some(RevisionWatch {
            writes: OutsideWrites::new(Arc::clone(&self.conn)),
            coordinator: Arc::clone(coordinator),
            key_store: Arc::clone(&self.key_store),
            signing_key: bootstrap.signing_key.clone(),
            alerts: Arc::clone(&self.alerts),
            audit: self.audit.clone(),
            health: Arc::clone(&self.health),
        })
    }

    fn report(&self) -> BootIntegrity<'_> {
        BootIntegrity {
            alerts: &self.alerts,
            audit: self.audit.as_deref(),
            health: self.health.as_ref(),
            now_ms: self.now_ms,
        }
    }
}

/// Whether clearing a blocking integrity alert would also adopt revisions of
/// a user other than `caller`: acknowledging re-signs every row the alert
/// covers, so it speaks for whoever owns them. Asked live, per acknowledgement.
#[must_use]
pub fn other_principals_hold_revisions(
    conn: Arc<Mutex<Connection>>,
) -> OtherPrincipalsHoldRevisionsFn {
    Arc::new(move |caller: &str| {
        let guard = conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        nrr_storage::revisions::RevisionsRepository::new(&guard)
            .distinct_principals()
            .map(|principals| {
                principals
                    .iter()
                    .any(|p| p != caller && p != nrr_storage::BASELINE_PRINCIPAL)
            })
            // Unreadable is not consent to speak for others.
            .unwrap_or(true)
    })
}

#[cfg(test)]
mod tests;
