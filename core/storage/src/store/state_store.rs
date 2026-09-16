use super::*;

impl SqliteStateStore {
    pub fn new(conn: Connection) -> Self {
        Self {
            conn: RefCell::new(conn),
            signing_key: None,
        }
    }

    /// Attach the key `revisions` rows are signed with, so
    /// [`Self::check_integrity`] can tell a tampered row from an unsigned one.
    #[must_use]
    pub fn with_signing_key(mut self, key: Vec<u8>) -> Self {
        self.signing_key = Some(key);
        self
    }

    fn signing_key(&self) -> Option<Vec<u8>> {
        self.signing_key.clone()
    }

    pub fn into_connection(self) -> Connection {
        self.conn.into_inner()
    }
}

impl RevisionMetadataRepository for SqliteStateStore {
    /// The active revision, read from the pair the activation path maintains:
    /// `active_revision_pointer` (plus `revisions.status = 'active'`).
    ///
    /// It used to consult an `active_revision` singleton first — two
    /// representations of one fact, grown apart. Reading only the singleton
    /// meant bootstrap reported "no active revision yet (first run)" on a
    /// machine that had been enforcing rules for months, and offered a recovery
    /// that would have written over a pointer nothing read. The singleton is
    /// gone as of state-DB v60; this is the only representation left.
    fn get_active_revision(&self) -> StorageResult<Option<RevisionId>> {
        let conn = self.conn.borrow();
        let live: Option<String> = conn
            .query_row(
                "SELECT revision_id FROM active_revision_pointer WHERE principal = ?1",
                params![crate::BASELINE_PRINCIPAL],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?;
        if let Some(id) = live {
            return RevisionId::from_prefixed_string(id)
                .map(Some)
                .map_err(|e| StorageError::Internal(format!("parse active revision: {e}")));
        }
        Ok(None)
    }

    /// Writes the pointer the rest of the system reads —
    /// `active_revision_pointer` for the baseline principal — and not the
    /// singleton `active_revision` row it used to write. Those were two
    /// different places: the recovery flow flipped one while every reader
    /// consulted the other, so an LKG fallback could not take effect even if
    /// there had been an LKG to fall back to.
    fn set_active_revision(&self, revision_id: &RevisionId) -> StorageResult<()> {
        let conn = self.conn.borrow();
        // Through the repository, not a raw INSERT: the pointer carries an HMAC
        // and a hand-rolled write here would leave the recovered pointer
        // unsigned. `apply_attempt_id` is cleared on purpose — recovery is not
        // an apply in flight.
        let repo = match self.signing_key() {
            Some(key) => crate::revisions::RevisionsRepository::with_signing_key(&conn, key),
            None => crate::revisions::RevisionsRepository::new(&conn),
        };
        repo.set_active_pointer_for(
            crate::BASELINE_PRINCIPAL,
            &crate::revisions::ActiveRevisionPointer {
                revision_id: revision_id.as_str().to_string(),
                activated_at: system_time_to_ms(SystemTime::now()),
                apply_attempt_id: None,
            },
        )
    }

    /// Derived, not stored: the rollback target is the most recent revision
    /// that WAS active and was replaced, which `revisions` already records.
    ///
    /// It used to be read out of a `last_known_good` singleton that nothing
    /// ever wrote — so the recovery flow always found `None` and every
    /// "fall back to the last known good" decision resolved to "there is
    /// nothing to fall back to". Deriving removes the write path instead of
    /// adding one, and keeps the answer per-principal, which a machine-wide
    /// singleton could never be.
    fn get_last_known_good(&self) -> StorageResult<Option<RevisionId>> {
        let conn = self.conn.borrow();
        let record = crate::revisions::RevisionsRepository::new(&conn).last_known_good()?;
        record
            .map(|r| RevisionId::from_prefixed_string(r.revision_id))
            .transpose()
            .map_err(|e| StorageError::Internal(format!("parse LKG revision: {e}")))
    }

    fn check_integrity(&self) -> StorageResult<(IntegrityCheckResult, RecoveryAction)> {
        let conn = self.conn.borrow();

        // 1. SQLite structural integrity.
        let check: String = conn
            .query_row("PRAGMA integrity_check(1)", [], |r| r.get(0))
            .map_err(db_err)?;
        if check != "ok" {
            return Ok((
                IntegrityCheckResult::PolicyIntegrityFailed { details: check },
                RecoveryAction::FallbackToLastKnownGood,
            ));
        }

        // 2. Every principal's ACTIVE revision, checked against the live
        // per-row signature — when this store was given the key. Bootstrap runs
        // before the platform key store is opened, so there it verifies
        // structure and format only; the signature sweep over every revision
        // happens right after, in the keyed tamper bootstrap, which raises its
        // own blocking alerts. What matters is that neither of them checks the
        // dead singletons any more. This used to read an `active_revision` singleton
        // whose `integrity_hash` was written by this same function and read by
        // nothing else — the check verified its own bookkeeping over a table
        // the enforcement path had stopped using, so in production it verified
        // an empty table. `revisions.row_hmac` is what actually protects a row
        // from being edited underneath us.
        let repo = match self.signing_key() {
            Some(key) => crate::revisions::RevisionsRepository::with_signing_key(&conn, key),
            None => crate::revisions::RevisionsRepository::new(&conn),
        };
        let mut active_ids: Vec<String> = Vec::new();
        {
            let mut stmt = conn
                .prepare("SELECT revision_id FROM active_revision_pointer")
                .map_err(db_err)?;
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(db_err)?;
            for row in rows {
                active_ids.push(row.map_err(db_err)?);
            }
        }
        for raw in &active_ids {
            if RevisionId::from_prefixed_string(raw.clone()).is_err() {
                return Ok((
                    IntegrityCheckResult::PolicyIntegrityFailed {
                        details: format!("active revision has invalid format: {raw:?}"),
                    },
                    RecoveryAction::FallbackToLastKnownGood,
                ));
            }
            // `Unsigned` is not a failure: a row written without a key predates
            // signing, and refusing to start over it would lock the user out of
            // their own policy. `Tampered` is.
            if matches!(
                repo.verify_row_hmac(raw)?,
                Some(crate::revision_hmac::HmacVerification::Tampered)
            ) {
                return Ok((
                    IntegrityCheckResult::PolicyIntegrityFailed {
                        details: format!("active revision row signature mismatch for {raw:?}"),
                    },
                    RecoveryAction::FallbackToLastKnownGood,
                ));
            }
        }

        // 3. The rollback target, derived from `revisions` (see
        // `get_last_known_good`). Missing is not a hard failure on a first
        // start — there is simply nothing to fall back to yet.
        let lkg = crate::revisions::RevisionsRepository::new(&conn).last_known_good()?;
        let Some(lkg) = lkg else {
            // Distinguishable from a clean `Ok`: rollback is not available, and
            // the caller decides what to do about that.
            return Ok((
                IntegrityCheckResult::OkNoRollbackTarget,
                RecoveryAction::None,
            ));
        };

        // 4. A rollback target whose row has been tampered with is worse than
        // no target: falling back to it would install edited policy.
        if matches!(
            repo.verify_row_hmac(&lkg.revision_id)?,
            Some(crate::revision_hmac::HmacVerification::Tampered)
        ) {
            return Ok((
                IntegrityCheckResult::PolicyIntegrityFailed {
                    details: format!(
                        "last-known-good row signature mismatch for {:?}",
                        lkg.revision_id
                    ),
                },
                RecoveryAction::RequireUserAction(
                    "LKG revision signature mismatch — fallback target may be corrupt".to_string(),
                ),
            ));
        }

        Ok((IntegrityCheckResult::Ok, RecoveryAction::None))
    }

    fn record_integrity_check(
        &self,
        result: &IntegrityCheckResult,
        checked_at: SystemTime,
    ) -> StorageResult<()> {
        let conn = self.conn.borrow();
        let (result_str, detail) = integrity_result_text(result);
        conn.execute(
            "INSERT INTO integrity_log (result, detail, checked_at) VALUES (?1, ?2, ?3)",
            params![result_str, detail, system_time_to_ms(checked_at)],
        )
        .map_err(db_err)?;
        Ok(())
    }

    fn get_integrity_status(&self) -> StorageResult<IntegrityStatus> {
        let conn = self.conn.borrow();
        let row: Option<(String, i64)> = conn
            .query_row(
                "SELECT result, checked_at FROM integrity_log ORDER BY checked_at DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db_err)?;

        let (state_db, last_verified_at) = match row {
            Some((result_str, checked_at_ms)) => {
                let state = match result_str.as_str() {
                    "ok" => DbIntegrityState::Ok,
                    "cache_corrupt" => DbIntegrityState::CacheCorruptRebuildable,
                    "policy_failed" => DbIntegrityState::PolicyIntegrityFailed,
                    "unsupported" => DbIntegrityState::UnsupportedSchema,
                    _ => DbIntegrityState::Unavailable,
                };
                (state, Some(ms_to_system_time(checked_at_ms)))
            }
            None => (DbIntegrityState::Ok, None),
        };

        Ok(IntegrityStatus {
            cache_db: DbIntegrityState::Ok, // filled by CacheRepository side
            state_db,
            last_verified_at,
        })
    }
}
