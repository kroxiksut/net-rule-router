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
    /// The baseline principal's `active_revision_pointer`.
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

    /// Moves the baseline principal's `active_revision_pointer`.
    fn set_active_revision(&self, revision_id: &RevisionId) -> StorageResult<()> {
        let conn = self.conn.borrow();
        // Through the repository so the pointer is signed. No attempt id:
        // recovery is not an apply in flight.
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

    /// Derived, not stored: the baseline's most recently superseded revision.
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

        // 2. Every principal's pointer and the row it names. Signatures are
        // checked only when this store holds the key: the boot store does not
        // (the key store opens later) and the keyed tamper bootstrap sweeps
        // every row and pointer right after. Existence needs no key.
        let repo = match self.signing_key() {
            Some(key) => crate::revisions::RevisionsRepository::with_signing_key(&conn, key),
            None => crate::revisions::RevisionsRepository::new(&conn),
        };
        let mut pointers: Vec<(String, bool)> = Vec::new();
        {
            let mut stmt = conn
                .prepare(
                    "SELECT p.revision_id,
                            EXISTS (SELECT 1 FROM revisions r
                                    WHERE r.principal = p.principal
                                      AND r.revision_id = p.revision_id)
                     FROM active_revision_pointer p",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?)))
                .map_err(db_err)?;
            for row in rows {
                pointers.push(row.map_err(db_err)?);
            }
        }
        for (raw, target_exists) in &pointers {
            if RevisionId::from_prefixed_string(raw.clone()).is_err() {
                return Ok((
                    IntegrityCheckResult::PolicyIntegrityFailed {
                        details: format!("active revision has invalid format: {raw:?}"),
                    },
                    RecoveryAction::FallbackToLastKnownGood,
                ));
            }
            // Only an editor running without `foreign_keys` leaves a pointer
            // dangling, and a deleted row has no signature left to fail.
            if !target_exists {
                return Ok((
                    IntegrityCheckResult::PolicyIntegrityFailed {
                        details: format!("active revision {raw:?} is missing"),
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
        // Which revision is active is policy too: a pointer moved onto an older,
        // validly signed row passes every row check above.
        if repo
            .verify_all_pointers()?
            .iter()
            .any(|(_, v)| *v == crate::revision_hmac::HmacVerification::Tampered)
        {
            return Ok((
                IntegrityCheckResult::PolicyIntegrityFailed {
                    details: "active revision pointer signature mismatch".to_string(),
                },
                RecoveryAction::FallbackToLastKnownGood,
            ));
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
