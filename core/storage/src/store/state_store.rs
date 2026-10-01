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
        let mut pointers: Vec<(String, String, bool)> = Vec::new();
        {
            let mut stmt = conn
                .prepare(
                    "SELECT p.principal, p.revision_id,
                            EXISTS (SELECT 1 FROM revisions r
                                    WHERE r.principal = p.principal
                                      AND r.revision_id = p.revision_id)
                     FROM active_revision_pointer p
                     ORDER BY p.principal ASC",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, bool>(2)?,
                    ))
                })
                .map_err(db_err)?;
            for row in rows {
                pointers.push(row.map_err(db_err)?);
            }
        }
        for (principal, raw, target_exists) in &pointers {
            if RevisionId::from_prefixed_string(raw.clone()).is_err() {
                return Ok((
                    IntegrityCheckResult::PolicyIntegrityFailed {
                        details: format!(
                            "active revision of {principal:?} has invalid format: {raw:?}"
                        ),
                    },
                    RecoveryAction::FallbackToLastKnownGood,
                ));
            }
            // Only an editor running without `foreign_keys` leaves a pointer
            // dangling, and a deleted row has no signature left to fail.
            if !target_exists {
                return Ok((
                    IntegrityCheckResult::PolicyIntegrityFailed {
                        details: format!("active revision {raw:?} of {principal:?} is missing"),
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
                        details: format!(
                            "active revision row signature mismatch for {raw:?} of {principal:?}"
                        ),
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

        // 3. Each principal's own rollback target. One whose row was edited is
        // worse than none: recovering onto it would install edited policy.
        for (principal, _, _) in &pointers {
            let Some(lkg) = repo.last_known_good_for(principal)? else {
                continue;
            };
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
                        "LKG revision signature mismatch — fallback target may be corrupt"
                            .to_string(),
                    ),
                ));
            }
        }

        Ok((IntegrityCheckResult::Ok, RecoveryAction::None))
    }
}
