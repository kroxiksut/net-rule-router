//! `install_policy` singleton: the administrator's install-time choices for
//! the whole machine.
//!
//! Written by the service when it applies what the installer staged, read by
//! the policy source and the route-policy writer. Machine-wide on purpose: a
//! per-principal row would be writable by the account the policy restricts.

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{StorageError, StorageResult};
use crate::route_bindings::BehaviorMode;

/// Where additional-route rules go while the user has no additional
/// connection bound.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SecondaryUnset {
    /// Straight out of the main connection, as if the rules were not there.
    #[default]
    Direct,
    /// Refused until an additional connection is bound (Fail-Closed).
    Block,
}

impl SecondaryUnset {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Block => "block",
        }
    }

    pub fn from_slug(slug: &str) -> Option<Self> {
        match slug {
            "direct" => Some(Self::Direct),
            "block" => Some(Self::Block),
            _ => None,
        }
    }
}

/// The singleton as stored; [`InstallPolicy::default`] when never written.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InstallPolicy {
    pub secondary_unset: SecondaryUnset,
    /// The mode a user's first saved policy starts from; `None` leaves the
    /// client's own default.
    pub default_route_mode: Option<BehaviorMode>,
}

pub struct InstallPolicyRepository<'c> {
    conn: &'c Connection,
}

impl<'c> InstallPolicyRepository<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    /// The stored row, or the default. A value the CHECK should have kept out
    /// is an error, not a silent default: it would decide Fail-Closed.
    pub fn get(&self) -> StorageResult<InstallPolicy> {
        let row: Option<(String, String)> = self
            .conn
            .query_row(
                "SELECT secondary_unset, default_route_mode FROM install_policy WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("install_policy get: {e}")))?;
        let Some((unset, mode)) = row else {
            return Ok(InstallPolicy::default());
        };
        let secondary_unset = SecondaryUnset::from_slug(&unset).ok_or_else(|| {
            StorageError::Internal(format!("install_policy: unknown secondary_unset {unset:?}"))
        })?;
        let default_route_mode = match mode.as_str() {
            "" => None,
            slug => Some(BehaviorMode::from_slug(slug).ok_or_else(|| {
                StorageError::Internal(format!("install_policy: unknown mode {slug:?}"))
            })?),
        };
        Ok(InstallPolicy {
            secondary_unset,
            default_route_mode,
        })
    }

    pub fn set(&self, policy: &InstallPolicy, now_ms: i64) -> StorageResult<()> {
        let mode = policy.default_route_mode.map_or("", BehaviorMode::slug);
        self.conn
            .execute(
                "INSERT INTO install_policy (id, secondary_unset, default_route_mode, updated_at)
                 VALUES (1, ?1, ?2, ?3)
                 ON CONFLICT(id) DO UPDATE SET
                     secondary_unset = excluded.secondary_unset,
                     default_route_mode = excluded.default_route_mode,
                     updated_at = excluded.updated_at",
                params![policy.secondary_unset.slug(), mode, now_ms],
            )
            .map_err(|e| StorageError::Internal(format!("install_policy set: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::{open_connection, SqliteMigrationRunner};
    use crate::repository::MigrationRunner;

    fn migrated() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_connection(&dir.path().join("state.db")).expect("open");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        (dir, runner.into_connection())
    }

    #[test]
    fn a_never_written_row_reads_as_direct_with_no_mode() {
        let (_dir, conn) = migrated();
        let policy = InstallPolicyRepository::new(&conn).get().expect("get");
        assert_eq!(policy, InstallPolicy::default());
        assert_eq!(policy.secondary_unset, SecondaryUnset::Direct);
    }

    #[test]
    fn both_values_round_trip() {
        let (_dir, conn) = migrated();
        let repo = InstallPolicyRepository::new(&conn);
        for unset in [SecondaryUnset::Block, SecondaryUnset::Direct] {
            let policy = InstallPolicy {
                secondary_unset: unset,
                default_route_mode: Some(BehaviorMode::PreferSecondaryWhenAvailable),
            };
            repo.set(&policy, 7).expect("set");
            assert_eq!(repo.get().expect("get"), policy);
        }
    }

    #[test]
    fn a_value_outside_the_check_is_refused_by_the_schema() {
        let (_dir, conn) = migrated();
        let refused = conn.execute(
            "INSERT INTO install_policy (id, secondary_unset, updated_at) VALUES (1, 'leak', 0)",
            [],
        );
        assert!(refused.is_err());
    }
}
