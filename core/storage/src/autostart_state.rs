//! `autostart_state` singleton.
//!
//! Persists the user's autostart preference and the last-known state of
//! the `HKCU\...\Run` registry value. Default after install: disabled
//! (no row), so the GUI toggle starts in the "off" position.
//!
//! The Windows registry helper writes the actual registry entry; this
//! storage row tracks our intent and the last observed external state
//! so the GUI can warn the user when something else overwrote our value.
//!
//! `last_known_state` slugs:
//!
//! | Slug                     | Meaning                                                |
//! |--------------------------|--------------------------------------------------------|
//! | `enabled`                | Registry value present and points at our binary.       |
//! | `disabled`               | Registry value absent (no autostart entry).            |
//! | `overridden-externally`  | Registry value present but points at a different path. |
//! | `absent`                 | We have not yet probed the registry (clean install).   |

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{StorageError, StorageResult};

// ── Slug enum ─────────────────────────────────────────────────────────────────

/// Last-known registry state. Keeps the platform-side
/// `AutostartCurrentState` and the storage row in sync without forcing
/// a domain dep.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AutostartLastKnownState {
    Enabled,
    Disabled,
    OverriddenExternally,
    Absent,
}

impl AutostartLastKnownState {
    pub const fn as_slug(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
            Self::OverriddenExternally => "overridden-externally",
            Self::Absent => "absent",
        }
    }

    pub fn from_slug(s: &str) -> Option<Self> {
        match s {
            "enabled" => Some(Self::Enabled),
            "disabled" => Some(Self::Disabled),
            "overridden-externally" => Some(Self::OverriddenExternally),
            "absent" => Some(Self::Absent),
            _ => None,
        }
    }
}

// ── DTO ───────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutostartStateRecord {
    /// User's intent — what the GUI toggle is set to.
    pub enabled: bool,
    /// Last-known registry value (or `None` if we have never probed).
    pub last_known_state: Option<AutostartLastKnownState>,
    pub updated_at: i64,
}

// ── Repository ────────────────────────────────────────────────────────────────

pub struct AutostartStateRepository<'c> {
    conn: &'c Connection,
}

impl<'c> AutostartStateRepository<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    /// Reads the singleton row. Returns `enabled = false`,
    /// `last_known_state = None`, `updated_at = 0` when no row exists.
    pub fn get_or_default(&self) -> StorageResult<AutostartStateRecord> {
        let row = self
            .conn
            .query_row(
                "SELECT enabled, last_known_state, updated_at
                 FROM autostart_state WHERE id = 1",
                [],
                |row| {
                    let enabled_int: i64 = row.get(0)?;
                    let slug: Option<String> = row.get(1)?;
                    Ok((enabled_int, slug, row.get::<_, i64>(2)?))
                },
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("autostart_state get: {e}")))?;

        Ok(match row {
            None => AutostartStateRecord {
                enabled: false,
                last_known_state: None,
                updated_at: 0,
            },
            Some((enabled_int, slug, updated_at)) => {
                let last_known_state = match slug {
                    None => None,
                    Some(s) => Some(AutostartLastKnownState::from_slug(&s).ok_or_else(|| {
                        StorageError::Internal(format!("unknown autostart slug {s:?}"))
                    })?),
                };
                AutostartStateRecord {
                    enabled: enabled_int != 0,
                    last_known_state,
                    updated_at,
                }
            }
        })
    }

    /// Inserts or replaces the singleton row.
    pub fn set(
        &self,
        enabled: bool,
        last_known_state: Option<AutostartLastKnownState>,
        now: i64,
    ) -> StorageResult<()> {
        self.conn
            .execute(
                "INSERT INTO autostart_state
                 (id, enabled, last_known_state, updated_at)
                 VALUES (1, ?1, ?2, ?3)
                 ON CONFLICT(id) DO UPDATE SET
                     enabled = excluded.enabled,
                     last_known_state = excluded.last_known_state,
                     updated_at = excluded.updated_at",
                params![enabled as i64, last_known_state.map(|s| s.as_slug()), now,],
            )
            .map_err(|e| StorageError::Internal(format!("autostart_state set: {e}")))?;
        Ok(())
    }

    /// Updates only the last-known registry observation, leaving the
    /// user's `enabled` intent unchanged. Called by the registry probe
    /// after each scan.
    pub fn record_observation(
        &self,
        last_known_state: AutostartLastKnownState,
        now: i64,
    ) -> StorageResult<()> {
        let current = self.get_or_default()?;
        self.set(current.enabled, Some(last_known_state), now)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::{open_connection, SqliteMigrationRunner};
    use crate::repository::MigrationRunner;

    fn open_state_db(dir: &tempfile::TempDir) -> Connection {
        let path = dir.path().join("state.db");
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        runner.into_connection()
    }

    #[test]
    fn slug_roundtrip() {
        for variant in [
            AutostartLastKnownState::Enabled,
            AutostartLastKnownState::Disabled,
            AutostartLastKnownState::OverriddenExternally,
            AutostartLastKnownState::Absent,
        ] {
            let slug = variant.as_slug();
            let parsed = AutostartLastKnownState::from_slug(slug).expect("roundtrip");
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn slug_unknown_returns_none() {
        assert!(AutostartLastKnownState::from_slug("UPPERCASE").is_none());
        assert!(AutostartLastKnownState::from_slug("").is_none());
    }

    #[test]
    fn default_is_disabled_with_no_observation() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = AutostartStateRepository::new(&conn);
        let r = repo.get_or_default().expect("get");
        assert!(!r.enabled);
        assert!(r.last_known_state.is_none());
        assert_eq!(r.updated_at, 0);
    }

    #[test]
    fn set_then_get_roundtrip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = AutostartStateRepository::new(&conn);
        repo.set(true, Some(AutostartLastKnownState::Enabled), 1_700_000_000)
            .expect("set");
        let r = repo.get_or_default().expect("get");
        assert!(r.enabled);
        assert_eq!(r.last_known_state, Some(AutostartLastKnownState::Enabled));
        assert_eq!(r.updated_at, 1_700_000_000);
    }

    #[test]
    fn record_observation_preserves_enabled() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = AutostartStateRepository::new(&conn);
        repo.set(true, None, 100).expect("set initial");
        repo.record_observation(AutostartLastKnownState::OverriddenExternally, 200)
            .expect("observe");
        let r = repo.get_or_default().expect("get");
        assert!(r.enabled, "user intent must survive observation update");
        assert_eq!(
            r.last_known_state,
            Some(AutostartLastKnownState::OverriddenExternally)
        );
        assert_eq!(r.updated_at, 200);
    }

    #[test]
    fn sql_check_rejects_unknown_slug_on_direct_insert() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let result = conn.execute(
            "INSERT INTO autostart_state (id, enabled, last_known_state, updated_at)
             VALUES (1, 0, 'whatever', 0)",
            [],
        );
        assert!(result.is_err(), "SQL CHECK must reject unknown slug");
    }
}
