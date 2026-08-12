//! Debounced write-through for the QML preferences round-trip.
//!
//! Every `NRR_PREFS_JSON:` line the Qt host prints is a complete, already
//! reconciled snapshot of the user's settings, so it can go to disk the moment
//! it arrives. Holding it in memory until the process exits means a
//! force-killed GUI (`taskkill /F`, a crash, a fast shutdown) silently discards
//! everything the user changed in that session — including the recorded
//! service intents.
//!
//! Publications arrive in bursts (one per toggle, per keystroke-committed
//! field), so writing each one straight through would put file I/O on the hot
//! path of a settings page. The writer therefore coalesces: the first payload
//! of a burst arms a deadline, later payloads only replace what will be
//! written, and the newest snapshot lands once the deadline passes. The caller
//! must flush at the end of the session so the tail of the last burst is never
//! the thing that gets lost.

use std::time::{Duration, Instant};

use nrr_ui_support::ui_preferences::{UiPreferences, UiPreferencesStore};

use crate::launcher::{diag_log, preferences_to_persist};

/// How long a burst of publications may coalesce before the newest snapshot is
/// written.
///
/// The bound that matters is how much work a kill can destroy, and that is
/// exactly this interval — half a second of toggling, i.e. at most one setting
/// in practice. The bound going the other way is write amplification: a user
/// dragging a spinbox or typing into a text field can emit tens of payloads a
/// second, and each write is a serialize plus a temp-file-and-rename. Half a
/// second caps that at two writes per second while staying far below the delay
/// a human would register as "it did not save".
pub(crate) const PREFS_WRITE_DEBOUNCE: Duration = Duration::from_millis(500);

/// Coalescing write-through of preference snapshots into the shared store.
pub(crate) struct DebouncedPreferenceWriter {
    surface_tag: &'static str,
    store: Option<UiPreferencesStore>,
    /// Baseline the next payload is applied over. Advanced to the result of
    /// every successful write so fields absent from a later payload keep the
    /// value that was already persisted.
    base: UiPreferences,
    debounce: Duration,
    /// Newest snapshot not yet on disk. `None` means this surface has nothing
    /// of its own to save — and must therefore not touch the file, which the
    /// other surface's process shares.
    pending: Option<String>,
    due_at: Option<Instant>,
    /// Payloads folded into `pending` since the last write.
    coalesced: u32,
    /// Completed writes this session, reported in the diagnostic line.
    writes: u32,
}

impl DebouncedPreferenceWriter {
    pub(crate) fn new(
        surface_tag: &'static str,
        store: Option<UiPreferencesStore>,
        base: UiPreferences,
    ) -> Self {
        Self::with_debounce(surface_tag, store, base, PREFS_WRITE_DEBOUNCE)
    }

    pub(crate) fn with_debounce(
        surface_tag: &'static str,
        store: Option<UiPreferencesStore>,
        base: UiPreferences,
        debounce: Duration,
    ) -> Self {
        Self {
            surface_tag,
            store,
            base,
            debounce,
            pending: None,
            due_at: None,
            coalesced: 0,
            writes: 0,
        }
    }

    /// When the caller must wake up to write, or `None` while nothing is
    /// pending and it may block indefinitely.
    pub(crate) fn due_at(&self) -> Option<Instant> {
        self.due_at
    }

    /// Accept a snapshot. The deadline is armed by the first payload of a burst
    /// and deliberately not pushed back by the ones that follow, so a
    /// continuous stream still reaches disk at a steady rate instead of never.
    pub(crate) fn observe(&mut self, payload: &str, now: Instant) {
        self.pending = Some(payload.to_string());
        self.coalesced = self.coalesced.saturating_add(1);
        if self.due_at.is_none() {
            self.due_at = Some(now + self.debounce);
        }
    }

    /// Write the pending snapshot if its deadline has passed.
    pub(crate) fn flush_if_due(&mut self, now: Instant) {
        match self.due_at {
            Some(due) if now >= due => self.write_pending("debounce"),
            _ => {}
        }
    }

    /// Write whatever is still pending, regardless of the deadline. A no-op
    /// when nothing was published or everything already landed.
    pub(crate) fn flush(&mut self) {
        self.write_pending("final");
    }

    fn write_pending(&mut self, reason: &str) {
        let Some(payload) = self.pending.take() else {
            return;
        };
        self.due_at = None;
        let coalesced = std::mem::replace(&mut self.coalesced, 0);
        let payload_bytes = payload.len();

        let Some(updated) = preferences_to_persist(self.base.clone(), Some(payload)) else {
            return;
        };
        let Some(store) = self.store.as_ref() else {
            // No store: keep the snapshot in memory so a later payload is still
            // applied over the newest baseline.
            self.base = updated;
            return;
        };

        match store.save(&updated) {
            Ok(()) => {
                self.base = updated;
                self.writes = self.writes.saturating_add(1);
                diag_log(
                    self.surface_tag,
                    &format!(
                        "NRR_LAUNCHER[prefs] persisted reason={reason} coalesced={coalesced} \
                         payload_bytes={payload_bytes} writes={}",
                        self.writes
                    ),
                );
            }
            Err(error) => {
                // Dropping the payload is safe: the baseline is left untouched,
                // so the next publication rewrites the same state.
                diag_log(
                    self.surface_tag,
                    &format!(
                        "NRR_LAUNCHER[prefs] persist failed reason={reason} path={}: {error}",
                        store.path().display()
                    ),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DebouncedPreferenceWriter, PREFS_WRITE_DEBOUNCE};
    use nrr_shared::ThemeMode;
    use nrr_ui_support::ui_preferences::{UiPreferences, UiPreferencesStore};
    use std::time::{Duration, Instant};

    const TAG: &str = "test";
    const DEBOUNCE: Duration = Duration::from_millis(500);

    /// A payload shaped like the one `emitPrefs()` publishes: the round-trip
    /// parser requires the full set of non-defaulted keys, so a stub object
    /// would exercise the parse-failure path instead of the happy one.
    fn payload_with_theme(theme_mode: &str) -> String {
        let mut object = serde_json::Map::new();
        object.insert("launchWindowOnStartup".into(), true.into());
        object.insert("minimizeToTrayInsteadOfClose".into(), true.into());
        object.insert("showNotifications".into(), true.into());
        object.insert("reopenLastSectionOnStartup".into(), true.into());
        object.insert("firstRunCompleted".into(), true.into());
        object.insert("themeMode".into(), theme_mode.into());
        object.insert("accessibilityHighContrast".into(), false.into());
        object.insert("fontScalePercent".into(), 100u64.into());
        object.insert("systemFont".into(), "system-default".into());
        object.insert("enhancedFocus".into(), false.into());
        object.insert("simplifiedLabels".into(), false.into());
        object.insert("tooltipsEnabled".into(), true.into());
        object.insert("language".into(), "en".into());
        object.insert("routePrimaryLabel".into(), "Primary".into());
        object.insert("routeSecondaryLabel".into(), "Secondary".into());
        object.insert("selectedPrimaryInterfaceName".into(), "".into());
        object.insert("selectedSecondaryInterfaceName".into(), "".into());
        object.insert("routeBehaviorMode".into(), "prefer-primary".into());
        object.insert("lastOpenedSection".into(), "interfaces-routes".into());
        serde_json::Value::Object(object).to_string()
    }

    fn writer_over(store: UiPreferencesStore, base: UiPreferences) -> DebouncedPreferenceWriter {
        DebouncedPreferenceWriter::with_debounce(TAG, Some(store), base, DEBOUNCE)
    }

    #[test]
    fn snapshot_reaches_disk_without_the_process_exiting() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("ui-preferences.json");
        let store = UiPreferencesStore::for_path(path.clone());
        let mut writer = writer_over(store, UiPreferences::default());

        let t0 = Instant::now();
        writer.observe(&payload_with_theme("dark"), t0);
        writer.flush_if_due(t0 + DEBOUNCE);

        assert_eq!(writer.writes, 1, "the armed deadline must produce a write");
        let reloaded = UiPreferencesStore::for_path(path).load().expect("reload");
        assert_eq!(reloaded.theme_mode, ThemeMode::Dark);
    }

    #[test]
    fn nothing_is_written_before_the_deadline() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("ui-preferences.json");
        let store = UiPreferencesStore::for_path(path.clone());
        let mut writer = writer_over(store, UiPreferences::default());

        let t0 = Instant::now();
        writer.observe(&payload_with_theme("dark"), t0);
        writer.flush_if_due(t0 + Duration::from_millis(100));

        assert_eq!(writer.writes, 0);
        assert!(!path.exists(), "the burst must still be coalescing");
    }

    #[test]
    fn a_burst_of_publications_collapses_into_one_write() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("ui-preferences.json");
        let store = UiPreferencesStore::for_path(path.clone());
        let mut writer = writer_over(store, UiPreferences::default());

        let t0 = Instant::now();
        writer.observe(&payload_with_theme("dark"), t0);
        writer.observe(&payload_with_theme("light"), t0 + Duration::from_millis(40));
        writer.observe(
            &payload_with_theme("system"),
            t0 + Duration::from_millis(90),
        );
        writer.flush_if_due(t0 + DEBOUNCE);

        assert_eq!(writer.writes, 1, "three payloads must cost one write");
        let reloaded = UiPreferencesStore::for_path(path).load().expect("reload");
        assert_eq!(
            reloaded.theme_mode,
            ThemeMode::System,
            "the newest snapshot of the burst wins"
        );
    }

    #[test]
    fn a_continuous_stream_still_writes_once_per_interval() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("ui-preferences.json");
        let store = UiPreferencesStore::for_path(path);
        let mut writer = writer_over(store, UiPreferences::default());

        let t0 = Instant::now();
        for step in 0..40u32 {
            let now = t0 + Duration::from_millis(u64::from(step) * 50);
            writer.observe(&payload_with_theme("dark"), now);
            writer.flush_if_due(now);
        }

        assert_eq!(
            writer.writes, 3,
            "a two-second stream must not amplify into forty writes"
        );
    }

    #[test]
    fn the_last_snapshot_survives_termination() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("ui-preferences.json");
        let store = UiPreferencesStore::for_path(path.clone());
        let mut writer = writer_over(store, UiPreferences::default());

        let t0 = Instant::now();
        writer.observe(&payload_with_theme("dark"), t0);
        writer.flush_if_due(t0 + DEBOUNCE);
        writer.observe(&payload_with_theme("light"), t0 + DEBOUNCE);
        // Session ends mid-burst, well before the deadline.
        writer.flush();

        assert_eq!(writer.writes, 2);
        let reloaded = UiPreferencesStore::for_path(path).load().expect("reload");
        assert_eq!(reloaded.theme_mode, ThemeMode::Light);
    }

    #[test]
    fn a_surface_that_published_nothing_never_rewrites_the_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("ui-preferences.json");
        // Stand in for what the other surface's process wrote while this one
        // was running: whatever this writer loaded at start is stale.
        let written_by_the_other_surface = UiPreferences {
            theme_mode: ThemeMode::Dark,
            ..Default::default()
        };
        UiPreferencesStore::for_path(path.clone())
            .save(&written_by_the_other_surface)
            .expect("seed store");
        let on_disk = std::fs::read_to_string(&path).expect("read seeded file");

        let mut writer = writer_over(
            UiPreferencesStore::for_path(path.clone()),
            UiPreferences::default(),
        );
        writer.flush_if_due(Instant::now() + PREFS_WRITE_DEBOUNCE);
        writer.flush();

        assert_eq!(writer.writes, 0);
        assert_eq!(
            std::fs::read_to_string(&path).expect("read file"),
            on_disk,
            "a surface with no payload of its own must leave the file alone"
        );
    }

    #[test]
    fn flushing_twice_does_not_write_twice() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = UiPreferencesStore::for_path(dir.path().join("ui-preferences.json"));
        let mut writer = writer_over(store, UiPreferences::default());

        writer.observe(&payload_with_theme("dark"), Instant::now());
        writer.flush();
        writer.flush();

        assert_eq!(writer.writes, 1);
    }

    #[test]
    fn no_deadline_is_armed_while_nothing_is_pending() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = UiPreferencesStore::for_path(dir.path().join("ui-preferences.json"));
        let mut writer = writer_over(store, UiPreferences::default());

        assert!(writer.due_at().is_none());
        let t0 = Instant::now();
        writer.observe(&payload_with_theme("dark"), t0);
        assert_eq!(writer.due_at(), Some(t0 + DEBOUNCE));
        writer.flush_if_due(t0 + DEBOUNCE);
        assert!(writer.due_at().is_none());
    }

    #[test]
    fn an_unparsable_payload_still_persists_the_baseline() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("ui-preferences.json");
        let base = UiPreferences {
            theme_mode: ThemeMode::Dark,
            ..Default::default()
        };
        let mut writer = writer_over(UiPreferencesStore::for_path(path.clone()), base);

        writer.observe("not-json", Instant::now());
        writer.flush();

        assert_eq!(writer.writes, 1);
        let reloaded = UiPreferencesStore::for_path(path).load().expect("reload");
        assert_eq!(reloaded.theme_mode, ThemeMode::Dark);
    }
}
