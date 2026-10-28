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

use nrr_shared::launcher_rpc::{parse_request_line, LauncherRpcResponse};
use nrr_shared::user_settings::UserSettingsStore;
use nrr_ui_support::ui_preferences::{UiPreferences, UiPreferencesStore};
use serde_json::{json, Value};

use crate::launcher::{diag_log, preferences_to_persist};
use crate::user_settings_bridge::{
    overlay, preference_changes, UserSettingsMirror, FOLLOW_OPERATION,
};

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
    /// The shared user settings, written after each preferences save.
    user_settings: Option<UserSettingsMirror>,
    /// The last snapshot's shared fields did not reach that file.
    user_settings_unpublished: bool,
}

/// A follow answer for a file that would not load. Only damage is said, with
/// the file and the reason; a lock or a moment's I/O error is not damage.
fn unreadable_answer(stamp: &str, error: &nrr_shared::user_settings::UserSettingsError) -> Value {
    let mut answer = json!({ "stamp": stamp, "changed": false, "unreadable": true });
    if matches!(
        error,
        nrr_shared::user_settings::UserSettingsError::Damaged { .. }
    ) {
        answer["damaged"] = Value::Bool(true);
        answer["reason"] = Value::String(error.to_string());
    }
    answer
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
            user_settings: None,
            user_settings_unpublished: false,
        }
    }

    /// Also mirror the shared fields into `user-settings.json`.
    pub(crate) fn with_user_settings(mut self, mirror: Option<UserSettingsMirror>) -> Self {
        self.user_settings = mirror;
        self
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
                self.publish_user_settings(&updated);
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

    /// `local.user-settings.follow` `{since, adopt}`: the shared fields as
    /// another client left them since the file's stamp `since`. With `adopt`
    /// the window takes the answer: its unwritten snapshot lands first, so the
    /// file never takes back the window's own change, and its later saves are
    /// measured against what it took, so they do not undo the next change made
    /// elsewhere. Without, nothing here moves (the tray only reads).
    pub(crate) fn follow_user_settings(&mut self, payload: &Value) -> Value {
        let since = payload
            .get("since")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let adopt = payload.get("adopt").and_then(Value::as_bool) == Some(true);
        let store = match self.user_settings.as_ref() {
            Some(mirror) => UserSettingsStore::at(mirror.path().to_path_buf()),
            None => match UserSettingsStore::open() {
                Ok(store) => store,
                Err(_) => return json!({ "stamp": "", "changed": false, "unreadable": true }),
            },
        };
        if store.stamp() == since {
            return json!({ "stamp": since, "changed": false });
        }
        if adopt {
            self.flush();
            // A change the file refused is tried again: the file may read now.
            if self.user_settings_unpublished {
                let base = self.base.clone();
                self.publish_user_settings(&base);
            }
            // The window's own change is not in the file yet; taking the
            // file now would hand the window the value it replaced.
            if self.user_settings_unpublished {
                // A damaged file is why the change waits: still say it.
                return match store.load() {
                    Err(error @ nrr_shared::user_settings::UserSettingsError::Damaged { .. }) => {
                        unreadable_answer(since, &error)
                    }
                    _ => json!({ "stamp": since, "changed": false }),
                };
            }
        }
        let stamp = store.stamp();
        let settings = match store.load() {
            Ok(settings) => settings,
            Err(error) => return unreadable_answer(&stamp, &error),
        };
        let mut followed = self.base.clone();
        if let Some(settings) = &settings {
            overlay(&mut followed, settings);
        }
        let changes = preference_changes(&self.base, &followed);
        if adopt {
            if let Some(mirror) = self.user_settings.as_mut() {
                mirror.adopt(&followed);
            }
            self.base = followed;
        }
        let rules_files = settings.map_or(Value::Null, |settings| {
            json!({
                "primary": settings.rules_files.primary,
                "secondary": settings.rules_files.secondary,
            })
        });
        json!({
            "stamp": stamp,
            "changed": true,
            "preferences": changes,
            "rules-files": rules_files,
        })
    }

    /// A host request this loop answers itself — it holds the window's
    /// preferences — or `None` for the dispatcher.
    pub(crate) fn answer_in_loop(&mut self, line: &str) -> Option<LauncherRpcResponse> {
        // Most lines name another operation; most payloads are not worth a parse.
        if !line.contains(FOLLOW_OPERATION) {
            return None;
        }
        let request = parse_request_line(line)?.ok()?;
        if request.operation != FOLLOW_OPERATION {
            return None;
        }
        let answer = self.follow_user_settings(&request.payload);
        Some(LauncherRpcResponse::ok(request.correlation_id, answer))
    }

    /// Best effort: the preferences already landed, and a field that failed
    /// here is retried with the next snapshot because it still differs.
    fn publish_user_settings(&mut self, preferences: &UiPreferences) {
        let Some(mirror) = self.user_settings.as_mut() else {
            return;
        };
        let published = mirror.publish(preferences);
        self.user_settings_unpublished = published.is_err();
        let line = match published {
            Ok(false) => return,
            Ok(true) => format!(
                "NRR_LAUNCHER[prefs] user settings written path={}",
                mirror.path().display()
            ),
            Err(error) => format!("NRR_LAUNCHER[prefs] user settings not written: {error}"),
        };
        diag_log(self.surface_tag, &line);
    }
}

#[cfg(test)]
mod tests {
    use super::{DebouncedPreferenceWriter, PREFS_WRITE_DEBOUNCE};
    use nrr_shared::user_settings::{UserSettings, UserSettingsStore};
    use nrr_shared::ThemeMode;
    use nrr_ui_support::ui_preferences::{UiPreferences, UiPreferencesStore};
    use serde_json::{json, Value};
    use std::path::{Path, PathBuf};
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
    fn a_saved_snapshot_merges_its_shared_field_into_user_settings() {
        use crate::user_settings_bridge::open_session_in;
        use nrr_shared::user_settings::UserSettingsStore;

        let dir = tempfile::tempdir().expect("temp dir");
        let shared = dir.path().join("user-settings.json");
        let mut base = UiPreferences::default();
        let mirror = open_session_in(UserSettingsStore::at(shared.clone()), &mut base, true);
        assert!(mirror.is_some());
        // The terminal binds a file while the window runs.
        UserSettingsStore::at(shared.clone())
            .update(|s| s.rules_files.primary = "/terminal/rules_primary.txt".to_string())
            .expect("terminal write");

        let mut writer = writer_over(
            UiPreferencesStore::for_path(dir.path().join("ui-preferences.conf")),
            base,
        )
        .with_user_settings(mirror);
        let mut payload: serde_json::Value =
            serde_json::from_str(&payload_with_theme("dark")).expect("payload");
        payload["userPresetsDir"] = "/window/sets".into();
        writer.observe(&payload.to_string(), Instant::now());
        writer.flush();

        let on_disk = UserSettingsStore::at(shared)
            .load()
            .expect("load")
            .expect("present");
        assert_eq!(on_disk.rules_folder, "/window/sets");
        assert_eq!(on_disk.rules_files.primary, "/terminal/rules_primary.txt");
    }

    fn writer_with_shared(dir: &tempfile::TempDir) -> (DebouncedPreferenceWriter, PathBuf) {
        use crate::user_settings_bridge::open_session_in;
        let shared = dir.path().join("user-settings.json");
        let mut base = UiPreferences::default();
        let mirror = open_session_in(UserSettingsStore::at(shared.clone()), &mut base, true);
        assert!(mirror.is_some());
        let writer = writer_over(
            UiPreferencesStore::for_path(dir.path().join("ui-preferences.conf")),
            base,
        )
        .with_user_settings(mirror);
        (writer, shared)
    }

    fn terminal_writes(shared: &Path, change: impl FnOnce(&mut UserSettings)) {
        UserSettingsStore::at(shared.to_path_buf())
            .update(change)
            .expect("terminal write");
    }

    fn on_disk(shared: &Path) -> UserSettings {
        UserSettingsStore::at(shared.to_path_buf())
            .load()
            .expect("load")
            .expect("present")
    }

    fn follow(writer: &mut DebouncedPreferenceWriter, since: &str) -> Value {
        writer.follow_user_settings(&json!({ "since": since, "adopt": true }))
    }

    /// The terminal binds other files and another folder while the window
    /// runs: the open window is told, in its own preference names.
    #[test]
    fn a_change_the_terminal_made_reaches_the_open_window() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (mut writer, shared) = writer_with_shared(&dir);
        terminal_writes(&shared, |s| {
            s.rules_folder = "/terminal/sets".to_string();
            s.rules_files.primary = "/terminal/sets/a/rules_primary.txt".to_string();
            s.selected_set = "user:a".to_string();
        });

        let answer = follow(&mut writer, "");
        assert_eq!(answer["changed"], true, "{answer}");
        let prefs = &answer["preferences"];
        assert_eq!(prefs["userPresetsDir"], "/terminal/sets");
        assert_eq!(
            prefs["lastSavedPathPrimary"],
            "/terminal/sets/a/rules_primary.txt"
        );
        assert_eq!(
            prefs["lastLoadedPathPrimary"], "/terminal/sets/a/rules_primary.txt",
            "the Source line shows where the rules now come from"
        );
        assert_eq!(prefs["selectedPresetSet"], "user:a");
        assert!(
            prefs.get("lastSavedPathSecondary").is_none(),
            "a field nobody changed is not sent: {prefs}"
        );
        assert_eq!(
            answer["rules-files"]["primary"],
            "/terminal/sets/a/rules_primary.txt"
        );
    }

    /// Once the window holds what the terminal set, its next save carries that
    /// value back: it is not the window's own change and must not undo what
    /// the terminal set after it.
    #[test]
    fn a_window_that_took_a_terminal_change_does_not_undo_the_next_one() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (mut writer, shared) = writer_with_shared(&dir);
        terminal_writes(&shared, |s| {
            s.rules_files.primary = "/terminal/one.txt".to_string();
        });
        follow(&mut writer, "");
        terminal_writes(&shared, |s| {
            s.rules_files.primary = "/terminal/two.txt".to_string();
        });

        let mut payload: Value =
            serde_json::from_str(&payload_with_theme("dark")).expect("payload");
        payload["lastSavedPathPrimary"] = "/terminal/one.txt".into();
        writer.observe(&payload.to_string(), Instant::now());
        writer.flush();

        assert_eq!(on_disk(&shared).rules_files.primary, "/terminal/two.txt");
    }

    /// A change the window made a moment ago and has not written yet is the
    /// newest word on its field: following the file must not take it back.
    #[test]
    fn following_the_file_keeps_the_windows_unwritten_change() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (mut writer, shared) = writer_with_shared(&dir);
        let mut payload: Value =
            serde_json::from_str(&payload_with_theme("dark")).expect("payload");
        payload["userPresetsDir"] = "/window/sets".into();
        writer.observe(&payload.to_string(), Instant::now());
        terminal_writes(&shared, |s| {
            s.rules_files.primary = "/terminal/rules_primary.txt".to_string();
        });

        let answer = follow(&mut writer, "");
        let prefs = &answer["preferences"];
        assert!(prefs.get("userPresetsDir").is_none(), "{answer}");
        assert_eq!(prefs["lastSavedPathPrimary"], "/terminal/rules_primary.txt");
        let file = on_disk(&shared);
        assert_eq!(file.rules_folder, "/window/sets");
        assert_eq!(file.rules_files.primary, "/terminal/rules_primary.txt");
    }

    /// The window asks every few seconds; an unchanged file is answered from
    /// its stamp, and only a rewrite is read.
    #[test]
    fn the_file_is_read_again_only_after_it_changed() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (mut writer, shared) = writer_with_shared(&dir);
        // A file just written is read again until it settles.
        std::fs::File::options()
            .write(true)
            .open(&shared)
            .and_then(|file| {
                file.set_modified(std::time::SystemTime::now() - Duration::from_secs(3600))
            })
            .expect("date the file back");
        let first = follow(&mut writer, "");
        let stamp = first["stamp"].as_str().expect("stamp").to_owned();
        assert!(!stamp.is_empty(), "{first}");

        let again = follow(&mut writer, &stamp);
        assert_eq!(again["changed"], false, "{again}");
        assert!(again.get("preferences").is_none(), "{again}");

        terminal_writes(&shared, |s| s.selected_set = "user:b".to_string());
        let after = follow(&mut writer, &stamp);
        assert_eq!(after["changed"], true, "{after}");
        assert_eq!(after["preferences"]["selectedPresetSet"], "user:b");
    }

    /// A file damaged while the window runs is said, and stays as it is.
    #[test]
    fn a_file_damaged_while_the_window_runs_is_said_and_left_alone() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (mut writer, shared) = writer_with_shared(&dir);
        std::fs::write(&shared, "{broken").expect("damage");

        let answer = follow(&mut writer, "");
        assert_eq!(answer["unreadable"], true, "{answer}");
        assert_eq!(
            answer["damaged"], true,
            "the window cannot tell the user: {answer}"
        );
        assert!(
            answer["reason"]
                .as_str()
                .is_some_and(|r| r.contains("user-settings.json")),
            "the user is not told which file: {answer}"
        );
        assert_eq!(answer["changed"], false);
        assert!(answer.get("preferences").is_none());
        assert_eq!(std::fs::read_to_string(&shared).expect("read"), "{broken");
    }

    /// The window changed a shared setting and the damaged file refused it:
    /// that change waiting must not hide why it waits.
    #[test]
    fn a_damaged_file_is_said_while_the_windows_change_waits_for_it() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (mut writer, shared) = writer_with_shared(&dir);
        let first = follow(&mut writer, "");
        let stamp = first["stamp"].as_str().expect("stamp").to_owned();
        std::fs::write(&shared, "{broken").expect("damage");
        let mut payload: Value =
            serde_json::from_str(&payload_with_theme("dark")).expect("payload");
        payload["userPresetsDir"] = "/window/sets".into();
        writer.observe(&payload.to_string(), Instant::now());

        let answer = follow(&mut writer, &stamp);
        assert_eq!(answer["damaged"], true, "{answer}");
        assert_eq!(answer["changed"], false);
        assert_eq!(std::fs::read_to_string(&shared).expect("read"), "{broken");
    }

    /// The window opened while the shared file was damaged. Nothing is written
    /// over it; once the user fixes it and the window has read it, the
    /// window's next change of a shared setting reaches the terminal and tray.
    #[test]
    fn a_window_opened_over_a_damaged_file_writes_to_it_once_fixed() {
        use crate::user_settings_bridge::open_session_in;
        let dir = tempfile::tempdir().expect("temp dir");
        let shared = dir.path().join("user-settings.json");
        std::fs::write(&shared, "{broken").expect("damage");
        let mut base = UiPreferences::default();
        let mirror = open_session_in(UserSettingsStore::at(shared.clone()), &mut base, true);
        let mut writer = writer_over(
            UiPreferencesStore::for_path(dir.path().join("ui-preferences.conf")),
            base,
        )
        .with_user_settings(mirror);
        let with_folder = |folder: &str| {
            let mut payload: Value =
                serde_json::from_str(&payload_with_theme("dark")).expect("payload");
            payload["userPresetsDir"] = folder.into();
            payload.to_string()
        };

        writer.observe(&with_folder("/window/early"), Instant::now());
        writer.flush();
        let damaged = follow(&mut writer, "");
        assert_eq!(damaged["damaged"], true, "{damaged}");
        assert_eq!(std::fs::read_to_string(&shared).expect("read"), "{broken");

        std::fs::remove_file(&shared).expect("the user removes the damaged file");
        terminal_writes(&shared, |s| s.selected_set = "user:t".to_string());
        let fixed = follow(&mut writer, damaged["stamp"].as_str().unwrap_or_default());
        assert_eq!(fixed["changed"], true, "{fixed}");
        assert!(
            fixed["preferences"].get("userPresetsDir").is_none(),
            "the change made while the file was damaged was taken back: {fixed}"
        );
        assert_eq!(on_disk(&shared).rules_folder, "/window/early");
        writer.observe(&with_folder("/window/sets"), Instant::now());
        writer.flush();

        let file = on_disk(&shared);
        assert_eq!(file.rules_folder, "/window/sets");
        assert_eq!(file.selected_set, "user:t", "the terminal's value is kept");
    }

    /// The window's question is answered by the loop that holds its
    /// preferences; every other request goes on to the dispatcher.
    #[test]
    fn the_follow_request_is_answered_in_the_loop() {
        use nrr_shared::launcher_rpc::{encode_request_line, LauncherRpcRequest};
        let dir = tempfile::tempdir().expect("temp dir");
        let (mut writer, _shared) = writer_with_shared(&dir);
        let line = |operation: &str, payload: Value| {
            encode_request_line(&LauncherRpcRequest {
                correlation_id: "c-9".to_string(),
                operation: operation.to_string(),
                payload,
            })
            .expect("line")
        };

        let follow = line("local.user-settings.follow", json!({ "since": "" }));
        let answer = writer.answer_in_loop(&follow).expect("answered here");
        assert_eq!(answer.correlation_id, "c-9");
        assert!(answer.ok);
        assert!(answer.payload.expect("payload").get("stamp").is_some());

        let other = line(
            "local.system-theme",
            json!({ "note": "local.user-settings.follow" }),
        );
        assert!(writer.answer_in_loop(&other).is_none());
    }

    #[test]
    fn an_unparsable_payload_writes_nothing() {
        // The baseline is what THIS process read at start-up, and the file is
        // shared with the other surface. Persisting the baseline over a payload
        // we could not parse would overwrite whatever that surface saved since
        // — knowing less is never a reason to write an older picture.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("ui-preferences.json");
        let base = UiPreferences {
            theme_mode: ThemeMode::Dark,
            ..Default::default()
        };
        let mut writer = writer_over(UiPreferencesStore::for_path(path.clone()), base);

        writer.observe("not-json", Instant::now());
        writer.flush();

        assert_eq!(writer.writes, 0);
        assert!(!path.exists(), "nothing may reach the shared file");
    }
}
