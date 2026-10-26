use serde_json::{json, Map, Value};

use super::*;
use crate::screens::ScreenId;
use crate::testing::{missing_from_locales, texts_en, Scratch};

fn blob(value: Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}

/// Work the window parked is counted by kind; an empty or aged-out blob,
/// which the window itself would drop, is nothing to report.
#[test]
fn what_the_window_parked_is_counted_and_old_work_is_not_reported() {
    let now = 10_000_000_000;
    let fresh = blob(json!({
        "route-policy": { "mode": "prefer-secondary", "leak-protection": "everything" },
        "stability": { "verbose-logging": true },
        "binding": { "secondary": { "stable-id": "x" } },
        "parked-at-ms": now - 1000
    }));
    assert_eq!(
        parked(&fresh, now),
        Some(WindowParked {
            routing: 2,
            service: 1,
            roles: true
        })
    );
    let aged = blob(json!({
        "route-policy": { "mode": "prefer-secondary" },
        "parked-at-ms": now - nrr_shared::PARKED_INTENT_TTL_SECONDS * 1000 - 1
    }));
    assert_eq!(parked(&aged, now), None);
    let hollow =
        blob(json!({ "route-policy": {}, "stability": {}, "binding": {}, "parked-at-ms": now }));
    assert_eq!(parked(&hollow, now), None);
}

/// The Status screen says the window waits with changes, read from the file
/// both clients share; once the window has sent them, the line goes.
#[test]
fn the_status_screen_says_what_the_window_still_holds() {
    let dir = Scratch::new("window-parked");
    let file = dir
        .path()
        .join(nrr_shared::user_settings::USER_SETTINGS_FILE_NAME);
    let store = UserSettingsStore::at(file.clone());
    store
        .update(|s| {
            s.window_parked = blob(json!({
                "route-policy": { "mode": "prefer-secondary" },
                "parked-at-ms": chrono::Utc::now().timestamp_millis()
            }));
        })
        .expect("seed");
    let mut app = AppState::new(ScreenId::Status, false);
    app.rules.settings_file = Some(file);
    refresh(&mut app);
    let texts = texts_en();
    let shown = |app: &AppState| {
        crate::screens::screen(ScreenId::Status)
            .view(app, &texts)
            .panels
            .iter()
            .flat_map(|p| p.lines.iter().map(|l| l.plain_text()))
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert!(
        shown(&app).contains("routing settings: 1"),
        "{}",
        shown(&app)
    );

    store.update(|s| s.window_parked.clear()).expect("sent");
    refresh(&mut app);
    assert!(!shown(&app).contains("The window holds"), "{}", shown(&app));
}

#[test]
fn every_key_is_in_both_locale_files() {
    let missing = missing_from_locales(&[WAITING, ROUTING, SERVICE, ROLES]);
    assert!(missing.is_empty(), "{missing:?}");
}
