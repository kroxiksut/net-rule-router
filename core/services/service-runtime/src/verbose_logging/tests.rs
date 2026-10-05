use super::*;
use std::sync::Mutex;

#[derive(Default)]
struct Recording {
    calls: Mutex<Vec<bool>>,
}

impl VerbosityControl for Recording {
    fn set_verbose(&self, verbose: bool) {
        self.calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(verbose);
    }
}

impl Recording {
    fn calls(&self) -> Vec<bool> {
        self.calls.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

#[test]
fn nothing_stored_leaves_the_boot_filter_alone() {
    let control = Arc::new(Recording::default());
    let session = resume(None, now_ms(), Some(control.clone()));
    assert_eq!(session.window(), TimedWindow::Off);
    assert!(
        control.calls().is_empty(),
        "an NRR_LOG override must survive"
    );
}

#[test]
fn a_deadline_that_passed_while_down_turns_verbose_off() {
    let control = Arc::new(Recording::default());
    let session = resume(Some(1), now_ms(), Some(control.clone()));
    assert_eq!(session.window(), TimedWindow::Off);
    assert_eq!(control.calls(), vec![false]);
}

#[test]
fn a_request_reaches_the_live_filter() {
    let control = Arc::new(Recording::default());
    let session = resume(None, now_ms(), Some(control.clone()));
    session.set(TimedWindow::UntilRestart, now_ms());
    session.set(TimedWindow::Off, now_ms());
    assert_eq!(control.calls(), vec![true, false]);
}

#[test]
fn nothing_stored_at_boot_is_normal_logging() {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let path = dir.path().join("nrr_service_state.db");
    assert!(!verbose_at_boot(&path));
    assert_eq!(persisted_until_at_boot(&path), None);
}
