use super::*;
use std::time::Instant;

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

/// Polls instead of sleeping a fixed time: a loaded machine delays the timer
/// thread, never the verdict.
fn wait_for(control: &Recording, want: &[bool]) -> Vec<bool> {
    let started = Instant::now();
    loop {
        let calls = control.calls();
        if calls == want || started.elapsed() > Duration::from_secs(10) {
            return calls;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn a_stored_deadline_resumes_only_while_it_is_ahead() {
    assert_eq!(
        VerboseWindow::resumed(Some(2_000), 1_000),
        VerboseWindow::Until { deadline_ms: 2_000 }
    );
    assert_eq!(
        VerboseWindow::resumed(Some(1_000), 1_000),
        VerboseWindow::Off
    );
    assert_eq!(VerboseWindow::resumed(Some(500), 1_000), VerboseWindow::Off);
    assert_eq!(VerboseWindow::resumed(None, 1_000), VerboseWindow::Off);
}

#[test]
fn requests_map_to_windows_and_only_timed_ones_persist() {
    let now = 10_000;
    let hour = VerboseWindow::requested(VerboseLoggingChange::OneHour, now);
    assert_eq!(
        hour,
        VerboseWindow::Until {
            deadline_ms: now + 3_600_000
        }
    );
    assert_eq!(hour.persisted_until_ms(), Some(now + 3_600_000));
    assert_eq!(
        VerboseWindow::requested(VerboseLoggingChange::FourHours, now).persisted_until_ms(),
        Some(now + 4 * 3_600_000)
    );
    let restart = VerboseWindow::requested(VerboseLoggingChange::UntilRestart, now);
    assert_eq!(restart, VerboseWindow::UntilRestart);
    assert_eq!(restart.persisted_until_ms(), None);
    assert_eq!(
        VerboseWindow::requested(VerboseLoggingChange::Off, now),
        VerboseWindow::Off
    );
}

#[test]
fn a_timed_window_reports_off_once_its_deadline_passes() {
    let window = VerboseWindow::Until { deadline_ms: 5_000 };
    assert!(window.is_verbose(4_999));
    assert_eq!(window.reported(4_999), (VerboseLoggingMode::Timed, 5_000));
    assert!(!window.is_verbose(5_000));
    assert_eq!(window.reported(5_000), (VerboseLoggingMode::Off, 0));
    assert_eq!(
        VerboseWindow::UntilRestart.reported(i64::MAX),
        (VerboseLoggingMode::UntilRestart, 0)
    );
}

#[test]
fn nothing_stored_leaves_the_boot_filter_alone() {
    let control = Arc::new(Recording::default());
    let session = VerboseLogging::resume(None, now_ms(), Some(control.clone()));
    assert_eq!(session.window(), VerboseWindow::Off);
    assert!(
        control.calls().is_empty(),
        "an NRR_LOG override must survive"
    );
}

#[test]
fn a_deadline_that_passed_while_down_turns_verbose_off() {
    let control = Arc::new(Recording::default());
    let session = VerboseLogging::resume(Some(1), now_ms(), Some(control.clone()));
    assert_eq!(session.window(), VerboseWindow::Off);
    assert_eq!(control.calls(), vec![false]);
}

#[test]
fn a_timed_window_ends_by_itself() {
    let control = Arc::new(Recording::default());
    let session = VerboseLogging::resume(None, now_ms(), Some(control.clone()));
    session.set(
        VerboseWindow::Until {
            deadline_ms: now_ms() + 150,
        },
        now_ms(),
    );
    assert_eq!(wait_for(&control, &[true, false]), vec![true, false]);
    assert_eq!(session.window(), VerboseWindow::Off);
}

#[test]
fn a_resumed_window_ends_by_itself() {
    let control = Arc::new(Recording::default());
    let session = VerboseLogging::resume(Some(now_ms() + 150), now_ms(), Some(control.clone()));
    assert!(matches!(session.window(), VerboseWindow::Until { .. }));
    assert_eq!(wait_for(&control, &[false]), vec![false]);
    assert_eq!(session.window(), VerboseWindow::Off);
}

#[test]
fn a_newer_window_retires_the_older_timer() {
    let control = Arc::new(Recording::default());
    let session = VerboseLogging::resume(None, now_ms(), Some(control.clone()));
    session.set(
        VerboseWindow::Until {
            deadline_ms: now_ms() + 100,
        },
        now_ms(),
    );
    session.set(VerboseWindow::UntilRestart, now_ms());
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(
        control.calls(),
        vec![true, true],
        "the old deadline must not fire"
    );
    assert_eq!(session.window(), VerboseWindow::UntilRestart);
}
