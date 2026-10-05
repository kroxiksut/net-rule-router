use super::*;
use std::time::Instant;

#[derive(Default)]
struct Recording {
    calls: Mutex<Vec<bool>>,
}

impl Recording {
    fn calls(&self) -> Vec<bool> {
        self.calls.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    fn sink(self: &Arc<Self>) -> WindowSink {
        let this = Arc::clone(self);
        Arc::new(move |open: bool| {
            this.calls
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(open);
        })
    }
}

fn live(kind: WindowKind, persisted: Option<i64>) -> (Arc<Recording>, TimedSwitch) {
    let recording = Arc::new(Recording::default());
    let switch = TimedSwitch::resume(kind, persisted, now_ms(), Some(recording.sink()));
    (recording, switch)
}

/// Polls instead of sleeping a fixed time: a loaded machine delays the timer
/// thread, never the verdict.
fn wait_for(recording: &Recording, want: &[bool]) -> Vec<bool> {
    let started = Instant::now();
    loop {
        let calls = recording.calls();
        if calls == want || started.elapsed() > Duration::from_secs(10) {
            return calls;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn a_stored_deadline_resumes_only_while_it_is_ahead() {
    assert_eq!(
        TimedWindow::resumed(Some(2_000), 1_000),
        TimedWindow::Until { deadline_ms: 2_000 }
    );
    assert_eq!(TimedWindow::resumed(Some(1_000), 1_000), TimedWindow::Off);
    assert_eq!(TimedWindow::resumed(Some(500), 1_000), TimedWindow::Off);
    assert_eq!(TimedWindow::resumed(None, 1_000), TimedWindow::Off);
}

#[test]
fn requests_map_to_windows_and_only_timed_ones_persist() {
    let now = 10_000;
    let hour = TimedWindow::requested(LogWindowChange::OneHour, now);
    assert_eq!(
        hour,
        TimedWindow::Until {
            deadline_ms: now + 3_600_000
        }
    );
    assert_eq!(hour.persisted_until_ms(), Some(now + 3_600_000));
    assert_eq!(
        TimedWindow::requested(LogWindowChange::FourHours, now).persisted_until_ms(),
        Some(now + 4 * 3_600_000)
    );
    let restart = TimedWindow::requested(LogWindowChange::UntilRestart, now);
    assert_eq!(restart, TimedWindow::UntilRestart);
    assert_eq!(restart.persisted_until_ms(), None);
    assert_eq!(
        TimedWindow::requested(LogWindowChange::Off, now),
        TimedWindow::Off
    );
}

#[test]
fn a_timed_window_reports_off_once_its_deadline_passes() {
    let window = TimedWindow::Until { deadline_ms: 5_000 };
    assert!(window.is_open(4_999));
    assert_eq!(window.reported(4_999), (LogWindowMode::Timed, 5_000));
    assert!(!window.is_open(5_000));
    assert_eq!(window.reported(5_000), (LogWindowMode::Off, 0));
    assert_eq!(
        TimedWindow::UntilRestart.reported(i64::MAX),
        (LogWindowMode::UntilRestart, 0)
    );
}

#[test]
fn nothing_stored_leaves_the_sink_alone() {
    let (recording, switch) = live(WindowKind::ConnTraceLog, None);
    assert_eq!(switch.window(), TimedWindow::Off);
    assert!(
        recording.calls().is_empty(),
        "a boot-time override must survive"
    );
}

#[test]
fn a_deadline_that_passed_while_down_closes_the_sink() {
    let (recording, switch) = live(WindowKind::ConnTraceLog, Some(1));
    assert_eq!(switch.window(), TimedWindow::Off);
    assert_eq!(recording.calls(), vec![false]);
}

#[test]
fn a_timed_window_ends_by_itself() {
    for kind in [WindowKind::VerboseLogging, WindowKind::ConnTraceLog] {
        let (recording, switch) = live(kind, None);
        switch.set(
            TimedWindow::Until {
                deadline_ms: now_ms() + 150,
            },
            now_ms(),
        );
        assert_eq!(wait_for(&recording, &[true, false]), vec![true, false]);
        assert_eq!(switch.window(), TimedWindow::Off);
    }
}

#[test]
fn a_resumed_window_ends_by_itself() {
    let (recording, switch) = live(WindowKind::ConnTraceLog, Some(now_ms() + 150));
    assert!(matches!(switch.window(), TimedWindow::Until { .. }));
    assert_eq!(wait_for(&recording, &[false]), vec![false]);
    assert_eq!(switch.window(), TimedWindow::Off);
}

#[test]
fn a_newer_window_retires_the_older_timer() {
    let (recording, switch) = live(WindowKind::ConnTraceLog, None);
    switch.set(
        TimedWindow::Until {
            deadline_ms: now_ms() + 100,
        },
        now_ms(),
    );
    switch.set(TimedWindow::UntilRestart, now_ms());
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(
        recording.calls(),
        vec![true, true],
        "the old deadline must not fire"
    );
    assert_eq!(switch.window(), TimedWindow::UntilRestart);
}

#[test]
fn clones_share_one_window() {
    let (recording, switch) = live(WindowKind::ConnTraceLog, None);
    let other = switch.clone();
    other.set(TimedWindow::UntilRestart, now_ms());
    assert_eq!(switch.window(), TimedWindow::UntilRestart);
    switch.set(TimedWindow::Off, now_ms());
    assert_eq!(other.window(), TimedWindow::Off);
    assert_eq!(recording.calls(), vec![true, false]);
}

/// "Until restart" is held by the process; any other window is what the
/// stored deadline says.
#[test]
fn the_effective_window_follows_the_stored_deadline_except_until_restart() {
    let switch = TimedSwitch::resume(WindowKind::ConnTraceLog, None, 0, None);
    assert_eq!(
        switch.effective(Some(2_000), 1_000),
        TimedWindow::Until { deadline_ms: 2_000 }
    );
    assert_eq!(switch.effective(Some(500), 1_000), TimedWindow::Off);
    switch.set(TimedWindow::UntilRestart, 0);
    assert_eq!(
        switch.effective(Some(500), 1_000),
        TimedWindow::UntilRestart
    );
}
