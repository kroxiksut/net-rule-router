//! A verbose window that ends must close BOTH gates on the way to disk: the
//! tracing filter and the log writer's own level gate. Its own test binary,
//! because it installs the process-wide subscriber the service installs.

use std::sync::Arc;
use std::time::{Duration, Instant};

use nrr_diagnostics::{
    LogWriter, LogWriterConfig, LoggingMode, DEFAULT_TRACING_FILTER, VERBOSE_TRACING_FILTER,
};
use nrr_service_runtime::verbose_logging::{VerboseLogging, VerboseWindow};
use nrr_service_runtime::{install_ndjson_tracing_with_verbose, VerbosityControl};

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[test]
fn an_expired_window_closes_the_filter_and_the_writer_gate() {
    let dir = tempfile::tempdir().expect("temp dir");
    let writer = Arc::new(LogWriter::open(LogWriterConfig::new(dir.path())));
    let deadline = now_ms() + 300;
    // The boot path: a stored deadline still ahead installs verbose tracing.
    let (_outcome, handle) = install_ndjson_tracing_with_verbose(Arc::clone(&writer), true);
    assert_eq!(
        handle.active_directive().as_deref(),
        Some(VERBOSE_TRACING_FILTER)
    );
    assert_eq!(writer.filter().mode(), LoggingMode::Diagnostic);

    let session = VerboseLogging::resume(
        Some(deadline),
        now_ms(),
        Some(Arc::new(handle.clone()) as Arc<dyn VerbosityControl>),
    );
    assert!(matches!(session.window(), VerboseWindow::Until { .. }));

    let started = Instant::now();
    while session.window() != VerboseWindow::Off && started.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        session.window(),
        VerboseWindow::Off,
        "the window must end on its own"
    );
    assert_eq!(
        handle.active_directive().as_deref(),
        Some(DEFAULT_TRACING_FILTER),
        "the tracing filter must be back to the default directive"
    );
    assert_eq!(
        writer.filter().mode(),
        LoggingMode::Default,
        "the writer's own gate must be back to Default, or debug events keep reaching disk"
    );
}
