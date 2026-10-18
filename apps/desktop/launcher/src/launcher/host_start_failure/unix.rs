// Unix: the loader prints its own line and exits 127, so there is no box to
// keep away; the notice goes to stderr and, where one runs, to the desktop's
// notification service.

use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::HostStartNotice;

/// Longest body handed to `notify-send`.
const MAX_NOTIFICATION_BODY_CHARS: usize = 2000;
/// How long `notify-send` may take before the launcher stops waiting for it.
const NOTIFY_WAIT: Duration = Duration::from_secs(3);
const NOTIFY_POLL: Duration = Duration::from_millis(50);

/// Nothing to hold on Unix; a value so the spawn site reads the same on every OS.
pub(crate) struct NothingSuppressed;

pub(crate) fn suppress_loader_error_ui() -> NothingSuppressed {
    NothingSuppressed
}

pub(crate) fn show_notice(notice: &HostStartNotice) {
    eprintln!("{}: {}", notice.title, notice.body);
    notify_desktop(notice);
}

/// Best effort: no `notify-send` on PATH, or no notification service behind
/// it, leaves stderr and the log as the only record.
fn notify_desktop(notice: &HostStartNotice) {
    // No shell: argv only, `--` so no text can be read as an option. Library
    // names and versions in the body are already reduced to `[A-Za-z0-9._+-]`,
    // so no markup reaches a server that renders it.
    let body: String = notice
        .body
        .chars()
        .take(MAX_NOTIFICATION_BODY_CHARS)
        .collect();
    let spawned = Command::new("notify-send")
        .arg("--urgency=critical")
        .arg(format!(
            "--app-name={}",
            nrr_shared::product_identity::PRODUCT_NAME
        ))
        .arg("--")
        .arg(&notice.title)
        .arg(body)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = spawned else {
        return;
    };
    let started = Instant::now();
    while started.elapsed() < NOTIFY_WAIT {
        match child.try_wait() {
            Ok(None) => thread::sleep(NOTIFY_POLL),
            Ok(Some(_)) | Err(_) => return,
        }
    }
}
