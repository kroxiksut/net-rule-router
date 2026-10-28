//! The launcher reads the host's stdout and stderr until both pipes close. The
//! static `QProcess::startDetached` hands the started process the host's own
//! channels: on Linux file descriptors 0-2, on Windows every inheritable handle
//! (Qt always passes `bInheritHandles = TRUE`). A tray or window started from
//! the host then keeps the launcher's pipes open for as long as it lives, and
//! the launcher waits on a session that has already ended. Every detached start
//! goes through the one helper that gives the child channels of its own.

use std::path::{Path, PathBuf};

fn host_sources() -> Vec<(PathBuf, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../qt-host/native/src");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("list {}: {e}", dir.display()))
        .flatten()
    {
        let path = entry.path();
        let is_source = matches!(path.extension().and_then(|e| e.to_str()), Some("cpp" | "h"));
        if is_source {
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
                .replace("\r\n", "\n");
            out.push((path, text));
        }
    }
    assert!(!out.is_empty(), "no host sources under {}", dir.display());
    out
}

/// The line with any `//` comment removed, so prose naming the call is not
/// mistaken for the call.
fn code_of(line: &str) -> &str {
    line.split("//").next().unwrap_or_default()
}

#[test]
fn no_detached_start_hands_over_the_host_channels() {
    let mut offenders = Vec::new();
    for (path, text) in host_sources() {
        for (index, line) in text.lines().enumerate() {
            if code_of(line).contains("QProcess::startDetached(") {
                offenders.push(format!("{}:{}", path.display(), index + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "static QProcess::startDetached passes the launcher's pipes on to the child; \
         use startDetachedWithOwnChannels: {offenders:?}"
    );
}

#[test]
fn the_helper_closes_every_inherited_channel() {
    let support = host_sources()
        .into_iter()
        .find(|(path, _)| path.ends_with("host_support.h"))
        .map(|(_, text)| text)
        .unwrap_or_else(|| panic!("host_support.h is gone"));
    let body = support
        .split("inline bool startDetachedWithOwnChannels(")
        .nth(1)
        .and_then(|rest| rest.split("\n}\n").next())
        .unwrap_or_else(|| panic!("startDetachedWithOwnChannels is gone"));
    for needed in [
        "setStandardInputFile(QProcess::nullDevice())",
        "setStandardOutputFile(QProcess::nullDevice())",
        "setStandardErrorFile(QProcess::nullDevice())",
        "inheritHandles = false",
        "STARTF_USESTDHANDLES",
        ".startDetached(pid)",
    ] {
        assert!(
            body.contains(needed),
            "startDetachedWithOwnChannels no longer does `{needed}`"
        );
    }
}
