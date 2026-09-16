#![allow(clippy::expect_used)]

//! Coverage for `resolve_native_host_executable`, consulted on every launch
//! to find `nrr_qt_native_host.exe`.

use nrr_launcher::resolve_native_host_executable;
use std::env;
use std::sync::{Mutex, MutexGuard, OnceLock};
use tempfile::tempdir;

/// Both tests below drive the SAME process-wide variable, and `cargo test`
/// runs them on separate threads — whichever set it last decided the other's
/// answer, so the suite failed at random. Serialise them.
fn env_guard() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
fn explicit_env_override_is_honoured() {
    let _serialised = env_guard();
    let dir = tempdir().expect("tempdir must be creatable");
    let fake_host = dir.path().join("nrr_qt_native_host.exe");
    std::fs::write(&fake_host, b"stub").expect("stub binary must be writable");

    // Restored unconditionally below, so a later test sees the original value.
    let prior = env::var_os("NRR_QT_NATIVE_HOST_EXE");
    env::set_var("NRR_QT_NATIVE_HOST_EXE", &fake_host);

    let resolved = resolve_native_host_executable();

    if let Some(value) = prior {
        env::set_var("NRR_QT_NATIVE_HOST_EXE", value);
    } else {
        env::remove_var("NRR_QT_NATIVE_HOST_EXE");
    }

    let resolved = resolved.expect("env override must resolve to existing path");
    assert_eq!(resolved, fake_host);
}

#[test]
fn missing_env_path_falls_through_to_other_strategies() {
    let _serialised = env_guard();
    let dir = tempdir().expect("tempdir must be creatable");
    let missing = dir.path().join("no-such-file.exe");
    let prior = env::var_os("NRR_QT_NATIVE_HOST_EXE");
    env::set_var("NRR_QT_NATIVE_HOST_EXE", &missing);

    let resolved = resolve_native_host_executable();

    if let Some(value) = prior {
        env::set_var("NRR_QT_NATIVE_HOST_EXE", value);
    } else {
        env::remove_var("NRR_QT_NATIVE_HOST_EXE");
    }

    assert_ne!(resolved.as_deref(), Some(missing.as_path()));
    // Beside the binary, then (debug builds only) the build-time path. A tree
    // without a built host legitimately yields None, so only an answer that
    // names a missing file is wrong.
    if let Some(path) = resolved {
        assert!(
            path.exists(),
            "resolved path must exist on disk: {}",
            path.display()
        );
    }
}
