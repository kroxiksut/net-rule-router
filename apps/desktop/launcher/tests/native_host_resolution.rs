#![allow(clippy::expect_used)]

//! Coverage for `resolve_native_host_executable`. The function is consulted
//! every launch to find `nrr_qt_native_host.exe`; getting it wrong was the
//! root cause of the `cargo run` fallback that produced the original blue
//! console window during the 13.R-GUI investigation.

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
    let prior = env::var_os("NRR_QT_NATIVE_HOST_EXE");
    env::set_var("NRR_QT_NATIVE_HOST_EXE", "C:/nonexistent/no-such-file.exe");

    let resolved = resolve_native_host_executable();

    if let Some(value) = prior {
        env::set_var("NRR_QT_NATIVE_HOST_EXE", value);
    } else {
        env::remove_var("NRR_QT_NATIVE_HOST_EXE");
    }

    // The fallback chain (current_exe-adjacent → CMake-baked path) is
    // expected to find the host in a normal dev build. Outside a build
    // (CI cache miss, fresh checkout) it may legitimately return None — we
    // only assert that the resolver does not panic and that, when it does
    // resolve, it returns a path that exists.
    if let Some(path) = resolved {
        assert!(
            path.exists(),
            "resolved path must exist on disk: {}",
            path.display()
        );
    }
}
