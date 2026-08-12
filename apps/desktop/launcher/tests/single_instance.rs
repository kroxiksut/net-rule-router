#![allow(clippy::expect_used)]

//! Coverage for the launcher's single-instance lock. Each test uses a
//! unique key so parallel test runs cannot collide on the shared lock
//! directory at `%TEMP%\NetRuleRouter\<key>.lock`.

use nrr_launcher::SingleInstanceGuard;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_key(label: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("nrr-launcher-test-{label}-{nanos}-{}", std::process::id())
}

#[test]
fn acquire_succeeds_when_no_lock_exists() {
    let key = unique_key("first-acquire");
    let guard = SingleInstanceGuard::acquire(&key)
        .expect("acquire must not error")
        .expect("first acquire must return Some");
    drop(guard);
}

#[test]
fn second_acquire_returns_none_while_guard_alive() {
    let key = unique_key("contention");
    let _primary = SingleInstanceGuard::acquire(&key)
        .expect("acquire must not error")
        .expect("primary must succeed");

    let secondary = SingleInstanceGuard::acquire(&key).expect("secondary acquire must not error");
    assert!(
        secondary.is_none(),
        "secondary acquire must return None while primary holds the lock"
    );
}

#[test]
fn acquire_succeeds_after_guard_is_dropped() {
    let key = unique_key("re-acquire-after-drop");
    {
        let guard = SingleInstanceGuard::acquire(&key)
            .expect("first acquire must not error")
            .expect("first acquire must succeed");
        drop(guard);
    }
    let reacquired = SingleInstanceGuard::acquire(&key)
        .expect("re-acquire must not error")
        .expect("after drop the lock must be released and re-acquirable");
    drop(reacquired);
}

#[test]
fn stale_lock_with_dead_pid_is_cleaned() {
    use std::fs;
    use std::io::Write;

    let key = unique_key("stale-lock");
    let lock_directory = std::env::temp_dir().join("NetRuleRouter");
    fs::create_dir_all(&lock_directory).expect("temp lock dir must be creatable");
    let lock_path = lock_directory.join(format!("{key}.lock"));

    // Use PID=1 which is reserved on Windows (System Idle Process); tasklist
    // will not return our launcher process for it, so cleanup_stale_lock_file
    // treats it as stale.
    {
        let mut handle = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&lock_path)
            .expect("must be able to seed stale lock");
        writeln!(handle, "pid=1").expect("must be able to write seeded pid");
    }

    let guard = SingleInstanceGuard::acquire(&key)
        .expect("acquire must not error after seeding stale lock")
        .expect("stale lock must be cleaned up and acquire must succeed");
    drop(guard);
}
