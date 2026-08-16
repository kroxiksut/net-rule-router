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

/// The incident this guard was rebuilt for: a user cleaning out the runtime
/// directory while the app runs. Ownership must survive the file's deletion,
/// or every later launch becomes a second primary (two trays, two GUIs).
#[test]
fn deleting_the_lock_file_does_not_let_a_second_instance_become_primary() {
    let key = unique_key("deleted-lock");
    let _primary = SingleInstanceGuard::acquire(&key)
        .expect("acquire must not error")
        .expect("primary must succeed");

    let lock_path = nrr_platform_api::paths::user_runtime_dir().join(format!("{key}.lock"));
    std::fs::remove_file(&lock_path).expect("the lock file must be deletable, as it is for a user");

    let secondary = SingleInstanceGuard::acquire(&key).expect("secondary acquire must not error");
    assert!(
        secondary.is_none(),
        "ownership must outlive the lock file — the primary is still running"
    );
}

/// Two primaries can only ever coexist through a bug, but if they do, the first
/// one to exit must not strip the survivor's lock.
#[test]
fn dropping_a_guard_leaves_a_lock_file_that_records_another_owner() {
    use std::io::Write;

    let key = unique_key("foreign-owner");
    let guard = SingleInstanceGuard::acquire(&key)
        .expect("acquire must not error")
        .expect("acquire must succeed");
    let lock_path = nrr_platform_api::paths::user_runtime_dir().join(format!("{key}.lock"));

    {
        let mut handle = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&lock_path)
            .expect("lock file must be writable");
        writeln!(handle, "pid=424242").expect("must be able to record a foreign owner");
    }
    drop(guard);

    assert!(
        lock_path.exists(),
        "a guard must delete only the lock that still records its own pid"
    );
    let _ = std::fs::remove_file(&lock_path);
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
