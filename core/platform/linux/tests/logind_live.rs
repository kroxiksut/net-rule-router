//! Live logind probe. `#[ignore]`d out of the default gate because a container
//! or a WSL image built without systemd has no logind; under `--ignored` a
//! missing logind fails, so a pass never reports coverage the test did not have.
//!
//! Needs no privileges: reading who is logged in is not a privileged question.

#![cfg(target_os = "linux")]

use nrr_platform_linux::logind::{live_users, LogindError};

#[test]
#[ignore = "needs systemd-logind as the session manager"]
fn logind_answers_who_is_logged_in() {
    match live_users() {
        Ok(users) => {
            // Nobody logged in is a legitimate answer on a headless box, so the
            // assertion is about the SHAPE of what came back, not the count.
            for u in &users {
                assert!(
                    !u.name.is_empty(),
                    "a live user without a name means the JSON shape changed"
                );
                // uid 0 IS a legitimate login — a root shell, which this project
                // meets routinely on a daemon host. What it must never be is a
                // field that failed to parse into a plausible-looking zero, and
                // the name is what tells the two apart.
                assert!(
                    u.uid != 0 || u.name == "root",
                    "uid 0 must belong to root; anything else is a zero that came from a field this parser did not understand",
                );
            }
            eprintln!("logind reported {} live user(s)", users.len());
        }
        Err(LogindError::Unavailable(e)) => {
            panic!("logind is not available here ({e}): this test needs systemd-logind");
        }
        Err(LogindError::Unreadable(e)) => {
            // Worth failing on: it means this systemd prints a shape we cannot
            // read, which is exactly what the module refuses to guess at.
            panic!("loginctl answered unreadably — systemd too old for --output=json? {e}");
        }
        Err(e) => panic!("loginctl failed: {e}"),
    }
}
