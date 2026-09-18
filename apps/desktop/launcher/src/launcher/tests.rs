#[test]
fn a_bundled_resource_is_never_taken_from_a_parent_directory() {
    use super::resolve::find_bundled;
    let root = tempfile::tempdir().expect("tempdir");
    let binary_dir = root.path().join("package");
    fs::create_dir_all(&binary_dir).expect("binary dir");
    let planted = root.path().join("apps").join("desktop").join("qml");
    fs::create_dir_all(&planted).expect("planted dir");
    fs::write(planted.join("Main.qml"), "planted").expect("planted file");

    let relative = "apps/desktop/qml/Main.qml";
    assert_eq!(find_bundled(Some(&binary_dir), None, relative), None);

    let shipped = binary_dir.join("apps").join("desktop").join("qml");
    fs::create_dir_all(&shipped).expect("shipped dir");
    fs::write(shipped.join("Main.qml"), "shipped").expect("shipped file");
    assert_eq!(
        find_bundled(Some(&binary_dir), Some(root.path()), relative),
        Some(shipped.join("Main.qml"))
    );
}

#[test]
fn the_checkout_is_consulted_only_after_the_binary_directory() {
    use super::resolve::find_bundled;
    let binary_dir = tempfile::tempdir().expect("binary dir");
    let checkout = tempfile::tempdir().expect("checkout");
    fs::write(checkout.path().join("app.ico"), "dev").expect("dev file");

    assert_eq!(
        find_bundled(Some(binary_dir.path()), Some(checkout.path()), "app.ico"),
        Some(checkout.path().join("app.ico"))
    );
}

use super::diag_log::rotate_session_log;
use super::single_instance::parse_pid_from_lock_content;
use super::{LauncherConfig, LauncherSurface};
use std::fs;

#[test]
fn pid_parser_extracts_value_from_lock_content() {
    assert_eq!(parse_pid_from_lock_content("pid=12345\n"), Some(12345));
    assert_eq!(parse_pid_from_lock_content("pid=abc\n"), None);
    assert_eq!(parse_pid_from_lock_content("key=value\n"), None);
}

#[test]
fn launcher_config_main_gui_uses_canonical_names() {
    let config = LauncherConfig::main_gui();
    assert_eq!(config.surface, LauncherSurface::MainGui);
    assert_eq!(config.app_name, super::BinaryRole::Gui.host_file_name());
    assert_eq!(config.single_instance_key, "gui-shell-v1");
}

#[test]
fn launcher_config_tray_uses_canonical_names() {
    let config = LauncherConfig::tray();
    assert_eq!(config.surface, LauncherSurface::Tray);
    assert_eq!(config.app_name, super::BinaryRole::Tray.host_file_name());
    assert_eq!(config.single_instance_key, "tray-shell-v1");
}

#[test]
fn rotate_session_log_moves_existing_file_to_prev() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("launcher-main.log");
    fs::write(&path, b"session one\n").expect("write log");

    rotate_session_log(&path);

    assert!(!path.exists(), "current log must be moved out of the way");
    let prev = dir.path().join("launcher-main.prev.log");
    assert_eq!(
        fs::read_to_string(&prev).expect("read prev"),
        "session one\n"
    );
}

#[test]
fn rotate_session_log_replaces_an_older_prev() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("launcher-main.log");
    let prev = dir.path().join("launcher-main.prev.log");
    fs::write(&prev, b"stale, two sessions ago\n").expect("write stale prev");
    fs::write(&path, b"session two\n").expect("write log");

    rotate_session_log(&path);

    assert_eq!(
        fs::read_to_string(&prev).expect("read prev"),
        "session two\n"
    );
}

#[test]
fn rotate_session_log_is_a_noop_when_no_file_exists() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("launcher-main.log");

    // Must not create a file or panic on a first-ever launch.
    rotate_session_log(&path);

    assert!(!path.exists());
    assert!(!dir.path().join("launcher-main.prev.log").exists());
}

#[cfg(windows)]
#[test]
fn tasklist_csv_line_parser_extracts_matching_image_name_and_pid() {
    use super::single_instance::parse_tasklist_csv_line;

    assert_eq!(
        parse_tasklist_csv_line("\"NetRuleRouter.exe\",\"12345\",\"Console\",\"1\",\"10,000 K\""),
        Some(("NetRuleRouter.exe".to_string(), 12345))
    );
}

#[cfg(windows)]
#[test]
fn tasklist_csv_line_parser_extracts_an_unrelated_image_name_too() {
    use super::single_instance::parse_tasklist_csv_line;

    // The parser only extracts fields; deciding whether the name matches
    // ours is `is_process_alive`'s job, not the parser's.
    assert_eq!(
        parse_tasklist_csv_line("\"unrelated.exe\",\"12345\",\"Console\",\"1\",\"5,000 K\""),
        Some(("unrelated.exe".to_string(), 12345))
    );
}

#[cfg(windows)]
#[test]
fn tasklist_csv_line_parser_rejects_garbage() {
    use super::single_instance::parse_tasklist_csv_line;

    assert_eq!(parse_tasklist_csv_line("INFO: No tasks are running."), None);
    assert_eq!(parse_tasklist_csv_line(""), None);
    assert_eq!(parse_tasklist_csv_line("\"OnlyOneField\""), None);
}

#[test]
fn a_live_owner_earns_the_long_activation_wait() {
    // Our own pid stands in for a primary that exists but has not reached
    // the point of reading the activation file yet.
    let key = format!("nrr-test-live-owner-{}", std::process::id());
    let dir = nrr_platform_api::paths::user_runtime_dir();
    std::fs::create_dir_all(&dir).expect("runtime dir");
    let lock = dir.join(format!("{key}.lock"));
    std::fs::write(
        &lock,
        format!(
            "pid={}
",
            std::process::id()
        ),
    )
    .expect("write lock");

    assert_eq!(
        super::activation_ack_budget(&key),
        super::ACTIVATION_ACK_TIMEOUT_OWNER_ALIVE,
        "a starting primary must not be declared unresponsive"
    );

    std::fs::write(
        &lock, "pid=1
",
    )
    .expect("write lock");
    // Pid 1 is the system idle process on Windows and init on Linux — never
    // our launcher, so the owner counts as gone.
    let dead_owner = super::activation_ack_budget(&key);
    assert!(dead_owner <= super::ACTIVATION_ACK_TIMEOUT_OWNER_ALIVE);

    let _ = std::fs::remove_file(&lock);
}
