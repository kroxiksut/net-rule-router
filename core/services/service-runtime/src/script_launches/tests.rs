use super::*;
use crate::app_observation_lookup::AppObservationLookup;
use nrr_platform_api::process_launch::{MockProcessLaunches, ProcessLaunch};
use std::net::Ipv4Addr;

const FOLDER: &str = "/opt/tools/*";

fn args(list: &[&str], cwd: Option<&str>) -> ProcessLaunch {
    ProcessLaunch {
        args: list.iter().map(|a| (*a).to_string()).collect(),
        raw: None,
        cwd: cwd.map(str::to_string),
    }
}

fn linux_store_watching(folder: &str) -> AppObservationStore {
    let store = AppObservationStore::new().with_path_style(PathStyle::Linux);
    // A plan asking about the rule is what makes it watched.
    assert!(store.ips_for_app(folder).is_empty());
    store
}

fn launches(mock: &Arc<MockProcessLaunches>) -> ScriptLaunches {
    ScriptLaunches::new(Arc::clone(mock) as Arc<dyn ProcessLaunchReader>)
        .with_path_style(PathStyle::Linux)
}

#[test]
fn a_script_from_the_rule_folder_is_the_rules_program() {
    let mock = Arc::new(MockProcessLaunches::default());
    mock.set(41, 7, args(&["python3", "-u", "/opt/tools/sync.py"], None));
    mock.set(42, 7, args(&["python3", "/home/u/other.py"], None));
    let scripts = launches(&mock);
    let store = linux_store_watching(FOLDER);

    assert_eq!(
        scripts.rule_paths_run_by(&store, 41, "/usr/bin/python3.11"),
        vec![FOLDER.to_string()]
    );
    assert!(scripts
        .rule_paths_run_by(&store, 42, "/usr/bin/python3.11")
        .is_empty());

    let ip = Ipv4Addr::new(203, 0, 113, 7);
    assert!(store.record_for_rule_paths(&[FOLDER.to_string()], ip));
    assert_eq!(store.ips_for_app(FOLDER), vec![ip]);
    // The interpreter's own name learns nothing from the folder's bucket.
    assert!(store.ips_for_app("python3.11").is_empty());
}

#[test]
fn nothing_is_read_while_no_rule_names_a_path() {
    let mock = Arc::new(MockProcessLaunches::default());
    mock.set(41, 7, args(&["python3", "/opt/tools/sync.py"], None));
    let scripts = launches(&mock);
    let store = AppObservationStore::new().with_path_style(PathStyle::Linux);
    assert!(store.ips_for_app("python3").is_empty());
    assert!(scripts
        .rule_paths_run_by(&store, 41, "/usr/bin/python3")
        .is_empty());
    assert_eq!(mock.reads(), 0);
}

#[test]
fn an_editor_with_a_file_from_the_folder_is_not_its_program() {
    let mock = Arc::new(MockProcessLaunches::default());
    mock.set(51, 1, args(&["vim", "/opt/tools/sync.py"], None));
    mock.set(52, 1, args(&["notepad.exe", r"/opt/tools/run.sh"], None));
    let scripts = launches(&mock);
    let store = linux_store_watching(FOLDER);
    assert!(scripts
        .rule_paths_run_by(&store, 51, "/usr/bin/vim.basic")
        .is_empty());
    assert!(scripts
        .rule_paths_run_by(&store, 52, "notepad.exe")
        .is_empty());
    assert_eq!(mock.reads(), 0, "an editor's command line is never read");
}

#[test]
fn a_process_is_read_once_per_start() {
    let mock = Arc::new(MockProcessLaunches::default());
    mock.set(41, 7, args(&["bash", "/opt/tools/run.sh"], None));
    let scripts = launches(&mock);
    let store = linux_store_watching(FOLDER);
    for _ in 0..3 {
        assert_eq!(
            scripts.rule_paths_run_by(&store, 41, "/usr/bin/bash"),
            vec![FOLDER.to_string()]
        );
    }
    assert_eq!(mock.reads(), 1);

    // The same pid, started again, runs something else.
    mock.set(41, 9, args(&["bash", "/home/u/x.sh"], None));
    assert!(scripts
        .rule_paths_run_by(&store, 41, "/usr/bin/bash")
        .is_empty());
    assert_eq!(mock.reads(), 2);

    // A process that has exited answers nothing, and is not read.
    mock.exit(41);
    assert!(scripts
        .rule_paths_run_by(&store, 41, "/usr/bin/bash")
        .is_empty());
    assert_eq!(mock.reads(), 2);
    assert!(scripts
        .rule_paths_run_by(&store, 0, "/usr/bin/bash")
        .is_empty());
}

#[test]
fn a_file_without_a_script_extension_counts_only_if_it_runs_by_itself() {
    let mock = Arc::new(MockProcessLaunches::default());
    mock.set(61, 1, args(&["python3", "./tool"], Some("/opt/tools")));
    mock.set(62, 1, args(&["python3", "./notes"], Some("/opt/tools")));
    mock.set(63, 1, args(&["python3", "./elsewhere"], Some("/srv")));
    mock.set_runnable("/opt/tools/tool");
    let scripts = launches(&mock);
    let store = linux_store_watching(FOLDER);
    assert_eq!(
        scripts.rule_paths_run_by(&store, 61, "/usr/bin/python3"),
        vec![FOLDER.to_string()]
    );
    assert!(scripts
        .rule_paths_run_by(&store, 62, "/usr/bin/python3")
        .is_empty());
    assert!(scripts
        .rule_paths_run_by(&store, 63, "/usr/bin/python3")
        .is_empty());
}

#[test]
fn java_is_the_program_of_its_jar_and_class_path() {
    let mock = Arc::new(MockProcessLaunches::default());
    mock.set(
        71,
        1,
        args(
            &[
                "java",
                "-cp",
                "/usr/share/java/*:/opt/cassandra/lib/*",
                "org.apache.cassandra.service.CassandraDaemon",
            ],
            None,
        ),
    );
    mock.set(72, 1, args(&["java", "-jar", "/opt/tools/app.jar"], None));
    mock.set(
        73,
        1,
        args(&["java", "-Xmx1g", "org.example.Main"], Some("/")),
    );
    mock.set_class_path(73, "/opt/tools/lib/*");
    let scripts = launches(&mock);
    let cassandra = "/opt/cassandra/*";
    let store = AppObservationStore::new().with_path_style(PathStyle::Linux);
    let _ = store.ips_for_app(cassandra);
    let _ = store.ips_for_app(FOLDER);
    assert_eq!(
        scripts.rule_paths_run_by(&store, 71, "/usr/lib/jvm/bin/java"),
        vec![cassandra.to_string()]
    );
    assert_eq!(
        scripts.rule_paths_run_by(&store, 72, "/usr/lib/jvm/bin/java"),
        vec![FOLDER.to_string()]
    );
    assert_eq!(
        scripts.rule_paths_run_by(&store, 73, "/usr/lib/jvm/bin/java"),
        vec![FOLDER.to_string()]
    );
}

#[test]
fn the_census_counts_a_rules_script_as_its_own_program() {
    let store = linux_store_watching(FOLDER);
    let folder = FOLDER.to_string();
    let ip = Ipv4Addr::new(203, 0, 113, 30);
    // Seen before its command line was read: somebody else, for now.
    store.note_process_destination_running("/usr/bin/python3", 41, &[], ip);
    assert!(store.destination_used_outside(std::slice::from_ref(&folder), ip));
    // The same process, now known to run the folder's script.
    store.note_process_destination_running(
        "/usr/bin/python3",
        41,
        std::slice::from_ref(&folder),
        ip,
    );
    assert!(!store.destination_used_outside(std::slice::from_ref(&folder), ip));
    // Another interpreter process on the address is somebody else.
    store.note_process_destination_running("/usr/bin/python3", 77, &[], ip);
    assert!(store.destination_used_outside(std::slice::from_ref(&folder), ip));
    // A name rule for the interpreter covers every one of them.
    assert!(!store.destination_used_outside(&["python3".to_string()], ip));
}
