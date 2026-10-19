#![no_main]
//! A command line another process set for itself, as each platform keeps
//! it: the Windows string, the Linux NUL-separated area, the macOS argument
//! buffer and environment block, then the reading of which file it runs.

use libfuzzer_sys::fuzz_target;
use nrr_platform_api::process_launch::{
    class_path_files, environ_value, read_launch, split_nul_args, split_procargs2,
    split_windows_command_line, ProcessLaunch, MAX_ARGUMENTS, MAX_CLASS_PATH_ENTRIES,
    MAX_COMMAND_LINE_BYTES,
};
use nrr_shared::app_path::PathStyle;

fuzz_target!(|data: &[u8]| {
    if data.len() > 2 * MAX_COMMAND_LINE_BYTES {
        return;
    }
    let text = String::from_utf8_lossy(data);
    let windows = split_windows_command_line(&text);
    assert!(windows.len() <= MAX_ARGUMENTS);
    let launch = ProcessLaunch {
        args: windows,
        raw: Some(text.to_string()),
        cwd: Some(r"C:\Users\a\".to_string()),
    };
    let _ = read_launch(&launch, PathStyle::Windows);

    let unix = split_nul_args(data);
    assert!(unix.len() <= MAX_ARGUMENTS);
    let launch = ProcessLaunch {
        args: unix,
        raw: None,
        cwd: Some("/home/a".to_string()),
    };
    let _ = read_launch(&launch, PathStyle::Linux);

    let (mac, environ) = split_procargs2(data);
    assert!(mac.len() <= MAX_ARGUMENTS);
    let launch = ProcessLaunch {
        args: mac,
        raw: None,
        cwd: None,
    };
    let _ = read_launch(&launch, PathStyle::MacOS);
    if let Some(value) = environ_value(environ, "CLASSPATH") {
        let entries = class_path_files(&value, PathStyle::MacOS, Some("/"));
        assert!(entries.len() <= MAX_CLASS_PATH_ENTRIES);
    }
    let entries = class_path_files(&text, PathStyle::Windows, Some(r"C:\a"));
    assert!(entries.len() <= MAX_CLASS_PATH_ENTRIES);
});
