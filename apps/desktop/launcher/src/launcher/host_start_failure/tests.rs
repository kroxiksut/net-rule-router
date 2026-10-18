use super::*;

const GLIBC_MISSING: &str = "/opt/netrulerouter/nrr_qt_native_host: error while loading shared \
    libraries: libQt6Core.so.6: cannot open shared object file: No such file or directory";
const GLIBC_OUTDATED: &str = "/opt/netrulerouter/nrr_qt_native_host: \
    /lib/x86_64-linux-gnu/libQt6Core.so.6: version `Qt_6.6' not found \
    (required by /opt/netrulerouter/nrr_qt_native_host)";

fn tail_of(lines: &[&str]) -> StderrTail {
    let mut tail = StderrTail::default();
    for line in lines {
        tail.push(line);
    }
    tail
}

fn unix(code: Option<i32>, lines: &[&str]) -> Option<HostStartFailure> {
    classify_host_exit(LoaderConvention::UnixDynamicLoader, code, &tail_of(lines))
}

fn windows(code: Option<i32>) -> Option<HostStartFailure> {
    classify_host_exit(
        LoaderConvention::WindowsNtStatus,
        code,
        &StderrTail::default(),
    )
}

fn nt(status: u32) -> Option<i32> {
    Some(i32::from_ne_bytes(status.to_ne_bytes()))
}

fn named(library: &str) -> Option<HostStartFailure> {
    Some(HostStartFailure::MissingLibrary {
        library: Some(library.to_owned()),
    })
}

const UNNAMED: Option<HostStartFailure> = Some(HostStartFailure::MissingLibrary { library: None });

#[test]
fn windows_missing_dll_and_missing_entry_point_are_loader_failures() {
    assert_eq!(windows(nt(0xC000_0135)), UNNAMED);
    assert_eq!(windows(nt(0xC000_0139)), UNNAMED);
}

#[test]
fn windows_normal_exits_and_other_crashes_are_not() {
    for code in [
        Some(0),
        Some(1),
        Some(127),
        nt(0xC000_0005), // access violation
        nt(0xC000_007B), // bad image format
        nt(0xC000_0409), // stack buffer overrun
        None,
    ] {
        assert_eq!(windows(code), None, "{code:?}");
    }
}

#[test]
fn glibc_missing_library_is_named() {
    assert_eq!(unix(Some(127), &[GLIBC_MISSING]), named("libQt6Core.so.6"));
}

#[test]
fn musl_missing_library_is_named() {
    let line = "Error loading shared library libQt6Gui.so.6: No such file or directory \
        (needed by /opt/netrulerouter/nrr_qt_native_host)";
    assert_eq!(unix(Some(127), &[line]), named("libQt6Gui.so.6"));
}

#[test]
fn glibc_version_mismatch_names_library_and_version() {
    assert_eq!(
        unix(Some(127), &[GLIBC_OUTDATED]),
        Some(HostStartFailure::OutdatedLibrary {
            library: "libQt6Core.so.6".to_owned(),
            version: "Qt_6.6".to_owned(),
        })
    );
    let quoted = GLIBC_OUTDATED.replace('`', "'");
    assert_eq!(
        unix(Some(127), &[&quoted]),
        Some(HostStartFailure::OutdatedLibrary {
            library: "libQt6Core.so.6".to_owned(),
            version: "Qt_6.6".to_owned(),
        })
    );
}

#[test]
fn a_library_given_as_a_path_is_named_by_its_file() {
    let line = "x: error while loading shared libraries: /opt/qt/lib/libQt6Core.so.6: cannot open";
    assert_eq!(unix(Some(127), &[line]), named("libQt6Core.so.6"));
}

#[test]
fn undefined_symbol_is_a_loader_failure_without_a_name() {
    let line = "/opt/netrulerouter/nrr_qt_native_host: symbol lookup error: \
        /opt/netrulerouter/nrr_qt_native_host: undefined symbol: _ZN7QObject5eventEP6QEvent";
    assert_eq!(unix(Some(127), &[line]), UNNAMED);
}

#[test]
fn the_unix_verdict_needs_both_the_exit_code_and_the_loader_line() {
    assert_eq!(unix(Some(1), &[GLIBC_MISSING]), None);
    assert_eq!(unix(Some(0), &[GLIBC_MISSING]), None);
    assert_eq!(unix(None, &[GLIBC_MISSING]), None);
    assert_eq!(
        unix(Some(127), &["qt.qpa.xcb: could not connect to display"]),
        None
    );
    assert_eq!(unix(Some(127), &[]), None);
}

#[test]
fn a_windows_code_means_nothing_under_the_unix_convention() {
    assert_eq!(unix(nt(0xC000_0135), &[GLIBC_MISSING]), None);
}

#[test]
fn the_loader_line_is_found_among_other_output() {
    let lines = ["qt.qpa.plugin: something", GLIBC_MISSING, "trailing noise"];
    assert_eq!(unix(Some(127), &lines), named("libQt6Core.so.6"));
}

#[test]
fn a_hostile_library_name_is_never_repeated() {
    for name in [
        "<b>lib</b>.so",
        "lib\u{1b}[31mred.so",
        "lib name.so",
        "\u{431}\u{438}\u{431}.so",
        "",
    ] {
        let line = format!("x: error while loading shared libraries: {name}: cannot open");
        assert_eq!(unix(Some(127), &[&line]), UNNAMED, "{name:?}");
    }
    let long = format!(
        "x: error while loading shared libraries: lib{}.so: cannot open",
        "a".repeat(4096)
    );
    assert_eq!(unix(Some(127), &[&long]), UNNAMED);
}

#[test]
fn a_hostile_version_falls_back_to_the_named_library() {
    let line = "x: /lib/libQt6Core.so.6: version `<i>6.6</i>' not found (required by x)";
    assert_eq!(unix(Some(127), &[line]), named("libQt6Core.so.6"));
}

#[test]
fn a_version_line_without_not_found_is_ignored() {
    let line = "x: /lib/libQt6Core.so.6: version `Qt_6.6' is fine";
    assert_eq!(unix(Some(127), &[line]), None);
}

#[test]
fn lossy_decoded_bytes_do_not_hide_the_library() {
    let bytes = b"/opt/\xff\xfe: error while loading shared libraries: libQt6Core.so.6: x";
    let line = String::from_utf8_lossy(bytes);
    assert_eq!(unix(Some(127), &[&line]), named("libQt6Core.so.6"));
}

#[test]
fn the_tail_is_bounded_in_lines_and_bytes() {
    let mut tail = StderrTail::default();
    let huge = "\u{44f}".repeat(MAX_TAIL_LINE_BYTES); // two bytes each
    for _ in 0..(MAX_TAIL_LINES * 4) {
        tail.push(&huge);
    }
    tail.push(GLIBC_MISSING);
    let lines = tail.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), MAX_TAIL_LINES);
    assert!(lines.iter().all(|line| line.len() <= MAX_TAIL_LINE_BYTES));
    assert_eq!(lines.last().copied(), Some(GLIBC_MISSING));
    let clipped = lines.first().copied().unwrap_or_default();
    assert!(clipped.chars().all(|ch| ch == '\u{44f}'));
}

#[test]
fn clipping_never_splits_a_character() {
    assert_eq!(clip_to_bytes("a\u{44f}", 2), "a");
    assert_eq!(clip_to_bytes("abc", 3), "abc");
    assert_eq!(clip_to_bytes("\u{1f600}", 3), "");
}

#[test]
fn a_poisoned_tail_still_records_and_classifies() {
    let tail = StderrTail::shared();
    let poisoner = Arc::clone(&tail);
    let _ = std::thread::spawn(move || {
        let _guard = poisoner.lock();
        panic!("poison the tail");
    })
    .join();
    record_stderr_line(&tail, GLIBC_MISSING);
    let guard = tail.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(
        classify_host_exit(LoaderConvention::UnixDynamicLoader, Some(127), &guard),
        named("libQt6Core.so.6")
    );
}

fn catalog(language: &str, entries: &[(&str, &str)]) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut catalog = BTreeMap::new();
    catalog.insert(
        language.to_owned(),
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect(),
    );
    catalog
}

#[test]
fn the_notice_names_the_library_and_the_log() {
    let notice = notice_text(
        &HostStartFailure::MissingLibrary {
            library: Some("libQt6Core.so.6".to_owned()),
        },
        &BTreeMap::new(),
        "en",
        Path::new("/home/u/.local/state/netrulerouter/launcher-main.log"),
    );
    assert_eq!(notice.title, "NetRuleRouter cannot start");
    assert!(notice.body.contains("libQt6Core.so.6"));
    assert!(notice
        .body
        .contains("/home/u/.local/state/netrulerouter/launcher-main.log"));
    assert!(!notice.body.contains('{'));
}

#[test]
fn the_notice_follows_the_language_and_falls_back_per_key() {
    let mut catalog = catalog(
        "en",
        &[
            ("dialog.host-start.title", "EN title"),
            ("dialog.host-start.missing-library", "EN body"),
            ("dialog.host-start.log-hint", "EN log {log}"),
        ],
    );
    catalog.insert(
        "ru".to_owned(),
        [("dialog.host-start.title".to_owned(), "RU title".to_owned())]
            .into_iter()
            .collect(),
    );
    let notice = notice_text(
        &HostStartFailure::MissingLibrary { library: None },
        &catalog,
        "ru",
        Path::new("C:\\log.txt"),
    );
    assert_eq!(notice.title, "RU title");
    assert_eq!(notice.body, "EN body\n\nEN log C:\\log.txt");
}

#[test]
fn a_log_path_with_braces_is_shown_as_is() {
    let catalog = catalog(
        "en",
        &[
            ("dialog.host-start.outdated-library", "{library} {version}"),
            ("dialog.host-start.log-hint", "{log}"),
        ],
    );
    let notice = notice_text(
        &HostStartFailure::OutdatedLibrary {
            library: "libQt6Core.so.6".to_owned(),
            version: "Qt_6.6".to_owned(),
        },
        &catalog,
        "en",
        Path::new("/tmp/{library}/x.log"),
    );
    assert_eq!(
        notice.body,
        "libQt6Core.so.6 Qt_6.6\n\n/tmp/{library}/x.log"
    );
}
