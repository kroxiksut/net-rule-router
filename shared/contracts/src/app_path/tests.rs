use super::*;

const WIN: PathStyle = PathStyle::Windows;
const LINUX: PathStyle = PathStyle::Linux;
const MAC: PathStyle = PathStyle::MacOS;

fn parsed(raw: &str, style: PathStyle) -> (AppPathKind, String) {
    let path = AppPath::parse(raw, style).unwrap_or_else(|e| panic!("{raw}: {e}"));
    (path.kind(), path.as_str().to_string())
}

#[test]
fn every_windows_form_reads_as_written() {
    for (raw, kind, text) in [
        (r"C:\Temp\App.exe", AppPathKind::File, r"c:\temp\app.exe"),
        (r"C:\Temp", AppPathKind::Folder, r"c:\temp\"),
        (r"C:\Temp\", AppPathKind::Folder, r"c:\temp\"),
        (r"C:\Temp\*", AppPathKind::FolderTree, r"c:\temp\*"),
        ("C:/Temp/*", AppPathKind::FolderTree, r"c:\temp\*"),
        (
            r"C:\Temp\App.exe\",
            AppPathKind::Folder,
            r"c:\temp\app.exe\",
        ),
        (r"C:\", AppPathKind::Folder, r"c:\"),
        (r"C:\*", AppPathKind::FolderTree, r"c:\*"),
        (
            r"\\Server\Share\Tools\",
            AppPathKind::Folder,
            r"\\server\share\tools\",
        ),
        (
            r"\\?\C:\Temp\App.exe",
            AppPathKind::File,
            r"c:\temp\app.exe",
        ),
        (r"  C:\Temp\\Sub.\ ", AppPathKind::Folder, r"c:\temp\sub\"),
    ] {
        assert_eq!(parsed(raw, WIN), (kind, text.to_string()), "{raw}");
    }
}

#[test]
fn a_unix_path_without_a_trailing_slash_waits_for_the_disk() {
    for style in [LINUX, MAC] {
        assert_eq!(parsed("/opt/app", style).0, AppPathKind::FileOrFolder);
        assert_eq!(parsed("/opt/app/", style).0, AppPathKind::Folder);
        assert_eq!(parsed("/opt/app/*", style).0, AppPathKind::FolderTree);
        assert_eq!(parsed("/", style), (AppPathKind::Folder, "/".to_string()));
        assert_eq!(
            parsed("/*", style),
            (AppPathKind::FolderTree, "/*".to_string())
        );
    }
}

#[test]
fn case_is_folded_only_where_the_platform_ignores_it() {
    assert_eq!(parsed("/opt/App/", LINUX).1, "/opt/App/");
    assert_eq!(
        parsed("/Applications/App.app/*", MAC).1,
        "/applications/app.app/*"
    );
    assert_eq!(parsed(r"C:\Apps\", WIN).1, r"c:\apps\");
}

#[test]
fn a_star_stands_only_as_the_last_segment() {
    for raw in [
        r"C:\Temp\*.exe",
        r"C:\*\app.exe",
        r"C:\Temp\nord*",
        r"C:\Temp\*\",
        r"C:\Temp\**",
    ] {
        assert_eq!(
            AppPath::parse(raw, WIN),
            Err(AppPathError::StarNotLast),
            "{raw}"
        );
    }
    for raw in ["/opt/*/bin", "/opt/app*", "/opt/**"] {
        assert_eq!(
            AppPath::parse(raw, LINUX),
            Err(AppPathError::StarNotLast),
            "{raw}"
        );
    }
}

#[test]
fn a_relative_path_names_no_program() {
    for raw in [
        r"Temp\app.exe",
        r"C:Temp\app.exe",
        r".\app.exe",
        r"\app.exe",
        "bin/app",
    ] {
        assert_eq!(
            AppPath::parse(raw, WIN),
            Err(AppPathError::NotAbsolute),
            "{raw}"
        );
    }
    for raw in ["./app", "bin/app", "~/bin/app", "../app"] {
        assert_eq!(
            AppPath::parse(raw, LINUX),
            Err(AppPathError::NotAbsolute),
            "{raw}"
        );
    }
}

#[test]
fn a_path_that_climbs_or_breaks_is_malformed() {
    for raw in [
        r"C:\Temp\..\Windows\",
        r"C:\Temp\a:b\",
        r"\\server",
        "C:\\Temp\u{1}\\",
    ] {
        assert_eq!(
            AppPath::parse(raw, WIN),
            Err(AppPathError::Malformed),
            "{raw}"
        );
    }
    assert_eq!(
        AppPath::parse("/opt/../etc/", LINUX),
        Err(AppPathError::Malformed)
    );
    let deep = format!("/{}", "a/".repeat(MAX_PATH_SEGMENTS + 1));
    assert_eq!(AppPath::parse(&deep, LINUX), Err(AppPathError::Malformed));
    let long = format!("/{}", "a".repeat(MAX_PATH_BYTES));
    assert_eq!(AppPath::parse(&long, LINUX), Err(AppPathError::Malformed));
}

#[test]
fn a_separator_makes_a_value_a_path() {
    assert!(is_path_value(r"C:\Temp\app.exe", WIN));
    assert!(is_path_value("C:/Temp/app.exe", WIN));
    assert!(is_path_value("/opt/app", LINUX));
    assert!(!is_path_value("app.exe", WIN));
    assert!(!is_path_value("nord*", WIN));
    // A Linux file name may hold a backslash.
    assert!(!is_path_value(r"odd\name", LINUX));
}

#[test]
fn canonicalizing_twice_changes_nothing() {
    for (raw, style) in [
        (r"C:\Temp\App.exe", WIN),
        (r"C:\Temp", WIN),
        (r"C:\Temp\*", WIN),
        ("/opt/App", LINUX),
        ("/opt/App/", LINUX),
        ("/opt/App/*", MAC),
    ] {
        let once = AppPath::parse(raw, style).expect("parses");
        let twice = AppPath::parse(once.as_str(), style).expect("parses again");
        assert_eq!(once, twice, "{raw}");
    }
}

#[test]
fn an_image_is_matched_by_the_form_the_rule_names() {
    let image = r"C:\Program Files\Example\bin\example.exe";
    let rule = |raw: &str| AppPath::parse(raw, WIN).expect("parses");
    assert_eq!(
        rule(r"C:\Program Files\Example\bin\Example.exe").match_image(image),
        Some(AppPathKind::File)
    );
    assert_eq!(
        rule(r"C:\Program Files\Example\bin\").match_image(image),
        Some(AppPathKind::Folder)
    );
    assert_eq!(rule(r"C:\Program Files\Example\").match_image(image), None);
    assert_eq!(
        rule(r"C:\Program Files\Example\*").match_image(image),
        Some(AppPathKind::FolderTree)
    );
    assert_eq!(
        rule(r"C:\Program Files\Example\bin\*").match_image(image),
        Some(AppPathKind::FolderTree)
    );
    assert_eq!(rule(r"C:\Program Files\Other\*").match_image(image), None);
    assert_eq!(
        rule(r"C:\Program Files\Example\bin\other.exe").match_image(image),
        None
    );
    assert_eq!(
        rule(r"C:\Program Files\Example\*").match_image("example.exe"),
        None
    );
}

#[test]
fn an_undecided_unix_path_matches_as_a_file_or_as_a_folder() {
    let rule = AppPath::parse("/opt/app", LINUX).expect("parses");
    assert_eq!(rule.match_image("/opt/app"), Some(AppPathKind::File));
    assert_eq!(rule.match_image("/opt/app/run"), Some(AppPathKind::Folder));
    assert_eq!(rule.match_image("/opt/app/bin/run"), None);
    // Linux compares case exactly.
    assert_eq!(rule.match_image("/opt/App/run"), None);
    let mac = AppPath::parse("/Applications/App.app/*", MAC).expect("parses");
    assert_eq!(
        mac.match_image("/Applications/APP.app/Contents/MacOS/App"),
        Some(AppPathKind::FolderTree)
    );
}

#[test]
fn the_disk_decides_an_undecided_path_and_moves_a_rule_to_its_real_place() {
    let undecided = AppPath::parse("/opt/app", LINUX).expect("parses");
    let folder = undecided.on_disk("/data/app", true).expect("real folder");
    assert_eq!(folder.kind(), AppPathKind::Folder);
    assert_eq!(folder.as_str(), "/data/app/");
    assert_eq!(
        folder.match_image("/data/app/run"),
        Some(AppPathKind::Folder)
    );
    assert_eq!(folder.match_image("/opt/app/run"), None);
    let file = undecided.on_disk("/opt/app", false).expect("a file");
    assert_eq!(file.kind(), AppPathKind::File);
    assert_eq!(file.match_image("/opt/app"), Some(AppPathKind::File));
    assert_eq!(file.match_image("/opt/app/run"), None);

    // A decided form is kept; only the place moves, behind a junction too.
    let tree = AppPath::parse(r"C:\Tools\*", WIN).expect("parses");
    let real = tree.on_disk(r"\\?\D:\Real Tools", true).expect("real");
    assert_eq!(real.kind(), AppPathKind::FolderTree);
    assert_eq!(real.as_str(), r"d:\real tools\*");
    assert_eq!(
        real.match_image(r"D:\Real Tools\v2\tool.exe"),
        Some(AppPathKind::FolderTree)
    );
    assert!(tree.on_disk("relative", true).is_err());
    assert!(tree.on_disk("", true).is_err());
}

/// The vectors the macOS port keeps from the start: a bundle folder with its
/// subfolders, compared without case as the default volume does.
#[test]
fn a_mac_bundle_rule_covers_every_program_inside_the_bundle() {
    let bundle = AppPath::parse("/Applications/X.app/*", MAC).expect("parses");
    assert_eq!(bundle.kind(), AppPathKind::FolderTree);
    assert_eq!(bundle.as_str(), "/applications/x.app/*");
    for image in [
        "/Applications/X.app/Contents/MacOS/X",
        "/applications/x.app/Contents/Frameworks/Helper.app/Contents/MacOS/Helper",
    ] {
        assert_eq!(
            bundle.match_image(image),
            Some(AppPathKind::FolderTree),
            "{image}"
        );
    }
    for image in [
        "/Applications/Y.app/Contents/MacOS/Y",
        "/Applications/X.app",
        "/Applications/X.application/Contents/MacOS/X",
    ] {
        assert_eq!(bundle.match_image(image), None, "{image}");
    }
    // The same spelling on Linux compares case exactly.
    let linux = AppPath::parse("/Applications/X.app/*", LINUX).expect("parses");
    assert_eq!(
        linux.match_image("/applications/x.app/Contents/MacOS/X"),
        None
    );
}

#[test]
fn depth_counts_below_the_root() {
    let depth = |raw: &str, style| AppPath::parse(raw, style).expect("parses").depth();
    assert_eq!(depth(r"C:\", WIN), 0);
    assert_eq!(depth(r"C:\a\b\", WIN), 2);
    assert_eq!(depth("/", LINUX), 0);
    assert_eq!(depth("/a/b/*", LINUX), 2);
}

#[test]
fn the_place_of_a_tree_is_its_folder() {
    let place = |raw: &str| {
        AppPath::parse(raw, WIN)
            .expect("parses")
            .place()
            .to_string()
    };
    assert_eq!(place(r"C:\Temp\*"), r"c:\temp\");
    assert_eq!(place(r"C:\Temp\app.exe"), r"c:\temp\app.exe");
}

#[test]
fn hostile_input_never_panics() {
    let samples = [
        "",
        "\\",
        "/",
        "\\\\",
        "\\\\?\\",
        "\\\\?\\unc\\",
        "C:",
        ":",
        "*",
        "/*",
        "\\*",
        "ﬀ:\\x",
        "C:\\\u{0130}\\",
        "/\u{10FFFF}/",
    ];
    for raw in samples {
        for style in [WIN, LINUX, MAC] {
            let _ = AppPath::parse(raw, style);
            let _ = path_segments(raw, style, true);
        }
    }
}

#[test]
fn a_path_has_its_own_byte_bound_and_a_name_the_shorter_one() {
    assert_eq!(
        app_value_byte_limit("/opt/tool/", LINUX),
        MAX_PATH_VALUE_BYTES
    );
    assert_eq!(
        app_value_byte_limit("tool.exe", WIN),
        crate::rule_value_class::MAX_RULE_VALUE_BYTES
    );
    const { assert!(MAX_PATH_VALUE_BYTES > crate::rule_value_class::MAX_RULE_VALUE_BYTES) };
}
