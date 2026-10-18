use super::*;

fn names(listing: &FolderListing, root: &Path) -> Vec<String> {
    listing
        .programs
        .iter()
        .map(|p| {
            p.strip_prefix(root)
                .unwrap_or(p)
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect()
}

fn tree(files: &[&str]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    for file in files {
        let path = dir.path().join(file);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("mkdir");
        }
        std::fs::write(&path, b"").expect("write");
    }
    dir
}

fn by_extension(path: &Path) -> bool {
    path.extension().is_some_and(|e| e == "bin")
}

#[test]
fn a_folder_lists_its_own_programs_and_a_tree_every_level_in_a_stable_order() {
    let dir = tree(&[
        "b.bin",
        "a.bin",
        "notes.txt",
        "v2/new.bin",
        "v1/old.bin",
        "v1/deep/inner.bin",
    ]);
    let root = dir.path();
    let style = PathStyle::Linux;
    let own = list_programs(root, false, style, &by_extension, ListingLimits::default());
    assert_eq!(names(&own, root), ["a.bin", "b.bin"]);
    assert!(!own.truncated);
    let all = list_programs(root, true, style, &by_extension, ListingLimits::default());
    assert_eq!(
        names(&all, root),
        [
            "a.bin",
            "b.bin",
            "v1/old.bin",
            "v2/new.bin",
            "v1/deep/inner.bin"
        ],
        "breadth first, each level sorted"
    );
    assert!(!all.truncated);
}

/// Every bound says so: a partly covered folder never reads as a complete one.
#[test]
fn each_bound_marks_the_listing_truncated() {
    let dir = tree(&["a.bin", "b.bin", "c.bin", "sub/d.bin", "sub/deeper/e.bin"]);
    let root = dir.path();
    let style = PathStyle::Linux;
    let capped = list_programs(
        root,
        true,
        style,
        &by_extension,
        ListingLimits {
            programs: 2,
            ..ListingLimits::default()
        },
    );
    assert_eq!(names(&capped, root), ["a.bin", "b.bin"]);
    assert!(capped.truncated);

    let shallow = list_programs(
        root,
        true,
        style,
        &by_extension,
        ListingLimits {
            depth: 1,
            ..ListingLimits::default()
        },
    );
    assert_eq!(
        names(&shallow, root),
        ["a.bin", "b.bin", "c.bin", "sub/d.bin"]
    );
    assert!(shallow.truncated, "a folder below the depth bound exists");

    // The budget runs out inside the second folder: it is left out whole.
    let budget = list_programs(
        root,
        true,
        style,
        &by_extension,
        ListingLimits {
            entries: 5,
            ..ListingLimits::default()
        },
    );
    assert_eq!(names(&budget, root), ["a.bin", "b.bin", "c.bin"]);
    assert!(budget.truncated);
}

#[test]
fn a_missing_or_unreadable_folder_lists_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let listing = list_programs(
        &dir.path().join("absent"),
        true,
        PathStyle::Linux,
        &by_extension,
        ListingLimits::default(),
    );
    assert_eq!(listing, FolderListing::default());
}

/// A link inside a rule's folder is not followed: it cannot widen the rule to
/// wherever it points, nor make the walk loop.
#[cfg(unix)]
#[test]
fn a_link_inside_the_folder_is_not_followed() {
    let outside = tree(&["elsewhere.bin"]);
    let dir = tree(&["own.bin"]);
    std::os::unix::fs::symlink(outside.path(), dir.path().join("linked")).expect("link");
    std::os::unix::fs::symlink(dir.path(), dir.path().join("loop")).expect("loop");
    let listing = list_programs(
        dir.path(),
        true,
        PathStyle::Linux,
        &by_extension,
        ListingLimits::default(),
    );
    assert_eq!(names(&listing, dir.path()), ["own.bin"]);
}

#[test]
fn a_windows_program_is_an_exe_and_a_unix_one_has_an_execute_bit() {
    let dir = tree(&["tool.EXE", "tool.dll", "script"]);
    assert!(is_program_file(
        &dir.path().join("tool.EXE"),
        PathStyle::Windows
    ));
    assert!(!is_program_file(
        &dir.path().join("tool.dll"),
        PathStyle::Windows
    ));
    assert!(!is_program_file(
        &dir.path().join("absent.exe"),
        PathStyle::Windows
    ));
    assert!(!is_program_file(
        &dir.path().join("script"),
        PathStyle::Linux
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let script = dir.path().join("script");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        assert!(is_program_file(&script, PathStyle::Linux));
        assert!(is_program_file(&script, PathStyle::MacOS));
        assert!(!is_program_file(dir.path(), PathStyle::Linux), "a folder");
    }
}

#[test]
fn the_verbatim_prefix_goes_only_from_a_drive_path() {
    assert_eq!(
        strip_verbatim_drive_prefix(PathBuf::from(r"\\?\C:\Apps\x.exe")),
        PathBuf::from(r"C:\Apps\x.exe")
    );
    let share = PathBuf::from(r"\\?\UNC\server\share\x.exe");
    assert_eq!(strip_verbatim_drive_prefix(share.clone()), share);
    assert_eq!(
        strip_verbatim_drive_prefix(PathBuf::from("/opt/app")),
        PathBuf::from("/opt/app")
    );
}

#[test]
fn a_place_is_a_file_a_folder_or_missing() {
    let dir = tree(&["file.bin"]);
    assert_eq!(place_of(dir.path()), PlaceOnDisk::Folder);
    assert_eq!(place_of(&dir.path().join("file.bin")), PlaceOnDisk::File);
    assert_eq!(place_of(&dir.path().join("none")), PlaceOnDisk::Missing);
}

#[test]
fn a_log_beside_the_programs_is_noise_and_a_new_folder_is_not() {
    for noise in ["debug.log", r"logs\app.LOG", "cache/data.ldb", "x.tmp"] {
        assert!(!name_may_change_programs(noise), "{noise}");
    }
    for change in [
        "app-1.0.9164",
        r"app-1.0.9164\Discord.exe",
        "tool",
        "Update.exe",
    ] {
        assert!(name_may_change_programs(change), "{change}");
    }
    assert!(name_is_windows_program(r"sub\Tool.EXE"));
    assert!(!name_is_windows_program(".exe"));
    assert!(!name_is_windows_program("tool.exe.log"));
    assert!(!name_is_windows_program("\u{0430}\u{0431}"));
}

// ── ReadDirectoryChangesW records ─────────────────────────────────────────────

fn record(action: u32, name: &str, last: bool) -> Vec<u8> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let name_len = units.len() * 2;
    // Records are DWORD aligned, as the OS writes them.
    let len = (12 + name_len).div_ceil(4) * 4;
    let mut bytes = Vec::with_capacity(len);
    let next = if last { 0 } else { len as u32 };
    bytes.extend_from_slice(&next.to_le_bytes());
    bytes.extend_from_slice(&action.to_le_bytes());
    bytes.extend_from_slice(&(name_len as u32).to_le_bytes());
    for unit in units {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.resize(len, 0);
    bytes
}

#[test]
fn every_record_of_a_buffer_is_read_with_its_name() {
    let mut buffer = record(1, r"app-1.0.9164\Discord.exe", false);
    buffer.extend(record(5, "Ünïcødé.exe", true));
    let records = notify_records(&buffer);
    assert_eq!(
        records,
        vec![
            NotifyRecord {
                action: 1,
                name: r"app-1.0.9164\Discord.exe".into()
            },
            NotifyRecord {
                action: 5,
                name: "Ünïcødé.exe".into()
            },
        ]
    );
    assert!(notify_buffer_is_relevant(&buffer));
}

#[test]
fn a_record_running_past_the_buffer_ends_the_walk() {
    let mut buffer = record(1, "tool.exe", false);
    buffer.extend(record(1, "second.exe", true));
    buffer.truncate(buffer.len() - 6);
    assert_eq!(notify_records(&buffer).len(), 1);
    // A name length past the end, and an offset that wraps.
    let mut lying = record(1, "x.exe", true);
    lying[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(notify_records(&lying).is_empty());
    let mut wrapping = record(1, "x.exe", false);
    wrapping[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(notify_records(&wrapping).len(), 1);
    assert!(notify_records(&[0u8; 11]).is_empty());
}

#[test]
fn a_log_rewritten_in_place_is_not_a_change_and_an_overflow_is() {
    let log = record(3, r"logs\app.log", true);
    assert!(!notify_buffer_is_relevant(&log));
    let added_log = record(1, "app.log", true);
    assert!(!notify_buffer_is_relevant(&added_log));
    let written_exe = record(3, "tool.exe", true);
    assert!(notify_buffer_is_relevant(&written_exe));
    let new_folder = record(1, "app-1.0.9165", true);
    assert!(notify_buffer_is_relevant(&new_folder));
    assert!(notify_buffer_is_relevant(&[]), "an overflow says nothing");
    assert!(
        notify_buffer_is_relevant(&[1, 2, 3]),
        "nor does a broken one"
    );
}

#[test]
fn a_hostile_buffer_never_panics() {
    let mut buffer = Vec::new();
    for i in 0..64u8 {
        buffer.push(i.wrapping_mul(37));
        let _ = notify_records(&buffer);
        let _ = notify_buffer_is_relevant(&buffer);
    }
    // A chain that points one byte forward each time stays bounded.
    let mut crawl = vec![0u8; 4096];
    for chunk in crawl.chunks_mut(4) {
        chunk.copy_from_slice(&1u32.to_le_bytes());
    }
    assert!(notify_records(&crawl).len() <= MAX_NOTIFY_RECORDS);
}
