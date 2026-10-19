use super::*;

const WIN: PathStyle = PathStyle::Windows;
const LINUX: PathStyle = PathStyle::Linux;

fn win(line: &str, cwd: Option<&str>) -> ProcessLaunch {
    ProcessLaunch {
        args: split_windows_command_line(line),
        raw: Some(line.to_string()),
        cwd: cwd.map(str::to_string),
    }
}

fn unix(args: &[&str], cwd: Option<&str>) -> ProcessLaunch {
    ProcessLaunch {
        args: args.iter().map(|a| (*a).to_string()).collect(),
        raw: None,
        cwd: cwd.map(str::to_string),
    }
}

fn files(reading: &LaunchReading) -> Vec<Launched> {
    reading.files.iter().map(|f| f.target.clone()).collect()
}

fn file(path: &str) -> Launched {
    Launched::File(path.to_string())
}

fn folder(path: &str) -> Launched {
    Launched::FilesIn(path.to_string())
}

// ── The Windows command line ─────────────────────────────────────────────────

#[test]
fn quoted_paths_with_spaces_split_whole() {
    assert_eq!(
        split_windows_command_line(
            r#""C:\Program Files\Python\python.exe" -u "C:\My Tools\run.py""#
        ),
        vec![
            r"C:\Program Files\Python\python.exe",
            "-u",
            r"C:\My Tools\run.py"
        ]
    );
}

#[test]
fn backslashes_escape_only_before_a_quote() {
    // Three backslashes and a quote: one backslash and a literal quote.
    assert_eq!(
        split_windows_command_line(r#"prog a\\\"b c"#),
        vec!["prog", r#"a\"b"#, "c"]
    );
    // Two and a quote: one backslash, and the quote closes the quoting.
    assert_eq!(
        split_windows_command_line(r#"prog "a\\" b"#),
        vec!["prog", r"a\", "b"]
    );
    // No quote after them: every backslash stays.
    assert_eq!(
        split_windows_command_line(r"prog a\b\\c"),
        vec!["prog", r"a\b\\c"]
    );
}

#[test]
fn two_quotes_inside_quotes_are_one_literal_quote() {
    assert_eq!(
        split_windows_command_line(r#"prog "a""b""#),
        vec!["prog", r#"a"b"#]
    );
    assert_eq!(split_windows_command_line(r#"prog """#), vec!["prog", ""]);
    assert_eq!(
        split_windows_command_line(r#"prog "" x"#),
        vec!["prog", "", "x"]
    );
}

#[test]
fn the_program_name_has_quotes_but_no_escapes() {
    assert_eq!(
        split_windows_command_line(r#""C:\x y\p.exe"z q"#),
        vec![r"C:\x y\p.exez", "q"]
    );
    assert_eq!(
        split_windows_command_line(r#"C:\a\"b c"#),
        vec![r"C:\a\b c"]
    );
    assert_eq!(split_windows_command_line(""), vec![""]);
    assert_eq!(
        split_windows_command_line("prog   x \t "),
        vec!["prog", "x"]
    );
}

#[test]
fn unicode_survives_the_split() {
    assert_eq!(
        split_windows_command_line(r#"python "C:\Пользователи\я\скрипт.py" ✓"#),
        vec!["python", r"C:\Пользователи\я\скрипт.py", "✓"]
    );
}

#[test]
fn a_huge_command_line_is_read_within_its_bounds() {
    let many = format!("prog{}", " a".repeat(10_000));
    assert_eq!(split_windows_command_line(&many).len(), MAX_ARGUMENTS);
    let long = format!("prog \"{}", "é".repeat(MAX_COMMAND_LINE_BYTES));
    let args = split_windows_command_line(&long);
    assert!(args.iter().map(String::len).sum::<usize>() <= MAX_COMMAND_LINE_BYTES);
    let slashes = format!("prog {}\"", "\\".repeat(100_000));
    assert!(split_windows_command_line(&slashes).len() <= 2);
}

// ── Linux and macOS forms ────────────────────────────────────────────────────

#[test]
fn nul_separated_arguments_split_and_stay_bounded() {
    assert_eq!(
        split_nul_args(b"python3\0/opt/app/x.py\0"),
        vec!["python3", "/opt/app/x.py"]
    );
    assert_eq!(split_nul_args(b"one"), vec!["one"]);
    assert!(split_nul_args(b"").is_empty());
    assert_eq!(split_nul_args(b"a\0\0b\0"), vec!["a", "", "b"]);
    assert_eq!(split_nul_args(b"\xff\xfe\0"), vec!["\u{FFFD}\u{FFFD}"]);
    let many = b"a\0".repeat(10_000);
    assert_eq!(split_nul_args(&many).len(), MAX_ARGUMENTS);
}

#[test]
fn an_environment_value_is_found_by_its_exact_name() {
    let block = b"PATH=/bin\0CLASSPATHX=no\0CLASSPATH=/opt/a/*:/b\0";
    assert_eq!(
        environ_value(block, "CLASSPATH").as_deref(),
        Some("/opt/a/*:/b")
    );
    assert_eq!(environ_value(block, "HOME"), None);
    assert_eq!(environ_value(b"", "CLASSPATH"), None);
}

#[test]
fn a_procargs2_buffer_gives_its_arguments_and_environment() {
    let mut buffer = 2i32.to_ne_bytes().to_vec();
    buffer.extend_from_slice(
        b"/usr/bin/python3\0\0\0\0python3\0/Applications/X.app/run.py\0HOME=/x\0",
    );
    let (args, environ) = split_procargs2(&buffer);
    assert_eq!(args, vec!["python3", "/Applications/X.app/run.py"]);
    assert_eq!(environ_value(environ, "HOME").as_deref(), Some("/x"));

    let mut negative = (-5i32).to_ne_bytes().to_vec();
    negative.extend_from_slice(b"/bin/x\0a\0");
    assert!(split_procargs2(&negative).0.is_empty());
    assert!(split_procargs2(b"\x01\0").0.is_empty());
    let mut no_path_end = 1i32.to_ne_bytes().to_vec();
    no_path_end.extend_from_slice(b"/bin/x");
    assert!(split_procargs2(&no_path_end).0.is_empty());
}

// ── The script position ──────────────────────────────────────────────────────

#[test]
fn an_interpreter_option_before_the_script_is_skipped() {
    let reading = read_launch(
        &win("python -u script.py --verbose", Some(r"C:\Tools")),
        WIN,
    );
    assert_eq!(files(&reading), vec![file(r"C:\Tools\script.py")]);
    assert_eq!(reading.files[0].evidence, LaunchEvidence::ScriptExtension);

    let reading = read_launch(&win(r"python -W ignore C:\Tools\x.py", None), WIN);
    assert_eq!(files(&reading), vec![file(r"C:\Tools\x.py")]);
}

#[test]
fn powershell_runs_the_file_after_its_options() {
    let reading = read_launch(&win("powershell -File x.ps1", Some(r"C:\Tools")), WIN);
    assert_eq!(files(&reading), vec![file(r"C:\Tools\x.ps1")]);
    let reading = read_launch(
        &win(
            r#"powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\My Tools\x.ps1""#,
            None,
        ),
        WIN,
    );
    assert_eq!(files(&reading), vec![file(r"C:\My Tools\x.ps1")]);
    let reading = read_launch(
        &win(r"powershell -exec bypass -file .\x.ps1", Some(r"C:\Tools\")),
        WIN,
    );
    assert_eq!(files(&reading), vec![file(r"C:\Tools\x.ps1")]);
}

/// "Run with PowerShell" hands the script over as the last statement of a
/// command, `& 'path'`; that form alone of a command string names a script.
#[test]
fn a_command_ending_in_a_call_of_a_script_runs_that_script() {
    let explorer = r#""C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "-Command" "if((Get-ExecutionPolicy ) -ne 'AllSigned') { Set-ExecutionPolicy -Scope Process Bypass }; & 'C:\My Tools\x.ps1'""#;
    for (line, expected) in [
        (explorer, r"C:\My Tools\x.ps1"),
        (r"powershell -Command & 'C:\Tools\x.ps1'", r"C:\Tools\x.ps1"),
        (r#"pwsh -c "& \"C:\Tools\y.ps1\" ;  ""#, r"C:\Tools\y.ps1"),
        (
            r#"powershell -Command "& 'C:\Tools\it''s.ps1'""#,
            r"C:\Tools\it's.ps1",
        ),
        (r#"powershell -com "& '.\z.ps1'""#, r"C:\Tools\z.ps1"),
    ] {
        let reading = read_launch(&win(line, Some(r"C:\Tools")), WIN);
        assert_eq!(files(&reading), vec![file(expected)], "{line}");
    }
    // A command that names no script runs none, and bash's `-c` is code.
    let reading = read_launch(
        &unix(
            &["bash", "-c", "cat /opt/x/a.sh", "/opt/x/b.sh"],
            Some("/opt/x"),
        ),
        LINUX,
    );
    assert!(reading.files.is_empty());
    assert_eq!(called_script("  ;  "), None);
    assert_eq!(called_script("& ''"), Some(String::new()));
    assert_eq!(called_script(&"& '".repeat(50_000)), None);
}

#[test]
fn a_command_string_runs_no_file_it_mentions() {
    for line in [
        r#"powershell -Command "Get-Date; & 'C:\Tools\x.ps1'; rm C:\Tools\log""#,
        r#"powershell -Command "Get-Content C:\Tools\x.ps1""#,
        r#"powershell -Command "& 'C:\Tools\x.ps1' -Force""#,
        r#"powershell -Command "& \"$env:TOOLS\x.ps1\"""#,
        r#"powershell -Command "Write-Output 'a & b'""#,
        r#"powershell -Command "Get-Item x && & 'C:\Tools\x.ps1'""#,
        r#"pwsh -c "C:\Tools\x.ps1""#,
        r"powershell -EncodedCommand ZQBjAGgAbwA=",
        r#"python -c "import runpy" C:\Tools\x.py"#,
        r"python -m http.server",
    ] {
        assert!(
            read_launch(&win(line, Some(r"C:\Tools")), WIN)
                .files
                .is_empty(),
            "{line}"
        );
    }
    for args in [
        &["bash", "-c", "cat /opt/x/a.sh", "/opt/x/b.sh"][..],
        &["bash", "-lc", "/opt/x/run.sh"][..],
        &["perl", "-e", "print 1", "/opt/x/a.pl"][..],
        &["node", "-e", "1", "/opt/x/a.js"][..],
    ] {
        assert!(
            read_launch(&unix(args, Some("/opt/x")), LINUX)
                .files
                .is_empty(),
            "{args:?}"
        );
    }
}

#[test]
fn cmd_runs_the_program_of_its_command_string() {
    let reading = read_launch(&win("cmd /c x.bat", Some(r"C:\Tools")), WIN);
    assert_eq!(files(&reading), vec![file(r"C:\Tools\x.bat")]);
    // How Explorer starts a batch file whose path has a space in it.
    let reading = read_launch(
        &win(
            r#"C:\Windows\system32\cmd.exe /c ""C:\My Tools\x.bat" ""#,
            None,
        ),
        WIN,
    );
    assert_eq!(files(&reading), vec![file(r"C:\My Tools\x.bat")]);
    let reading = read_launch(&win(r#"cmd /d /c "C:\Tools\x.cmd" arg"#, None), WIN);
    assert_eq!(files(&reading), vec![file(r"C:\Tools\x.cmd")]);
    let reading = read_launch(&win(r#"cmd /c "C:\My Tools\x.bat""#, None), WIN);
    assert_eq!(files(&reading), vec![file(r"C:\My Tools\x.bat")]);
    // A program by plain name is found on the search path, not here.
    assert!(read_launch(&win("cmd /c dir", Some(r"C:\Tools")), WIN)
        .files
        .is_empty());
    // Without the raw line the next argument stands in.
    let split = ProcessLaunch {
        args: vec!["cmd".into(), "/c".into(), r"C:\Tools\x.bat".into()],
        raw: None,
        cwd: None,
    };
    assert_eq!(
        files(&read_launch(&split, WIN)),
        vec![file(r"C:\Tools\x.bat")]
    );
}

#[test]
fn windows_script_hosts_run_their_file() {
    for (line, expected) in [
        ("wscript x.vbs", r"C:\Tools\x.vbs"),
        (
            r"wscript.exe //B //Nologo C:\Tools\y.vbs",
            r"C:\Tools\y.vbs",
        ),
        (r#"cscript //nologo "C:\Tools\z.wsf""#, r"C:\Tools\z.wsf"),
        (
            r#"mshta.exe "C:\Tools\x.hta" {1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}"#,
            r"C:\Tools\x.hta",
        ),
        (
            r#""C:\Python\pythonw.exe" "C:\Tools\gui.pyw""#,
            r"C:\Tools\gui.pyw",
        ),
        ("node server.js", r"C:\Tools\server.js"),
    ] {
        let reading = read_launch(&win(line, Some(r"C:\Tools")), WIN);
        assert_eq!(files(&reading), vec![file(expected)], "{line}");
    }
}

#[test]
fn java_runs_its_jar_or_its_class_path() {
    let reading = read_launch(
        &win("java -Xmx1g -jar x.jar --port 1", Some(r"C:\Tools")),
        WIN,
    );
    assert_eq!(files(&reading), vec![file(r"C:\Tools\x.jar")]);
    assert_eq!(reading.files[0].evidence, LaunchEvidence::JavaOption);

    let reading = read_launch(
        &win(r"java -cp a;C:\lib\*;C:\app\app.jar Main", Some(r"C:\app")),
        WIN,
    );
    assert_eq!(
        files(&reading),
        vec![
            folder(r"C:\app\a"),
            folder(r"C:\lib"),
            file(r"C:\app\app.jar")
        ]
    );
    assert!(!reading.wants_class_path);

    let cassandra = [
        "java",
        "-ea",
        "-Xss256k",
        "-cp",
        "/etc/cassandra:/usr/share/cassandra/lib/*:/opt/cassandra/build/classes",
        "-Dcassandra.storagedir=/var/lib/cassandra",
        "org.apache.cassandra.service.CassandraDaemon",
    ];
    let reading = read_launch(&unix(&cassandra, None), LINUX);
    assert_eq!(
        files(&reading),
        vec![
            folder("/etc/cassandra"),
            folder("/usr/share/cassandra/lib"),
            folder("/opt/cassandra/build/classes"),
        ]
    );
    let reading = read_launch(
        &unix(&["java", "--class-path=/opt/app/lib/*", "app.Main"], None),
        LINUX,
    );
    assert_eq!(files(&reading), vec![folder("/opt/app/lib")]);
}

#[test]
fn a_main_class_without_a_class_path_asks_for_the_environment() {
    let reading = read_launch(&unix(&["java", "-Xmx1g", "org.example.Main"], None), LINUX);
    assert!(reading.files.is_empty());
    assert!(reading.wants_class_path);
    let reading = read_launch(&unix(&["java", "Main"], None), LINUX);
    assert!(reading.wants_class_path);
    let reading = read_launch(&unix(&["java", "-cp", "/opt/a", "Main"], None), LINUX);
    assert!(!reading.wants_class_path);
    // A plain lower-case word is no class.
    assert!(!read_launch(&unix(&["tool", "fetch"], None), LINUX).wants_class_path);
}

#[test]
fn class_path_entries_are_bounded() {
    let value = vec!["/opt/a.jar"; 2000].join(":");
    assert_eq!(
        class_path_files(&value, LINUX, None).len(),
        MAX_CLASS_PATH_ENTRIES
    );
    assert!(class_path_files("relative.jar", LINUX, None).is_empty());
    assert_eq!(
        class_path_files("*", LINUX, Some("/opt/app")),
        vec![LaunchedFile {
            target: folder("/opt/app"),
            evidence: LaunchEvidence::JavaOption
        }]
    );
}

#[test]
fn unix_interpreters_run_their_file() {
    for (args, cwd, expected, evidence) in [
        (
            &["/bin/bash", "./run.sh"][..],
            "/opt/app",
            "/opt/app/run.sh",
            LaunchEvidence::ScriptExtension,
        ),
        (
            &["zsh", "x.zsh"][..],
            "/opt/app",
            "/opt/app/x.zsh",
            LaunchEvidence::ScriptExtension,
        ),
        (
            &["perl", "-w", "x.pl"][..],
            "/opt/app",
            "/opt/app/x.pl",
            LaunchEvidence::ScriptExtension,
        ),
        (
            &["Rscript", "--vanilla", "x.R"][..],
            "/opt/app",
            "/opt/app/x.R",
            LaunchEvidence::ScriptExtension,
        ),
        (
            &["python3", "./tool"][..],
            "/opt/app",
            "/opt/app/tool",
            LaunchEvidence::RunsByItself,
        ),
        (
            &["php", "artisan", "serve"][..],
            "/var/www/site",
            "/var/www/site/artisan",
            LaunchEvidence::RunsByItself,
        ),
        (
            &["/bin/sh", "-x", "/opt/cassandra/bin/cassandra", "-f"][..],
            "/",
            "/opt/cassandra/bin/cassandra",
            LaunchEvidence::RunsByItself,
        ),
        (
            &["python3", "../other/x.py"][..],
            "/opt/app",
            "/opt/other/x.py",
            LaunchEvidence::ScriptExtension,
        ),
    ] {
        let reading = read_launch(&unix(args, Some(cwd)), LINUX);
        assert_eq!(
            reading.files,
            vec![LaunchedFile {
                target: file(expected),
                evidence
            }],
            "{args:?}"
        );
    }
}

#[test]
fn only_the_first_positional_argument_is_the_script() {
    let reading = read_launch(
        &unix(&["python3", "/usr/lib/tool.py", "/opt/app/data.py"], None),
        LINUX,
    );
    assert_eq!(files(&reading), vec![file("/usr/lib/tool.py")]);
    // A path after an option is taken as the script, not skipped as a value.
    let reading = read_launch(
        &unix(&["bash", "-x", "/usr/bin/helper", "/opt/app/x.sh"], None),
        LINUX,
    );
    assert_eq!(files(&reading), vec![file("/usr/bin/helper")]);
}

#[test]
fn a_relative_script_needs_the_working_folder_and_stays_inside_its_root() {
    assert!(read_launch(&unix(&["python3", "x.py"], None), LINUX)
        .files
        .is_empty());
    assert!(read_launch(
        &unix(&["python3", "../../../../x.py"], Some("/opt/app")),
        LINUX
    )
    .files
    .is_empty());
    let reading = read_launch(&win(r"python \x.py", Some(r"C:\Tools\")), WIN);
    assert_eq!(files(&reading), vec![file(r"C:\x.py")]);
    assert!(read_launch(&win("python C:x.py", Some(r"C:\Tools")), WIN)
        .files
        .is_empty());
    let reading = read_launch(&win(r"python \\srv\share\x.py", None), WIN);
    assert_eq!(files(&reading), vec![file(r"\\srv\share\x.py")]);
    let reading = read_launch(&win(r"python ..\x.py", Some(r"C:\Tools\sub")), WIN);
    assert_eq!(files(&reading), vec![file(r"C:\Tools\x.py")]);
}

/// The list is compared with a lower-cased stem: an entry spelled any other
/// way would never match.
#[test]
fn the_file_opener_list_is_spelled_as_it_is_compared() {
    for name in OPENS_FILES_IT_NAMES {
        assert_eq!(*name, name.to_ascii_lowercase(), "{name}");
        assert!(!name.contains('.') && !name.contains(['/', '\\']), "{name}");
        assert!(opens_files_it_names(name), "{name}");
        assert!(
            opens_files_it_names(&format!(r"C:\Program Files\x\{name}.exe")),
            "{name}"
        );
    }
}

#[test]
fn editors_and_copy_tools_open_the_files_they_name() {
    for image in [
        r"C:\Windows\System32\notepad.exe",
        r"C:\Program Files\Microsoft VS Code\Code.exe",
        "/usr/bin/vim.basic",
        "/usr/bin/nvim",
        "/usr/bin/scp",
        "nano",
    ] {
        assert!(opens_files_it_names(image), "{image}");
    }
    for image in [
        "/usr/bin/python3.11",
        r"C:\Windows\System32\cmd.exe",
        "java",
        "bash",
    ] {
        assert!(!opens_files_it_names(image), "{image}");
    }
}

#[test]
fn hostile_command_lines_never_panic() {
    let inputs = [
        "",
        "\"",
        "\\",
        "\"\\\"",
        "a /c",
        "a /c \"",
        "a /c \"\"\"",
        "a -jar",
        "a -cp",
        "a --class-path=",
        "a -- ",
        "a \u{0} b",
        "a \u{10FFFF}.py",
        "a ..\\..\\..\\x.py",
        "a \\\\",
        "a \\\\srv",
        "a C:",
        "a ::.py",
        "a ////x.py",
    ];
    for line in inputs {
        for cwd in [
            None,
            Some(""),
            Some("C:"),
            Some(r"\\srv\s"),
            Some("/"),
            Some("relative"),
        ] {
            let launch = win(line, cwd);
            let _ = read_launch(&launch, WIN);
            let _ = read_launch(&launch, LINUX);
            let _ = read_launch(&launch, PathStyle::MacOS);
        }
        let _ = split_nul_args(line.as_bytes());
        let _ = split_procargs2(line.as_bytes());
        let _ = class_path_files(line, WIN, Some(r"C:\x"));
        let _ = class_path_files(line, LINUX, Some("/x"));
    }
}
