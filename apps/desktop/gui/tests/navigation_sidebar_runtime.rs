use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn runner() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("NRR_QMLTESTRUNNER") {
        return Some(PathBuf::from(path));
    }
    let executable = if cfg!(windows) {
        "qmltestrunner.exe"
    } else {
        "qmltestrunner"
    };
    let mut directories: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).collect())
        .unwrap_or_default();
    if let Some(prefixes) = std::env::var_os("CMAKE_PREFIX_PATH") {
        directories.extend(std::env::split_paths(&prefixes).map(|path| path.join("bin")));
    }
    directories.push(PathBuf::from("/usr/lib/qt6/bin"));
    directories
        .into_iter()
        .map(|directory| directory.join(executable))
        .find(|path| path.is_file())
}

fn file_url(path: &Path) -> String {
    let path = path.to_string_lossy();
    let path = path
        .strip_prefix("\\\\?\\")
        .unwrap_or(&path)
        .replace('\\', "/");
    format!(
        "file://{}{path}",
        if path.starts_with('/') { "" } else { "/" }
    )
}

#[test]
fn every_sidebar_submenu_keeps_a_hit_rectangle_and_accepts_mouse_and_space() {
    let Some(runner) = runner() else {
        assert!(
            std::env::var_os("NRR_REQUIRE_QT_TESTS").is_none(),
            "Qt runtime tests are required; set NRR_QMLTESTRUNNER or provide the Qt SDK on PATH/CMAKE_PREFIX_PATH"
        );
        eprintln!("Qt SDK absent: skipping real sidebar input tests (NRR_REQUIRE_QT_TESTS makes this an error)");
        return;
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap_or_else(|error| panic!("resolve checkout: {error}"));
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let scratch = std::env::temp_dir().join(format!("nrr-sidebar-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&scratch)
        .unwrap_or_else(|error| panic!("create test directory: {error}"));
    let locale: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("locales/ru.json"))
            .unwrap_or_else(|error| panic!("read Russian locale: {error}")),
    )
    .unwrap_or_else(|error| panic!("parse Russian locale: {error}"));
    for mode in ["light", "dark"] {
        for scale in [100, 160] {
            let case = scratch.join(format!("{mode}-{scale}"));
            std::fs::create_dir_all(&case).unwrap_or_else(|error| panic!("create case: {error}"));
            let settings = serde_json::json!({
                "mode": mode, "scale": scale, "locale": locale,
                "assets": file_url(&root.join("assets")),
                "output": case.join("capture").to_string_lossy().replace('\\', "/"),
            });
            let mut fixture = include_str!("qml/tst_navigation.qml").replace(
                "property var testSettings: ({})",
                &format!("property var testSettings: ({settings})"),
            );
            for directory in ["components", "theme"] {
                fixture = fixture.replace(
                    &format!("\"../../../qml/{directory}\""),
                    &format!(
                        "\"{}\"",
                        file_url(&root.join("apps/desktop/qml").join(directory))
                    ),
                );
            }
            std::fs::write(case.join("tst_navigation.qml"), fixture)
                .unwrap_or_else(|error| panic!("write fixture: {error}"));
            let output = case.join("runner.log");
            let log = std::fs::File::create(&output)
                .unwrap_or_else(|error| panic!("create log: {error}"));
            let errors = log
                .try_clone()
                .unwrap_or_else(|error| panic!("clone log handle: {error}"));
            let mut command = Command::new(&runner);
            command
                .arg("-input")
                .arg(&case)
                .env("QT_QPA_PLATFORM", "offscreen")
                .env("QT_QUICK_BACKEND", "software")
                .env("QT_QUICK_CONTROLS_STYLE", "Fusion")
                .stdout(Stdio::from(log))
                .stderr(Stdio::from(errors));
            if cfg!(windows) {
                if let Some(windows) = std::env::var_os("WINDIR") {
                    command.env("QT_QPA_FONTDIR", PathBuf::from(windows).join("Fonts"));
                }
            }
            let mut child = command
                .spawn()
                .unwrap_or_else(|error| panic!("launch {}: {error}", runner.display()));
            let deadline = Instant::now() + Duration::from_secs(30);
            let status = loop {
                if let Some(status) = child
                    .try_wait()
                    .unwrap_or_else(|error| panic!("wait for Qt: {error}"))
                {
                    break status;
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("Qt sidebar test timed out; evidence: {}", case.display());
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            assert!(
                status.success(),
                "{mode}/{scale}% sidebar regression failed; evidence {}:\n{}",
                case.display(),
                std::fs::read_to_string(&output).unwrap_or_default()
            );
        }
    }
    std::fs::remove_dir_all(&scratch)
        .unwrap_or_else(|error| panic!("remove test artifacts: {error}"));
}
