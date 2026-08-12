#![allow(clippy::expect_used)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let native_dir = manifest_dir.join("native");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let build_dir = out_dir.join("qt-native-host-build");
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    // Cargo's dev profile used to mean a Debug C++ host, which links the DEBUG
    // Qt libraries and leaves `Q_ASSERT` live. Qt's window-update bookkeeping
    // assertion then ABORTS the tray process over a state release Qt tolerates
    // — a crash no user can reach, because shipped builds are release, and one
    // that cost four rounds of chasing. Dev builds get RelWithDebInfo: no
    // asserts, symbols kept, same Qt libraries the user runs.
    // `NRR_QT_HOST_BUILD_TYPE=Debug` puts the assertions back when the C++
    // itself is what needs debugging.
    let config = env::var("NRR_QT_HOST_BUILD_TYPE").unwrap_or_else(|_| {
        if profile.eq_ignore_ascii_case("release") {
            "Release".to_string()
        } else {
            "RelWithDebInfo".to_string()
        }
    });
    let qt_prefix = env::var("CMAKE_PREFIX_PATH")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(default_qt_prefix);

    // CMake caches the found Qt (`Qt6_DIR` etc.) inside the build dir, and a
    // later `-DCMAKE_PREFIX_PATH=<new>` does NOT invalidate that cache — a Qt
    // upgrade would silently keep linking the old version. Stamp the prefix
    // and wipe the build dir when it changes.
    let stamp = out_dir.join("qt-prefix.stamp");
    let previous = fs::read_to_string(&stamp).unwrap_or_default();
    if previous != qt_prefix {
        if build_dir.exists() {
            fs::remove_dir_all(&build_dir).expect("remove stale CMake build dir");
        }
        fs::write(&stamp, &qt_prefix).expect("write qt prefix stamp");
    }

    println!("cargo:rerun-if-changed={}", native_dir.display());
    // A directory-level `rerun-if-changed` only tracks the directory entry's
    // own mtime, which (on Windows) does NOT change when a file *inside* it is
    // edited in place. So edits to the resource template / CMake / C++ source
    // were silently not picked up. Track the load-bearing files explicitly.
    for rel in ["resources/app.rc.in", "CMakeLists.txt", "src/main.cpp"] {
        println!("cargo:rerun-if-changed={}", native_dir.join(rel).display());
    }
    println!("cargo:rerun-if-env-changed=CMAKE_PREFIX_PATH");
    println!("cargo:rerun-if-env-changed=NRR_QT_HOST_GENERATOR");
    println!("cargo:rerun-if-env-changed=NRR_QT_HOST_BUILD_TYPE");
    println!("cargo:rerun-if-env-changed=NRR_SKIP_QT_HOST");

    let executable = build_dir.join(&config).join(exe_name("nrr_qt_native_host"));

    // Machines without Qt (CI runners) still get the Rust gate: clippy and the
    // test suite run, the C++ host is not built. The baked path then names a
    // file that was never produced — the launcher's own missing-host check
    // reports that at startup, which is the honest outcome for such a build.
    if env::var("NRR_SKIP_QT_HOST")
        .map(|value| value != "0")
        .unwrap_or(false)
    {
        println!(
            "cargo:warning=NRR_SKIP_QT_HOST is set: the C++ Qt host was not built, \
             so the produced binaries cannot open a window"
        );
        println!(
            "cargo:rustc-env=NRR_QT_NATIVE_HOST_EXE={}",
            executable.display()
        );
        return;
    }

    run(
        Command::new("cmake")
            .arg("-S")
            .arg(&native_dir)
            .arg("-B")
            .arg(&build_dir)
            .arg("-G")
            .arg(
                env::var("NRR_QT_HOST_GENERATOR")
                    .unwrap_or_else(|_| "Visual Studio 17 2022".to_string()),
            )
            .arg("-A")
            .arg("x64")
            .arg(format!("-DCMAKE_PREFIX_PATH={qt_prefix}")),
        "configure native Qt host",
    );

    run(
        Command::new("cmake")
            .arg("--build")
            .arg(&build_dir)
            .arg("--config")
            .arg(&config)
            .arg("--target")
            .arg("nrr_qt_native_host"),
        "build native Qt host",
    );

    if !executable.exists() {
        panic!(
            "native Qt host executable was not produced at '{}'",
            executable.display()
        );
    }

    // The `NetRuleRouter.exe` and `NetRuleRouterTray.exe` names are owned by
    // the Rust orchestrator crates (`nrr-desktop-gui` and `nrr-desktop-tray`
    // via their `[[bin]]` entries). Don't copy the bare native host under
    // those names — it would collide with the Rust outputs in
    // `target/<profile>/`. The native host stays as `nrr_qt_native_host.exe`
    // in the CMake build dir and is exposed via the `NRR_QT_NATIVE_HOST_EXE`
    // env var below.
    let _unused_out_dir = &out_dir;
    let _unused_profile = &profile;

    println!(
        "cargo:rustc-env=NRR_QT_NATIVE_HOST_EXE={}",
        executable.display()
    );
}

fn run(command: &mut Command, step: &str) {
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("failed to {step}: {error}"));
    if !status.success() {
        panic!("{step} failed with status {status}");
    }
}

/// Pick the newest Qt under `C:\Qt\<X.Y.Z>\msvc2022_64` when
/// `CMAKE_PREFIX_PATH` is not set. Version directories sort numerically
/// (so 6.11.1 beats 6.9.2 despite the string order).
fn default_qt_prefix() -> String {
    let root = Path::new("C:/Qt");
    let mut best: Option<(Vec<u64>, PathBuf)> = None;
    for entry in root.read_dir().into_iter().flatten().flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let version: Vec<u64> = name.split('.').filter_map(|p| p.parse().ok()).collect();
        if version.len() != 3 {
            continue; // Tools/Docs/dist and other non-version entries
        }
        let cmake = entry.path().join("msvc2022_64/lib/cmake");
        if cmake.exists() && best.as_ref().is_none_or(|(v, _)| version > *v) {
            best = Some((version, cmake));
        }
    }
    match best {
        Some((_, cmake)) => cmake.display().to_string(),
        None => panic!(
            "CMAKE_PREFIX_PATH is not set and no Qt with an msvc2022_64 kit was found under C:\\Qt"
        ),
    }
}

fn exe_name(base: &str) -> String {
    if cfg!(windows) {
        format!("{base}.exe")
    } else {
        base.to_string()
    }
}

// Reserved for future use: copy the native Qt host alongside the launcher
// binaries instead of relying on the `NATIVE_HOST_EXE` const fallback. Kept
// dead so the helper stays available without altering the build graph.
#[allow(dead_code)]
fn copy_native_product_executable(
    out_dir: &Path,
    profile: &str,
    native_executable: &Path,
    product_name: &str,
) -> PathBuf {
    let Some(profile_dir) = out_dir
        .ancestors()
        .find(|ancestor| ancestor.file_name().is_some_and(|name| name == profile))
    else {
        panic!(
            "failed to locate target profile directory from OUT_DIR '{}'",
            out_dir.display()
        );
    };

    let destination = profile_dir.join(exe_name(product_name));
    match fs::copy(native_executable, &destination) {
        Ok(_) => {}
        Err(error)
            if error.kind() == std::io::ErrorKind::PermissionDenied && destination.exists() =>
        {
            println!(
                "cargo:warning=skipping refresh of '{}' because the file is currently in use",
                destination.display()
            );
        }
        Err(error) => {
            panic!(
                "failed to copy native Qt host '{}' to '{}': {error}",
                native_executable.display(),
                destination.display()
            )
        }
    }
    destination
}
