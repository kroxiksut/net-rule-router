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
    println!("cargo:rerun-if-changed={}", native_dir.display());
    // A directory-level `rerun-if-changed` only tracks the directory entry's
    // own mtime, which (on Windows) does NOT change when a file *inside* it is
    // edited in place. So edits to the resource template / CMake / C++ source
    // were silently not picked up. Track the load-bearing files explicitly.
    println!(
        "cargo:rerun-if-changed={}",
        native_dir.join("CMakeLists.txt").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir
            .join("../../../packaging/windows/app.rc.in")
            .display()
    );
    if let Ok(entries) = std::fs::read_dir(native_dir.join("src")) {
        for entry in entries.flatten() {
            println!("cargo:rerun-if-changed={}", entry.path().display());
        }
    }
    println!("cargo:rerun-if-env-changed=CMAKE_PREFIX_PATH");
    println!("cargo:rerun-if-env-changed=QT_HOST_PATH");
    println!("cargo:rerun-if-env-changed=NRR_QT_HOST_GENERATOR");
    println!("cargo:rerun-if-env-changed=CMAKE_GENERATOR");
    println!("cargo:rerun-if-env-changed=NRR_QT_HOST_BUILD_TYPE");
    println!("cargo:rerun-if-env-changed=NRR_SKIP_QT_HOST");

    let executable = build_dir.join(&config).join(exe_name("nrr_qt_native_host"));

    // Machines without Qt (CI runners) still get the Rust gate: clippy and the
    // test suite run, the C++ host is not built. The baked path then names a
    // file that was never produced — the launcher's own missing-host check
    // reports that at startup, which is the honest outcome for such a build.
    //
    // Asked BEFORE the Qt prefix is resolved: resolving it is itself what fails
    // on a machine with no Qt, so a switch consulted afterwards can never be
    // reached by the builds it exists for.
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

    // The host links the launcher's target, not the build machine: an ARM64
    // build on x64 needs the ARM64 kit and the ARM64 compiler.
    let msvc = MsvcTarget::from_cargo();
    // Windows has no system Qt, so a prefix must be found or the configure step
    // fails with an unhelpful message. On Linux the distribution's Qt6 is where
    // CMake already looks, so an unset prefix is the normal case and passing an
    // empty one would only override a working search.
    let qt_prefix = env::var("CMAKE_PREFIX_PATH")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| cfg!(windows).then(|| default_qt_prefix(msvc)))
        .unwrap_or_default();
    // A cross-compiled kit runs moc and rcc from a kit for the build machine.
    let qt_host_path = env::var("QT_HOST_PATH")
        .ok()
        .filter(|value| !value.trim().is_empty());

    // CMake caches the found Qt (`Qt6_DIR` etc.) inside the build dir, and a
    // later `-DCMAKE_PREFIX_PATH=<new>` does NOT invalidate that cache — a Qt
    // upgrade would silently keep linking the old version. Stamp the prefix
    // and wipe the build dir when it changes.
    let stamp = out_dir.join("qt-prefix.stamp");
    let stamp_value = match &qt_host_path {
        Some(host) => format!("{qt_prefix}\n{host}"),
        None => qt_prefix.clone(),
    };
    let previous = fs::read_to_string(&stamp).unwrap_or_default();
    if previous != stamp_value {
        if build_dir.exists() {
            fs::remove_dir_all(&build_dir).expect("remove stale CMake build dir");
        }
        fs::write(&stamp, &stamp_value).expect("write qt prefix stamp");
    }

    let mut configure = Command::new("cmake");
    configure
        .arg("-S")
        .arg(&native_dir)
        .arg("-B")
        .arg(&build_dir);
    match env::var("NRR_QT_HOST_GENERATOR") {
        Ok(generator) => {
            configure.arg("-G").arg(generator);
        }
        // CMake's default on Windows is the newest Visual Studio it finds, a
        // multi-config generator, hence the architecture argument and the
        // per-config output directory below. Naming one version breaks on a
        // machine that carries only a newer one. Elsewhere CMake's own default
        // (Unix Makefiles / Ninja) is right.
        Err(_) if cfg!(windows) && env::var_os("CMAKE_GENERATOR").is_none() => {
            configure.arg("-A").arg(msvc.platform);
        }
        Err(_) => {}
    }
    if !qt_prefix.is_empty() {
        configure.arg(format!("-DCMAKE_PREFIX_PATH={qt_prefix}"));
    }
    if let Some(host) = &qt_host_path {
        configure.arg(format!("-DQT_HOST_PATH={host}"));
    }
    // Single-config generators take the build type at configure time; the
    // multi-config ones ignore it and take `--build --config` instead.
    configure.arg(format!("-DCMAKE_BUILD_TYPE={config}"));
    configure.arg(format!(
        "-DNRR_VERSION={}",
        env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION")
    ));
    // The C++ build type is RelWithDebInfo in both profiles, so NDEBUG cannot
    // tell a dev host from a shipped one; the cargo profile can. Passed either
    // way, because CMake would otherwise keep a previous run's cached value.
    let dev_layout = !profile.eq_ignore_ascii_case("release");
    configure.arg(format!(
        "-DNRR_DEV_LAYOUT={}",
        if dev_layout { "ON" } else { "OFF" }
    ));
    let dev_bin_dir = dev_layout
        .then(|| cargo_profile_dir(&out_dir))
        .flatten()
        .map(|dir| dir.display().to_string())
        .unwrap_or_default();
    configure.arg(format!("-DNRR_DEV_BIN_DIR={dev_bin_dir}"));
    run(&mut configure, "configure native Qt host");

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

    // A single-config generator writes straight into the build directory; the
    // per-config subdirectory is a multi-config thing. Accept whichever landed.
    let executable = if executable.exists() {
        executable
    } else {
        build_dir.join(exe_name("nrr_qt_native_host"))
    };
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

/// `target/<profile>`, where cargo puts the launcher binaries: `OUT_DIR` is
/// `<profile>/build/<crate>-<hash>/out`.
fn cargo_profile_dir(out_dir: &Path) -> Option<PathBuf> {
    let build = out_dir.ancestors().nth(2)?;
    (build.file_name()? == "build").then(|| build.parent().map(Path::to_path_buf))?
}

fn run(command: &mut Command, step: &str) {
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("failed to {step}: {error}"));
    if !status.success() {
        panic!("{step} failed with status {status}");
    }
}

/// The Visual Studio platform and the Qt kit directory of the cargo target.
#[derive(Clone, Copy)]
struct MsvcTarget {
    platform: &'static str,
    qt_kit: &'static str,
}

impl MsvcTarget {
    fn from_cargo() -> Self {
        match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
            Ok("aarch64") => Self {
                platform: "ARM64",
                qt_kit: "msvc2022_arm64",
            },
            _ => Self {
                platform: "x64",
                qt_kit: "msvc2022_64",
            },
        }
    }
}

/// Pick the newest Qt under `C:\Qt\<X.Y.Z>\<kit>` when `CMAKE_PREFIX_PATH`
/// is not set. Version directories sort numerically (so 6.11.1 beats 6.9.2
/// despite the string order).
fn default_qt_prefix(msvc: MsvcTarget) -> String {
    let root = Path::new("C:/Qt");
    let mut best: Option<(Vec<u64>, PathBuf)> = None;
    for entry in root.read_dir().into_iter().flatten().flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let version: Vec<u64> = name.split('.').filter_map(|p| p.parse().ok()).collect();
        if version.len() != 3 {
            continue; // Tools/Docs/dist and other non-version entries
        }
        let cmake = entry.path().join(format!("{}/lib/cmake", msvc.qt_kit));
        if cmake.exists() && best.as_ref().is_none_or(|(v, _)| version > *v) {
            best = Some((version, cmake));
        }
    }
    match best {
        Some((_, cmake)) => cmake.display().to_string(),
        None => panic!(
            "CMAKE_PREFIX_PATH is not set and no Qt with an {} kit was found under C:\\Qt",
            msvc.qt_kit
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
