//! Stage the vendored Wintun driver next to the built executables.
//!
//! WireGuard LLC's `wintun.dll` is a runtime component, not a cargo
//! dependency: it is loaded by name at runtime. So the build copies the
//! architecture-matching vendored copy into `<target>/<profile>/lib/`, which is
//! where `fake_ip::wintun_dll_candidates` looks right after the executable's own
//! directory. A redirected `[build] target-dir` is handled for free because the
//! destination is derived from `OUT_DIR`.
//!
//! The copy is best-effort: a build on a machine without the vendored file (or
//! a non-Windows host) must still succeed — the feature then reports itself
//! unavailable at runtime instead of breaking the build.

use std::path::{Path, PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env_or_empty("CARGO_MANIFEST_DIR"));
    // Architecture-matched to the built binary, not to the host: a 32-bit build
    // must ship the `x86` driver even on 64-bit Windows.
    let arch = match env_or_empty("CARGO_CFG_TARGET_ARCH").as_str() {
        "aarch64" => "arm64",
        "x86" => "x86",
        _ => "amd64",
    };
    // core/platform/windows → repository root.
    let source = manifest_dir
        .join("../../../third_party/wintun/bin")
        .join(arch)
        .join("wintun.dll");
    println!("cargo:rerun-if-changed={}", source.display());

    if env_or_empty("CARGO_CFG_TARGET_OS") != "windows" {
        return;
    }
    let Some(profile_dir) = profile_dir_from_out_dir() else {
        return;
    };
    let destination_dir = profile_dir.join("lib");
    if !source.is_file() {
        println!(
            "cargo:warning=vendored wintun.dll not found at {} — fake-IP will report itself unavailable",
            source.display()
        );
        return;
    }
    if std::fs::create_dir_all(&destination_dir).is_err() {
        return;
    }
    let destination = destination_dir.join("wintun.dll");
    if let Err(err) = std::fs::copy(&source, &destination) {
        println!(
            "cargo:warning=could not stage wintun.dll into {}: {err}",
            destination_dir.display()
        );
    }
}

fn env_or_empty(key: &str) -> String {
    std::env::var(key).unwrap_or_default()
}

/// `OUT_DIR` is `<target>/<profile>/build/<pkg>-<hash>/out`; the profile
/// directory — where the executables land — is three levels above it.
fn profile_dir_from_out_dir() -> Option<PathBuf> {
    let out_dir = std::env::var("OUT_DIR").ok()?;
    let profile_dir = Path::new(&out_dir).ancestors().nth(3)?.to_path_buf();
    profile_dir.is_dir().then_some(profile_dir)
}
