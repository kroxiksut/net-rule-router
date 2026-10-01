//! Bakes the compiler that built this crate into `NRR_BUILD_RUSTC_VERSION`, so
//! the About window names the real toolchain rather than the declared minimum.

use std::process::Command;

fn main() {
    // A toolchain change rebuilds every unit anyway; `RUSTC` is the only other
    // input this script reads.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=RUSTC");

    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let version = Command::new(rustc)
        .arg("-V")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|line| line.trim().trim_start_matches("rustc ").to_owned())
        .filter(|version| !version.is_empty() && !version.contains(['\n', '\r']))
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=NRR_BUILD_RUSTC_VERSION={version}");
}
