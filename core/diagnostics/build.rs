//! Captures build provenance so a diagnostic archive names the EXACT build
//! it came from.
//!
//! Emits three `cargo:rustc-env` values the manifest reads via `env!`:
//! - `NRR_BUILD_COMMIT` — short git SHA (with a `-dirty` suffix when the tree
//!   has uncommitted changes), or `"unknown"` when git is unavailable (a
//!   source tarball build, or git not on PATH).
//! - `NRR_BUILD_PROFILE` — `debug` / `release` (from `PROFILE`).
//! - `NRR_BUILD_TARGET` — the target triple (from `TARGET`).
//!
//! Best-effort: a failed git call never fails the build — provenance simply
//! reads `"unknown"`.

use std::process::Command;

fn main() {
    let commit = git_short_commit().unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=NRR_BUILD_COMMIT={commit}");

    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=NRR_BUILD_PROFILE={profile}");

    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=NRR_BUILD_TARGET={target}");

    // Re-run when HEAD moves so the embedded commit stays current.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");
}

/// `git rev-parse --short HEAD`, plus a `-dirty` marker when the working tree
/// has staged or unstaged changes. `None` on any failure.
fn git_short_commit() -> Option<String> {
    let head = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;
    if !head.status.success() {
        return None;
    }
    let sha = String::from_utf8(head.stdout).ok()?.trim().to_string();
    if sha.is_empty() {
        return None;
    }
    // `git status --porcelain` prints nothing for a clean tree.
    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);
    Some(if dirty { format!("{sha}-dirty") } else { sha })
}
