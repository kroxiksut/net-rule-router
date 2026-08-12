//! Build-only crate that drives the CMake compilation of the C++ Qt host
//! (`nrr_qt_native_host.exe`) and exposes its absolute path as a constant
//! consumable from `nrr-launcher` at runtime.
//!
//! After 13.R-GUI.4 the Rust orchestrator binary that lived in `src/main.rs`
//! is gone — its responsibilities are owned by `nrr-launcher`. The crate
//! continues to ship `build.rs`, which is what actually produces the C++
//! binary; this `lib.rs` only re-exports the path baked at build time so
//! callers don't have to duplicate the env-var lookup.

/// Absolute path to `nrr_qt_native_host.exe` produced by `build.rs` via
/// CMake. Resolved at compile time from the `NRR_QT_NATIVE_HOST_EXE`
/// environment variable that `build.rs` sets via `cargo:rustc-env`.
pub const NATIVE_HOST_EXE: &str = env!("NRR_QT_NATIVE_HOST_EXE");
