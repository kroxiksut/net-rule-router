//! Build-only crate that drives the CMake compilation of the C++ Qt host
//! (`nrr_qt_native_host.exe`) and exposes its absolute path as a constant
//! consumable from `nrr-launcher` at runtime.
//!
//! The process itself belongs to `nrr-launcher`; this crate only builds the
//! host and names it, so callers never repeat the build-time lookup.

/// Absolute path to `nrr_qt_native_host.exe` produced by `build.rs` via
/// CMake. Resolved at compile time from the `NRR_QT_NATIVE_HOST_EXE`
/// environment variable that `build.rs` sets via `cargo:rustc-env`.
pub const NATIVE_HOST_EXE: &str = env!("NRR_QT_NATIVE_HOST_EXE");
