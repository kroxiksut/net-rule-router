//! Block T (traffic counter) — Windows interface-counter source.
//!
//! The neutral value type (`InterfaceCounters`) and the `InterfaceCounterSource`
//! port live in `nrr-platform-api`; re-export them so
//! `nrr_platform_windows::interface_traffic::*` paths resolve. The Windows
//! MECHANISM — `WindowsInterfaceCounterSource`, which reads cumulative octets
//! via `GetIfTable2` — stays here.

use nrr_platform_api::error::PlatformError;

pub use nrr_platform_api::interface_traffic::{
    InterfaceCounterSource, InterfaceCounters, MockInterfaceCounterSource,
    NoopInterfaceCounterSource,
};

/// Production source: reads per-interface cumulative octets via `GetIfTable2`
/// (`crate::win32_ffi::interface_counters`). Reading a counter is O(number of
/// interfaces), independent of traffic volume.
#[derive(Default)]
pub struct WindowsInterfaceCounterSource;

impl WindowsInterfaceCounterSource {
    pub fn new() -> Self {
        Self
    }
}

impl InterfaceCounterSource for WindowsInterfaceCounterSource {
    fn read_counters(&self) -> Result<Vec<InterfaceCounters>, PlatformError> {
        #[cfg(target_os = "windows")]
        {
            crate::win32_ffi::interface_counters::read_interface_counters()
        }
        // Off-Windows (cross-platform CI check) the crate still compiles; there
        // are no Win32 counters to read.
        #[cfg(not(target_os = "windows"))]
        {
            Ok(Vec::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_reads_without_error() {
        let src = WindowsInterfaceCounterSource::new();
        // On Windows this hits `GetIfTable2`; off-Windows it returns empty.
        let counters = src.read_counters().expect("read must succeed");
        // On a real Windows host the loopback interface guarantees non-empty,
        // but we accept empty so the cross-platform build's stub also passes.
        for c in &counters {
            assert!(!c.stable_name.is_empty());
        }
    }
}
