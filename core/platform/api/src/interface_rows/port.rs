// Where this host's adapter rows come from. Only the enumeration is per-OS;
// every judgement about a row is the neutral code around this module.

use std::sync::Mutex;

use super::*;

/// Enumerate this machine's adapters as enriched rows.
///
/// `probe_external_ip` additionally asks each adapter what the outside world
/// sees behind it. The probe sends a datagram to a third party, so only a path
/// where the user asked for the check passes `true`; a routine refresh passes
/// `false` and stays network-silent.
///
/// Never empty: an enumeration that produced nothing answers with
/// [`fallback_rows`] tagged [`InterfacesDataSource::FallbackMock`], so the
/// caller can tell invented adapters from this machine's own.
pub trait InterfaceRowsPort: Send + Sync {
    fn collect_rows(
        &self,
        probe_external_ip: bool,
    ) -> (InterfacesDataSource, Vec<InterfaceRouteRow>);
}

/// An OS with no enumeration of its own: the placeholder set, marked as such.
#[derive(Debug, Default, Clone, Copy)]
pub struct PlaceholderInterfaceRows;

impl InterfaceRowsPort for PlaceholderInterfaceRows {
    fn collect_rows(
        &self,
        _probe_external_ip: bool,
    ) -> (InterfacesDataSource, Vec<InterfaceRouteRow>) {
        (InterfacesDataSource::FallbackMock, fallback_rows())
    }
}

/// Test double answering with fixed rows and recording each probe request.
#[derive(Debug)]
pub struct MockInterfaceRows {
    source: InterfacesDataSource,
    rows: Vec<InterfaceRouteRow>,
    probe_requests: Mutex<Vec<bool>>,
}

impl MockInterfaceRows {
    #[must_use]
    pub fn new(source: InterfacesDataSource, rows: Vec<InterfaceRouteRow>) -> Self {
        Self {
            source,
            rows,
            probe_requests: Mutex::new(Vec::new()),
        }
    }

    /// The `probe_external_ip` flag of every call so far, in order.
    pub fn probe_requests(&self) -> Vec<bool> {
        self.probe_requests
            .lock()
            .map(|requests| requests.clone())
            .unwrap_or_default()
    }
}

impl InterfaceRowsPort for MockInterfaceRows {
    fn collect_rows(
        &self,
        probe_external_ip: bool,
    ) -> (InterfacesDataSource, Vec<InterfaceRouteRow>) {
        if let Ok(mut requests) = self.probe_requests.lock() {
            requests.push(probe_external_ip);
        }
        (self.source, self.rows.clone())
    }
}
