//! One reading of the machine's links and route table, shared by everything a
//! single planning pass asks about them.
//!
//! Each consumer used to enumerate for itself, so one pass asked the OS the
//! same question a dozen times and could get a dozen different answers. The
//! reading keeps each half's error: an unreadable table is not an empty one,
//! and every consumer still decides for itself what an unreadable half means.

use nrr_platform_api::adapters::AdapterInfo;
use nrr_platform_api::{PlatformError, RouteEntry};

pub struct MachineReading {
    routes: Result<Vec<RouteEntry>, PlatformError>,
    adapters: Result<Vec<AdapterInfo>, PlatformError>,
}

impl MachineReading {
    /// The reading, with every row the service installed marked `is_ours`.
    ///
    /// The OS never marks a row as ours, and a consumer reading an unmarked
    /// table takes our own host routes via the main gateway for tunnel servers.
    /// Marking here, once, leaves no consumer to forget it. `owns` is the
    /// path's own knowledge of what it installed.
    pub fn new(
        routes: Result<Vec<RouteEntry>, PlatformError>,
        adapters: Result<Vec<AdapterInfo>, PlatformError>,
        owns: impl Fn(&RouteEntry) -> bool,
    ) -> Self {
        let routes = routes.map(|mut rows| {
            for row in &mut rows {
                row.is_ours = row.is_ours || owns(row);
            }
            rows
        });
        Self { routes, adapters }
    }

    /// A machine with nothing on it, for an orchestrator that has no route
    /// mechanism wired.
    pub fn empty() -> Self {
        Self {
            routes: Ok(Vec::new()),
            adapters: Ok(Vec::new()),
        }
    }

    /// The route table, or `None` when it could not be read.
    pub fn routes(&self) -> Option<&[RouteEntry]> {
        self.routes.as_deref().ok()
    }

    /// The route table, or why it could not be read.
    pub fn routes_or_error(&self) -> Result<&[RouteEntry], &PlatformError> {
        self.routes.as_deref()
    }

    /// The adapters, or `None` when they could not be enumerated.
    pub fn adapters(&self) -> Option<&[AdapterInfo]> {
        self.adapters.as_deref().ok()
    }

    /// The adapters, or why they could not be enumerated.
    pub fn adapters_or_error(&self) -> Result<&[AdapterInfo], &PlatformError> {
        self.adapters.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::RouteTableRef;
    use std::net::{IpAddr, Ipv4Addr};

    fn row(last: u8) -> RouteEntry {
        RouteEntry {
            destination: IpAddr::V4(Ipv4Addr::new(203, 0, 113, last)),
            prefix_length: 32,
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            interface_index: 7,
            metric: 5,
            is_ours: false,
            table: RouteTableRef::Main,
        }
    }

    #[test]
    fn the_reading_marks_what_its_owner_installed_and_nothing_else() {
        let reading = MachineReading::new(Ok(vec![row(1), row(2)]), Ok(Vec::new()), |r| {
            r.destination == IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))
        });
        let routes = reading.routes().expect("table");
        assert!(routes[0].is_ours);
        assert!(!routes[1].is_ours);
    }

    #[test]
    fn an_unreadable_table_stays_unreadable() {
        let reading = MachineReading::new(
            Err(PlatformError::Transient {
                operation: "read routes",
                detail: "test".to_string(),
            }),
            Ok(Vec::new()),
            |_| true,
        );
        assert!(reading.routes().is_none());
        assert!(reading.routes_or_error().is_err());
    }
}
