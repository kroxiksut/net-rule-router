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
    pub routes: Result<Vec<RouteEntry>, PlatformError>,
    pub adapters: Result<Vec<AdapterInfo>, PlatformError>,
}

impl MachineReading {
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

    /// The adapters, or `None` when they could not be enumerated.
    pub fn adapters(&self) -> Option<&[AdapterInfo]> {
        self.adapters.as_deref().ok()
    }
}
