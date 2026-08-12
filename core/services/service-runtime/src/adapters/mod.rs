//! Concrete port adapters for the service runtime.
//!
//! "Adapter" here is the hexagonal-architecture term: a concrete
//! implementation of a port trait defined in [`crate::integration_ports`].
//! These are **not** network adapters (interfaces) — those live in
//! `nrr-platform-windows` and are surfaced through the
//! `AdapterEventSource` / `AdapterMonitor` machinery in that crate.
//!
//! ## Wiring direction
//!
//! - Port traits (`CacheLookupPort`, `DiagnosticsPort`, …) live in
//!   `integration_ports.rs`.
//! - `Noop*` test/preview impls live in `windows_apply_adapter.rs`.
//! - Real production impls — backed by SQLite, the operational NDJSON
//!   writer, the audit writer, etc. — live in this module, one file per
//!   port.
//!
//! Each adapter is a thin glue layer: shape conversion + error mapping.
//! Storage I/O is delegated to `nrr-storage`; diagnostics writes go to
//! `nrr-diagnostics`. No new business logic.

pub mod ndjson_diagnostics;
pub mod sqlite_cache;

pub use ndjson_diagnostics::NdjsonDiagnosticsPort;
pub use sqlite_cache::SqliteCachePort;
