//! What the platform reports as missing or in the way, for the status card.
//!
//! The decision of what counts is the platform's: the service installs its own
//! source once at start-up. Without one nothing is reported.

use std::sync::OnceLock;

static SOURCE: OnceLock<fn() -> Vec<String>> = OnceLock::new();

/// Install the platform's source of capability slugs. Only the first call counts.
pub fn install_source(source: fn() -> Vec<String>) {
    let _ = SOURCE.set(source);
}

/// Slugs for the clients' `platform.missing.<slug>.*` keys; empty when none.
#[must_use]
pub fn current() -> Vec<String> {
    SOURCE.get().map(|source| source()).unwrap_or_default()
}
