// Security alerts are persisted in the SQLite-backed `security_alerts`
// table owned by the service. See
// `nrr_service_runtime::ProductionSecurityAlertsRepository`.
pub mod backend_facade;
pub mod mock_backend;
pub mod route_bindings;

// Re-export the domain-level rule-value validator so UI-adjacent crates
// (`apps/desktop/gui`, `nrr-launcher`) can use it without taking a direct
// `nrr-domain` dependency. The dependency chain stays
// `apps → application → domain`, matching the allowed crate-boundary
// rules in CLAUDE.md.
pub use nrr_domain::rule_value_validation;

pub const APPLICATION_LAYER_NOTE: &str =
    "Transport-agnostic application workflows are composed here.";

// Moved into `nrr-shared`: the service needed these two strings and nothing
// else from this crate, and that lone edge dragged the UI and preview crates
// into its binary. Re-exported so the desktop runtimes, which legitimately
// depend on this crate, keep the same path.
pub use nrr_shared::{runtime_boot_banner, runtime_boot_role_message};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AboutWindowInfo {
    pub product_name: &'static str,
    pub edition: &'static str,
    pub version: &'static str,
    pub license: &'static str,
    pub build_profile: &'static str,
    pub rust_toolchain: &'static str,
}

/// The edition this build ships. One value today; it exists as a field because
/// the About window shows it and Pro is a planned second value.
pub const EDITION: &str = "Free";

pub const fn about_window_info() -> AboutWindowInfo {
    AboutWindowInfo {
        // Read from the product-identity SSOT, never retyped.
        product_name: nrr_shared::product_identity::PRODUCT_NAME,
        edition: EDITION,
        version: env!("CARGO_PKG_VERSION"),
        license: env!("CARGO_PKG_LICENSE"),
        build_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        // Baked from `rust-version` at compile time rather than the word
        // "stable", which was neither the pinned toolchain nor ever updated.
        rust_toolchain: env!("CARGO_PKG_RUST_VERSION"),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        about_window_info, runtime_boot_banner, runtime_boot_role_message, APPLICATION_LAYER_NOTE,
        EDITION,
    };

    #[test]
    fn application_note_is_not_empty() {
        assert!(!APPLICATION_LAYER_NOTE.is_empty());
    }

    #[test]
    fn boot_banner_mentions_component_name() {
        let banner = runtime_boot_banner("GUI");
        assert!(banner.contains("GUI"), "{banner}");
        assert!(
            banner.contains(nrr_shared::product_identity::PRODUCT_NAME),
            "{banner}"
        );
    }

    #[test]
    fn the_service_boot_line_says_it_enforces() {
        // The old line claimed the runtime carried no routing logic — in the
        // process that carries all of it.
        let line = runtime_boot_role_message("service");
        assert!(line.contains("enforces"), "{line}");
    }

    #[test]
    fn about_window_info_contains_expected_metadata() {
        let info = about_window_info();
        // Compared with the SSOT, not with a second copy of the name.
        assert_eq!(
            info.product_name,
            nrr_shared::product_identity::PRODUCT_NAME
        );
        assert_eq!(info.edition, EDITION);
        assert_eq!(info.license, "MPL-2.0");
        assert!(!info.version.is_empty());
        // The toolchain shown to the user is the pinned one, not the word
        // "stable" — that literal never matched and never updated.
        assert_eq!(info.rust_toolchain, env!("CARGO_PKG_RUST_VERSION"));
        assert!(
            info.rust_toolchain.starts_with('1'),
            "{}",
            info.rust_toolchain
        );
    }
}
