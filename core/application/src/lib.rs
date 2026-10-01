pub mod backend_facade;
pub mod mock_backend;

// Re-export the domain-level rule-value validator so UI-adjacent crates
// (`apps/desktop/gui`, `nrr-launcher`) can use it without taking a direct
// `nrr-domain` dependency. The dependency chain stays
// `apps → application → domain`, matching the allowed crate-boundary
// rules in CLAUDE.md.
pub use nrr_domain::rule_value_validation;

// Same reason, same chain: the launcher answers `preset.parse`, and the
// window must be able to say "the service will refuse this file" BEFORE the
// user has chosen what to do with its contents.
pub use nrr_domain::preset_validation;

// Re-exported from `nrr-shared` so desktop runtimes that legitimately depend
// on this crate keep one path; the service reads these two strings straight
// from `nrr-shared` and stays off this crate's dependency graph.
pub use nrr_shared::{runtime_boot_banner, runtime_boot_role_message};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AboutWindowInfo {
    pub product_name: &'static str,
    pub version: &'static str,
    pub license: &'static str,
    pub build_profile: &'static str,
    pub rust_toolchain: &'static str,
}

pub const fn about_window_info() -> AboutWindowInfo {
    AboutWindowInfo {
        // Read from the product-identity SSOT, never retyped.
        product_name: nrr_shared::product_identity::PRODUCT_NAME,
        version: env!("CARGO_PKG_VERSION"),
        license: env!("CARGO_PKG_LICENSE"),
        build_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        // The compiler that built this, not the declared minimum `rust-version`.
        rust_toolchain: env!("NRR_BUILD_RUSTC_VERSION"),
    }
}

#[cfg(test)]
mod tests {
    use super::{about_window_info, runtime_boot_banner, runtime_boot_role_message};

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
        assert_eq!(info.license, "MPL-2.0");
        assert!(!info.version.is_empty());
        // The version `rustc -V` reported, e.g. "1.94.1 (hash date)".
        assert!(
            info.rust_toolchain.starts_with('1'),
            "{}",
            info.rust_toolchain
        );
    }
}
