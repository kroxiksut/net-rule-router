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

pub fn runtime_boot_banner(component: &str) -> String {
    format!(
        "NetRuleRouter {} entrypoint scaffold (Rust-first)",
        component
    )
}

pub fn runtime_boot_guard_message() -> &'static str {
    "Runtime starts without routing business logic."
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AboutWindowInfo {
    pub product_name: &'static str,
    pub edition: &'static str,
    pub version: &'static str,
    pub license: &'static str,
    pub build_profile: &'static str,
    pub rust_toolchain: &'static str,
}

pub const fn about_window_info() -> AboutWindowInfo {
    AboutWindowInfo {
        product_name: "NetRuleRouter",
        edition: "",
        version: env!("CARGO_PKG_VERSION"),
        license: env!("CARGO_PKG_LICENSE"),
        build_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        rust_toolchain: "stable",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        about_window_info, runtime_boot_banner, runtime_boot_guard_message, APPLICATION_LAYER_NOTE,
    };

    #[test]
    fn application_note_is_not_empty() {
        assert!(!APPLICATION_LAYER_NOTE.is_empty());
    }

    #[test]
    fn boot_banner_mentions_component_name() {
        assert_eq!(
            runtime_boot_banner("GUI"),
            "NetRuleRouter GUI entrypoint scaffold (Rust-first)"
        );
    }

    #[test]
    fn boot_guard_message_stays_stable() {
        assert_eq!(
            runtime_boot_guard_message(),
            "Runtime starts without routing business logic."
        );
    }

    #[test]
    fn about_window_info_contains_expected_metadata() {
        let info = about_window_info();
        assert_eq!(info.product_name, "NetRuleRouter");
        assert_eq!(info.edition, "");
        assert_eq!(info.license, "MPL-2.0");
        assert!(!info.version.is_empty());
    }
}
