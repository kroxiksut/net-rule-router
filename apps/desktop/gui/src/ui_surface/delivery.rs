//! Parts of the package this copy lacks that the window can still name once it
//! is up. Qt, the C runtime and the QML are the launcher's to report: without
//! them nothing here runs. The service's own components (the TUN driver) are
//! reported by the service, which is the process that loads them.

use nrr_shared::{LocaleLoadReport, LocaleLoadStatus, LocaleSource};

/// The shipped rule sets (`presets/`).
pub(super) const PRESETS: &str = "presets";
/// The shipped locale files (`locales/`); the window then shows English.
pub(super) const LOCALES: &str = "locales";
/// The service executable beside this one, without which the window can
/// neither install nor start the service.
pub(super) const SERVICE_BINARY: &str = "service-binary";

/// What was found, as the payload lookup saw it.
pub(super) struct DeliveryFacts {
    pub presets_dir: bool,
    pub bundled_locale_loaded: bool,
    /// `None` where the check does not apply: a development tree is not a
    /// package, and its service is often run from elsewhere.
    pub service_binary: Option<bool>,
}

/// Missing parts as slugs, in the order the notice names them.
pub(super) fn missing_parts(facts: &DeliveryFacts) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if !facts.presets_dir {
        missing.push(PRESETS);
    }
    if !facts.bundled_locale_loaded {
        missing.push(LOCALES);
    }
    if facts.service_binary == Some(false) {
        missing.push(SERVICE_BINARY);
    }
    missing
}

/// A shipped locale file was read and kept. A user's own file does not count:
/// it covers one language, and the package still lacks the rest.
pub(super) fn bundled_locale_loaded(reports: &[LocaleLoadReport]) -> bool {
    reports.iter().any(|report| {
        report.source == LocaleSource::Bundled && report.status != LocaleLoadStatus::Rejected
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(source: LocaleSource, status: LocaleLoadStatus) -> LocaleLoadReport {
        LocaleLoadReport {
            id: "en".to_string(),
            file_name: "en.json".to_string(),
            source,
            status,
            warnings: Vec::new(),
            errors: Vec::new(),
        }
    }

    #[test]
    fn a_complete_copy_names_nothing() {
        let facts = DeliveryFacts {
            presets_dir: true,
            bundled_locale_loaded: true,
            service_binary: Some(true),
        };
        assert!(missing_parts(&facts).is_empty());
    }

    #[test]
    fn every_missing_part_is_named_once_in_order() {
        let facts = DeliveryFacts {
            presets_dir: false,
            bundled_locale_loaded: false,
            service_binary: Some(false),
        };
        assert_eq!(
            missing_parts(&facts),
            vec![PRESETS, LOCALES, SERVICE_BINARY]
        );
    }

    #[test]
    fn a_service_check_that_does_not_apply_is_not_a_gap() {
        let facts = DeliveryFacts {
            presets_dir: true,
            bundled_locale_loaded: true,
            service_binary: None,
        };
        assert!(missing_parts(&facts).is_empty());
    }

    #[test]
    fn only_a_kept_shipped_locale_counts() {
        assert!(bundled_locale_loaded(&[report(
            LocaleSource::Bundled,
            LocaleLoadStatus::AcceptedWithWarnings
        )]));
        assert!(!bundled_locale_loaded(&[report(
            LocaleSource::Bundled,
            LocaleLoadStatus::Rejected
        )]));
        assert!(!bundled_locale_loaded(&[report(
            LocaleSource::User,
            LocaleLoadStatus::Accepted
        )]));
        assert!(!bundled_locale_loaded(&[]));
    }
}
