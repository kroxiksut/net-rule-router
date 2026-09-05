use nrr_shared::{
    FreeRuleType, RouteRole, RuleScenario, RulesEnabledFilter, RulesTypeFilter, RulesViewSort,
};

const SUPPORTED_FREE_RULE_TYPES: [FreeRuleType; 4] = [
    FreeRuleType::Application,
    FreeRuleType::Domain,
    FreeRuleType::Zone,
    FreeRuleType::ExactIp,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RulesDataSource {
    PreviewSeed,
}

impl RulesDataSource {
    pub const fn title(self) -> &'static str {
        match self {
            Self::PreviewSeed => "preview-seed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleRowPreview {
    pub id: &'static str,
    pub enabled: bool,
    pub rule_type: FreeRuleType,
    pub match_value: &'static str,
    pub target_route: RouteRole,
    pub comment: &'static str,
    /// Which per-OS section an application rule lives in (`--- Windows`,
    /// `--- Linux`, `--- MacOS`); `None` for every other rule type, which is
    /// platform-neutral.
    ///
    /// Without it the preview had no way to honour what
    /// `RulesTypeFilter::Application` promises — "the current platform's
    /// section" — so it answered with `.exe` names on Linux and left the Linux
    /// filter permanently empty.
    pub app_section: Option<RulesTypeFilter>,
}

/// The application section THIS build calls "the current platform".
///
/// `RulesTypeFilter::Application` is host-relative by contract; spelling the
/// roles out as Windows-is-native is what made the preview wrong off Windows.
const fn native_app_section() -> RulesTypeFilter {
    if cfg!(target_os = "windows") {
        RulesTypeFilter::Windows
    } else if cfg!(target_os = "linux") {
        RulesTypeFilter::Linux
    } else {
        RulesTypeFilter::MacOS
    }
}

const RULE_ROWS: [RuleRowPreview; 8] = [
    RuleRowPreview {
        id: "R-0001",
        enabled: true,
        rule_type: FreeRuleType::Application,
        match_value: "browser.exe",
        target_route: RouteRole::Secondary,
        comment: "Browser traffic to secondary route.",
        app_section: Some(RulesTypeFilter::Windows),
    },
    RuleRowPreview {
        id: "R-0002",
        enabled: true,
        rule_type: FreeRuleType::Domain,
        match_value: "updates.example.org",
        target_route: RouteRole::Secondary,
        comment: "Vendor updates domain and all subdomains.",
        app_section: None,
    },
    RuleRowPreview {
        // All IDs are zero-padded to 4 digits so the GUI's id-collision
        // check (used by `loadDemoRules`) treats `R-0003` and the legacy
        // `R-003` as the same row. Drift between paddings causes visible
        // duplicates with identical content.
        id: "R-0003",
        enabled: true,
        rule_type: FreeRuleType::Domain,
        match_value: "corp.example.net",
        target_route: RouteRole::Primary,
        comment: "Internal corporate domain and all subdomains.",
        app_section: None,
    },
    RuleRowPreview {
        id: "R-0004",
        enabled: false,
        rule_type: FreeRuleType::ExactIp,
        match_value: "203.0.113.7",
        target_route: RouteRole::Secondary,
        comment: "Temporary exact IP routing override.",
        app_section: None,
    },
    RuleRowPreview {
        id: "R-0005",
        enabled: true,
        rule_type: FreeRuleType::Application,
        match_value: "powershell.exe",
        target_route: RouteRole::Primary,
        comment: "Maintenance script traffic on primary route.",
        app_section: Some(RulesTypeFilter::Windows),
    },
    // Demo zone rule for routing-probe testing. Free tier supports
    // domain-suffix zones (TLD or internal-suffix) as a first-class
    // `FreeRuleType::Zone` variant. The rule engine matches any hostname
    // ending in `.{zone_name}`; `.ru` here catches every Russian-zone
    // domain.
    RuleRowPreview {
        id: "R-0006",
        enabled: true,
        rule_type: FreeRuleType::Zone,
        match_value: "ru",
        target_route: RouteRole::Primary,
        comment: "Russian-zone domains to primary route (demo).",
        app_section: None,
    },
    // One application rule per OS section, so the preview shows the feature on
    // every host instead of only on Windows — and so the "other OS" filters
    // have something to demonstrate.
    RuleRowPreview {
        id: "R-0007",
        enabled: true,
        rule_type: FreeRuleType::Application,
        match_value: "firefox",
        target_route: RouteRole::Secondary,
        comment: "Browser traffic to secondary route.",
        app_section: Some(RulesTypeFilter::Linux),
    },
    RuleRowPreview {
        id: "R-0008",
        enabled: true,
        rule_type: FreeRuleType::Application,
        match_value: "Safari",
        target_route: RouteRole::Secondary,
        comment: "Browser traffic to secondary route.",
        app_section: Some(RulesTypeFilter::MacOS),
    },
];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RulesScreenRequest {
    pub search_query: Option<String>,
    pub type_filter: Option<RulesTypeFilter>,
    pub enabled_filter: Option<RulesEnabledFilter>,
    pub sort_mode: Option<RulesViewSort>,
    pub scenario: Option<RuleScenario>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RulesScreenPreviewSnapshot {
    pub data_source: RulesDataSource,
    pub applied_search_query: Option<String>,
    pub applied_type_filter: Option<RulesTypeFilter>,
    pub applied_enabled_filter: RulesEnabledFilter,
    pub applied_sort_mode: RulesViewSort,
    pub active_scenario: RuleScenario,
    pub supported_rule_types: &'static [FreeRuleType],
    /// Visible rows after search, type-filter, enabled-filter, and sort are applied.
    pub rows: Vec<RuleRowPreview>,
}

pub fn rules_screen_preview_snapshot(request: RulesScreenRequest) -> RulesScreenPreviewSnapshot {
    let normalized_query = normalize_search_query(request.search_query);
    let enabled_filter = request.enabled_filter.unwrap_or_default();
    let sort_mode = request.sort_mode.unwrap_or_default();
    let rows = build_rows(
        normalized_query.as_deref(),
        request.type_filter,
        enabled_filter,
        sort_mode,
    );

    RulesScreenPreviewSnapshot {
        data_source: RulesDataSource::PreviewSeed,
        applied_search_query: normalized_query,
        applied_type_filter: request.type_filter,
        applied_enabled_filter: enabled_filter,
        applied_sort_mode: sort_mode,
        active_scenario: request.scenario.unwrap_or(RuleScenario::Search),
        supported_rule_types: &SUPPORTED_FREE_RULE_TYPES,
        rows,
    }
}

fn normalize_search_query(query: Option<String>) -> Option<String> {
    let value = query?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        // Unicode case folding, not ASCII: Russian is a baseline locale here,
        // and `to_ascii_lowercase` leaves «Корп» as it is, so it never matches
        // a rule commented «корп».
        Some(trimmed.to_lowercase())
    }
}

fn build_rows(
    query: Option<&str>,
    type_filter: Option<RulesTypeFilter>,
    enabled_filter: RulesEnabledFilter,
    sort_mode: RulesViewSort,
) -> Vec<RuleRowPreview> {
    let mut rows: Vec<RuleRowPreview> = RULE_ROWS
        .iter()
        .copied()
        .filter(|row| match type_filter {
            None | Some(RulesTypeFilter::All) => true,
            Some(RulesTypeFilter::Domain) => row.rule_type == FreeRuleType::Domain,
            Some(RulesTypeFilter::Zones) => row.rule_type == FreeRuleType::Zone,
            Some(RulesTypeFilter::ExactIp) => row.rule_type == FreeRuleType::ExactIp,
            // Host-relative, as the contract says: `Application` is whichever
            // per-OS section this build calls its own.
            Some(RulesTypeFilter::Application) => row.app_section == Some(native_app_section()),
            Some(
                section @ (RulesTypeFilter::Windows
                | RulesTypeFilter::Linux
                | RulesTypeFilter::MacOS),
            ) => row.app_section == Some(section),
        })
        .filter(|row| match enabled_filter {
            RulesEnabledFilter::All => true,
            RulesEnabledFilter::EnabledOnly => row.enabled,
            RulesEnabledFilter::DisabledOnly => !row.enabled,
        })
        .filter(|row| query.is_none_or(|needle| row_matches_query(row, needle)))
        .collect();

    match sort_mode {
        RulesViewSort::ByDisplayOrder => {}
        RulesViewSort::ByMatchValue => {
            rows.sort_by(|a, b| a.match_value.cmp(b.match_value));
        }
        RulesViewSort::ByType => {
            rows.sort_by_key(|row| row.rule_type.evaluation_priority());
        }
        RulesViewSort::ByRoute => {
            rows.sort_by_key(|row| match row.target_route {
                RouteRole::Primary => 0u8,
                RouteRole::Secondary => 1u8,
            });
        }
    }

    rows
}

fn row_matches_query(row: &RuleRowPreview, query: &str) -> bool {
    // Folded the same way as the query — see `normalize_search_query`.
    row.id.to_lowercase().contains(query)
        || row.match_value.to_lowercase().contains(query)
        || row.comment.to_lowercase().contains(query)
}

#[cfg(test)]
mod tests {
    use super::{rules_screen_preview_snapshot, RulesScreenRequest};
    use nrr_shared::{RuleScenario, RulesTypeFilter};

    #[test]
    fn rules_snapshot_exposes_the_free_rule_types() {
        let snapshot = rules_screen_preview_snapshot(RulesScreenRequest::default());
        assert_eq!(snapshot.supported_rule_types.len(), 4);
        assert_eq!(snapshot.rows.len(), super::RULE_ROWS.len());
    }

    #[test]
    fn rules_snapshot_filters_by_type_and_search() {
        let snapshot = rules_screen_preview_snapshot(RulesScreenRequest {
            search_query: Some("browser".to_string()),
            type_filter: Some(RulesTypeFilter::Application),
            enabled_filter: None,
            sort_mode: None,
            scenario: Some(RuleScenario::Search),
        });
        assert_eq!(snapshot.applied_search_query.as_deref(), Some("browser"));
        assert_eq!(
            snapshot.applied_type_filter,
            Some(RulesTypeFilter::Application)
        );
        // Host-relative, like the filter itself: each OS section carries one
        // browser rule, and `Application` must answer with THIS host's. Naming
        // `R-0001` outright passed on a Windows runner and asserted the defect
        // everywhere else.
        assert_eq!(snapshot.rows.len(), 1);
        assert_eq!(
            snapshot.rows[0].app_section,
            Some(super::native_app_section())
        );
    }

    /// The contract calls `Application` "the current platform's section", and
    /// `Linux` / `MacOS` the explicit other-OS filters. Before this the seed
    /// answered `Application` with `.exe` names on every host and left both
    /// other-OS filters permanently empty.
    #[test]
    fn each_os_section_answers_with_its_own_rules() {
        let listed = |filter: RulesTypeFilter| {
            rules_screen_preview_snapshot(RulesScreenRequest {
                search_query: None,
                type_filter: Some(filter),
                enabled_filter: None,
                sort_mode: None,
                scenario: None,
            })
            .rows
        };

        for section in [
            RulesTypeFilter::Windows,
            RulesTypeFilter::Linux,
            RulesTypeFilter::MacOS,
        ] {
            let rows = listed(section);
            assert!(
                !rows.is_empty(),
                "{section:?} has nothing to demonstrate the feature with"
            );
            assert!(
                rows.iter().all(|r| r.app_section == Some(section)),
                "{section:?} answered with another section's rules"
            );
        }

        let native = listed(RulesTypeFilter::Application);
        assert_eq!(native, listed(super::native_app_section()));
    }

    /// ASCII case folding leaves Cyrillic alone, so an uppercase query never
    /// matched a lowercase rule — in a product whose baseline locale is Russian.
    /// The preview rows are English, so the Cyrillic half is proven on the
    /// folding itself and the matching half on a Latin row.
    #[test]
    fn search_folds_case_for_cyrillic_not_only_latin() {
        assert_eq!(
            super::normalize_search_query(Some("  BROWSER ".to_string())).as_deref(),
            Some("browser")
        );
        assert_eq!(
            super::normalize_search_query(Some("\u{041a}\u{043e}\u{0440}\u{043f}".to_string()))
                .as_deref(),
            Some("\u{043a}\u{043e}\u{0440}\u{043f}"),
            "an uppercase Cyrillic query must fold like a Latin one"
        );

        let snapshot = rules_screen_preview_snapshot(RulesScreenRequest {
            search_query: Some("BROWSER".to_string()),
            type_filter: None,
            enabled_filter: None,
            sort_mode: None,
            scenario: Some(RuleScenario::Search),
        });
        assert!(
            !snapshot.rows.is_empty(),
            "an uppercase query must match a lowercase comment"
        );
    }

    #[test]
    fn rules_snapshot_keeps_requested_scenario() {
        let snapshot = rules_screen_preview_snapshot(RulesScreenRequest {
            search_query: None,
            type_filter: None,
            enabled_filter: None,
            sort_mode: None,
            scenario: Some(RuleScenario::Reorder),
        });
        assert_eq!(snapshot.active_scenario, RuleScenario::Reorder);
    }
}
