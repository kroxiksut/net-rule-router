use nrr_domain::{
    canonical::{CanonicalProfile, CanonicalRuleBook},
    import::{process_import, ImportRequest, ImportResult, ImportTrigger},
    revision::{ContentHash, RevisionActor, RevisionId, RevisionSeq, UnixTimestamp},
    AdapterIdentity, BindingSource, RouteBehaviorMode, RouteBinding, RouteRole as DomainRouteRole,
};
use nrr_shared::{
    FreeRuleListType, FreeRuleType, RouteRole, RuleFormFieldId, RuleScenario, RulesEnabledFilter,
    RulesFileChangeBehavior, RulesTypeFilter, RulesViewSort,
};

pub const RULES_PREVIEW_NOTICE: &str =
    "Rules UI is in preview mode in block 2: real validation and policy apply are connected later.";

const SUPPORTED_FREE_RULE_TYPES: [FreeRuleType; 4] = [
    FreeRuleType::Application,
    FreeRuleType::Domain,
    FreeRuleType::Zone,
    FreeRuleType::ExactIp,
];

const RULE_SCENARIOS: [RuleScenario; 5] = [
    RuleScenario::Create,
    RuleScenario::Edit,
    RuleScenario::Delete,
    RuleScenario::Reorder,
    RuleScenario::Search,
];

const SUPPORTED_LIST_TYPES: [FreeRuleListType; 2] = [
    FreeRuleListType::SingleActiveManagedList,
    FreeRuleListType::ImportedPresetReplacingActiveList,
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleFormFieldPreview {
    pub id: RuleFormFieldId,
    pub required: bool,
    pub constraint_hint: &'static str,
}

const FORM_FIELDS: [RuleFormFieldPreview; 5] = [
    RuleFormFieldPreview {
        id: RuleFormFieldId::RuleType,
        required: true,
        constraint_hint:
            "Select one supported Free type: application, exact FQDN, suffix/subdomain, exact IP.",
    },
    RuleFormFieldPreview {
        id: RuleFormFieldId::MatchValue,
        required: true,
        constraint_hint: "1..255 chars; exact FQDN/IP must not contain wildcard.",
    },
    RuleFormFieldPreview {
        id: RuleFormFieldId::TargetRoute,
        required: true,
        constraint_hint: "Allowed targets are Primary route and Secondary route.",
    },
    RuleFormFieldPreview {
        id: RuleFormFieldId::Enabled,
        required: false,
        constraint_hint: "Boolean toggle; new rule starts as enabled.",
    },
    RuleFormFieldPreview {
        id: RuleFormFieldId::Comment,
        required: false,
        constraint_hint: "Optional note up to 256 chars.",
    },
];

const LOAD_DIALOG_FIELDS: [&str; 7] = [
    "File path",
    "Format",
    "Schema version",
    "Parsed summary",
    "Replace current list",
    "Load action",
    "Cancel action",
];

const EDIT_DIALOG_FIELDS: [&str; 7] = [
    "List name",
    "Description",
    "Rules set",
    "Rules order",
    "Default mode",
    "Save action",
    "Cancel action",
];

const REVIEW_DIALOG_FIELDS: [&str; 7] = [
    "Incoming list name",
    "Incoming rules count",
    "Current rules count",
    "Default mode difference",
    "New rule types summary",
    "Replace action",
    "Cancel action",
];

const RULE_ROWS: [RuleRowPreview; 6] = [
    RuleRowPreview {
        id: "R-0001",
        enabled: true,
        rule_type: FreeRuleType::Application,
        match_value: "browser.exe",
        target_route: RouteRole::Secondary,
        comment: "Browser traffic to secondary route.",
    },
    RuleRowPreview {
        id: "R-0002",
        enabled: true,
        rule_type: FreeRuleType::Domain,
        match_value: "updates.example.org",
        target_route: RouteRole::Secondary,
        comment: "Vendor updates domain and all subdomains.",
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
    },
    RuleRowPreview {
        id: "R-0004",
        enabled: false,
        rule_type: FreeRuleType::ExactIp,
        match_value: "203.0.113.7",
        target_route: RouteRole::Secondary,
        comment: "Temporary exact IP routing override.",
    },
    RuleRowPreview {
        id: "R-0005",
        enabled: true,
        rule_type: FreeRuleType::Application,
        match_value: "powershell.exe",
        target_route: RouteRole::Primary,
        comment: "Maintenance script traffic on primary route.",
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
    },
];

/// A preview of a cross-set duplicate: the same match target appears in both
/// the primary and secondary rule sets, so the user must decide how to resolve it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplicateConflictPreview {
    /// ID of the conflicting rule in the primary set.
    pub primary_rule_id: String,
    /// ID of the conflicting rule in the secondary set.
    pub secondary_rule_id: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RulesScreenRequest {
    pub search_query: Option<String>,
    pub type_filter: Option<RulesTypeFilter>,
    pub enabled_filter: Option<RulesEnabledFilter>,
    pub sort_mode: Option<RulesViewSort>,
    pub scenario: Option<RuleScenario>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadListDialogPreview {
    pub fields: &'static [&'static str],
    pub accepted_formats: &'static [&'static str],
    pub requires_review_before_replace: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EditListDialogPreview {
    pub fields: &'static [&'static str],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplaceReviewDialogPreview {
    pub fields: &'static [&'static str],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RulesScreenPreviewSnapshot {
    pub data_source: RulesDataSource,
    pub preview_notice: &'static str,
    pub applied_search_query: Option<String>,
    pub applied_type_filter: Option<RulesTypeFilter>,
    pub applied_enabled_filter: RulesEnabledFilter,
    pub applied_sort_mode: RulesViewSort,
    pub active_scenario: RuleScenario,
    pub supported_rule_types: &'static [FreeRuleType],
    pub supported_list_types: &'static [FreeRuleListType],
    pub placeholder_scenarios: &'static [RuleScenario],
    pub form_fields: &'static [RuleFormFieldPreview],
    /// Visible rows after search, type-filter, enabled-filter, and sort are applied.
    pub rows: Vec<RuleRowPreview>,
    /// Cross-set duplicate conflicts the user must resolve. Empty in this preview seed.
    pub duplicate_conflicts: Vec<DuplicateConflictPreview>,
    pub load_list_dialog: LoadListDialogPreview,
    pub edit_list_dialog: EditListDialogPreview,
    pub replace_review_dialog: ReplaceReviewDialogPreview,
    /// Active file-change behavior setting for this preview seed.
    pub file_change_behavior: RulesFileChangeBehavior,
    /// Whether a file change was detected since the rules were last applied.
    /// Always `false` in the preview seed — real detection is wired in the
    /// service-backed implementation.
    pub has_pending_file_change: bool,
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
        preview_notice: RULES_PREVIEW_NOTICE,
        applied_search_query: normalized_query,
        applied_type_filter: request.type_filter,
        applied_enabled_filter: enabled_filter,
        applied_sort_mode: sort_mode,
        active_scenario: request.scenario.unwrap_or(RuleScenario::Search),
        supported_rule_types: &SUPPORTED_FREE_RULE_TYPES,
        supported_list_types: &SUPPORTED_LIST_TYPES,
        placeholder_scenarios: &RULE_SCENARIOS,
        form_fields: &FORM_FIELDS,
        rows,
        duplicate_conflicts: Vec::new(),
        load_list_dialog: LoadListDialogPreview {
            fields: &LOAD_DIALOG_FIELDS,
            accepted_formats: &["yaml", "yml"],
            requires_review_before_replace: true,
        },
        edit_list_dialog: EditListDialogPreview {
            fields: &EDIT_DIALOG_FIELDS,
        },
        replace_review_dialog: ReplaceReviewDialogPreview {
            fields: &REVIEW_DIALOG_FIELDS,
        },
        file_change_behavior: RulesFileChangeBehavior::default(),
        has_pending_file_change: false,
    }
}

fn normalize_search_query(query: Option<String>) -> Option<String> {
    let value = query?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_ascii_lowercase())
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
            Some(RulesTypeFilter::Application | RulesTypeFilter::Windows) => {
                row.rule_type == FreeRuleType::Application
            }
            Some(RulesTypeFilter::Linux | RulesTypeFilter::MacOS) => false,
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

fn mock_active_content_hash() -> ContentHash {
    ContentHash::from_bytes([0xAB; 32])
}

fn mock_canonical_profile() -> CanonicalProfile {
    CanonicalProfile {
        primary: RouteBinding {
            role: DomainRouteRole::Primary,
            adapter: AdapterIdentity {
                stable_id: "adapter-aa:bb:cc:dd:ee:01-1".to_string(),
                display_name: "Primary (mock)".to_string(),
            },
            source: BindingSource::UserAssigned,
        },
        secondary: Some(RouteBinding {
            role: DomainRouteRole::Secondary,
            adapter: AdapterIdentity {
                stable_id: "adapter-ff:ee:dd:cc:bb:02-2".to_string(),
                display_name: "Secondary (mock)".to_string(),
            },
            source: BindingSource::UserAssigned,
        }),
        behavior_mode: RouteBehaviorMode::StrictSecondaryFailClosed,
        rule_book: CanonicalRuleBook::default(),
    }
}

/// Simulates a controlled import for UI preview purposes.
///
/// Pass `same_content = true` to exercise the no-change path;
/// `false` to produce a `PendingReview` result.
#[allow(clippy::expect_used)]
pub fn simulate_import(trigger: ImportTrigger, same_content: bool) -> ImportResult {
    let active_hash = mock_active_content_hash();
    let content_hash = if same_content {
        active_hash.clone()
    } else {
        ContentHash::from_bytes([0xCD; 32])
    };
    let request = ImportRequest {
        revision_id: RevisionId::from_prefixed_string("rev-mock-import-preview-001".to_string())
            .expect("valid mock revision id"),
        seq: RevisionSeq::FIRST,
        source_path: r"C:\Users\user\Documents\rules_primary.txt".to_string(),
        file_hash: ContentHash::from_bytes([0xDE; 32]),
        content_hash,
        acquired_at: UnixTimestamp::from_secs(1_700_000_000),
        trigger,
        actor: RevisionActor::LocalUser,
        content: mock_canonical_profile(),
        displaces_pending_id: None,
    };
    process_import(request, Some(&active_hash), None)
}

fn row_matches_query(row: &RuleRowPreview, query: &str) -> bool {
    row.id.to_ascii_lowercase().contains(query)
        || row.match_value.to_ascii_lowercase().contains(query)
        || row.comment.to_ascii_lowercase().contains(query)
}

#[cfg(test)]
mod tests {
    use super::{rules_screen_preview_snapshot, RulesScreenRequest};
    use nrr_shared::{RuleScenario, RulesTypeFilter};

    #[test]
    fn rules_snapshot_exposes_free_rule_types_scenarios_and_dialogs() {
        let snapshot = rules_screen_preview_snapshot(RulesScreenRequest::default());
        assert_eq!(snapshot.supported_rule_types.len(), 4);
        assert_eq!(snapshot.supported_list_types.len(), 2);
        assert!(snapshot
            .placeholder_scenarios
            .contains(&RuleScenario::Create));
        assert!(snapshot
            .placeholder_scenarios
            .contains(&RuleScenario::Delete));
        assert_eq!(snapshot.form_fields.len(), 5);
        assert_eq!(snapshot.rows.len(), 6);
        assert!(snapshot.load_list_dialog.requires_review_before_replace);
        assert_eq!(snapshot.load_list_dialog.accepted_formats, &["yaml", "yml"]);
        assert_eq!(snapshot.edit_list_dialog.fields.len(), 7);
        assert_eq!(snapshot.replace_review_dialog.fields.len(), 7);
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
        assert_eq!(snapshot.rows.len(), 1);
        assert_eq!(snapshot.rows[0].id, "R-0001");
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
