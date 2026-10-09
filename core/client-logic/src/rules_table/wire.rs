//! Rows to the canonical wire `RuleDto` and back from the service's answers.

use nrr_shared::auto_rule::{AutoRuleReason, RuleOrigin};
use nrr_shared::ipc_payloads::RuleRowEntry;
use nrr_shared::preset_parser::ParsedRule;
use nrr_shared::rules_json::{AddressMatchDto, AppMatchDto, AppPatternDto, RuleDto};

use super::{RowOrigin, RuleRow, RuleType, TargetRoute};
use crate::{js, Route};

/// What [`rule_row_to_wire_dto`] keeps besides the routing itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireDtoOptions {
    /// `false` writes an empty id.
    pub keep_id: bool,
    /// `false` drops the comment and the provenance: metadata, not routing.
    pub keep_comment: bool,
}

impl WireDtoOptions {
    /// Everything: the form an apply sends.
    pub const FULL: Self = Self {
        keep_id: true,
        keep_comment: true,
    };
    /// Routing only: the form drift hashing compares. A file parse and the
    /// service assign different ids to the same rules, and a note the user
    /// typed is not a routing change.
    pub const ROUTING_ONLY: Self = Self {
        keep_id: false,
        keep_comment: false,
    };
}

impl Default for WireDtoOptions {
    fn default() -> Self {
        Self::FULL
    }
}

/// THE row-to-wire mapper (`ruleRowToWireDto`): one serializer for apply,
/// review and drift, so no two callers disagree on a field.
///
/// `ace_encode` turns a host value into its ACE form; an empty answer keeps
/// the value. Only host-like types go through it. A `domain` row carries both
/// host kinds and is decoded by its `*.` prefix; a type this build does not
/// know is read the same way.
pub fn rule_row_to_wire_dto(
    row: &RuleRow,
    ace_encode: Option<&dyn Fn(&str) -> String>,
    options: WireDtoOptions,
) -> RuleDto {
    let value = ace_encode
        .filter(|_| row.rule_type.is_hostlike())
        .map(|encode| encode(row.match_value.as_str()))
        .filter(|encoded| !encoded.is_empty())
        .unwrap_or_else(|| row.match_value.clone());

    let mut app_match = None;
    let address_match = match &row.rule_type {
        RuleType::ExactFqdn => Some(AddressMatchDto::ExactFqdn { value }),
        RuleType::SuffixDomain => Some(AddressMatchDto::SuffixDomain {
            suffix: value.strip_prefix("*.").unwrap_or(&value).to_owned(),
        }),
        RuleType::Zone => Some(AddressMatchDto::Zone { name: value }),
        // The address names its own family: only IPv6 text has a colon.
        RuleType::ExactIp | RuleType::ExactIpv4 | RuleType::ExactIpv6 => {
            Some(if value.contains(':') {
                AddressMatchDto::ExactIpv6 { address: value }
            } else {
                AddressMatchDto::ExactIpv4 { address: value }
            })
        }
        RuleType::Subnet => Some(AddressMatchDto::Subnet {
            network: js::trim(&value).to_owned(),
        }),
        RuleType::IpRange => Some(ip_range(&value)),
        RuleType::Application => {
            // A `*` makes it a pattern, exactly as the preset parser reads it.
            let pattern = if value.contains('*') {
                AppPatternDto::Glob { value }
            } else {
                AppPatternDto::Exact { value }
            };
            app_match = Some(AppMatchDto {
                pattern,
                include_child_processes: false,
            });
            None
        }
        RuleType::Domain | RuleType::Other(_) => Some(host_match(value)),
    };

    let origin = row
        .auto_origin()
        .filter(|_| options.keep_comment)
        .map(|origin| {
            RuleOrigin::auto(
                AutoRuleReason::from_slug(&origin.reason),
                origin.anchor.clone(),
                origin.added.clone(),
            )
        });

    RuleDto {
        id: if options.keep_id {
            row.id.clone()
        } else {
            String::new()
        },
        enabled: row.enabled,
        address_match,
        app_match,
        comment: if options.keep_comment {
            row.comment.clone()
        } else {
            String::new()
        },
        action: row.action(),
        origin,
    }
}

/// A `domain` value: `*.` marks a suffix, anything else is one exact name.
/// Reading it as exact regardless would leave `*.x` a literal no host matches.
fn host_match(value: String) -> AddressMatchDto {
    if let Some(suffix) = value.strip_prefix("*.") {
        return AddressMatchDto::SuffixDomain {
            suffix: suffix.to_owned(),
        };
    }
    AddressMatchDto::ExactFqdn { value }
}

/// `first-last`. Neither family's address text has a `-`; a value without
/// one keeps all of it in `first`, so the service refuses it by name.
fn ip_range(value: &str) -> AddressMatchDto {
    let (first, last) = value.split_once('-').unwrap_or((value, ""));
    AddressMatchDto::IpRange {
        first: js::trim(first).to_owned(),
        last: js::trim(last).to_owned(),
    }
}

/// An empty route slug from an older peer reads as primary.
fn wire_target_route(slug: &str) -> TargetRoute {
    if slug.is_empty() {
        TargetRoute::Primary
    } else {
        TargetRoute::from_slug(slug)
    }
}

/// A full file row from one `rules.list` entry (`fileRowFromServiceWire`), for
/// writing a rules file without a table to read. Keeps comment and
/// provenance — file content — and carries no id, as a file has none.
/// `ace_decode` turns the wire's ACE host back into the Unicode the rules file
/// stores.
pub fn file_row_from_service_wire(
    entry: &RuleRowEntry,
    ace_decode: impl Fn(&str) -> String,
) -> RuleRow {
    let rule_type = RuleType::from_slug(&entry.rule_type);
    let match_value = if rule_type.is_hostlike() {
        ace_decode(&entry.match_value)
    } else {
        entry.match_value.clone()
    };
    RuleRow {
        id: String::new(),
        enabled: entry.enabled,
        rule_type,
        match_value,
        target_route: wire_target_route(&entry.target_route),
        verify: entry.verify,
        comment: entry.comment.clone().unwrap_or_default(),
        origin: entry.origin.as_ref().map(|origin| RowOrigin {
            reason: origin.reason().as_slug().to_owned(),
            anchor: origin.anchor().to_owned(),
            added: origin.added().to_owned(),
        }),
    }
}

/// The routing part of one `rules.list` entry (`driftRowFromServiceWire`):
/// what moves a drift hash and nothing else.
pub fn drift_row_from_service_wire(entry: &RuleRowEntry) -> RuleRow {
    drift_row(
        entry.enabled,
        RuleType::from_slug(&entry.rule_type),
        entry.match_value.clone(),
        wire_target_route(&entry.target_route),
        entry.verify,
    )
}

/// The target a `preset.parse` rule takes when read from the rules file of
/// `file` (`parsedRuleTargetRoute`): `+block`, or the file's own route.
pub fn parsed_rule_target_route(rule: &ParsedRule, file: Route) -> TargetRoute {
    if rule.blocked {
        TargetRoute::Block
    } else {
        file.into()
    }
}

/// The `?` of a `preset.parse` rule (`parsedRuleVerify`), in either file. A
/// block takes none.
pub fn parsed_rule_verify(rule: &ParsedRule) -> bool {
    rule.verify_primary && !rule.blocked
}

/// The routing part of one `preset.parse` rule read from the rules file of
/// `file` (`driftRowFromParsedRule`).
pub fn drift_row_from_parsed_rule(rule: &ParsedRule, file: Route) -> RuleRow {
    drift_row(
        rule.enabled,
        RuleType::from_slug(rule.rule_type.slug()),
        rule.match_value.clone(),
        parsed_rule_target_route(rule, file),
        parsed_rule_verify(rule),
    )
}

fn drift_row(
    enabled: bool,
    rule_type: RuleType,
    match_value: String,
    target_route: TargetRoute,
    verify: bool,
) -> RuleRow {
    RuleRow {
        id: String::new(),
        enabled,
        rule_type,
        match_value,
        target_route,
        verify,
        comment: String::new(),
        origin: None,
    }
}
