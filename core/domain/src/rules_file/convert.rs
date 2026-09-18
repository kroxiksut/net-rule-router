// Between the file shape and the canonical rule set.

use super::*;

/// Converts a [`RulesFileParsed`] into a [`crate::RouteRuleSet`] for one route.
///
/// This is the bridge between the parse stage and the semantic
/// validation pipeline. The returned `RouteRuleSet` can be placed
/// into an [`crate::ActiveConfiguration`] and passed to
/// [`crate::validation::validate_and_canonicalize`].
///
/// Only sections that are active on `platform` are converted. Sections for
/// other platforms are skipped.
///
/// # Rule IDs
///
/// Parse-time IDs use the short format `"r-{index:04}"` (rendered `R-NNNN`
/// in the GUI). They are stable within a single parse run but not across
/// runs, and are route-local (primary and secondary each start at `r-0000`).
///
/// # `include_child_processes`
///
/// This is a global GUI setting, not a per-rule file attribute. The caller
/// passes the current value; it is applied uniformly to all application rules.
pub fn rules_file_to_route_rule_set(
    parsed: &RulesFileParsed,
    platform: HostPlatform,
    include_child_processes: bool,
) -> crate::RouteRuleSet {
    use crate::{AddressMatch, AppMatch, AppMatchPattern, Rule, RuleId};

    let mut rules = Vec::new();
    let mut global_idx: usize = 0;

    for section_content in parsed.active_sections_for(platform) {
        let section = section_content.section;
        for entry in &section_content.entries {
            // Short, route-local id (`r-0001`, rendered `R-0001` in the GUI),
            // matching `nrr_shared::preset_parser`'s `R-{:04}` scheme. The
            // section is shown in the rule-type column, so it does not need
            // to live in the id.
            let id = RuleId(format!("r-{global_idx:04}"));
            global_idx += 1;

            let (address_match, app_match) = match section {
                RulesFileSection::Zones => (
                    // Zones accept `*.ru` and `ru` — both are valid inputs.
                    // The validator strips the `*.` prefix during normalization.
                    Some(AddressMatch::Zone(entry.match_value.clone())),
                    None,
                ),
                // `Auto` shares the domain value grammar — it separates
                // authorship, not match kinds.
                RulesFileSection::Domains | RulesFileSection::Auto => {
                    // `*.example.com` → SuffixDomain (stored without `*.` prefix).
                    // `example.com` → ExactFqdn.
                    let addr_match = if let Some(label) = entry.match_value.strip_prefix("*.") {
                        AddressMatch::SuffixDomain(label.to_string())
                    } else {
                        AddressMatch::ExactFqdn(entry.match_value.clone())
                    };
                    (Some(addr_match), None)
                }
                RulesFileSection::Ip => {
                    let addr = entry.match_value.parse::<std::net::IpAddr>().ok();
                    match addr {
                        Some(ip) => (Some(AddressMatch::ExactIp(ip)), None),
                        // Unparseable IP — pass through as ExactFqdn so the
                        // semantic validator can produce a proper diagnostic.
                        None => (
                            Some(AddressMatch::ExactFqdn(entry.match_value.clone())),
                            None,
                        ),
                    }
                }
                // Platform-specific app sections.
                RulesFileSection::Windows | RulesFileSection::Linux | RulesFileSection::MacOS => {
                    let pattern = if entry.match_value.contains('*') {
                        AppMatchPattern::Glob(entry.match_value.clone())
                    } else {
                        AppMatchPattern::Exact(entry.match_value.clone())
                    };
                    (
                        None,
                        Some(AppMatch {
                            pattern,
                            include_child_processes,
                            windows_service_name: None,
                        }),
                    )
                }
            };

            rules.push(Rule {
                id,
                enabled: entry.enabled,
                address_match,
                app_match,
                comment: entry.inline_comment.clone().unwrap_or_default(),
                action: if entry.blocked {
                    crate::RuleAction::Block
                } else {
                    crate::RuleAction::Route
                },
                origin: entry.origin.clone(),
            });
        }
    }

    crate::RouteRuleSet { rules }
}

// ── CanonicalRuleSet → RulesFileParsed converter ──────────────────────────────

/// Converts a [`crate::CanonicalRuleSet`] into a [`RulesFileParsed`] suitable
/// for [`write_rules_file`]. Inverse of the parser+canonicalize pipeline for
/// the subset of canonical rules that map back to the Free-edition section
/// model.
///
/// # Section mapping
///
/// | Canonical address kind     | File section | Match value rendering |
/// |----------------------------|--------------|-----------------------|
/// | `ExactFqdn(label)`         | `Domains`    | `label`               |
/// | `SuffixDomain(label)`      | `Domains`    | `*.label`             |
/// | `Zone(name)`               | `Zones`      | `name`                |
/// | `ExactIp(addr)`            | `IP`         | `addr.to_string()`    |
/// | (app match, no address)    | `host_app_section` | `pattern.as_str()` |
///
/// A rule carrying an [`nrr_shared::auto_rule::RuleOrigin`] overrides the
/// address-kind mapping for the two domain kinds and lands in `Auto` instead,
/// with its provenance rendered into the inline comment.
///
/// # `host_app_section`
///
/// Free-edition canonical rules don't carry a platform tag — app match
/// values were normalized assuming the current host. Callers pass the
/// section header that matches the host (`RulesFileSection::Windows`
/// on Windows, `Linux` / `MacOS` elsewhere). On a non-matching host the
/// parser would skip these rules; round-trip is host-local only.
///
/// # Section ordering
///
/// Sections appear in canonical order (Zones → Auto) regardless of input
/// rule order. Sections with no rules are omitted (matches the writer's
/// "only sections present" semantics).
///
/// # Empty section behaviour
///
/// If the rule set contains no rules for a section, that section is **not**
/// emitted in the returned `RulesFileParsed`. Callers that want the full
/// section skeleton (docs/en/rules-file-format.md Sections "self-documenting") must pad with
/// empty `SectionContent` entries themselves.
pub fn canonical_rule_set_to_rules_file_parsed(
    set: &crate::canonical::CanonicalRuleSet,
    host_app_section: RulesFileSection,
) -> RulesFileParsed {
    use crate::canonical::{CanonicalAddressMatch, CanonicalAppPattern};

    let mut zones: Vec<RulesFileEntry> = Vec::new();
    let mut domains: Vec<RulesFileEntry> = Vec::new();
    let mut ips: Vec<RulesFileEntry> = Vec::new();
    let mut apps: Vec<RulesFileEntry> = Vec::new();
    let mut auto: Vec<RulesFileEntry> = Vec::new();

    for rule in set.rules() {
        let comment = if rule.comment.is_empty() {
            None
        } else {
            Some(rule.comment.clone())
        };
        let blocked = matches!(rule.action, crate::RuleAction::Block);

        if let Some(addr) = &rule.address_match {
            // App-authored rules are emitted under `--- Auto`, which carries
            // domain-style values only. An IP or a zone written there would be
            // re-read as a hostname on the next load, so those keep their
            // natural section — a combination the authoring path never
            // produces, since it only learns hostnames.
            let app_authored = rule.origin.is_some()
                && matches!(
                    addr,
                    CanonicalAddressMatch::ExactFqdn(_) | CanonicalAddressMatch::SuffixDomain(_)
                );
            let (bucket, value) = match addr {
                CanonicalAddressMatch::ExactFqdn(label) => (
                    if app_authored {
                        &mut auto
                    } else {
                        &mut domains
                    },
                    label.clone(),
                ),
                CanonicalAddressMatch::SuffixDomain(label) => (
                    if app_authored {
                        &mut auto
                    } else {
                        &mut domains
                    },
                    format!("*.{label}"),
                ),
                CanonicalAddressMatch::Zone(name) => (&mut zones, name.clone()),
                CanonicalAddressMatch::ExactIp(addr) => (&mut ips, addr.to_string()),
            };
            bucket.push(RulesFileEntry {
                match_value: value,
                inline_comment: comment,
                enabled: rule.enabled,
                blocked,
                origin: if app_authored {
                    rule.origin.clone()
                } else {
                    None
                },
            });
        } else if let Some(app) = &rule.app_match {
            let value = match &app.pattern {
                CanonicalAppPattern::Exact(s) | CanonicalAppPattern::Glob(s) => s.clone(),
            };
            apps.push(RulesFileEntry {
                match_value: value,
                inline_comment: comment,
                enabled: rule.enabled,
                blocked,
                origin: None,
            });
        }
        // CanonicalRule with neither address_match nor app_match cannot
        // occur — the validation pipeline enforces "at least one of the
        // two is Some" before a rule reaches a CanonicalRuleSet. We
        // silently skip such a rule if encountered (defensive).
    }

    let mut sections = Vec::new();
    if !zones.is_empty() {
        sections.push(SectionContent {
            section: RulesFileSection::Zones,
            entries: zones,
        });
    }
    if !domains.is_empty() {
        sections.push(SectionContent {
            section: RulesFileSection::Domains,
            entries: domains,
        });
    }
    if !ips.is_empty() {
        sections.push(SectionContent {
            section: RulesFileSection::Ip,
            entries: ips,
        });
    }
    if !apps.is_empty() {
        sections.push(SectionContent {
            section: host_app_section,
            entries: apps,
        });
    }
    if !auto.is_empty() {
        sections.push(SectionContent {
            section: RulesFileSection::Auto,
            entries: auto,
        });
    }

    RulesFileParsed { sections }
}

// ── RulesFileParsed → text writer ─────────────────────────────────────────────
