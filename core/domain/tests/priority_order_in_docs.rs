//! The rule priority the user reads must be the one the engine runs.
//!
//! The order is derived from `match_sample`, not restated: one rule of every
//! kind matches the same destination, and the winner is removed until only the
//! default route is left. Each document's list is read in its own order and
//! every entry is classified by its first example value, so the check does not
//! depend on the language of the page.

#![allow(clippy::expect_used, clippy::panic)]

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use nrr_domain::canonical::{
    CanonicalAddressMatch, CanonicalAppMatch, CanonicalAppPattern, CanonicalRule,
    CanonicalRuleBook, CanonicalRuleSet,
};
use nrr_domain::decision_engine_input::match_sample;
use nrr_domain::decision_matching::{RequestedRouteDecision, ZonePriorityPolicy};
use nrr_domain::{RouteBehaviorMode, RuleAction, RuleId};
use nrr_shared::ip_block::{IpBlock, IpRange};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    ExactDomain,
    Subdomains,
    ExactIp,
    Network,
    Zone,
    Application,
    Default,
}

const HOST: &str = "h.example.ru";
const ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
const PROCESS: &str = "app.exe";

fn rule(id: &str, address: Option<CanonicalAddressMatch>) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.to_string()),
        enabled: true,
        app_match: address.is_none().then(|| CanonicalAppMatch {
            pattern: CanonicalAppPattern::Exact(PROCESS.to_string()),
            include_child_processes: false,
        }),
        address_match: address,
        comment: String::new(),
        action: RuleAction::Route,
        origin: None,
    }
}

fn kind_of(rule: &CanonicalRule) -> Kind {
    match &rule.address_match {
        Some(CanonicalAddressMatch::ExactFqdn(_)) => Kind::ExactDomain,
        Some(CanonicalAddressMatch::SuffixDomain(_)) => Kind::Subdomains,
        Some(CanonicalAddressMatch::ExactIp(_)) => Kind::ExactIp,
        Some(CanonicalAddressMatch::Subnet(_) | CanonicalAddressMatch::IpRange(_)) => Kind::Network,
        Some(CanonicalAddressMatch::Zone(_)) => Kind::Zone,
        None => Kind::Application,
    }
}

fn engine_order() -> Vec<Kind> {
    let range = IpRange::parse("192.0.2.0-192.0.2.200").expect("range parses");
    let mut rules = vec![
        rule("f", Some(CanonicalAddressMatch::ExactFqdn(HOST.into()))),
        rule(
            "s",
            Some(CanonicalAddressMatch::SuffixDomain("example.ru".into())),
        ),
        rule("i", Some(CanonicalAddressMatch::ExactIp(ADDRESS))),
        rule(
            "n",
            Some(CanonicalAddressMatch::Subnet(
                IpBlock::parse("192.0.2.0/24").expect("subnet parses"),
            )),
        ),
        rule("r", Some(CanonicalAddressMatch::ip_range(range))),
        rule("z", Some(CanonicalAddressMatch::Zone("ru".into()))),
        rule("a", None),
    ];
    let mut order: Vec<Kind> = Vec::new();
    loop {
        let book = CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(rules.clone()),
            secondary: CanonicalRuleSet::from_rules(Vec::new()),
        };
        let decision = match_sample(
            &book,
            Some(HOST),
            Some(ADDRESS),
            Some(PROCESS),
            ZonePriorityPolicy::default(),
            RouteBehaviorMode::PreferPrimary,
        );
        let RequestedRouteDecision::MatchedRoute { candidate } = decision else {
            order.push(Kind::Default);
            assert!(rules.is_empty(), "rules the engine never picked: {rules:?}");
            return order;
        };
        let at = rules
            .iter()
            .position(|r| r.id == candidate.rule_id)
            .expect("the winner is in the book");
        let kind = kind_of(&rules.remove(at));
        // A subnet and a range share one tier.
        if order.last() != Some(&kind) {
            order.push(kind);
        }
    }
}

/// The kind of rule a document entry describes, from its first example value;
/// an entry with no example is the default route.
fn classify(entry: &str) -> Kind {
    let Some(example) = entry.split('`').nth(1) else {
        return Kind::Default;
    };
    let is_ip = |text: &str| text.trim().parse::<IpAddr>().is_ok();
    if example.ends_with(".exe") {
        Kind::Application
    } else if example.starts_with("*.") {
        Kind::Subdomains
    } else if example.starts_with('.') || !example.contains('.') {
        Kind::Zone
    } else if example.contains('/')
        || example
            .split_once('-')
            .is_some_and(|(first, last)| is_ip(first) && is_ip(last))
    {
        Kind::Network
    } else if is_ip(example) {
        Kind::ExactIp
    } else {
        Kind::ExactDomain
    }
}

fn read_doc(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .replace("\r\n", "\n")
}

/// Lines from `heading` to the next heading.
fn section<'a>(text: &'a str, heading: &str) -> Vec<&'a str> {
    let mut lines = text.lines().skip_while(|l| l.trim_end() != heading);
    assert!(lines.next().is_some(), "heading `{heading}` not found");
    lines.take_while(|l| !l.starts_with('#')).collect()
}

fn listed_order(relative: &str, heading: &str, is_entry: fn(&str) -> bool) -> Vec<Kind> {
    let text = read_doc(relative);
    section(&text, heading)
        .into_iter()
        .filter(|l| is_entry(l))
        .map(classify)
        .collect()
}

fn numbered_table_row(line: &str) -> bool {
    line.split('|')
        .nth(1)
        .is_some_and(|cell| cell.trim().parse::<u8>().is_ok())
}

fn numbered_list_item(line: &str) -> bool {
    line.split_once(". ")
        .is_some_and(|(n, _)| n.parse::<u8>().is_ok())
}

fn table_row_with_example(line: &str) -> bool {
    line.starts_with('|') && line.contains('`')
}

#[test]
fn readme_lists_the_engine_order() {
    let expected = engine_order();
    for (doc, heading) in [
        ("README.md", "## How routing decisions are made"),
        ("README_RU.md", "## Как принимаются решения о маршруте"),
    ] {
        assert_eq!(
            listed_order(doc, heading, numbered_table_row),
            expected,
            "{doc}"
        );
    }
}

#[test]
fn rules_file_format_lists_the_engine_order() {
    let expected = engine_order();
    for (doc, heading) in [
        (
            "docs/en/rules-file-format.md",
            "### 1.5 Rule evaluation priority",
        ),
        (
            "docs/ru/rules-file-format.md",
            "### 1.5 Приоритет оценки правил",
        ),
    ] {
        assert_eq!(
            listed_order(doc, heading, numbered_list_item),
            expected,
            "{doc}"
        );
    }
}

#[test]
fn quickstart_lists_rule_types_strongest_first() {
    let mut expected = engine_order();
    expected.retain(|k| *k != Kind::Default);
    for (doc, heading) in [
        ("docs/en/quickstart.md", "## Rules: how it works"),
        ("docs/ru/quickstart.md", "## Правила: как это работает"),
    ] {
        assert_eq!(
            listed_order(doc, heading, table_row_with_example),
            expected,
            "{doc}"
        );
    }
}

#[test]
fn the_engine_runs_the_narrower_rule_first() {
    assert_eq!(
        engine_order(),
        [
            Kind::ExactDomain,
            Kind::Subdomains,
            Kind::ExactIp,
            Kind::Network,
            Kind::Zone,
            Kind::Application,
            Kind::Default,
        ]
    );
}
