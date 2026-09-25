//! The overlaps screen must name the rule the engine actually picks. The
//! detector lives in `nrr-shared` so the launcher can run it on the rules on
//! screen; this pins every winner it reports against `match_sample`.

#![allow(clippy::expect_used, clippy::panic)]

use nrr_domain::decision_engine_input::match_sample;
use nrr_domain::decision_matching::{RequestedRouteDecision, ZonePriorityPolicy};
use nrr_domain::rules_json_codec::decode;
use nrr_domain::RouteBehaviorMode;
use nrr_shared::rules_json::{
    AddressMatchDto, CanonicalRulesJsonV1, RuleAction, RuleDto, RULES_JSON_SCHEMA_VERSION,
};
use nrr_shared::rules_overlap::find_route_overlaps;
use nrr_shared::RouteRole;

fn rule(id: &str, address_match: AddressMatchDto) -> RuleDto {
    RuleDto {
        id: id.to_string(),
        enabled: true,
        address_match: Some(address_match),
        app_match: None,
        comment: String::new(),
        action: RuleAction::Route,
        origin: None,
    }
}

fn exact(id: &str, value: &str) -> RuleDto {
    rule(
        id,
        AddressMatchDto::ExactFqdn {
            value: value.into(),
        },
    )
}

fn suffix(id: &str, suffix: &str) -> RuleDto {
    rule(
        id,
        AddressMatchDto::SuffixDomain {
            suffix: suffix.into(),
        },
    )
}

fn zone(id: &str, name: &str) -> RuleDto {
    rule(id, AddressMatchDto::Zone { name: name.into() })
}

#[test]
fn every_reported_winner_is_the_engines_winner() {
    let dto = CanonicalRulesJsonV1 {
        schema_version: RULES_JSON_SCHEMA_VERSION,
        primary: vec![
            zone("P1", "example"),
            suffix("P2", "ai.search.example"),
            exact("P3", "dup.example"),
            suffix("P4", "longer.zone.test"),
        ],
        secondary: vec![
            exact("S1", "www.site.example"),
            suffix("S2", "search.example"),
            suffix("S3", "example"),
            exact("S4", "dup.example"),
            zone("S5", "test"),
        ],
    };
    let found = find_route_overlaps(&dto, false);
    assert!(found.len() >= 5, "{found:?}");
    for overlap in &found {
        // The screen states a pairwise fact, so the engine is asked about a
        // book holding only the two rules of the pair.
        let pick = |side: &nrr_shared::rules_overlap::OverlapRule| {
            let set = if side.route == "primary" {
                &dto.primary
            } else {
                &dto.secondary
            };
            set.iter()
                .find(|r| r.id == side.rule_id)
                .cloned()
                .expect("reported rule is in its set")
        };
        let mut pair = CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: Vec::new(),
            secondary: Vec::new(),
        };
        for side in [&overlap.winner, &overlap.loser] {
            let target = if side.route == "primary" {
                &mut pair.primary
            } else {
                &mut pair.secondary
            };
            target.push(pick(side));
        }
        let book = decode(pair).expect("pair decodes").rule_book;
        let host = match overlap.winner.rule_type.as_str() {
            "exact-fqdn" => overlap.winner.value.clone(),
            _ if overlap.loser.rule_type == "exact-fqdn" => overlap.loser.value.clone(),
            _ => format!("x.{}", overlap.winner.value),
        };
        let decision = match_sample(
            &book,
            Some(&host),
            None,
            None,
            ZonePriorityPolicy::default(),
            RouteBehaviorMode::PreferPrimary,
        );
        let RequestedRouteDecision::MatchedRoute { candidate } = decision else {
            panic!("{host} matched nothing");
        };
        assert_ne!(
            candidate.rule_id.as_str(),
            overlap.loser.rule_id,
            "{host}: {overlap:?}"
        );
        let expected = if overlap.winner.route == "primary" {
            RouteRole::Primary
        } else {
            RouteRole::Secondary
        };
        assert_eq!(candidate.route_role, expected, "{host}: {overlap:?}");
    }
}
