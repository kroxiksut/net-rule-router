#![allow(clippy::expect_used)]

//! A rule book a newer build wrote, read by this one. Whatever it cannot read
//! is kept aside verbatim; it never turns the whole book into "no rules".

use nrr_shared::rules_json::{
    from_canonical_string, required_schema_version, to_canonical_string, AppPatternDto, RuleAction,
    RULES_JSON_SCHEMA_VERSION,
};

/// One rule this build can apply, carrying an origin kind and a field it has
/// never heard of, then one rule per thing it cannot read: an application
/// pattern kind, an action and an address kind.
const NEWER_BOOK: &str = r#"{
  "schema-version": 999,
  "primary": [
    {
      "id": "r-known",
      "enabled": true,
      "address-match": { "kind": "exact-fqdn", "value": "known.example" },
      "origin": { "kind": "imported-from-a-list", "list": "vendor" },
      "added-by-a-newer-build": { "nested": [1, 2] }
    },
    {
      "id": "r-app",
      "enabled": true,
      "app-match": {
        "pattern": { "kind": "signed-by", "publisher": "Example Publisher" },
        "include-child-processes": false
      }
    }
  ],
  "secondary": [
    {
      "id": "r-action",
      "enabled": true,
      "address-match": { "kind": "zone", "name": "example" },
      "action": "tarpit"
    },
    {
      "id": "r-kind",
      "enabled": true,
      "address-match": { "kind": "port-span", "from": 80, "to": 90 }
    }
  ]
}"#;

#[test]
fn the_rules_it_can_read_stay_rules_and_the_rest_is_set_aside() {
    let book = from_canonical_string(NEWER_BOOK).expect("a newer book still reads");

    let known = &book.primary[0];
    assert!(!known.is_unrecognized(), "{known:?}");
    assert_eq!(known.origin, None, "an unknown origin reads as the user's");

    let unreadable: Vec<&str> = book
        .primary
        .iter()
        .chain(&book.secondary)
        .filter(|rule| rule.is_unrecognized())
        .map(|rule| rule.id.as_str())
        .collect();
    assert_eq!(unreadable, ["r-app", "r-action", "r-kind"]);

    // Newer, not broken: none of them is refused as a damaged payload.
    let app = book.primary[1].app_match.as_ref().expect("app match");
    assert!(matches!(app.pattern, AppPatternDto::Unrecognized(_)));
    assert_eq!(
        book.secondary[0].action,
        RuleAction::Unrecognized("tarpit".into())
    );
    assert!(!book.secondary[0].action.is_malformed());
    let kind = book.secondary[1].address_match.as_ref().expect("address");
    assert_eq!(kind.kind(), "port-span");
    assert!(!kind.is_malformed());
}

#[test]
fn a_rewrite_keeps_what_it_cannot_read_and_does_not_claim_an_older_schema() {
    let book = from_canonical_string(NEWER_BOOK).expect("decodes");
    let written = to_canonical_string(&book).expect("encodes");
    let again = from_canonical_string(&written).expect("decodes again");

    assert_eq!(again, book, "nothing set aside is lost on the way back");
    assert!(
        written.contains(r#""publisher":"Example Publisher""#),
        "{written}"
    );
    assert!(written.contains(r#""action":"tarpit""#), "{written}");

    // Each unknown kind alone is enough for the newest schema this book names.
    for rule in book.primary.iter().chain(&book.secondary).skip(1) {
        let alone = nrr_shared::rules_json::CanonicalRulesJsonV1 {
            schema_version: 999,
            primary: vec![rule.clone()],
            secondary: Vec::new(),
        };
        assert_eq!(required_schema_version(&alone), 999, "{rule:?}");
    }
    let only_known = nrr_shared::rules_json::CanonicalRulesJsonV1 {
        schema_version: 999,
        primary: vec![book.primary[0].clone()],
        secondary: Vec::new(),
    };
    assert!(required_schema_version(&only_known) <= RULES_JSON_SCHEMA_VERSION);
}
