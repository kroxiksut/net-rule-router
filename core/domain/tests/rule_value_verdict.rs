//! The rules table, the Add/Edit dialog and the service's acceptance of a
//! revision judge a rule value by the same pipeline the service imports rules
//! with. Every row pins the verdict and checks it against that pipeline, fed
//! the way the rules file feeds it.

#![allow(clippy::expect_used, clippy::panic)]

use nrr_domain::canonical::CanonicalAddressMatch;
use nrr_domain::preset_canonicalize::{canonicalize_preset_rules, PresetRulesCanonicalizeOutcome};
use nrr_domain::rule_value_validation::{
    drop_rules_refused_outright, rules_with_refused_values, validate_rule_value, RefusedRuleValue,
};
use nrr_domain::rules_file::{parse_rules_file, HostPlatform};
use nrr_domain::rules_json_codec::decode;
use nrr_domain::rules_json_codec::encode;
use nrr_domain::validation::ValidationWarning;
use nrr_shared::rules_json::{
    AddressMatchDto, AppMatchDto, AppPatternDto, CanonicalRulesJsonV1, RuleAction, RuleDto,
    RULES_JSON_SCHEMA_VERSION,
};
use nrr_shared::RouteRole;

/// `(rule type, value, verdict)`. The value is what the user types.
fn rows() -> Vec<(&'static str, String, &'static str)> {
    let long_ascii = "abcdef.".repeat(40) + "com";
    // Under 253 bytes as typed, over it once punycoded.
    let long_idn = ["中"; 40].join(".");
    let mut rows: Vec<(&'static str, String, &'static str)> = [
        ("domain", "example.com", "valid"),
        ("domain", "Example.COM", "valid"),
        ("domain", "example.com.", "valid"),
        ("domain", "*.example.com", "valid"),
        ("domain", "*.example.com.", "valid"),
        ("domain", "пример.рф", "valid"),
        ("domain", "db_srv.corp.intra", "valid"),
        ("domain", ".example.com", "error"),
        ("domain", "example..com", "error"),
        ("domain", "192.168.1.1", "error"),
        ("domain", "2001:db8::1", "error"),
        ("domain", "192.168.1.0/24", "error"),
        ("domain", "foo.*.bar", "error"),
        ("domain", "*.", "error"),
        ("domain", "hello world", "error"),
        ("zone", "ru", "valid"),
        ("zone", ".ru", "valid"),
        ("zone", "ru.", "valid"),
        ("zone", "*.ru", "valid"),
        ("zone", "рф", "valid"),
        ("zone", ".рф", "valid"),
        ("zone", "corp.internal", "valid"),
        ("zone", "123", "error"),
        ("zone", "-ru", "error"),
        ("zone", "..ru", "error"),
        ("zone", ".", "error"),
        ("exact-ip", "203.0.113.7", "valid"),
        ("exact-ip", "2001:db8::7", "valid"),
        ("exact-ip", "::ffff:192.0.2.1", "valid"),
        ("exact-ip", "1.0.0.1", "valid"),
        ("exact-ip", "100.64.0.1", "valid"),
        ("exact-ip", "169.253.255.255", "valid"),
        ("exact-ip", "0.0.0.0", "error"),
        ("exact-ip", "0.1.2.3", "error"),
        ("exact-ip", "0.255.255.255", "error"),
        ("exact-ip", "255.255.255.255", "error"),
        ("exact-ip", "::", "error"),
        ("exact-ip", "::ffff:0.0.0.0", "error"),
        ("exact-ip", "::ffff:255.255.255.255", "error"),
        ("exact-ip", "127.0.0.1", "warning"),
        ("exact-ip", "::1", "warning"),
        ("exact-ip", "224.0.0.1", "warning"),
        ("exact-ip", "239.255.255.250", "warning"),
        ("exact-ip", "ff02::fb", "warning"),
        ("exact-ip", "169.254.1.1", "warning"),
        ("exact-ip", "fe80::1", "warning"),
        ("exact-ip", "300.1.1.1", "error"),
        ("exact-ip", "010.1.1.1", "error"),
        ("exact-ip", "192.168.1.0/24", "error"),
        ("exact-ip", "10.0.0.1-10.0.0.9", "error"),
        ("exact-ip", "abc.def", "error"),
        ("exact-ip", "example.com", "error"),
        ("application", "browser.exe", "valid"),
        ("application", "Messenger", "valid"),
        ("application", "*vpn*.exe", "valid"),
        ("application", "браузер.exe", "valid"),
        ("application", "C:\\Apps\\app.exe", "valid"),
        ("application", "/usr/bin/app", "valid"),
        ("application", "app:1.exe", "valid"),
        ("application", "a?b.exe", "valid"),
        ("application", "*", "error"),
        ("application", "app\u{1}.exe", "error"),
    ]
    .into_iter()
    .map(|(t, v, verdict)| (t, v.to_string(), verdict))
    .collect();
    rows.push(("domain", long_ascii.clone(), "error"));
    rows.push(("zone", long_ascii, "error"));
    rows.push(("domain", long_idn.clone(), "error"));
    rows.push(("zone", long_idn, "error"));
    rows.push(("application", "a".repeat(260), "valid"));
    rows.push(("application", "a".repeat(261), "error"));
    rows
}

fn stored_value(address: Option<&CanonicalAddressMatch>, app: Option<&str>) -> String {
    match address {
        Some(
            CanonicalAddressMatch::Zone(v)
            | CanonicalAddressMatch::ExactFqdn(v)
            | CanonicalAddressMatch::SuffixDomain(v),
        ) => v.clone(),
        Some(other) => other.to_display_string(),
        None => app.expect("an application rule").to_string(),
    }
}

/// What the service's import does with the value: `Some(canonical)` when it
/// keeps the rule, `None` when it refuses the file or drops the rule.
fn pipeline(rule_type: &str, value: &str) -> Option<String> {
    let section = match rule_type {
        "zone" => "Zones",
        "domain" => "Domains",
        "exact-ip" => "IP",
        "application" => "Windows",
        other => panic!("unknown rule type: {other}"),
    };
    let parsed = parse_rules_file(&format!("--- {section}\n{value}\n"));
    match canonicalize_preset_rules(&parsed, RouteRole::Primary, HostPlatform::Windows, false) {
        PresetRulesCanonicalizeOutcome::Rejected { .. } => None,
        outcome => {
            let set = outcome.rule_set().expect("accepted");
            set.rules().first().map(|rule| {
                stored_value(
                    rule.address_match.as_ref(),
                    rule.app_match.as_ref().map(|a| a.pattern.as_str()),
                )
            })
        }
    }
}

#[test]
fn the_row_verdict_is_the_import_pipeline_verdict() {
    for (rule_type, value, expected) in rows() {
        let verdict = validate_rule_value(rule_type, &value);
        assert_eq!(
            verdict.status_slug(),
            expected,
            "{rule_type} {value:?}: {verdict:?}"
        );
        assert_eq!(
            verdict.is_error(),
            pipeline(rule_type, &value).is_none(),
            "{rule_type} {value:?}: the row verdict and the pipeline disagree"
        );
    }
}

/// A rule as the GUI sends it over the wire.
fn wire_rule(id: &str, rule_type: &str, value: &str) -> RuleDto {
    let mut rule = RuleDto {
        id: id.into(),
        enabled: true,
        address_match: None,
        app_match: None,
        comment: String::new(),
        action: RuleAction::Route,
        origin: None,
    };
    match rule_type {
        "zone" => {
            rule.address_match = Some(AddressMatchDto::Zone { name: value.into() });
        }
        "domain" => {
            rule.address_match = Some(match value.strip_prefix("*.") {
                Some(suffix) => AddressMatchDto::SuffixDomain {
                    suffix: suffix.into(),
                },
                None => AddressMatchDto::ExactFqdn {
                    value: value.into(),
                },
            });
        }
        "exact-ip" => {
            rule.address_match = Some(if value.contains(':') {
                AddressMatchDto::ExactIpv6 {
                    address: value.into(),
                }
            } else {
                AddressMatchDto::ExactIpv4 {
                    address: value.into(),
                }
            });
        }
        _ => {
            rule.app_match = Some(AppMatchDto {
                pattern: if value.contains('*') {
                    AppPatternDto::Glob {
                        value: value.into(),
                    }
                } else {
                    AppPatternDto::Exact {
                        value: value.into(),
                    }
                },
                include_child_processes: false,
            });
        }
    }
    rule
}

fn book(primary: Vec<RuleDto>) -> CanonicalRulesJsonV1 {
    CanonicalRulesJsonV1 {
        schema_version: RULES_JSON_SCHEMA_VERSION,
        primary,
        secondary: vec![],
    }
}

/// The GUI saves over the wire, not through the rules file: a value shown as
/// valid must reach storage in the spelling the pipeline would have given it,
/// or `.ru` is kept as typed and never matches.
#[test]
fn a_valid_value_saved_over_the_wire_is_stored_as_the_pipeline_spells_it() {
    for (rule_type, value, expected) in rows() {
        if expected == "error" {
            continue;
        }
        let content = decode(
            book(vec![wire_rule("r-1", rule_type, &value)]),
            HostPlatform::Windows,
        )
        .expect("decode");
        let rule = &content.rule_book.primary.rules()[0];
        let stored = stored_value(
            rule.address_match.as_ref(),
            rule.app_match.as_ref().map(|a| a.pattern.as_str()),
        );
        assert_eq!(
            Some(stored),
            pipeline(rule_type, &value),
            "{rule_type} {value:?}"
        );
    }
}

/// The service refuses a new revision by the same verdict, naming each
/// refused row and its value — a wire-sendable one, at least: the decoder
/// already refuses an address it cannot read.
#[test]
fn the_service_refuses_exactly_the_rows_the_table_marks_as_errors() {
    let wire_rows: Vec<_> = rows()
        .into_iter()
        .filter(|(rule_type, value, _)| {
            *rule_type != "exact-ip" || value.parse::<std::net::IpAddr>().is_ok()
        })
        .enumerate()
        .map(|(i, (rule_type, value, expected))| (format!("r-{i:04}"), rule_type, value, expected))
        .collect();
    let submitted = book(
        wire_rows
            .iter()
            .map(|(id, rule_type, value, _)| wire_rule(id, rule_type, value))
            .collect(),
    );
    let expected: Vec<RefusedRuleValue> = wire_rows
        .iter()
        .filter(|(.., verdict)| *verdict == "error")
        .map(|(id, _, value, _)| RefusedRuleValue {
            rule_id: id.clone(),
            value: value.to_string(),
        })
        .collect();
    assert!(!expected.is_empty());
    assert_eq!(rules_with_refused_values(&submitted, None), expected);
}

fn refused_ids(refused: Vec<RefusedRuleValue>) -> Vec<String> {
    refused.into_iter().map(|r| r.rule_id).collect()
}

/// A refused value the book in force already holds is not new, so the edit
/// that carries it along is accepted; the same value added anew is not.
#[test]
fn a_refused_value_already_in_force_is_spared() {
    let carried = book(vec![
        wire_rule("r-0000", "domain", "192.168.1.1"),
        wire_rule("r-0001", "zone", "ru"),
    ]);
    let edited = book(vec![
        wire_rule("r-0000", "domain", "192.168.1.1"),
        wire_rule("r-0001", "zone", "ru"),
        wire_rule("r-0002", "domain", "example.com"),
    ]);
    assert!(rules_with_refused_values(&edited, Some(&carried)).is_empty());

    let added = book(vec![
        wire_rule("r-0000", "domain", "192.168.1.1"),
        wire_rule("r-0001", "zone", "123"),
    ]);
    assert_eq!(
        rules_with_refused_values(&added, Some(&carried)),
        vec![RefusedRuleValue {
            rule_id: "r-0001".into(),
            value: "123".into(),
        }]
    );
    assert_eq!(
        refused_ids(rules_with_refused_values(&added, None)),
        vec!["r-0000".to_string(), "r-0001".to_string()]
    );
}

/// The per-row message names why the address is refused or unusual.
#[test]
fn the_address_class_is_named_in_the_verdict() {
    for (value, key) in [
        ("0.0.0.0", "match-value-invalid.exact-ip-this-host"),
        ("0.1.2.3", "match-value-invalid.exact-ip-this-host"),
        ("::", "match-value-invalid.exact-ip-this-host"),
        ("255.255.255.255", "match-value-invalid.exact-ip-broadcast"),
        ("127.0.0.1", "match-value-warning.exact-ip-loopback"),
        ("ff02::fb", "match-value-warning.exact-ip-multicast"),
        ("169.254.1.1", "match-value-warning.exact-ip-link-local"),
        ("fe80::1", "match-value-warning.exact-ip-link-local"),
    ] {
        let verdict = validate_rule_value("exact-ip", value);
        assert_eq!(
            verdict.message_key(),
            format!("rules.validation.{key}"),
            "{value}"
        );
    }
}

/// A stored book with a rule on no destination loads without exactly that
/// rule, and saving what was read does not bring it back.
#[test]
fn a_stored_book_drops_its_rules_on_no_destination_and_keeps_the_rest() {
    let mut stored = CanonicalRulesJsonV1 {
        schema_version: RULES_JSON_SCHEMA_VERSION,
        primary: vec![
            wire_rule("r-1", "exact-ip", "203.0.113.7"),
            wire_rule("r-2", "exact-ip", "255.255.255.255"),
            wire_rule("r-3", "domain", "example.com"),
        ],
        secondary: vec![
            wire_rule("r-4", "exact-ip", "169.254.1.1"),
            wire_rule("r-5", "exact-ip", "::"),
        ],
    };
    // Unread, the book cannot be decoded: the decoder refuses the address.
    assert!(decode(stored.clone(), HostPlatform::Windows).is_err());

    let dropped = drop_rules_refused_outright(&mut stored);
    assert_eq!(
        dropped,
        vec![
            RefusedRuleValue {
                rule_id: "r-2".into(),
                value: "255.255.255.255".into(),
            },
            RefusedRuleValue {
                rule_id: "r-5".into(),
                value: "::".into(),
            },
        ]
    );
    let read = decode(stored, HostPlatform::Windows).expect("the rest loads");
    let ids = |set: &nrr_domain::canonical::CanonicalRuleSet| -> Vec<String> {
        set.rules()
            .iter()
            .map(|r| r.id.as_str().to_string())
            .collect()
    };
    let mut primary = ids(&read.rule_book.primary);
    primary.sort();
    assert_eq!(primary, ["r-1", "r-3"]);
    assert_eq!(ids(&read.rule_book.secondary), ["r-4"]);

    // Saved as read, then read again: nothing to drop, nothing came back.
    let mut saved = encode(&read);
    assert!(drop_rules_refused_outright(&mut saved).is_empty());
    assert_eq!(saved.primary.len() + saved.secondary.len(), 3);
    assert_eq!(decode(saved, HostPlatform::Windows).expect("decode"), read);
}

/// An application value the pipeline refuses (too long, a control character
/// other than tab, the bare `*`) in a stored book is dropped the same way, the
/// rest loads, and saving what was read does not bring it back.
#[test]
fn a_stored_book_drops_its_refused_application_rows_and_keeps_the_rest() {
    let long = format!("{}.exe", "a".repeat(300));
    let mut stored = CanonicalRulesJsonV1 {
        schema_version: RULES_JSON_SCHEMA_VERSION,
        primary: vec![
            wire_rule("r-1", "application", "chrome.exe"),
            wire_rule("r-2", "application", &long),
            wire_rule("r-3", "application", "bell\u{7}.exe"),
            wire_rule("r-4", "application", "tab\tname.exe"),
        ],
        secondary: vec![
            wire_rule("r-5", "application", "*"),
            wire_rule("r-6", "application", "chrome*.exe"),
        ],
    };
    assert!(decode(stored.clone(), HostPlatform::Windows).is_err());

    let dropped = drop_rules_refused_outright(&mut stored);
    assert_eq!(
        refused_ids(dropped.clone()),
        ["r-2", "r-3", "r-5"].map(String::from)
    );
    assert_eq!(dropped[0].value, long);
    let read = decode(stored, HostPlatform::Windows).expect("the rest loads");
    assert_eq!(
        read.rule_book.primary.rules().len() + read.rule_book.secondary.rules().len(),
        3
    );

    let mut saved = encode(&read);
    assert!(drop_rules_refused_outright(&mut saved).is_empty());
    assert_eq!(decode(saved, HostPlatform::Windows).expect("decode"), read);
}

/// Reading the book in force dropped a refused application row, so it is
/// never spared: resubmitting it is a new value.
#[test]
fn a_refused_application_in_force_is_not_spared() {
    let long = format!("{}.exe", "a".repeat(300));
    let carried = book(vec![
        wire_rule("r-0000", "application", &long),
        wire_rule("r-0001", "domain", "192.168.1.1"),
    ]);
    assert_eq!(
        rules_with_refused_values(&carried, Some(&carried)),
        vec![RefusedRuleValue {
            rule_id: "r-0000".into(),
            value: long,
        }]
    );
}

/// The book in force spares an old refused value, but never a rule on no
/// destination: reading that book dropped it, so resubmitting it is new.
#[test]
fn a_rule_on_no_destination_in_force_is_not_spared() {
    let carried = book(vec![
        wire_rule("r-0000", "exact-ip", "255.255.255.255"),
        wire_rule("r-0001", "domain", "192.168.1.1"),
    ]);
    assert_eq!(
        rules_with_refused_values(&carried, Some(&carried)),
        vec![RefusedRuleValue {
            rule_id: "r-0000".into(),
            value: "255.255.255.255".into(),
        }]
    );
}

/// A rules file is stored data too: the rule is dropped with a warning, the
/// rest of the file imports.
#[test]
fn a_rules_file_import_drops_a_rule_on_no_destination() {
    let parsed = parse_rules_file(
        "--- IP\n203.0.113.7\n255.255.255.255\n0.0.0.0\n--- Domains\nexample.com\n",
    );
    let outcome =
        canonicalize_preset_rules(&parsed, RouteRole::Primary, HostPlatform::Windows, false);
    let set = outcome.rule_set().expect("the file imports");
    assert_eq!(set.rules().len(), 2);
    let dropped: Vec<&str> = outcome
        .warnings()
        .iter()
        .filter_map(|w| match w {
            ValidationWarning::RuleOnNoDestinationDropped { value, .. } => Some(value.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(dropped.len(), 2);
    assert!(dropped.contains(&"255.255.255.255") && dropped.contains(&"0.0.0.0"));
}

/// An application value the pipeline refuses outright is dropped the same way
/// as an address that is never a destination, alongside it in the same file:
/// both are reported, the rest of the file imports.
#[test]
fn a_rules_file_import_drops_a_refused_application_row_alongside_a_bad_address() {
    let long = format!("{}.exe", "a".repeat(300));
    let parsed = parse_rules_file(&format!(
        "--- IP\n203.0.113.7\n255.255.255.255\n--- Domains\nexample.com\n--- Windows\nchrome.exe\n*\n{long}\n"
    ));
    let outcome =
        canonicalize_preset_rules(&parsed, RouteRole::Primary, HostPlatform::Windows, false);
    let set = outcome.rule_set().expect("the file imports");
    // Only the good address and the good application survive.
    assert_eq!(set.rules().len(), 3);

    let mut address_dropped = Vec::new();
    let mut app_dropped = Vec::new();
    for w in outcome.warnings() {
        match w {
            ValidationWarning::RuleOnNoDestinationDropped { value, .. } => {
                address_dropped.push(value.as_str())
            }
            ValidationWarning::AppPatternRefusedDropped { value, .. } => {
                app_dropped.push(value.as_str())
            }
            _ => {}
        }
    }
    assert_eq!(address_dropped, ["255.255.255.255"]);
    assert_eq!(app_dropped, ["*", long.as_str()]);
}

/// A file with only good rows is unaffected by the outright-refusal policy:
/// nothing is dropped, no warning of that kind is raised.
#[test]
fn a_rules_file_import_with_only_good_rows_drops_nothing() {
    let parsed = parse_rules_file(
        "--- IP\n203.0.113.7\n--- Domains\nexample.com\n--- Windows\nchrome.exe\n",
    );
    let outcome =
        canonicalize_preset_rules(&parsed, RouteRole::Primary, HostPlatform::Windows, false);
    let set = outcome.rule_set().expect("the file imports");
    assert_eq!(set.rules().len(), 3);
    assert!(outcome.warnings().iter().all(|w| !matches!(
        w,
        ValidationWarning::RuleOnNoDestinationDropped { .. }
            | ValidationWarning::AppPatternRefusedDropped { .. }
    )));
}
