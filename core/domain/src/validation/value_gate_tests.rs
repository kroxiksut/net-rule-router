use super::*;

fn err_for(value: &str) -> ValidationError {
    let mut warnings = Vec::new();
    normalize_domain_label(value, &RuleId("r-1".to_owned()), &mut warnings)
        .expect_err("must be refused")
}

/// A subnet, a range or a typo in a domain rule was once accepted as a host
/// name and travelled into storage and codegen; it is refused and named.
#[test]
fn an_address_shaped_value_is_refused_and_named() {
    assert!(matches!(
        err_for("192.168.1.0/24"),
        ValidationError::WrongAddressSection {
            belongs_in: IpValueKind::Subnet,
            ..
        }
    ));
    assert!(matches!(
        err_for("10.0.0.1-10.0.0.9"),
        ValidationError::WrongAddressSection {
            belongs_in: IpValueKind::Range,
            ..
        }
    ));
    assert!(matches!(
        err_for("2001:db8::1"),
        ValidationError::DomainInvalidValue { .. }
    ));
    assert!(matches!(
        err_for("192.168.1"),
        ValidationError::InvalidIpAddress { .. }
    ));
}

/// Anything that is not a host name at all cannot match a packet, so
/// storing it is worse than refusing it: the rule looks live and does
/// nothing.
#[test]
fn a_value_that_is_not_a_host_name_is_refused() {
    for value in ["hello world", "C:/windows/system32", "a*b.example.com"] {
        assert!(
            matches!(err_for(value), ValidationError::DomainInvalidValue { .. }),
            "{value} must be refused"
        );
    }
    // A control byte never reaches a DNS query either.
    let with_nul = format!("exam{}ple.com", '\u{0}');
    assert!(matches!(
        err_for(&with_nul),
        ValidationError::DomainInvalidValue { .. }
    ));
}

/// The gate must not start refusing ordinary rules — including the ones
/// with an underscore, which the rule validator accepts on purpose.
#[test]
fn ordinary_host_names_still_pass() {
    let mut warnings = Vec::new();
    for value in [
        "example.com",
        "db_srv.corp.intra",
        "xn--80ak6aa92e.com",
        "a.b.c.d.example.co.uk",
        // The bundled presets ship IDN zones; they reach the gate as
        // punycode and must survive it.
        "\u{440}\u{444}",
        "\u{4e2d}\u{56fd}",
    ] {
        assert!(
            normalize_domain_label(value, &RuleId("r-1".to_owned()), &mut warnings).is_ok(),
            "{value} must be accepted"
        );
    }
}

/// The matcher drops a host longer than 253 octets as malformed, so a rule
/// naming one was accepted and never matched. The limit is on the punycode
/// form: an IDN that fits in UTF-8 can outgrow it once encoded.
#[test]
fn a_name_longer_than_253_octets_is_refused_the_way_the_matcher_drops_it() {
    let label = |c: char, n: usize| c.to_string().repeat(n);
    let fits = [
        label('a', 63),
        label('b', 63),
        label('c', 63),
        label('d', 61),
    ]
    .join(".");
    let over = [
        label('a', 63),
        label('b', 63),
        label('c', 63),
        label('d', 62),
    ]
    .join(".");
    assert_eq!(fits.len(), 253);
    let mut warnings = Vec::new();
    assert!(normalize_domain_label(&fits, &RuleId("r-1".to_owned()), &mut warnings).is_ok());
    assert!(matches!(
        err_for(&over),
        ValidationError::DomainInvalidValue { .. }
    ));

    let idn_label = format!("{}ü", label('a', 55));
    let idn = [idn_label.as_str(); 4].join(".");
    assert!(idn.len() <= 253, "fits before encoding");
    assert!(matches!(
        err_for(&idn),
        ValidationError::DomainInvalidValue { .. }
    ));
}
