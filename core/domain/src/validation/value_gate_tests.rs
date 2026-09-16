use super::*;

fn err_for(value: &str) -> ValidationError {
    let mut warnings = Vec::new();
    normalize_domain_label(value, &RuleId("r-1".to_owned()), &mut warnings)
        .expect_err("must be refused")
}

/// The `--- IP` section passes an unparseable value through as a domain so
/// the semantic validator can name the problem. It never did: a subnet, a
/// range and a typo were all accepted as host names, with zero errors and
/// zero warnings, and travelled into storage and codegen.
#[test]
fn an_address_shaped_value_is_refused_and_named() {
    assert!(matches!(
        err_for("192.168.1.0/24"),
        ValidationError::CidrNotSupported { .. }
    ));
    assert!(matches!(
        err_for("10.0.0.1-10.0.0.9"),
        ValidationError::IpRangeNotSupported { .. }
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
