//! The Add/Edit rule form's reading of a typed value (`formRuleValue` in
//! `pure.js`).

use nrr_shared::preset_parser::unquote_program_value;

/// `raw` as the rule it names: a program value in one outer pair of double
/// quotes loses them, as a rules-file line does (a path copied with its
/// quotes, a name with spaces). Every other value, and every other rule type,
/// comes back as given.
pub fn form_rule_value(rule_type: &str, raw: &str) -> String {
    let inner = (rule_type == "application")
        .then(|| unquote_program_value(raw))
        .flatten();
    inner.unwrap_or(raw).to_owned()
}

#[cfg(test)]
mod tests {
    use super::form_rule_value;

    #[test]
    fn only_a_program_loses_its_quotes() {
        assert_eq!(
            form_rule_value("application", "\"Web Content\""),
            "Web Content"
        );
        assert_eq!(form_rule_value("application", "\"\"x\"\""), "\"x\"");
        assert_eq!(
            form_rule_value("exact-fqdn", "\"a.example\""),
            "\"a.example\""
        );
        assert_eq!(form_rule_value("application", "\"\""), "\"\"");
    }
}
