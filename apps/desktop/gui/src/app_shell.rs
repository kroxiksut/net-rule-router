use nrr_shared::{ActivationSource, AppSection, FirstRunScenarioId};
use serde::Serialize;
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HelperCommand {
    EmitContext {
        output_path: PathBuf,
        request: LaunchRequest,
    },
    SavePreferences {
        input_path: PathBuf,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchRequest {
    pub source: ActivationSource,
    pub section: Option<AppSection>,
    pub open_about: bool,
    pub open_license: bool,
    pub first_run_completed_override: Option<bool>,
    pub first_run_scenario_override: Option<FirstRunScenarioId>,
    /// Secondary launchers can carry an opaque "action" slug that the
    /// primary GUI consumes via the `gui-activation.json` hand-off.
    /// Currently the only known slug is `"safe-disable"` (tray
    /// "Temporarily disable product impact" menu) which triggers a
    /// confirm-dialog flow in the primary instead of just a section
    /// switch. Backward compat: older launchers don't write this
    /// field; the primary GUI tolerates it being absent.
    pub action: Option<String>,
    /// Operator-provided justification accompanying `action`. Empty /
    /// `None` is acceptable — the primary GUI will prompt the user to
    /// fill it in if missing. Captured for audit regardless of where
    /// it originated.
    pub reason: Option<String>,
    /// Setting the window scrolls to and highlights (`--focus=<id>`). Only the
    /// shape is checked here; an id the window does not know is its to ignore.
    pub focus: Option<String>,
    /// What the banner beside `focus` says (`--focus-context=<json>`).
    pub focus_context: Option<FocusContext>,
}

/// Display-only context for a focused setting: which programs and addresses a
/// block concerned. Reduced to bounded plain strings on the way in, so nothing
/// in it can be more than text on the screen it lands on.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct FocusContext {
    pub reason: String,
    pub apps: Vec<String>,
    pub addresses: Vec<String>,
    /// Addresses the sender held back beyond `addresses`.
    pub more: u32,
}

const FOCUS_ID_MAX_LEN: usize = 48;
const FOCUS_CONTEXT_MAX_BYTES: usize = 4096;
const FOCUS_CONTEXT_MAX_APPS: usize = 3;
const FOCUS_CONTEXT_MAX_ADDRESSES: usize = 5;
const FOCUS_CONTEXT_MAX_MORE: u64 = 10_000;

fn parse_focus_id(value: &str) -> Option<String> {
    let id = value.trim();
    let well_formed = !id.is_empty()
        && id.len() <= FOCUS_ID_MAX_LEN
        && !id.starts_with('-')
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    well_formed.then(|| id.to_string())
}

impl FocusContext {
    /// `None` for anything that is not a JSON object within the size cap;
    /// fields of the wrong type or shape are dropped one by one.
    pub fn parse(raw: &str) -> Option<Self> {
        if raw.len() > FOCUS_CONTEXT_MAX_BYTES {
            return None;
        }
        let value: serde_json::Value = serde_json::from_str(raw).ok()?;
        let object = value.as_object()?;
        let reason = object
            .get("reason")
            .and_then(|v| v.as_str())
            .and_then(parse_focus_id)
            .unwrap_or_default();
        Some(Self {
            reason,
            apps: bounded_strings(object.get("apps"), FOCUS_CONTEXT_MAX_APPS, 128, false),
            addresses: bounded_strings(
                object.get("addresses"),
                FOCUS_CONTEXT_MAX_ADDRESSES,
                255,
                true,
            ),
            more: object
                .get("more")
                .and_then(|v| v.as_u64())
                .map_or(0, |n| n.min(FOCUS_CONTEXT_MAX_MORE) as u32),
        })
    }
}

fn bounded_strings(
    value: Option<&serde_json::Value>,
    max_items: usize,
    max_len: usize,
    reject_whitespace: bool,
) -> Vec<String> {
    let Some(items) = value.and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| item.as_str())
        .map(str::trim)
        .filter(|s| {
            !s.is_empty()
                && s.chars().count() <= max_len
                && !s.chars().any(char::is_control)
                && (!reject_whitespace || !s.chars().any(char::is_whitespace))
        })
        .take(max_items)
        .map(str::to_string)
        .collect()
}

pub fn parse_launch_request_arguments<I>(arguments: I) -> LaunchRequest
where
    I: IntoIterator<Item = String>,
{
    let mut request = LaunchRequest {
        source: ActivationSource::Menu,
        section: None,
        open_about: false,
        open_license: false,
        first_run_completed_override: None,
        first_run_scenario_override: None,
        action: None,
        reason: None,
        focus: None,
        focus_context: None,
    };

    for argument in arguments {
        if argument == "--about" {
            request.open_about = true;
            continue;
        }
        if argument == "--license" {
            request.open_license = true;
            continue;
        }
        // `--action=<slug>` carries a secondary launch's intent beyond
        // a plain section switch. Today the only consumer is
        // `safe-disable`; unknown slugs are forwarded verbatim and
        // ignored by the primary GUI's dispatcher.
        if let Some(value) = argument.strip_prefix("--action=") {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                request.action = Some(trimmed.to_string());
            }
            continue;
        }
        if let Some(value) = argument.strip_prefix("--reason=") {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                request.reason = Some(trimmed.to_string());
            }
            continue;
        }

        if let Some(value) = argument.strip_prefix("--focus=") {
            request.focus = parse_focus_id(value);
            if request.focus.is_none() {
                eprintln!("Ignoring malformed --focus value '{value}'.");
            }
            continue;
        }
        if let Some(value) = argument.strip_prefix("--focus-context=") {
            request.focus_context = FocusContext::parse(value);
            if request.focus_context.is_none() {
                eprintln!("Ignoring malformed --focus-context value.");
            }
            continue;
        }

        if let Some(value) = argument.strip_prefix("--source=") {
            match value.parse::<ActivationSource>() {
                Ok(source) => request.source = source,
                Err(_) => eprintln!("Unknown --source value '{}'. Use menu|tray.", value),
            }
            continue;
        }

        if let Some(value) = argument.strip_prefix("--section=") {
            match value.parse::<AppSection>() {
                Ok(section) => request.section = Some(section),
                Err(_) => {
                    let known: Vec<&str> = AppSection::ALL.iter().map(|s| s.slug()).collect();
                    eprintln!(
                        "Unknown --section value '{}'. Use {}.",
                        value,
                        known.join("|")
                    );
                }
            }
            continue;
        }

        if let Some(value) = argument.strip_prefix("--first-run=") {
            request.first_run_completed_override = match value {
                "required" | "pending" => Some(false),
                "completed" | "done" | "skip" => Some(true),
                _ => {
                    eprintln!(
                        "Unknown --first-run value '{}'. Use required|completed.",
                        value
                    );
                    None
                }
            };
            continue;
        }

        if let Some(value) = argument.strip_prefix("--scenario=") {
            request.first_run_scenario_override = parse_first_run_scenario(value);
            if request.first_run_scenario_override.is_none() {
                eprintln!(
                    "Unknown --scenario value '{}'. Use quick-start|guided-default.",
                    value
                );
            }
            continue;
        }

        eprintln!("Unknown GUI launch argument '{}'.", argument);
    }

    request
}

pub fn parse_first_run_scenario(value: &str) -> Option<FirstRunScenarioId> {
    match value {
        "quick-start" | "quick" => Some(FirstRunScenarioId::QuickStart),
        "guided-default" | "guided" => Some(FirstRunScenarioId::GuidedDefault),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_first_run_scenario, parse_launch_request_arguments, FocusContext};
    use nrr_shared::{ActivationSource, AppSection, FirstRunScenarioId};

    #[test]
    fn first_run_scenario_parser_accepts_supported_aliases() {
        assert_eq!(
            parse_first_run_scenario("quick-start"),
            Some(FirstRunScenarioId::QuickStart)
        );
        assert_eq!(
            parse_first_run_scenario("guided-default"),
            Some(FirstRunScenarioId::GuidedDefault)
        );
        assert_eq!(parse_first_run_scenario("unknown"), None);
    }

    #[test]
    fn launch_request_parser_maps_common_arguments() {
        let request = parse_launch_request_arguments([
            "--source=tray".to_string(),
            "--section=rules".to_string(),
            "--about".to_string(),
            "--first-run=required".to_string(),
            "--scenario=quick-start".to_string(),
        ]);

        assert_eq!(request.source, ActivationSource::Tray);
        assert_eq!(request.section, Some(AppSection::Rules));
        assert!(request.open_about);
        assert!(!request.open_license);
        assert_eq!(request.first_run_completed_override, Some(false));
        assert_eq!(
            request.first_run_scenario_override,
            Some(FirstRunScenarioId::QuickStart)
        );
    }

    #[test]
    fn launch_request_parser_opens_sub_sections() {
        let request = parse_launch_request_arguments(["--section=conn-trace".to_string()]);
        assert_eq!(request.section, Some(AppSection::ConnectionTrace));
        let request = parse_launch_request_arguments(["--section=cache".to_string()]);
        assert_eq!(request.section, Some(AppSection::Cache));
    }

    #[test]
    fn launch_request_parser_accepts_action_and_reason() {
        let request = parse_launch_request_arguments([
            "--source=tray".to_string(),
            "--action=safe-disable".to_string(),
            "--reason=operator-test".to_string(),
        ]);

        assert_eq!(request.source, ActivationSource::Tray);
        assert_eq!(request.action.as_deref(), Some("safe-disable"));
        assert_eq!(request.reason.as_deref(), Some("operator-test"));
    }

    #[test]
    fn launch_request_parser_accepts_focus_and_its_context() {
        let request = parse_launch_request_arguments([
            "--source=tray".to_string(),
            "--section=settings".to_string(),
            "--focus=doh-lockdown".to_string(),
            r#"--focus-context={"reason":"dns-lockdown","apps":["curl.exe"],"addresses":["192.0.2.1","192.0.2.2"],"more":3}"#.to_string(),
        ]);

        assert_eq!(request.section, Some(AppSection::Settings));
        assert_eq!(request.focus.as_deref(), Some("doh-lockdown"));
        let context = request.focus_context.expect("context parsed");
        assert_eq!(context.reason, "dns-lockdown");
        assert_eq!(context.apps, vec!["curl.exe".to_string()]);
        assert_eq!(
            context.addresses,
            vec!["192.0.2.1".to_string(), "192.0.2.2".to_string()]
        );
        assert_eq!(context.more, 3);
    }

    #[test]
    fn launch_request_parser_rejects_malformed_focus() {
        for bad in [
            "--focus=",
            "--focus=Doh",
            "--focus=-x",
            "--focus=a b",
            "--focus=a\"b",
        ] {
            let request = parse_launch_request_arguments([bad.to_string()]);
            assert_eq!(request.focus, None, "{bad}");
        }
        let long = format!("--focus={}", "a".repeat(49));
        assert_eq!(parse_launch_request_arguments([long]).focus, None);
    }

    #[test]
    fn focus_context_keeps_only_bounded_plain_strings() {
        assert_eq!(FocusContext::parse("not json"), None);
        assert_eq!(FocusContext::parse("[1,2]"), None);
        assert_eq!(FocusContext::parse(&"x".repeat(5000)), None);

        let context = FocusContext::parse(
            r#"{"reason":"<b>x</b>","apps":["a.exe","b\u0007.exe",7,"c.exe","d.exe","e.exe"],
                "addresses":["192.0.2.1","has space","2001:db8::1","192.0.2.3","192.0.2.4","192.0.2.5","192.0.2.6"],
                "more":99999999,"enable":true}"#,
        )
        .expect("an object parses");
        assert_eq!(context.reason, "");
        assert_eq!(context.apps, vec!["a.exe", "c.exe", "d.exe"]);
        assert_eq!(context.addresses.len(), 5);
        assert!(!context.addresses.iter().any(|a| a.contains(' ')));
        assert_eq!(context.more, 10_000);
    }

    #[test]
    fn launch_request_parser_ignores_blank_action_and_reason() {
        let request =
            parse_launch_request_arguments(["--action= ".to_string(), "--reason=".to_string()]);

        assert_eq!(request.action, None);
        assert_eq!(request.reason, None);
    }
}
