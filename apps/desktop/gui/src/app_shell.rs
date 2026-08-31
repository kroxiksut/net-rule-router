use nrr_shared::{ActivationSource, AppSection, FirstRunScenarioId};
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
                Err(_) => eprintln!(
                    "Unknown --section value '{}'. Use interfaces-routes|rules|diagnostics|logs|settings.",
                    value
                ),
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
    use super::{parse_first_run_scenario, parse_launch_request_arguments};
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
    fn launch_request_parser_ignores_blank_action_and_reason() {
        let request =
            parse_launch_request_arguments(["--action= ".to_string(), "--reason=".to_string()]);

        assert_eq!(request.action, None);
        assert_eq!(request.reason, None);
    }
}
