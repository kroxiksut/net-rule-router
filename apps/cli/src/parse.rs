//! Argument parsing — a pure function over argv, so the whole command surface
//! is testable without a service manager, a console, or privilege.
//!
//! Two rules inherited from the service entrypoints and kept deliberately:
//! no arguments prints help (never a silent action), and an unrecognised verb
//! is an error (never a fallback to something plausible).

use nrr_platform_api::service_control::ServiceStartMode;

use crate::verbs::{self, VerbSpec};

/// A parsed, validated command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Register the service.
    Install { start_mode: ServiceStartMode },
    /// Deregister the service, optionally deleting service-owned data.
    Uninstall { purge: bool },
    /// Start the service.
    Start,
    /// Stop the service.
    Stop,
    /// Stop then start the service.
    Restart,
    /// Report registration and run state.
    Status,
    /// Check the installation and report what is wrong with it.
    DiagDoctor,
    /// Print the console version.
    Version,
    /// Print usage.
    Help,
}

/// Why an argument list could not be turned into a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The first argument is not a verb this console declares.
    UnknownVerb { verb: String },
    /// A verb that groups subverbs was given none.
    MissingSubcommand { verb: &'static str },
    /// The group exists but declares no such subverb.
    UnknownSubcommand {
        verb: &'static str,
        subcommand: String,
    },
    /// The verb exists but does not accept this flag.
    UnknownFlag { verb: &'static str, flag: String },
    /// A flag that takes a value was given none.
    MissingValue {
        verb: &'static str,
        flag: &'static str,
    },
    /// A switch was given a value, which it does not take.
    UnexpectedValue {
        verb: &'static str,
        flag: &'static str,
    },
    /// The value is not one this flag accepts.
    InvalidValue {
        verb: &'static str,
        flag: &'static str,
        value: String,
    },
    /// A positional argument the verb has no use for.
    UnexpectedArgument {
        verb: &'static str,
        argument: String,
    },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownVerb { verb } => write!(f, "unknown verb `{verb}`"),
            Self::MissingSubcommand { verb } => {
                // Name the choices here rather than sending the user to the
                // help: the list comes from the same table the help renders,
                // so it cannot be a stale copy.
                let choices = verbs::find(verb)
                    .map(verbs::subverb_names)
                    .unwrap_or_default();
                write!(f, "`{verb}` needs one of: {choices}")
            }
            Self::UnknownSubcommand { verb, subcommand } => {
                let choices = verbs::find(verb)
                    .map(verbs::subverb_names)
                    .unwrap_or_default();
                write!(f, "`{verb}` has no `{subcommand}`; it has: {choices}")
            }
            Self::UnknownFlag { verb, flag } => {
                write!(f, "`{verb}` does not accept `--{flag}`")
            }
            Self::MissingValue { verb, flag } => {
                write!(f, "`{verb} --{flag}` requires a value")
            }
            Self::UnexpectedValue { verb, flag } => {
                write!(f, "`{verb} --{flag}` does not take a value")
            }
            Self::InvalidValue { verb, flag, value } => {
                write!(f, "`{verb} --{flag}`: `{value}` is not a valid value")
            }
            Self::UnexpectedArgument { verb, argument } => {
                write!(f, "`{verb}` does not take the argument `{argument}`")
            }
        }
    }
}

/// One `--name` or `--name=value` occurrence.
struct ParsedFlag {
    name: String,
    value: Option<String>,
}

/// Parse argv (without the executable name) into a command.
pub fn parse(args: &[String]) -> Result<Command, ParseError> {
    let Some(first) = args.first() else {
        return Ok(Command::Help);
    };

    // Leading dashes and case are normalised so `--status`, `status` and
    // `STATUS` are the same verb — the same forgiveness the service
    // entrypoints already grant.
    let verb_word = first.trim_start_matches('-').to_ascii_lowercase();
    if verb_word.is_empty() || verb_word == "h" {
        return Ok(Command::Help);
    }
    let Some(spec) = verbs::find(&verb_word) else {
        return Err(ParseError::UnknownVerb { verb: verb_word });
    };

    // A grouping verb consumes one more word; everything after that is flags of
    // the subverb, which owns them.
    let (spec, rest, spelling) = if spec.subverbs.is_empty() {
        (spec, &args[1..], spec.name.to_string())
    } else {
        let Some(word) = args.get(1) else {
            return Err(ParseError::MissingSubcommand { verb: spec.name });
        };
        let sub_word = word.trim_start_matches('-').to_ascii_lowercase();
        match verbs::find_subverb(spec, &sub_word) {
            Some(sub) => (sub, &args[2..], format!("{} {}", spec.name, sub.name)),
            None => {
                return Err(ParseError::UnknownSubcommand {
                    verb: spec.name,
                    subcommand: sub_word,
                })
            }
        }
    };

    let flags = collect_flags(spec, rest)?;
    build(&spelling, spec, &flags)
}

/// Split the remaining arguments into flags, rejecting anything the verb does
/// not declare.
fn collect_flags(spec: &'static VerbSpec, rest: &[String]) -> Result<Vec<ParsedFlag>, ParseError> {
    let mut parsed = Vec::new();
    for arg in rest {
        let Some(body) = arg.strip_prefix("--").or_else(|| arg.strip_prefix('-')) else {
            return Err(ParseError::UnexpectedArgument {
                verb: spec.name,
                argument: arg.clone(),
            });
        };
        let (name, value) = match body.split_once('=') {
            Some((name, value)) => (name.to_ascii_lowercase(), Some(value.to_string())),
            None => (body.to_ascii_lowercase(), None),
        };
        let Some(flag) = spec.flags.iter().find(|f| f.name == name) else {
            return Err(ParseError::UnknownFlag {
                verb: spec.name,
                flag: name,
            });
        };
        match (flag.value, &value) {
            (Some(_), None) => {
                return Err(ParseError::MissingValue {
                    verb: spec.name,
                    flag: flag.name,
                })
            }
            (None, Some(_)) => {
                return Err(ParseError::UnexpectedValue {
                    verb: spec.name,
                    flag: flag.name,
                })
            }
            _ => {}
        }
        parsed.push(ParsedFlag { name, value });
    }
    Ok(parsed)
}

fn flag<'a>(flags: &'a [ParsedFlag], name: &str) -> Option<&'a ParsedFlag> {
    flags.iter().find(|f| f.name == name)
}

/// Turn a resolved verb into a command. Matching happens on the full spelling
/// (`diag doctor`, not `doctor`) so a subverb can never be reached by typing
/// its name at the top level.
fn build(
    spelling: &str,
    spec: &'static VerbSpec,
    flags: &[ParsedFlag],
) -> Result<Command, ParseError> {
    match spelling {
        "install" => {
            let start_mode = match flag(flags, "start-mode") {
                Some(f) => {
                    let raw = f.value.as_deref().unwrap_or_default();
                    ServiceStartMode::from_slug(&raw.to_ascii_lowercase()).ok_or_else(|| {
                        ParseError::InvalidValue {
                            verb: spec.name,
                            flag: "start-mode",
                            value: raw.to_string(),
                        }
                    })?
                }
                None => ServiceStartMode::default(),
            };
            Ok(Command::Install { start_mode })
        }
        "uninstall" => Ok(Command::Uninstall {
            purge: flag(flags, "purge").is_some(),
        }),
        "start" => Ok(Command::Start),
        "stop" => Ok(Command::Stop),
        "restart" => Ok(Command::Restart),
        "status" => Ok(Command::Status),
        "diag doctor" => Ok(Command::DiagDoctor),
        "version" => Ok(Command::Version),
        "help" => Ok(Command::Help),
        // Unreachable while every declared verb is built above — and the test
        // below is what keeps it unreachable when a verb is added.
        other => Err(ParseError::UnknownVerb {
            verb: other.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Command, ParseError> {
        let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        parse(&owned)
    }

    #[test]
    fn no_arguments_is_help_never_an_action() {
        assert_eq!(p(&[]), Ok(Command::Help));
    }

    #[test]
    fn every_declared_verb_parses() {
        // The table is the contract; this is what makes "declared but not
        // wired" impossible to ship. Grouping verbs are spelled with their
        // subverb, which is exactly how the user must type them.
        for (spelling, _) in verbs::invocable() {
            let words: Vec<&str> = spelling.split(' ').collect();
            let parsed = p(&words);
            assert!(
                parsed.is_ok(),
                "declared verb `{spelling}` does not parse: {parsed:?}"
            );
        }
    }

    #[test]
    fn a_grouping_verb_alone_names_its_choices() {
        assert_eq!(
            p(&["diag"]),
            Err(ParseError::MissingSubcommand { verb: "diag" })
        );
        // The message lists what is available, from the same table.
        let message = ParseError::MissingSubcommand { verb: "diag" }.to_string();
        assert!(message.contains("doctor"), "message was: {message}");
    }

    #[test]
    fn an_unknown_subcommand_is_reported_not_guessed() {
        assert_eq!(
            p(&["diag", "everything"]),
            Err(ParseError::UnknownSubcommand {
                verb: "diag",
                subcommand: "everything".to_string()
            })
        );
    }

    #[test]
    fn a_subverb_is_not_reachable_at_the_top_level() {
        // `nrr-cli doctor` must not work: the group is part of the spelling,
        // and a console that accepts both spellings has two contracts.
        assert_eq!(
            p(&["doctor"]),
            Err(ParseError::UnknownVerb {
                verb: "doctor".to_string()
            })
        );
    }

    #[test]
    fn diag_doctor_takes_no_flags() {
        assert_eq!(p(&["diag", "doctor"]), Ok(Command::DiagDoctor));
        assert_eq!(
            p(&["diag", "doctor", "--json"]),
            Err(ParseError::UnknownFlag {
                verb: "doctor",
                flag: "json".to_string()
            })
        );
    }

    #[test]
    fn verb_spelling_is_forgiving_about_dashes_and_case() {
        assert_eq!(p(&["--status"]), Ok(Command::Status));
        assert_eq!(p(&["STATUS"]), Ok(Command::Status));
        assert_eq!(p(&["-h"]), Ok(Command::Help));
    }

    #[test]
    fn unknown_verb_is_reported_not_guessed() {
        assert_eq!(
            p(&["frobnicate"]),
            Err(ParseError::UnknownVerb {
                verb: "frobnicate".to_string()
            })
        );
    }

    #[test]
    fn install_defaults_to_starting_with_the_operating_system() {
        assert_eq!(
            p(&["install"]),
            Ok(Command::Install {
                start_mode: ServiceStartMode::WithWindows
            })
        );
    }

    #[test]
    fn install_start_mode_accepts_the_declared_spellings() {
        assert_eq!(
            p(&["install", "--start-mode=on-demand"]),
            Ok(Command::Install {
                start_mode: ServiceStartMode::OnAppLaunch
            })
        );
        assert_eq!(
            p(&["install", "--start-mode=AUTO"]),
            Ok(Command::Install {
                start_mode: ServiceStartMode::WithWindows
            })
        );
    }

    #[test]
    fn install_start_mode_rejects_anything_else() {
        assert_eq!(
            p(&["install", "--start-mode=whenever"]),
            Err(ParseError::InvalidValue {
                verb: "install",
                flag: "start-mode",
                value: "whenever".to_string()
            })
        );
        assert_eq!(
            p(&["install", "--start-mode"]),
            Err(ParseError::MissingValue {
                verb: "install",
                flag: "start-mode"
            })
        );
    }

    #[test]
    fn uninstall_keeps_data_unless_purge_is_asked_for() {
        assert_eq!(p(&["uninstall"]), Ok(Command::Uninstall { purge: false }));
        assert_eq!(
            p(&["uninstall", "--purge"]),
            Ok(Command::Uninstall { purge: true })
        );
    }

    #[test]
    fn a_switch_given_a_value_is_a_usage_error() {
        assert_eq!(
            p(&["uninstall", "--purge=yes"]),
            Err(ParseError::UnexpectedValue {
                verb: "uninstall",
                flag: "purge"
            })
        );
    }

    #[test]
    fn undeclared_flags_are_rejected_by_the_verb_that_owns_them() {
        assert_eq!(
            p(&["status", "--json"]),
            Err(ParseError::UnknownFlag {
                verb: "status",
                flag: "json".to_string()
            })
        );
        assert_eq!(
            p(&["start", "--purge"]),
            Err(ParseError::UnknownFlag {
                verb: "start",
                flag: "purge".to_string()
            })
        );
    }

    #[test]
    fn positional_arguments_are_rejected() {
        assert_eq!(
            p(&["status", "extra"]),
            Err(ParseError::UnexpectedArgument {
                verb: "status",
                argument: "extra".to_string()
            })
        );
    }
}
