//! The verb table — the single declaration of what this console accepts.
//!
//! Help text is rendered FROM this table, so the two cannot disagree: adding a
//! verb without describing it, or describing one that does not exist, is not
//! expressible. The parser reads the same table, so an unknown flag is rejected
//! by the same declaration that documents the known ones.
//!
//! Deliberately absent, and staying absent: anything that mutates policy, any
//! machine-readable output mode, any way to point the console at a config file
//! or another host. The console is for keeping the service alive and diagnosing
//! it — not for driving it.

/// Privilege a verb requires from the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Privilege {
    /// Runs as any user.
    Any,
    /// Requires an elevated / root console. The console never elevates itself:
    /// it reports what is needed and exits, so a script cannot silently gain
    /// privilege by invoking it.
    Administrator,
}

/// A flag a verb accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlagSpec {
    /// Long name, without the leading dashes.
    pub name: &'static str,
    /// Name of the value the flag takes, or `None` for a switch.
    pub value: Option<&'static str>,
    /// One-line description for the help output.
    pub summary: &'static str,
}

/// A verb.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerbSpec {
    /// The word the user types.
    pub name: &'static str,
    /// One-line description for the help output.
    pub summary: &'static str,
    /// Flags this verb accepts. Anything else is a usage error.
    pub flags: &'static [FlagSpec],
    /// What the verb needs from the caller.
    pub privilege: Privilege,
    /// Subverbs, for a verb that groups a family of actions expected to grow.
    /// Lifecycle verbs stay flat because that family is closed; diagnostics is
    /// a group because it is not. A grouping verb is never an action by itself
    /// and declares no flags of its own — the subverb owns those.
    pub subverbs: &'static [VerbSpec],
}

const START_MODE_FLAG: FlagSpec = FlagSpec {
    name: "start-mode",
    value: Some("auto|on-demand"),
    summary: "start with the operating system (default), or when the app is launched",
};

const PURGE_FLAG: FlagSpec = FlagSpec {
    name: "purge",
    value: None,
    summary: "also delete the service-owned data directory (user rule files are kept)",
};

/// Subverbs of `diag`. The group exists because diagnostics is the part of
/// this console that keeps growing; the lifecycle above does not.
const DIAG_SUBVERBS: &[VerbSpec] = &[VerbSpec {
    name: "doctor",
    summary: "Check this installation and report what is wrong with it",
    flags: &[],
    privilege: Privilege::Any,
    subverbs: &[],
}];

/// Every verb this console accepts.
pub static VERBS: &[VerbSpec] = &[
    VerbSpec {
        name: "install",
        summary: "Register the service with the operating system",
        flags: &[START_MODE_FLAG],
        privilege: Privilege::Administrator,
        subverbs: &[],
    },
    VerbSpec {
        name: "uninstall",
        summary: "Deregister the service",
        flags: &[PURGE_FLAG],
        privilege: Privilege::Administrator,
        subverbs: &[],
    },
    VerbSpec {
        name: "start",
        summary: "Start the service",
        flags: &[],
        privilege: Privilege::Administrator,
        subverbs: &[],
    },
    VerbSpec {
        name: "stop",
        summary: "Stop the service",
        flags: &[],
        privilege: Privilege::Administrator,
        subverbs: &[],
    },
    VerbSpec {
        name: "restart",
        summary: "Stop then start the service",
        flags: &[],
        privilege: Privilege::Administrator,
        subverbs: &[],
    },
    VerbSpec {
        name: "status",
        summary: "Show whether the service is installed, running, and how it starts",
        flags: &[],
        privilege: Privilege::Any,
        subverbs: &[],
    },
    VerbSpec {
        name: "diag",
        summary: "Diagnostics",
        flags: &[],
        privilege: Privilege::Any,
        subverbs: DIAG_SUBVERBS,
    },
    VerbSpec {
        name: "version",
        summary: "Print the console version",
        flags: &[],
        privilege: Privilege::Any,
        subverbs: &[],
    },
    VerbSpec {
        name: "help",
        summary: "Show this help",
        flags: &[],
        privilege: Privilege::Any,
        subverbs: &[],
    },
];

/// Look a verb up by name.
pub fn find(name: &str) -> Option<&'static VerbSpec> {
    VERBS.iter().find(|v| v.name == name)
}

/// Look a subverb up inside a grouping verb.
pub fn find_subverb(group: &'static VerbSpec, name: &str) -> Option<&'static VerbSpec> {
    group.subverbs.iter().find(|v| v.name == name)
}

/// Comma-separated subverb names, for a usage error that names the choices
/// instead of telling the user to go read the help.
pub fn subverb_names(group: &'static VerbSpec) -> String {
    group
        .subverbs
        .iter()
        .map(|v| v.name)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Every invocable verb as the user spells it: a flat verb, or a grouping verb
/// with one of its subverbs appended. Help and the parser tests walk this, so
/// neither can miss a verb that the table declares.
pub fn invocable() -> Vec<(String, &'static VerbSpec)> {
    let mut rows = Vec::with_capacity(VERBS.len());
    for verb in VERBS {
        if verb.subverbs.is_empty() {
            rows.push((verb.name.to_string(), verb));
        } else {
            for sub in verb.subverbs {
                rows.push((format!("{} {}", verb.name, sub.name), sub));
            }
        }
    }
    rows
}

/// Render the help text from the table.
pub fn render_help(exe: &str) -> String {
    let mut out = String::with_capacity(1024);
    out.push_str(&format!(
        "{exe} — {} service console\n\n",
        nrr_shared::product_identity::PRODUCT_NAME
    ));
    out.push_str(&format!("USAGE:\n    {exe} <VERB> [FLAGS]\n\nVERBS:\n"));

    let rows = invocable();
    let width = rows.iter().map(|(name, _)| name.len()).max().unwrap_or(0);
    for (name, verb) in &rows {
        out.push_str(&format!(
            "    {:width$}  {}",
            name,
            verb.summary,
            width = width
        ));
        if verb.privilege == Privilege::Administrator {
            out.push_str(" (requires administrator)");
        }
        out.push('\n');
        for flag in verb.flags {
            let spelling = match flag.value {
                Some(value) => format!("--{}=<{value}>", flag.name),
                None => format!("--{}", flag.name),
            };
            out.push_str(&format!(
                "    {:width$}    {spelling}  {}\n",
                "",
                flag.summary,
                width = width
            ));
        }
    }

    out.push_str(
        "\nThe console manages the service itself: install, run, inspect. \
         Routing policy — rules, adapters, applying changes — is edited in the \
         application, not here.\n",
    );
    out.push_str(
        "\nPre-release: verbs, flags and exit codes may still change. \
         The text this console prints is never a stable interface — do not \
         parse it. See docs/en/cli.md.\n",
    );
    out
}

#[cfg(test)]
mod tests {
    // Test assertions panic on infallible fixtures by design.
    #![allow(clippy::expect_used)]
    use super::*;

    /// Every declared spec, grouping verbs and their subverbs alike. The
    /// boundary tests below walk this so a rule cannot be escaped by declaring
    /// the offending verb one level down.
    fn all_specs() -> Vec<&'static VerbSpec> {
        let mut specs: Vec<&'static VerbSpec> = Vec::new();
        for verb in VERBS {
            specs.push(verb);
            specs.extend(verb.subverbs.iter());
        }
        specs
    }

    #[test]
    fn verb_names_are_unique_lowercase_words() {
        let mut names: Vec<&str> = VERBS.iter().map(|v| v.name).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "verb names must be unique");
        for verb in all_specs() {
            assert_eq!(verb.name, verb.name.to_ascii_lowercase());
            assert!(
                !verb.name.contains(' '),
                "a verb is one word: {}",
                verb.name
            );
        }
        for group in VERBS {
            let mut subs: Vec<&str> = group.subverbs.iter().map(|v| v.name).collect();
            let count = subs.len();
            subs.sort_unstable();
            subs.dedup();
            assert_eq!(
                subs.len(),
                count,
                "subverbs of `{}` must be unique",
                group.name
            );
        }
    }

    #[test]
    fn a_grouping_verb_declares_no_flags_of_its_own() {
        // `diag --something doctor` has no obvious reading, so the shape that
        // would create the ambiguity is rejected at declaration time rather
        // than resolved by parser precedence.
        for verb in VERBS {
            if !verb.subverbs.is_empty() {
                assert!(
                    verb.flags.is_empty(),
                    "`{}` groups subverbs, so its flags belong to them",
                    verb.name
                );
            }
        }
    }

    #[test]
    fn subverbs_do_not_nest_further() {
        // Two levels is a console; three is a shell. The depth is a decision,
        // and this is where it is enforced.
        for group in VERBS {
            for sub in group.subverbs {
                assert!(
                    sub.subverbs.is_empty(),
                    "`{} {}` may not group further subverbs",
                    group.name,
                    sub.name
                );
            }
        }
    }

    #[test]
    fn flag_names_are_unique_within_a_verb() {
        for verb in all_specs() {
            let mut names: Vec<&str> = verb.flags.iter().map(|f| f.name).collect();
            let count = names.len();
            names.sort_unstable();
            names.dedup();
            assert_eq!(
                names.len(),
                count,
                "flags of `{}` must be unique",
                verb.name
            );
        }
    }

    #[test]
    fn the_console_declares_no_policy_verb() {
        // The Free console manages the service; it never edits or applies
        // policy. If one of these ever appears in the table, the boundary was
        // crossed by accident rather than by decision.
        const FORBIDDEN: &[&str] = &["apply", "rules", "switch", "pause", "resume", "profile"];
        for verb in all_specs() {
            assert!(
                !FORBIDDEN.contains(&verb.name),
                "`{}` mutates policy and does not belong in this console",
                verb.name
            );
        }
    }

    #[test]
    fn the_console_does_not_put_itself_on_the_users_path() {
        // Making this console reachable by name changes the environment every
        // future shell of that user inherits. It is offered as an explicit
        // action in the application, where the user can see what it will change
        // and undo it, and it is deliberately NOT a verb here: a console that
        // can install itself into the environment is a console a script can
        // invoke to do so quietly. The capability itself lives behind
        // `nrr_platform_api::path_registration`.
        const FORBIDDEN: &[&str] = &["path", "register", "setup"];
        for verb in all_specs() {
            assert!(
                !FORBIDDEN.contains(&verb.name),
                "`{}` changes the caller's environment and belongs to the explicit \
                 in-app action, not to this console",
                verb.name
            );
        }
    }

    #[test]
    fn the_console_declares_no_machine_output_or_remoting_flag() {
        // Machine-readable output, config files and remote targets are what
        // turn a console into an automation API. Their absence is a decision.
        const FORBIDDEN: &[&str] = &["json", "config", "host", "watch", "token"];
        for verb in all_specs() {
            for flag in verb.flags {
                assert!(
                    !FORBIDDEN.contains(&flag.name),
                    "`--{}` on `{}` is an automation surface",
                    flag.name,
                    verb.name
                );
            }
        }
    }

    #[test]
    fn help_lists_every_verb_and_flag() {
        let help = render_help("nrr-cli");
        for (spelling, verb) in invocable() {
            assert!(help.contains(&spelling), "help omits verb `{spelling}`");
            for flag in verb.flags {
                assert!(
                    help.contains(flag.name),
                    "help omits flag `--{}` of `{spelling}`",
                    flag.name
                );
            }
        }
    }

    #[test]
    fn the_published_reference_lists_every_verb_this_console_accepts() {
        // The console's public page is written by hand, so nothing but a test
        // keeps it honest: a verb added here without a line there ships a
        // reference that is quietly incomplete. The reverse direction (a
        // documented verb that does not exist) is caught by the parser test
        // that walks the same table.
        let doc = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/en/cli.md")
            .canonicalize()
            .expect("the console reference must exist at docs/en/cli.md");
        let text = std::fs::read_to_string(&doc).expect("the console reference must be readable");
        for (spelling, _) in invocable() {
            assert!(
                text.contains(&format!("`{spelling}`")),
                "docs/en/cli.md does not document `{spelling}`"
            );
        }
    }

    #[test]
    fn help_states_that_output_is_not_a_contract() {
        let help = render_help("nrr-cli");
        assert!(
            help.contains("do not"),
            "help must warn against parsing output"
        );
        assert!(help.contains("Pre-release"), "help must state the stage");
    }

    #[test]
    fn lookup_finds_declared_verbs_only() {
        assert_eq!(find("status").map(|v| v.name), Some("status"));
        assert!(find("apply").is_none());
    }
}
