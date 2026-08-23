//! Answers to the first-run questions, supplied ahead of the first launch.
//!
//! The setup wizard asks a fixed set of questions — which connections to use,
//! whether to arm the kill-switch and DNS lockdown, which rule set to start
//! from. An installer is in a position to have asked them already, and a
//! portable copy can carry the same file next to the executable. When every
//! required answer is present the wizard has nothing left to ask and does not
//! appear; a partial file pre-fills what it does answer.
//!
//! Reading only. Nothing here writes the file back: it is an input the user (or
//! their administrator) authored, and the app's own state lives in preferences.

use std::env;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// File name looked for next to the executable and under the machine state
/// root. Stable, because an installer writes it before this code ever runs.
pub const PROVISIONING_FILE_NAME: &str = "first-run.json";

/// One first-run answer sheet. Every field is optional: a file that answers
/// two questions and leaves the rest is valid, and the wizard asks the rest.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ProvisioningAnswers {
    /// Windows connection name (not the adapter description) for the main
    /// link, e.g. `"Ethernet"`. Resolved against the live adapter list by the
    /// GUI, so a name that no longer exists simply leaves the slot unanswered.
    pub primary_connection: Option<String>,
    /// Same for the additional link.
    pub secondary_connection: Option<String>,
    /// Arm the kill-switch (block rather than leak when the additional link is
    /// down).
    pub kill_switch: Option<bool>,
    /// Keep browsers from resolving routed hosts past NetRuleRouter.
    pub doh_lockdown: Option<bool>,
    /// Route hosts by name so an address shared with another site is not
    /// dragged along.
    pub fake_ip: Option<bool>,
    /// Rule set to import, as `<country>/<pack>` under the bundled presets —
    /// e.g. `"ru/osnovnoy-i-zarubezh"`. `"none"` starts empty.
    pub rule_set: Option<String>,
    /// UI language tag (`"ru"`, `"en"`). Absent = follow the OS.
    pub language: Option<String>,
}

impl ProvisioningAnswers {
    /// Does this sheet answer everything the wizard would otherwise ask? Only
    /// then may the wizard be skipped outright.
    ///
    /// The connections are deliberately NOT part of the bar: an installer
    /// cannot know which adapter a VPN client will create on first connect,
    /// and demanding it would make the common case unusable.
    pub fn completes_first_run(&self) -> bool {
        self.kill_switch.is_some()
            && self.doh_lockdown.is_some()
            && self.fake_ip.is_some()
            && self.rule_set.is_some()
    }

    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// A loaded sheet plus where it came from, for the log line and the settings
/// screen that has to explain why the wizard never appeared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedProvisioning {
    pub answers: ProvisioningAnswers,
    pub source_path: PathBuf,
}

/// Search order: next to the executable (portable copy, installer payload),
/// then up to five directories above it (a dev checkout runs the binary from
/// `target/<profile>/`), then the machine state root.
pub fn load() -> Option<LoadedProvisioning> {
    for candidate in candidate_paths() {
        match read_answers(&candidate) {
            Ok(Some(answers)) => {
                return Some(LoadedProvisioning {
                    answers,
                    source_path: candidate,
                })
            }
            Ok(None) => continue,
            Err(message) => {
                // A malformed sheet must not take the wizard down with it: the
                // user still has to be able to set the app up by hand.
                eprintln!("nrr-gui: ignoring {}: {message}", candidate.display());
                continue;
            }
        }
    }
    None
}

fn candidate_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(exe) = env::current_exe() {
        let mut dir = exe.parent();
        for _ in 0..6 {
            let Some(d) = dir else { break };
            out.push(d.join(PROVISIONING_FILE_NAME));
            dir = d.parent();
        }
    }
    if let Some(root) = nrr_platform_api::paths::production_data_root() {
        out.push(root.join(PROVISIONING_FILE_NAME));
    }
    out
}

/// `Ok(None)` = no file there. `Err` = the file exists but could not be used.
fn read_answers(path: &Path) -> Result<Option<ProvisioningAnswers>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let answers: ProvisioningAnswers =
        serde_json::from_str(&text).map_err(|e| format!("not a valid answer sheet: {e}"))?;
    if answers.is_empty() {
        return Err("answer sheet is empty".to_string());
    }
    Ok(Some(answers))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sheet_answering_every_gate_question_skips_the_wizard() {
        let answers = ProvisioningAnswers {
            kill_switch: Some(true),
            doh_lockdown: Some(true),
            fake_ip: Some(false),
            rule_set: Some("ru/osnovnoy-i-zarubezh".to_string()),
            ..ProvisioningAnswers::default()
        };
        assert!(answers.completes_first_run());
    }

    #[test]
    fn connections_alone_do_not_complete_first_run() {
        let answers = ProvisioningAnswers {
            primary_connection: Some("Ethernet".to_string()),
            secondary_connection: Some("VPN".to_string()),
            ..ProvisioningAnswers::default()
        };
        assert!(!answers.completes_first_run());
    }

    #[test]
    fn kebab_case_keys_round_trip_from_the_file_form() {
        let parsed: ProvisioningAnswers = serde_json::from_str(
            r#"{"primary-connection":"Ethernet","kill-switch":true,"rule-set":"none"}"#,
        )
        .expect("parses");
        assert_eq!(parsed.primary_connection.as_deref(), Some("Ethernet"));
        assert_eq!(parsed.kill_switch, Some(true));
        assert_eq!(parsed.rule_set.as_deref(), Some("none"));
        assert!(!parsed.completes_first_run());
    }

    #[test]
    fn an_unknown_key_is_refused_rather_than_silently_ignored() {
        let err = serde_json::from_str::<ProvisioningAnswers>(r#"{"kill-swich":true}"#);
        assert!(err.is_err(), "a typo must not read as 'unanswered'");
    }
}
