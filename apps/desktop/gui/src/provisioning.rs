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
use std::io::Read;
use std::path::{Path, PathBuf};

use nrr_platform_api::admin_authored::AdminAuthoredFiles;
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

/// Largest sheet read: the answers are a handful of short strings.
const MAX_SHEET_BYTES: u64 = 64 * 1024;

/// One place a sheet may come from, and whether it must be shown to have been
/// placed by an administrator before it is believed.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Candidate {
    path: PathBuf,
    admin_only: bool,
}

/// Search order: next to the executable (portable copy, installer payload),
/// then the machine state root. Never a directory above the executable: a
/// sheet there could be planted by another local user and would seed policy.
///
/// The state root may predate the service, created by any local account, so a
/// sheet there counts only when `machine_files` says no ordinary account could
/// have written it. The executable's own folder needs no such proof: whoever
/// can write there can replace the executable too.
pub fn load(machine_files: &dyn AdminAuthoredFiles) -> Option<LoadedProvisioning> {
    let executable = env::current_exe().ok();
    load_from(
        &candidate_paths_for(
            executable.as_deref().and_then(Path::parent),
            nrr_platform_api::paths::production_data_root().as_deref(),
        ),
        machine_files,
    )
}

fn load_from(
    candidates: &[Candidate],
    machine_files: &dyn AdminAuthoredFiles,
) -> Option<LoadedProvisioning> {
    for candidate in candidates {
        if !candidate.path.exists() {
            continue;
        }
        if candidate.admin_only {
            if let Some(why) = machine_files.untrusted_because(&candidate.path) {
                eprintln!(
                    "nrr-gui: ignoring {}: not placed by an administrator ({why})",
                    candidate.path.display()
                );
                continue;
            }
        }
        match read_answers(&candidate.path) {
            Ok(Some(answers)) => {
                return Some(LoadedProvisioning {
                    answers,
                    source_path: candidate.path.clone(),
                })
            }
            Ok(None) => continue,
            Err(message) => {
                // A malformed sheet must not take the wizard down with it: the
                // user still has to be able to set the app up by hand.
                eprintln!("nrr-gui: ignoring {}: {message}", candidate.path.display());
                continue;
            }
        }
    }
    None
}

fn candidate_paths_for(executable_dir: Option<&Path>, state_root: Option<&Path>) -> Vec<Candidate> {
    let beside = executable_dir.map(|dir| Candidate {
        path: dir.join(PROVISIONING_FILE_NAME),
        admin_only: false,
    });
    let machine = state_root.map(|dir| Candidate {
        path: dir.join(PROVISIONING_FILE_NAME),
        admin_only: true,
    });
    beside.into_iter().chain(machine).collect()
}

/// `Ok(None)` = no file there. `Err` = the file exists but could not be used.
fn read_answers(path: &Path) -> Result<Option<ProvisioningAnswers>, String> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let mut text = String::new();
    file.take(MAX_SHEET_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    if text.len() as u64 > MAX_SHEET_BYTES {
        return Err(format!("larger than {MAX_SHEET_BYTES} bytes"));
    }
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

    struct Refuse;
    impl AdminAuthoredFiles for Refuse {
        fn untrusted_because(&self, _path: &Path) -> Option<String> {
            Some("planted".to_owned())
        }
    }
    struct Believe;
    impl AdminAuthoredFiles for Believe {
        fn untrusted_because(&self, _path: &Path) -> Option<String> {
            None
        }
    }

    /// A fresh directory removed on drop; this crate has no temp-dir crate.
    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            let dir =
                env::temp_dir().join(format!("nrr-provisioning-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("scratch dir");
            Self(dir)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const SHEET: &str =
        r#"{"kill-switch":false,"doh-lockdown":false,"fake-ip":false,"rule-set":"none"}"#;

    #[test]
    fn the_sheet_is_looked_for_only_beside_the_binary_and_under_the_state_root() {
        let binary_dir = Path::new("package").join("bin");
        let state_root = Path::new("state");
        assert_eq!(
            candidate_paths_for(Some(&binary_dir), Some(state_root)),
            vec![
                Candidate {
                    path: binary_dir.join(PROVISIONING_FILE_NAME),
                    admin_only: false,
                },
                Candidate {
                    path: state_root.join(PROVISIONING_FILE_NAME),
                    admin_only: true,
                },
            ]
        );
    }

    #[test]
    fn a_machine_sheet_an_ordinary_account_could_have_placed_is_ignored() {
        let state_root = Scratch::new("machine");
        std::fs::write(state_root.path().join(PROVISIONING_FILE_NAME), SHEET).expect("plant");
        let candidates = candidate_paths_for(None, Some(state_root.path()));
        assert_eq!(load_from(&candidates, &Refuse), None);
        let believed = load_from(&candidates, &Believe).expect("an administrator's sheet");
        assert!(believed.answers.completes_first_run());
    }

    #[test]
    fn the_sheet_beside_the_binary_needs_no_proof_of_authorship() {
        let binary_dir = Scratch::new("beside");
        std::fs::write(binary_dir.path().join(PROVISIONING_FILE_NAME), SHEET).expect("write");
        let candidates = candidate_paths_for(Some(binary_dir.path()), None);
        assert!(load_from(&candidates, &Refuse).is_some());
    }

    #[test]
    fn an_oversized_sheet_is_refused_unread() {
        let dir = Scratch::new("oversized");
        let path = dir.path().join(PROVISIONING_FILE_NAME);
        let padding = " ".repeat(MAX_SHEET_BYTES as usize);
        std::fs::write(&path, format!("{padding}{SHEET}")).expect("write");
        assert!(read_answers(&path).is_err());
    }

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
