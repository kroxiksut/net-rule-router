//! Answers to the first-run questions, supplied ahead of the first launch.
//!
//! The setup wizard asks a fixed set of questions: which connections to use,
//! the leak protection level, DNS lockdown, which rule set to start from. An
//! installer may have asked them already and left the file next to the
//! executable. When every required answer is
//! present the wizard has nothing left to ask; a partial file pre-fills what
//! it does answer.
//!
//! Both clients read the sheet through this module. Reading only: the sheet is
//! an input its author wrote, and the app's own state lives elsewhere.
//!
//! The file sits in a place others may write, so the read is bounded, never
//! panics and contains a bad sheet to "no sheet".

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::ipc_payloads::LeakProtectionDto;

/// Looked for next to the executable and, where the OS has one, in the
/// machine folder. Stable,
/// because an installer writes it before this code ever runs.
pub const PROVISIONING_FILE_NAME: &str = "first-run.json";

/// Largest sheet read: the answers are a handful of short strings.
pub const MAX_SHEET_BYTES: u64 = 64 * 1024;

/// One first-run answer sheet. Every field is optional: a file that answers
/// two questions and leaves the rest is valid, and the wizard asks the rest.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ProvisioningAnswers {
    /// Connection name (not the adapter description) of the main link, e.g.
    /// `"Ethernet"`. A name that no longer exists leaves the slot unanswered.
    pub primary_connection: Option<String>,
    /// Same for the additional link.
    pub secondary_connection: Option<String>,
    /// `off` | `sites` | `everything`. `sites` under the additional-connection
    /// default route is taken as `everything`, as the wizard does.
    pub leak_protection: Option<LeakProtectionDto>,
    /// Keep browsers from resolving routed hosts past NetRuleRouter.
    pub doh_lockdown: Option<bool>,
    /// Route hosts by name so an address shared with another site is not
    /// dragged along.
    pub fake_ip: Option<bool>,
    /// Rule set to import, as `<country>/<pack>` under the bundled presets;
    /// `"none"` starts empty.
    pub rule_set: Option<String>,
    /// UI language tag (`"ru"`, `"en"`). Absent = follow the OS.
    pub language: Option<String>,
}

impl ProvisioningAnswers {
    /// Does this sheet answer everything the wizard would otherwise ask? Only
    /// then may the wizard be skipped outright.
    ///
    /// The connections are deliberately NOT part of the bar: an installer
    /// cannot know which adapter a VPN client will create on first connect.
    pub fn completes_first_run(&self) -> bool {
        self.leak_protection.is_some()
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

/// What a search found, and every sheet it passed over with the reason, for
/// the caller to report in its own way.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SheetSearch {
    pub found: Option<LoadedProvisioning>,
    pub ignored: Vec<String>,
}

/// One place a sheet may come from, and whether it must be shown to have been
/// placed by an administrator before it is believed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub path: PathBuf,
    pub admin_only: bool,
}

/// Whether a sheet next to the executable is believed as found, or only once
/// it is shown that no ordinary account could have placed or changed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BesideBinary {
    Believed,
    NeedsProof,
}

/// Search order: next to the executable (portable copy, installer payload),
/// then `machine_dir`, the per-OS folder an administrator fills. Never a
/// directory above either: a sheet there could be planted by another local
/// user and would seed policy.
pub fn candidate_paths(
    executable_dir: Option<&Path>,
    beside_binary: BesideBinary,
    machine_dir: Option<&Path>,
) -> Vec<Candidate> {
    let beside = executable_dir.map(|dir| Candidate {
        path: dir.join(PROVISIONING_FILE_NAME),
        admin_only: beside_binary == BesideBinary::NeedsProof,
    });
    let machine = machine_dir.map(|dir| Candidate {
        path: dir.join(PROVISIONING_FILE_NAME),
        admin_only: true,
    });
    beside.into_iter().chain(machine).collect()
}

/// An `admin_only` candidate as the OS check left it. The sheet is read from
/// the file the check opened, so what was judged is what is read.
#[derive(Debug)]
pub enum AdminAuthored {
    Missing,
    /// Present, but an ordinary account could have placed or changed it.
    Refused(String),
    Opened(std::fs::File),
}

/// Walks `candidates` in order. An `admin_only` sheet counts only when
/// `open_admin_authored` opens it: the machine folder may predate the service
/// and be created by any local account, and where the install folder is the
/// administrator's place, a copy anyone can write is not.
pub fn search(
    candidates: &[Candidate],
    open_admin_authored: &dyn Fn(&Path) -> AdminAuthored,
) -> SheetSearch {
    let mut result = SheetSearch::default();
    for candidate in candidates {
        let shown = candidate.path.display();
        let read = if candidate.admin_only {
            match open_admin_authored(&candidate.path) {
                AdminAuthored::Missing => continue,
                AdminAuthored::Refused(why) => {
                    result
                        .ignored
                        .push(format!("{shown}: not placed by an administrator ({why})"));
                    continue;
                }
                AdminAuthored::Opened(file) => read_open_sheet(file).map(Some),
            }
        } else {
            read_sheet(&candidate.path)
        };
        match read {
            Ok(Some(answers)) => {
                result.found = Some(LoadedProvisioning {
                    answers,
                    source_path: candidate.path.clone(),
                });
                return result;
            }
            Ok(None) => {}
            // A malformed sheet must not take the wizard down with it: the
            // user still has to be able to set the app up by hand.
            Err(message) => result.ignored.push(format!("{shown}: {message}")),
        }
    }
    result
}

/// `Ok(None)` = no file there. `Err` = the file exists but could not be used.
pub fn read_sheet(path: &Path) -> Result<Option<ProvisioningAnswers>, String> {
    match std::fs::File::open(path) {
        Ok(file) => read_open_sheet(file).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// The sheet in an already open file, under the same size bound.
fn read_open_sheet(file: std::fs::File) -> Result<ProvisioningAnswers, String> {
    let mut bytes = Vec::new();
    file.take(MAX_SHEET_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    parse_sheet(&bytes)
}

/// Parses sheet bytes; the one entry point the fuzz target calls.
pub fn parse_sheet(bytes: &[u8]) -> Result<ProvisioningAnswers, String> {
    if bytes.len() as u64 > MAX_SHEET_BYTES {
        return Err(format!("larger than {MAX_SHEET_BYTES} bytes"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "not UTF-8 text".to_string())?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let answers: ProvisioningAnswers =
        serde_json::from_str(text).map_err(|e| format!("not a valid answer sheet: {e}"))?;
    if answers.is_empty() {
        return Err("answer sheet is empty".to_string());
    }
    Ok(answers)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refuse(path: &Path) -> AdminAuthored {
        if path.exists() {
            AdminAuthored::Refused("planted".to_owned())
        } else {
            AdminAuthored::Missing
        }
    }
    fn believe(path: &Path) -> AdminAuthored {
        match std::fs::File::open(path) {
            Ok(file) => AdminAuthored::Opened(file),
            Err(_) => AdminAuthored::Missing,
        }
    }

    /// A sheet swapped between the check and the read must not be what is
    /// read: the answers come from the file the check opened.
    #[test]
    fn the_sheet_read_is_the_file_the_check_opened() {
        let dir = tempfile::tempdir().expect("dir");
        let checked = dir.path().join("checked.json");
        std::fs::write(&checked, SHEET).expect("write");
        std::fs::write(
            dir.path().join(PROVISIONING_FILE_NAME),
            r#"{"rule-set":"swapped-in"}"#,
        )
        .expect("write");
        let candidates = candidate_paths(Some(dir.path()), BesideBinary::NeedsProof, None);
        let opened_checked =
            |_: &Path| AdminAuthored::Opened(std::fs::File::open(&checked).expect("open"));
        let found = search(&candidates, &opened_checked).found.expect("sheet");
        assert_eq!(found.answers.rule_set.as_deref(), Some("none"));
    }

    const SHEET: &str =
        r#"{"leak-protection":"off","doh-lockdown":false,"fake-ip":false,"rule-set":"none"}"#;

    #[test]
    fn the_sheet_is_looked_for_only_beside_the_binary_and_in_the_machine_folder() {
        let binary_dir = Path::new("package").join("bin");
        let machine_dir = Path::new("machine");
        assert_eq!(
            candidate_paths(Some(&binary_dir), BesideBinary::Believed, Some(machine_dir)),
            vec![
                Candidate {
                    path: binary_dir.join(PROVISIONING_FILE_NAME),
                    admin_only: false,
                },
                Candidate {
                    path: machine_dir.join(PROVISIONING_FILE_NAME),
                    admin_only: true,
                },
            ]
        );
    }

    #[test]
    fn a_machine_sheet_an_ordinary_account_could_have_placed_is_ignored() {
        let machine_dir = tempfile::tempdir().expect("dir");
        std::fs::write(machine_dir.path().join(PROVISIONING_FILE_NAME), SHEET).expect("plant");
        let candidates = candidate_paths(None, BesideBinary::Believed, Some(machine_dir.path()));
        let refused = search(&candidates, &refuse);
        assert_eq!(refused.found, None);
        assert_eq!(refused.ignored.len(), 1);
        let believed = search(&candidates, &believe).found.expect("admin sheet");
        assert!(believed.answers.completes_first_run());
    }

    #[test]
    fn the_sheet_beside_the_binary_needs_no_proof_of_authorship() {
        let binary_dir = tempfile::tempdir().expect("dir");
        std::fs::write(binary_dir.path().join(PROVISIONING_FILE_NAME), SHEET).expect("write");
        let candidates = candidate_paths(Some(binary_dir.path()), BesideBinary::Believed, None);
        assert!(search(&candidates, &refuse).found.is_some());
    }

    /// Where the install folder is the administrator's place for the sheet, a
    /// copy of the program in a folder anyone can write must not seed the
    /// setup of whoever runs it; the reason is reported.
    #[test]
    fn a_sheet_beside_the_binary_that_needs_proof_is_believed_only_with_it() {
        let binary_dir = tempfile::tempdir().expect("dir");
        std::fs::write(binary_dir.path().join(PROVISIONING_FILE_NAME), SHEET).expect("write");
        let candidates = candidate_paths(Some(binary_dir.path()), BesideBinary::NeedsProof, None);
        let refused = search(&candidates, &refuse);
        assert_eq!(refused.found, None);
        assert_eq!(refused.ignored.len(), 1, "{:?}", refused.ignored);
        assert!(search(&candidates, &believe).found.is_some());
    }

    #[test]
    fn a_broken_sheet_is_reported_and_the_search_goes_on() {
        let beside = tempfile::tempdir().expect("dir");
        let machine = tempfile::tempdir().expect("dir");
        std::fs::write(beside.path().join(PROVISIONING_FILE_NAME), "{nope").expect("write");
        std::fs::write(machine.path().join(PROVISIONING_FILE_NAME), SHEET).expect("write");
        let candidates = candidate_paths(
            Some(beside.path()),
            BesideBinary::Believed,
            Some(machine.path()),
        );
        let result = search(&candidates, &believe);
        assert!(result.found.is_some());
        assert_eq!(result.ignored.len(), 1);
    }

    #[test]
    fn an_oversized_sheet_is_refused_unread() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join(PROVISIONING_FILE_NAME);
        let padding = " ".repeat(MAX_SHEET_BYTES as usize);
        std::fs::write(&path, format!("{padding}{SHEET}")).expect("write");
        assert!(read_sheet(&path).is_err());
    }

    #[test]
    fn bytes_that_are_not_text_are_refused_not_panicked_on() {
        assert!(parse_sheet(&[0xff, 0xfe, 0x00, 0x80]).is_err());
        assert!(parse_sheet(b"").is_err());
        assert!(parse_sheet(b"[]").is_err());
        assert!(parse_sheet(b"{}").is_err());
    }

    #[test]
    fn a_sheet_with_a_byte_order_mark_is_read() {
        let mut bytes = vec![0xef, 0xbb, 0xbf];
        bytes.extend_from_slice(SHEET.as_bytes());
        assert!(parse_sheet(&bytes).is_ok());
    }

    #[test]
    fn a_sheet_answering_every_gate_question_skips_the_wizard() {
        let answers = ProvisioningAnswers {
            leak_protection: Some(LeakProtectionDto::Sites),
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
        let parsed = parse_sheet(
            br#"{"primary-connection":"Ethernet","leak-protection":"everything","rule-set":"none"}"#,
        )
        .expect("parses");
        assert_eq!(parsed.primary_connection.as_deref(), Some("Ethernet"));
        assert_eq!(parsed.leak_protection, Some(LeakProtectionDto::Everything));
        assert_eq!(parsed.rule_set.as_deref(), Some("none"));
        assert!(!parsed.completes_first_run());
    }

    #[test]
    fn an_unknown_key_is_refused_rather_than_silently_ignored() {
        assert!(parse_sheet(br#"{"leak-protecton":"off"}"#).is_err());
        assert!(
            parse_sheet(br#"{"kill-switch":true}"#).is_err(),
            "the old key"
        );
    }

    #[test]
    fn leak_protection_takes_exactly_the_three_levels() {
        for (slug, level) in [
            ("off", LeakProtectionDto::Off),
            ("sites", LeakProtectionDto::Sites),
            ("everything", LeakProtectionDto::Everything),
        ] {
            let sheet = format!(r#"{{"leak-protection":"{slug}"}}"#);
            let parsed = parse_sheet(sheet.as_bytes()).expect("parses");
            assert_eq!(parsed.leak_protection, Some(level));
        }
        assert!(parse_sheet(br#"{"leak-protection":true}"#).is_err());
        assert!(parse_sheet(br#"{"leak-protection":"strict"}"#).is_err());
    }
}
