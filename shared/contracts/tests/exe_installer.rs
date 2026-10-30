#![allow(clippy::expect_used)]

//! The EXE installer script holds what a Windows without the Visual C++
//! Redistributable and an unattended deployment rely on. Nothing in the gate
//! compiles or runs the installer, so these are read from the script itself.

use std::path::Path;

fn read(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    let text = std::fs::read_to_string(&path).expect("a packaging file");
    text.trim_start_matches('\u{feff}').replace("\r\n", "\n")
}

fn installer_script() -> String {
    read("packaging/windows/NetRuleRouter.iss")
}

/// The body of the Pascal routine `name`, up to its closing `end;` at column 0.
fn routine<'a>(script: &'a str, name: &str) -> &'a str {
    let head = format!("function {name}(");
    let start = script
        .find(&head)
        .or_else(|| script.find(&format!("procedure {name}(")))
        .unwrap_or_else(|| panic!("{name} not found in the installer script"));
    let body = &script[start..];
    let end = body.find("\nend;").expect("the routine's end");
    &body[..end]
}

#[test]
fn the_service_binary_run_from_tmp_has_its_runtime_beside_it() {
    let script = installer_script();
    let files: Vec<&str> = script
        .lines()
        .filter(|line| line.starts_with("Source:") && line.contains("dontcopy"))
        .collect();
    assert!(
        files.iter().any(|line| line.contains(r"\vcruntime140.dll")),
        "vcruntime140.dll is not stored for extraction to {{tmp}}"
    );

    let check = routine(&script, "CheckProvisioning");
    let exec = check
        .find(r"{tmp}\nrr-service.exe")
        .expect("the provision check runs the service binary from {tmp}");
    let runtime = check
        .find("ExtractTemporaryFile('vcruntime140.dll')")
        .expect("the runtime is extracted beside the service binary");
    assert!(
        runtime < exec,
        "the runtime is extracted after the binary has run"
    );

    // The installer stores only what every package variant carries.
    let contents = read("packaging/windows/package-contents.txt");
    assert!(
        contents
            .lines()
            .any(|line| line.split_whitespace().eq(["all", "vcruntime140.dll"])),
        "package-contents.txt no longer requires vcruntime140.dll in every variant"
    );
}

#[test]
fn a_check_that_did_not_start_is_not_reported_as_a_refused_file() {
    let script = installer_script();
    let check = routine(&script, "CheckProvisioning");
    assert!(
        !check.contains("Code := 14"),
        "a failure to start the check is reported as the service binary's code 14"
    );
    let prepare = routine(&script, "PrepareToInstall");
    assert!(
        prepare.contains("(Refused >= 10) and (Refused <= 14)"),
        "only the service binary's own codes may read as a refused file"
    );
    assert!(prepare.contains("ProvisionNotChecked"));
}

/// An upgrade cancelled, or refused, after Setup stopped the old service left
/// no service running: rules no longer followed, and with protection kept for
/// the new files, the network held by filters nothing maintains.
#[test]
fn a_cancelled_upgrade_starts_the_stopped_service_again() {
    let script = installer_script();
    let prepare = routine(&script, "PrepareToInstall");
    let stop = prepare
        .find("'-Action Stop'")
        .expect("Setup stops the service");
    let remembered = prepare
        .find("ServiceStoppedBySetup := True")
        .expect("the stop is remembered");
    assert!(
        remembered < stop,
        "remembered before the stop runs, so a stop that half-failed counts too"
    );
    let post_install = routine(&script, "CurStepChanged");
    let register = post_install.find("'-Action Register'").expect("register");
    let cleared = post_install
        .find("ServiceStoppedBySetup := False")
        .expect("a finished install hands the service to Register");
    assert!(cleared > register);
    let deinit = routine(&script, "DeinitializeSetup");
    assert!(
        deinit.contains("if ServiceStoppedBySetup then") && deinit.contains("'-Action Resume'"),
        "{deinit}"
    );
    let actions = read("packaging/windows/setup-actions.ps1");
    assert!(
        actions.contains("'Resume' {"),
        "setup-actions.ps1 has no Resume"
    );
}

/// ISCC fills a wizard text missing in one language from another with only a
/// warning, and the package build compiles quietly: a Russian Setup would
/// show English text, or an English one Russian, and nothing would say so.
#[test]
fn every_installer_text_is_written_in_both_languages() {
    let script = installer_script();
    let names = |language: &str| -> std::collections::BTreeSet<String> {
        let prefix = format!("{language}.");
        script
            .lines()
            .filter_map(|line| line.strip_prefix(&prefix))
            .filter_map(|rest| rest.split_once('='))
            .map(|(name, _)| name.to_owned())
            .collect()
    };
    let english = names("english");
    let russian = names("russian");
    assert!(!english.is_empty(), "no english.<Name>= texts found");
    let only_english: Vec<_> = english.difference(&russian).collect();
    let only_russian: Vec<_> = russian.difference(&english).collect();
    assert!(
        only_english.is_empty() && only_russian.is_empty(),
        "texts missing in Russian: {only_english:?}; missing in English: {only_russian:?}"
    );
}

/// Restart Manager cannot close the launchers of the window and the tray,
/// which have no window: an upgrade asked the user to close them, and a
/// removal left their files behind.
#[test]
fn upgrade_and_removal_close_the_program_before_its_files_are_touched() {
    let script = installer_script();
    let prepare = routine(&script, "PrepareToInstall");
    let close = prepare
        .find("'-Action CloseApps")
        .expect("an upgrade closes the window and the tray");
    let stop = prepare.find("'-Action Stop'").expect("the service stops");
    assert!(close < stop, "{prepare}");

    let removal = routine(&script, "CurUninstallStepChanged");
    let close = removal
        .find("'-Action CloseApps'")
        .expect("a removal closes the window and the tray");
    let unregister = removal.find("'-Action Unregister'").expect("unregister");
    assert!(close < unregister, "{removal}");
    assert!(read("packaging/windows/setup-actions.ps1").contains("'CloseApps' {"));
}

/// The service runs as LocalSystem from the folder Setup installs into, and
/// the uninstaller runs scripts from it elevated: the folder page and /DIR=
/// alike must keep to a place only administrators can change.
#[test]
fn the_folder_page_and_a_silent_dir_keep_to_program_files() {
    let script = installer_script();
    assert!(
        !script.contains("DisableDirPage=yes"),
        "the folder cannot be chosen"
    );
    let allowed = routine(&script, "FolderAllowed");
    assert!(
        allowed.contains("{commonpf64}") && allowed.contains("{commonpf32}"),
        "{allowed}"
    );
    let next = routine(&script, "NextButtonClick");
    assert!(
        next.contains("wpSelectDir") && next.contains("FolderAllowed(WizardDirValue())"),
        "{next}"
    );
    let prepare = routine(&script, "PrepareToInstall");
    assert!(
        prepare.contains("FolderAllowed(ExpandConstant('{app}'))"),
        "a silent /DIR= is not checked: {prepare}"
    );
}

/// Every folder on PATH is searched for DLLs by other programs; the program
/// folder holds Qt and runtime DLLs they would load instead of their own.
#[test]
fn path_gets_the_console_links_folder_never_the_program_folder() {
    let script = installer_script();
    let bin = routine(&script, "ConsoleBin");
    assert!(bin.contains("ExpandConstant('{app}\\bin')"), "{bin}");
    let edits: Vec<&str> = script
        .lines()
        .filter(|line| line.trim_start().starts_with("EditPath("))
        .collect();
    assert!(!edits.is_empty(), "nothing puts the console tools on PATH");
    for line in edits {
        assert!(line.contains("ConsoleBin()"), "{line}");
    }
    assert!(script.contains("ChangesEnvironment=yes"));
}

/// Setup showed no licence page at all: each language must show the product
/// agreement in that language, made from the Markdown at package time.
#[test]
fn every_setup_language_shows_the_agreement_in_that_language() {
    let script = installer_script();
    let languages = script
        .split("\n[Languages]\n")
        .nth(1)
        .and_then(|rest| rest.split("\n[").next())
        .expect("a [Languages] section");
    let package = read("scripts/package-windows.ps1");
    let mut seen = 0;
    for line in languages.lines().filter(|line| line.starts_with("Name:")) {
        seen += 1;
        let define = line
            .split("LicenseFile: \"{#")
            .nth(1)
            .and_then(|rest| rest.split('}').next())
            .unwrap_or_else(|| panic!("no agreement for {line}"));
        let suffix = if line.contains("\"russian\"") {
            "ru"
        } else {
            "en"
        };
        let passed = package
            .lines()
            .find(|l| l.contains(&format!("\"/D{define}=")))
            .unwrap_or_else(|| panic!("the package script does not pass {define}"));
        assert!(
            passed.contains(&format!("eula.{suffix}")),
            "{define} is not the {suffix} agreement: {passed}"
        );
    }
    assert_eq!(seen, 2, "{languages}");
    assert!(
        script.contains("#ifndef AgreementEn"),
        "Setup compiles without an agreement"
    );
}

#[test]
fn a_silent_install_without_a_registered_service_does_not_exit_with_zero() {
    let script = installer_script();
    let post_install = routine(&script, "CurStepChanged");
    assert!(
        post_install.contains("RegisterFailed := RunAction("),
        "the outcome of registering the service is not kept"
    );
    let exit_code = routine(&script, "GetCustomSetupExitCode");
    assert!(
        exit_code.contains("RegisterFailed") && exit_code.contains("RegisterFailedExitCode"),
        "the exit code does not reflect a service that failed to register"
    );
    assert!(script.contains("RegisterFailedExitCode = 15;"));
}

/// The arguments of the Pascal call that starts at `call` (just past its `(`),
/// split at top-level commas.
fn call_arguments(call: &str) -> Vec<String> {
    let (mut depth, mut quoted) = (0usize, false);
    let mut arguments = vec![String::new()];
    for c in call.chars() {
        match c {
            '\'' => quoted = !quoted,
            '(' | '[' if !quoted => depth += 1,
            ')' | ']' if !quoted && depth == 0 => break,
            ')' | ']' if !quoted => depth -= 1,
            ',' if !quoted && depth == 0 => {
                arguments.push(String::new());
                continue;
            }
            _ => {}
        }
        if let Some(last) = arguments.last_mut() {
            last.push(c);
        }
    }
    arguments
        .into_iter()
        .map(|a| a.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect()
}

/// "Remove completely" stopped the uninstaller with "Internal error:
/// TaskDialogMsgBox: Invalid Buttons": unlike MsgBox, a task dialog takes only
/// a plain button set, and MB_DEFBUTTON2 made the whole removal fail. Its
/// default is the first button, so the answer that keeps the audit trail must
/// be the first one.
#[test]
fn removal_questions_use_only_button_sets_a_task_dialog_accepts() {
    const PLAIN: [&str; 6] = [
        "MB_OK",
        "MB_OKCANCEL",
        "MB_YESNO",
        "MB_YESNOCANCEL",
        "MB_RETRYCANCEL",
        "MB_ABORTRETRYIGNORE",
    ];
    let script = installer_script();
    let calls: Vec<Vec<String>> = script
        .split("TaskDialogMsgBox(")
        .skip(1)
        .map(call_arguments)
        .collect();
    assert!(!calls.is_empty(), "no TaskDialogMsgBox call found");
    for arguments in &calls {
        let buttons = arguments.get(3).map(String::as_str).unwrap_or_default();
        assert!(
            PLAIN.contains(&buttons),
            "a task dialog with buttons `{buttons}` stops Setup: {arguments:?}"
        );
    }

    let audit = calls
        .iter()
        .find(|arguments| arguments.iter().any(|a| a.contains("UninstallAuditTitle")))
        .expect("the audit question");
    let labels = audit.get(4).map(String::as_str).unwrap_or_default();
    let keep = labels.find("UninstallAuditKeep").expect("a keep answer");
    let erase = labels.find("UninstallAuditErase").expect("an erase answer");
    assert!(
        keep < erase,
        "the default answer erases the audit trail: {labels}"
    );
    let uninstall = routine(&script, "InitializeUninstall");
    assert!(
        uninstall
            .contains("'UninstallAuditKeep'), CustomMessage('UninstallAuditErase')], 0) = IDNO"),
        "erasing is not the second answer: {uninstall}"
    );
}

/// The app skips its own agreement page for the account that accepted the
/// installer's licence page. A record written by a silent Setup, which shows no
/// page, would spare someone who never read the agreement.
#[test]
fn the_agreement_is_recorded_only_after_the_wizard_showed_it_and_it_was_accepted() {
    let script = installer_script();
    let entries: Vec<&str> = script
        .lines()
        .filter(|line| {
            line.starts_with("Root:") && line.contains(r"SOFTWARE\NetRuleRouter\Agreement")
        })
        .collect();
    assert!(
        entries
            .iter()
            .any(|line| line.contains("ValueName: \"Version\"")
                && line.contains("ValueData: \"{#AgreementVersion}\"")),
        "the revision the page showed is not recorded: {entries:?}"
    );
    assert!(
        entries
            .iter()
            .any(|line| line.contains("ValueName: \"AcceptedBy\"")),
        "the account that accepted is not recorded: {entries:?}"
    );
    for entry in &entries {
        assert!(
            entry.contains("Check: AgreementAcceptedInWizard"),
            "recorded whether or not the page was accepted: {entry}"
        );
    }

    let check = routine(&script, "AgreementAcceptedInWizard");
    assert!(
        check.contains("LicenceAcceptedInWizard") && check.contains("not WizardSilent()"),
        "the record does not wait for the licence page: {check}"
    );
    let next = routine(&script, "NextButtonClick");
    assert!(
        next.contains("CurPageID = wpLicense") && next.contains("LicenseAcceptedRadio.Checked"),
        "leaving the licence page does not note the acceptance: {next}"
    );
    assert!(
        script.contains("#ifndef AgreementVersion"),
        "a build without the revision would record a wrong one"
    );
    let package = read("scripts/package-windows.ps1");
    assert!(
        package.contains("\"/DAgreementVersion=$agreementVersion\""),
        "the EXE build is not given the agreement's revision"
    );
}

/// The account is the one Setup runs as, read from the system, never a name
/// that a second account could share or a value from the command line.
#[test]
fn the_account_recorded_is_the_one_setup_runs_as() {
    let script = installer_script();
    let account = routine(&script, "SetupAccountSid");
    assert!(
        account.contains(r"{sys}\whoami.exe") && account.contains("/user"),
        "the account is not read from the system: {account}"
    );
    assert!(
        !account.contains("{param:"),
        "the command line names the account"
    );
    assert!(
        !account.contains("GetUserNameString"),
        "a user name is not an account"
    );
}

/// Uninstalling leaves nothing that would spare a later installation's user.
#[test]
fn removal_takes_the_agreement_record_with_it() {
    let script = installer_script();
    let removal = routine(&script, "CurUninstallStepChanged");
    assert!(
        removal
            .contains(r"RegDeleteKeyIncludingSubkeys(HKLM64, 'SOFTWARE\NetRuleRouter\Agreement')"),
        "the agreement record outlives the program: {removal}"
    );
}
