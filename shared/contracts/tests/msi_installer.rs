#![allow(clippy::expect_used)]

//! What the MSI owes the person installing or removing it. Nothing in the gate
//! builds or runs the package, so these are read from its source.

use std::path::Path;

fn read(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    let text = std::fs::read_to_string(&path).expect("a packaging file");
    text.trim_start_matches('\u{feff}').replace("\r\n", "\n")
}

fn wxs() -> String {
    read("packaging/windows/NetRuleRouter.wxs")
}

/// The opening tag holding `needle`, from its `<` to its closing `>`.
fn tag_with<'a>(text: &'a str, needle: &str) -> Option<&'a str> {
    let at = text.find(needle)?;
    let start = text[..=at].rfind('<')?;
    let end = at + text[at..].find('>')?;
    Some(&text[start..=end])
}

/// A wizard that goes from the licence straight to installing gives no say in
/// the folder, and one without the exit page's box gives no way to start the
/// program; the window must start as the person who installed, never as the
/// elevated installer.
#[test]
fn the_wizard_asks_for_the_folder_and_offers_to_start_the_program() {
    let wxs = wxs();
    assert!(
        !wxs.contains("WixUI_Minimal"),
        "the minimal wizard has no folder page"
    );
    let to_folder = tag_with(&wxs, "Dialog=\"LicenseAgreementDlg\" Control=\"Next\"")
        .expect("the licence page leads on");
    let folder_dialog = to_folder
        .split("Value=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("the page after the licence");
    let dialog = tag_with(&wxs, &format!("<Dialog Id=\"{folder_dialog}\""))
        .expect("the page after the licence is defined here");
    assert!(dialog.contains("<Dialog"), "{dialog}");
    let folder_start = wxs
        .find(&format!("<Dialog Id=\"{folder_dialog}\""))
        .expect("folder dialog");
    let folder_body =
        &wxs[folder_start..folder_start + wxs[folder_start..].find("</Dialog>").expect("end")];
    assert!(
        folder_body.contains("Type=\"PathEdit\"") && folder_body.contains("WIXUI_INSTALLDIR"),
        "the page after the licence does not let the folder be chosen"
    );

    let launch = tag_with(
        &wxs,
        "Dialog=\"ExitDialog\" Control=\"Finish\" Event=\"DoAction\"",
    )
    .expect("the last page starts the program when its box is ticked");
    let action = launch
        .split("Value=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("the action");
    let custom = tag_with(&wxs, &format!("<CustomAction Id=\"{action}\""))
        .expect("the launch action is defined");
    assert!(custom.contains("WixShellExec"), "{custom}");
    assert!(
        !custom.contains("deferred") && !custom.contains("Impersonate=\"no\""),
        "the window would start elevated: {custom}"
    );
    assert!(wxs.contains("WIXUI_EXITDIALOGOPTIONALCHECKBOXTEXT"));
}

/// The service runs as LocalSystem from the chosen folder, and the removal
/// steps run elevated from it: a folder an ordinary account could change would
/// hand that account the system. The wizard and a silent install with
/// INSTALLFOLDER= both stop at the same rule.
#[test]
fn a_folder_outside_program_files_is_refused_in_the_wizard_and_silently() {
    let wxs = wxs();
    let refused = tag_with(&wxs, "<?define FolderRefused").expect("one rule for both paths");
    assert!(
        refused.contains("ProgramFiles64Folder") && refused.contains("ProgramFilesFolder"),
        "{refused}"
    );
    let sequenced = tag_with(&wxs, "<Custom Action=\"NrrFolderRefused\"")
        .expect("a silent install meets the rule");
    assert!(sequenced.contains("$(var.FolderRefused)"), "{sequenced}");
    let error = tag_with(&wxs, "<CustomAction Id=\"NrrFolderRefused\"").expect("its message");
    assert!(error.contains("Error="), "{error}");
    let spawn = tag_with(&wxs, "Value=\"NrrFolderRefusedDlg\"").expect("the wizard meets the rule");
    assert!(spawn.contains("$(var.FolderRefused)"), "{spawn}");
}

/// Removal stopped on "unable to automatically close all requested
/// applications": Restart Manager cannot close the launchers, which have no
/// window, nor a service that restarts after a stop it did not ask for, and
/// the MSI stopped the service only after that check.
#[test]
fn removal_closes_the_program_itself_before_the_files_in_use_check() {
    let wxs = wxs();
    let rm = tag_with(&wxs, "<Property Id=\"MSIRESTARTMANAGERCONTROL\"")
        .expect("Restart Manager is told what to do");
    assert!(rm.contains("Value=\"Disable\""), "{rm}");

    let user = tag_with(&wxs, "<Custom Action=\"NrrCloseAppsUser\"").expect("closed as the user");
    assert!(
        user.contains("After=\"NrrFolderRefused\"") || user.contains("Before=\"InstallValidate\""),
        "the installing user's window is closed after the files-in-use check: {user}"
    );
    let refused = tag_with(&wxs, "<Custom Action=\"NrrFolderRefused\"").expect("refusal");
    assert!(refused.contains("After=\"CostFinalize\""), "{refused}");

    let elevated = tag_with(&wxs, "<Custom Action=\"NrrCloseApps\"").expect("every session's");
    assert!(
        elevated.contains("After=\"InstallInitialize\""),
        "{elevated}"
    );
    let deferred = tag_with(&wxs, "<CustomAction Id=\"NrrCloseApps\"").expect("defined");
    assert!(
        deferred.contains("Execute=\"deferred\"") && deferred.contains("Impersonate=\"no\""),
        "{deferred}"
    );
    for action in ["SetNrrCloseAppsUser", "Id=\"NrrCloseApps\" Sequence"] {
        let set = tag_with(&wxs, action).expect("its command line");
        assert!(set.contains("-Action CloseApps"), "{set}");
    }
    assert!(read("packaging/windows/setup-actions.ps1").contains("'CloseApps' {"));
}

/// Every folder on PATH is searched for DLLs by other programs; the program
/// folder holds Qt and runtime DLLs they would load instead of their own.
#[test]
fn path_names_the_console_links_folder_never_the_program_folder() {
    let wxs = wxs();
    let environment = tag_with(&wxs, "<Environment ").expect("the PATH option");
    assert!(
        environment.contains("Value=\"[INSTALLFOLDER]bin\""),
        "{environment}"
    );
    let actions = read("packaging/windows/setup-actions.ps1");
    assert!(actions.contains("-ItemType SymbolicLink"));
}

fn package_script() -> String {
    read("scripts/package-windows.ps1")
}

/// The `Id`s of the `<String>` entries of a localization file.
fn loc_ids(wxl: &str) -> std::collections::BTreeSet<String> {
    wxl.split("<String Id=\"")
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
        .map(str::to_owned)
        .collect()
}

/// The value of attribute `name` in `tag`.
fn attribute<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let at = tag.find(&format!(" {name}=\""))? + name.len() + 3;
    tag[at..].split('"').next()
}

/// The installer showed MPL-2.0 as the licence to accept: the person installing
/// must accept the product's own agreement, in the wizard's language.
#[test]
fn the_licence_page_shows_the_agreement_in_the_wizard_language() {
    let script = package_script();
    for (culture, agreement) in [
        ("en-US", r"docs\legal\eula.en.md"),
        ("ru-RU", r"docs\legal\eula.ru.md"),
    ] {
        assert!(
            script.contains(&format!("Culture = '{culture}'"))
                && script.contains(&format!("Agreement = '{agreement}'")),
            "the {culture} wizard is not given {agreement}"
        );
    }
    assert!(
        !script.contains("ConvertTo-RtfFile -Source (Join-Path $repoRoot 'LICENSE')"),
        "the licence page is still made from LICENSE (MPL-2.0)"
    );
    let wxs = wxs();
    let licence = tag_with(&wxs, "Id=\"WixUILicenseRtf\"").expect("the licence page's text");
    assert_eq!(attribute(licence, "Value"), Some("$(var.LicenseRtf)"));
    let passed = script
        .lines()
        .find(|line| line.contains("\"LicenseRtf="))
        .expect("the build is given the licence text");
    assert!(
        passed.contains("$culture.Rtf") || passed.contains("$agreementRtf"),
        "the licence text is not the culture's agreement: {passed}"
    );
}

/// The MSI was English only on a Russian Windows, while the EXE asks for the
/// language: the Russian wizard is carried inside the one MSI and Windows
/// Installer picks it by the display language.
#[test]
fn a_russian_windows_gets_the_russian_wizard() {
    let script = package_script();
    assert!(script.contains("'-culture'"), "no culture is built");
    assert!(
        script.contains("Culture = 'ru-RU'; Lcid = 1049"),
        "the Russian build is not listed with its language id"
    );
    assert!(
        script.contains("'msi', 'transform'") && script.contains("_Storages"),
        "the Russian wizard is not embedded as a language transform"
    );
    // The release check proves it on the built MSI, not only on its source.
    let check = read("scripts/check-windows-package.ps1");
    assert!(
        check.contains("_Storages") && check.contains("ProductLanguage"),
        "check-windows-package.ps1 does not look for the Russian transform"
    );

    let wxs = wxs();
    let english = read("packaging/windows/NetRuleRouter.en-US.wxl");
    let russian = read("packaging/windows/NetRuleRouter.ru-RU.wxl");
    let (en_ids, ru_ids) = (loc_ids(&english), loc_ids(&russian));
    assert!(!en_ids.is_empty());
    assert_eq!(en_ids, ru_ids, "a text is missing in one language");
    for used in wxs.split("!(loc.Nrr").skip(1) {
        let id = format!("Nrr{}", used.split(')').next().unwrap_or_default());
        assert!(en_ids.contains(&id), "{id} is not translated");
    }
    let ru_head = tag_with(&russian, "<WixLocalization").expect("head");
    assert_eq!(attribute(ru_head, "Culture"), Some("ru-RU"));
    assert_eq!(attribute(ru_head, "Codepage"), Some("1251"));
    assert_eq!(attribute(ru_head, "Language"), Some("1049"));

    // Our own pages and messages carry no text of their own language.
    let mut rest = wxs.as_str();
    while let Some(at) = rest.find("<Dialog Id=\"Nrr") {
        let body = &rest[at..at + rest[at..].find("</Dialog>").expect("end")];
        for text in body.split(" Text=\"").skip(1) {
            let value = text.split('"').next().unwrap_or_default();
            assert!(
                value
                    .trim_start_matches("{\\WixUI_Font_Title}")
                    .starts_with("!(loc."),
                "untranslated text in {}: {value}",
                &body[..body.find('\n').unwrap_or(body.len())]
            );
        }
        rest = &rest[at + 1..];
    }
    for (needle, name) in [
        ("<MajorUpgrade", "DowngradeErrorMessage"),
        ("<Launch Condition", "Message"),
        ("<CustomAction Id=\"NrrFolderRefused\"", "Error"),
        ("Id=\"WIXUI_EXITDIALOGOPTIONALCHECKBOXTEXT\"", "Value"),
    ] {
        let tag = tag_with(&wxs, needle).expect(needle);
        assert!(
            attribute(tag, name).is_some_and(|v| v.starts_with("!(loc.")),
            "untranslated: {tag}"
        );
    }
    // Installed under one display language, upgraded under another.
    let upgrade = tag_with(&wxs, "<MajorUpgrade").expect("upgrade");
    assert!(upgrade.contains("IgnoreLanguage=\"yes\""), "{upgrade}");
}

/// Removed from Settings > Apps, the MSI ran with no dialog and kept every
/// setting: a reinstall then never showed the first-run screen. The entry
/// there must open the wizard, whose removal asks whether to keep the data;
/// a silent removal keeps it unless told otherwise.
#[test]
fn removal_from_settings_asks_whether_to_keep_the_data() {
    let wxs = wxs();
    let hidden = tag_with(&wxs, "<Property Id=\"ARPSYSTEMCOMPONENT\"")
        .expect("the package's own entry, which removes with no dialog, is hidden");
    assert_eq!(attribute(hidden, "Value"), Some("1"));

    let key = tag_with(
        &wxs,
        r#"<RegistryKey Root="HKLM" Key="SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\"#,
    )
    .expect("an Apps entry of its own");
    let start = wxs.find(key).expect("key");
    let entry = &wxs[start..start + wxs[start..].find("</RegistryKey>").expect("end")];
    let value = |name: &str| {
        tag_with(entry, &format!("Name=\"{name}\""))
            .and_then(|tag| attribute(tag, "Value"))
            .unwrap_or_else(|| panic!("the Apps entry has no {name}"))
    };
    assert_eq!(value("UninstallString"), "MsiExec.exe /I[ProductCode]");
    let quiet = value("QuietUninstallString");
    assert!(
        quiet.contains("/X[ProductCode]")
            && quiet.contains("/qn")
            && !quiet.contains("REMOVEALLDATA"),
        "{quiet}"
    );
    for name in [
        "DisplayName",
        "DisplayVersion",
        "Publisher",
        "DisplayIcon",
        "EstimatedSize",
        "InstallLocation",
    ] {
        assert!(!value(name).is_empty(), "{name}");
    }
    assert!(key.contains("ForceDeleteOnUninstall=\"yes\""), "{key}");

    let remove = tag_with(
        &wxs,
        "Dialog=\"MaintenanceTypeDlg\" Control=\"RemoveButton\" Event=\"NewDialog\"",
    )
    .expect("Remove leads on");
    let page = attribute(remove, "Value").expect("to a page");
    assert_ne!(page, "VerifyReadyDlg", "Remove goes straight to removing");
    let page_start = wxs
        .find(&format!("<Dialog Id=\"{page}\""))
        .expect("the removal page is defined here");
    let body = &wxs[page_start..page_start + wxs[page_start..].find("</Dialog>").expect("end")];
    let group = tag_with(body, "Type=\"RadioButtonGroup\"").expect("a choice");
    let choice = attribute(group, "Property").expect("its property");
    let default = tag_with(&wxs, &format!("<Property Id=\"{choice}\""))
        .and_then(|tag| attribute(tag, "Value"))
        .expect("a default choice");
    let erase = tag_with(
        &wxs,
        &format!("Dialog=\"{page}\" Control=\"Next\" Property=\"REMOVEALLDATA\" Value=\"1\""),
    )
    .expect("the complete choice asks for the data to go");
    let condition = attribute(erase, "Condition")
        .expect("only on that choice")
        .replace("&quot;", "\"");
    let chosen = condition.split('"').nth(1).unwrap_or_default();
    assert!(
        condition.trim_start().starts_with(choice) && !chosen.is_empty() && chosen != default,
        "the default choice erases the data: {erase}"
    );
    let secure = tag_with(&wxs, "<Property Id=\"REMOVEALLDATA\"").expect("declared");
    assert!(
        secure.contains("Secure=\"yes\""),
        "the choice never reaches the removal: {secure}"
    );
}

/// The body of the element that starts at the tag holding `needle`, up to its
/// closing `</{element}>`.
fn element_with<'a>(text: &'a str, needle: &str, element: &str) -> Option<&'a str> {
    let at = text.find(needle)?;
    let start = text[..=at].rfind('<')?;
    let end = start + text[start..].find(&format!("</{element}>"))?;
    Some(&text[start..end])
}

/// The EXE asked whose Start menu, desktop and PATH get NetRuleRouter; the MSI
/// put them in every account's, and someone installing for themselves alone
/// had no way to say so. The program and the service stay per machine either
/// way.
#[test]
fn the_wizard_asks_whether_the_shortcuts_and_path_are_for_everyone_or_only_me() {
    let wxs = wxs();
    // The buttons hold NRR_INSTALL_FOR itself, or a copy their page hands back.
    let choice = wxs
        .split("Type=\"RadioButtonGroup\"")
        .skip(1)
        .find(|rest| {
            rest.split('>')
                .next()
                .is_some_and(|tag| tag.contains("Property=\"NRR_INSTALL_FOR"))
        })
        .expect("a page with the choice");
    let head = format!(" {}", choice.split('>').next().unwrap_or_default());
    let held = attribute(&head, "Property").expect("its property");
    let at = choice.as_ptr() as usize - wxs.as_ptr() as usize;
    let page_start = wxs[..at].rfind("<Dialog Id=\"").expect("on a page");
    let page = wxs[page_start + "<Dialog Id=\"".len()..]
        .split('"')
        .next()
        .expect("page id");
    let body = element_with(&wxs, &format!("<Dialog Id=\"{page}\""), "Dialog").expect("page");
    for value in ["all", "me"] {
        assert!(
            body.contains(&format!("<RadioButton Value=\"{value}\"")),
            "the page offers no `{value}`"
        );
    }
    let reached = wxs
        .split("<Publish ")
        .skip(1)
        .filter_map(|rest| rest.split("/>").next())
        .any(|publish| {
            publish.contains("Event=\"NewDialog\"")
                && publish.contains(&format!("Value=\"{page}\""))
                && !publish.contains(&format!("Dialog=\"{page}\""))
        });
    assert!(reached, "no page of the wizard leads to {page}");
    if held != "NRR_INSTALL_FOR" {
        let handed = tag_with(
            &wxs,
            &format!("Dialog=\"{page}\" Control=\"Next\" Property=\"NRR_INSTALL_FOR\""),
        )
        .expect("the page hands the choice back");
        assert_eq!(
            attribute(handed, "Value"),
            Some(format!("[{held}]").as_str())
        );
    }

    let property = tag_with(&wxs, "<Property Id=\"NRR_INSTALL_FOR\"").expect("declared");
    assert!(
        property.contains("Secure=\"yes\""),
        "the choice never reaches the elevated half: {property}"
    );
    let remembered = tag_with(&wxs, "Name=\"InstallFor\" Type=\"raw\"")
        .expect("an upgrade reads the earlier choice back");
    assert!(
        remembered.contains(r"SOFTWARE\NetRuleRouter\Setup"),
        "{remembered}"
    );
    let choices = element_with(&wxs, "<Component Id=\"SetupChoices\"", "Component").expect("kept");
    assert!(
        choices.contains("Name=\"InstallFor\"") && choices.contains("[NRR_INSTALL_FOR]"),
        "the choice is not kept for the next installation: {choices}"
    );
    let refused = tag_with(&wxs, "<Custom Action=\"NrrInstallForRefused\"")
        .expect("a value other than all or me stops the installation");
    assert!(refused.contains("NRR_INSTALL_FOR"), "{refused}");
}

/// Shortcuts and the PATH entry go to exactly the scope chosen: every
/// account's folders and the machine PATH, or the installing person's own
/// folders, kept by an HKCU key, and their own PATH.
#[test]
fn every_shortcut_and_path_entry_belongs_to_one_scope() {
    let wxs = wxs();
    let components: Vec<&str> = wxs
        .split("<Component")
        .skip(1)
        .filter(|rest| rest.starts_with([' ', '>']))
        .map(|rest| &rest[..rest.find("</Component>").unwrap_or(rest.len())])
        .filter(|body| body.contains("<Shortcut ") || body.contains("<Environment "))
        .collect();
    let (mut all, mut me) = (Vec::new(), Vec::new());
    for body in &components {
        let head = &body[..body.find('>').unwrap_or(body.len())];
        let condition = attribute(&format!(" {head}"), "Condition")
            .unwrap_or_default()
            .replace("&quot;", "\"");
        assert!(
            !body.contains("<File "),
            "a shortcut rides on a file and cannot follow the choice: {head}"
        );
        let for_all = condition.contains("NRR_INSTALL_FOR<>\"me\"")
            || condition.contains("NOT (NRR_INSTALL_FOR=\"me\")");
        if !for_all && condition.contains("NRR_INSTALL_FOR=\"me\"") {
            me.push(*body);
            assert!(
                body.contains("Root=\"HKCU\"") && body.contains("KeyPath=\"yes\""),
                "a per-user shortcut or PATH entry kept by no HKCU key: {head}"
            );
            assert!(
                !body.contains("System=\"yes\"")
                    && !body.contains("Directory=\"ProgramMenuFolder\"")
                    && !body.contains("Directory=\"DesktopFolder\""),
                "only me reaches every account: {head}"
            );
        } else {
            assert!(for_all, "follows neither choice: {head} {condition}");
            all.push(*body);
            assert!(
                !body.contains("Root=\"HKCU\"") && !body.contains("System=\"no\""),
                "all users lands in one account: {head}"
            );
        }
    }
    let shortcuts = |set: &[&str]| set.iter().filter(|b| b.contains("<Shortcut ")).count();
    let paths = |set: &[&str]| set.iter().filter(|b| b.contains("<Environment ")).count();
    assert_eq!(
        (shortcuts(&all), paths(&all)),
        (2, 1),
        "all users: Start menu, desktop, PATH"
    );
    assert_eq!(
        (shortcuts(&me), paths(&me)),
        (2, 1),
        "only me: Start menu, desktop, PATH"
    );
    assert!(
        me.iter().any(|b| b.contains("System=\"no\"")),
        "only me does not use the person's own PATH"
    );

    // Removed by another administrator, the shortcuts go from the profile they
    // were made in, not the remover's.
    let stored = element_with(&wxs, "<Component Id=\"SetupChoices\"", "Component").expect("kept");
    for (value, property) in [
        ("UserPrograms", "NRR_PREV_USER_PROGRAMS"),
        ("UserDesktop", "NRR_PREV_USER_DESKTOP"),
    ] {
        assert!(
            stored.contains(&format!("Name=\"{value}\"")),
            "{value} is not kept"
        );
        let reused = wxs
            .split("<SetProperty ")
            .skip(1)
            .filter_map(|rest| rest.split("/>").next())
            .any(|tag| tag.contains("Installed") && tag.contains(&format!("[{property}]")));
        assert!(
            reused,
            "removal does not go back to the folder {value} named"
        );
    }
}

/// The app skips its own agreement page for the account that accepted the
/// wizard's licence page. The record must come from that page alone: a silent
/// install shows none, and a property given on the command line is no reading.
#[test]
fn the_agreement_is_recorded_only_from_the_wizards_licence_page() {
    let wxs = wxs();
    const PROPERTY: &str = "NRR_AGREEMENT_ACCEPTED_BY";
    const KEY: &str = r#"Key="SOFTWARE\NetRuleRouter\Agreement""#;

    let record = element_with(&wxs, KEY, "RegistryKey").expect("the agreement record");
    assert!(
        record.contains("Name=\"Version\" Type=\"integer\" Value=\"$(var.AgreementVersion)\""),
        "the revision the page showed is not recorded: {record}"
    );
    assert!(
        record.contains(&format!(
            "Name=\"AcceptedBy\" Type=\"string\" Value=\"[{PROPERTY}]\""
        )),
        "the account that accepted is not recorded: {record}"
    );
    let at = wxs.find(KEY).expect("record");
    let component_start = wxs[..at].rfind("<Component ").expect("its component");
    let component =
        &wxs[component_start..component_start + wxs[component_start..].find('>').expect("tag")];
    assert_eq!(
        attribute(component, "Condition"),
        Some(PROPERTY),
        "recorded whether or not the page was accepted"
    );

    // Set in one place: leaving the licence page with the box ticked.
    let setters: Vec<&str> = wxs
        .match_indices(&format!("Property=\"{PROPERTY}\""))
        .filter_map(|(at, _)| {
            let start = wxs[..at].rfind('<')?;
            Some(&wxs[start..at + wxs[at..].find('>')?])
        })
        .collect();
    assert_eq!(setters.len(), 1, "set elsewhere too: {setters:?}");
    let setter = setters[0];
    assert!(
        setter.contains("Dialog=\"LicenseAgreementDlg\" Control=\"Next\"")
            && attribute(setter, "Value") == Some("[UserSID]")
            && attribute(setter, "Condition") == Some("LicenseAccepted = &quot;1&quot;"),
        "{setter}"
    );

    // Cleared where it could come from the command line instead.
    let clears: Vec<&str> = wxs
        .match_indices(&format!("<SetProperty Id=\"{PROPERTY}\""))
        .filter_map(|(at, _)| Some(&wxs[at..at + wxs[at..].find("/>")?]))
        .collect();
    assert!(
        clears.iter().any(|tag| tag.contains("Sequence=\"ui\"")
            && tag.contains("Value=\"[NRR_UNSET]\"")
            && !tag.contains("Condition=")),
        "a value given to the wizard on the command line survives: {clears:?}"
    );
    assert!(
        clears.iter().any(|tag| tag.contains("Sequence=\"execute\"")
            && tag.contains("Value=\"[NRR_UNSET]\"")
            && tag.contains("Condition=\"UILevel &lt; 5\"")),
        "a silent install takes the value from the command line: {clears:?}"
    );
    let declared = tag_with(&wxs, &format!("<Property Id=\"{PROPERTY}\"")).expect("declared");
    assert!(
        declared.contains("Secure=\"yes\""),
        "the wizard's value never reaches the elevated half: {declared}"
    );

    let package = package_script();
    assert!(
        package.contains("'-d', \"AgreementVersion=$agreementVersion\""),
        "the MSI build is not given the agreement's revision"
    );
}

/// The revision both installers record is read from the very text their
/// licence pages show, and the translations must agree on it.
#[test]
fn the_recorded_revision_comes_from_the_agreement_shown() {
    let package = package_script();
    assert!(
        package.contains("Get-AgreementRevision -Source (Join-Path $repoRoot $_.Agreement)"),
        "the revision is not read from the agreements the pages show"
    );
    assert!(
        package.contains("$agreementRevisions.Count -ne 1"),
        "translations naming different revisions are not refused"
    );
}

/// Removal from Settings → Apps runs msiexec without `/l`: only the
/// `MsiLogging` property makes that run, or an install from Explorer, keep a log.
#[test]
fn every_msi_run_keeps_a_log_without_being_asked() {
    let wxs = wxs();
    let declared = wxs
        .lines()
        .find(|line| line.contains("<Property Id=\"MsiLogging\""))
        .unwrap_or_else(|| panic!("no MsiLogging property: a removal leaves no log"));
    assert!(
        declared.contains("Value=\"voicewarmupx\""),
        "MsiLogging logs too little to tell why a removal failed: {declared}"
    );
}

/// The progress page said nothing while the MSI closed the program, stopped,
/// registered and started the service: a minute of "Please wait" read as a
/// hang. Every step of ours names itself there, in the wizard's language.
#[test]
fn every_step_of_ours_says_on_the_progress_page_what_it_is_doing() {
    let wxs = wxs();
    let english = read("packaging/windows/NetRuleRouter.en-US.wxl");
    let russian = read("packaging/windows/NetRuleRouter.ru-RU.wxl");
    let steps: Vec<&str> = wxs
        .split("<CustomAction Id=\"")
        .skip(1)
        .filter(|rest| {
            rest.split("/>")
                .next()
                .is_some_and(|tag| tag.contains("DllEntry=\"WixQuietExec\""))
        })
        .filter_map(|rest| rest.split('"').next())
        .collect();
    assert!(steps.len() >= 8, "only {steps:?}");
    for step in steps {
        let text = tag_with(&wxs, &format!("<ProgressText Action=\"{step}\""))
            .unwrap_or_else(|| panic!("{step} runs with nothing on the progress page"));
        let message = attribute(text, "Message").unwrap_or_default();
        let id = message
            .strip_prefix("!(loc.")
            .and_then(|rest| rest.strip_suffix(')'))
            .unwrap_or_else(|| panic!("untranslated: {text}"));
        for wxl in [&english, &russian] {
            let value = tag_with(wxl, &format!("<String Id=\"{id}\""))
                .and_then(|tag| attribute(tag, "Value"))
                .unwrap_or_default();
            assert!(!value.trim().is_empty(), "{id} is empty in a language");
        }
    }
}

/// Asked to see what the installation did, the person had to know Windows
/// Installer keeps its log in %TEMP% under a random name: the last page names it.
#[test]
fn the_last_page_names_the_installation_log() {
    let wxs = wxs();
    let shown = tag_with(&wxs, "<SetProperty Id=\"WIXUI_EXITDIALOGOPTIONALTEXT\"")
        .expect("the last page carries a text of ours");
    assert!(shown.contains("Sequence=\"ui\""), "{shown}");
    let id = attribute(shown, "Value")
        .and_then(|value| value.strip_prefix("!(loc."))
        .and_then(|rest| rest.strip_suffix(')'))
        .unwrap_or_else(|| panic!("untranslated: {shown}"));
    for culture in ["en-US", "ru-RU"] {
        let wxl = read(&format!("packaging/windows/NetRuleRouter.{culture}.wxl"));
        let value = tag_with(&wxl, &format!("<String Id=\"{id}\""))
            .and_then(|tag| attribute(tag, "Value"))
            .unwrap_or_default();
        assert!(
            value.contains("[MsiLogFileLocation]"),
            "the {culture} text does not name the log: {value}"
        );
    }
    // Only a run that keeps a log can name one.
    assert!(wxs.contains("<Property Id=\"MsiLogging\""));
}

/// The owner's rule: the symbol on the glass plate is the app's icon (window,
/// tray, executables, Apps entry); the wizards' own pictures show the symbol
/// without it. The picture comes from a copy the build alone reads: anything
/// under assets\ other than assets\brand ships beside the binaries.
#[test]
fn wizard_pictures_show_the_symbol_and_the_app_keeps_its_icon() {
    let script = package_script();
    let body = script
        .split("function New-InstallerImages {")
        .nth(1)
        .and_then(|rest| rest.split("\n}\n").next())
        .expect("New-InstallerImages");
    assert!(
        body.contains(r"'packaging\windows\art\logo-symbol.png'"),
        "the wizard pictures are not drawn from the symbol: {body}"
    );
    assert!(
        !body.contains(r"assets\icons") && !body.contains(r"assets\brand"),
        "the wizard pictures are drawn from the app icon or unshipped brand art: {body}"
    );
    let symbol = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("packaging/windows/art/logo-symbol.png");
    let bytes = std::fs::read(&symbol).expect("the symbol is in the checkout");
    assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"), "not a PNG");
    // Colour type 6: RGBA, so the symbol sits on the wizard's own background.
    assert_eq!(bytes.get(25), Some(&6), "the symbol has no transparency");
    assert!(
        !script.contains("Copy-Payload 'packaging"),
        "the build's art would ship with the program"
    );

    let wxs = wxs();
    let icon = tag_with(&wxs, "<Icon Id=\"AppIcon\"").expect("the Apps icon");
    assert!(icon.contains(r"assets\icons\app\app.ico"), "{icon}");
    let iss = read("packaging/windows/NetRuleRouter.iss");
    assert!(
        iss.lines()
            .any(|l| l == r"SetupIconFile={#PackageDir}\assets\icons\app\app.ico"),
        "Setup.exe lost the app icon"
    );
    for (needle, define) in [
        ("WixUIBannerBmp", "$(var.BannerBmp)"),
        ("WixUIDialogBmp", "$(var.DialogBmp)"),
    ] {
        let tag = tag_with(&wxs, &format!("Id=\"{needle}\"")).expect(needle);
        assert_eq!(attribute(tag, "Value"), Some(define));
    }
    for line in [
        "WizardImageFile={#WizardImages}",
        "WizardSmallImageFile={#WizardSmallImages}",
    ] {
        assert!(iss.lines().any(|l| l == line), "{line}");
    }
}
