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
