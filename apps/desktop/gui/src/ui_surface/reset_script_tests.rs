use super::*;

#[test]
fn recovery_script_resolves_and_its_command_quotes_the_path() {
    let path =
        resolve_reset_script_path().expect("the source tree always carries the recovery script");
    let path = path.to_string_lossy().into_owned();
    let command = reset_script_command_line(&path);
    assert!(
        command.contains(&format!("\"{path}\"")),
        "the path must be quoted so a space in it cannot split the command: {command}"
    );
}

#[test]
fn a_bundled_resource_is_never_taken_from_a_parent_directory() {
    let root = env::temp_dir().join(format!("nrr-gui-bundled-{}", std::process::id()));
    let binary_dir = root.join("package");
    let planted = root.join("scripts");
    fs::create_dir_all(&binary_dir).expect("binary dir");
    fs::create_dir_all(&planted).expect("planted dir");
    fs::write(planted.join("reset-network.ps1"), "planted").expect("planted file");

    let relative = "scripts/reset-network.ps1";
    let from_parent = find_bundled(Some(&binary_dir), None, relative);

    let shipped = binary_dir.join("scripts");
    fs::create_dir_all(&shipped).expect("shipped dir");
    fs::write(shipped.join("reset-network.ps1"), "shipped").expect("shipped file");
    let with_both = find_bundled(Some(&binary_dir), Some(&root), relative);
    let _ = fs::remove_dir_all(&root);

    assert_eq!(from_parent, None);
    assert_eq!(with_both, Some(shipped.join("reset-network.ps1")));
}
