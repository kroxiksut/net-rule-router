use super::*;

fn scratch(name: &str) -> PathBuf {
    let root = env::temp_dir().join(format!("nrr-gui-assets-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("scratch dir");
    root
}

/// A package whose QML sits anywhere still finds its icons: the root is the
/// folder beside the binary, whatever the depth of the QML tree.
#[test]
fn a_package_finds_its_assets_beside_the_binary() {
    let root = scratch("package");
    let package = root.join("NetRuleRouter");
    fs::create_dir_all(package.join("assets").join("icons").join("ui")).expect("package assets");
    let checkout = root.join("checkout");
    fs::create_dir_all(checkout.join("assets")).expect("checkout assets");

    let found = assets_root_in(Some(&package), Some(&checkout));
    let _ = fs::remove_dir_all(&root);

    assert_eq!(found, Some(package.join("assets")));
}

/// Another local user can create `assets` above a portable copy (a drive root,
/// a shared folder); the window must not draw what they planted.
#[test]
fn assets_planted_above_the_package_are_never_used() {
    let root = scratch("planted");
    let package = root.join("NetRuleRouter");
    fs::create_dir_all(&package).expect("package dir");
    fs::create_dir_all(root.join("assets").join("icons").join("ui")).expect("planted assets");

    let found = assets_root_in(Some(&package), None);
    let _ = fs::remove_dir_all(&root);

    assert_eq!(found, None);
}

/// A stray file named `assets` beside a dev binary must not hide the checkout.
#[test]
fn a_file_named_assets_does_not_shadow_the_checkout() {
    let root = scratch("file");
    let binary_dir = root.join("target");
    fs::create_dir_all(&binary_dir).expect("binary dir");
    fs::write(binary_dir.join("assets"), "not a folder").expect("stray file");
    let checkout = root.join("checkout");
    fs::create_dir_all(checkout.join("assets")).expect("checkout assets");

    let found = assets_root_in(Some(&binary_dir), Some(&checkout));
    let _ = fs::remove_dir_all(&root);

    assert_eq!(found, Some(checkout.join("assets")));
}

/// Without the field the QML has no root to build any icon from, and every
/// image in the window comes up empty.
#[test]
fn the_window_context_carries_the_assets_root() {
    let shell = nrr_shared::gui_shell_v1();
    let first_run = nrr_ui_support::first_run::first_run_flow_snapshot(&shell);
    let request = crate::app_shell::LaunchRequest {
        source: nrr_shared::ActivationSource::Tray,
        section: None,
        open_about: false,
        open_license: false,
        first_run_completed_override: None,
        action: None,
        reason: None,
        focus: None,
        focus_context: None,
    };
    let root = scratch("context");
    let path = root.join("context.json");
    write_qt_context_file_at(
        &path,
        &shell,
        AppSection::Rules,
        UiPreferences::default(),
        &first_run,
        &request,
        &nrr_application::backend_facade::MockBackendFacade::default(),
        &BackendConnectionStatus::Connected,
        false,
        false,
        &HostAnswerDeadlines::default(),
        &nrr_platform_api::admin_authored::TrustNothing,
    )
    .expect("write context");
    let raw = fs::read_to_string(&path).expect("read context");
    let _ = fs::remove_dir_all(&root);
    let json: serde_json::Value = serde_json::from_str(&raw).expect("parse context");

    // A test binary has no package around it, so the checkout's folder answers.
    let checkout_assets = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("checkout root")
        .join("assets");
    assert_eq!(
        json["assetsRootUrl"].as_str(),
        Some(path_to_file_url(&checkout_assets).as_str())
    );
}
