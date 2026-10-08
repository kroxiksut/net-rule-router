//! "Start when the app opens" is offered only where the service control can
//! carry it out, and the refusal a platform gives for it reads as a sentence in
//! the user's language rather than the launcher's English detail.
#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

use nrr_shared::platform_profile::PlatformProfile;
use serde_json::Value;

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

/// The QML object that opens with `id: <id>`, up to its closing brace.
fn object_with_id<'a>(source: &'a str, id: &str) -> &'a str {
    let marker = format!("id: {id}\n");
    let at = source
        .find(&marker)
        .unwrap_or_else(|| panic!("`{id}` not found"));
    let open = source[..at].rfind('{').expect("object opens");
    let mut depth = 0usize;
    for (offset, ch) in source[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[open..=open + offset];
                }
            }
            _ => {}
        }
    }
    panic!("`{id}` never closes")
}

#[test]
fn the_on_launch_mode_is_gated_on_the_platform_flag() {
    assert!(
        PlatformProfile::windows()
            .supports
            .service_start_on_app_launch
    );
    assert!(
        !PlatformProfile::linux()
            .supports
            .service_start_on_app_launch
    );

    let qml = repo_file("apps/desktop/qml/sections/settings/ServiceManagementSettings.qml");
    let radio = object_with_id(&qml, "startModeOnLaunchRadio");
    assert!(
        radio.contains("visible: root.supports(\"serviceStartOnAppLaunch\")"),
        "the on-launch radio must be hidden where the service control refuses it"
    );
}

fn locale_errors(file: &str) -> Value {
    let json: Value = serde_json::from_str(&repo_file(file)).expect("locale parses");
    json["errors"].clone()
}

#[test]
fn the_platform_refusal_has_wording_in_every_bundled_locale() {
    let launcher = repo_file("apps/desktop/launcher/src/service_control_linux.rs");
    assert!(
        launcher.contains("\"unsupported-platform\""),
        "the Linux service control no longer refuses with `unsupported-platform`"
    );
    for file in ["locales/en.json", "locales/ru.json"] {
        let text = locale_errors(file)["unsupported-platform"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_default();
        assert!(
            !text.is_empty(),
            "{file} has no `errors.unsupported-platform`"
        );
    }
}

/// The refusal code reaches QML and is worded there; the bare English detail
/// is only the fallback for a code with no wording of its own.
#[test]
fn a_failed_service_action_is_worded_from_its_code() {
    let controller = repo_file("apps/desktop/qt-host/native/src/service_controller.h");
    assert!(
        controller.contains("emit operationCompleted(operation, false, errorMessage, errorCode);"),
        "the broker's refusal code must travel with the failure"
    );
    let main = repo_file("apps/desktop/qml/Main.qml");
    assert!(main.contains("function serviceOperationErrorText(code, message)"));
    for (file, call) in [
        (
            "apps/desktop/qml/Main.qml",
            "window.serviceOperationErrorText(errorCode, errorMessage)",
        ),
        (
            "apps/desktop/qml/sections/settings/ServiceManagementSettings.qml",
            "root.serviceOperationErrorText(errorCode, errorMessage)",
        ),
    ] {
        let source = repo_file(file);
        assert!(
            source.contains(
                "function onOperationCompleted(operation, success, errorMessage, errorCode)"
            ),
            "{file}: the handler does not take the refusal code"
        );
        assert!(
            source.contains(call),
            "{file}: the failure is not worded from its code"
        );
    }
}
