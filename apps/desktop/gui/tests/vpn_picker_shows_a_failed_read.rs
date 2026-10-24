//! The VPN program picker opens over a fresh read of the stored set. When that
//! read fails it says so: opening over the prefs copy would offer for saving a
//! set the service may no longer hold, and a save would bring removed programs
//! back.

use std::path::{Path, PathBuf};

fn qml(rel: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../qml")
        .join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

fn function_body<'a>(text: &'a str, signature: &str) -> &'a str {
    let from = text
        .find(signature)
        .unwrap_or_else(|| panic!("`{signature}` not found"));
    let rest = &text[from..];
    let to = rest
        .find("\n    }\n")
        .unwrap_or_else(|| panic!("end of `{signature}` not found"));
    &rest[..to]
}

#[test]
fn a_failed_read_opens_the_picker_unread() {
    let main = qml("Main.qml");
    let body = function_body(&main, "function openVpnOnboarding()");
    assert!(
        !body.contains("_linkProvidersMirror"),
        "the picker never opens over the prefs copy:\n{body}"
    );
    let unread = body.matches("vpnOnboardingDialog.openUnread()").count();
    assert_eq!(
        unread, 2,
        "both a missing read and a failed one open the picker unread:\n{body}"
    );
    let record = body
        .find("_recordLinkProvidersFrom(p)")
        .unwrap_or_else(|| panic!("the answer is recorded:\n{body}"));
    let open = body
        .find("vpnOnboardingDialog.open(currentLinkProviders())")
        .unwrap_or_else(|| panic!("a good read opens the picker:\n{body}"));
    assert!(record < open, "the picker opens over the answer:\n{body}");
    let failed = body
        .find("if (!ok)")
        .unwrap_or_else(|| panic!("a failed answer is told apart:\n{body}"));
    assert!(failed < record, "{body}");
}

#[test]
fn an_unread_picker_offers_no_save() {
    let dialog = qml("components/VpnOnboardingDialog.qml");
    assert!(
        dialog.contains("function openUnread()"),
        "openUnread exists"
    );
    assert!(
        dialog.contains("enabled: !root.storedUnread\n"),
        "confirm is disabled over an unread set"
    );
    assert!(
        dialog.contains("root.tr(\"action.retry\", \"Try again\")"),
        "an unread set offers a retry"
    );
    let host = qml("components/DialogHost.qml");
    assert!(
        host.contains("onRetryReadRequested: ownerRoot.openVpnOnboarding()"),
        "retry reads again"
    );
}
