//! The About window and the terminal interface name the build's channel. A
//! packaged alpha said "development": the channel was a constant, so every
//! build, released or not, claimed to be a developer's.

use nrr_shared::build_channel_of;

#[test]
fn a_release_build_names_the_channel_its_version_carries() {
    for (version, channel) in [
        ("0.1.0-alpha.1", "alpha"),
        ("0.3.0-beta.2", "beta"),
        ("1.0.0-rc.1", "rc"),
        ("1.0.0", "stable"),
        ("1.0.0+build.7", "stable"),
        ("1.1.0-alpha", "alpha"),
        ("2.0.0-preview.1", "pre-release"),
    ] {
        assert_eq!(build_channel_of(version, false), channel, "{version}");
    }
}

#[test]
fn a_developer_build_says_so_whatever_its_version() {
    for version in ["0.1.0-alpha.1", "1.0.0"] {
        assert_eq!(build_channel_of(version, true), "development", "{version}");
    }
}

/// The workspace version, built as a package is, must not read as a
/// developer's build.
#[test]
fn this_version_packaged_is_not_called_a_development_build() {
    let packaged = build_channel_of(env!("CARGO_PKG_VERSION"), false);
    assert_ne!(packaged, "development");
    // Tests build with debug assertions, so the contract's value alone cannot
    // tell a constant from the version's channel: its source can.
    let model = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/shell_model.rs"),
    )
    .unwrap_or_default();
    assert!(
        model.contains(
            "build_channel: build_channel_of(env!(\"CARGO_PKG_VERSION\"), cfg!(debug_assertions))"
        ),
        "the About contract does not take the channel from the version"
    );
}
