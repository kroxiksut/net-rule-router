//! Embeds the icon and version block (`packaging/windows/app.rc.in`) into the
//! console binary. Windows only: elsewhere the icon is a desktop-entry or
//! bundle concern.

#[cfg(target_os = "windows")]
mod app_resource {
    include!("../../packaging/windows/app_resource.rs");
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    #[cfg(target_os = "windows")]
    {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        app_resource::embed(&repo_root, "nrr-cli", "NetRuleRouter (console)");
    }
}
