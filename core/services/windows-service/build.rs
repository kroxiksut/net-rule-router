//! Embeds the Windows application icon into the service binary so the
//! executable shows the NetRuleRouter icon in Explorer, Task Manager,
//! and the Services console (mirrors the launcher's `embed-resource`
//! setup in `apps/desktop/launcher/build.rs`).
//!
//! Same single source of truth as the GUI/tray binaries:
//! `<repo>/assets/icons/app/app.ico`.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=resources/app.rc");
    println!("cargo:rerun-if-changed=../../../assets/icons/app/app.ico");

    #[cfg(target_os = "windows")]
    {
        embed_resource::compile("resources/app.rc", embed_resource::NONE);
    }
}
