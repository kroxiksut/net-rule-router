//! Embeds the Windows application icon into the launcher binaries.
//!
//! The icon file lives at `<repo>/assets/icons/app/app.ico`.  The `.rc`
//! resource descriptor references it with a path relative to the `.rc`
//! file location, and the Windows Resource Compiler bundles the icon into
//! the PE resource section at link time.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=resources/app.rc");
    println!("cargo:rerun-if-changed=../../../assets/icons/app/app.ico");

    #[cfg(target_os = "windows")]
    {
        embed_resource::compile("resources/app.rc", embed_resource::NONE);
    }
}
