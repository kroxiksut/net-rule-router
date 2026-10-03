// Shared by the build scripts of every Windows executable through `include!`,
// so the icon and version block have one template: `app.rc.in` beside this file.

use std::env;
use std::fs;
use std::path::Path;

/// Fills the template for the binary `bin` and links the result into it alone.
pub fn embed(repo_root: &Path, bin: &str, description: &str) {
    let template_path = repo_root.join("packaging/windows/app.rc.in");
    let icon_path = repo_root.join("assets/icons/app/app.ico");
    let helper_path = repo_root.join("packaging/windows/app_resource.rs");
    for path in [&template_path, &icon_path, &helper_path] {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    let var = |key: &str| env::var(key).unwrap_or_else(|error| panic!("{key}: {error}"));
    let template = fs::read_to_string(&template_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", template_path.display()));
    let version_commas = format!(
        "{},{},{},0",
        var("CARGO_PKG_VERSION_MAJOR"),
        var("CARGO_PKG_VERSION_MINOR"),
        var("CARGO_PKG_VERSION_PATCH")
    );
    // rc reads a backslash in a string literal as an escape.
    let icon = icon_path.display().to_string().replace('\\', "/");
    let script = template
        .replace("@APP_ICON_PATH@", &icon)
        .replace("@NRR_VERSION_COMMAS@", &version_commas)
        .replace("@NRR_VERSION@", &var("CARGO_PKG_VERSION"))
        .replace("@NRR_FILE_DESCRIPTION@", description)
        .replace("@NRR_ORIGINAL_FILENAME@", &format!("{bin}.exe"));

    let out = Path::new(&var("OUT_DIR")).join(format!("{bin}.rc"));
    fs::write(&out, script).unwrap_or_else(|error| panic!("write {}: {error}", out.display()));
    embed_resource::compile_for(&out, [bin], embed_resource::NONE);
}
