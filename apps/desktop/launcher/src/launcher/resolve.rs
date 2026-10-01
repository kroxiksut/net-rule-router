// Payload and helper-binary discovery: the native Qt host, the per-surface
// QML entry point, the service sibling, the app icon, and the two-root
// (executable directory, dev checkout) lookup they all share.

use std::env;
use std::path::{Path, PathBuf};

use nrr_shared::product_identity::BinaryRole;

use super::LauncherSurface;

/// An environment variable naming code or payload to run. A release build never
/// reads one: whoever can set the variable would choose what the launcher runs.
fn env_override(allow_env_overrides: bool, name: &str) -> Option<PathBuf> {
    if !allow_env_overrides {
        return None;
    }
    let path = PathBuf::from(env::var_os(name)?);
    path.exists().then_some(path)
}

pub fn resolve_native_host_executable() -> Option<PathBuf> {
    if let Some(path) = env_override(cfg!(debug_assertions), "NRR_QT_NATIVE_HOST_EXE") {
        return Some(path);
    }

    let executable_name = if cfg!(windows) {
        "nrr_qt_native_host.exe"
    } else {
        "nrr_qt_native_host"
    };
    if let Some(beside) = beside_executable(executable_name) {
        return Some(beside);
    }

    // The path `nrr-qt-host` baked at build time names the build machine's
    // target directory; on any other machine that folder may be creatable by
    // anyone, so only a debug build trusts it.
    #[cfg(debug_assertions)]
    {
        let baked = PathBuf::from(nrr_qt_host::NATIVE_HOST_EXE);
        if baked.exists() {
            return Some(baked);
        }
    }

    None
}

pub(super) fn resolve_qml_path(surface: LauncherSurface) -> Option<PathBuf> {
    let (env_var, relative) = match surface {
        LauncherSurface::MainGui => ("NRR_QML_MAIN", "apps/desktop/qml/Main.qml"),
        LauncherSurface::Tray => ("NRR_QML_TRAY", "apps/desktop/qml/Tray.qml"),
    };
    if let Some(path) = env_override(cfg!(debug_assertions), env_var) {
        return Some(path);
    }
    bundled_resource(relative)
}

/// The service binary next to THIS executable, if it is there. Only the
/// sibling counts — the same trust boundary the host and the broker draw.
pub(crate) fn sibling_service_binary() -> Option<PathBuf> {
    beside_executable(BinaryRole::Service.host_file_name()).filter(|path| path.is_file())
}

pub(super) fn resolve_native_icon_path() -> Option<PathBuf> {
    // Windows takes the multi-size `.ico` the shell also embeds; X11 and the
    // hicolor theme take a PNG. `appIconRelativePath()` in the Qt host chooses
    // by the same rule — both sides must name the same file.
    let relative = if cfg!(windows) {
        "assets/icons/app/app.ico"
    } else {
        "assets/icons/app/icon-256.png"
    };
    bundled_resource(relative)
}

/// A payload path the package ships with the binary, `/`-separated relative to
/// the package root. Looked up beside the executable and, in a debug build
/// only, in the checkout it was built from — never in a parent directory,
/// where on a shared machine any user can create folders.
fn bundled_resource(relative: &str) -> Option<PathBuf> {
    // `apps/desktop/launcher` sits three levels below the checkout root.
    #[cfg(debug_assertions)]
    let checkout = Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(3);
    #[cfg(not(debug_assertions))]
    let checkout = None;
    find_bundled(executable_dir().as_deref(), checkout, relative)
}

fn beside_executable(relative: &str) -> Option<PathBuf> {
    find_bundled(executable_dir().as_deref(), None, relative)
}

fn executable_dir() -> Option<PathBuf> {
    env::current_exe().ok()?.parent().map(Path::to_path_buf)
}

/// Exactly these two roots, in order; neither is climbed.
pub(super) fn find_bundled(
    executable_dir: Option<&Path>,
    checkout: Option<&Path>,
    relative: &str,
) -> Option<PathBuf> {
    executable_dir
        .into_iter()
        .chain(checkout)
        .map(|root| {
            relative
                .split('/')
                .fold(root.to_path_buf(), |path, segment| path.join(segment))
        })
        .find(|candidate| candidate.exists())
}

#[cfg(test)]
mod tests {
    use super::env_override;

    #[test]
    fn env_override_needs_the_gate_and_an_existing_path() {
        let dir = std::env::temp_dir();
        std::env::set_var("NRR_TEST_ENV_OVERRIDE_PATH", &dir);
        assert_eq!(
            env_override(true, "NRR_TEST_ENV_OVERRIDE_PATH").as_deref(),
            Some(dir.as_path())
        );
        assert_eq!(env_override(false, "NRR_TEST_ENV_OVERRIDE_PATH"), None);

        std::env::set_var("NRR_TEST_ENV_OVERRIDE_PATH", dir.join("no-such-file"));
        assert_eq!(env_override(true, "NRR_TEST_ENV_OVERRIDE_PATH"), None);
        std::env::remove_var("NRR_TEST_ENV_OVERRIDE_PATH");
    }
}
