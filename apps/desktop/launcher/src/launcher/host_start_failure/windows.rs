// Windows: the loader's own "DLL not found" box kept away from the host, and
// the launcher's message box in its place.

use nrr_platform_windows::loader_failure::{show_error_box, LoaderErrorBoxesSuppressed};

use super::HostStartNotice;

/// Hold across the host spawn and drop right after: the child inherits the
/// mode at creation, and the launcher gets its own mode back.
pub(crate) fn suppress_loader_error_ui() -> LoaderErrorBoxesSuppressed {
    LoaderErrorBoxesSuppressed::engage()
}

pub(crate) fn show_notice(notice: &HostStartNotice) {
    show_error_box(&notice.title, &notice.body);
}
