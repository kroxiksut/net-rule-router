//! Telling a signed-in user something while none of their surfaces runs.
//!
//! The decision — whether a site that does not open is worth starting the tray
//! for, how often, and for whom — is neutral in `service-runtime`. Only the OS
//! mechanism lives behind this port: on Windows the tray started in the user's
//! own session; elsewhere nothing, and the profile does not offer the setting.
//!
//! The port starts only the binary it locates itself, beside the service, and
//! only where no ordinary account could have replaced it. A host is passed as
//! an argument after [`notice_site_argument`] has checked it, so nothing the
//! observed traffic named can widen the command line.

/// The tray argument that opens it as one notice about `host`.
pub const NOTICE_SITE_FLAG: &str = "--nrr-notice-site=";

/// Longest host a notice names.
pub const MAX_NOTICE_HOST_LEN: usize = 253;

/// The tray argument for `host`, or `None` for anything but a lower-case
/// dotted host name: no space, quote or switch can ride into a command line.
#[must_use]
pub fn notice_site_argument(host: &str) -> Option<String> {
    valid_notice_host(host).then(|| format!("{NOTICE_SITE_FLAG}{host}"))
}

/// The host a launch argument names, under the same rule as
/// [`notice_site_argument`].
#[must_use]
pub fn notice_site_from_argument(argument: &str) -> Option<&str> {
    argument
        .strip_prefix(NOTICE_SITE_FLAG)
        .filter(|host| valid_notice_host(host))
}

fn valid_notice_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_NOTICE_HOST_LEN
        && host.contains('.')
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-'])
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
}

/// Why a notice could not be shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SiteNoticeRefused {
    /// This OS has no way to start a user's surface from the service.
    Unsupported,
    /// The host is not one a notice may name.
    BadHost,
    /// The user has no session the service can reach.
    NoSession,
    /// The tray is not where the service expects it.
    NotFound,
    /// An ordinary account could have replaced the tray or planted beside it;
    /// what could change it, in words.
    UntrustedLocation(String),
    /// The OS refused to start it.
    Failed(String),
}

/// Starts `sid`'s tray as one notice about a site.
pub trait SiteNoticeLauncher: Send + Sync {
    fn show_site_notice(&self, sid: &str, host: &str) -> Result<(), SiteNoticeRefused>;
}

/// Where the service cannot reach a user's session.
pub struct NoSiteNotice;

impl SiteNoticeLauncher for NoSiteNotice {
    fn show_site_notice(&self, _sid: &str, _host: &str) -> Result<(), SiteNoticeRefused> {
        Err(SiteNoticeRefused::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_plain_host_reaches_the_command_line() {
        assert_eq!(
            notice_site_argument("login.site.example").as_deref(),
            Some("--nrr-notice-site=login.site.example")
        );
        for hostile in [
            "",
            "localhost",
            "site.example --qml=C:\\x.qml",
            "site.example\" --x",
            "SITE.example",
            "-x.example",
            "site.example.",
            "a\u{0}.example",
            "сайт.example",
        ] {
            assert_eq!(notice_site_argument(hostile), None, "{hostile:?}");
        }
        assert_eq!(
            notice_site_argument(&format!("{}.example", "a".repeat(250))),
            None
        );
    }

    #[test]
    fn the_tray_reads_back_only_what_the_service_may_write() {
        assert_eq!(
            notice_site_from_argument("--nrr-notice-site=site.example"),
            Some("site.example")
        );
        assert_eq!(
            notice_site_from_argument("--nrr-notice-site=a b.example"),
            None
        );
        assert_eq!(notice_site_from_argument("--qml=site.example"), None);
    }
}
