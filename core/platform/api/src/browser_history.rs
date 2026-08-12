//! Browser-history read port.
//!
//! An OPT-IN way to close the "visited before the service started" blind spot:
//! a host the browser reached from its own cache (never wire-queried while the
//! service was up) has no FQDN-cache entry, so a suffix/zone rule never expanded
//! to it and it can be blocked under block-all (the dzen.ru class).
//! The browser's HISTORY, however, records every hostname the user visited. This
//! port surfaces those hostnames so the service can resolve the rule-matching
//! ones and pre-fill the cache — turning "sites you actually visit" into permits
//! before the first block.
//!
//! **Policy / mechanism seam.** This trait is the neutral decision
//! surface; the per-OS mechanism (finding Chrome/Edge/Firefox profile paths,
//! copying the locked SQLite file, and reading the `urls` / `moz_places` table)
//! lives in `nrr-platform-windows` / `-linux` / `-macos`. Only HOSTNAMES cross
//! this boundary — never full URLs, titles, timestamps, or visit counts, so the
//! caller cannot reconstruct browsing history; it only learns "this hostname was
//! visited", which the rule gate immediately narrows to rule-matching hosts.

/// Reads the distinct hostnames present in the local browsers' history. Returns
/// lower-cased, de-duplicated hostnames (no scheme, port, path, or query). A
/// browser that is absent, locked beyond copy, or unreadable is skipped — the
/// read is best-effort and partial results are valid.
pub trait BrowserHistoryReadPort: Send + Sync {
    /// Distinct visited hostnames across all detected browser profiles of the
    /// given `principal` (the OS identity whose browsers to read — a Windows
    /// SID string; a uid/username on other platforms), or an error only when
    /// NOTHING could be read (every backend failed). An empty vec is a valid
    /// "no history found" result.
    ///
    /// The principal is REQUIRED because the caller (the
    /// background service) does not run as the browsing user: on Windows the
    /// service is LocalSystem, whose own profile has no browsers, so a reader
    /// that consulted its process environment found nothing. The mechanism
    /// must resolve the principal's profile root instead.
    fn read_history_hostnames(&self, principal: &str) -> Result<Vec<String>, BrowserHistoryError>;
}

/// Why a browser-history read yielded nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrowserHistoryError {
    /// No supported browser profile was found on this machine.
    NoBrowsersFound,
    /// A profile was found but could not be read (locked + copy failed, corrupt
    /// DB, permissions). The detail is for diagnostics only.
    ReadFailed(String),
    /// This platform has no browser-history mechanism wired yet.
    Unsupported,
}

impl std::fmt::Display for BrowserHistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoBrowsersFound => write!(f, "no supported browser profiles found"),
            Self::ReadFailed(d) => write!(f, "browser history read failed: {d}"),
            Self::Unsupported => {
                write!(f, "browser-history read is not supported on this platform")
            }
        }
    }
}

impl std::error::Error for BrowserHistoryError {}

/// No-op port: always reports [`BrowserHistoryError::Unsupported`]. The default
/// on platforms without a wired mechanism, so the seed path degrades to a no-op.
pub struct NoopBrowserHistoryRead;

impl BrowserHistoryReadPort for NoopBrowserHistoryRead {
    fn read_history_hostnames(&self, _principal: &str) -> Result<Vec<String>, BrowserHistoryError> {
        Err(BrowserHistoryError::Unsupported)
    }
}

/// A scripted port for tests — returns a fixed hostname list.
pub struct MockBrowserHistoryRead {
    pub hostnames: Vec<String>,
}

impl BrowserHistoryReadPort for MockBrowserHistoryRead {
    fn read_history_hostnames(&self, _principal: &str) -> Result<Vec<String>, BrowserHistoryError> {
        if self.hostnames.is_empty() {
            Err(BrowserHistoryError::NoBrowsersFound)
        } else {
            Ok(self.hostnames.clone())
        }
    }
}

/// Normalise a raw history URL/host into a bare lower-cased hostname, or `None`
/// when it carries no usable host (a `file:`/`about:`/`chrome:` URL, an IP
/// literal we keep as-is, or an empty string). Pure so the per-OS readers share
/// one definition and it is unit-tested here. Accepts either a full URL
/// (`https://host/path`) or a bare host.
pub fn hostname_from_history_url(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    // Reject known non-network pseudo-schemes up front, whether or not they use
    // `://` (`about:blank`, `chrome://settings`, `file:///…`, `data:…`).
    if let Some(colon) = s.find(':') {
        let scheme = &s[..colon];
        if !scheme.is_empty()
            && scheme.chars().all(|c| c.is_ascii_alphabetic())
            && matches!(
                scheme.to_ascii_lowercase().as_str(),
                "about" | "chrome" | "edge" | "file" | "data" | "javascript" | "view-source"
            )
        {
            return None;
        }
    }
    // Strip a scheme if present.
    let after_scheme = match s.find("://") {
        Some(i) => &s[i + 3..],
        None => s,
    };
    // Drop credentials (`user:pass@host`), then path/query/fragment, then port.
    let host_region = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let host_region = host_region.rsplit('@').next().unwrap_or(host_region);
    // Strip a trailing `:port` (but keep IPv6 brackets intact if present — rare
    // in history; we simply take up to the first `:` after a `]`).
    let host = if let Some(stripped) = host_region.strip_prefix('[') {
        // IPv6 literal `[::1]:443` → `::1`.
        stripped.split(']').next().unwrap_or(stripped)
    } else {
        host_region.split(':').next().unwrap_or(host_region)
    };
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || !host.contains(|c: char| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_bare_hostname_from_urls() {
        assert_eq!(
            hostname_from_history_url("https://dzen.ru/feed?x=1"),
            Some("dzen.ru".into())
        );
        assert_eq!(
            hostname_from_history_url("http://Sub.Example.COM/path"),
            Some("sub.example.com".into())
        );
        assert_eq!(
            hostname_from_history_url("https://user:pass@host.tld:8443/x"),
            Some("host.tld".into())
        );
        assert_eq!(
            hostname_from_history_url("dns.google"),
            Some("dns.google".into())
        );
        // Trailing dot (FQDN root) stripped.
        assert_eq!(
            hostname_from_history_url("https://ya.ru./"),
            Some("ya.ru".into())
        );
    }

    #[test]
    fn rejects_non_network_urls() {
        assert_eq!(hostname_from_history_url(""), None);
        assert_eq!(hostname_from_history_url("about:blank"), None);
        assert_eq!(hostname_from_history_url("chrome://settings"), None);
        assert_eq!(hostname_from_history_url("file:///c:/tmp/x.html"), None);
        assert_eq!(hostname_from_history_url("data:text/html,hi"), None);
    }

    #[test]
    fn ipv6_literal_host_kept() {
        assert_eq!(
            hostname_from_history_url("http://[2001:db8::1]:8080/x"),
            Some("2001:db8::1".into())
        );
    }

    #[test]
    fn noop_port_is_unsupported() {
        assert_eq!(
            NoopBrowserHistoryRead.read_history_hostnames("S-1-5-21-TEST"),
            Err(BrowserHistoryError::Unsupported)
        );
    }

    #[test]
    fn mock_port_returns_scripted_hosts() {
        let m = MockBrowserHistoryRead {
            hostnames: vec!["dzen.ru".into(), "ya.ru".into()],
        };
        assert_eq!(
            m.read_history_hostnames("S-1-5-21-TEST").unwrap(),
            vec!["dzen.ru".to_string(), "ya.ru".to_string()]
        );
    }
}
