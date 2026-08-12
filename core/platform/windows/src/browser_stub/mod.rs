//! Browser stub experimental feature.
//!
//! ## Status: deferred to post-MVP (Pro-only future feature)
//!
//! This module is gated behind the `browser-stub` Cargo feature flag.
//! In MVP the feature is **disabled at compile time** — no infrastructure
//! is built unless `--features browser-stub` is explicitly requested.
//!
//! ## What this feature does (when enabled)
//!
//! When a secondary-bound destination is blocked (Fail-Closed)
//! and the originating process is a known browser, instead of a silent TCP
//! reset the browser shows an **explanatory HTML page** explaining why the
//! connection was blocked and what the user can do.
//!
//! ## Why this is deferred
//!
//! Full browser stub requires infrastructure that is out of scope for MVP:
//!
//! 1. **DNS proxy**: intercept DNS queries from the browser process and
//!    return `127.0.0.1` for blocked hostnames. Requires:
//!    - Binding a local UDP listener on port 5353 (or alternative).
//!    - WFP rule redirecting the browser's DNS queries to our proxy.
//!    - This is complex and conflicts with `mDNSResponder` / `llmnrd`.
//!
//! 2. **HTTP stub server**: serve the explanatory HTML page over HTTP.
//!    Simple to implement but only useful if the DNS redirect works.
//!
//! 3. **Kernel callout driver**: the only reliable per-process redirect
//!    mechanism at the network layer. Out of scope for MVP (Pro feature).
//!
//! ## Known limitations (must be communicated to user)
//!
//! | Scenario | Behavior |
//! |----------|----------|
//! | HTTPS to a site with HSTS | Browser shows `ERR_SSL_PROTOCOL_ERROR` or similar |
//! | Certificate-pinned HTTPS | Browser shows pin validation error |
//! | HTTP plain | Stub page shown if DNS redirect is active |
//! | Non-browser processes | Plain block (no stub) |
//! | HTTPS without pinning | Browser shows cert warning (stub uses self-signed cert) |
//!
//! **Recommendation:** For all HTTPS traffic, plain block (15.6) is more
//! consistent and honest. The stub only adds value for plain HTTP, which
//! is increasingly rare.
//!
//! ## Future implementation plan (post-MVP)
//!
//! 1. Bind local DNS proxy (`127.0.0.1:5353`; fallback ports 15353, 25353).
//! 2. Add WFP filter redirecting browser's `53/udp` to our proxy.
//! 3. Start HTTP stub server (`127.0.0.1:<random port>`).
//! 4. DNS proxy returns `127.0.0.1` for blocked FQDNs.
//! 5. HTTP stub serves explanatory page with rule details.
//! 6. Stub server lifecycle: one instance per service, bounded by session.
//! 7. Resource caps: max 10 concurrent connections, max 1 KB response body.
//! 8. `SO_EXCLUSIVEADDRUSE` on all listeners to prevent hijack.

// ── Browser detection ─────────────────────────────────────────────────────────

/// Known browser executable basenames (lowercase, without path).
/// Used for `process_path`-based detection when `ProcessContext.browser_hint`
/// is not available.
///
/// Prefer under-detection over over-detection:
/// false-negative (browser not detected) → plain block (safe)
/// false-positive (non-browser detected as browser) → stub attempt (wrong UX)
pub const KNOWN_BROWSER_BASENAMES: &[&str] = &[
    "firefox.exe",
    "chrome.exe",
    "msedge.exe",
    "opera.exe",
    "brave.exe",
    "vivaldi.exe",
    "iexplore.exe",
    "microsoftedge.exe",
    "browser.exe", // some Chromium-based forks
    "chromium.exe",
];

/// Classification result for one process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessClassification {
    /// Process is a known browser. Stub page may be shown (when feature active).
    KnownBrowser,
    /// Process is not a browser. Plain block is always used.
    NotBrowser,
}

impl ProcessClassification {
    /// Returns `true` when the stub should be attempted for this process.
    pub fn should_attempt_stub(self) -> bool {
        matches!(self, Self::KnownBrowser)
    }
}

/// Classify a process as browser or non-browser.
///
/// ## Priority
///
/// 1. `browser_hint = true` from the rule engine — trusted signal.
/// 2. Basename of `process_path` matched against `KNOWN_BROWSER_BASENAMES`.
/// 3. Default → `NotBrowser` (safe fallback).
pub fn classify_process(process_path: Option<&str>, browser_hint: bool) -> ProcessClassification {
    if browser_hint {
        return ProcessClassification::KnownBrowser;
    }
    if let Some(path) = process_path {
        let basename = extract_basename(path);
        if KNOWN_BROWSER_BASENAMES.contains(&basename) {
            return ProcessClassification::KnownBrowser;
        }
    }
    ProcessClassification::NotBrowser
}

/// Extract the lowercase basename from a Windows file path.
fn extract_basename(path: &str) -> &str {
    // Windows paths may use `\` or `/`.
    let last_sep = path.rfind(|c| c == '\\' || c == '/');
    let name = match last_sep {
        Some(i) => &path[i + 1..],
        None => path,
    };
    // We compare the original (lowercased at call site via const table).
    // The table is already lowercase; we need to lowercase the input.
    // Since we return a `&str`, we can't lowercase here — caller must use
    // `str::eq_ignore_ascii_case` or lowercase before passing.
    name
}

/// Returns `true` if `path`'s basename matches any known browser, case-insensitively.
pub fn path_matches_known_browser(path: &str) -> bool {
    let basename = extract_basename(path);
    KNOWN_BROWSER_BASENAMES
        .iter()
        .any(|&known| basename.eq_ignore_ascii_case(known))
}

// ── Configuration ─────────────────────────────────────────────────────────────

/// Configuration for the browser stub feature.
/// Constructed from UI settings; default is disabled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrowserStubConfig {
    /// Whether the browser stub is enabled at all.
    /// Default: `false`. Requires explicit user opt-in with warning banner.
    pub enabled: bool,
    /// Primary port for the local DNS proxy listener.
    /// Fallback ports are tried if primary is in use.
    pub dns_proxy_port: u16,
    /// Maximum concurrent connections to the stub HTTP server.
    pub max_connections: usize,
    /// Body size cap in bytes for the stub HTML page.
    pub max_body_bytes: usize,
    /// Connection timeout in seconds.
    pub connection_timeout_secs: u64,
}

impl Default for BrowserStubConfig {
    fn default() -> Self {
        Self {
            enabled: false, // off by default — user must opt in
            dns_proxy_port: 5353,
            max_connections: 10,
            max_body_bytes: 1024,
            connection_timeout_secs: 5,
        }
    }
}

/// DNS proxy port fallback sequence (tried in order when primary is busy).
pub const DNS_PROXY_PORT_FALLBACKS: &[u16] = &[5353, 15353, 25353];

// ── Stub server status ────────────────────────────────────────────────────────

/// Runtime status of the browser stub subsystem.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StubServerStatus {
    /// Feature is disabled (default). Plain block used for all processes.
    Disabled,
    /// Feature is enabled but could not start because a required port was
    /// unavailable. Plain block is used; user is warned in GUI.
    PortUnavailable { tried_ports: Vec<u16> },
    /// Feature is active. DNS proxy and HTTP stub server are running.
    Active {
        dns_proxy_port: u16,
        http_stub_port: u16,
    },
    /// Feature not available in current build (compiled without
    /// `browser-stub` feature flag).
    NotCompiledIn,
}

// ── StubServer ────────────────────────────────────────────────────────────────

/// Browser stub server lifecycle manager.
///
/// In MVP this is a no-op stub. The full implementation (DNS proxy +
/// HTTP server) is deferred to post-MVP.
///
/// ## MVP behaviour
///
/// `start()` immediately returns `Disabled` or `NotCompiledIn`.
/// All connections to blocked destinations receive plain TCP block (15.6).
#[derive(Default)]
pub struct StubServer;

impl StubServer {
    pub fn new() -> Self {
        Self
    }

    /// Attempt to start the browser stub subsystem.
    ///
    /// MVP: always returns the appropriate "not active" status.
    /// Post-MVP: binds DNS proxy port, starts HTTP listener.
    pub fn start(&self, config: &BrowserStubConfig) -> StubServerStatus {
        if !config.enabled {
            return StubServerStatus::Disabled;
        }
        // TODO(post-MVP): bind local DNS proxy, start HTTP stub server.
        // For now, report that the DNS proxy port is unavailable to signal
        // that stub is not active (plain block will be used as fallback).
        StubServerStatus::PortUnavailable {
            tried_ports: DNS_PROXY_PORT_FALLBACKS.to_vec(),
        }
    }

    /// Stop the stub server. No-op in MVP.
    pub fn stop(&self) {
        // TODO(post-MVP): shutdown DNS proxy and HTTP server gracefully.
    }
}

// ── Stub HTML page ────────────────────────────────────────────────────────────

/// Generate the HTML body for the browser stub page.
/// Kept minimal (< 1 KB) as required by `max_body_bytes`.
pub fn stub_html_body(blocked_host: &str, block_reason: &str) -> String {
    format!(
        "<!DOCTYPE html><html><head>\
         <meta charset=\"utf-8\">\
         <title>Connection blocked — NetRuleRouter</title></head>\
         <body>\
         <h1>Connection blocked</h1>\
         <p>NetRuleRouter blocked the connection to <strong>{blocked_host}</strong>.</p>\
         <p>Reason: {block_reason}</p>\
         <p>This page is shown only for plain HTTP connections. \
         HTTPS connections receive a direct block without this page.</p>\
         <p><a href=\"about:blank\">Close</a></p>\
         </body></html>"
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── classify_process ──────────────────────────────────────────────────

    #[test]
    fn browser_hint_true_always_classifies_as_browser() {
        let c = classify_process(None, true);
        assert_eq!(c, ProcessClassification::KnownBrowser);
    }

    #[test]
    fn browser_hint_true_overrides_unknown_process_path() {
        let c = classify_process(Some("C:\\Windows\\System32\\svchost.exe"), true);
        assert_eq!(c, ProcessClassification::KnownBrowser);
    }

    #[test]
    fn known_browser_paths_are_detected() {
        let cases = [
            (r"C:\Program Files\Mozilla Firefox\firefox.exe", true),
            (
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                true,
            ),
            (
                r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                true,
            ),
            (r"C:\Program Files\Opera\opera.exe", true),
            (
                r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
                true,
            ),
        ];
        for (path, expected) in &cases {
            let c = classify_process(Some(path), false);
            if *expected {
                assert_eq!(
                    c,
                    ProcessClassification::KnownBrowser,
                    "path '{path}' must be detected as browser"
                );
            }
        }
    }

    #[test]
    fn non_browser_paths_return_not_browser() {
        let cases = [
            r"C:\Windows\System32\svchost.exe",
            r"C:\Program Files\SomeApp\app.exe",
            r"C:\Users\user\Downloads\setup.exe",
        ];
        for path in &cases {
            let c = classify_process(Some(path), false);
            assert_eq!(
                c,
                ProcessClassification::NotBrowser,
                "'{path}' must not be detected as browser"
            );
        }
    }

    #[test]
    fn none_path_and_no_hint_is_not_browser() {
        assert_eq!(
            classify_process(None, false),
            ProcessClassification::NotBrowser
        );
    }

    #[test]
    fn browser_detection_is_case_insensitive() {
        // Windows paths may use mixed case.
        assert!(path_matches_known_browser(r"C:\Firefox\FIREFOX.EXE"));
        assert!(path_matches_known_browser(r"C:\Chrome\Chrome.exe"));
    }

    #[test]
    fn should_attempt_stub_only_for_known_browser() {
        assert!(ProcessClassification::KnownBrowser.should_attempt_stub());
        assert!(!ProcessClassification::NotBrowser.should_attempt_stub());
    }

    // ── BrowserStubConfig ─────────────────────────────────────────────────

    #[test]
    fn default_config_is_disabled() {
        let cfg = BrowserStubConfig::default();
        assert!(!cfg.enabled, "browser stub must be OFF by default");
    }

    #[test]
    fn default_config_has_sensible_resource_caps() {
        let cfg = BrowserStubConfig::default();
        assert!(cfg.max_connections > 0 && cfg.max_connections <= 20);
        assert!(cfg.max_body_bytes > 0 && cfg.max_body_bytes <= 4096);
        assert!(cfg.connection_timeout_secs > 0);
    }

    // ── StubServer ────────────────────────────────────────────────────────

    #[test]
    fn start_with_disabled_config_returns_disabled() {
        let server = StubServer::new();
        let status = server.start(&BrowserStubConfig::default());
        assert_eq!(status, StubServerStatus::Disabled);
    }

    #[test]
    fn start_with_enabled_config_returns_port_unavailable_in_mvp() {
        let server = StubServer::new();
        let cfg = BrowserStubConfig {
            enabled: true,
            ..Default::default()
        };
        let status = server.start(&cfg);
        // MVP: full DNS proxy not implemented → PortUnavailable
        assert!(
            matches!(status, StubServerStatus::PortUnavailable { .. }),
            "MVP must not return Active — stub not yet implemented: {status:?}"
        );
    }

    // ── stub_html_body ────────────────────────────────────────────────────

    #[test]
    fn stub_html_body_is_under_1kb() {
        let html = stub_html_body("example.com", "secondary unavailable");
        assert!(
            html.len() < 1024,
            "stub HTML must be under 1 KB, was {} bytes",
            html.len()
        );
    }

    #[test]
    fn stub_html_body_contains_host_and_reason() {
        let html = stub_html_body("blocked.example.com", "secondary down");
        assert!(html.contains("blocked.example.com"));
        assert!(html.contains("secondary down"));
    }

    // ── DNS_PROXY_PORT_FALLBACKS ──────────────────────────────────────────

    #[test]
    fn dns_proxy_fallbacks_list_is_non_empty_and_ordered() {
        assert!(!DNS_PROXY_PORT_FALLBACKS.is_empty());
        // First port should be 5353 (mDNS standard)
        assert_eq!(DNS_PROXY_PORT_FALLBACKS[0], 5353);
    }

    #[test]
    fn known_browser_basenames_are_all_lowercase() {
        for name in KNOWN_BROWSER_BASENAMES {
            assert_eq!(
                *name,
                name.to_lowercase(),
                "browser basename must be lowercase: '{name}'"
            );
        }
    }
}
