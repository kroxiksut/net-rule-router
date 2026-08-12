//! Cross-platform, read-only reader for the OS `hosts` file.
//!
//! The OS `hosts` file maps `hostname → IP` at the *resolver*, BEFORE any
//! traffic reaches NetRuleRouter. It is commonly used for ad-blocking
//! (`ad.example 127.0.0.1`). NRR never overrides it. This module lets the
//! service surface, per rule, that the OS `hosts` file redirects or blocks
//! a rule's hostname — a purely informational annotation so the user
//! understands why a rule behaves oddly.
//!
//! ## Design
//!
//! - **Per-OS path** (resolved via `cfg`):
//!   - Windows: `%SystemRoot%\System32\drivers\etc\hosts` (via the
//!     `SystemRoot` environment variable, falling back to `C:\Windows`).
//!   - Unix: `/etc/hosts`.
//! - **One shared parser** ([`parse_hosts_map`]) builds a
//!   `HashMap<hostname, HostsPin>` where `blocking` is set when the IP is
//!   loopback (`127.0.0.0/8`) or unspecified (`0.0.0.0`).
//! - **mtime-gated cache**: [`OsHostsFileReader`] re-reads and re-parses
//!   only when the file's modified-time changes, so a rules-list call over
//!   a huge ad-block `hosts` file does not re-parse on every request.
//! - A missing / unreadable file yields an **empty map** — never an error.
//!
//! This module is fully OS-neutral — only [`default_hosts_path`]
//! is `cfg`-gated, and even there the `cfg` only picks a path *string* (no
//! OS-specific API calls). It lives in `nrr-platform-api` because it is
//! platform I/O (CLAUDE.md: `domain` must not do I/O; per-OS platform
//! crates re-export it unchanged so `service-runtime → platform` callers
//! are unaffected).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// One resolved `hosts`-file pin for a hostname.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostsPin {
    /// The IPv4 address the `hosts` file maps the hostname to.
    pub ip: Ipv4Addr,
    /// `true` when the address is loopback (`127.0.0.0/8`) or the
    /// unspecified address (`0.0.0.0`) — the ad-block "black-hole"
    /// convention (the hostname is effectively blocked). `false` for a
    /// real redirect target.
    pub blocking: bool,
}

impl HostsPin {
    fn from_ip(ip: Ipv4Addr) -> Self {
        Self {
            blocking: ip.is_loopback() || ip.is_unspecified(),
            ip,
        }
    }
}

/// Read-only view over the OS `hosts` file's `hostname → pin` map.
pub trait HostsFileReader: Send + Sync {
    /// Return the current `hostname → pin` map. Implementations may cache
    /// and only re-read the underlying file when it changes. Hostnames are
    /// lowercased with any trailing dot stripped. A missing or unreadable
    /// file yields an empty map.
    fn snapshot(&self) -> Arc<HashMap<String, HostsPin>>;

    /// Convenience exact-name lookup. `hostname` is normalized (trimmed,
    /// lowercased, trailing dot stripped) before the lookup. Returns
    /// `None` when the name is absent or the file is unavailable.
    ///
    /// Callers annotating many rows should prefer taking a single
    /// [`Self::snapshot`] and doing O(1) map lookups, rather than one
    /// `lookup` per row (each `lookup` re-`stat`s the file).
    fn lookup(&self, hostname: &str) -> Option<HostsPin> {
        let key = normalize_hostname(hostname);
        if key.is_empty() {
            return None;
        }
        self.snapshot().get(&key).copied()
    }
}

/// Normalize a hostname for map keying / lookup: trim surrounding
/// whitespace, strip a single trailing dot (the FQDN root label), and
/// lowercase ASCII.
pub fn normalize_hostname(hostname: &str) -> String {
    hostname.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Parse `hosts`-file text into a `hostname → pin` map.
///
/// Rules (shared across OSes):
/// - `#` starts a comment; everything to the end of the line is ignored.
/// - Blank / whitespace-only lines are skipped.
/// - The first whitespace-delimited token is the address; it must parse as
///   IPv4 (IPv6 and any other lines are ignored for the Free tier).
/// - Every remaining token is a hostname alias mapped to that address.
/// - First entry wins on a duplicate hostname (matches resolver order).
pub fn parse_hosts_map(contents: &str) -> HashMap<String, HostsPin> {
    let mut map: HashMap<String, HostsPin> = HashMap::new();
    for raw_line in contents.lines() {
        // Strip inline comments (`10.0.0.1 host # note`).
        let line = match raw_line.split('#').next() {
            Some(head) => head.trim(),
            None => continue,
        };
        if line.is_empty() {
            continue;
        }
        let mut tokens = line.split_whitespace();
        let Some(ip_token) = tokens.next() else {
            continue;
        };
        // IPv6 (and any non-IPv4) address lines are ignored.
        let Ok(ip) = ip_token.parse::<Ipv4Addr>() else {
            continue;
        };
        let pin = HostsPin::from_ip(ip);
        for alias in tokens {
            let host = normalize_hostname(alias);
            if host.is_empty() {
                continue;
            }
            map.entry(host).or_insert(pin);
        }
    }
    map
}

/// Resolve the OS `hosts`-file path for the current platform.
pub fn default_hosts_path() -> PathBuf {
    #[cfg(windows)]
    {
        // `SystemRoot` is set on every Windows session; fall back to the
        // canonical install path if the environment is unexpectedly bare.
        let system_root = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        system_root
            .join("System32")
            .join("drivers")
            .join("etc")
            .join("hosts")
    }
    #[cfg(all(unix, not(windows)))]
    {
        PathBuf::from("/etc/hosts")
    }
    #[cfg(not(any(windows, unix)))]
    {
        PathBuf::from("hosts")
    }
}

struct CacheSlot {
    /// The file mtime the cached map was parsed from. `None` records that
    /// the file was missing/unreadable at the last read.
    mtime: Option<SystemTime>,
    /// `true` once at least one read has populated `map`, so a genuine
    /// "file missing → empty" state is not re-read on every call.
    loaded: bool,
    map: Arc<HashMap<String, HostsPin>>,
}

/// Production [`HostsFileReader`] backed by an on-disk `hosts` file with an
/// mtime-gated cache. Cheap to [`Self::snapshot`] repeatedly: it `stat`s
/// the file and only re-reads + re-parses when the modified-time changed.
///
/// Note: like every mtime cache, this can miss two writes that share the
/// same modified-time (sub-granularity edits). That is acceptable for an
/// informational annotation — the next distinct edit picks it up.
pub struct OsHostsFileReader {
    path: PathBuf,
    cache: Mutex<CacheSlot>,
}

impl OsHostsFileReader {
    /// Reader over the current platform's OS `hosts` file.
    pub fn new() -> Self {
        Self::with_path(default_hosts_path())
    }

    /// Reader over an explicit path (used in tests, or to point at a
    /// non-default location).
    pub fn with_path(path: PathBuf) -> Self {
        Self {
            path,
            cache: Mutex::new(CacheSlot {
                mtime: None,
                loaded: false,
                map: Arc::new(HashMap::new()),
            }),
        }
    }

    fn current_mtime(&self) -> Option<SystemTime> {
        std::fs::metadata(&self.path)
            .and_then(|meta| meta.modified())
            .ok()
    }
}

impl Default for OsHostsFileReader {
    fn default() -> Self {
        Self::new()
    }
}

impl HostsFileReader for OsHostsFileReader {
    fn snapshot(&self) -> Arc<HashMap<String, HostsPin>> {
        let current = self.current_mtime();
        let mut slot = match self.cache.lock() {
            Ok(guard) => guard,
            // Poisoned mutex: degrade to an empty map rather than panic.
            Err(_) => return Arc::new(HashMap::new()),
        };
        if slot.loaded && slot.mtime == current {
            return Arc::clone(&slot.map);
        }
        let map = match std::fs::read_to_string(&self.path) {
            Ok(text) => parse_hosts_map(&text),
            // Missing / unreadable file → empty map, no error surfaced.
            Err(_) => HashMap::new(),
        };
        let shared = Arc::new(map);
        slot.mtime = current;
        slot.loaded = true;
        slot.map = Arc::clone(&shared);
        shared
    }
}

/// Static, in-memory [`HostsFileReader`] over a fixed map. Used by callers
/// and tests that want to inject a known `hosts` map without touching disk.
pub struct StaticHostsFileReader {
    map: Arc<HashMap<String, HostsPin>>,
}

impl StaticHostsFileReader {
    pub fn new(map: HashMap<String, HostsPin>) -> Self {
        Self { map: Arc::new(map) }
    }

    /// Build from `(hostname, ipv4)` pairs; `blocking` is classified from
    /// the IP just like the file parser.
    pub fn from_pairs<I, S>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (S, Ipv4Addr)>,
        S: AsRef<str>,
    {
        let map = pairs
            .into_iter()
            .map(|(host, ip)| (normalize_hostname(host.as_ref()), HostsPin::from_ip(ip)))
            .collect();
        Self::new(map)
    }
}

impl HostsFileReader for StaticHostsFileReader {
    fn snapshot(&self) -> Arc<HashMap<String, HostsPin>> {
        Arc::clone(&self.map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_comments_blanks_and_multi_alias_lines() {
        let text = "\
# full-line comment
127.0.0.1   localhost   loopback.local   # inline comment

   \t
0.0.0.0        ads.example.com
203.0.113.7    redirect.example.com  alias.example.com
";
        let map = parse_hosts_map(text);
        // localhost + its alias both mapped, comment ignored.
        assert_eq!(
            map.get("localhost").map(|p| p.ip),
            Some(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(
            map.get("loopback.local").map(|p| p.ip),
            Some(Ipv4Addr::LOCALHOST)
        );
        // Multi-alias redirect line maps both names to the same IP.
        assert_eq!(
            map.get("redirect.example.com").map(|p| p.ip),
            Some(Ipv4Addr::new(203, 0, 113, 7))
        );
        assert_eq!(
            map.get("alias.example.com").map(|p| p.ip),
            Some(Ipv4Addr::new(203, 0, 113, 7))
        );
        // Blank / whitespace-only / comment lines add nothing.
        assert_eq!(map.len(), 5);
    }

    #[test]
    fn classifies_blocking_versus_redirect() {
        let map = parse_hosts_map(
            "127.0.0.1 blocked-loopback.example\n\
             0.0.0.0 blocked-unspecified.example\n\
             198.51.100.9 real-redirect.example\n",
        );
        assert!(map.get("blocked-loopback.example").unwrap().blocking);
        assert!(map.get("blocked-unspecified.example").unwrap().blocking);
        assert!(!map.get("real-redirect.example").unwrap().blocking);
    }

    #[test]
    fn ignores_ipv6_and_malformed_lines() {
        let map = parse_hosts_map(
            "::1 ip6-localhost\n\
             fe80::1 ip6-router\n\
             not-an-ip host.example\n\
             10.0.0.5 valid.example\n",
        );
        assert!(!map.contains_key("ip6-localhost"));
        assert!(!map.contains_key("ip6-router"));
        assert!(!map.contains_key("host.example"));
        assert_eq!(
            map.get("valid.example").map(|p| p.ip),
            Some(Ipv4Addr::new(10, 0, 0, 5))
        );
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn normalizes_case_and_trailing_dot() {
        let map = parse_hosts_map("127.0.0.1 MixedCase.Example.COM.\n");
        assert!(map.contains_key("mixedcase.example.com"));
        // Lookup normalizes the query the same way.
        let reader = StaticHostsFileReader::new(map);
        assert!(reader.lookup("MixedCase.Example.com").is_some());
        assert!(reader.lookup("mixedcase.example.com.").is_some());
    }

    #[test]
    fn first_entry_wins_on_duplicate_hostname() {
        let map = parse_hosts_map(
            "127.0.0.1 dup.example\n\
             203.0.113.1 dup.example\n",
        );
        // Resolver order: the first mapping is authoritative.
        assert!(map.get("dup.example").unwrap().blocking);
        assert_eq!(map.get("dup.example").unwrap().ip, Ipv4Addr::LOCALHOST);
    }

    #[test]
    fn missing_file_yields_empty_map_without_error() {
        let dir = tempfile::tempdir().expect("temp dir");
        let missing = dir.path().join("does-not-exist-hosts");
        let reader = OsHostsFileReader::with_path(missing);
        assert!(reader.snapshot().is_empty());
        // Repeated calls stay empty (cached-missing path).
        assert!(reader.snapshot().is_empty());
        assert!(reader.lookup("anything.example").is_none());
    }

    #[test]
    fn mtime_cache_reparses_only_when_modified_time_changes() {
        use std::fs::File;
        use std::time::Duration;

        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("hosts");

        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let write_with_mtime = |contents: &str, mtime: SystemTime| {
            std::fs::write(&path, contents).expect("write");
            let f = File::options().write(true).open(&path).expect("open");
            f.set_modified(mtime).expect("set_modified");
        };

        // First read parses v1.
        write_with_mtime("127.0.0.1 first.example\n", base);
        let reader = OsHostsFileReader::with_path(path.clone());
        let snap1 = reader.snapshot();
        assert!(snap1.contains_key("first.example"));
        assert!(!snap1.contains_key("second.example"));

        // Overwrite the CONTENT but keep the SAME mtime → cache hit, the
        // old map is served (proves we did not re-read).
        write_with_mtime("203.0.113.9 second.example\n", base);
        let snap2 = reader.snapshot();
        assert!(snap2.contains_key("first.example"));
        assert!(!snap2.contains_key("second.example"));
        assert!(Arc::ptr_eq(&snap1, &snap2));

        // Bump the mtime → the reader re-parses and serves v2.
        let later = base + Duration::from_secs(5);
        write_with_mtime("203.0.113.9 second.example\n", later);
        let snap3 = reader.snapshot();
        assert!(!snap3.contains_key("first.example"));
        assert!(snap3.contains_key("second.example"));
        assert!(!Arc::ptr_eq(&snap2, &snap3));
    }

    #[test]
    fn default_path_agrees_with_platform_profile_descriptor() {
        // Drift-guard: the GUI reveals the hosts file
        // using `PlatformProfile::current().hosts_file_path` (nrr-shared,
        // which sits below this crate and so re-derives the path rather than
        // importing it). Assert the two derivations agree on the running OS,
        // so a future change to one never silently diverges from the other.
        let from_platform = default_hosts_path();
        let from_profile = nrr_shared::platform_profile::PlatformProfile::current().hosts_file_path;
        assert_eq!(from_platform.to_string_lossy(), from_profile);
    }

    #[test]
    fn static_reader_from_pairs_classifies_and_looks_up() {
        let reader = StaticHostsFileReader::from_pairs([
            ("blocked.example", Ipv4Addr::LOCALHOST),
            ("redirect.example", Ipv4Addr::new(192, 0, 2, 5)),
        ]);
        assert!(reader.lookup("blocked.example").unwrap().blocking);
        assert!(!reader.lookup("redirect.example").unwrap().blocking);
        assert!(reader.lookup("absent.example").is_none());
    }
}
