//! The connection trace's view filters, over the row's display string: it may
//! carry a port and may be masked by the redaction tier, and a value that does
//! not parse is never classified, so no filter hides a row it could not read.
//! Also the list's grouping by program or by program folder.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use nrr_shared::app_path::{PathStyle, MAX_PATH_BYTES, MAX_PATH_SEGMENTS};

use crate::js;

/// Whether a trace endpoint is IPv6 (`isIpv6Endpoint`): a bracketed literal,
/// or a bare address with more than one colon.
pub fn is_ipv6_endpoint(endpoint: &str) -> bool {
    let s = js::trim(endpoint);
    if s.is_empty() {
        return false;
    }
    s.starts_with('[') || s.split(':').count() > 2
}

/// Whether a trace remote never leaves the machine (`isNonInternetAddress`):
/// loopback, link-local, or a private range of either family.
pub fn is_non_internet_address(remote: &str) -> bool {
    let trimmed = js::trim(remote);
    if trimmed.is_empty() {
        return false;
    }
    let mut host = if let Some(rest) = trimmed.strip_prefix('[') {
        trimmed.find(']').map_or(rest, |close| &trimmed[1..close])
    } else {
        // A bare IPv6 has several colons; only a single `:port` is stripped.
        match (trimmed.find(':'), trimmed.rfind(':')) {
            (Some(first), Some(last)) if last > 0 && first == last => &trimmed[..last],
            _ => trimmed,
        }
    };
    if let Some(zone) = host.find('%') {
        host = &host[..zone];
    }
    let host = host.to_lowercase();
    if host.is_empty() {
        return false;
    }

    if host.contains(':') {
        // fe80::/10 link-local, fc00::/7 unique-local.
        let link_local = ["fe8", "fe9", "fea", "feb"]
            .iter()
            .any(|p| host.starts_with(p));
        let unique_local = host.starts_with("fc") || host.starts_with("fd");
        return host == "::1" || link_local || unique_local;
    }

    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    let mut octets = [0u32; 4];
    for (octet, part) in octets.iter_mut().zip(&parts) {
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|c| c.is_ascii_digit()) {
            return false;
        }
        let n = part.bytes().fold(0u32, |n, c| n * 10 + u32::from(c - b'0'));
        if n > 255 {
            return false;
        }
        *octet = n;
    }
    match octets {
        [127 | 10, ..] | [169, 254, ..] | [192, 168, ..] => true,
        [172, second, ..] => (16..=31).contains(&second),
        _ => false,
    }
}

/// How the trace list is grouped. Each client keeps the choice in its own
/// settings; `Program` is what the list did before there was a choice.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum TraceGrouping {
    /// One flat list.
    None,
    /// By the program's name.
    #[default]
    Program,
    /// By the folder the program lives in; a folder inside another listed
    /// folder joins that folder's group.
    Folder,
}

impl TraceGrouping {
    /// In the order the choice is offered.
    pub const ALL: [Self; 3] = [Self::None, Self::Program, Self::Folder];

    /// The stored slug: `none`, `program` or `folder`.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Program => "program",
            Self::Folder => "folder",
        }
    }

    /// `None` for any other slug, so a value this build does not know falls
    /// back to the default rather than to a flat list.
    #[must_use]
    pub fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|g| g.slug() == slug)
    }
}

/// What a group of trace rows shares.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TraceGroupKind {
    Program,
    Folder,
    /// Rows whose program path is missing or does not read as one.
    NoPath,
}

impl TraceGroupKind {
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Program => "program",
            Self::Folder => "folder",
            Self::NoPath => "no-path",
        }
    }
}

/// One group of the trace list (`connTraceGroups` in `pure.js`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceGroup {
    pub kind: TraceGroupKind,
    /// The group's identity across rebuilds, for its expanded state.
    pub key: String,
    /// The program's name, the folder as the trace spells it, or empty for
    /// rows without a path.
    pub label: String,
    /// The application rule value naming the folder and every folder below
    /// it. `None` for a program, for rows without a path and for a drive or
    /// file-system root, which no one means as a program folder.
    pub rule_value: Option<String>,
    /// The group's rows as indices into the input, in input order.
    pub rows: Vec<usize>,
    /// Distinct programs among the rows: by path, by name where the path is
    /// unreadable.
    pub programs: usize,
    /// Whether the list puts a header over the rows: a program seen once is
    /// shown as its row alone.
    pub header: bool,
}

/// The two fields of a trace row the grouping reads.
#[derive(Clone, Copy, Debug)]
pub struct TraceRowRef<'a> {
    pub process: &'a str,
    pub process_path: &'a str,
}

/// A program path as the grouping reads it: the root (drive or share; empty
/// on Unix), the folders below it and the file, spelled as the trace spells
/// them.
struct ProgramPath {
    root: String,
    folders: Vec<String>,
    file: String,
}

fn strip_prefix_ascii_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) {
        s.get(prefix.len()..)
    } else {
        None
    }
}

/// The path as `style` spells it, or `None` when it names no program file:
/// not absolute, climbing with `..`, oversized, too deep, or holding a
/// control character. The OS reports these for other users' processes too,
/// so the read is bounded and linear.
fn program_path(raw: &str, style: PathStyle) -> Option<ProgramPath> {
    if raw.len() > MAX_PATH_BYTES || raw.chars().any(char::is_control) {
        return None;
    }
    let path = js::trim(raw);
    let windows = style == PathStyle::Windows;
    let (root, rest) = if windows {
        let unified = path.replace('/', "\\");
        let unified = if let Some(unc) = strip_prefix_ascii_ci(&unified, r"\\?\unc\") {
            format!(r"\\{unc}")
        } else if let Some(local) = unified
            .strip_prefix(r"\\?\")
            .or_else(|| unified.strip_prefix(r"\\.\"))
        {
            local.to_owned()
        } else {
            unified
        };
        if let Some(share) = unified.strip_prefix(r"\\") {
            let mut parts = share.split('\\').filter(|p| !p.is_empty());
            let server = parts.next()?;
            let name = parts.next()?;
            if [server, name].iter().any(|p| matches!(*p, "." | "..")) {
                return None;
            }
            (
                format!(r"\\{server}\{name}"),
                parts.collect::<Vec<_>>().join("\\"),
            )
        } else {
            let bytes = unified.as_bytes();
            let drive = bytes.first().copied().filter(u8::is_ascii_alphabetic)?;
            if bytes.get(1) != Some(&b':') || !matches!(bytes.get(2), None | Some(b'\\')) {
                return None;
            }
            (
                format!("{}:", char::from(drive)),
                unified.get(2..).unwrap_or_default().to_owned(),
            )
        }
    } else {
        (String::new(), path.strip_prefix('/')?.to_owned())
    };
    let mut segments = Vec::new();
    for raw in rest.split(style.separator()) {
        if raw.is_empty() || raw == "." {
            continue;
        }
        if raw == ".." {
            return None;
        }
        let segment = if windows {
            // A colon past the drive is a stream name; Windows drops trailing
            // dots and spaces.
            if raw.contains(':') {
                return None;
            }
            let trimmed = raw.trim_end_matches(['.', ' ']);
            if trimmed.is_empty() {
                return None;
            }
            trimmed
        } else {
            raw
        };
        segments.push(segment.to_owned());
        if segments.len() > MAX_PATH_SEGMENTS {
            return None;
        }
    }
    let file = segments.pop()?;
    Some(ProgramPath {
        root,
        folders: segments,
        file,
    })
}

fn fold(s: &str, style: PathStyle) -> String {
    if style.case_insensitive() {
        s.to_lowercase()
    } else {
        s.to_owned()
    }
}

/// The folder `folders` below `root` names: `C:\` for the drive alone,
/// `\\server\share`, `/` for the Unix root.
fn folder_text(root: &str, folders: &[String], style: PathStyle) -> String {
    let sep = style.separator();
    let mut out = String::from(root);
    if folders.is_empty() {
        if root.is_empty() || root.ends_with(':') {
            out.push(sep);
        }
        return out;
    }
    for folder in folders {
        out.push(sep);
        out.push_str(folder);
    }
    out
}

/// The folder's identity: the root and each folder as `style` compares them.
fn folder_key(path: &ProgramPath, style: PathStyle) -> Vec<String> {
    let root = (!path.root.is_empty()).then(|| fold(&path.root, style));
    root.into_iter()
        .chain(path.folders.iter().map(|f| fold(f, style)))
        .collect()
}

/// `a` against `b` by UTF-16 code unit, as JavaScript's `<` compares.
fn cmp_code_units(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// The trace rows grouped as `grouping` asks, on a trace whose paths are
/// spelled and compared as `style` says (the OS of the service that observed
/// them, never the build target). Program groups sort by name, folder groups
/// by folder, both ignoring case; the rows without a path come last. A flat
/// list (`TraceGrouping::None`) has no groups.
#[must_use]
pub fn group_trace_rows(
    rows: &[TraceRowRef<'_>],
    grouping: TraceGrouping,
    style: PathStyle,
) -> Vec<TraceGroup> {
    let paths: Vec<Option<ProgramPath>> = match grouping {
        TraceGrouping::None => return Vec::new(),
        _ => rows
            .iter()
            .map(|row| program_path(row.process_path, style))
            .collect(),
    };
    let identity = |i: usize| match &paths[i] {
        Some(path) => {
            let mut id = String::from("p");
            id.push_str(&folder_text(&path.root, &path.folders, style));
            id.push(style.separator());
            id.push_str(&path.file);
            fold(&id, style)
        }
        None => format!("n{}", rows[i].process),
    };
    let programs = |members: &[usize]| {
        members
            .iter()
            .map(|&i| identity(i))
            .collect::<HashSet<_>>()
            .len()
    };
    let by_label = |a: &TraceGroup, b: &TraceGroup| {
        cmp_code_units(&a.label.to_lowercase(), &b.label.to_lowercase())
    };

    if grouping == TraceGrouping::Program {
        let mut order: Vec<(String, Vec<usize>)> = Vec::new();
        let mut at: HashMap<String, usize> = HashMap::new();
        for (i, row) in rows.iter().enumerate() {
            let name = if row.process.is_empty() {
                "—"
            } else {
                row.process
            };
            let slot = *at.entry(name.to_owned()).or_insert_with(|| {
                order.push((name.to_owned(), Vec::new()));
                order.len() - 1
            });
            order[slot].1.push(i);
        }
        let mut groups: Vec<TraceGroup> = order
            .into_iter()
            .map(|(name, members)| TraceGroup {
                kind: TraceGroupKind::Program,
                key: format!("program:{name}"),
                programs: programs(&members),
                header: members.len() > 1,
                label: name,
                rule_value: None,
                rows: members,
            })
            .collect();
        groups.sort_by(by_label);
        return groups;
    }

    // Distinct folders, each with the row that first spelled it.
    let mut first_row: HashMap<Vec<String>, usize> = HashMap::new();
    for (i, path) in paths.iter().enumerate() {
        if let Some(path) = path {
            first_row.entry(folder_key(path, style)).or_insert(i);
        }
    }
    // Sorted by segments, a folder's descendants follow it in one run, so
    // each folder's group is the run's first, shallowest folder. A root never
    // takes in the folders below it: that would be every program on the disk.
    let mut folders: Vec<&Vec<String>> = first_row.keys().collect();
    folders.sort();
    let root_len = style.root_len();
    let mut group_of: HashMap<&Vec<String>, &Vec<String>> = HashMap::new();
    let mut current: Option<&Vec<String>> = None;
    for folder in folders {
        let top = match current {
            Some(top) if folder.starts_with(top) => top,
            _ => folder,
        };
        current = (folder.len() > root_len).then_some(top);
        group_of.insert(folder, top);
    }

    let mut order: Vec<(&Vec<String>, Vec<usize>)> = Vec::new();
    let mut at: HashMap<&Vec<String>, usize> = HashMap::new();
    let mut without_path = Vec::new();
    for (i, path) in paths.iter().enumerate() {
        let Some(path) = path else {
            without_path.push(i);
            continue;
        };
        let key = folder_key(path, style);
        let Some(&top) = group_of.get(&key) else {
            without_path.push(i);
            continue;
        };
        let slot = *at.entry(top).or_insert_with(|| {
            order.push((top, Vec::new()));
            order.len() - 1
        });
        order[slot].1.push(i);
    }
    let mut groups: Vec<TraceGroup> = order
        .into_iter()
        .filter_map(|(top, members)| {
            let path = paths[*first_row.get(top)?].as_ref()?;
            let below_root = top.len().saturating_sub(root_len);
            let label = folder_text(&path.root, path.folders.get(..below_root)?, style);
            let rule_value = (below_root > 0).then(|| format!("{label}{}*", style.separator()));
            Some(TraceGroup {
                kind: TraceGroupKind::Folder,
                key: format!("folder:{}", fold(&label, style)),
                programs: programs(&members),
                header: true,
                label,
                rule_value,
                rows: members,
            })
        })
        .collect();
    groups.sort_by(by_label);
    if !without_path.is_empty() {
        groups.push(TraceGroup {
            kind: TraceGroupKind::NoPath,
            key: "no-path".to_owned(),
            label: String::new(),
            rule_value: None,
            programs: programs(&without_path),
            header: true,
            rows: without_path,
        });
    }
    groups
}

/// How soon a success over the additional route must follow a held connection
/// for the two to read as one story: held while the address was learned, then
/// routed. Later than this, the hold is its own event and stays a block.
pub const LEARNED_ROUTE_WINDOW_MS: i64 = 10_000;

/// The fields of a trace row the learned-route fold reads.
#[derive(Clone, Copy, Debug)]
pub struct TraceOutcomeRef<'a> {
    pub process: &'a str,
    pub process_path: &'a str,
    pub remote: &'a str,
    pub verdict: &'a str,
    pub blocked_by: &'a str,
    pub block_reason: &'a str,
    pub egress_role: &'a str,
    pub observed_at_ms: i64,
}

/// A held connection and the success over the additional route that followed
/// it: the list shows `routed` alone, saying it was held first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LearnedRoute {
    pub held: usize,
    pub routed: usize,
}

/// The address part of a trace endpoint: `[v6]:port`, `v4:port` or bare.
fn endpoint_address(remote: &str) -> &str {
    let s = js::trim(remote);
    if let Some(rest) = s.strip_prefix('[') {
        return rest.find(']').map_or(rest, |close| &rest[..close]);
    }
    match (s.find(':'), s.rfind(':')) {
        (Some(first), Some(last)) if first == last => &s[..last],
        _ => s,
    }
}

/// Who and where a row went: the program by path, by name where the path is
/// missing, and the address without its port. `None` when either is unknown,
/// since a pair of strangers proves nothing.
fn outcome_key(row: &TraceOutcomeRef<'_>) -> Option<String> {
    let address = endpoint_address(row.remote);
    let program = if !row.process_path.is_empty() {
        format!("p{}", row.process_path)
    } else if !row.process.is_empty() && row.process != "?" {
        format!("n{}", row.process)
    } else {
        return None;
    };
    (!address.is_empty()).then(|| format!("{program}\n{address}"))
}

/// A hold an app rule's own learning explains: ours, and not a rule's block.
fn is_held(row: &TraceOutcomeRef<'_>) -> bool {
    row.verdict == "block"
        && row.blocked_by == "netrulerouter"
        && matches!(row.block_reason, "route-unavailable" | "unattributed" | "")
        && row.observed_at_ms > 0
}

fn is_routed(row: &TraceOutcomeRef<'_>) -> bool {
    row.verdict == "permit" && row.egress_role == "secondary" && row.observed_at_ms > 0
}

/// Each held connection followed within [`LEARNED_ROUTE_WINDOW_MS`] by the
/// same program reaching the same address over the additional route
/// (`connTraceLearnedRoutes` in `pure.js`), paired with the earliest such
/// success; by `held`, in input order. Several holds may share one success.
/// Run on a read of the trace, never per connection.
#[must_use]
pub fn conn_trace_learned_routes(rows: &[TraceOutcomeRef<'_>]) -> Vec<LearnedRoute> {
    let mut routed: HashMap<String, Vec<(i64, usize)>> = HashMap::new();
    for (i, row) in rows.iter().enumerate() {
        if is_routed(row) {
            if let Some(key) = outcome_key(row) {
                routed.entry(key).or_default().push((row.observed_at_ms, i));
            }
        }
    }
    for successes in routed.values_mut() {
        successes.sort_unstable();
    }
    rows.iter()
        .enumerate()
        .filter(|(_, row)| is_held(row))
        .filter_map(|(held, row)| {
            let successes = routed.get(&outcome_key(row)?)?;
            let at = successes.partition_point(|&(t, _)| t < row.observed_at_ms);
            let &(t, routed) = successes.get(at)?;
            (t - row.observed_at_ms <= LEARNED_ROUTE_WINDOW_MS)
                .then_some(LearnedRoute { held, routed })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome<'a>(
        verdict: &'a str,
        egress_role: &'a str,
        remote: &'a str,
        observed_at_ms: i64,
    ) -> TraceOutcomeRef<'a> {
        TraceOutcomeRef {
            process: "claude.exe",
            process_path: r"C:\Apps\claude.exe",
            remote,
            verdict,
            blocked_by: if verdict == "block" {
                "netrulerouter"
            } else {
                ""
            },
            block_reason: if verdict == "block" {
                "route-unavailable"
            } else {
                ""
            },
            egress_role,
            observed_at_ms,
        }
    }

    /// The first contact to a new address is held, then routed: the user must
    /// see one row that went over the tunnel, not "it works but blocks".
    #[test]
    fn a_hold_then_a_tunnel_success_reads_as_one_routed_row() {
        let rows = [
            outcome("permit", "secondary", "160.79.104.10:443", 1_003_000),
            outcome("block", "primary", "160.79.104.10:443", 1_000_000),
        ];
        assert_eq!(
            conn_trace_learned_routes(&rows),
            vec![LearnedRoute { held: 1, routed: 0 }]
        );
    }

    /// Nothing went through afterwards: the block is real and must stay one.
    #[test]
    fn a_hold_without_a_success_stays_a_block() {
        let rows = [
            outcome("block", "primary", "160.79.104.10:443", 1_000_000),
            outcome("permit", "primary", "160.79.104.10:443", 1_002_000),
            outcome("permit", "secondary", "160.79.104.11:443", 1_002_000),
        ];
        assert!(conn_trace_learned_routes(&rows).is_empty());
    }

    /// A success long after is no evidence the hold was the learning step.
    #[test]
    fn a_success_much_later_leaves_two_rows() {
        let rows = [
            outcome("block", "primary", "160.79.104.10:443", 1_000_000),
            outcome("permit", "secondary", "160.79.104.10:443", 1_060_000),
        ];
        assert!(conn_trace_learned_routes(&rows).is_empty());
    }

    /// The user's own Block rule and a foreign firewall are never folded away.
    #[test]
    fn a_rule_block_or_a_foreign_block_is_never_folded() {
        let mut by_rule = outcome("block", "primary", "160.79.104.10:443", 1_000_000);
        by_rule.block_reason = "blocked-by-rule";
        let mut foreign = outcome("block", "primary", "160.79.104.10:443", 1_000_500);
        foreign.blocked_by = "other";
        let rows = [
            by_rule,
            foreign,
            outcome("permit", "secondary", "160.79.104.10:443", 1_001_000),
        ];
        assert!(conn_trace_learned_routes(&rows).is_empty());
    }

    #[test]
    fn ports_brackets_and_zones_are_read_through() {
        assert!(is_non_internet_address("10.0.0.5:443"));
        assert!(is_non_internet_address("[fe80::1%4]:53"));
        assert!(!is_non_internet_address("203.0.113.7:443"));
        assert!(!is_non_internet_address("<private-ipv4>"));
        assert!(is_ipv6_endpoint("[2001:db8::1]:443"));
        assert!(!is_ipv6_endpoint("192.0.2.1:80"));
    }

    fn rows<'a>(paths: &[(&'a str, &'a str)]) -> Vec<TraceRowRef<'a>> {
        paths
            .iter()
            .map(|&(process, process_path)| TraceRowRef {
                process,
                process_path,
            })
            .collect()
    }

    #[test]
    fn a_folder_inside_a_listed_folder_joins_its_group() {
        let input = rows(&[
            ("avp.exe", r"C:\Program Files\AVP\avp.exe"),
            ("avp2.exe", r"c:\program files\avp\sub\avp2.exe"),
            ("other.exe", r"C:\Tools\other.exe"),
            ("avp.exe", r"C:\Program Files\AVP\avp.exe"),
        ]);
        let groups = group_trace_rows(&input, TraceGrouping::Folder, PathStyle::Windows);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].label, r"C:\Program Files\AVP");
        assert_eq!(groups[0].rows, vec![0, 1, 3]);
        assert_eq!(groups[0].programs, 2);
        assert_eq!(
            groups[0].rule_value.as_deref(),
            Some(r"C:\Program Files\AVP\*")
        );
        assert_eq!(groups[1].label, r"C:\Tools");
    }

    #[test]
    fn case_and_separators_follow_the_style_not_the_build() {
        let input = rows(&[("a", "/opt/App/a"), ("b", "/opt/app/b")]);
        let linux = group_trace_rows(&input, TraceGrouping::Folder, PathStyle::Linux);
        assert_eq!(linux.len(), 2);
        let mac = group_trace_rows(&input, TraceGrouping::Folder, PathStyle::MacOS);
        assert_eq!(mac.len(), 1);
        assert_eq!(mac[0].rule_value.as_deref(), Some("/opt/App/*"));
    }

    #[test]
    fn a_root_never_takes_in_the_folders_below_it() {
        let input = rows(&[("boot.exe", r"C:\boot.exe"), ("t.exe", r"C:\Tools\t.exe")]);
        let groups = group_trace_rows(&input, TraceGrouping::Folder, PathStyle::Windows);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].label, r"C:\");
        assert_eq!(groups[0].rule_value, None);
        assert_eq!(groups[1].rows, vec![1]);
    }

    #[test]
    fn unreadable_paths_go_last_and_nothing_panics() {
        let long = format!(r"C:\{}\x.exe", "a".repeat(MAX_PATH_BYTES));
        let deep = format!("/{}x", "d/".repeat(MAX_PATH_SEGMENTS + 1));
        let odd = [
            "",
            "relative\\x.exe",
            "C:\\a\\..\\x.exe",
            "C:\\a\u{0}\\x.exe",
            "\\\\server",
            "\\\\?\\",
            "C:",
            "/",
            "\u{feff}",
            long.as_str(),
            deep.as_str(),
            "C:\\a:stream\\x.exe",
            "\\\\.\\..\\x",
        ];
        for style in [PathStyle::Windows, PathStyle::Linux, PathStyle::MacOS] {
            let input: Vec<_> = odd
                .iter()
                .map(|p| TraceRowRef {
                    process: "p",
                    process_path: p,
                })
                .collect();
            let groups = group_trace_rows(&input, TraceGrouping::Folder, style);
            let last = groups.last().map(|g| g.kind);
            assert_eq!(last, Some(TraceGroupKind::NoPath), "{style:?}");
            let total: usize = groups.iter().map(|g| g.rows.len()).sum();
            assert_eq!(total, odd.len());
        }
        let unc = rows(&[
            ("x", r"\\?\UNC\srv\share\app\x.exe"),
            ("y", r"\\srv\share\app\y.exe"),
        ]);
        let groups = group_trace_rows(&unc, TraceGrouping::Folder, PathStyle::Windows);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].label, r"\\srv\share\app");
    }

    #[test]
    fn a_program_seen_once_has_no_header_and_a_flat_list_no_groups() {
        let input = rows(&[("b", ""), ("a", ""), ("b", "")]);
        let groups = group_trace_rows(&input, TraceGrouping::Program, PathStyle::Windows);
        let shape: Vec<_> = groups
            .iter()
            .map(|g| (g.label.as_str(), g.header))
            .collect();
        assert_eq!(shape, vec![("a", false), ("b", true)]);
        let flat = group_trace_rows(&input, TraceGrouping::None, PathStyle::Windows);
        assert!(flat.is_empty());
        for grouping in TraceGrouping::ALL {
            assert_eq!(TraceGrouping::from_slug(grouping.slug()), Some(grouping));
        }
    }
}
