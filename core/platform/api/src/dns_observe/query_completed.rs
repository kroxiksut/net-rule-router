//! The payload of `Microsoft-Windows-DNS-Client` event 3008 ("query
//! completed"), walked without the OS.
//!
//! Kept beside the port rather than in the Windows backend so the walk is
//! tested on every host and fuzzed: the answers inside are whatever a remote
//! server or an on-path spoofer sent, and the callback that runs it sees every
//! resolution on the machine.
//!
//! Layout: `QueryName` (UTF-16, NUL-terminated), fixed fields, then
//! `QueryResults` (UTF-16, NUL-terminated). The name is the first string and
//! the results the LAST non-empty one, which is robust to the fixed fields in
//! between. Windows decorates the results with type prefixes and semicolons
//! (`"type:  5 cdn.example;::ffff:192.0.2.1;2001:db8::1;"`).

use std::net::IpAddr;

use super::DnsObservation;

/// Addresses kept per family from one answer; the rest are ignored. A real
/// answer holds a few dozen at most, and the cap keeps the duplicate check
/// linear in the payload.
pub const MAX_ADDRESSES_PER_FAMILY: usize = 64;

/// The observation event 3008 carries, or `None` when it answered no address.
///
/// Scanned in place: the only allocations are the hostname and the address
/// lists of an observation that is returned. An IPv4-mapped answer
/// (`::ffff:a.b.c.d`) is its IPv4 address.
#[must_use]
pub fn parse_query_completed(bytes: &[u8]) -> Option<DnsObservation> {
    let units = Utf16Le(bytes);
    let n = units.len();
    let name_end = (0..n).find(|&i| units.at(i) == 0).unwrap_or(n);
    let results_from = (name_end + 1).min(n);

    let mut end = n;
    while end > results_from && units.at(end - 1) == 0 {
        end -= 1;
    }
    let mut start = end;
    while start > results_from && units.at(start - 1) != 0 {
        start -= 1;
    }
    let mut ipv4s = Vec::new();
    let mut ipv6s = Vec::new();
    for_each_record::<MAX_RECORD>((start..end).map(|i| units.at(i)), |record| {
        match record.and_then(record_address) {
            Some(IpAddr::V4(v4)) => push_distinct(&mut ipv4s, v4),
            Some(IpAddr::V6(v6)) => push_distinct(&mut ipv6s, v6),
            None => {}
        }
    });
    if ipv4s.is_empty() && ipv6s.is_empty() {
        return None;
    }
    // The canonical form drops trailing dots, so a name of dots alone is none.
    if (0..name_end).all(|i| units.at(i) == u16::from(b'.')) {
        return None;
    }
    Some(DnsObservation {
        hostname: canonical_hostname((0..name_end).map(|i| units.at(i)), name_end),
        ipv4s,
        ipv6s,
        owner: None,
    })
}

/// A little-endian UTF-16 payload read unit by unit; a trailing odd byte
/// belongs to no unit.
#[derive(Clone, Copy)]
struct Utf16Le<'a>(&'a [u8]);

impl Utf16Le<'_> {
    fn len(self) -> usize {
        self.0.len() / 2
    }

    fn at(self, i: usize) -> u16 {
        u16::from_le_bytes([self.0[2 * i], self.0[2 * i + 1]])
    }
}

/// What `canonicalize_hostname` makes of the lossy-decoded name, built in one
/// allocation.
fn canonical_hostname(units: impl Iterator<Item = u16>, unit_count: usize) -> String {
    let mut name = String::with_capacity(unit_count);
    name.extend(char::decode_utf16(units).map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER)));
    let kept = name.trim_end_matches('.').len();
    name.truncate(kept);
    name.make_ascii_lowercase();
    name
}

fn push_distinct<T: PartialEq>(out: &mut Vec<T>, value: T) {
    if out.len() < MAX_ADDRESSES_PER_FAMILY && !out.contains(&value) {
        out.push(value);
    }
}

/// Longest record kept: a `type:  28 ` prefix plus a scoped mapped address.
const MAX_RECORD: usize = 64;

/// Calls `flush` with every `;`-separated record of the results, trimmed; a
/// record longer than `N` or holding a non-ASCII unit is passed as `None`.
/// Fixed-size buffer: the scan never allocates.
fn for_each_record<const N: usize>(
    units: impl Iterator<Item = u16>,
    mut flush: impl FnMut(Option<&str>),
) {
    fn emit(record: &[u8], damaged: bool, flush: &mut impl FnMut(Option<&str>)) {
        if damaged {
            flush(None);
            return;
        }
        let text = std::str::from_utf8(record).map_or("", str::trim_ascii);
        if !text.is_empty() {
            flush(Some(text));
        }
    }
    let mut record = [0u8; N];
    let mut len = 0usize;
    let mut damaged = false;
    for unit in units {
        match u8::try_from(unit) {
            Ok(b';') => {
                emit(&record[..len], damaged, &mut flush);
                len = 0;
                damaged = false;
            }
            Ok(b) if b.is_ascii() => {
                if len < N {
                    record[len] = b;
                    len += 1;
                } else {
                    damaged = true;
                }
            }
            _ => damaged = true,
        }
    }
    emit(&record[..len], damaged, &mut flush);
}

/// The address one results record names, or `None`. A record is an address
/// alone (`192.0.2.1`, `::ffff:192.0.2.1`) or one behind a `type: 1` /
/// `type: 28` prefix, parsed whole. Any other record, a CNAME name
/// (`type:  5 cdn.example`) above all, is dropped whole: a run of digits and
/// dots inside a name the remote server chose was never an answer.
fn record_address(record: &str) -> Option<IpAddr> {
    let value = match record.strip_prefix("type:") {
        Some(rest) => {
            let rest = rest.trim_ascii_start();
            let digits = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
            let (rtype, value) = rest.split_at(digits);
            if !matches!(rtype, "1" | "28") {
                return None;
            }
            value.trim_ascii_start()
        }
        None => record,
    };
    // A link-local AAAA carries its zone, which no address parser takes.
    let value = value.split_once('%').map_or(value, |(address, _)| address);
    value.parse::<IpAddr>().ok().map(|ip| ip.to_canonical())
}

#[cfg(test)]
mod tests;
