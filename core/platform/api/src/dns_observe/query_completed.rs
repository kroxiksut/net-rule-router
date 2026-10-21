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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
    let results = || (start..end).map(move |i| units.at(i));
    let mut ipv4s = ipv4_tokens(results());
    let ipv6s = ipv6_tokens(results(), &mut ipv4s);
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

/// Calls `flush` with every maximal run of ASCII bytes `admits` accepts, a run
/// longer than `N` passed as `None`. Fixed-size buffer: the scan never
/// allocates.
fn for_each_token<const N: usize>(
    units: impl Iterator<Item = u16>,
    admits: impl Fn(u8) -> bool,
    mut flush: impl FnMut(Option<&str>),
) {
    fn emit(token: &[u8], overlong: bool, flush: &mut impl FnMut(Option<&str>)) {
        if token.is_empty() {
            return;
        }
        flush(if overlong {
            None
        } else {
            std::str::from_utf8(token).ok()
        });
    }
    let mut token = [0u8; N];
    let mut len = 0usize;
    let mut overlong = false;
    for unit in units {
        match u8::try_from(unit) {
            Ok(b) if admits(b) => {
                if len < N {
                    token[len] = b;
                    len += 1;
                } else {
                    overlong = true;
                }
            }
            _ => {
                emit(&token[..len], overlong, &mut flush);
                len = 0;
                overlong = false;
            }
        }
    }
    emit(&token[..len], overlong, &mut flush);
}

/// Every distinct dotted-quad IPv4 in a results string, in order; a token is a
/// maximal run of ASCII digits and dots.
fn ipv4_tokens(units: impl Iterator<Item = u16>) -> Vec<Ipv4Addr> {
    // "255.255.255.255": anything longer is no address.
    const MAX_TOKEN: usize = 15;
    let mut out = Vec::new();
    for_each_token::<MAX_TOKEN>(
        units,
        |b| b.is_ascii_digit() || b == b'.',
        |token| {
            if let Some(ip) = token.and_then(|t| t.parse::<Ipv4Addr>().ok()) {
                push_distinct(&mut out, ip);
            }
        },
    );
    out
}

/// Every distinct IPv6 in a results string, in order; a token is a maximal run
/// of hex digits, colons and dots holding a colon. A mapped one goes to
/// `ipv4s` instead, as the IPv4 address it is.
fn ipv6_tokens(units: impl Iterator<Item = u16>, ipv4s: &mut Vec<Ipv4Addr>) -> Vec<Ipv6Addr> {
    // "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255".
    const MAX_TOKEN: usize = 45;
    let mut out = Vec::new();
    for_each_token::<MAX_TOKEN>(
        units,
        |b| b.is_ascii_hexdigit() || b == b':' || b == b'.',
        |token| {
            let Some(ip) = token
                .filter(|t| t.contains(':'))
                .and_then(|t| t.parse::<Ipv6Addr>().ok())
            else {
                return;
            };
            match IpAddr::V6(ip).to_canonical() {
                IpAddr::V4(v4) => push_distinct(ipv4s, v4),
                IpAddr::V6(v6) => push_distinct(&mut out, v6),
            }
        },
    );
    out
}

#[cfg(test)]
mod tests;
