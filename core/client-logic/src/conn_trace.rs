//! The connection trace's view filters, over the row's display string: it may
//! carry a port and may be masked by the redaction tier, and a value that does
//! not parse is never classified, so no filter hides a row it could not read.

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_brackets_and_zones_are_read_through() {
        assert!(is_non_internet_address("10.0.0.5:443"));
        assert!(is_non_internet_address("[fe80::1%4]:53"));
        assert!(!is_non_internet_address("203.0.113.7:443"));
        assert!(!is_non_internet_address("<private-ipv4>"));
        assert!(is_ipv6_endpoint("[2001:db8::1]:443"));
        assert!(!is_ipv6_endpoint("192.0.2.1:80"));
    }
}
