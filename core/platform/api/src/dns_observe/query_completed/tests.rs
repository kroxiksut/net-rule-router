use super::*;

fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// An event 3008 payload: the name, fixed fields, then the results.
fn payload(name: &str, results: &str) -> Vec<u8> {
    let mut d = utf16z(name);
    d.extend_from_slice(&1u32.to_le_bytes()); // QueryType
    d.extend_from_slice(&0x6000u64.to_le_bytes()); // QueryOptions
    d.extend_from_slice(&0u32.to_le_bytes()); // QueryStatus
    d.extend(utf16z(results));
    d
}

/// The parse that decodes every string, kept as the oracle the in-place scan
/// must agree with.
mod reference {
    use super::super::*;

    fn read_utf16z(bytes: &[u8], off: usize) -> Option<(String, usize)> {
        let mut units: Vec<u16> = Vec::new();
        let mut i = off;
        while i + 1 < bytes.len() {
            let u = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
            i += 2;
            if u == 0 {
                return Some((String::from_utf16_lossy(&units), i));
            }
            units.push(u);
        }
        if units.is_empty() {
            None
        } else {
            Some((String::from_utf16_lossy(&units), i))
        }
    }

    fn read_last_utf16z(bytes: &[u8], from: usize) -> Option<String> {
        let mut last: Option<String> = None;
        let mut i = from;
        while i + 1 < bytes.len() {
            if let Some((s, next)) = read_utf16z(bytes, i) {
                if !s.is_empty() {
                    last = Some(s);
                }
                if next <= i {
                    break;
                }
                i = next;
            } else {
                break;
            }
        }
        last
    }

    fn push<T: PartialEq>(out: &mut Vec<T>, value: T) {
        if out.len() < MAX_ADDRESSES_PER_FAMILY && !out.contains(&value) {
            out.push(value);
        }
    }

    fn addresses(results: &str) -> (Vec<Ipv4Addr>, Vec<Ipv6Addr>) {
        let mut v4 = Vec::new();
        for token in results.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
            if let Ok(ip) = token.parse::<Ipv4Addr>() {
                push(&mut v4, ip);
            }
        }
        let mut v6 = Vec::new();
        for token in results.split(|c: char| !(c.is_ascii_hexdigit() || c == ':' || c == '.')) {
            if !token.contains(':') {
                continue;
            }
            if let Ok(ip) = token.parse::<Ipv6Addr>() {
                match ip.to_ipv4_mapped() {
                    Some(mapped) => push(&mut v4, mapped),
                    None => push(&mut v6, ip),
                }
            }
        }
        (v4, v6)
    }

    pub(super) fn parse(bytes: &[u8]) -> Option<DnsObservation> {
        if bytes.len() < 2 {
            return None;
        }
        let (hostname, after) = read_utf16z(bytes, 0)?;
        let results = read_last_utf16z(bytes, after).unwrap_or_default();
        let (ipv4s, ipv6s) = addresses(&results);
        if ipv4s.is_empty() && ipv6s.is_empty() {
            return None;
        }
        let canonical = crate::dns::canonicalize_hostname(&hostname);
        if canonical.is_empty() {
            return None;
        }
        Some(DnsObservation {
            hostname: canonical,
            ipv4s,
            ipv6s,
            owner: None,
        })
    }
}

fn golden_payloads() -> Vec<Vec<u8>> {
    let mut out = vec![
        payload(
            "Host.Example.COM.",
            "type:  5 cdn.example.net;192.0.2.10;192.0.2.11;192.0.2.10;",
        ),
        payload("a.example", "::ffff:c000:22c;not-an-ip;198.51.100.7;"),
        payload("v6only.example", "2001:db8::1;2001:DB8::2;2001:db8::1;"),
        payload("...", "192.0.2.1;"),
        payload("", "192.0.2.1;"),
        payload("xn--d1acufc.example", "203.0.113.255;999.1.1.1;1.2.3.4.5;"),
        payload("long.example", "192.0.2.1234567890123;0192.0.2.1;192.0.2.3"),
        payload("\u{0445}\u{043e}\u{0441}\u{0442}.example", "192.0.2.4"),
        payload("empty.example", ""),
        utf16z("unterminated.example")[..40].to_vec(),
        vec![0, 0],
        vec![0x41],
    ];
    // A zero-padded tail with an odd byte, a trailing string that is not
    // the results, and a lone surrogate inside the answer.
    let mut tail = payload("tail.example", "192.0.2.5;");
    tail.extend_from_slice(&[0, 0, 0, 0, 7]);
    out.push(tail);
    let mut shadowed = payload("shadow.example", "192.0.2.6;");
    shadowed.extend(utf16z("x"));
    out.push(shadowed);
    let mut surrogate = utf16z("s.example");
    let answer = "192.0.2.7"
        .encode_utf16()
        .chain([0xD800])
        .chain("192.0.2.8;".encode_utf16());
    for u in answer {
        surrogate.extend_from_slice(&u.to_le_bytes());
    }
    surrogate.extend_from_slice(&[0, 0]);
    out.push(surrogate);
    out.push(payload(
        "dual.example",
        "type:  28 ::ffff:192.0.2.9;2001:db8::9;fe80::1%12;12345:db8::1;",
    ));
    out
}

#[test]
fn golden_payloads_parse_as_expected() {
    let got: Vec<_> = golden_payloads()
        .iter()
        .map(|p| parse_query_completed(p))
        .collect();
    let ip = |d| Ipv4Addr::new(192, 0, 2, d);
    let v6 = |s: &str| s.parse::<Ipv6Addr>().expect("v6");
    let obs = |h: &str, ipv4s: Vec<Ipv4Addr>, ipv6s: Vec<Ipv6Addr>| {
        Some(DnsObservation {
            hostname: h.into(),
            ipv4s,
            ipv6s,
            owner: None,
        })
    };
    assert_eq!(
        got[0],
        obs("host.example.com", vec![ip(10), ip(11)], vec![])
    );
    // The mapped answer is the IPv4 address it maps.
    assert_eq!(
        got[1],
        obs(
            "a.example",
            vec![Ipv4Addr::new(198, 51, 100, 7), ip(44)],
            vec![]
        )
    );
    assert_eq!(
        got[2],
        obs(
            "v6only.example",
            vec![],
            vec![v6("2001:db8::1"), v6("2001:db8::2")]
        )
    );
    assert_eq!(got[3], None);
    assert_eq!(got[4], None);
    assert_eq!(
        got[5],
        obs(
            "xn--d1acufc.example",
            vec![Ipv4Addr::new(203, 0, 113, 255)],
            vec![]
        )
    );
    assert_eq!(got[6], obs("long.example", vec![ip(3)], vec![]));
    assert_eq!(
        got[7],
        obs(
            "\u{0445}\u{043e}\u{0441}\u{0442}.example",
            vec![ip(4)],
            vec![]
        )
    );
    assert_eq!(got[8], None);
    assert_eq!(got[9], None);
    assert_eq!(got[10], None);
    assert_eq!(got[11], None);
    assert_eq!(got[12], obs("tail.example", vec![ip(5)], vec![]));
    assert_eq!(got[13], None, "the last string is the results field");
    assert_eq!(got[14], obs("s.example", vec![ip(7), ip(8)], vec![]));
    assert_eq!(
        got[15],
        obs(
            "dual.example",
            vec![ip(9)],
            vec![v6("2001:db8::9"), v6("fe80::1")]
        )
    );
}

#[test]
fn an_answer_keeps_a_bounded_number_of_addresses_per_family() {
    let mut results = String::new();
    for i in 0..300u32 {
        results.push_str(&format!("10.0.{}.{};2001:db8::{:x};", i / 256, i % 256, i));
    }
    let got = parse_query_completed(&payload("many.example", &results)).expect("answered");
    assert_eq!(got.ipv4s.len(), MAX_ADDRESSES_PER_FAMILY);
    assert_eq!(got.ipv6s.len(), MAX_ADDRESSES_PER_FAMILY);
    assert_eq!(got.ipv4s[0], Ipv4Addr::new(10, 0, 0, 0));
}

#[test]
fn agrees_with_the_reference_parse() {
    for p in golden_payloads() {
        assert_eq!(parse_query_completed(&p), reference::parse(&p), "{p:?}");
    }
    // Deterministic noise over the alphabet a results string is made of.
    let alphabet: Vec<u16> = "0123456789abcdefABF.;:: typeAZ\u{0}\u{044f}"
        .encode_utf16()
        .chain([0xD800])
        .collect();
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..5000 {
        let len = (next() % 96) as usize;
        let mut d = Vec::with_capacity(2 * len + 1);
        for _ in 0..len {
            let u = alphabet[(next() % alphabet.len() as u64) as usize];
            d.extend_from_slice(&u.to_le_bytes());
        }
        if next() & 1 == 1 {
            d.push(b'1');
        }
        assert_eq!(parse_query_completed(&d), reference::parse(&d), "{d:?}");
    }
}
