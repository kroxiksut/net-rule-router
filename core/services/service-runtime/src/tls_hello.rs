//! A TLS ClientHello carrying a server name, and what the first bytes back say.
//!
//! The question is "does this link deliver TLS for this name", not "is this a
//! valid server": filtering by name lets the TCP connection complete and then
//! silences or resets the ClientHello, so a TCP probe answers "reachable"
//! exactly for the hosts that are not. One hello and the header of the first
//! record are enough; the handshake is never finished, so no TLS library is
//! needed.

/// What the first bytes after the ClientHello were.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsAnswer {
    /// A handshake record (ServerHello): TLS for this name gets through.
    Handshake,
    /// An alert record: a TLS peer answered, so the path carries TLS too.
    Alert,
    /// Bytes that are not TLS — something on the path answered in its place.
    NotTls,
}

/// A TLS 1.3-capable ClientHello naming `server_name`. `None` for a name that
/// cannot go into SNI (empty, too long, or not plain ASCII — IDNs travel in
/// their `xn--` form).
pub fn client_hello(
    server_name: &str,
    random: &[u8; 32],
    session_id: &[u8; 32],
    x25519_share: &[u8; 32],
) -> Option<Vec<u8>> {
    let name = server_name.trim_end_matches('.').as_bytes();
    if name.is_empty()
        || name.len() > 253
        || !name
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'.')
    {
        return None;
    }

    let mut ext = Vec::with_capacity(256);
    // server_name: list(len) → host_name(0) → name(len)
    let list_len = name.len() + 3;
    push_ext(&mut ext, 0x0000, &{
        let mut v = Vec::with_capacity(list_len + 2);
        v.extend_from_slice(&u16_be(list_len));
        v.push(0);
        v.extend_from_slice(&u16_be(name.len()));
        v.extend_from_slice(name);
        v
    });
    // supported_groups: x25519, secp256r1, secp384r1
    push_ext(
        &mut ext,
        0x000a,
        &[0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18],
    );
    // ec_point_formats: uncompressed
    push_ext(&mut ext, 0x000b, &[0x01, 0x00]);
    // signature_algorithms
    push_ext(
        &mut ext,
        0x000d,
        &[
            0x00, 0x10, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01,
            0x08, 0x06, 0x06, 0x01,
        ],
    );
    // ALPN: h2, http/1.1 — some fronts close a hello that names no protocol.
    push_ext(
        &mut ext,
        0x0010,
        &[
            0x00, 0x0c, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
        ],
    );
    // supported_versions: TLS 1.3, TLS 1.2
    push_ext(&mut ext, 0x002b, &[0x04, 0x03, 0x04, 0x03, 0x03]);
    // psk_key_exchange_modes: psk_dhe_ke
    push_ext(&mut ext, 0x002d, &[0x01, 0x01]);
    // key_share: x25519. Any 32 bytes are a valid point; the handshake never
    // gets far enough to need the private half.
    push_ext(&mut ext, 0x0033, &{
        let mut v = Vec::with_capacity(38);
        v.extend_from_slice(&[0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
        v.extend_from_slice(x25519_share);
        v
    });

    let mut body = Vec::with_capacity(ext.len() + 128);
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
    body.extend_from_slice(random);
    body.push(32);
    body.extend_from_slice(session_id);
    // TLS 1.3 suites, then the common ECDHE-AEAD TLS 1.2 ones.
    let suites: [u16; 9] = [
        0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
    ];
    body.extend_from_slice(&u16_be(suites.len() * 2));
    for s in suites {
        body.extend_from_slice(&s.to_be_bytes());
    }
    body.extend_from_slice(&[0x01, 0x00]); // compression: null
    body.extend_from_slice(&u16_be(ext.len()));
    body.extend_from_slice(&ext);

    let mut handshake = Vec::with_capacity(body.len() + 4);
    handshake.push(0x01); // ClientHello
    handshake.extend_from_slice(&u24_be(body.len()));
    handshake.extend_from_slice(&body);

    let mut record = Vec::with_capacity(handshake.len() + 5);
    record.extend_from_slice(&[0x16, 0x03, 0x01]);
    record.extend_from_slice(&u16_be(handshake.len()));
    record.extend_from_slice(&handshake);
    Some(record)
}

/// Classifies the first bytes read after the hello. `None` until there is a
/// whole record header to judge.
pub fn classify_first_record(bytes: &[u8]) -> Option<TlsAnswer> {
    let header = bytes.get(..5)?;
    let tls_version = header[1] == 0x03 && header[2] <= 0x04;
    Some(match header[0] {
        0x16 if tls_version => TlsAnswer::Handshake,
        0x15 if tls_version => TlsAnswer::Alert,
        _ => TlsAnswer::NotTls,
    })
}

fn push_ext(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&u16_be(data.len()));
    out.extend_from_slice(data);
}

/// Lengths here are bounded by the 253-byte name, far below `u16::MAX`.
fn u16_be(n: usize) -> [u8; 2] {
    u16::try_from(n).unwrap_or(u16::MAX).to_be_bytes()
}

fn u24_be(n: usize) -> [u8; 3] {
    let b = u32::try_from(n).unwrap_or(u32::MAX).to_be_bytes();
    [b[1], b[2], b[3]]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(name: &str) -> Option<Vec<u8>> {
        client_hello(name, &[7; 32], &[9; 32], &[5; 32])
    }

    /// Lengths at every level must agree, or a server drops the hello as
    /// malformed — which would read as "the link silences this name".
    #[test]
    fn the_hello_is_one_consistent_record_naming_the_host() {
        let h = hello("accounts.example").expect("valid name");
        assert_eq!(&h[..3], &[0x16, 0x03, 0x01]);
        let record_len = usize::from(u16::from_be_bytes([h[3], h[4]]));
        assert_eq!(record_len, h.len() - 5);
        assert_eq!(h[5], 0x01, "ClientHello");
        let hs_len = (usize::from(h[6]) << 16) | (usize::from(h[7]) << 8) | usize::from(h[8]);
        assert_eq!(hs_len, h.len() - 9);

        // Walk the body to the extensions and check their total length.
        let mut at = 9 + 2 + 32;
        at += 1 + usize::from(h[at]);
        let suites = usize::from(u16::from_be_bytes([h[at], h[at + 1]]));
        at += 2 + suites;
        at += 1 + usize::from(h[at]);
        let ext_len = usize::from(u16::from_be_bytes([h[at], h[at + 1]]));
        assert_eq!(ext_len, h.len() - at - 2);

        let needle = b"accounts.example";
        assert!(h.windows(needle.len()).any(|w| w == needle));
    }

    #[test]
    fn a_name_that_cannot_go_into_sni_gives_no_hello() {
        assert!(hello("").is_none());
        assert!(hello("пример.рф").is_none(), "IDNs go in their xn-- form");
        assert!(hello("a b.example").is_none());
        assert!(hello(&"a".repeat(254)).is_none());
        assert!(
            hello("xn--e1afmkfd.xn--p1ai.").is_some(),
            "a trailing dot is fine"
        );
    }

    #[test]
    fn only_a_tls_record_header_counts_as_tls() {
        assert_eq!(
            classify_first_record(&[0x16, 0x03, 0x03, 0x00, 0x7a]),
            Some(TlsAnswer::Handshake)
        );
        assert_eq!(
            classify_first_record(&[0x15, 0x03, 0x03, 0x00, 0x02]),
            Some(TlsAnswer::Alert)
        );
        assert_eq!(
            classify_first_record(b"HTTP/1.1 403"),
            Some(TlsAnswer::NotTls)
        );
        assert_eq!(
            classify_first_record(&[0x16, 0x03]),
            None,
            "not a whole header yet"
        );
    }
}
