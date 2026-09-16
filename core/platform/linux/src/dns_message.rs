//! Encoding and decoding of the DNS messages the Linux resolver exchanges.
//!
//! Deliberately hand-written and deliberately minimal: the product asks exactly
//! one question — "what A records does this name have, and for how long" — and a
//! full resolver library would bring an async runtime and a dependency surface
//! for it. What is here is the wire format from RFC 1035 sections 4.1.1-4.1.4,
//! plus name compression, which is not optional: real servers use it in every
//! answer.
//!
//! Pure over bytes, so every test runs on any host — the socket lives in
//! [`crate::dns_resolver`].

pub use nrr_platform_api::dns::AddressFamily;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Resource-record type for an IPv4 address.
const TYPE_A: u16 = 1;
/// Resource-record type for an IPv6 address.
const TYPE_AAAA: u16 = 28;
/// Resource-record type for a canonical-name alias.
const TYPE_CNAME: u16 = 5;
/// The only class this product speaks.
const CLASS_IN: u16 = 1;
/// Two high bits set marks a compression pointer rather than a length.
const POINTER_MASK: u8 = 0xC0;
/// A label is at most 63 bytes; a name at most 255.
const MAX_LABEL: usize = 63;
const MAX_NAME: usize = 255;
/// Bound on compression jumps while reading one name. A message can point back
/// at itself, and a reader without this bound loops forever on a hostile answer.
const MAX_JUMPS: usize = 16;

/// Wire record type carrying an address of `family`.
const fn record_type(family: AddressFamily) -> u16 {
    match family {
        AddressFamily::Ipv4 => TYPE_A,
        AddressFamily::Ipv6 => TYPE_AAAA,
    }
}

/// RDATA width of one address record of `family`.
const fn record_rdlength(family: AddressFamily) -> usize {
    match family {
        AddressFamily::Ipv4 => 4,
        AddressFamily::Ipv6 => 16,
    }
}

/// Read an address out of RDATA already known to be 4 or 16 octets wide.
fn address_from(rdata: &[u8]) -> IpAddr {
    if let Ok(octets) = <[u8; 4]>::try_from(rdata) {
        return IpAddr::V4(Ipv4Addr::from(octets));
    }
    match <[u8; 16]>::try_from(rdata) {
        Ok(octets) => IpAddr::V6(Ipv6Addr::from(octets)),
        // Unreachable: the caller matched RDLENGTH against the family width
        // before calling. The unspecified address is the inert answer, and it
        // is dropped downstream like any other non-routable one.
        Err(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

/// What a server said about a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsAnswer {
    /// The name resolved. `addresses` is never empty here, and every entry
    /// belongs to the family that was asked for.
    Addresses {
        addresses: Vec<IpAddr>,
        /// Smallest TTL across the records, which is when the answer as a whole
        /// stops being trustworthy.
        min_ttl: u32,
    },
    /// The name does not exist. Authoritative — worth caching as a negative.
    NxDomain,
    /// The name exists but has no record of the family asked for (a
    /// `CNAME`-only name, or one that lives on the other family), or the
    /// answer section carried nothing we asked for.
    NoAddresses,
    /// The server refused to answer.
    Refused,
    /// Any other non-zero rcode, kept as a number rather than guessed at.
    ServerFailure { rcode: u8 },
}

/// Why a response could not be read as an answer to our question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsDecodeError {
    /// Shorter than the header, or a record runs past the end.
    Truncated,
    /// The transaction id is not the one we sent — a reply to somebody else's
    /// question, or an attempt to answer ours before the real server does.
    WrongTransaction { expected: u16, got: u16 },
    /// The response answers a different name than the one asked.
    WrongQuestion { asked: String, answered: String },
    /// The message is a query, not a response.
    NotAResponse,
    /// The answer did not fit in a datagram and must be re-asked over TCP.
    TruncatedByServer,
    /// A name is malformed: an over-long label, a pointer loop, a name past the
    /// length limit.
    MalformedName,
}

/// Lower-case, no trailing dot — the form both the query and the cache use.
#[must_use]
pub fn canonical_name(hostname: &str) -> String {
    hostname.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Build a standard recursive query for `hostname`'s records of `family`.
///
/// Returns `None` for a name no query can be built from: empty, an over-long
/// label, or one carrying bytes that cannot appear in the wire format.
#[must_use]
pub fn encode_query(transaction_id: u16, hostname: &str, family: AddressFamily) -> Option<Vec<u8>> {
    let canonical = canonical_name(hostname);
    if canonical.is_empty() || canonical.len() > MAX_NAME || canonical.contains('\0') {
        return None;
    }

    let mut message = Vec::with_capacity(canonical.len() + 18);
    message.extend_from_slice(&transaction_id.to_be_bytes());
    // RD (recursion desired): we are a stub, the server does the walking.
    message.extend_from_slice(&0x0100u16.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes()); // one question
    message.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // no answers/authority/extra

    for label in canonical.split('.') {
        if label.is_empty() || label.len() > MAX_LABEL {
            return None;
        }
        // A label is length-prefixed, so its own length must fit in six bits.
        message.push(u8::try_from(label.len()).ok()?);
        message.extend_from_slice(label.as_bytes());
    }
    message.push(0); // root label ends the name
    message.extend_from_slice(&record_type(family).to_be_bytes());
    message.extend_from_slice(&CLASS_IN.to_be_bytes());
    Some(message)
}

/// Read a response to the query we sent.
///
/// `expected_id` and `asked` are checked before anything in the answer is
/// believed: a datagram is trivially forged, and the only cheap defences a stub
/// has are that the transaction matches and that the answer is about the name it
/// asked for.
pub fn decode_response(
    message: &[u8],
    expected_id: u16,
    asked: &str,
    family: AddressFamily,
) -> Result<DnsAnswer, DnsDecodeError> {
    let want = record_type(family);
    let want_rdlength = record_rdlength(family);
    if message.len() < 12 {
        return Err(DnsDecodeError::Truncated);
    }
    let id = u16::from_be_bytes([message[0], message[1]]);
    if id != expected_id {
        return Err(DnsDecodeError::WrongTransaction {
            expected: expected_id,
            got: id,
        });
    }
    let flags = u16::from_be_bytes([message[2], message[3]]);
    if flags & 0x8000 == 0 {
        return Err(DnsDecodeError::NotAResponse);
    }
    if flags & 0x0200 != 0 {
        return Err(DnsDecodeError::TruncatedByServer);
    }
    let rcode = (flags & 0x000F) as u8;
    let question_count = u16::from_be_bytes([message[4], message[5]]);
    let answer_count = u16::from_be_bytes([message[6], message[7]]);

    let mut at = 12;
    for _ in 0..question_count {
        let (name, next) = read_name(message, at)?;
        // The question is echoed back; a mismatch means this datagram is not
        // about our name, whatever else it claims.
        let echoed_type = message
            .get(next..next + 2)
            .map(|t| u16::from_be_bytes([t[0], t[1]]));
        if question_count == 1 && (name != canonical_name(asked) || echoed_type != Some(want)) {
            return Err(DnsDecodeError::WrongQuestion {
                asked: canonical_name(asked),
                answered: name,
            });
        }
        at = next + 4; // qtype + qclass
        if at > message.len() {
            return Err(DnsDecodeError::Truncated);
        }
    }

    match rcode {
        0 => {}
        3 => return Ok(DnsAnswer::NxDomain),
        5 => return Ok(DnsAnswer::Refused),
        other => return Ok(DnsAnswer::ServerFailure { rcode: other }),
    }

    let mut addresses = Vec::new();
    let mut min_ttl = u32::MAX;
    for _ in 0..answer_count {
        let (_name, after_name) = read_name(message, at)?;
        let header_end = after_name + 10;
        if header_end > message.len() {
            return Err(DnsDecodeError::Truncated);
        }
        let rtype = u16::from_be_bytes([message[after_name], message[after_name + 1]]);
        let rclass = u16::from_be_bytes([message[after_name + 2], message[after_name + 3]]);
        let ttl = u32::from_be_bytes([
            message[after_name + 4],
            message[after_name + 5],
            message[after_name + 6],
            message[after_name + 7],
        ]);
        let rdlength =
            u16::from_be_bytes([message[after_name + 8], message[after_name + 9]]) as usize;
        let rdata_end = header_end + rdlength;
        if rdata_end > message.len() {
            return Err(DnsDecodeError::Truncated);
        }
        if rclass == CLASS_IN && rtype == want && rdlength == want_rdlength {
            addresses.push(address_from(&message[header_end..rdata_end]));
            min_ttl = min_ttl.min(ttl);
        } else if rclass == CLASS_IN && rtype == TYPE_CNAME {
            // The alias itself is not an address; its own A records follow in
            // the same answer section, so the chain needs no separate walk. The
            // TTL still counts: the answer is only good while the alias is.
            min_ttl = min_ttl.min(ttl);
        }
        at = rdata_end;
    }

    if addresses.is_empty() {
        return Ok(DnsAnswer::NoAddresses);
    }
    Ok(DnsAnswer::Addresses {
        addresses,
        // `min_ttl` cannot still be MAX here: an address always sets it.
        min_ttl,
    })
}

/// Read a (possibly compressed) name, returning it and the offset just past the
/// name AS WRITTEN — following a pointer must not advance the caller's cursor.
fn read_name(message: &[u8], start: usize) -> Result<(String, usize), DnsDecodeError> {
    let mut labels: Vec<String> = Vec::new();
    let mut at = start;
    let mut end_of_name: Option<usize> = None;
    let mut jumps = 0;
    let mut total = 0usize;

    loop {
        let length = *message.get(at).ok_or(DnsDecodeError::Truncated)?;
        if length & POINTER_MASK == POINTER_MASK {
            let second = *message.get(at + 1).ok_or(DnsDecodeError::Truncated)?;
            let target = usize::from(u16::from_be_bytes([length & !POINTER_MASK, second]));
            // The name as written ends at the pointer, wherever it leads.
            end_of_name.get_or_insert(at + 2);
            jumps += 1;
            if jumps > MAX_JUMPS || target >= message.len() {
                return Err(DnsDecodeError::MalformedName);
            }
            at = target;
            continue;
        }
        if length == 0 {
            at += 1;
            break;
        }
        let length = usize::from(length);
        if length > MAX_LABEL {
            return Err(DnsDecodeError::MalformedName);
        }
        let from = at + 1;
        let to = from + length;
        let label = message.get(from..to).ok_or(DnsDecodeError::Truncated)?;
        total += length + 1;
        if total > MAX_NAME {
            return Err(DnsDecodeError::MalformedName);
        }
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        at = to;
    }

    Ok((labels.join("."), end_of_name.unwrap_or(at)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn header(id: u16, flags: u16, questions: u16, answers: u16) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(&id.to_be_bytes());
        h.extend_from_slice(&flags.to_be_bytes());
        h.extend_from_slice(&questions.to_be_bytes());
        h.extend_from_slice(&answers.to_be_bytes());
        h.extend_from_slice(&[0, 0, 0, 0]);
        h
    }

    fn name(labels: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for label in labels {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn a_record(ttl: u32, ip: [u8; 4]) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&[0xC0, 0x0C]); // pointer to the question's name
        r.extend_from_slice(&TYPE_A.to_be_bytes());
        r.extend_from_slice(&CLASS_IN.to_be_bytes());
        r.extend_from_slice(&ttl.to_be_bytes());
        r.extend_from_slice(&4u16.to_be_bytes());
        r.extend_from_slice(&ip);
        r
    }

    fn aaaa_record(ttl: u32, ip: [u8; 16]) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&[0xC0, 0x0C]); // pointer to the question's name
        r.extend_from_slice(&TYPE_AAAA.to_be_bytes());
        r.extend_from_slice(&CLASS_IN.to_be_bytes());
        r.extend_from_slice(&ttl.to_be_bytes());
        r.extend_from_slice(&16u16.to_be_bytes());
        r.extend_from_slice(&ip);
        r
    }

    fn response(id: u16, answers: &[Vec<u8>], rcode: u16) -> Vec<u8> {
        response_of(id, answers, rcode, TYPE_A)
    }

    fn response_of(id: u16, answers: &[Vec<u8>], rcode: u16, qtype: u16) -> Vec<u8> {
        let mut m = header(id, 0x8180 | rcode, 1, answers.len() as u16);
        m.extend_from_slice(&name(&["example", "com"]));
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&CLASS_IN.to_be_bytes());
        for answer in answers {
            m.extend_from_slice(answer);
        }
        m
    }

    /// The v6 half of the decoder is not on today's data path, which is exactly
    /// why it needs its own round trip.
    #[test]
    fn an_aaaa_answer_decodes_to_v6_addresses() {
        let ip = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let message = response_of(3, &[aaaa_record(90, ip)], 0, TYPE_AAAA);

        assert_eq!(
            decode_response(&message, 3, "example.com", AddressFamily::Ipv6),
            Ok(DnsAnswer::Addresses {
                addresses: vec![IpAddr::V6(Ipv6Addr::from(ip))],
                min_ttl: 90,
            })
        );
    }

    /// RDLENGTH and TYPE together are what keep one family out of the other's
    /// answer: an `A` record must never satisfy an `AAAA` question.
    #[test]
    fn an_answer_of_the_other_family_is_not_an_address() {
        // Right question type, wrong record inside.
        let message = response_of(4, &[a_record(60, [1, 2, 3, 4])], 0, TYPE_AAAA);
        assert_eq!(
            decode_response(&message, 4, "example.com", AddressFamily::Ipv6),
            Ok(DnsAnswer::NoAddresses)
        );

        // Right record, wrong question echoed back: not an answer to ours.
        let crossed = response_of(5, &[a_record(60, [1, 2, 3, 4])], 0, TYPE_A);
        assert!(matches!(
            decode_response(&crossed, 5, "example.com", AddressFamily::Ipv6),
            Err(DnsDecodeError::WrongQuestion { .. })
        ));
    }

    #[test]
    fn a_query_carries_the_name_as_length_prefixed_labels() {
        let query = encode_query(0x1234, "Example.COM.", AddressFamily::Ipv4)
            .expect("a plain name must encode");

        assert_eq!(&query[0..2], &[0x12, 0x34]);
        assert_eq!(u16::from_be_bytes([query[2], query[3]]) & 0x0100, 0x0100);
        assert_eq!(&query[12..], b"\x07example\x03com\x00\x00\x01\x00\x01");
    }

    #[test]
    fn a_name_that_cannot_be_asked_about_is_refused_rather_than_mangled() {
        assert!(encode_query(1, "", AddressFamily::Ipv4).is_none());
        assert!(encode_query(1, "a..b", AddressFamily::Ipv4).is_none());
        assert!(encode_query(1, &"x".repeat(64), AddressFamily::Ipv4).is_none());
        assert!(encode_query(1, "bad\0name", AddressFamily::Ipv4).is_none());
    }

    #[test]
    fn addresses_and_the_smallest_ttl_come_back() {
        let message = response(
            7,
            &[a_record(300, [23, 10, 20, 138]), a_record(60, [1, 2, 3, 4])],
            0,
        );

        let answer = decode_response(&message, 7, "example.com", AddressFamily::Ipv4)
            .expect("a well-formed answer");

        assert_eq!(
            answer,
            DnsAnswer::Addresses {
                addresses: vec![v4(23, 10, 20, 138), v4(1, 2, 3, 4)],
                // The answer is only good while its shortest-lived record is.
                min_ttl: 60,
            }
        );
    }

    /// The two cheap defences a stub resolver has. Without them any host on the
    /// path could answer first and put its own address in the routing policy.
    #[test]
    fn a_reply_to_a_different_question_is_rejected() {
        let message = response(7, &[a_record(60, [1, 2, 3, 4])], 0);

        assert!(matches!(
            decode_response(&message, 8, "example.com", AddressFamily::Ipv4),
            Err(DnsDecodeError::WrongTransaction { .. })
        ));
        assert!(matches!(
            decode_response(&message, 7, "other.com", AddressFamily::Ipv4),
            Err(DnsDecodeError::WrongQuestion { .. })
        ));
    }

    #[test]
    fn an_authoritative_no_such_name_is_distinct_from_an_empty_answer() {
        let nx = response(1, &[], 3);
        let empty = response(1, &[], 0);

        assert_eq!(
            decode_response(&nx, 1, "example.com", AddressFamily::Ipv4),
            Ok(DnsAnswer::NxDomain)
        );
        assert_eq!(
            decode_response(&empty, 1, "example.com", AddressFamily::Ipv4),
            Ok(DnsAnswer::NoAddresses)
        );
    }

    #[test]
    fn a_refusal_and_an_unknown_rcode_are_kept_apart() {
        let refused = response(1, &[], 5);
        let odd = response(1, &[], 9);

        assert_eq!(
            decode_response(&refused, 1, "example.com", AddressFamily::Ipv4),
            Ok(DnsAnswer::Refused)
        );
        assert_eq!(
            decode_response(&odd, 1, "example.com", AddressFamily::Ipv4),
            Ok(DnsAnswer::ServerFailure { rcode: 9 })
        );
    }

    /// An answer too big for a datagram must be re-asked over TCP, not read as
    /// "these are all the addresses".
    #[test]
    fn a_server_truncated_answer_says_so() {
        let mut message = response(1, &[a_record(60, [1, 2, 3, 4])], 0);
        // TC is bit 9 of the flags word, which lives in the HIGH byte.
        message[2] |= 0x02;

        assert_eq!(
            decode_response(&message, 1, "example.com", AddressFamily::Ipv4),
            Err(DnsDecodeError::TruncatedByServer)
        );
    }

    /// A message may point at itself. A reader without a jump bound never
    /// returns, which on a service means one hostile answer stops DNS refresh.
    #[test]
    fn a_compression_loop_is_an_error_rather_than_a_hang() {
        let mut message = header(1, 0x8180, 1, 1);
        message.extend_from_slice(&name(&["example", "com"]));
        message.extend_from_slice(&TYPE_A.to_be_bytes());
        message.extend_from_slice(&CLASS_IN.to_be_bytes());
        let loop_at = message.len() as u16;
        // A pointer to itself.
        message.extend_from_slice(&[0xC0 | (loop_at >> 8) as u8, loop_at as u8]);

        assert_eq!(
            decode_response(&message, 1, "example.com", AddressFamily::Ipv4),
            Err(DnsDecodeError::MalformedName)
        );
    }

    /// A record whose length runs past the buffer is a truncated read, never a
    /// silent slice of whatever follows in memory.
    #[test]
    fn a_record_running_past_the_end_is_truncated() {
        let mut message = response(1, &[a_record(60, [1, 2, 3, 4])], 0);
        message.truncate(message.len() - 2);

        assert_eq!(
            decode_response(&message, 1, "example.com", AddressFamily::Ipv4),
            Err(DnsDecodeError::Truncated)
        );
    }

    #[test]
    fn a_cname_before_the_addresses_does_not_hide_them() {
        let mut cname = Vec::new();
        cname.extend_from_slice(&[0xC0, 0x0C]);
        cname.extend_from_slice(&TYPE_CNAME.to_be_bytes());
        cname.extend_from_slice(&CLASS_IN.to_be_bytes());
        cname.extend_from_slice(&30u32.to_be_bytes());
        let target = name(&["cdn", "example", "net"]);
        cname.extend_from_slice(&(target.len() as u16).to_be_bytes());
        cname.extend_from_slice(&target);

        let message = response(2, &[cname, a_record(300, [10, 0, 0, 7])], 0);

        assert_eq!(
            decode_response(&message, 2, "example.com", AddressFamily::Ipv4),
            Ok(DnsAnswer::Addresses {
                addresses: vec![v4(10, 0, 0, 7)],
                // The alias's own TTL bounds the answer too.
                min_ttl: 30,
            })
        );
    }
}
