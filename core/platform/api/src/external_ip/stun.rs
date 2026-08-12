//! Pure STUN binding-message codec (RFC 5389).
//!
//! This is the policy half of the external-address probe: it turns a
//! transaction id into the 20 bytes that go on the wire, and turns a datagram
//! that came back into an `Ipv4Addr` — or into nothing. No sockets, no clock,
//! no randomness, so the whole thing is exercised by byte fixtures alone.
//!
//! Every entry point is **total**: a truncated, malformed, mis-declared or
//! attacker-chosen datagram yields `None`, never a panic. The parser therefore
//! uses only checked slicing and checked arithmetic.
//!
//! Only what the probe needs is implemented — the fixed header,
//! `XOR-MAPPED-ADDRESS` (preferred) and `MAPPED-ADDRESS` (legacy fallback),
//! IPv4 family. Message integrity, fingerprint, authentication, IPv6 and the
//! TURN/ICE attribute space are deliberately absent: the answer is advisory
//! display data, never an input to a security decision. The transaction id is
//! the only correlation token, and it is checked.

use std::net::Ipv4Addr;

/// RFC 5389 magic cookie. Doubles as the mask of `XOR-MAPPED-ADDRESS`.
const MAGIC_COOKIE: u32 = 0x2112_A442;

/// Fixed header: type (2) + body length (2) + cookie (4) + transaction id (12).
pub const HEADER_LEN: usize = 20;

const TYPE_BINDING_REQUEST: u16 = 0x0001;
const TYPE_BINDING_SUCCESS: u16 = 0x0101;

const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

const ATTR_HEADER_LEN: usize = 4;
const FAMILY_IPV4: u8 = 0x01;

/// 96-bit transaction id — the only thing tying a response to our request.
pub type TransactionId = [u8; 12];

/// Encode a binding request with no attributes: the smallest legal STUN
/// message, and all the probe needs to learn its own reflexive address.
#[must_use]
pub fn build_binding_request(transaction_id: &TransactionId) -> [u8; HEADER_LEN] {
    let mut message = [0u8; HEADER_LEN];
    message[0..2].copy_from_slice(&TYPE_BINDING_REQUEST.to_be_bytes());
    // Bytes 2..4 (body length) stay zero — no attributes follow.
    message[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    message[8..HEADER_LEN].copy_from_slice(transaction_id);
    message
}

/// Extract the reflexive IPv4 address from a binding success response.
///
/// Returns `None` for anything that is not a success response to *this*
/// transaction, or that carries no IPv4 mapped address.
#[must_use]
pub fn parse_binding_response(datagram: &[u8], transaction_id: &TransactionId) -> Option<Ipv4Addr> {
    let header: [u8; HEADER_LEN] = datagram.get(..HEADER_LEN)?.try_into().ok()?;

    if u16::from_be_bytes([header[0], header[1]]) != TYPE_BINDING_SUCCESS {
        // Error responses (0x0111) and indications land here too.
        return None;
    }
    if u32::from_be_bytes([header[4], header[5], header[6], header[7]]) != MAGIC_COOKIE {
        return None;
    }
    if header.get(8..HEADER_LEN)? != transaction_id.as_slice() {
        // Stray, late or spoofed datagram for a different exchange.
        return None;
    }

    let declared_body_len = usize::from(u16::from_be_bytes([header[2], header[3]]));
    let body_end = HEADER_LEN.checked_add(declared_body_len)?;
    let body = datagram.get(HEADER_LEN..body_end)?;
    read_mapped_address(body)
}

/// Walk the attribute list once, preferring `XOR-MAPPED-ADDRESS` and falling
/// back to the legacy `MAPPED-ADDRESS` only if no XOR form is present.
fn read_mapped_address(body: &[u8]) -> Option<Ipv4Addr> {
    let mut legacy = None;
    let mut cursor = 0usize;

    loop {
        let Some(attr_end) = cursor.checked_add(ATTR_HEADER_LEN) else {
            break;
        };
        let Some(&[type_hi, type_lo, len_hi, len_lo]) = body.get(cursor..attr_end) else {
            break;
        };
        let attr_type = u16::from_be_bytes([type_hi, type_lo]);
        let value_len = usize::from(u16::from_be_bytes([len_hi, len_lo]));

        let Some(value_end) = attr_end.checked_add(value_len) else {
            break;
        };
        let Some(value) = body.get(attr_end..value_end) else {
            // Declared length runs past the message: stop rather than guess.
            break;
        };

        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => {
                if let Some(address) = decode_address(value, true) {
                    return Some(address);
                }
            }
            ATTR_MAPPED_ADDRESS => {
                if legacy.is_none() {
                    legacy = decode_address(value, false);
                }
            }
            // Unknown attributes are skipped by design — servers routinely add
            // SOFTWARE, FINGERPRINT, RESPONSE-ORIGIN and friends.
            _ => {}
        }

        // Attribute values are padded to a 4-byte boundary; the padding is not
        // counted in the declared length.
        let Some(next) = attr_end.checked_add(value_len.div_ceil(4) * 4) else {
            break;
        };
        if next <= cursor {
            // Defensive: a zero-length attribute must still advance the cursor,
            // which it does (+4). Anything else would loop forever.
            break;
        }
        cursor = next;
    }

    legacy
}

/// Decode one MAPPED-ADDRESS-shaped value: reserved (1) + family (1) +
/// port (2) + address (4 for IPv4). The port is of no interest to us.
fn decode_address(value: &[u8], xor: bool) -> Option<Ipv4Addr> {
    if *value.get(1)? != FAMILY_IPV4 {
        // IPv6 reflexive addresses are ignored: the probe binds an IPv4 source
        // address, so an IPv6 answer would describe a different path.
        return None;
    }
    let raw: [u8; 4] = value.get(4..8)?.try_into().ok()?;
    let address = u32::from_be_bytes(raw);
    Some(Ipv4Addr::from(if xor {
        address ^ MAGIC_COOKIE
    } else {
        address
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TID: TransactionId = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];

    /// Assemble a success response around a raw attribute block.
    fn success_response(transaction_id: &TransactionId, attributes: &[u8]) -> Vec<u8> {
        let mut message = Vec::with_capacity(HEADER_LEN + attributes.len());
        message.extend_from_slice(&TYPE_BINDING_SUCCESS.to_be_bytes());
        let len = u16::try_from(attributes.len()).expect("fixture body fits in u16");
        message.extend_from_slice(&len.to_be_bytes());
        message.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        message.extend_from_slice(transaction_id);
        message.extend_from_slice(attributes);
        message
    }

    fn xor_mapped_ipv4(address: Ipv4Addr, port: u16) -> Vec<u8> {
        let xored = u32::from(address) ^ MAGIC_COOKIE;
        let xored_port = port ^ u16::try_from(MAGIC_COOKIE >> 16).expect("upper half is u16");
        let mut attribute = vec![0x00, 0x20, 0x00, 0x08, 0x00, FAMILY_IPV4];
        attribute.extend_from_slice(&xored_port.to_be_bytes());
        attribute.extend_from_slice(&xored.to_be_bytes());
        attribute
    }

    fn mapped_ipv4(address: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut attribute = vec![0x00, 0x01, 0x00, 0x08, 0x00, FAMILY_IPV4];
        attribute.extend_from_slice(&port.to_be_bytes());
        attribute.extend_from_slice(&u32::from(address).to_be_bytes());
        attribute
    }

    #[test]
    fn binding_request_is_a_bare_20_byte_header() {
        let request = build_binding_request(&TID);
        assert_eq!(request.len(), HEADER_LEN);
        assert_eq!([request[0], request[1]], [0x00, 0x01], "binding request");
        assert_eq!([request[2], request[3]], [0x00, 0x00], "no attributes");
        assert_eq!(
            [request[4], request[5], request[6], request[7]],
            [0x21, 0x12, 0xa4, 0x42],
            "magic cookie"
        );
        assert_eq!(&request[8..], &TID);
    }

    #[test]
    fn xor_mapped_address_is_unmasked() {
        let expected = Ipv4Addr::new(203, 0, 113, 10);
        let datagram = success_response(&TID, &xor_mapped_ipv4(expected, 54_321));
        assert_eq!(parse_binding_response(&datagram, &TID), Some(expected));
    }

    #[test]
    fn legacy_mapped_address_is_the_fallback() {
        let expected = Ipv4Addr::new(198, 51, 100, 7);
        let datagram = success_response(&TID, &mapped_ipv4(expected, 1234));
        assert_eq!(parse_binding_response(&datagram, &TID), Some(expected));
    }

    #[test]
    fn xor_form_wins_over_legacy_form() {
        let mut attributes = mapped_ipv4(Ipv4Addr::new(198, 51, 100, 7), 1234);
        attributes.extend_from_slice(&xor_mapped_ipv4(Ipv4Addr::new(203, 0, 113, 10), 4321));
        let datagram = success_response(&TID, &attributes);
        assert_eq!(
            parse_binding_response(&datagram, &TID),
            Some(Ipv4Addr::new(203, 0, 113, 10))
        );
    }

    #[test]
    fn unknown_and_oddly_padded_attributes_are_skipped() {
        // SOFTWARE, 5 bytes of value → 3 bytes of padding before the next one.
        let mut attributes = vec![
            0x80, 0x22, 0x00, 0x05, b'n', b'r', b'r', b'-', b'x', 0, 0, 0,
        ];
        attributes.extend_from_slice(&xor_mapped_ipv4(Ipv4Addr::new(192, 0, 2, 33), 1));
        let datagram = success_response(&TID, &attributes);
        assert_eq!(
            parse_binding_response(&datagram, &TID),
            Some(Ipv4Addr::new(192, 0, 2, 33))
        );
    }

    #[test]
    fn foreign_transaction_id_is_rejected() {
        let datagram = success_response(&TID, &xor_mapped_ipv4(Ipv4Addr::new(203, 0, 113, 10), 1));
        let mut other = TID;
        other[0] ^= 0xff;
        assert_eq!(parse_binding_response(&datagram, &other), None);
    }

    #[test]
    fn error_response_yields_nothing() {
        let mut datagram =
            success_response(&TID, &xor_mapped_ipv4(Ipv4Addr::new(203, 0, 113, 10), 1));
        datagram[0] = 0x01;
        datagram[1] = 0x11;
        assert_eq!(parse_binding_response(&datagram, &TID), None);
    }

    #[test]
    fn wrong_magic_cookie_yields_nothing() {
        let mut datagram =
            success_response(&TID, &xor_mapped_ipv4(Ipv4Addr::new(203, 0, 113, 10), 1));
        datagram[4] = 0x00;
        assert_eq!(parse_binding_response(&datagram, &TID), None);
    }

    #[test]
    fn ipv6_family_is_ignored() {
        let mut attribute = vec![0x00, 0x20, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00];
        attribute.extend_from_slice(&[0x11; 16]);
        let datagram = success_response(&TID, &attribute);
        assert_eq!(parse_binding_response(&datagram, &TID), None);
    }

    #[test]
    fn attribute_length_past_the_message_yields_nothing() {
        // Declares an 8-byte value but supplies 4.
        let attribute = vec![0x00, 0x20, 0x00, 0x08, 0x00, FAMILY_IPV4, 0x00, 0x00];
        let datagram = success_response(&TID, &attribute);
        assert_eq!(parse_binding_response(&datagram, &TID), None);
    }

    #[test]
    fn body_length_past_the_datagram_yields_nothing() {
        let mut datagram =
            success_response(&TID, &xor_mapped_ipv4(Ipv4Addr::new(203, 0, 113, 10), 1));
        datagram[3] = 0xff;
        assert_eq!(parse_binding_response(&datagram, &TID), None);
    }

    #[test]
    fn every_truncation_is_handled_without_panicking() {
        let datagram = success_response(&TID, &xor_mapped_ipv4(Ipv4Addr::new(203, 0, 113, 10), 1));
        for cut in 0..datagram.len() {
            assert_eq!(
                parse_binding_response(&datagram[..cut], &TID),
                None,
                "truncated to {cut} bytes must not parse"
            );
        }
        assert!(parse_binding_response(&datagram, &TID).is_some());
    }

    #[test]
    fn arbitrary_noise_is_handled_without_panicking() {
        // Deterministic pseudo-noise: no panic, no infinite loop.
        let mut byte = 7u8;
        for len in 0..600usize {
            let noise = (0..len)
                .map(|_| {
                    byte = byte.wrapping_mul(31).wrapping_add(17);
                    byte
                })
                .collect::<Vec<u8>>();
            let _ = parse_binding_response(&noise, &TID);
        }
    }
}
