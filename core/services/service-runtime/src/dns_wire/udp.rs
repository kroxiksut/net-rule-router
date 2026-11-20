//! Client-side UDP sizing. Upstream TCP success does not enlarge the stub's
//! receive buffer; only that stub's own EDNS0 OPT can negotiate a larger reply.

use super::{skip_encoded_name, DNS_HEADER_LEN};

const LEGACY_BUDGET: usize = 512;
// The listener receives 65,535 bytes. Advertise the smaller IPv4 UDP payload
// ceiling so the same response works on either family of the local listener.
const RECEIVE_CAPACITY: u16 = 65_507;
const MAX_MESSAGE: usize = 65_535;
const TYPE_OPT: u16 = 41;

#[derive(Clone, Copy)]
struct Edns {
    payload: u16,
    extended_rcode: u8,
    version: u8,
    dnssec_ok: bool,
}

/// Inspect sections without interpreting their RDATA. Every iteration consumes
/// at least eleven bytes, every option at least four; counts cannot make the
/// walk exceed the bounded datagram. A malformed or duplicate OPT grants no
/// larger UDP budget. Unsupported EDNS versions retain the existing handling.
fn message_edns(packet: &[u8]) -> Option<Edns> {
    if packet.len() < DNS_HEADER_LEN
        || packet.len() > MAX_MESSAGE
        || packet[4..6] != [0, 1]
        || packet[10..12] == [0, 0]
    {
        return None;
    }
    let answer = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let authority = u16::from_be_bytes([packet[8], packet[9]]) as usize;
    let additional = u16::from_be_bytes([packet[10], packet[11]]) as usize;
    let count = answer + authority + additional;
    if count > packet.len() / 11 {
        return None;
    }
    super::question_key(packet)?;
    let mut off = skip_encoded_name(packet, DNS_HEADER_LEN)?.checked_add(4)?;
    packet.get(..off)?;
    let mut opt = None;
    for index in 0..count {
        let after_name = skip_encoded_name(packet, off)?;
        let fixed = packet.get(after_name..after_name.checked_add(10)?)?;
        let rdlen = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        let start = after_name + 10;
        let end = start.checked_add(rdlen)?;
        let rdata = packet.get(start..end)?;
        if u16::from_be_bytes([fixed[0], fixed[1]]) == TYPE_OPT {
            if index < answer + authority
                || opt.is_some()
                || after_name != off + 1
                || packet[off] != 0
            {
                return None;
            }
            let mut option = 0usize;
            while option < rdata.len() {
                let header = rdata.get(option..option.checked_add(4)?)?;
                let len = u16::from_be_bytes([header[2], header[3]]) as usize;
                option = option.checked_add(4 + len)?;
                rdata.get(..option)?;
            }
            opt = Some(Edns {
                payload: u16::from_be_bytes([fixed[2], fixed[3]]),
                extended_rcode: fixed[4],
                version: fixed[5],
                dnssec_ok: fixed[6] & 0x80 != 0,
            });
        }
        off = end;
    }
    (off == packet.len()).then_some(opt).flatten()
}

fn client_edns(query: &[u8]) -> Option<Edns> {
    message_edns(query).filter(|opt| opt.version == 0 && opt.extended_rcode == 0)
}

fn append_opt(reply: &mut Vec<u8>, opt: Edns) {
    reply[10..12].copy_from_slice(&1u16.to_be_bytes());
    reply.extend_from_slice(&[0, 0, TYPE_OPT as u8]);
    reply.extend_from_slice(&RECEIVE_CAPACITY.to_be_bytes());
    reply.extend_from_slice(&[
        opt.extended_rcode,
        0,
        if opt.dnssec_ok { 0x80 } else { 0 },
        0,
        0,
        0,
    ]);
}

/// Generated answers have no additional records. Acknowledge valid EDNS0 on
/// either transport; never copy client options or claim DNSSEC validation.
pub(super) fn synthesized_reply(query: &[u8], mut reply: Vec<u8>) -> Vec<u8> {
    if let Some(opt) = client_edns(query) {
        append_opt(&mut reply, opt);
    }
    reply
}

/// Expand the question before discarding other sections: a compression pointer
/// must not survive pointing at bytes we removed. Preserve label case and class.
fn standalone_question(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < DNS_HEADER_LEN || query.len() > MAX_MESSAGE || query[4..6] != [0, 1] {
        return None;
    }
    let fixed = skip_encoded_name(query, DNS_HEADER_LEN)?;
    let fixed = query.get(fixed..fixed.checked_add(4)?)?;
    let mut question = Vec::new();
    let mut off = DNS_HEADER_LEN;
    let mut jumps = 0;
    loop {
        let len = *query.get(off)? as usize;
        if len == 0 {
            question.push(0);
            break;
        }
        if len & 0xC0 == 0xC0 {
            jumps += 1;
            if jumps > 32 {
                return None;
            }
            off = ((len & 0x3F) << 8) | *query.get(off + 1)? as usize;
            continue;
        }
        if len & 0xC0 != 0 || question.len() + 1 + len > 254 {
            return None;
        }
        question.push(len as u8);
        question.extend_from_slice(query.get(off + 1..off + 1 + len)?);
        off += 1 + len;
    }
    question.extend_from_slice(fixed);
    Some(question)
}

/// Fit every UDP response at the final send boundary, after policy enforcement.
/// Drop whole RRsets rather than cutting bytes or publishing a partial RRset.
/// TCP retains the full answer through its existing, independently pinned path.
pub(crate) fn fit_reply(query: &[u8], reply: Vec<u8>) -> Option<Vec<u8>> {
    let edns = client_edns(query);
    let budget = edns.map_or(LEGACY_BUDGET, |opt| {
        usize::from(opt.payload.clamp(LEGACY_BUDGET as u16, RECEIVE_CAPACITY))
    });
    if reply.len() <= budget {
        return Some(reply);
    }
    let question = standalone_question(query)?;
    let mut truncated = reply.get(..DNS_HEADER_LEN)?.to_vec();
    truncated[..2].copy_from_slice(&query[..2]);
    truncated[2] |= 0x82; // QR + TC
    truncated[3] &= !0x20; // discarded records cannot carry an AD assertion
    truncated[4..6].copy_from_slice(&1u16.to_be_bytes());
    truncated[6..12].fill(0);
    truncated.extend_from_slice(&question);
    if let Some(mut opt) = edns {
        // Extended errors belong to the response OPT, never the request.
        opt.extended_rcode = message_edns(&reply).map_or(0, |upstream| upstream.extended_rcode);
        append_opt(&mut truncated, opt);
    }
    Some(truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_wire::{build_a_response, build_address_query, is_truncated, QTYPE_A};
    use std::net::Ipv4Addr;

    fn query() -> Vec<u8> {
        build_address_query(7, "LaRgE.example", QTYPE_A).expect("query")
    }

    fn large_reply(query: &[u8]) -> Vec<u8> {
        let ips: Vec<_> = (1..=32).map(|n| Ipv4Addr::new(192, 0, 2, n)).collect();
        build_a_response(query, &ips, 60).expect("reply")
    }

    fn with_opt() -> Vec<u8> {
        let mut q = query();
        q[10..12].copy_from_slice(&[0, 1]);
        q.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
        q
    }

    #[test]
    fn malformed_or_misplaced_opt_never_grants_a_larger_udp_budget() {
        let valid = with_opt();
        let start = query().len();
        let mut bad = Vec::new();
        for end in start..valid.len() {
            bad.push(valid[..end].to_vec());
        }
        for (offset, byte) in [
            (start, 0xC0),
            (start + 1, 1),
            (start + 6, 1),
            (start + 5, 1),
        ] {
            let mut q = valid.clone();
            q[offset] = byte;
            bad.push(q);
        }
        let mut duplicate = valid.clone();
        duplicate[10..12].copy_from_slice(&[0, 2]);
        duplicate.extend_from_slice(&valid[start..]);
        bad.push(duplicate);
        let mut option_overrun = valid.clone();
        option_overrun[start + 10] = 4;
        option_overrun.extend_from_slice(&[0, 1, 0, 1]); // option body missing
        bad.push(option_overrun);
        let mut trailing = valid.clone();
        trailing.push(0);
        bad.push(trailing);
        let mut wrong_section = valid.clone();
        wrong_section[6..8].copy_from_slice(&[0, 1]);
        wrong_section[10..12].copy_from_slice(&[0, 0]);
        bad.push(wrong_section);
        for q in bad {
            let reply = fit_reply(&q, large_reply(&q)).expect("minimal reply");
            assert!(reply.len() <= LEGACY_BUDGET);
            assert!(
                is_truncated(&reply),
                "malformed OPT must not enlarge the budget"
            );
            assert_eq!(&reply[10..12], &[0, 0]);
        }
    }

    #[test]
    fn valid_opt_after_an_unrelated_record_is_not_read_from_the_tail_by_guessing() {
        let base = query();
        let valid = with_opt();
        let rr = [0, 0, 16, 0, 1, 0, 0, 0, 0, 0, 1, 0]; // root TXT, one empty string
        for opt_first in [false, true] {
            let mut q = base.clone();
            q[10..12].copy_from_slice(&[0, 2]);
            if opt_first {
                q.extend_from_slice(&valid[base.len()..]);
                q.extend_from_slice(&rr);
            } else {
                q.extend_from_slice(&rr);
                q.extend_from_slice(&valid[base.len()..]);
            }
            let reply = fit_reply(&q, large_reply(&q)).expect("reply");
            assert!(reply.len() > LEGACY_BUDGET);
            assert!(!is_truncated(&reply));
        }
    }

    #[test]
    fn truncation_preserves_case_class_and_extended_error_without_dangling_pointers() {
        let base = query();
        let mut q = base[..DNS_HEADER_LEN].to_vec();
        q[10..12].copy_from_slice(&[0, 1]);
        q.extend_from_slice(&[0xC0, 0x12, 0, 1, 0, 3]); // name at18, QCLASS CH
        q.extend_from_slice(&base[DNS_HEADER_LEN..base.len() - 4]);
        q.extend_from_slice(&[0, 16, 0, 1, 0, 0, 0, 0, 0, 1, 0]); // additional TXT
        let mut reply = large_reply(&base);
        reply[3] |= 0x20; // AD must not survive discarded RRsets
        let tc = fit_reply(&q, reply).expect("expanded question");
        assert!(is_truncated(&tc));
        assert_eq!(
            &tc[DNS_HEADER_LEN..tc.len() - 2],
            &base[DNS_HEADER_LEN..base.len() - 2]
        );
        assert_eq!(&tc[tc.len() - 2..], &[0, 3]);
        assert_eq!(tc[3] & 0x20, 0);

        let mut edns_query = with_opt();
        let opt_start = base.len();
        edns_query[opt_start + 3..opt_start + 5].copy_from_slice(&512u16.to_be_bytes());
        let mut answer = large_reply(&edns_query);
        let opt_start = answer.len() - 11;
        answer[opt_start + 5] = 1; // BADVERS is encoded in the response OPT
        let tc = fit_reply(&edns_query, answer).expect("EDNS TC");
        assert!(is_truncated(&tc));
        assert_eq!(&tc[10..12], &[0, 1]);
        assert_eq!(tc[tc.len() - 6], 1, "extended error retained");

        q[13] = 0x0C; // self-referential question pointer
        assert!(fit_reply(&q, large_reply(&base)).is_none());
    }
}
