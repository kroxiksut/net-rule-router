//! minimal DNS wire codec.
//!
//! Just enough of the DNS message format (RFC 1035 §4) for the loopback
//! resolver listener: (a) extract the FIRST question's name + type so the
//! listener can decide whether a query is an `A` query for a rule host, and
//! (b) build an `A` (or error) response for the *intercept* case. Everything
//! the listener does NOT intercept — AAAA, TXT, non-rule `A`, EDNS, … — is
//! forwarded upstream as **raw bytes** with no parse, so this codec covers only
//! the narrow A-record path: robust by delegation, and dependency-free (no
//! hickory / async framework — the service runtime is blocking, not tokio).
//!
//! Names in a QUESTION are uncompressed (stub resolvers never compress the
//! question). Anything we cannot parse confidently returns `None`, and the
//! listener forwards it raw — so a codec limitation degrades to a transparent
//! proxy, never to a wrong answer.

use std::net::Ipv4Addr;

/// Fixed DNS header length (RFC 1035 §4.1.1).
pub const DNS_HEADER_LEN: usize = 12;
/// `QTYPE`/`TYPE` value for an `A` record.
pub const QTYPE_A: u16 = 1;
/// `TYPE` value for a `CNAME` record — the only alias an `A` answer may be
/// delivered under (see [`parse_a_response`]).
pub const QTYPE_CNAME: u16 = 5;
/// `QTYPE`/`TYPE` value for a `PTR` record (reverse DNS).
pub const QTYPE_PTR: u16 = 12;
/// `QTYPE`/`TYPE` value for an `HTTPS` record (RFC 9460). Its `ipv4hint` /
/// `ipv6hint` service parameters carry addresses a client may connect to
/// without ever asking for `A`.
pub const QTYPE_HTTPS: u16 = 65;
/// `CLASS` value for `IN` (the only class we accept).
const CLASS_IN: u16 = 1;
/// `RCODE` 3 — authoritative "name does not exist".
pub const RCODE_NXDOMAIN: u8 = 3;
/// `RCODE` 2 — server failure (upstream unreachable).
pub const RCODE_SERVFAIL: u8 = 2;

/// The first question of a query, plus the byte offset just past it (where the
/// answer section would begin) so a response can echo the header + question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedQuestion {
    /// Lower-cased dotted name, no trailing dot (e.g. `chatgpt.com`).
    pub qname: String,
    /// Query type (`A` = [`QTYPE_A`], `AAAA` = 28, …).
    pub qtype: u16,
    /// Offset of the byte just after the question's `QCLASS` — i.e. the length
    /// of `header + question`. A response echoes `query[..question_end]`.
    pub question_end: usize,
}

/// Parse an uncompressed QNAME starting at `off`. Returns the dotted name and
/// the offset just past the terminating zero label. `None` on any malformation
/// (truncation, or a compression pointer / reserved label the question must not
/// contain).
fn parse_qname(packet: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut total = 0usize;
    loop {
        let len = *packet.get(off)? as usize;
        if len == 0 {
            off += 1;
            break;
        }
        // Top two bits set = compression pointer (0xC0) or reserved — never
        // valid at the start of a QUESTION name. Bail so the listener forwards
        // the packet raw instead of guessing.
        if len & 0xC0 != 0 {
            return None;
        }
        off += 1;
        let end = off.checked_add(len)?;
        let label = packet.get(off..end)?;
        // A hostname label is ASCII; bail on non-UTF8 rather than lossy-decode.
        let s = std::str::from_utf8(label).ok()?.to_ascii_lowercase();
        // Guard against a pathological name length (defensive; real names ≤255).
        total = total.checked_add(len + 1)?;
        if total > 255 {
            return None;
        }
        labels.push(s);
        off = end;
    }
    Some((labels.join("."), off))
}

/// Parse the first question of a DNS query. `None` when the packet is too short,
/// carries no question, or the name cannot be parsed confidently.
pub fn parse_question(packet: &[u8]) -> Option<ParsedQuestion> {
    if packet.len() < DNS_HEADER_LEN {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return None;
    }
    let (qname, after_name) = parse_qname(packet, DNS_HEADER_LEN)?;
    // QTYPE (2) + QCLASS (2) follow the name.
    let qtype = u16::from_be_bytes([*packet.get(after_name)?, *packet.get(after_name + 1)?]);
    let _qclass = u16::from_be_bytes([*packet.get(after_name + 2)?, *packet.get(after_name + 3)?]);
    let question_end = after_name.checked_add(4)?;
    if question_end > packet.len() {
        return None;
    }
    Some(ParsedQuestion {
        qname,
        qtype,
        question_end,
    })
}

/// Turn `query`'s header + question into a response frame: QR set, RA set,
/// AA/TC cleared, opcode + RD preserved, and the NS/AR sections dropped
/// (so `NSCOUNT`/`ARCOUNT` = 0 — this also discards any EDNS OPT). `rcode` and
/// `ancount` are written by the caller. Returns the buffer positioned right
/// after the question (answers appended by the caller).
fn response_prefix(query: &[u8], question_end: usize, rcode: u8, ancount: u16) -> Vec<u8> {
    let mut resp = query[..question_end].to_vec();
    // Flags byte 1: QR=1, keep opcode (bits 3–6) + RD (bit 0), clear AA/TC.
    resp[2] = 0x80 | (resp[2] & 0x79);
    // Flags byte 2: RA=1, Z=0, RCODE=rcode.
    resp[3] = 0x80 | (rcode & 0x0F);
    resp[6..8].copy_from_slice(&ancount.to_be_bytes()); // ANCOUNT
    resp[8..10].copy_from_slice(&[0, 0]); // NSCOUNT
    resp[10..12].copy_from_slice(&[0, 0]); // ARCOUNT
    resp
}

/// Build an `A` response for `query` answering with `ips` at `ttl` seconds.
/// Each answer RR points its NAME at the question via the `0xC00C` compression
/// pointer (the question always starts at offset 12). `None` when `query` has no
/// parseable question or `ips` is empty (use [`build_error_response`] instead).
pub fn build_a_response(query: &[u8], ips: &[Ipv4Addr], ttl: u32) -> Option<Vec<u8>> {
    if ips.is_empty() {
        return None;
    }
    let q = parse_question(query)?;
    let ancount = ips.len().min(u16::MAX as usize) as u16;
    let mut resp = response_prefix(query, q.question_end, 0, ancount);
    for ip in ips.iter().take(ancount as usize) {
        resp.extend_from_slice(&[0xC0, 0x0C]); // NAME → pointer to question (offset 12)
        resp.extend_from_slice(&QTYPE_A.to_be_bytes()); // TYPE A
        resp.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        resp.extend_from_slice(&ttl.to_be_bytes()); // TTL
        resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
        resp.extend_from_slice(&ip.octets()); // RDATA
    }
    Some(resp)
}

/// Build an answer-less response carrying `rcode` (e.g. [`RCODE_NXDOMAIN`] for
/// no records, [`RCODE_SERVFAIL`] for an unreachable upstream). `None` when
/// `query` has no parseable question.
pub fn build_error_response(query: &[u8], rcode: u8) -> Option<Vec<u8>> {
    let q = parse_question(query)?;
    Some(response_prefix(query, q.question_end, rcode, 0))
}

// ── Client side (HW-0714 — raw-UDP upstream pin) ─────────────────────────────
//
// The Mode-B intercept resolved rule hosts through the OS resolver, which
// honours the very NRPT catch-all Mode B installs — a self-reference that
// timed out every rule-host query (HW-0712 finding C10-a). The direct client
// below talks RFC 1035 wire format straight to the captured upstream over a
// raw socket, which NRPT does not touch by construction (NRPT only steers the
// Windows DNS Client service). It also never consults the hosts file — the
// `resolve_hosts_bypass` posture for rule hosts rides the same codec.

/// Encode `qname` as an uncompressed QNAME. `None` when a label is empty,
/// longer than 63 octets, non-ASCII, or the total name exceeds 255 octets —
/// the caller treats the host as unresolvable rather than sending garbage.
fn encode_qname(qname: &str) -> Option<Vec<u8>> {
    let name = qname.strip_suffix('.').unwrap_or(qname);
    if name.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return None;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    if out.len() > 255 {
        return None;
    }
    Some(out)
}

/// Build a recursive `A` query for `qname` with message id `id` (one question,
/// RD set, no EDNS). `None` when the name cannot be encoded.
pub fn build_a_query(id: u16, qname: &str) -> Option<Vec<u8>> {
    let name = encode_qname(qname)?;
    let mut p = Vec::with_capacity(DNS_HEADER_LEN + name.len() + 4);
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
    p.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR
    p.extend_from_slice(&name);
    p.extend_from_slice(&QTYPE_A.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
    Some(p)
}

/// the reverse-DNS name for an IPv4
/// address: `a.b.c.d` → `d.c.b.a.in-addr.arpa` (RFC 1035 §3.5).
fn reverse_in_addr_arpa(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
}

/// Build a recursive `PTR` query for `ip`'s reverse name with message id `id`
/// (one question, RD set, no EDNS). Used by the FCrDNS learner to recover a
/// hostname for an NRR-dropped destination IP under armed block-all.
pub fn build_ptr_query(id: u16, ip: Ipv4Addr) -> Option<Vec<u8>> {
    let name = encode_qname(&reverse_in_addr_arpa(ip))?;
    let mut p = Vec::with_capacity(DNS_HEADER_LEN + name.len() + 4);
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
    p.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR
    p.extend_from_slice(&name);
    p.extend_from_slice(&QTYPE_PTR.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
    Some(p)
}

/// What one upstream response datagram means for a `PTR` query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PtrResponseOutcome {
    /// NOERROR with at least one `PTR` record. Lower-cased dotted names, no
    /// trailing dot. The FCrDNS learner forward-confirms each before trusting.
    Names(Vec<String>),
    /// Authoritative "no name": NXDOMAIN, or NOERROR with no `PTR` record.
    NoRecords,
    /// TC=1 — answer did not fit; treated as transient (no TCP fallback).
    Truncated,
    /// Any other RCODE (SERVFAIL, REFUSED, …) — transient upstream failure.
    Failed(u8),
    /// Not OUR response: wrong id, not a response frame, or a different
    /// question. Same off-path-spoofing hygiene as [`parse_a_response`].
    Mismatch,
}

/// Decode a (possibly compressed) DNS name starting at `off` into a lower-cased
/// dotted string with no trailing dot. Follows compression pointers with a
/// bounded jump budget so a malicious pointer loop cannot hang. `None` on any
/// malformation. Used only to read PTR RDATA (owner names in the answer).
fn decode_name(packet: &[u8], mut off: usize) -> Option<String> {
    let mut labels: Vec<String> = Vec::new();
    // Bound the total pointer jumps: a well-formed name has at most one, but cap
    // generously to survive legal multi-hop compression while refusing loops.
    let mut jumps = 0usize;
    let mut total = 0usize;
    loop {
        let len = *packet.get(off)? as usize;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer: the low 14 bits are the target offset.
            let b2 = *packet.get(off + 1)? as usize;
            let target = ((len & 0x3F) << 8) | b2;
            jumps += 1;
            if jumps > 32 || target >= packet.len() {
                return None;
            }
            off = target;
            continue;
        }
        if len & 0xC0 != 0 {
            return None; // reserved label type
        }
        off += 1;
        let label = packet.get(off..off + len)?;
        // Reject non-ASCII / control to keep the learned hostname sane.
        if !label.iter().all(|&b| b.is_ascii_graphic() || b == b'-') {
            return None;
        }
        total += len + 1;
        if total > 255 {
            return None;
        }
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        off += len;
    }
    if labels.is_empty() {
        return None;
    }
    Some(labels.join("."))
}

/// Parse an upstream response to [`build_ptr_query`]`(expect_id, ip)`. Collects
/// every `PTR`/`IN` record's target name in the ANSWER section. Never panics on
/// malformed input — any structural surprise stops the walk and returns what was
/// collected so far.
pub fn parse_ptr_response(expect_id: u16, ip: Ipv4Addr, packet: &[u8]) -> PtrResponseOutcome {
    if packet.len() < DNS_HEADER_LEN {
        return PtrResponseOutcome::Mismatch;
    }
    if u16::from_be_bytes([packet[0], packet[1]]) != expect_id {
        return PtrResponseOutcome::Mismatch;
    }
    if packet[2] & 0x80 == 0 {
        return PtrResponseOutcome::Mismatch; // QR=0
    }
    let Some(q) = parse_question(packet) else {
        return PtrResponseOutcome::Mismatch;
    };
    if q.qname != reverse_in_addr_arpa(ip) || q.qtype != QTYPE_PTR {
        return PtrResponseOutcome::Mismatch;
    }
    if packet[2] & 0x02 != 0 {
        return PtrResponseOutcome::Truncated;
    }
    let rcode = packet[3] & 0x0F;
    if rcode == RCODE_NXDOMAIN {
        return PtrResponseOutcome::NoRecords;
    }
    if rcode != 0 {
        return PtrResponseOutcome::Failed(rcode);
    }
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut names = Vec::new();
    let mut off = q.question_end;
    for _ in 0..ancount {
        let Some(after_name) = skip_encoded_name(packet, off) else {
            break;
        };
        let Some(fixed) = packet.get(after_name..after_name + 10) else {
            break;
        };
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let rclass = u16::from_be_bytes([fixed[2], fixed[3]]);
        let rdlen = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        let rdata_start = after_name + 10;
        if packet.get(rdata_start..rdata_start + rdlen).is_none() {
            break;
        }
        if rtype == QTYPE_PTR && rclass == 1 {
            // PTR RDATA is a domain name (possibly compressed into earlier bytes).
            if let Some(name) = decode_name(packet, rdata_start) {
                names.push(name);
            }
        }
        off = rdata_start + rdlen;
    }
    if names.is_empty() {
        return PtrResponseOutcome::NoRecords;
    }
    PtrResponseOutcome::Names(names)
}

/// What one upstream response datagram means for an `A` query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AResponseOutcome {
    /// NOERROR with at least one `A` record. `min_ttl` is the smallest TTL
    /// across the returned `A` records (the safe cache horizon).
    Answers {
        addresses: Vec<Ipv4Addr>,
        min_ttl: u32,
    },
    /// Authoritative "no usable records": NXDOMAIN, or NOERROR whose answer
    /// section carries no `A` record (e.g. a CNAME chain ending off-answer).
    NoRecords,
    /// TC=1 — the answer did not fit the datagram. The caller treats this as
    /// transient (no TCP fallback in phase 1; the passive observer backstops).
    Truncated,
    /// Any other RCODE (SERVFAIL, REFUSED, …) — transient upstream failure.
    Failed(u8),
    /// Not OUR response: wrong id, not a response frame, or a different
    /// question. The transport keeps waiting for the matching datagram —
    /// baseline off-path-spoofing hygiene, and robust against late replies of
    /// a previous (timed-out) query on a reused socket.
    Mismatch,
}

/// Skip one (possibly compressed) encoded name starting at `off`; returns the
/// offset just past it. A compression pointer terminates the encoding in place
/// (RFC 1035 §4.1.4) — it is skipped, never followed (we only need the width).
fn skip_encoded_name(packet: &[u8], mut off: usize) -> Option<usize> {
    loop {
        let len = *packet.get(off)? as usize;
        if len == 0 {
            return Some(off + 1);
        }
        if len & 0xC0 == 0xC0 {
            // Two-byte pointer ends the name.
            packet.get(off + 1)?;
            return Some(off + 2);
        }
        if len & 0xC0 != 0 {
            return None; // reserved label type
        }
        off = off.checked_add(1 + len)?;
    }
}

/// One ANSWER-section record, minimally decoded. `owner` is `None` when the
/// record's owner name could not be decoded confidently — such a record can
/// never be attributed to the question and is therefore never accepted.
struct AnswerRr {
    owner: Option<String>,
    rtype: u16,
    rclass: u16,
    ttl: u32,
    rdata_start: usize,
    rdlen: usize,
}

/// Walk up to `ancount` ANSWER records starting at `off`. Returns what was
/// collected; any structural surprise stops the walk (never panics).
fn read_answer_records(packet: &[u8], mut off: usize, ancount: usize) -> Vec<AnswerRr> {
    let mut out = Vec::new();
    for _ in 0..ancount {
        let Some(after_name) = skip_encoded_name(packet, off) else {
            break;
        };
        // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) = 10 fixed octets.
        let Some(fixed) = packet.get(after_name..after_name + 10) else {
            break;
        };
        let rdlen = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        let rdata_start = after_name + 10;
        if packet.get(rdata_start..rdata_start + rdlen).is_none() {
            break;
        }
        out.push(AnswerRr {
            owner: decode_name(packet, off),
            rtype: u16::from_be_bytes([fixed[0], fixed[1]]),
            rclass: u16::from_be_bytes([fixed[2], fixed[3]]),
            ttl: u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]),
            rdata_start,
            rdlen,
        });
        off = rdata_start + rdlen;
    }
    out
}

/// The names an `A` record in this response may legitimately be an answer for:
/// the question name plus every target reachable from it through the response's
/// own `CNAME` records. Closed by iteration, so a server that emits the alias
/// after the address record is handled the same as one that emits it before.
fn answer_owner_closure(
    packet: &[u8],
    records: &[AnswerRr],
    qname: &str,
) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    names.insert(qname.to_string());
    // Every pass adds at least one link or stops; a chain cannot be longer than
    // the record count.
    for _ in 0..records.len() {
        let mut grew = false;
        for rr in records
            .iter()
            .filter(|r| r.rtype == QTYPE_CNAME && r.rclass == CLASS_IN)
        {
            let Some(owner) = rr.owner.as_deref() else {
                continue;
            };
            if !names.contains(owner) {
                continue;
            }
            if let Some(target) = decode_name(packet, rr.rdata_start) {
                grew |= names.insert(target);
            }
        }
        if !grew {
            break;
        }
    }
    names
}

/// Parse an upstream response to [`build_a_query`]`(expect_id, expect_qname)`.
///
/// Accepts an `A`/`IN` record only when its owner name is the question name or
/// a name reachable from it through the response's own `CNAME` chain. An
/// address record filed under an unrelated owner is dropped: it cannot be an
/// answer to this question, and accepting it would let an upstream (or an
/// off-path forgery that guessed id + question) place arbitrary addresses in
/// the enforcement set under someone else's name. Never panics on malformed
/// input — any structural surprise inside the answer section stops the walk and
/// returns what was collected.
pub fn parse_a_response(expect_id: u16, expect_qname: &str, packet: &[u8]) -> AResponseOutcome {
    if packet.len() < DNS_HEADER_LEN {
        return AResponseOutcome::Mismatch;
    }
    if u16::from_be_bytes([packet[0], packet[1]]) != expect_id {
        return AResponseOutcome::Mismatch;
    }
    if packet[2] & 0x80 == 0 {
        return AResponseOutcome::Mismatch; // QR=0 — a query, not a response
    }
    let Some(q) = parse_question(packet) else {
        return AResponseOutcome::Mismatch;
    };
    let expect = expect_qname
        .strip_suffix('.')
        .unwrap_or(expect_qname)
        .to_ascii_lowercase();
    if q.qname != expect || q.qtype != QTYPE_A {
        return AResponseOutcome::Mismatch;
    }
    if packet[2] & 0x02 != 0 {
        return AResponseOutcome::Truncated; // TC bit
    }
    let rcode = packet[3] & 0x0F;
    if rcode == RCODE_NXDOMAIN {
        return AResponseOutcome::NoRecords;
    }
    if rcode != 0 {
        return AResponseOutcome::Failed(rcode);
    }
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let records = read_answer_records(packet, q.question_end, ancount);
    let owners = answer_owner_closure(packet, &records, &q.qname);
    let mut addresses = Vec::new();
    let mut min_ttl = u32::MAX;
    let mut off_chain = 0usize;
    for rr in records
        .iter()
        .filter(|r| r.rtype == QTYPE_A && r.rclass == CLASS_IN && r.rdlen == 4)
    {
        if !rr.owner.as_deref().is_some_and(|o| owners.contains(o)) {
            off_chain += 1;
            continue;
        }
        let Some(rdata) = packet.get(rr.rdata_start..rr.rdata_start + 4) else {
            continue;
        };
        addresses.push(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
        min_ttl = min_ttl.min(rr.ttl);
    }
    if off_chain > 0 {
        tracing::debug!(
            target: "nrr::dns-resolver",
            host = %q.qname,
            off_chain,
            kept = addresses.len(),
            "dropped A records filed under an owner name the question's CNAME chain never reaches",
        );
    }
    if addresses.is_empty() {
        return AResponseOutcome::NoRecords;
    }
    AResponseOutcome::Answers {
        addresses,
        min_ttl: if min_ttl == u32::MAX { 0 } else { min_ttl },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    /// Craft a minimal query for `name`/`qtype` (RD set, one question).
    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&[0x12, 0x34]); // ID
        p.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
        p.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        p.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
        p.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        p.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
        for label in name.split('.') {
            p.push(label.len() as u8);
            p.extend_from_slice(label.as_bytes());
        }
        p.push(0); // root
        p.extend_from_slice(&qtype.to_be_bytes());
        p.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
        p
    }

    #[test]
    fn parses_a_question_name_and_type() {
        let q = parse_question(&query("chatgpt.com", QTYPE_A)).expect("parse");
        assert_eq!(q.qname, "chatgpt.com");
        assert_eq!(q.qtype, QTYPE_A);
        // header(12) + [7]chatgpt + [3]com + 0 + qtype(2) + qclass(2)
        assert_eq!(q.question_end, 12 + 8 + 4 + 1 + 4);
    }

    #[test]
    fn lowercases_name_and_reads_non_a_type() {
        let q = parse_question(&query("ChatGPT.COM", 28 /* AAAA */)).expect("parse");
        assert_eq!(q.qname, "chatgpt.com");
        assert_eq!(q.qtype, 28);
    }

    #[test]
    fn rejects_truncated_or_empty_packets() {
        assert!(parse_question(&[]).is_none());
        assert!(parse_question(&[0u8; 5]).is_none()); // shorter than header
                                                      // Header claims a question but the name is truncated.
        let mut p = query("a.b", QTYPE_A);
        p.truncate(14); // header + one length byte, no label bytes
        assert!(parse_question(&p).is_none());
    }

    #[test]
    fn rejects_compression_pointer_in_question() {
        let mut p = query("chatgpt.com", QTYPE_A);
        // Overwrite the first label length byte with a compression pointer.
        p[DNS_HEADER_LEN] = 0xC0;
        assert!(parse_question(&p).is_none());
    }

    #[test]
    fn builds_a_response_with_pointer_ttl_and_rdata() {
        let q = query("chatgpt.com", QTYPE_A);
        let resp = build_a_response(&q, &[ip(172, 64, 155, 209)], 60).expect("resp");
        // QR set, RA set, RCODE 0.
        assert_eq!(resp[2] & 0x80, 0x80, "QR bit");
        assert_eq!(resp[2] & 0x01, 0x01, "RD preserved");
        assert_eq!(resp[3] & 0x80, 0x80, "RA bit");
        assert_eq!(resp[3] & 0x0F, 0, "RCODE 0");
        // ANCOUNT = 1, NS/AR = 0.
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
        assert_eq!(&resp[8..12], &[0, 0, 0, 0]);
        // The answer RR is appended after the echoed question.
        let ans = &resp[q.len()..];
        assert_eq!(&ans[0..2], &[0xC0, 0x0C], "name pointer to question");
        assert_eq!(u16::from_be_bytes([ans[2], ans[3]]), QTYPE_A);
        assert_eq!(
            u32::from_be_bytes([ans[6], ans[7], ans[8], ans[9]]),
            60,
            "TTL"
        );
        assert_eq!(u16::from_be_bytes([ans[10], ans[11]]), 4, "RDLENGTH");
        assert_eq!(&ans[12..16], &[172, 64, 155, 209], "RDATA");
    }

    #[test]
    fn a_response_none_when_no_ips() {
        assert!(build_a_response(&query("x.com", QTYPE_A), &[], 60).is_none());
    }

    #[test]
    fn builds_nxdomain_error_response() {
        let q = query("nope.example", QTYPE_A);
        let resp = build_error_response(&q, RCODE_NXDOMAIN).expect("resp");
        assert_eq!(resp[2] & 0x80, 0x80, "QR");
        assert_eq!(resp[3] & 0x0F, RCODE_NXDOMAIN);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0, "no answers");
        assert_eq!(resp.len(), q.len(), "header + question only");
    }

    // ── Client side (HW-0714) ─────────────────────────────────────────────────

    #[test]
    fn a_query_round_trips_through_own_parser() {
        let q = build_a_query(0xBEEF, "chatgpt.com").expect("query");
        assert_eq!(u16::from_be_bytes([q[0], q[1]]), 0xBEEF, "id");
        assert_eq!(q[2] & 0x01, 0x01, "RD set");
        let parsed = parse_question(&q).expect("parse own query");
        assert_eq!(parsed.qname, "chatgpt.com");
        assert_eq!(parsed.qtype, QTYPE_A);
        // Trailing-dot FQDN encodes identically.
        assert_eq!(build_a_query(0xBEEF, "chatgpt.com.").expect("fqdn"), q);
    }

    #[test]
    fn a_query_rejects_unencodable_names() {
        assert!(build_a_query(1, "").is_none());
        assert!(build_a_query(1, "a..b").is_none(), "empty label");
        assert!(build_a_query(1, &"x".repeat(64)).is_none(), "label > 63");
        assert!(build_a_query(1, "приложение.ru").is_none(), "non-ASCII");
        let long = ["abcdefgh"; 32].join("."); // 8×32 + dots > 255
        assert!(build_a_query(1, &long).is_none(), "name > 255");
    }

    #[test]
    fn a_response_parses_answers_and_min_ttl() {
        let q = build_a_query(7, "chatgpt.com").expect("query");
        // Reuse the server-side builder, then rewrite the two answer TTLs to
        // differ so min-TTL selection is observable.
        let mut resp = build_a_response(&q, &[ip(1, 2, 3, 4), ip(5, 6, 7, 8)], 300).expect("resp");
        let ans2_ttl_at = parse_question(&q).expect("q").question_end + 16 + 6;
        resp[ans2_ttl_at..ans2_ttl_at + 4].copy_from_slice(&120u32.to_be_bytes());
        match parse_a_response(7, "chatgpt.com", &resp) {
            AResponseOutcome::Answers { addresses, min_ttl } => {
                assert_eq!(addresses, vec![ip(1, 2, 3, 4), ip(5, 6, 7, 8)]);
                assert_eq!(min_ttl, 120);
            }
            other => panic!("expected answers, got {other:?}"),
        }
    }

    #[test]
    fn a_response_skips_cname_and_collects_terminal_a() {
        // NOERROR answer: CNAME (uncompressed owner) then an A record.
        let q = build_a_query(9, "www.example.com").expect("query");
        let question_end = parse_question(&q).expect("q").question_end;
        let mut resp = q.clone();
        resp[2] = 0x80 | (resp[2] & 0x79); // QR=1
        resp[3] = 0x80; // RA, RCODE 0
        resp[6..8].copy_from_slice(&2u16.to_be_bytes()); // ANCOUNT=2
        assert_eq!(resp.len(), question_end);
        // CNAME RR: name→pointer, TYPE=5, CLASS=IN, TTL, RDLENGTH, target name.
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&5u16.to_be_bytes());
        resp.extend_from_slice(&[0x00, 0x01]);
        resp.extend_from_slice(&60u32.to_be_bytes());
        let target = {
            let mut t = Vec::new();
            for label in ["edge", "example", "com"] {
                t.push(label.len() as u8);
                t.extend_from_slice(label.as_bytes());
            }
            t.push(0);
            t
        };
        resp.extend_from_slice(&(target.len() as u16).to_be_bytes());
        resp.extend_from_slice(&target);
        // A RR owned by the CNAME target (uncompressed owner name).
        resp.extend_from_slice(&target);
        resp.extend_from_slice(&QTYPE_A.to_be_bytes());
        resp.extend_from_slice(&[0x00, 0x01]);
        resp.extend_from_slice(&45u32.to_be_bytes());
        resp.extend_from_slice(&[0x00, 0x04]);
        resp.extend_from_slice(&[9, 9, 9, 9]);
        match parse_a_response(9, "www.example.com", &resp) {
            AResponseOutcome::Answers { addresses, min_ttl } => {
                assert_eq!(addresses, vec![ip(9, 9, 9, 9)]);
                assert_eq!(min_ttl, 45, "CNAME TTL must not participate");
            }
            other => panic!("expected answers, got {other:?}"),
        }
    }

    /// Encode an uncompressed domain name (labels + root).
    fn encoded(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    /// Append one `A`/`IN` answer RR with an explicit owner-name encoding.
    fn push_a_rr(resp: &mut Vec<u8>, owner: &[u8], addr: Ipv4Addr, ttl: u32) {
        resp.extend_from_slice(owner);
        resp.extend_from_slice(&QTYPE_A.to_be_bytes());
        resp.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        resp.extend_from_slice(&ttl.to_be_bytes());
        resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
        resp.extend_from_slice(&addr.octets());
    }

    /// Start a NOERROR response frame for `query` with `ancount` answers.
    fn response_frame(query: &[u8], ancount: u16) -> Vec<u8> {
        let mut resp = query.to_vec();
        resp[2] = 0x80 | (resp[2] & 0x79); // QR=1
        resp[3] = 0x80; // RA, RCODE 0
        resp[6..8].copy_from_slice(&ancount.to_be_bytes());
        resp
    }

    /// An upstream (or an off-path forgery that guessed id + question) that
    /// appends `A` records filed under a DIFFERENT owner name must not get
    /// those addresses attributed to the question. Two unrelated hostnames
    /// answered with one identical address pair is exactly the shape this
    /// guards against.
    #[test]
    fn a_response_rejects_addresses_owned_by_an_unrelated_name() {
        let q = build_a_query(11, "signal.me").expect("query");
        let mut resp = response_frame(&q, 3);
        push_a_rr(&mut resp, &[0xC0, 0x0C], ip(76, 223, 92, 165), 300);
        push_a_rr(&mut resp, &encoded("chatgpt.com"), ip(8, 47, 69, 0), 300);
        push_a_rr(&mut resp, &encoded("chatgpt.com"), ip(8, 6, 112, 0), 300);
        match parse_a_response(11, "signal.me", &resp) {
            AResponseOutcome::Answers { addresses, .. } => {
                assert_eq!(
                    addresses,
                    vec![ip(76, 223, 92, 165)],
                    "only the question's own address survives"
                );
            }
            other => panic!("expected answers, got {other:?}"),
        }
    }

    /// When every address record belongs to a foreign owner nothing usable
    /// remains — surfaced as `NoRecords` so the caller's fallback (public
    /// resolvers) runs instead of the addresses being enforced.
    #[test]
    fn a_response_is_empty_when_every_address_is_off_chain() {
        let q = build_a_query(12, "signal.me").expect("query");
        let mut resp = response_frame(&q, 1);
        push_a_rr(&mut resp, &encoded("chatgpt.com"), ip(8, 47, 69, 0), 300);
        assert_eq!(
            parse_a_response(12, "signal.me", &resp),
            AResponseOutcome::NoRecords
        );
    }

    /// The alias may legally arrive AFTER the address it introduces; the owner
    /// closure is order-independent.
    #[test]
    fn a_response_accepts_a_record_preceding_its_cname() {
        let q = build_a_query(13, "www.example.com").expect("query");
        let mut resp = response_frame(&q, 2);
        push_a_rr(&mut resp, &encoded("edge.example.com"), ip(9, 9, 9, 9), 45);
        // CNAME www.example.com → edge.example.com, emitted last.
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&QTYPE_CNAME.to_be_bytes());
        resp.extend_from_slice(&[0x00, 0x01]);
        resp.extend_from_slice(&60u32.to_be_bytes());
        let target = encoded("edge.example.com");
        resp.extend_from_slice(&(target.len() as u16).to_be_bytes());
        resp.extend_from_slice(&target);
        match parse_a_response(13, "www.example.com", &resp) {
            AResponseOutcome::Answers { addresses, min_ttl } => {
                assert_eq!(addresses, vec![ip(9, 9, 9, 9)]);
                assert_eq!(min_ttl, 45);
            }
            other => panic!("expected answers, got {other:?}"),
        }
    }

    #[test]
    fn a_response_classifies_errors_and_mismatches() {
        let q = build_a_query(3, "x.example").expect("query");
        let nx = build_error_response(&q, RCODE_NXDOMAIN).expect("nx");
        assert_eq!(
            parse_a_response(3, "x.example", &nx),
            AResponseOutcome::NoRecords
        );
        let servfail = build_error_response(&q, RCODE_SERVFAIL).expect("sf");
        assert_eq!(
            parse_a_response(3, "x.example", &servfail),
            AResponseOutcome::Failed(RCODE_SERVFAIL)
        );
        // NOERROR + zero answers = authoritative empty.
        let empty = build_error_response(&q, 0).expect("empty");
        assert_eq!(
            parse_a_response(3, "x.example", &empty),
            AResponseOutcome::NoRecords
        );
        // Wrong id / wrong question / a query frame → Mismatch.
        let ok = build_a_response(&q, &[ip(1, 1, 1, 1)], 60).expect("ok");
        assert_eq!(
            parse_a_response(4, "x.example", &ok),
            AResponseOutcome::Mismatch
        );
        assert_eq!(
            parse_a_response(3, "y.example", &ok),
            AResponseOutcome::Mismatch
        );
        assert_eq!(
            parse_a_response(3, "x.example", &q),
            AResponseOutcome::Mismatch
        );
        // TC bit → Truncated.
        let mut tc = ok;
        tc[2] |= 0x02;
        assert_eq!(
            parse_a_response(3, "x.example", &tc),
            AResponseOutcome::Truncated
        );
    }

    // ── PTR / FCrDNS (HW-0719, killswitch-B) ──────────────────────────────────

    /// Append one PTR answer RR (owner = pointer to the question at 0x0C, RDATA =
    /// uncompressed target name) to a response being built.
    fn push_ptr_rr(resp: &mut Vec<u8>, target: &str, ttl: u32) {
        resp.extend_from_slice(&[0xC0, 0x0C]); // owner name → question
        resp.extend_from_slice(&QTYPE_PTR.to_be_bytes());
        resp.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        resp.extend_from_slice(&ttl.to_be_bytes());
        let mut rdata = Vec::new();
        for label in target.split('.') {
            rdata.push(label.len() as u8);
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0);
        resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        resp.extend_from_slice(&rdata);
    }

    /// Build a NOERROR PTR response for `ip` carrying the given target names.
    fn ptr_response(id: u16, ip: Ipv4Addr, targets: &[&str]) -> Vec<u8> {
        let q = build_ptr_query(id, ip).expect("ptr query");
        let mut resp = q.clone();
        resp[2] = 0x80; // QR=1, RD cleared (irrelevant)
        resp[3] = 0x80; // RA, RCODE 0
        resp[6..8].copy_from_slice(&(targets.len() as u16).to_be_bytes());
        for t in targets {
            push_ptr_rr(&mut resp, t, 3600);
        }
        resp
    }

    #[test]
    fn ptr_query_encodes_reversed_in_addr_arpa() {
        let q = build_ptr_query(0x1234, ip(8, 8, 4, 4)).expect("query");
        let parsed = parse_question(&q).expect("parse");
        assert_eq!(parsed.qname, "4.4.8.8.in-addr.arpa");
        assert_eq!(parsed.qtype, QTYPE_PTR);
        assert_eq!(u16::from_be_bytes([q[0], q[1]]), 0x1234);
        assert_eq!(q[2] & 0x01, 0x01, "RD set");
    }

    #[test]
    fn ptr_response_collects_target_names() {
        let resp = ptr_response(5, ip(93, 184, 216, 34), &["example.com", "www.example.com"]);
        match parse_ptr_response(5, ip(93, 184, 216, 34), &resp) {
            PtrResponseOutcome::Names(names) => {
                assert_eq!(names, vec!["example.com", "www.example.com"]);
            }
            other => panic!("expected names, got {other:?}"),
        }
    }

    #[test]
    fn ptr_response_decodes_compressed_rdata_name() {
        // RDATA target uses a compression pointer back into the question's
        // `in-addr.arpa` suffix — decode_name must follow it.
        let id = 6;
        let target_ip = ip(1, 2, 3, 4);
        let q = build_ptr_query(id, target_ip).expect("q");
        let mut resp = q.clone();
        resp[2] = 0x80;
        resp[3] = 0x80;
        resp[6..8].copy_from_slice(&1u16.to_be_bytes());
        // Owner → question pointer; RDATA = [4]host + pointer to "in-addr.arpa".
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&QTYPE_PTR.to_be_bytes());
        resp.extend_from_slice(&[0x00, 0x01]);
        resp.extend_from_slice(&3600u32.to_be_bytes());
        // Offset of "in-addr.arpa" inside the question: header(12) + labels for
        // "4.2.3.1" = 4 labels ("4","2","3","1") each 2 bytes = 8 → 12+8 = 20.
        let in_addr_off: u16 = 0x0C + 8;
        let mut rdata = Vec::new();
        rdata.push(4);
        rdata.extend_from_slice(b"host");
        rdata.extend_from_slice(&[0xC0, in_addr_off as u8]);
        resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        resp.extend_from_slice(&rdata);
        match parse_ptr_response(id, target_ip, &resp) {
            PtrResponseOutcome::Names(names) => assert_eq!(names, vec!["host.in-addr.arpa"]),
            other => panic!("expected compressed name, got {other:?}"),
        }
    }

    #[test]
    fn ptr_response_classifies_errors_and_mismatches() {
        let target_ip = ip(1, 1, 1, 1);
        let q = build_ptr_query(3, target_ip).expect("q");
        let nx = build_error_response(&q, RCODE_NXDOMAIN).expect("nx");
        assert_eq!(
            parse_ptr_response(3, target_ip, &nx),
            PtrResponseOutcome::NoRecords
        );
        let sf = build_error_response(&q, RCODE_SERVFAIL).expect("sf");
        assert_eq!(
            parse_ptr_response(3, target_ip, &sf),
            PtrResponseOutcome::Failed(RCODE_SERVFAIL)
        );
        // Wrong id, wrong IP → Mismatch.
        let ok = ptr_response(3, target_ip, &["a.example"]);
        assert_eq!(
            parse_ptr_response(4, target_ip, &ok),
            PtrResponseOutcome::Mismatch
        );
        assert_eq!(
            parse_ptr_response(3, ip(9, 9, 9, 9), &ok),
            PtrResponseOutcome::Mismatch
        );
        // TC → Truncated.
        let mut tc = ok;
        tc[2] |= 0x02;
        assert_eq!(
            parse_ptr_response(3, target_ip, &tc),
            PtrResponseOutcome::Truncated
        );
    }
}
