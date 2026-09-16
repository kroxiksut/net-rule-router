//! What a hostname's SHAPE says, before any traffic is counted.
//!
//! Two questions live here: which part of a name is the registrable domain,
//! and whether a name looks like delivery infrastructure, one machine, or a
//! document host. All pure and all cheap — they gate the ledger's work, so
//! anything expensive would be on the path of every observation.

use super::*;

// ── Registrable-domain heuristic ──────────────────────────────────────────────

/// Common multi-part public suffixes recognized by [`registrable_domain`].
///
/// This is a deliberately short, static HEURISTIC table of frequent two-label
/// public suffixes — it is NOT the Public Suffix List and does not try to be.
/// A miss only makes suffix generalization slightly less aggressive (the
/// engine falls back to exact-host proposals), never incorrect routing.
const MULTI_PART_PUBLIC_SUFFIXES: &[&str] = &[
    "ac.uk", "co.uk", "gov.uk", "org.uk", "co.jp", "ne.jp", "or.jp", "com.br", "com.au", "net.au",
    "org.au", "com.tr", "com.cn", "net.cn", "org.cn", "com.ua", "co.in", "co.kr", "co.za",
    "com.ar", "com.hk", "com.mx", "com.sg", "com.tw",
];

/// A suffix rule on `suffix` would route the anchor itself — the site whose
/// companions we are proposing. `*.x` covers `x`, so equality counts.
pub(super) fn covers_the_anchor(anchor: &str, suffix: &str) -> bool {
    anchor.eq_ignore_ascii_case(suffix) || is_under_suffix(anchor, suffix)
}

/// Whether generalizing to `*.apex` would also swallow the anchor itself.
///
/// One site under a corporate umbrella says nothing about the umbrella:
/// `aistudio.search.example` is evidence about itself, not about every host under
/// `search.example`. Generalizing there is only earned when the anchor IS the
/// apex (`ab.test` may speak for `*.ab.test`). A companion apex the anchor does
/// not live under — a CDN, say — is unaffected and still generalizes on its
/// own evidence.
pub(super) fn suffix_would_swallow_the_anchor(anchor: &str, apex: &str) -> bool {
    !anchor.eq_ignore_ascii_case(apex)
        && registrable_domain(anchor).is_some_and(|d| d.eq_ignore_ascii_case(apex))
}

/// `host` sits strictly below `suffix` (`ev-h.disk.example` under
/// `disk.example`), matching the label boundary rather than the raw bytes.
pub(super) fn is_under_suffix(host: &str, suffix: &str) -> bool {
    host.len() > suffix.len()
        && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
        && host[host.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

/// The deepest suffix that `min_members` of `hostnames` share, deeper than
/// `apex` and accepted by `accept`.
///
/// Used when the registrable domain is out of reach: a dozen fourth-level names
/// of one service is not a review list anybody reads, and the level they share
/// (`disk.example` under `example.md`) names that service exactly. Deeper is
/// narrower, so this can only propose LESS than the apex proposal it stands in
/// for. Deeper wins, then alphabetical, so the choice is deterministic.
pub(super) fn deepest_shared_suffix<'a>(
    hostnames: &[&'a str],
    apex: &str,
    min_members: usize,
    accept: impl Fn(&str) -> bool,
) -> Option<&'a str> {
    let apex_labels = apex.split('.').count();
    let mut members: BTreeMap<&'a str, usize> = BTreeMap::new();
    for host in hostnames {
        let mut candidate: &'a str = host;
        while let Some((_, parent)) = candidate.split_once('.') {
            candidate = parent;
            if candidate.split('.').count() <= apex_labels {
                break;
            }
            *members.entry(candidate).or_insert(0) += 1;
        }
    }
    members
        .into_iter()
        .filter(|&(suffix, count)| count >= min_members && accept(suffix))
        .max_by(|(a, _), (b, _)| {
            a.split('.')
                .count()
                .cmp(&b.split('.').count())
                .then_with(|| b.cmp(a))
        })
        .map(|(suffix, _)| suffix)
}

/// Extracts the registrable domain of a hostname using a documented heuristic:
/// the last two labels, or the last three when the last two form a known
/// multi-part public suffix (see [`MULTI_PART_PUBLIC_SUFFIXES`]).
///
/// Returns `None` when no registrable domain can be extracted: single-label
/// hosts (`localhost`, intranet flat names) and hostnames that consist of a
/// bare multi-part suffix (`co.uk`). The suffix-table comparison is
/// ASCII-case-insensitive; the returned slice borrows from the input
/// unchanged.
///
/// This is a heuristic, not a Public Suffix List implementation — see the
/// table's documentation for the failure mode (strictly less generalization).
pub fn registrable_domain(hostname: &str) -> Option<&str> {
    let mut dots = hostname.rmatch_indices('.').map(|(i, _)| i);
    // Index of the dot preceding the last label; `None` => single label.
    dots.next()?;
    let second_dot = dots.next();
    let last_two = second_dot.map_or(hostname, |i| &hostname[i + 1..]);
    let is_multi_part = MULTI_PART_PUBLIC_SUFFIXES
        .iter()
        .any(|s| s.eq_ignore_ascii_case(last_two));
    if !is_multi_part {
        return Some(last_two);
    }
    // The last two labels are a public suffix: the registrable domain is the
    // last THREE labels — absent a third label there is nothing registrable.
    let second_dot = second_dot?;
    if let Some(third_dot) = dots.next() {
        return Some(&hostname[third_dot + 1..]);
    }
    // Exactly three labels: the whole hostname is the registrable domain,
    // unless a leading dot makes the first label empty (malformed input).
    if second_dot == 0 {
        return None;
    }
    Some(hostname)
}

// ── Name-shape signals ────────────────────────────────────────────────────────

/// Shortest brand token accepted for a substring relation.
///
/// Below this, containment is coincidence rather than branding: three-letter
/// tokens (`ab`, `ok`, `mts`) appear inside unrelated words constantly.
const MIN_BRAND_TOKEN_LEN: usize = 4;

/// Substrings that mark a hostname as a delivery endpoint rather than a site.
///
/// Deliberately a short, human-auditable list of the words operators actually
/// put in delivery hostnames. It is a WEAK signal on purpose — advertising and
/// telemetry endpoints match it just as well — which is why the tier using it
/// also demands temporal evidence.
pub const DELIVERY_NAME_MASKS: &[&str] = &[
    "cdn", "static", "cache", "edge", "media", "img", "video", "stream", "assets", "content",
];

/// The first label of the registrable domain — the token that carries the
/// brand (`static.chatapp.test` -> `chatapp`, `login.ab.test` -> `ab`).
pub(super) fn brand_token(hostname: &str) -> &str {
    registrable_domain(hostname)
        .unwrap_or(hostname)
        .split('.')
        .next()
        .unwrap_or(hostname)
}

/// The candidate carries the anchor's brand, or the anchor carries the
/// candidate's: `web.chatapp.example` and `static.chatapp.test`, `ab.example` and
/// `login.ab.test`, `tiktok.com` and `tiktokv.com`, `feed.example` and
/// `static.feedinfra.example`.
///
/// Containment (not equality) is what catches the last two shapes: operators
/// register adjacent brands rather than reusing the exact one. Every label of
/// the hostname is searched, so a brand appearing in a deeper label still counts.
pub(super) fn is_brand_related(anchor: &str, candidate: &str) -> bool {
    brand_relation(anchor, candidate) != BrandRelation::None
}

/// What a shared brand is worth as evidence.
///
/// The equality branch has no length floor, and it must not get one: `ab.example`
/// and `login.ab.test` are kin precisely because their token matches exactly,
/// and `ab` is below the length containment demands. But the same branch makes
/// `q.test`/`q.example`, `x.com`/`x.ai` and `ok.ru`/`ok.com` kin as well, and a token
/// that short is one registrar away from coincidence. So the relation stands
/// and its REACH does not: weak evidence buys the exact host, never the apex.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum BrandRelation {
    None,
    /// Equal tokens, too short for the containment branch to have accepted them.
    ShortToken,
    /// A token long enough to name an operator rather than collide with one.
    Named,
}

pub(super) fn brand_relation(anchor: &str, candidate: &str) -> BrandRelation {
    let (anchor_brand, candidate_brand) = (brand_token(anchor), brand_token(candidate));
    if anchor_brand == candidate_brand {
        return if anchor_brand.len() >= MIN_BRAND_TOKEN_LEN {
            BrandRelation::Named
        } else {
            BrandRelation::ShortToken
        };
    }
    if carries_brand(candidate, anchor_brand) || carries_brand(anchor, candidate_brand) {
        BrandRelation::Named
    } else {
        BrandRelation::None
    }
}

/// Whether `name` carries `brand` as a label, a label's prefix, or a label's
/// suffix — the shapes branding actually takes (`feedinfra`, `tiktokv`,
/// `cdninsta`).
///
/// Anchored on purpose. A brand found anywhere INSIDE a label is a collision,
/// not a relation: `istu` sits in the middle of `aistudio`, and reading that as
/// kinship proposed an unrelated domain as a companion of the AI studio host.
///
/// Only the REGISTRABLE domain is searched. A brand sitting in a subdomain of
/// somebody else's apex names the customer, not the owner: `mozilla.map.fastly.net`
/// is a Fastly machine, and treating it as kin proposed moving all of
/// `mozilla.org` onto the additional link. Ownership shapes survive, because
/// they put the brand in the registrable domain itself (`feedinfra.example`,
/// `githubusercontent.com`).
pub(super) fn carries_brand(name: &str, brand: &str) -> bool {
    brand.len() >= MIN_BRAND_TOKEN_LEN
        && registrable_domain(name)
            .unwrap_or(name)
            .split(['.', '-'])
            .any(|label| label.starts_with(brand) || label.ends_with(brand))
}

/// An explicit shard marker: `rr5---sn-ajaig5-5a.videocdn.test` and friends.
///
/// Only this literal, unmistakable form is recognized. A structural rule for
/// short alphanumeric labels (`s07.`, `p13.`) was measured and rejected: it
/// matches ordinary infrastructure such as software-update endpoints and floods
/// the review list with traffic that belongs on no site's route.
pub(super) fn is_sharded_delivery_label(hostname: &str) -> bool {
    let first_label = hostname.split('.').next().unwrap_or("");
    let Some((prefix, _)) = first_label.split_once("---sn-") else {
        return false;
    };
    !prefix.is_empty()
        && prefix.chars().all(|c| c.is_ascii_alphanumeric())
        && prefix.chars().any(|c| c.is_ascii_digit())
}

/// The hostname spells out an IPv4 address, so it names one machine rather
/// than a service: `a23-45-67-89.deploy.static.akamaitechnologies.com`,
/// `ec2-18-97-36-79.compute-1.amazonaws.com`, `140.206.0.34.bc.googleusercontent.com`.
///
/// These reach the ledger through the reverse-lookup learner, which exists to
/// name companions the DNS path never sees (browser cache, DoH). What it can
/// name, though, is the machine that answers at an address — never the service
/// the application asked for. Treating one as a companion proposes its shared
/// infrastructure apex for the tunnel, which is a rule over somebody else's
/// traffic.
pub(super) fn names_one_machine(hostname: &str) -> bool {
    // The leading octet often wears a prefix (`a23-`, `ec2-`), so a token is
    // read as its trailing digits. Demanding that three of the four be bare
    // numbers keeps ordinary names such as `a1-b2-c3-d4` out.
    let octet_of = |token: &str| -> Option<bool> {
        let digits = token.trim_start_matches(|c: char| c.is_ascii_alphabetic());
        let prefix = &token[..token.len() - digits.len()];
        (!digits.is_empty()
            && digits.len() <= 3
            && digits.bytes().all(|b| b.is_ascii_digit())
            && digits.parse::<u16>().is_ok_and(|n| n <= 255))
        .then_some(prefix.is_empty())
    };
    let mut run = 0_u8;
    let mut bare = 0_u8;
    for token in hostname.split(['.', '-']) {
        match octet_of(token) {
            Some(is_bare) => {
                run += 1;
                bare += u8::from(is_bare);
                if run >= 4 && bare >= 3 {
                    return true;
                }
            }
            None => {
                run = 0;
                bare = 0;
            }
        }
    }
    false
}

/// The hostname looks like a delivery endpoint (see [`DELIVERY_NAME_MASKS`]).
pub(super) fn is_delivery_named(hostname: &str) -> bool {
    DELIVERY_NAME_MASKS.iter().any(|m| hostname.contains(m)) || is_sharded_delivery_label(hostname)
}

/// The hostname looks like a PAGE rather than an endpoint a page fetches from:
/// the registrable apex itself or its `www.` form, and not delivery-named.
///
/// Used to answer "under whose page did this load?" — see
/// [`CompanionAffinityLedger::document_disowns`].
pub(super) fn is_document_shaped(hostname: &str) -> bool {
    if is_delivery_named(hostname) || names_one_machine(hostname) {
        return false;
    }
    match registrable_domain(hostname) {
        Some(apex) => hostname == apex || hostname.strip_prefix("www.") == Some(apex),
        None => false,
    }
}

/// Whether two hostnames belong to the same site — same registrable domain, or
/// related by brand (one operator, several domains).
pub(super) fn same_site(a: &str, b: &str) -> bool {
    if registrable_domain(a).is_some() && registrable_domain(a) == registrable_domain(b) {
        return true;
    }
    is_brand_related(a, b)
}
