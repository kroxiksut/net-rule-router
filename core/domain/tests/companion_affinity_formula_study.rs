//! Offline study of companion-affinity scoring formulas against a synthetic DNS trace.
//!
//! This test changes no production behaviour. It replays
//! `tests/fixtures/companion_affinity_trace.csv` — a synthetic trace shaped to mirror a
//! real browsing session — through several candidate scoring rules and reports, for each
//! rule and threshold, how many proposals it would emit and how many of them are real
//! companions of the anchor versus unrelated background traffic. Every hostname in the
//! fixtures is a fictitious placeholder under an RFC 2606 reserved TLD
//! (`.example` / `.test` / `.invalid`); none resolves to a real service, and none of the
//! structure below identifies which real sites (if any) originally shaped the timings.
//!
//! Run it with output:
//!
//! ```text
//! cargo test -p nrr-domain --test companion_affinity_formula_study -- --nocapture
//! ```
//!
//! ## Why the trace is shaped the way it is
//!
//! The trace holds hostnames and timings only. Anchor membership is a property of the
//! rule book, so this file declares it: [`ANCHORS`] is the set of site hostnames the user
//! actually browsed during the run. Everything else observed is a candidate. That models
//! the product situation directly — the user has rules for the sites they care about, and
//! the engine has to discover those sites' companion hostnames.
//!
//! ## What is being measured
//!
//! A proposal is *good* when the candidate really belongs to the anchor's site
//! ([`GROUND_TRUTH`]), *ambiguous* when it is shared platform infrastructure whose routing
//! is a judgement call ([`AMBIGUOUS`]), and *bad* otherwise — telemetry, software
//! updaters, and unrelated sites the user happened to have open. False positives are the
//! expensive error: an accepted proposal moves traffic onto another route.

use std::collections::{BTreeMap, BTreeSet};

use nrr_domain::companion_affinity::{
    CoActivityKind, CompanionAffinityLedger, CompanionSignal, NoExclusions, ProposedCompanionMatch,
};
use nrr_shared::RouteRole;

// ── Fixture ───────────────────────────────────────────────────────────────────

const TRACE: &str = include_str!("fixtures/companion_affinity_trace.csv");
const TRACE_RAW: &str = include_str!("fixtures/companion_affinity_trace_raw.csv");

/// Window parameters currently shipped by `companion_affinity`.
const WINDOW_MS: u64 = 15_000;
const MAX_WINDOW_MS: u64 = 60_000;

/// Site hostnames the user browsed during the run — the rule book for this study.
///
/// Fictitious placeholders (RFC 2606 reserved TLDs); the `anchor-<letter>` labels are
/// structural role codes, not brand names — they carry no information about which real
/// sites (if any) originally shaped this trace's timings.
const ANCHORS: &[&str] = &[
    "anchor-a.example",
    "anchorb.example",
    "anchor-c.example",
    "anchord.example",
    "anchor-e.example",
    "web.anchor-f.example",
    "www.anchor-g.example",
    "www.anchor-h.example",
    "www.anchor-i.example",
    "www.anchor-j.example",
    "www.anchor-k.example",
    "www.anchor-l.example",
    "www.anchor-m.example",
    "www.anchor-n.example",
    "anchor-o.example",
];

/// `candidate -> anchors it genuinely belongs to`.
const GROUND_TRUTH: &[(&str, &[&str])] = &[
    ("a.background-108.example", &["www.anchor-l.example"]),
    (
        "acollector.background-108.example",
        &["www.anchor-l.example"],
    ),
    ("antibot.anchor-l.example", &["www.anchor-l.example"]),
    ("api.anchor-e.example", &["anchor-e.example"]),
    ("avatars.anchorbx.example", &["anchorb.example"]),
    ("bot.anchor-i.example", &["www.anchor-i.example"]),
    (
        "cdn.cdn-g1.example",
        &["www.anchor-g.example", "www.anchor-j.example"],
    ),
    ("cdn.cdn-a.example", &["anchor-a.example"]),
    ("cdn.cdn-l1.example", &["www.anchor-l.example"]),
    ("crashlogs.anchor-f.test", &["web.anchor-f.example"]),
    (
        "cdn-g2.example",
        &["www.anchor-g.example", "www.anchor-j.example"],
    ),
    ("alt-i1.example", &["www.anchor-i.example"]),
    ("i.anchor-k.example", &["www.anchor-k.example"]),
    ("i.img-n1.example", &["www.anchor-n.example"]),
    ("id.anchor-e.example", &["anchor-e.example"]),
    ("login.anchor-e.test", &["anchor-e.example"]),
    ("login.anchor-e.example", &["anchor-e.example"]),
    ("alt-d1.test", &["anchord.example"]),
    (
        "rr2---sn-q4flrn7k.cdn-n1.example",
        &["www.anchor-n.example"],
    ),
    (
        "rr5---sn-5hne6nzd.cdn-n1.example",
        &["www.anchor-n.example"],
    ),
    (
        "rr5---sn-ajaig5-5a.cdn-n1.example",
        &["www.anchor-n.example"],
    ),
    (
        "rr5---sn-u15hn5-5t.cdn-n1.example",
        &["www.anchor-n.example"],
    ),
    ("rt.anchor-k.example", &["www.anchor-k.example"]),
    ("sso.anchorb.example", &["anchorb.example"]),
    ("static.anchorbx.example", &["anchorb.example"]),
    ("static.anchor-e.example", &["anchor-e.example"]),
    ("static.anchor-f.test", &["web.anchor-f.example"]),
    ("suggest.sso.anchorb.example", &["anchorb.example"]),
    ("suggest-svc.anchor-n.example", &["www.anchor-n.example"]),
    ("alt-o1.test", &["anchor-o.example"]),
    ("anchordx.example", &["anchord.example"]),
    ("alt-o2.example", &["anchor-o.example"]),
    ("alt-c1.test", &["anchor-c.example"]),
    ("anchor-m.example", &["www.anchor-m.example"]),
    ("anchor-n.example", &["www.anchor-n.example"]),
];

/// Shared platform infrastructure — routing it with any single site is defensible either
/// way, so it is scored separately and never counted as a win or as a defect.
const AMBIGUOUS: &[&str] = &[
    "avatars.mds.shared-a.example",
    "cloud-api.shared-a.example",
    "csp.shared-a.example",
    "favicon.shared-a.example",
    "imap.shared-a.test",
    "shared-b.example",
    "sso.passport.shared-a.invalid",
    "static-mon.shared-a.example",
];

// ── Trace replay ──────────────────────────────────────────────────────────────

fn parse(trace: &str) -> Vec<(u64, String)> {
    trace
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("offset_ms"))
        .filter_map(|l| {
            let (ms, host) = l.split_once(',')?;
            Some((ms.parse().ok()?, host.to_string()))
        })
        .collect()
}

/// Everything any of the studied formulas needs about one (anchor, candidate) pair.
#[derive(Clone, Debug)]
struct Pair {
    anchor: String,
    candidate: String,
    /// Distinct windows of this anchor the candidate was seen in.
    windows: u32,
    /// Windows this anchor opened in total.
    anchor_windows: u32,
    /// Distinct co-activity episodes of the candidate (counted once per moment,
    /// independently of how many anchor windows were open).
    episodes: u32,
    /// Sum of `windows` over every anchor this candidate ever met — the denominator the
    /// shipped formula uses.
    all_windows: u32,
    /// Observations where this anchor was the most recently active open window.
    nearest_hits: u32,
    /// Observations of this candidate that had any open window at all.
    total_hits: u32,
}

impl Pair {
    /// (a) shipped formula: `distinct_windows / total_windows`.
    fn baseline(&self) -> f64 {
        f64::from(self.windows) / f64::from(self.all_windows)
    }
    /// (b) denominator = co-activity episodes, so simultaneity no longer dilutes.
    fn episode(&self) -> f64 {
        (f64::from(self.windows) / f64::from(self.episodes.max(1))).min(1.0)
    }
    /// (d) share of observations for which this anchor was the nearest open window.
    fn nearest_share(&self) -> f64 {
        f64::from(self.nearest_hits) / f64::from(self.total_hits.max(1))
    }
    /// Fraction of the anchor's own windows in which the candidate appeared.
    fn coverage(&self) -> f64 {
        f64::from(self.windows) / f64::from(self.anchor_windows.max(1))
    }
}

fn replay(events: &[(u64, String)], anchors: &BTreeSet<String>) -> Vec<Pair> {
    struct Anchor {
        window_id: u64,
        start: u64,
        end: u64,
        last: u64,
        opened: u32,
    }
    let mut live: BTreeMap<String, Anchor> = BTreeMap::new();
    let mut next_window = 0_u64;
    let mut pair_windows: BTreeMap<(String, String), BTreeSet<u64>> = BTreeMap::new();
    let mut nearest: BTreeMap<(String, String), u32> = BTreeMap::new();
    let mut hits: BTreeMap<String, u32> = BTreeMap::new();
    let mut episodes: BTreeMap<String, u32> = BTreeMap::new();
    let mut last_signature: BTreeMap<String, Vec<u64>> = BTreeMap::new();

    for (at, host) in events {
        if anchors.contains(host) {
            match live.get_mut(host) {
                Some(a) if *at <= a.end => {
                    a.end = a.end.max(at + WINDOW_MS).min(a.start + MAX_WINDOW_MS);
                    a.last = *at;
                }
                Some(a) => {
                    a.window_id = next_window;
                    next_window += 1;
                    a.start = *at;
                    a.end = at + WINDOW_MS;
                    a.last = *at;
                    a.opened += 1;
                }
                None => {
                    live.insert(
                        host.clone(),
                        Anchor {
                            window_id: next_window,
                            start: *at,
                            end: at + WINDOW_MS,
                            last: *at,
                            opened: 1,
                        },
                    );
                    next_window += 1;
                }
            }
            continue;
        }
        let open: Vec<(&String, u64, u64)> = live
            .iter()
            .filter(|(_, a)| a.start <= *at && *at <= a.end)
            .map(|(n, a)| (n, a.window_id, a.last))
            .collect();
        if open.is_empty() {
            continue;
        }
        *hits.entry(host.clone()).or_default() += 1;
        let signature: Vec<u64> = open.iter().map(|(_, w, _)| *w).collect();
        if last_signature.get(host) != Some(&signature) {
            *episodes.entry(host.clone()).or_default() += 1;
            last_signature.insert(host.clone(), signature);
        }
        // "Nearest" = the anchor whose window saw activity most recently; name order
        // breaks ties so the result is deterministic.
        let nearest_anchor = open
            .iter()
            .max_by(|a, b| a.2.cmp(&b.2).then_with(|| a.0.cmp(b.0)))
            .map(|(n, _, _)| (*n).clone());
        if let Some(n) = nearest_anchor {
            *nearest.entry((n, host.clone())).or_default() += 1;
        }
        for (name, window_id, _) in open {
            pair_windows
                .entry((name.clone(), host.clone()))
                .or_default()
                .insert(window_id);
        }
    }

    let mut per_candidate: BTreeMap<String, u32> = BTreeMap::new();
    for ((_, c), w) in &pair_windows {
        *per_candidate.entry(c.clone()).or_default() += w.len() as u32;
    }
    pair_windows
        .iter()
        .map(|((a, c), w)| Pair {
            anchor: a.clone(),
            candidate: c.clone(),
            windows: w.len() as u32,
            anchor_windows: live.get(a).map_or(1, |x| x.opened),
            episodes: episodes.get(c).copied().unwrap_or(1),
            all_windows: per_candidate.get(c).copied().unwrap_or(1),
            nearest_hits: nearest.get(&(a.clone(), c.clone())).copied().unwrap_or(0),
            total_hits: hits.get(c).copied().unwrap_or(1),
        })
        .collect()
}

// ── Name-shape signals ────────────────────────────────────────────────────────

fn registrable(host: &str) -> &str {
    let mut dots = host.rmatch_indices('.').map(|(i, _)| i);
    dots.next();
    dots.next().map_or(host, |i| &host[i + 1..])
}

fn brand(host: &str) -> &str {
    registrable(host).split('.').next().unwrap_or(host)
}

/// The candidate carries the anchor's brand token, or the anchor carries the candidate's:
/// a same-brand host under a different TLD, or a sibling label built on the anchor's own
/// brand token as a prefix.
fn brand_related(anchor: &str, candidate: &str) -> bool {
    let (a, c) = (brand(anchor), brand(candidate));
    if a == c {
        return true;
    }
    (a.len() >= 4 && (c.contains(a) || candidate.contains(a)))
        || (c.len() >= 4 && (a.contains(c) || anchor.contains(c)))
}

/// Substrings that mark a hostname as a delivery endpoint rather than a site.
const CDN_MASKS: &[&str] = &[
    "cdn", "static", "cache", "edge", "media", "img", "video", "stream", "assets", "content",
];

/// `rr5---sn-ajaig5-5a.cdn-n1.example` and friends: a sharded delivery label.
fn sharded_label(host: &str) -> bool {
    let first = host.split('.').next().unwrap_or("");
    let Some(rest) = first.split_once("---sn-") else {
        return false;
    };
    !rest.0.is_empty()
        && rest.0.chars().all(|c| c.is_ascii_alphanumeric())
        && rest.0.chars().any(|c| c.is_ascii_digit())
}

fn cdn_named(host: &str) -> bool {
    CDN_MASKS.iter().any(|m| host.contains(m)) || sharded_label(host)
}

/// The literal form of the user's hypothesis: also treat any short alphanumeric label
/// (`s07.`, `p13.`) as a shard marker. Measured below — it is strictly harmful.
fn cdn_named_loose(host: &str) -> bool {
    if cdn_named(host) {
        return true;
    }
    host.split('.').any(|l| {
        (2..=5).contains(&l.len())
            && l.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && l.chars().any(|c| c.is_ascii_digit())
            && l.chars().all(|c| c.is_ascii_alphanumeric())
    })
}

// ── Scoring ───────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Verdict {
    Good,
    Bad,
    Ambiguous,
}

fn verdict(anchor: &str, candidate: &str) -> Verdict {
    if AMBIGUOUS.contains(&candidate) {
        return Verdict::Ambiguous;
    }
    match GROUND_TRUTH.iter().find(|(c, _)| *c == candidate) {
        Some((_, anchors)) if anchors.contains(&anchor) => Verdict::Good,
        _ => Verdict::Bad,
    }
}

#[derive(Default, Clone, Copy)]
struct Score {
    total: usize,
    good: usize,
    bad: usize,
    ambiguous: usize,
}

impl Score {
    fn of<'a>(pairs: impl Iterator<Item = &'a Pair>) -> Self {
        let mut s = Self::default();
        for p in pairs {
            s.total += 1;
            match verdict(&p.anchor, &p.candidate) {
                Verdict::Good => s.good += 1,
                Verdict::Bad => s.bad += 1,
                Verdict::Ambiguous => s.ambiguous += 1,
            }
        }
        s
    }
    fn precision(&self) -> String {
        if self.good + self.bad == 0 {
            "  -  ".to_string()
        } else {
            format!("{:.2} ", self.good as f64 / (self.good + self.bad) as f64)
        }
    }
}

fn row(label: &str, s: Score) {
    println!(
        "{label:<52} {:>5} {:>6} {:>5} {:>5}   {}",
        s.total,
        s.good,
        s.bad,
        s.ambiguous,
        s.precision()
    );
}

fn header(title: &str) {
    println!("\n{title}");
    println!(
        "{:<52} {:>5} {:>6} {:>5} {:>5}   prec",
        "variant / threshold", "prop", "good", "bad", "amb"
    );
}

/// The rule this study recommends: a name-related candidate needs only co-activity
/// evidence; a delivery-shaped name needs the anchor to dominate its attributions over at
/// least two windows; anything else is not proposed at all.
fn recommended(p: &Pair) -> bool {
    brand_related(&p.anchor, &p.candidate)
        || (cdn_named(&p.candidate) && p.windows >= 2 && p.nearest_share() >= 0.6)
}

// ── The study ─────────────────────────────────────────────────────────────────

#[test]
fn companion_affinity_formula_study() {
    let anchors: BTreeSet<String> = ANCHORS.iter().map(|s| (*s).to_string()).collect();
    let events = parse(TRACE);
    let pairs = replay(&events, &anchors);

    let good_total = pairs
        .iter()
        .filter(|p| verdict(&p.anchor, &p.candidate) == Verdict::Good)
        .count();
    println!(
        "\ntrace: {} events, {} anchors, {} candidates, {} observed (anchor,candidate) pairs, \
         {} of them genuine",
        events.len(),
        anchors.len(),
        pairs
            .iter()
            .map(|p| &p.candidate)
            .collect::<BTreeSet<_>>()
            .len(),
        pairs.len(),
        good_total,
    );

    header("A. scoring formulas, minimum 2 distinct windows (as shipped)");
    for th in [0.8, 0.6, 0.5, 0.4] {
        row(
            &format!("(a) shipped   n/total_windows  >= {th:.2}"),
            Score::of(
                pairs
                    .iter()
                    .filter(|p| p.windows >= 2 && p.baseline() >= th),
            ),
        );
    }
    for th in [1.0, 0.8, 0.6, 0.5] {
        row(
            &format!("(b) episode   n/episodes       >= {th:.2}"),
            Score::of(pairs.iter().filter(|p| p.windows >= 2 && p.episode() >= th)),
        );
    }
    for ratio in [3.0, 2.0, 1.5] {
        // (c) dominance: the leading anchor must beat the runner-up by `ratio`.
        let mut by_candidate: BTreeMap<&str, Vec<&Pair>> = BTreeMap::new();
        for p in &pairs {
            by_candidate.entry(&p.candidate).or_default().push(p);
        }
        let selected: Vec<&Pair> = by_candidate
            .values()
            .filter_map(|group| {
                let mut g = group.clone();
                g.sort_by(|a, b| {
                    b.windows
                        .cmp(&a.windows)
                        .then_with(|| a.anchor.cmp(&b.anchor))
                });
                let lead = g[0];
                let second = g.get(1).map_or(0, |p| p.windows);
                let dominant = second == 0 || f64::from(lead.windows) / f64::from(second) >= ratio;
                (lead.windows >= 2 && dominant).then_some(lead)
            })
            .collect();
        row(
            &format!("(c) dominance lead/runner-up    >= {ratio:.1}"),
            Score::of(selected.into_iter()),
        );
    }
    for th in [1.0, 0.8, 0.6, 0.5] {
        row(
            &format!("(d) nearest   nearest-share     >= {th:.2}"),
            Score::of(
                pairs
                    .iter()
                    .filter(|p| p.windows >= 2 && p.nearest_share() >= th),
            ),
        );
    }
    for th in [0.9, 0.6, 0.5, 0.4] {
        row(
            &format!("(e) coverage  windows/anchor_w  >= {th:.2}"),
            Score::of(
                pairs
                    .iter()
                    .filter(|p| p.windows >= 2 && p.coverage() >= th),
            ),
        );
    }

    header("B. name-shape signals alone, no temporal threshold at all");
    row(
        "brand-related name",
        Score::of(
            pairs
                .iter()
                .filter(|p| brand_related(&p.anchor, &p.candidate)),
        ),
    );
    row(
        "delivery-shaped name (mask list + ---sn- shard)",
        Score::of(pairs.iter().filter(|p| cdn_named(&p.candidate))),
    );
    row(
        "delivery-shaped name (+ loose `s07.`-style shard)",
        Score::of(pairs.iter().filter(|p| cdn_named_loose(&p.candidate))),
    );
    row(
        "no name signal, only 2+ windows",
        Score::of(pairs.iter().filter(|p| p.windows >= 2)),
    );

    header("C. delivery-shaped names gated by co-activity");
    for (th, minw) in [(1.0, 1), (0.8, 1), (0.6, 1), (0.8, 2), (0.6, 2), (0.5, 2)] {
        row(
            &format!("cdn-named & nearest-share >= {th:.2} & n >= {minw}"),
            Score::of(pairs.iter().filter(|p| {
                cdn_named(&p.candidate) && p.windows >= minw && p.nearest_share() >= th
            })),
        );
    }
    for (th, minw) in [(1.0, 1), (0.6, 1), (0.6, 2)] {
        row(
            &format!("loose-shard & nearest-share >= {th:.2} & n >= {minw}"),
            Score::of(pairs.iter().filter(|p| {
                cdn_named_loose(&p.candidate) && p.windows >= minw && p.nearest_share() >= th
            })),
        );
    }

    header("D. recommended two-tier rule");
    row(
        "T1 brand-related (any evidence) | T2 cdn n>=2 share>=0.6",
        Score::of(pairs.iter().filter(|p| recommended(p))),
    );
    println!("\n   proposals it emits:");
    for p in pairs.iter().filter(|p| recommended(p)) {
        println!(
            "     {:<10?} n={} anchor_windows={} episodes={} share={:.2}  {:<22} <- {}",
            verdict(&p.anchor, &p.candidate),
            p.windows,
            p.anchor_windows,
            p.episodes,
            p.nearest_share(),
            p.anchor,
            p.candidate
        );
    }
    println!("\n   genuine companions it does NOT reach (recall cost):");
    for p in pairs
        .iter()
        .filter(|p| verdict(&p.anchor, &p.candidate) == Verdict::Good && !recommended(p))
    {
        println!(
            "     n={} anchor_windows={} episodes={} share={:.2} brand={} cdn={}  {:<22} <- {}",
            p.windows,
            p.anchor_windows,
            p.episodes,
            p.nearest_share(),
            u8::from(brand_related(&p.anchor, &p.candidate)),
            u8::from(cdn_named(&p.candidate)),
            p.anchor,
            p.candidate
        );
    }

    header("E. robustness: unfiltered trace (seeder bursts included, never seen in production)");
    // A hostname that appears in the unfiltered trace but never in the user-driven one is
    // by construction a concrete rule hostname the seeder resolved. Production suppresses
    // exactly those through `CandidateExclusions::is_matched_by_existing_rule`, so the
    // robustness run applies the same exclusion instead of pretending it does not exist.
    let raw_events = parse(TRACE_RAW);
    let user_hosts: BTreeSet<&str> = events.iter().map(|(_, h)| h.as_str()).collect();
    let excluded: BTreeSet<&str> = raw_events
        .iter()
        .map(|(_, h)| h.as_str())
        .filter(|h| !user_hosts.contains(h))
        .collect();
    let raw_pairs: Vec<Pair> = replay(&raw_events, &anchors)
        .into_iter()
        .filter(|p| !excluded.contains(p.candidate.as_str()))
        .collect();
    row(
        "(a) shipped   n/total_windows  >= 0.80, n >= 2",
        Score::of(
            raw_pairs
                .iter()
                .filter(|p| p.windows >= 2 && p.baseline() >= 0.8),
        ),
    );
    row(
        "(b) episode   n/episodes       >= 0.80, n >= 2",
        Score::of(
            raw_pairs
                .iter()
                .filter(|p| p.windows >= 2 && p.episode() >= 0.8),
        ),
    );
    row(
        "recommended two-tier",
        Score::of(raw_pairs.iter().filter(|p| recommended(p))),
    );

    // ── Regression pins on the headline numbers ──────────────────────────────
    let shipped = Score::of(
        pairs
            .iter()
            .filter(|p| p.windows >= 2 && p.baseline() >= 0.8),
    );
    assert_eq!(
        shipped.total, 0,
        "the shipped 0.8 threshold must still be shown to emit nothing on this trace"
    );
    let episode = Score::of(
        pairs
            .iter()
            .filter(|p| p.windows >= 2 && p.episode() >= 0.8),
    );
    assert!(
        episode.bad > episode.good * 5,
        "the episode denominator must still be shown to be dominated by false positives \
         ({} good / {} bad)",
        episode.good,
        episode.bad
    );
    let rec = Score::of(pairs.iter().filter(|p| recommended(p)));
    assert_eq!(rec.bad, 0, "recommended rule must emit no false positive");
    assert!(
        rec.good >= 7,
        "recommended rule must still find at least 7 real companions, found {}",
        rec.good
    );
    let rec_raw = Score::of(raw_pairs.iter().filter(|p| recommended(p)));
    assert!(
        rec_raw.good > rec_raw.bad * 2,
        "recommended rule must stay mostly correct even on the pathological trace \
         ({} good / {} bad)",
        rec_raw.good,
        rec_raw.bad
    );
    let loose = Score::of(pairs.iter().filter(|p| cdn_named_loose(&p.candidate)));
    assert!(
        loose.bad > loose.good * 10,
        "the loose shard mask must still be shown to be strictly harmful \
         ({} good / {} bad)",
        loose.good,
        loose.bad
    );
}

// ── The shipped engine, replayed over the same trace ──────────────────────────

/// Verdict of a suffix proposal: it inherits the worst verdict among the trace
/// hosts it would actually cover, because that is the traffic it moves.
fn suffix_verdict(anchor: &str, apex: &str, observed: &BTreeSet<&str>) -> Verdict {
    let dotted = format!(".{apex}");
    let members: Vec<&str> = observed
        .iter()
        .copied()
        // The anchor itself is covered when the proposal generalizes its own
        // domain. That is not traffic being moved — it already has a rule.
        .filter(|h| *h != anchor && (*h == apex || h.ends_with(&dotted)))
        .collect();
    if members.iter().any(|m| verdict(anchor, m) == Verdict::Bad) {
        Verdict::Bad
    } else if members.iter().any(|m| verdict(anchor, m) == Verdict::Good) {
        Verdict::Good
    } else {
        Verdict::Ambiguous
    }
}

/// End-to-end pin: the shipped `CompanionAffinityLedger` fed the raw trace must
/// reproduce the rule the study recommends — every proposal it emits is a real
/// companion of the site it is offered for, and none is background traffic.
#[test]
fn the_shipped_engine_reproduces_the_recommended_rule_on_the_trace() {
    let anchors: BTreeSet<String> = ANCHORS.iter().map(|s| (*s).to_string()).collect();
    let events = parse(TRACE);
    let observed: BTreeSet<&str> = events.iter().map(|(_, h)| h.as_str()).collect();

    let mut ledger = CompanionAffinityLedger::with_defaults();
    for (at, host) in &events {
        let kind = if anchors.contains(host) {
            CoActivityKind::Anchor {
                route: RouteRole::Secondary,
            }
        } else {
            CoActivityKind::Candidate
        };
        ledger.observe(*at, host, kind);
    }
    let now = events.last().map_or(0, |(at, _)| *at);
    let proposals = ledger.proposals(now, &NoExclusions);

    let emitted: Vec<(&str, &str, CompanionSignal, Verdict)> = proposals
        .iter()
        .map(|p| {
            let anchor = p.anchor_hostname.as_str();
            let verdict = match &p.proposed {
                ProposedCompanionMatch::ExactHost(h) => verdict(anchor, h),
                ProposedCompanionMatch::SuffixDomain(apex) => {
                    suffix_verdict(anchor, apex, &observed)
                }
            };
            (anchor, p.proposed.value(), p.signal, verdict)
        })
        .collect();

    // Seven qualifying (anchor, candidate) pairs surface as six review rows:
    // brand and delivery names generalize to a *different* domain from the
    // anchor's own, so the two cross-TLD companions of `anchor-f` collapse into
    // one row. `rt.anchor-k.example` stays exact: its apex IS the anchor's own
    // domain (`anchor-k.example`), and generalizing there would swallow
    // `www.anchor-k.example` itself on one window's evidence — the same guard
    // that keeps a subdomain from speaking for the umbrella domain it lives under.
    assert_eq!(
        emitted,
        vec![
            (
                "anchor-a.example",
                "cdn-a.example",
                CompanionSignal::DeliveryName,
                Verdict::Good
            ),
            (
                "anchor-e.example",
                "anchor-e.test",
                CompanionSignal::BrandRelated,
                Verdict::Good
            ),
            (
                "anchord.example",
                "anchordx.example",
                CompanionSignal::BrandRelated,
                Verdict::Good
            ),
            (
                "web.anchor-f.example",
                "anchor-f.test",
                CompanionSignal::BrandRelated,
                Verdict::Good
            ),
            (
                "www.anchor-k.example",
                "rt.anchor-k.example",
                CompanionSignal::BrandRelated,
                Verdict::Good
            ),
            (
                "www.anchor-m.example",
                "anchor-m.example",
                CompanionSignal::BrandRelated,
                Verdict::Good
            ),
        ]
    );

    // Replaying the same events twice must produce the same list.
    let mut twin = CompanionAffinityLedger::with_defaults();
    for (at, host) in &events {
        let kind = if anchors.contains(host) {
            CoActivityKind::Anchor {
                route: RouteRole::Secondary,
            }
        } else {
            CoActivityKind::Candidate
        };
        twin.observe(*at, host, kind);
    }
    assert_eq!(twin.proposals(now, &NoExclusions), proposals);
}
