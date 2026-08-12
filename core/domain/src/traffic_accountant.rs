//! Traffic-counter accounting core (Block T) — pure, deterministic, no I/O.
//!
//! Turns per-interface cumulative octet readings into per-interval deltas,
//! bucketed by **role** (`primary` / `secondary` / `loopback` / `virtual`).
//!
//! # Design invariants
//!
//! - **Account by ROLE, not by adapter nature.** Roles are an arbitrary user
//!   assignment — the VPN may be the primary channel. Nothing here assumes
//!   "primary = physical / secondary = tunnel". [`categorize`] maps an
//!   interface to a [`TrafficCategory`] from the current role assignment plus
//!   the loopback/virtual toggles; the "route not wire" subtraction
//!   (carrier − tunnel) lives in the display layer, not here.
//! - **Prime on first sight.** The OS octet counters are cumulative since the
//!   interface came up. The first time the accountant sees an interface it
//!   records the cursor and emits **no** delta — otherwise the whole
//!   since-boot tally would land in "today". Persisted cursors are restored via
//!   [`TrafficAccountant::prime`] on service restart so traffic during downtime
//!   is captured (when no reset happened).
//! - **Reset detection.** On adapter re-up / reboot the OS counter drops back
//!   toward zero. When the current reading is below the cursor we treat it as a
//!   reset and count the whole current reading (the small pre-reset tail is
//!   unrecoverable and dropped), never a negative delta.

use std::collections::HashMap;

// ── TrafficCategory ───────────────────────────────────────────────────────────

/// The ledger bucket an interface's traffic is attributed to.
///
/// Only `Primary` / `Secondary` carry routed user traffic and are counted by
/// default. `Loopback` (localhost) and `Virtual` (VM host-only) are opt-in and
/// recorded only from the moment their toggle is switched on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TrafficCategory {
    /// The adapter currently assigned the primary route role.
    Primary,
    /// The adapter currently assigned the secondary (additional) route role.
    Secondary,
    /// Loopback (127.0.0.1) — opt-in, its own line.
    Loopback,
    /// Virtual VM host-only adapter — opt-in, aggregated.
    Virtual,
}

impl TrafficCategory {
    /// Stable persistence/display slug (used as the `role` column value).
    pub fn slug(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Secondary => "secondary",
            Self::Loopback => "loopback",
            Self::Virtual => "virtual",
        }
    }

    /// Parses a slug back into a category. Returns `None` for unknown slugs.
    pub fn from_slug(s: &str) -> Option<Self> {
        match s {
            "primary" => Some(Self::Primary),
            "secondary" => Some(Self::Secondary),
            "loopback" => Some(Self::Loopback),
            "virtual" => Some(Self::Virtual),
            _ => None,
        }
    }
}

// ── categorize ────────────────────────────────────────────────────────────────

/// The neutral classification bits [`categorize`] needs for one interface.
///
/// Deliberately booleans (not the platform `InterfaceType`) so this crate stays
/// free of any platform dependency — the sampler maps `InterfaceCounters` into
/// this shape.
#[derive(Clone, Copy, Debug)]
pub struct InterfaceFacts<'a> {
    pub stable_name: &'a str,
    pub is_loopback: bool,
    pub is_tunnel: bool,
    pub is_virtual: bool,
}

/// Current role assignment, keyed on the **stable name** (name-heal anchor).
#[derive(Clone, Copy, Debug, Default)]
pub struct RoleAssignment<'a> {
    pub primary_name: Option<&'a str>,
    pub secondary_name: Option<&'a str>,
}

/// Which opt-in categories are currently being recorded.
#[derive(Clone, Copy, Debug, Default)]
pub struct CountingToggles {
    pub count_loopback: bool,
    pub count_virtual: bool,
}

/// Assigns an interface to a ledger bucket, or `None` when it must not be
/// counted (an off toggle, or an "other physical" adapter that our routing
/// never sends traffic through).
///
/// Order matters: the role checks win first, so a tunnel that IS the secondary
/// is counted as `Secondary`, not folded into `Virtual`.
pub fn categorize(
    facts: InterfaceFacts<'_>,
    roles: RoleAssignment<'_>,
    toggles: CountingToggles,
) -> Option<TrafficCategory> {
    if roles.primary_name == Some(facts.stable_name) {
        return Some(TrafficCategory::Primary);
    }
    if roles.secondary_name == Some(facts.stable_name) {
        return Some(TrafficCategory::Secondary);
    }
    if facts.is_loopback {
        return toggles.count_loopback.then_some(TrafficCategory::Loopback);
    }
    // A tunnel that is neither role is some other (unselected) VPN — bucket it
    // with the virtual/host-only aggregate rather than as routed user traffic.
    if facts.is_virtual || facts.is_tunnel {
        return toggles.count_virtual.then_some(TrafficCategory::Virtual);
    }
    // "Other physical" — a third NIC our routing never uses. Not counted.
    None
}

// ── Samples / deltas ──────────────────────────────────────────────────────────

/// One interface reading fed into the accountant for a tick.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficSample {
    /// Stable-name identity anchor (also the `adapter_key`).
    pub stable_name: String,
    /// Which bucket this interface's traffic belongs to this tick.
    pub category: TrafficCategory,
    /// Cumulative octets received since the interface came up.
    pub in_octets: u64,
    /// Cumulative octets sent since the interface came up.
    pub out_octets: u64,
}

/// A computed increment to add to the current day's bucket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficDelta {
    pub stable_name: String,
    pub category: TrafficCategory,
    pub in_delta: u64,
    pub out_delta: u64,
}

/// Reset-aware increment: normal difference, or the whole current reading when
/// the counter dropped below the cursor (adapter re-up / reboot).
fn reset_aware_delta(current: u64, last: u64) -> u64 {
    if current >= last {
        current - last
    } else {
        current
    }
}

// ── tunnel_overlap_adjust (Block T Feature 1) ───────────────────────────────

/// Subtracts a tunnel secondary's tick delta from the primary's tick delta,
/// so a VPN's traffic is not counted twice: once decrypted on the tunnel
/// adapter (secondary) and again encrypted on the physical adapter carrying
/// it (primary). "What counts as VPN is not counted in the main channel."
///
/// # Gating
///
/// The subtraction applies **only** when `secondary_is_tunnel` is `true`.
/// When the secondary is a second PHYSICAL adapter (a genuine dual-NIC setup,
/// not a VPN), its traffic is independent of the primary's — subtracting it
/// there would corrupt the primary's stats for no reason, since there is no
/// physical double-counting to correct. Callers must pass the CURRENT tick's
/// classification (`InterfaceFacts::is_tunnel`, ORed with the raw MIB type —
/// see [`InterfaceFacts`]), not a cached assumption, since a role/adapter
/// swap can change it tick to tick.
///
/// # Why the residue is not always exactly zero
///
/// The encrypted outer flow (what the primary physically carries) is
/// slightly LARGER than the decrypted inner flow (what the tunnel adapter
/// reports) — protocol framing, encryption padding, and encapsulation
/// headers all add overhead. So a small positive residue legitimately
/// remains on the primary after subtraction; that is correct, not a bug.
/// `saturating_sub` additionally absorbs tick-to-tick timing skew between
/// the two counters (they are read in the same pass, but not atomically),
/// which can otherwise make the secondary's delta transiently exceed the
/// primary's for one tick.
///
/// Pure — no I/O, no clock. Called once per tick, per channel direction.
pub fn tunnel_overlap_adjust(
    primary_in_delta: u64,
    primary_out_delta: u64,
    secondary_in_delta: u64,
    secondary_out_delta: u64,
    secondary_is_tunnel: bool,
) -> (u64, u64) {
    if !secondary_is_tunnel {
        return (primary_in_delta, primary_out_delta);
    }
    (
        primary_in_delta.saturating_sub(secondary_in_delta),
        primary_out_delta.saturating_sub(secondary_out_delta),
    )
}

// ── TrafficAccountant ─────────────────────────────────────────────────────────

/// Holds the per-interface cursor (last cumulative reading) and turns fresh
/// readings into deltas. Pure — no clock, no storage.
#[derive(Debug, Default)]
pub struct TrafficAccountant {
    /// stable_name -> (last_in, last_out)
    cursors: HashMap<String, (u64, u64)>,
}

impl TrafficAccountant {
    pub fn new() -> Self {
        Self::default()
    }

    /// Restores a cursor from persisted state (service restart) WITHOUT emitting
    /// a delta. The next [`ingest`](Self::ingest) computes the increment against
    /// this baseline, capturing traffic that flowed while the service was down
    /// (as long as the interface did not reset in the meantime).
    pub fn prime(&mut self, stable_name: &str, last_in: u64, last_out: u64) {
        self.cursors
            .insert(stable_name.to_string(), (last_in, last_out));
    }

    /// Current cursor for an interface, for persistence.
    pub fn cursor(&self, stable_name: &str) -> Option<(u64, u64)> {
        self.cursors.get(stable_name).copied()
    }

    /// Ingests a tick's worth of samples and returns the deltas to accumulate.
    ///
    /// An interface seen for the first time (no cursor, not primed) is recorded
    /// and yields no delta — we cannot attribute its since-boot tally to the
    /// current interval. Deltas that are zero on both directions are omitted.
    pub fn ingest(&mut self, samples: &[TrafficSample]) -> Vec<TrafficDelta> {
        let mut out = Vec::new();
        for s in samples {
            match self.cursors.get(&s.stable_name).copied() {
                None => {
                    // First sight — prime the cursor, emit nothing.
                    self.cursors
                        .insert(s.stable_name.clone(), (s.in_octets, s.out_octets));
                }
                Some((last_in, last_out)) => {
                    let in_delta = reset_aware_delta(s.in_octets, last_in);
                    let out_delta = reset_aware_delta(s.out_octets, last_out);
                    self.cursors
                        .insert(s.stable_name.clone(), (s.in_octets, s.out_octets));
                    if in_delta != 0 || out_delta != 0 {
                        out.push(TrafficDelta {
                            stable_name: s.stable_name.clone(),
                            category: s.category,
                            in_delta,
                            out_delta,
                        });
                    }
                }
            }
        }
        out
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(name: &str, cat: TrafficCategory, in_o: u64, out_o: u64) -> TrafficSample {
        TrafficSample {
            stable_name: name.to_string(),
            category: cat,
            in_octets: in_o,
            out_octets: out_o,
        }
    }

    // ── categorize ────────────────────────────────────────────────────────────

    fn facts<'a>(name: &'a str, loop_: bool, tun: bool, virt: bool) -> InterfaceFacts<'a> {
        InterfaceFacts {
            stable_name: name,
            is_loopback: loop_,
            is_tunnel: tun,
            is_virtual: virt,
        }
    }

    #[test]
    fn primary_and_secondary_matched_by_name() {
        let roles = RoleAssignment {
            primary_name: Some("Ethernet"),
            secondary_name: Some("WireGuard"),
        };
        let t = CountingToggles::default();
        assert_eq!(
            categorize(facts("Ethernet", false, false, false), roles, t),
            Some(TrafficCategory::Primary)
        );
        // Secondary is a tunnel — still Secondary, NOT Virtual.
        assert_eq!(
            categorize(facts("WireGuard", false, true, false), roles, t),
            Some(TrafficCategory::Secondary)
        );
    }

    #[test]
    fn vpn_as_primary_is_counted_as_primary() {
        // Role assignment is arbitrary: the tunnel can be the primary.
        let roles = RoleAssignment {
            primary_name: Some("WireGuard"),
            secondary_name: Some("Ethernet"),
        };
        assert_eq!(
            categorize(
                facts("WireGuard", false, true, false),
                roles,
                CountingToggles::default()
            ),
            Some(TrafficCategory::Primary)
        );
    }

    #[test]
    fn loopback_only_when_toggle_on() {
        let roles = RoleAssignment::default();
        assert_eq!(
            categorize(
                facts("Loopback", true, false, false),
                roles,
                CountingToggles {
                    count_loopback: false,
                    count_virtual: false,
                }
            ),
            None
        );
        assert_eq!(
            categorize(
                facts("Loopback", true, false, false),
                roles,
                CountingToggles {
                    count_loopback: true,
                    count_virtual: false,
                }
            ),
            Some(TrafficCategory::Loopback)
        );
    }

    #[test]
    fn virtual_and_unselected_tunnel_only_when_toggle_on() {
        let roles = RoleAssignment::default();
        let on = CountingToggles {
            count_loopback: false,
            count_virtual: true,
        };
        assert_eq!(
            categorize(facts("Hyper-V", false, false, true), roles, on),
            Some(TrafficCategory::Virtual)
        );
        // An unselected tunnel (some other VPN) folds into Virtual.
        assert_eq!(
            categorize(facts("OtherVPN", false, true, false), roles, on),
            Some(TrafficCategory::Virtual)
        );
        assert_eq!(
            categorize(
                facts("Hyper-V", false, false, true),
                roles,
                CountingToggles::default()
            ),
            None
        );
    }

    #[test]
    fn other_physical_not_counted() {
        let roles = RoleAssignment {
            primary_name: Some("Ethernet"),
            secondary_name: None,
        };
        // A third physical NIC that is neither role and not virtual/loopback.
        assert_eq!(
            categorize(
                facts("Ethernet 2", false, false, false),
                roles,
                CountingToggles {
                    count_loopback: true,
                    count_virtual: true,
                }
            ),
            None
        );
    }

    #[test]
    fn slug_round_trips() {
        for c in [
            TrafficCategory::Primary,
            TrafficCategory::Secondary,
            TrafficCategory::Loopback,
            TrafficCategory::Virtual,
        ] {
            assert_eq!(TrafficCategory::from_slug(c.slug()), Some(c));
        }
        assert_eq!(TrafficCategory::from_slug("nope"), None);
    }

    // ── accountant ────────────────────────────────────────────────────────────

    #[test]
    fn first_sight_primes_and_emits_nothing() {
        let mut acc = TrafficAccountant::new();
        let deltas = acc.ingest(&[sample("eth0", TrafficCategory::Primary, 1000, 500)]);
        assert!(
            deltas.is_empty(),
            "first sight must not dump since-boot tally"
        );
        assert_eq!(acc.cursor("eth0"), Some((1000, 500)));
    }

    #[test]
    fn second_tick_emits_difference() {
        let mut acc = TrafficAccountant::new();
        acc.ingest(&[sample("eth0", TrafficCategory::Primary, 1000, 500)]);
        let deltas = acc.ingest(&[sample("eth0", TrafficCategory::Primary, 1600, 800)]);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].in_delta, 600);
        assert_eq!(deltas[0].out_delta, 300);
        assert_eq!(deltas[0].category, TrafficCategory::Primary);
    }

    #[test]
    fn counter_reset_counts_whole_current_reading() {
        let mut acc = TrafficAccountant::new();
        acc.ingest(&[sample("wg0", TrafficCategory::Secondary, 5000, 5000)]);
        // Adapter re-up: counter dropped back to a low value.
        let deltas = acc.ingest(&[sample("wg0", TrafficCategory::Secondary, 120, 30)]);
        assert_eq!(deltas.len(), 1);
        assert_eq!(
            deltas[0].in_delta, 120,
            "reset → count the whole new reading"
        );
        assert_eq!(deltas[0].out_delta, 30);
    }

    #[test]
    fn prime_restores_cursor_and_captures_downtime() {
        let mut acc = TrafficAccountant::new();
        // Persisted cursor from before the restart.
        acc.prime("eth0", 1000, 500);
        // First reading after restart already climbed during downtime.
        let deltas = acc.ingest(&[sample("eth0", TrafficCategory::Primary, 1400, 700)]);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].in_delta, 400, "captures traffic during downtime");
        assert_eq!(deltas[0].out_delta, 200);
    }

    #[test]
    fn zero_delta_is_omitted() {
        let mut acc = TrafficAccountant::new();
        acc.ingest(&[sample("eth0", TrafficCategory::Primary, 1000, 500)]);
        let deltas = acc.ingest(&[sample("eth0", TrafficCategory::Primary, 1000, 500)]);
        assert!(deltas.is_empty(), "idle interface emits no delta");
    }

    // ── tunnel_overlap_adjust (Block T Feature 1) ────────────────────────────

    #[test]
    fn tunnel_secondary_subtracts_from_primary() {
        let (in_adj, out_adj) = tunnel_overlap_adjust(1000, 500, 400, 150, true);
        assert_eq!((in_adj, out_adj), (600, 350));
    }

    #[test]
    fn physical_secondary_leaves_primary_unaffected() {
        // A second PHYSICAL adapter — its traffic is genuinely independent,
        // not encapsulated inside the primary's flow. No subtraction.
        let (in_adj, out_adj) = tunnel_overlap_adjust(1000, 500, 400, 150, false);
        assert_eq!((in_adj, out_adj), (1000, 500));
    }

    #[test]
    fn subtraction_clamps_at_zero_never_underflows() {
        // The encrypted outer flow is normally >= the inner flow, but timing
        // skew between the two counter reads can transiently invert that for
        // one tick. Must clamp, never wrap/panic.
        let (in_adj, out_adj) = tunnel_overlap_adjust(100, 50, 900, 900, true);
        assert_eq!((in_adj, out_adj), (0, 0));
    }

    #[test]
    fn small_positive_residue_survives_encapsulation_overhead() {
        // Outer (primary) flow is a little larger than inner (tunnel) flow —
        // legitimate encapsulation overhead, not a bug.
        let (in_adj, out_adj) = tunnel_overlap_adjust(1050, 520, 1000, 500, true);
        assert_eq!((in_adj, out_adj), (50, 20));
    }

    #[test]
    fn zero_secondary_delta_leaves_primary_unchanged() {
        // Primary-only tick (no tunnel secondary traffic this tick) is a
        // no-op subtraction — nothing to correct.
        let (in_adj, out_adj) = tunnel_overlap_adjust(1000, 500, 0, 0, true);
        assert_eq!((in_adj, out_adj), (1000, 500));
    }

    #[test]
    fn independent_interfaces_tracked_separately() {
        let mut acc = TrafficAccountant::new();
        acc.ingest(&[
            sample("eth0", TrafficCategory::Primary, 100, 100),
            sample("wg0", TrafficCategory::Secondary, 200, 200),
        ]);
        let deltas = acc.ingest(&[
            sample("eth0", TrafficCategory::Primary, 150, 100),
            sample("wg0", TrafficCategory::Secondary, 200, 260),
        ]);
        assert_eq!(deltas.len(), 2);
        let eth = deltas
            .iter()
            .find(|d| d.stable_name == "eth0")
            .expect("eth0");
        let wg = deltas.iter().find(|d| d.stable_name == "wg0").expect("wg0");
        assert_eq!((eth.in_delta, eth.out_delta), (50, 0));
        assert_eq!((wg.in_delta, wg.out_delta), (0, 60));
    }
}
