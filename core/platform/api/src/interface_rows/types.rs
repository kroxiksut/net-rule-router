// The row an interfaces screen shows, and the facts and assessment behind it.

use super::*;

/// Coarse availability bucket derived from the adapter `oper_status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BasicAvailabilityStatus {
    Available,
    Unavailable,
    RequiresCheck,
}

impl BasicAvailabilityStatus {
    pub const fn title(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Unavailable => "unavailable",
            Self::RequiresCheck => "requires-check",
        }
    }
}

/// Provenance of the enriched row set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterfacesDataSource {
    WindowsLive,
    LinuxLive,
    FallbackMock,
}

impl InterfacesDataSource {
    pub const fn title(self) -> &'static str {
        match self {
            Self::WindowsLive => "windows-live",
            Self::LinuxLive => "linux-live",
            Self::FallbackMock => "fallback-mock",
        }
    }

    /// Parse the wire spelling back. The service reports the provenance of the
    /// rows it enumerated and the client must carry that verdict rather than
    /// assume the rows are live — a placeholder list rendered as live invites
    /// the user to bind a route to an adapter that does not exist. An
    /// unrecognised spelling reads as [`Self::FallbackMock`]: the honest answer
    /// when the peer says something this build cannot vouch for.
    pub fn from_title(title: &str) -> Self {
        match title {
            "windows-live" => Self::WindowsLive,
            "linux-live" => Self::LinuxLive,
            _ => Self::FallbackMock,
        }
    }

    /// Whether these rows describe the machine as it actually is.
    pub const fn is_live(self) -> bool {
        matches!(self, Self::WindowsLive | Self::LinuxLive)
    }
}

/// One enriched adapter row consumed by the GUI list and the diagnostics
/// surfaces. `selected_role` / `route_state` start unbound here — the
/// preview layer (mock-backend) and the GUI re-apply user role bindings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceRouteRow {
    pub persistent_id: String,
    pub adapter_name: String,
    pub windows_name: String,
    pub interface_description: String,
    pub interface_type: String,
    pub is_bluetooth_like: bool,
    pub local_ip: String,
    pub gateway: String,
    pub dns_servers: String,
    pub has_default_route: bool,
    /// Whether traffic can actually be forwarded out of this interface: it
    /// exposes a classic gateway, OR the route table carries a default-style
    /// route on it with a real next-hop (see [`derive_forwarding_next_hop`]).
    ///
    /// [`Self::has_default_route`] cannot answer this — the enumeration
    /// derives it as "a gateway is present", so it says the same thing twice
    /// and reads `false` for every healthy gateway-less tunnel (OpenVPN /
    /// WireGuard install split-default routes instead of a gateway). This
    /// field is what separates "no way out" (host-only virtual adapter) from
    /// "no gateway, but routed" (the ordinary VPN case), and it is computed
    /// where the route table is available rather than guessed in the GUI.
    ///
    /// `None` = not evaluated (route table unavailable, or a row that came
    /// from a sender predating the field). Consumers must not read that as
    /// "unusable".
    pub has_forwarding_path: Option<bool>,
    /// The OS could not be asked for IP / gateway / DNS at all, so the three
    /// fields above read `"-"` for EVERY row.
    ///
    /// Phrased as "unavailable" rather than "known" so a sender predating the
    /// field defaults to `false` — data present — instead of silently marking
    /// every row unevaluated. A `"-"` local IP normally means "this adapter has
    /// no address"; with this flag set it means "nobody was able to ask", and a
    /// consumer that blocks on the first reading would declare a machine with a
    /// working link to have no usable adapter at all.
    pub runtime_data_unavailable: bool,
    pub availability_status: BasicAvailabilityStatus,
    pub observed_facts: ObservedInterfaceFacts,
    pub derived_assessment: DerivedInterfaceAssessment,
    // ── Decoration slots ─────────────────────────────────────────────────
    //
    // The three fields below are NOT observations. Nothing on the service side
    // fills them — `from_wire_dto` resets them on the way in — and the preview
    // layer recomputes all three from the fields above on every pass. Reading
    // one as "what the service is enforcing" is the mistake they invite: the
    // row can arrive from the service and still carry a purely local verdict
    // here. Their meaning is decided in `nrr-mock-backend::network_interfaces`.
    /// Advisory only, and it says so on the wire (`advisory_only`).
    pub recommendation: RouteRoleRecommendation,
    /// The role the USER bound, re-applied from the request — not a role the
    /// service reported.
    pub selected_role: Option<RouteRole>,
    /// Where this adapter stands in the SELECTION flow (chosen / needs a check
    /// / unusable), derived from the fields above. It is not the enforcement
    /// state of any policy.
    pub route_state: RouteSelectionState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedInterfaceFacts {
    pub connectivity_state: ConnectivityState,
    pub external_ip_status: ExternalIpStatus,
    pub external_ip: Option<String>,
    pub external_probe_attempted: bool,
    pub external_probe_note: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedInterfaceAssessment {
    pub vpn_tunnel_likelihood: DerivedLikelihood,
    pub virtual_interface_likelihood: DerivedLikelihood,
    pub service_interface_likelihood: DerivedLikelihood,
    pub classification: String,
    pub confidence_percent: u8,
    pub heuristic_only: bool,
    pub signals: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteRoleRecommendation {
    pub class: RecommendationClass,
    pub confidence: RecommendationConfidence,
    pub advisory_only: bool,
    pub summary: String,
    pub key_signals: Vec<String>,
    pub excluded_alternatives: Vec<String>,
}
