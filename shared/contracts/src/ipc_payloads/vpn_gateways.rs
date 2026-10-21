use super::*;

// ── Where a VPN program connects ─────────────────────────────────────────────

/// `vpn.gateway-candidates.list` — the remote addresses one program connected
/// to recently, so a VPN that must reach its gateway over the other link can
/// get a rule for that address.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct VpnGatewayCandidatesRequest {
    /// Executable file name, case-insensitive. A full path is reduced to its
    /// file name by the service.
    #[serde(default)]
    pub program: String,
}

/// One remote address the program connected to, folded over its connections.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct VpnGatewayCandidateDto {
    /// IPv4 or IPv6 text.
    pub address: String,
    /// A name the service's DNS saw this address answered for, or empty.
    #[serde(default)]
    pub hostname: String,
    /// Remote ports seen, ascending.
    #[serde(default)]
    pub ports: Vec<u16>,
    /// `tcp`, `udp` or `ip-<n>`, sorted.
    #[serde(default)]
    pub protocols: Vec<String>,
    pub connections: u32,
    /// UTC ms of the latest connection; 0 when the observer gave no time.
    pub last_seen_ms: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct VpnGatewayCandidatesResponse {
    /// The file name the service matched against.
    #[serde(default)]
    pub program: String,
    /// Most likely gateway first.
    #[serde(default)]
    pub candidates: Vec<VpnGatewayCandidateDto>,
    /// Further addresses the list left out.
    #[serde(default)]
    pub omitted: u32,
    /// `false` when nothing watches connections on this machine, so an empty
    /// list means "not watching" rather than "never connected".
    #[serde(default = "default_true")]
    pub observer_active: bool,
}

// ── Gateways of another VPN, confirmed by the user ───────────────────────────

/// Most gateways one user may confirm. A machine runs one or two VPNs, each
/// with a gateway or two; every entry is a hole in the block, so it is small.
pub const VPN_GATEWAYS_MAX: usize = 8;

/// Longest program name a gateway entry carries, in characters.
pub const VPN_GATEWAY_PROGRAM_MAX_CHARS: usize = 260;

/// The UDP ports a VPN handshake uses: IKE, IKE behind NAT, L2TP and the
/// WireGuard default. A confirmed gateway is reachable on these and nothing
/// else.
pub const VPN_HANDSHAKE_UDP_PORTS: [u16; 4] = [500, 4500, 1701, 51820];

/// One VPN gateway: the address another VPN connects to over the main link,
/// and the program seen connecting, when one was.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct VpnGatewayDto {
    /// IPv4 or IPv6 text.
    pub address: String,
    /// Executable path or name; empty when the system itself connected.
    #[serde(default)]
    pub program: String,
}

/// `route.vpn-gateways.set` — replace the caller's confirmed VPN gateways.
/// Full replacement: confirming adds to the list the client holds, revoking
/// sends it without the entry, and an empty list clears it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RouteVpnGatewaysSetRequest {
    #[serde(default)]
    pub gateways: Vec<VpnGatewayDto>,
}

/// The stored set after the write, in the order the service keeps it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RouteVpnGatewaysSetResponse {
    #[serde(default)]
    pub gateways: Vec<VpnGatewayDto>,
}
