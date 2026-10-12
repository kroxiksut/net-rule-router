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
