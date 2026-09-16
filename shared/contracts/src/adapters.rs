//! Adapter identity and the assessment vocabulary the interfaces screen reads.
//!
//! Identity is the load-bearing part: an adapter is named by `AdapterName`
//! with `ifindex + mac` as the fallback, because the friendly name is the one
//! thing a user can change.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConnectivityState {
    Available,
    Degraded,
    Unavailable,
    Unknown,
    Timeout,
}

impl ConnectivityState {
    pub const fn title(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Degraded => "degraded",
            Self::Unavailable => "unavailable",
            Self::Unknown => "unknown",
            Self::Timeout => "timeout",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExternalIpStatus {
    Resolved,
    NotChecked,
    CheckFailed,
    RateLimited,
    Blocked,
}

impl ExternalIpStatus {
    pub const fn title(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::NotChecked => "not-checked",
            Self::CheckFailed => "check-failed",
            Self::RateLimited => "rate-limited",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DerivedLikelihood {
    Likely,
    Possible,
    Unlikely,
    Unknown,
}

impl DerivedLikelihood {
    pub const fn title(self) -> &'static str {
        match self {
            Self::Likely => "likely",
            Self::Possible => "possible",
            Self::Unlikely => "unlikely",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecommendationClass {
    PreferredPrimary,
    PreferredSecondary,
    AllowedButNotRecommended,
    NotRecommended,
}

impl RecommendationClass {
    pub const fn title(self) -> &'static str {
        match self {
            Self::PreferredPrimary => "preferred-primary",
            Self::PreferredSecondary => "preferred-secondary",
            Self::AllowedButNotRecommended => "allowed-but-not-recommended",
            Self::NotRecommended => "not-recommended",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecommendationConfidence {
    High,
    Medium,
    Low,
    Unknown,
}

impl RecommendationConfidence {
    pub const fn title(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AdapterCheckActionId {
    CheckRoute,
    ShowExternalIp,
    CheckInternetAvailability,
}

impl AdapterCheckActionId {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::CheckRoute => "check-route",
            Self::ShowExternalIp => "show-external-ip",
            Self::CheckInternetAvailability => "check-internet-availability",
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::CheckRoute => "Check route",
            Self::ShowExternalIp => "Show external IP",
            Self::CheckInternetAvailability => "Internet available via adapter",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AdapterCheckExecutionScope {
    ReadOnlyDiagnostics,
    RequiresServiceMediation,
}

impl AdapterCheckExecutionScope {
    pub const fn title(self) -> &'static str {
        match self {
            Self::ReadOnlyDiagnostics => "read-only-diagnostics",
            Self::RequiresServiceMediation => "requires-service-mediation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AdapterCheckResultStatus {
    Success,
    Degraded,
    Unavailable,
    Timeout,
}

impl AdapterCheckResultStatus {
    pub const fn title(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Degraded => "degraded",
            Self::Unavailable => "unavailable",
            Self::Timeout => "timeout",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AdapterIdentityField {
    AdapterName,
    Ipv6IfIndex,
    PhysicalAddress,
}

impl AdapterIdentityField {
    pub const fn title(self) -> &'static str {
        match self {
            Self::AdapterName => "AdapterName",
            Self::Ipv6IfIndex => "IPv6IfIndex",
            Self::PhysicalAddress => "PhysicalAddress",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterIdentityContract {
    pub stable_fields: &'static [AdapterIdentityField],
    pub display_only_fields: &'static [&'static str],
    pub persistent_id_policy: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AdapterSnapshotDataSource {
    WindowsLive,
    FallbackMock,
}

impl AdapterSnapshotDataSource {
    pub const fn title(self) -> &'static str {
        match self {
            Self::WindowsLive => "windows-live",
            Self::FallbackMock => "fallback-mock",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterIdentity {
    pub persistent_id: String,
    pub adapter_name: String,
    pub ipv6_if_index: u32,
    pub physical_address: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterSnapshotEntry {
    pub identity: AdapterIdentity,
    pub windows_name: String,
    pub interface_description: String,
    pub interface_type: String,
    pub oper_status: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdaptersSnapshot {
    pub data_source: AdapterSnapshotDataSource,
    pub identity_contract: AdapterIdentityContract,
    pub adapters: Vec<AdapterSnapshotEntry>,
}
