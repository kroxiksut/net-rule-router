//! Which of our rules dropped a packet, as it travels from the lowering to the
//! drop observer.
//!
//! Windows names the dropping filter by its id and a registry says what role
//! that id plays. Here the lowering already knows the role when it emits the
//! drop, so the role itself is the name: it rides in the NFLOG prefix of the
//! drop's log statement and comes back on the packet. Pure, so the encoding is
//! tested on every host.

/// The NFLOG group our drop reports go to. Picked away from the low numbers
/// ulogd, Suricata and the documentation examples use: a group has one
/// listener, and a clash would silence one of the two programs (`0x4E52`, "NR").
pub const NRR_NFLOG_GROUP: u16 = 0x4E52;

/// Reports per second, per kind of drop. A blocked program retries a few
/// times a second, so this keeps every destination of a real outage while a
/// flood costs the kernel at most this many copies.
pub const DROP_LOG_RATE_PER_SECOND: u32 = 20;
/// Lets the burst of a page opening dozens of connections through whole.
pub const DROP_LOG_BURST: u32 = 50;

/// Bytes of each dropped packet copied to us: an IPv4 header with options, or
/// an IPv6 header with an extension header, plus the transport ports.
pub const NFLOG_SNAPLEN: u32 = 80;

const PREFIX_HEAD: &str = "nrr:";
const SYSTEM_SUFFIX: &str = ":sys";

/// High half of every spec id minted here ("NRLD"): never a WFP filter id, and
/// recognisable as ours in a trace row.
const SPEC_ID_SIGNATURE: u64 = 0x4E52_4C44_0000_0000;
const SPEC_ID_SIGNATURE_MASK: u64 = 0xFFFF_FFFF_0000_0000;
const SPEC_ID_SYSTEM_BIT: u64 = 0x100;

/// The role of the rule that dropped a packet. Mirrors the bands the Windows
/// drop registry tells apart, so one consumer reads both platforms alike.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DropKind {
    /// The guard of an egress pin: the destination may leave only by the
    /// bound link, and this packet tried another.
    Pin,
    /// A destination blocked outright because its link cannot be resolved.
    FailClosed,
    /// The block-all that holds while the additional route is down.
    BlockAll,
    /// IPv6 closed while the protection is on.
    Ipv6Cut,
    /// An application reaching for an encrypted resolver of its own.
    DnsLockdown,
    /// A block rule the user wrote.
    Rule,
    /// Strict mode's "no rule covers this host".
    Default,
    /// The relay pool's UDP veto.
    RelayPool,
    /// A drop in a band that does not normally carry one.
    Other,
}

impl DropKind {
    pub const ALL: [Self; 9] = [
        Self::Pin,
        Self::FailClosed,
        Self::BlockAll,
        Self::Ipv6Cut,
        Self::DnsLockdown,
        Self::Rule,
        Self::Default,
        Self::RelayPool,
        Self::Other,
    ];

    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Pin => "pin",
            Self::FailClosed => "fc",
            Self::BlockAll => "all",
            Self::Ipv6Cut => "v6",
            Self::DnsLockdown => "doh",
            Self::Rule => "rule",
            Self::Default => "dflt",
            Self::RelayPool => "pool",
            Self::Other => "other",
        }
    }

    const fn code(self) -> u64 {
        match self {
            Self::Pin => 1,
            Self::FailClosed => 2,
            Self::BlockAll => 3,
            Self::Ipv6Cut => 4,
            Self::DnsLockdown => 5,
            Self::Rule => 6,
            Self::Default => 7,
            Self::RelayPool => 8,
            Self::Other => 9,
        }
    }

    fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.slug() == slug)
    }

    fn from_code(code: u64) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.code() == code)
    }

    /// A drop that proves the route is held for the tunnel — the Windows
    /// registry's role-verifying set. Only these may teach an exemption or
    /// read as "the additional route is unavailable".
    #[must_use]
    pub const fn verifies_kill_switch(self) -> bool {
        matches!(self, Self::Pin | Self::FailClosed | Self::BlockAll)
    }
}

/// A [`DropKind`] plus whether the rule speaks for the machine's service
/// accounts rather than a signed-in user.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DropTag {
    pub kind: DropKind,
    pub system: bool,
}

impl DropTag {
    #[must_use]
    pub const fn user(kind: DropKind) -> Self {
        Self {
            kind,
            system: false,
        }
    }

    /// The NFLOG prefix, e.g. `nrr:pin` or `nrr:pin:sys`. Well inside the
    /// kernel's 64-byte limit.
    #[must_use]
    pub fn prefix(self) -> String {
        let system = if self.system { SYSTEM_SUFFIX } else { "" };
        format!("{PREFIX_HEAD}{}{system}", self.kind.slug())
    }

    /// Read a prefix back. `None` for anything we did not write — another
    /// program's rule logging to the same group must not be taken for ours.
    #[must_use]
    pub fn parse_prefix(prefix: &str) -> Option<Self> {
        let body = prefix.strip_prefix(PREFIX_HEAD)?;
        let (slug, system) = match body.strip_suffix(SYSTEM_SUFFIX) {
            Some(slug) => (slug, true),
            None => (body, false),
        };
        Some(Self {
            kind: DropKind::from_slug(slug)?,
            system,
        })
    }

    /// The per-tag chain the drop jumps to: `drop_pin`, `drop_pin_sys`.
    #[must_use]
    pub fn chain_name(self) -> String {
        let system = if self.system { "_sys" } else { "" };
        format!("drop_{}{system}", self.kind.slug())
    }

    /// The id a [`ConnectionObservation`] carries in `nrr_drop_spec_id`, so the
    /// consumer's role checks work on it as they do on a WFP filter id.
    ///
    /// [`ConnectionObservation`]: nrr_platform_api::conn_observe::ConnectionObservation
    #[must_use]
    pub const fn spec_id(self) -> u64 {
        let system = if self.system { SPEC_ID_SYSTEM_BIT } else { 0 };
        SPEC_ID_SIGNATURE | system | self.kind.code()
    }

    #[must_use]
    pub fn from_spec_id(id: u64) -> Option<Self> {
        if id & SPEC_ID_SIGNATURE_MASK != SPEC_ID_SIGNATURE {
            return None;
        }
        let low = id & !SPEC_ID_SIGNATURE_MASK;
        if low & !(SPEC_ID_SYSTEM_BIT | 0xFF) != 0 {
            return None;
        }
        Some(Self {
            kind: DropKind::from_code(low & 0xFF)?,
            system: low & SPEC_ID_SYSTEM_BIT != 0,
        })
    }

    /// Every tag there is, for publishing the role sets once.
    pub fn all() -> impl Iterator<Item = Self> {
        DropKind::ALL.into_iter().flat_map(|kind| {
            [false, true]
                .into_iter()
                .map(move |system| Self { kind, system })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tag_survives_its_prefix_and_its_spec_id() {
        for tag in DropTag::all() {
            assert_eq!(DropTag::parse_prefix(&tag.prefix()), Some(tag), "{tag:?}");
            assert_eq!(DropTag::from_spec_id(tag.spec_id()), Some(tag), "{tag:?}");
            assert!(tag.prefix().len() < 64, "{tag:?}");
        }
    }

    #[test]
    fn prefixes_name_the_kind_and_the_system_scope() {
        assert_eq!(DropTag::user(DropKind::Pin).prefix(), "nrr:pin");
        let system = DropTag {
            kind: DropKind::Pin,
            system: true,
        };
        assert_eq!(system.prefix(), "nrr:pin:sys");
        assert_eq!(system.chain_name(), "drop_pin_sys");
        assert_eq!(DropTag::user(DropKind::Ipv6Cut).chain_name(), "drop_v6");
    }

    #[test]
    fn a_foreign_prefix_or_id_is_not_ours() {
        assert_eq!(DropTag::parse_prefix("ufw-block"), None);
        assert_eq!(DropTag::parse_prefix("nrr:nonsense"), None);
        assert_eq!(DropTag::parse_prefix("nrr:pin:root"), None);
        assert_eq!(DropTag::parse_prefix(""), None);
        assert_eq!(DropTag::from_spec_id(80122), None);
        assert_eq!(DropTag::from_spec_id(SPEC_ID_SIGNATURE | 0x77), None);
        assert_eq!(DropTag::from_spec_id(SPEC_ID_SIGNATURE | 0x1_0001), None);
    }

    #[test]
    fn only_the_tunnel_guards_verify_the_kill_switch() {
        let verifying: Vec<DropKind> = DropKind::ALL
            .into_iter()
            .filter(|k| k.verifies_kill_switch())
            .collect();
        assert_eq!(
            verifying,
            vec![DropKind::Pin, DropKind::FailClosed, DropKind::BlockAll]
        );
    }
}
