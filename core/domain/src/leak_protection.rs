//! Leak protection: the user's one choice, and the one table that turns it,
//! the default route and the tunnel's state into what enforcement arms. Both
//! OS engines read [`protection_posture`]; neither decides on its own.

use core::fmt;
use core::str::FromStr;

use crate::RouteBehaviorMode;

/// What may leave over the main connection when the additional one is meant
/// to carry it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum LeakProtection {
    /// Nothing is held back: a dropped tunnel falls back to the main link.
    Off,
    /// What the rules send through the additional connection never leaves
    /// over the main one; everything else keeps working. The default: a VPN
    /// that is off, drops or starts late must not leak the sites meant for it.
    #[default]
    Sites,
    /// Nothing leaves except through the additional connection, the local
    /// network and what the rules send over the main connection.
    Everything,
}

impl LeakProtection {
    pub const ALL: [Self; 3] = [Self::Off, Self::Sites, Self::Everything];

    pub const fn as_slug(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Sites => "sites",
            Self::Everything => "everything",
        }
    }

    pub const fn is_on(self) -> bool {
        !matches!(self, Self::Off)
    }

    /// `Sites` is offered only with the main-connection default route; under the
    /// additional one it means `Everything`.
    pub const fn effective(self, mode: RouteBehaviorMode) -> Self {
        match (self, mode) {
            (Self::Sites, RouteBehaviorMode::PreferSecondaryWhenAvailable) => Self::Everything,
            (other, _) => other,
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::Sites => 1,
            Self::Everything => 2,
        }
    }

    /// The stronger of `self` and `floor`.
    pub const fn at_least(self, floor: Self) -> Self {
        if floor.rank() > self.rank() {
            floor
        } else {
            self
        }
    }
}

impl fmt::Display for LeakProtection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_slug())
    }
}

impl FromStr for LeakProtection {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "off" => Ok(Self::Off),
            "sites" => Ok(Self::Sites),
            "everything" => Ok(Self::Everything),
            _ => Err("unknown leak protection"),
        }
    }
}

// The wire twin. Lives here because the dependency runs domain → shared.
impl From<LeakProtection> for nrr_shared::ipc_payloads::LeakProtectionDto {
    fn from(value: LeakProtection) -> Self {
        match value {
            LeakProtection::Off => Self::Off,
            LeakProtection::Sites => Self::Sites,
            LeakProtection::Everything => Self::Everything,
        }
    }
}

impl From<nrr_shared::ipc_payloads::LeakProtectionDto> for LeakProtection {
    fn from(value: nrr_shared::ipc_payloads::LeakProtectionDto) -> Self {
        use nrr_shared::ipc_payloads::LeakProtectionDto as W;
        match value {
            W::Off => Self::Off,
            W::Sites => Self::Sites,
            W::Everything => Self::Everything,
        }
    }
}

/// What enforcement arms for one user at one moment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProtectionPosture {
    /// No protection filters.
    Open,
    /// Rule destinations of the additional route may leave only through the
    /// tunnel.
    PinRuleDestinations,
    /// Rule destinations of the additional route are blocked; the rest flows.
    BlockRuleDestinations,
    /// Everything this user sends is blocked except what the floor spares.
    BlockAll,
    /// Everything this user sends must leave through the tunnel.
    CatchAllThroughTunnel,
}

/// THE one decision table both OS engines use.
pub const fn protection_posture(
    mode: RouteBehaviorMode,
    protection: LeakProtection,
    tunnel_up: bool,
) -> ProtectionPosture {
    // `effective` already folded `Sites` under the additional default route
    // into `Everything`, so the `Sites` arms only see the main one.
    match (protection.effective(mode), mode, tunnel_up) {
        (LeakProtection::Off, _, _) => ProtectionPosture::Open,
        (LeakProtection::Sites, _, true) => ProtectionPosture::PinRuleDestinations,
        (LeakProtection::Sites, _, false) => ProtectionPosture::BlockRuleDestinations,
        // Under the main default route unmatched traffic belongs on the main
        // link, so a live tunnel only needs the rule destinations held to it.
        (LeakProtection::Everything, RouteBehaviorMode::PreferPrimary, true) => {
            ProtectionPosture::PinRuleDestinations
        }
        (LeakProtection::Everything, RouteBehaviorMode::PreferSecondaryWhenAvailable, true) => {
            ProtectionPosture::CatchAllThroughTunnel
        }
        (LeakProtection::Everything, _, false) => ProtectionPosture::BlockAll,
    }
}

#[cfg(test)]
mod tests {
    use super::ProtectionPosture::*;
    use super::*;
    use crate::RouteBehaviorMode::{
        PreferPrimary as Main, PreferSecondaryWhenAvailable as Additional,
    };

    const MODES: [RouteBehaviorMode; 2] = [Main, Additional];

    #[test]
    fn every_combination_has_its_posture() {
        let table = [
            (Main, LeakProtection::Off, true, Open),
            (Main, LeakProtection::Off, false, Open),
            (Additional, LeakProtection::Off, true, Open),
            (Additional, LeakProtection::Off, false, Open),
            (Main, LeakProtection::Sites, true, PinRuleDestinations),
            (Main, LeakProtection::Sites, false, BlockRuleDestinations),
            (
                Additional,
                LeakProtection::Sites,
                true,
                CatchAllThroughTunnel,
            ),
            (Additional, LeakProtection::Sites, false, BlockAll),
            (Main, LeakProtection::Everything, true, PinRuleDestinations),
            (Main, LeakProtection::Everything, false, BlockAll),
            (
                Additional,
                LeakProtection::Everything,
                true,
                CatchAllThroughTunnel,
            ),
            (Additional, LeakProtection::Everything, false, BlockAll),
        ];
        assert_eq!(table.len(), MODES.len() * LeakProtection::ALL.len() * 2);
        for (mode, protection, tunnel_up, expected) in table {
            assert_eq!(
                protection_posture(mode, protection, tunnel_up),
                expected,
                "{mode} / {protection} / tunnel up = {tunnel_up}"
            );
        }
    }

    #[test]
    fn main_default_route_never_catches_all_through_the_tunnel() {
        for protection in LeakProtection::ALL {
            for tunnel_up in [true, false] {
                assert_ne!(
                    protection_posture(Main, protection, tunnel_up),
                    CatchAllThroughTunnel
                );
            }
        }
    }

    #[test]
    fn off_never_blocks_anything() {
        for mode in MODES {
            for tunnel_up in [true, false] {
                assert_eq!(
                    protection_posture(mode, LeakProtection::Off, tunnel_up),
                    Open
                );
            }
        }
    }

    #[test]
    fn sites_means_everything_under_the_additional_default_route() {
        assert_eq!(
            LeakProtection::Sites.effective(Additional),
            LeakProtection::Everything
        );
        assert_eq!(LeakProtection::Sites.effective(Main), LeakProtection::Sites);
        for mode in MODES {
            assert_eq!(LeakProtection::Off.effective(mode), LeakProtection::Off);
            assert_eq!(
                LeakProtection::Everything.effective(mode),
                LeakProtection::Everything
            );
        }
    }

    #[test]
    fn slugs_round_trip_and_nothing_else_parses() {
        for protection in LeakProtection::ALL {
            assert_eq!(protection.as_slug().parse(), Ok(protection));
            assert_eq!(protection.to_string(), protection.as_slug());
        }
        for stray in [
            "",
            "on",
            "Off",
            "SITES",
            "all",
            "everything ",
            "kill-switch",
        ] {
            assert!(stray.parse::<LeakProtection>().is_err(), "{stray:?}");
        }
    }

    #[test]
    fn the_wire_twin_carries_the_same_slug() {
        use nrr_shared::ipc_payloads::LeakProtectionDto;
        for protection in LeakProtection::ALL {
            let dto = LeakProtectionDto::from(protection);
            assert_eq!(
                serde_json::to_value(dto).ok(),
                Some(serde_json::Value::String(protection.as_slug().into()))
            );
            assert_eq!(LeakProtection::from(dto), protection);
        }
    }

    #[test]
    fn only_off_is_off() {
        assert!(!LeakProtection::Off.is_on());
        assert!(LeakProtection::Sites.is_on());
        assert!(LeakProtection::Everything.is_on());
    }

    #[test]
    fn a_floor_only_ever_raises() {
        use LeakProtection::{Everything, Off, Sites};
        for (level, floor, expected) in [
            (Off, Off, Off),
            (Off, Sites, Sites),
            (Off, Everything, Everything),
            (Sites, Off, Sites),
            (Sites, Everything, Everything),
            (Everything, Off, Everything),
            (Everything, Sites, Everything),
        ] {
            assert_eq!(level.at_least(floor), expected, "{level} / {floor}");
        }
    }

    /// A user who never chose keeps what the rules send to the VPN off the
    /// main link while it is down, and nothing else is held.
    #[test]
    fn a_fresh_user_starts_with_routed_sites_protected() {
        assert_eq!(LeakProtection::default(), LeakProtection::Sites);
        assert_eq!(
            protection_posture(Main, LeakProtection::default(), false),
            BlockRuleDestinations
        );
    }
}
