// GUI/tray/console <-> service IPC contract. The operation catalogue lives in
// `catalog`, the operation names in `operation_name`, the envelope and
// versioning rules in `protocol`.

use core::fmt;
use std::str::FromStr;

mod catalog;
mod operation_name;
mod protocol;

pub use catalog::{ipc_operation_catalog, ipc_operation_spec, IpcOperationSpec};
pub use operation_name::IpcOperationName;
pub use protocol::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpcInteractionClass {
    Query,
    Command,
    LongRunningOperation,
    EventUpdate,
    HealthCheck,
}

impl IpcInteractionClass {
    pub const ALL: [Self; 5] = [
        Self::Query,
        Self::Command,
        Self::LongRunningOperation,
        Self::EventUpdate,
        Self::HealthCheck,
    ];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Command => "command",
            Self::LongRunningOperation => "long-running-operation",
            Self::EventUpdate => "event-update",
            Self::HealthCheck => "health-check",
        }
    }
}

impl fmt::Display for IpcInteractionClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

/// What kind of client is on the other end, and therefore what it is allowed to
/// ask for.
///
/// A profile can only ever NARROW what an already-authorized caller may do — it
/// is not an authorization mechanism of its own. The real gates are the channel
/// ACL (Windows) or the socket directory's `0700` (Unix), the per-principal
/// partition, and the elevation requirement on privileged classes. What the
/// profile adds is that a client which has no business changing policy cannot do
/// so by accident or by bug.
///
/// How the profile is established differs per OS, and honestly so: Windows
/// PROVES it from the connecting executable, while `SO_PEERCRED` on Unix yields
/// uid/pid/gid but not the executable, so there the caller declares its kind at
/// handshake time and is held to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpcClientProfile {
    GuiInteractive,
    TrayLightweight,
    /// The administrative console: reads and diagnoses, never changes policy.
    AdminConsole,
    /// The terminal interface: the window's policy surface without the desktop
    /// shell. Asks for elevation on demand, in its own terminal.
    Tui,
}

impl IpcClientProfile {
    pub const ALL: [Self; 4] = [
        Self::GuiInteractive,
        Self::TrayLightweight,
        Self::AdminConsole,
        Self::Tui,
    ];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::GuiInteractive => "gui-interactive",
            Self::TrayLightweight => "tray-lightweight",
            Self::AdminConsole => "admin-console",
            Self::Tui => "tui",
        }
    }

    /// Whether a caller with this profile may invoke an operation of `class`.
    ///
    /// Only the console is restricted, and only to the classes that change
    /// nothing: it exists to inspect and to collect diagnostics. Keeping the
    /// rule here — rather than as a discipline inside the console's own code —
    /// is what makes it hold when the console has a bug.
    pub const fn permits(self, class: crate::ipc_transport::IpcOperationClass) -> bool {
        use crate::ipc_transport::IpcOperationClass as C;
        match self {
            Self::GuiInteractive | Self::TrayLightweight | Self::Tui => true,
            Self::AdminConsole => matches!(
                class,
                C::ReadSnapshot | C::DiagnosticQuery | C::DiagnosticAction
            ),
        }
    }

    /// Whether this caller may be shown an authentication prompt for a
    /// privileged operation. The window and the terminal have a person in front
    /// of them; the tray and the console do not ask. A terminal with no agent to
    /// answer (SSH without one) is refused by the authority itself.
    pub const fn may_prompt_for_elevation(self) -> bool {
        matches!(self, Self::GuiInteractive | Self::Tui)
    }

    /// The narrower of two profiles: what the OS proved, and what the caller
    /// declared. Declaration never widens.
    ///
    /// When neither contains the other (the tray and the terminal each hold
    /// operations the other lacks), the answer is the console, the only
    /// profile inside both.
    pub fn narrowed_by(self, declared: Self) -> Self {
        if self.is_within(declared) {
            self
        } else if declared.is_within(self) {
            declared
        } else {
            Self::AdminConsole
        }
    }

    /// Whether everything `self` may do, `other` may do too. The console is
    /// narrowest by class; tray and terminal sit inside the window by
    /// `allowed_clients`, as a contract test holds — a tray-only or
    /// terminal-only operation must change this too.
    const fn is_within(self, other: Self) -> bool {
        matches!(
            (self, other),
            (Self::AdminConsole, _)
                | (Self::GuiInteractive, Self::GuiInteractive)
                | (
                    Self::TrayLightweight,
                    Self::TrayLightweight | Self::GuiInteractive
                )
                | (Self::Tui, Self::Tui | Self::GuiInteractive)
        )
    }
}

impl fmt::Display for IpcClientProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl FromStr for IpcClientProfile {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "gui" | "gui-interactive" => Ok(Self::GuiInteractive),
            "tray" | "tray-lightweight" => Ok(Self::TrayLightweight),
            // The console's own spelling was missing here while `slug()`
            // emitted it — the parser could not read back what the SSOT
            // writes, so a profile round-trip through text silently failed for
            // the one profile whose whole purpose is to be RESTRICTED.
            "console" | "admin-console" => Ok(Self::AdminConsole),
            "tui" => Ok(Self::Tui),
            _ => Err("unknown ipc client profile"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpcExecutionModel {
    SyncReply,
    AsyncAccepted,
    AsyncWithOperationHandle,
}

impl IpcExecutionModel {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::SyncReply => "sync-reply",
            Self::AsyncAccepted => "async-accepted",
            Self::AsyncWithOperationHandle => "async-with-operation-handle",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpcLifecycleStage {
    BootstrapNegotiation,
    InitialSnapshotLoad,
    StatusSubscriptionOrPolling,
    MutationRequest,
    ResultAndStateRefresh,
}

impl IpcLifecycleStage {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::BootstrapNegotiation => "bootstrap-negotiation",
            Self::InitialSnapshotLoad => "initial-snapshot-load",
            Self::StatusSubscriptionOrPolling => "status-subscription-or-polling",
            Self::MutationRequest => "mutation-request",
            Self::ResultAndStateRefresh => "result-and-state-refresh",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpcUpdateModel {
    Polling,
    PushEvents,
    Hybrid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpcDataDeliveryKind {
    FullSnapshot,
    IncrementalUpdate,
}

const IPC_LIFECYCLE_STAGES: [IpcLifecycleStage; 5] = [
    IpcLifecycleStage::BootstrapNegotiation,
    IpcLifecycleStage::InitialSnapshotLoad,
    IpcLifecycleStage::StatusSubscriptionOrPolling,
    IpcLifecycleStage::MutationRequest,
    IpcLifecycleStage::ResultAndStateRefresh,
];

pub fn ipc_lifecycle_stages() -> &'static [IpcLifecycleStage] {
    &IPC_LIFECYCLE_STAGES
}

#[cfg(test)]
mod tests;
