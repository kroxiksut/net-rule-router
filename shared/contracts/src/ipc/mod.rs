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
}

impl IpcClientProfile {
    pub const ALL: [Self; 3] = [
        Self::GuiInteractive,
        Self::TrayLightweight,
        Self::AdminConsole,
    ];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::GuiInteractive => "gui-interactive",
            Self::TrayLightweight => "tray-lightweight",
            Self::AdminConsole => "admin-console",
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
            Self::GuiInteractive | Self::TrayLightweight => true,
            Self::AdminConsole => matches!(
                class,
                C::ReadSnapshot | C::DiagnosticQuery | C::DiagnosticAction
            ),
        }
    }

    /// The narrower of two profiles: what the OS proved, and what the caller
    /// declared. Declaration never widens.
    pub fn narrowed_by(self, declared: Self) -> Self {
        if self.capability_rank() <= declared.capability_rank() {
            self
        } else {
            declared
        }
    }

    /// How much a profile may do, as a total order.
    ///
    /// The console is narrowest by class ([`Self::permits`]). Tray sits below
    /// GUI because of `allowed_clients`: every operation open to the tray is
    /// also open to the GUI, and some are GUI-only. That containment is what
    /// makes the order real rather than invented, so it is held by
    /// `no_operation_is_open_to_the_tray_but_closed_to_the_gui` — add a
    /// tray-only operation and the order stops being true, which is the moment
    /// this function has to change too.
    ///
    /// Why it matters that the order is total: a proven GUI that DECLARES
    /// itself the tray used to keep GUI capabilities, because anything other
    /// than the console fell through to "whatever the OS proved". A caller
    /// asking to be treated more narrowly should be taken at its word — that is
    /// the whole point of reading a declaration that can never widen.
    const fn capability_rank(self) -> u8 {
        match self {
            Self::AdminConsole => 0,
            Self::TrayLightweight => 1,
            Self::GuiInteractive => 2,
        }
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
