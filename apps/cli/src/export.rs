//! `diag export` — ask the service for a diagnostic archive.
//!
//! The console does not build the archive. It asks the service to, and prints
//! where the service put it. That is the whole design: the application already
//! has this button, and two assemblers of the same archive would drift until the
//! file a user attaches to a report depends on which surface produced it.
//!
//! Consequently this is the one verb that needs a running service — and it says
//! so plainly rather than degrading into a locally-assembled approximation.

use std::time::Duration;

use nrr_ipc_client::{IpcClientError, ServiceIpcClient};
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{DiagnosticsExportArchiveRequest, DiagnosticsExportArchiveResponse};

use crate::exit;

/// How long to wait for the archive. Generous: the service walks logs, audit
/// and storage to build it, and a support archive is worth waiting for.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(120);

/// How long to wait for the connection itself before concluding the service is
/// not answering. Short: this is a liveness question, not the work.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub fn run(exe: &str) -> u8 {
    // Introduce ourselves as the console BEFORE connecting: on Unix this
    // declaration is the only thing that distinguishes us from the application,
    // and it can only ever narrow what we are allowed to ask for.
    nrr_ipc_client::declare_client_kind(
        nrr_shared::ipc_payloads::ContractNegotiateClientKind::Console,
    );
    let client = ServiceIpcClient::start();
    if !wait_until_connected(&client) {
        eprintln!(
            "The {} service is not answering.",
            nrr_shared::product_identity::PRODUCT_NAME
        );
        eprintln!("Check that it is installed and running: {exe} status");
        return exit::NOT_RESPONDING;
    }

    // Built from the SSOT type rather than a hand-written object. Every field
    // of the request carries `serde(default)`, so a key spelled by hand is not
    // rejected — it is dropped and replaced by the default, silently, and the
    // archive the user attaches is missing the section they asked for. The
    // struct cannot be spelled wrong.
    let request = match serde_json::to_value(DiagnosticsExportArchiveRequest {
        include_logs: true,
        include_audit_summary: true,
        include_troubleshooting_playbooks: true,
        ..DiagnosticsExportArchiveRequest::default()
    }) {
        Ok(value) => value,
        Err(e) => {
            eprintln!("Could not build the export request: {e}");
            return exit::FAILED;
        }
    };
    match client.call(
        IpcOperationName::DiagnosticsExportArchive,
        request,
        EXPORT_TIMEOUT,
    ) {
        Ok(payload) => report_archive(&payload),
        Err(err) => report_failure(err, exe),
    }
}

/// Poll until the background worker reports a live connection, or the budget
/// runs out. The client connects asynchronously, so a call issued immediately
/// would fail for a reason ("not connected") that says nothing about the
/// service.
fn wait_until_connected(client: &ServiceIpcClient) -> bool {
    let deadline = std::time::Instant::now() + CONNECT_TIMEOUT;
    loop {
        match client.connection_status() {
            nrr_ipc_client::ConnectionStatus::Connected => return true,
            // Both are terminal for this one call: the archive comes from a
            // RUNNING service, and waiting out the budget would only delay the
            // same answer.
            nrr_ipc_client::ConnectionStatus::ServiceStopped
            | nrr_ipc_client::ConnectionStatus::NotInstalled
            | nrr_ipc_client::ConnectionStatus::Refused { .. } => return false,
            _ => {}
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn report_archive(payload: &serde_json::Value) -> u8 {
    // Same reason as the request: read through the type, so a renamed field
    // fails to compile here instead of printing an empty path at the user.
    let response: DiagnosticsExportArchiveResponse = match serde_json::from_value(payload.clone()) {
        Ok(response) => response,
        Err(e) => {
            eprintln!("The service answered with something this console cannot read: {e}");
            return exit::FAILED;
        }
    };
    if response.archive_path.is_empty() {
        eprintln!("The service reported success but named no archive.");
        return exit::FAILED;
    }
    println!("Diagnostic archive written.");
    println!("  path:  {}", response.archive_path);
    println!("  size:  {} bytes", response.size_bytes);
    exit::SUCCESS
}

fn report_failure(err: IpcClientError, exe: &str) -> u8 {
    match err {
        IpcClientError::ServerError { code, message, .. } => {
            eprintln!("The service refused the export: {message}");
            // A refusal by code is the service's own judgement; the console
            // reports it rather than reinterpreting it.
            eprintln!("  code: {code:?}");
            exit::FAILED
        }
        IpcClientError::Timeout => {
            eprintln!("The service did not finish the export in time.");
            eprintln!("It may still be writing; check the archives directory before retrying.");
            exit::NOT_RESPONDING
        }
        other => {
            eprintln!("Could not reach the service: {other:?}");
            eprintln!("Check that it is running: {exe} status");
            exit::NOT_RESPONDING
        }
    }
}
