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

    let request = serde_json::json!({
        "include-logs": true,
        "include-audit-summary": true,
        "include-troubleshooting-playbooks": true,
    });
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
            | nrr_ipc_client::ConnectionStatus::NotInstalled => return false,
            _ => {}
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn report_archive(payload: &serde_json::Value) -> u8 {
    let path = payload
        .get("archive-path")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if path.is_empty() {
        eprintln!("The service reported success but named no archive.");
        return exit::FAILED;
    }
    println!("Diagnostic archive written.");
    println!("  path:  {path}");
    if let Some(size) = payload.get("size-bytes").and_then(|v| v.as_u64()) {
        println!("  size:  {size} bytes");
    }
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
