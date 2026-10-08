//! `nrr-tui` — the terminal interface.
//!
//! What the GUI does, minus the GUI's own settings, for a live terminal: a
//! machine reached over SSH, a server without a desktop, or a user who works in
//! the console. Interactive only — a pipe or a script is refused and pointed at
//! `nrr-cli`. Two renderers over one screen model: full-screen, and `--plain`
//! line mode for screen readers.

mod args;
mod backend;
mod full;
mod i18n;
mod keys;
mod link;
mod plain;
mod platform;
mod screens;
mod state;
#[cfg(test)]
mod testing;
mod view;

use std::io::IsTerminal;
use std::process::ExitCode;
use std::sync::Arc;

use nrr_ipc_client::{IpcClient, ServiceIpcClient};

use args::{ArgError, Env, Invocation, Options};
use backend::Backend;
use i18n::Texts;
use link::{console_command, tui_command};
use screens::ScreenId;
use state::AppState;

/// The terminal could not be set up, or failed while running.
const EXIT_FAILED: u8 = 1;
const EXIT_USAGE: u8 = 2;
/// Standard input or output is not a terminal.
const EXIT_NOT_INTERACTIVE: u8 = 3;

fn main() -> ExitCode {
    platform::restrict_dll_search();
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let no_color = std::env::var("NO_COLOR").ok();
    let plain = std::env::var("NRR_TUI_PLAIN").ok();
    let parsed = args::parse(
        &argv,
        Env {
            no_color: no_color.as_deref(),
            plain: plain.as_deref(),
        },
    );
    let explicit_lang = match &parsed {
        Ok(Invocation::Run(options)) => options.lang.clone(),
        _ => None,
    };
    let system = platform::system_locale()
        .map(|port| port.ui_language_candidates())
        .unwrap_or_default();
    let texts = Texts::load(explicit_lang.as_deref(), &system);
    let tui = tui_command();

    let options = match parsed {
        Ok(Invocation::Run(options)) => options,
        Ok(Invocation::Help) => {
            println!("{}", texts.fill(keys::USAGE, &[("tui", tui)]));
            return ExitCode::SUCCESS;
        }
        Ok(Invocation::Version) => {
            println!("{tui} {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Err(ArgError::Unknown(option)) => {
            eprintln!(
                "{}",
                texts.fill(
                    keys::UNKNOWN_OPTION,
                    &[("option", option.as_str()), ("tui", tui)]
                )
            );
            return ExitCode::from(EXIT_USAGE);
        }
        Err(ArgError::MissingValue(option)) => {
            eprintln!("{}", texts.fill(keys::MISSING_VALUE, &[("option", option)]));
            return ExitCode::from(EXIT_USAGE);
        }
    };

    // The Free/Pro line: automation reads through the console, not through this.
    if !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
        eprintln!(
            "{}",
            texts.fill(
                keys::NOT_INTERACTIVE,
                &[("tui", tui), ("console", console_command())]
            )
        );
        return ExitCode::from(EXIT_NOT_INTERACTIVE);
    }

    match run(&options, &texts) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "{}",
                texts.fill(keys::TERMINAL_FAILED, &[("error", error.to_string())])
            );
            ExitCode::from(EXIT_FAILED)
        }
    }
}

fn run(options: &Options, texts: &Texts) -> std::io::Result<()> {
    // The client's stderr trace would land in the middle of the picture, or in
    // the middle of what a screen reader is reading.
    nrr_ipc_client::silence_diagnostics();
    // Before the first connection: the handshake carries what this client is.
    nrr_ipc_client::declare_client_kind(nrr_shared::ipc_payloads::ContractNegotiateClientKind::Tui);
    let client = Arc::new(ServiceIpcClient::start());
    let shared: Arc<dyn IpcClient> = client.clone();
    let (tx, events) = std::sync::mpsc::channel();
    let backend = Backend::spawn(shared, platform::service_control, tx)?;

    let first = if options.wizard {
        ScreenId::Wizard
    } else {
        ScreenId::Status
    };
    let mut app = AppState::new(first, options.bell);
    app.rules.baseline = platform::edits_baseline();
    // The setup offers the rule set of the region the system is set to.
    app.wizard.locale = platform::system_locale()
        .map(|port| port.ui_language_candidates())
        .unwrap_or_default();
    if options.wizard {
        app.wizard.opened_by_request();
    }
    let result = if options.plain {
        plain::run(&mut app, texts, &backend, events)
    } else {
        full::run(
            &mut app,
            texts,
            full::RenderOptions {
                colour: !options.no_color,
                ascii: options.ascii,
            },
            &backend,
            &events,
        )
    };
    drop(backend);
    client.shutdown();
    result
}
