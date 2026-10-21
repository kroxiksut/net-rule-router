//! `nrr-tui` — the terminal interface.
//!
//! What the GUI does, minus the GUI's own settings, for a live terminal: a
//! machine reached over SSH, a server without a desktop, or a user who works in
//! the console. Interactive only — a pipe or a script is refused and pointed at
//! `nrr-cli`. Two renderers over one screen model: full-screen, and `--plain`
//! line mode for screen readers.

mod args;
mod backend;
mod block_backlog;
mod block_route;
mod elevation_prompt;
mod forwarded_traffic;
mod full;
mod i18n;
mod keys;
mod link;
mod local_network_offer;
mod notice_mutes;
mod paste;
mod plain;
mod platform;
mod primary_suggestion;
mod restore;
mod screens;
mod state;
#[cfg(test)]
mod testing;
mod view;
mod vpn_gateway_trust;
mod vpn_trust;

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
        _ => args::lang_of(&argv),
    };
    let system = platform::system_locale()
        .map(|port| port.ui_language_candidates())
        .unwrap_or_default();
    let texts = Texts::load(explicit_lang.as_deref(), &system);
    let tui = tui_command();

    let mut options = match parsed {
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

    // What the Settings screen saved adds to what the command line asked.
    let prefs_path = screens::settings::prefs::default_path();
    let saved = prefs_path
        .as_deref()
        .map(screens::settings::prefs::load)
        .unwrap_or_default();
    options.plain |= saved.plain;
    options.no_color |= saved.no_color;
    options.ascii |= saved.ascii;

    // Under `sudo -E` the path is the user's own folder: a root-owned file
    // there would be unreadable for them, so root only reads.
    let save_to = prefs_path.filter(|_| !platform::edits_baseline());
    match run(&options, &texts, saved, save_to) {
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

fn run(
    options: &Options,
    texts: &Texts,
    saved: screens::settings::TuiPrefs,
    prefs_path: Option<std::path::PathBuf>,
) -> std::io::Result<()> {
    // The client's stderr trace would land in the middle of the picture, or in
    // the middle of what a screen reader is reading.
    nrr_ipc_client::silence_diagnostics();
    // Before the first connection: the handshake carries what this client is.
    nrr_ipc_client::declare_client_kind(nrr_shared::ipc_payloads::ContractNegotiateClientKind::Tui);
    let client = Arc::new(ServiceIpcClient::start());
    let shared: Arc<dyn IpcClient> = client.clone();
    let (tx, events) = std::sync::mpsc::channel();
    // Line mode reads every line on its own input thread, which would take the
    // password from the agent; it is told how to start elevated instead.
    let prompt_agent = if options.plain {
        None
    } else {
        platform::terminal_prompt_agent()
    };
    let backend =
        Backend::spawn_with_prompt_agent(shared, platform::service_control, tx, prompt_agent)?;

    let first = if options.wizard {
        ScreenId::Wizard
    } else {
        ScreenId::Status
    };
    let mut app = AppState::new(first, options.bell);
    app.settings.prefs = saved;
    app.settings.prefs_path = prefs_path;
    app.rules.baseline = platform::edits_baseline();
    screens::rules::on_texts(&mut app, texts);
    // The baseline's editor is not the user whose folder and files these are;
    // a root-owned copy in their profile would also lock the GUI out of it.
    if !app.rules.baseline {
        app.rules.settings_file = nrr_shared::user_settings::UserSettingsStore::open()
            .ok()
            .map(|store| store.path().to_path_buf());
    }
    // The setup offers the rule set of the region the system is set to.
    app.wizard.locale = platform::system_locale()
        .map(|port| port.ui_language_candidates())
        .unwrap_or_default();
    if options.wizard {
        app.wizard.opened_by_request();
    }
    start_licence_and_sheet(&mut app, texts);
    app.delivery_gaps = delivery_gaps();
    app.rules_need_a_sign_in = platform::rules_need_a_windows_sign_in();
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

/// Parts of the package this binary reads that are not beside it. A user's own
/// locale file does not count: the package still lacks the others.
fn delivery_gaps() -> Vec<&'static str> {
    let mut gaps = Vec::new();
    if screens::rules::presets_root().is_none() {
        gaps.push("presets");
    }
    let bundled_locale = nrr_shared::load_locale_state()
        .reports
        .iter()
        .any(|report| {
            report.source == nrr_shared::LocaleSource::Bundled
                && report.status != nrr_shared::LocaleLoadStatus::Rejected
        });
    if !bundled_locale {
        gaps.push("locales");
    }
    gaps
}

/// What the user's settings say about the agreement, and the installer's
/// answer sheet. Without the user's own settings file (`sudo`) the agreement is
/// asked every time rather than recorded in root's profile.
fn start_licence_and_sheet(app: &mut AppState, texts: &Texts) {
    let read = app
        .rules
        .settings_file
        .clone()
        .map(|file| nrr_shared::user_settings::UserSettingsStore::at(file).load());
    app.settings_unreadable = matches!(read, Some(Err(_)));
    let accepted = read
        .and_then(Result::ok)
        .flatten()
        .map_or(0, |settings| settings.accepted_eula);
    let executable = std::env::current_exe().ok();
    let candidates = nrr_shared::first_run_sheet::candidate_paths(
        executable.as_deref().and_then(std::path::Path::parent),
        nrr_platform_api::paths::machine_first_run_dir().as_deref(),
    );
    let machine_files = platform::machine_files();
    let sheet = nrr_shared::first_run_sheet::search(&candidates, &|path| {
        machine_files.untrusted_because(path)
    })
    .found
    .map(|loaded| loaded.answers);
    app.wizard.at_startup(accepted, texts.language(), sheet);
    if app.wizard.licence_pending() {
        app.screen = ScreenId::Wizard;
    }
}
