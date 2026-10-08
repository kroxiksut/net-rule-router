//! Line mode (`--plain`): no redrawing and no cursor jumps. Every change is a
//! new line, the menu is numbered, input is a question answered with Enter —
//! the form screen readers in a console read reliably.

use std::io::{self, BufRead, Write};
use std::sync::mpsc::{channel, Receiver};
use std::thread;
use std::time::Instant;

use crate::backend::{Backend, BackendEvent, Command};
use crate::i18n::Texts;
use crate::keys;
use crate::screens::{connection_lines, screen, ScreenId};
use crate::state::{AppState, Effect, Notice, NoticeLevel};
use crate::view::ViewLine;

pub struct PlainSession<W: Write> {
    out: W,
    /// What the user last saw of the current screen, line by line, to print
    /// only what changed.
    seen: Vec<String>,
    /// [`AppState::notice_count`] when notices were last printed.
    notices_seen: usize,
}

impl<W: Write> PlainSession<W> {
    pub fn new(out: W) -> Self {
        Self {
            out,
            seen: Vec::new(),
            notices_seen: 0,
        }
    }

    #[cfg(test)]
    pub fn into_inner(self) -> W {
        self.out
    }

    pub fn start(&mut self, app: &AppState, texts: &Texts) -> io::Result<()> {
        self.notices_seen = app.notice_count;
        self.print_menu(texts)?;
        self.print_screen(app, texts)?;
        self.prompt(app, texts)
    }

    /// After a change from the service: new notices, then the lines of the
    /// screen that differ from what was printed.
    pub fn changed(&mut self, app: &AppState, texts: &Texts) -> io::Result<()> {
        let fresh = app.notice_count.saturating_sub(self.notices_seen);
        for notice in app
            .notices
            .iter()
            .skip(app.notices.len().saturating_sub(fresh))
        {
            writeln!(self.out, "{}", notice_line(notice, texts))?;
        }
        self.notices_seen = app.notice_count;

        let now = summary(app, texts);
        let mut before = std::mem::take(&mut self.seen);
        for line in &now {
            match before.iter().position(|b| b == line) {
                Some(i) => {
                    before.swap_remove(i);
                }
                None => writeln!(self.out, "{line}")?,
            }
        }
        self.seen = now;
        self.out.flush()
    }

    /// One answer to the prompt.
    pub fn input(&mut self, line: &str, app: &mut AppState, texts: &Texts) -> io::Result<()> {
        let answer = line.trim();
        // A screen waiting for its own answer reads it first: a number there
        // picks an option, it does not open a screen.
        let current = screen(app.screen);
        if current.captures_keys(app) && current.on_line(app, answer) {
            self.print_screen(app, texts)?;
            return self.prompt(app, texts);
        }
        let mut chars = answer.chars();
        let target = match (chars.next(), chars.next()) {
            (Some(c), None) => ScreenId::from_hotkey(c),
            _ => None,
        };
        match answer {
            "" => self.print_screen(app, texts)?,
            "q" => {
                app.request_quit();
                if app.quit {
                    return self.out.flush();
                }
                self.print_screen(app, texts)?;
            }
            "h" | "?" => self.print_help(app, texts)?,
            _ => match target {
                Some(target) => {
                    app.open(target);
                    self.print_screen(app, texts)?;
                }
                None if screen(app.screen).on_line(app, answer) => {
                    self.print_screen(app, texts)?;
                }
                None => writeln!(
                    self.out,
                    "{}",
                    texts.fill(keys::PLAIN_UNKNOWN, &[("input", answer)])
                )?,
            },
        }
        self.prompt(app, texts)
    }

    fn print_menu(&mut self, texts: &Texts) -> io::Result<()> {
        writeln!(self.out, "{}:", texts.get(keys::MENU_TITLE))?;
        for id in ScreenId::ALL {
            writeln!(self.out, "  {}. {}", id.hotkey(), texts.get(id.title()))?;
        }
        Ok(())
    }

    fn print_screen(&mut self, app: &AppState, texts: &Texts) -> io::Result<()> {
        let view = screen(app.screen).view(app, texts);
        writeln!(self.out)?;
        writeln!(
            self.out,
            "{}",
            texts.fill(keys::PLAIN_SCREEN, &[("name", &view.title)])
        )?;
        for line in connection_lines(app, texts) {
            writeln!(self.out, "{}", line.plain_text())?;
        }
        for panel in &view.panels {
            writeln!(self.out, "{}:", panel.title)?;
            for line in &panel.lines {
                writeln!(self.out, "  {}", line.plain_text())?;
            }
        }
        self.print_commands(app, texts)?;
        self.seen = summary(app, texts);
        self.notices_seen = app.notice_count;
        Ok(())
    }

    fn print_help(&mut self, app: &AppState, texts: &Texts) -> io::Result<()> {
        writeln!(
            self.out,
            "{} — {}:",
            texts.get(keys::HELP_TITLE),
            texts.get(app.screen.title())
        )?;
        for k in [
            keys::PLAIN_HELP_NUMBER,
            keys::PLAIN_HELP_ENTER,
            keys::PLAIN_HELP_HELP,
            keys::HELP_QUIT,
        ] {
            writeln!(self.out, "  {}", texts.get(k))?;
        }
        self.print_commands(app, texts)?;
        self.print_menu(texts)
    }

    /// The screen's own commands, so line mode offers what its keys do.
    fn print_commands(&mut self, app: &AppState, texts: &Texts) -> io::Result<()> {
        let commands = screen(app.screen).plain_help();
        if commands.is_empty() {
            return Ok(());
        }
        writeln!(self.out, "{}:", texts.get(keys::PLAIN_COMMANDS))?;
        for &k in commands {
            writeln!(self.out, "  {}", texts.get(k))?;
        }
        Ok(())
    }

    fn prompt(&mut self, app: &AppState, texts: &Texts) -> io::Result<()> {
        let prompt = screen(app.screen)
            .plain_prompt(app)
            .unwrap_or(keys::PLAIN_PROMPT);
        writeln!(self.out, "{}", texts.get(prompt))?;
        self.out.flush()
    }

    pub fn bell(&mut self) -> io::Result<()> {
        self.out.write_all(b"\x07")?;
        self.out.flush()
    }
}

/// The screen as single lines that make sense on their own: the connection
/// line, then each line under its panel's title. The feed is left out: its
/// entries are printed as they arrive.
fn summary(app: &AppState, texts: &Texts) -> Vec<String> {
    let view = screen(app.screen).view(app, texts);
    connection_lines(app, texts)
        .iter()
        .map(ViewLine::plain_text)
        .chain(view.panels.iter().filter(|p| !p.feed).flat_map(|panel| {
            panel
                .lines
                .iter()
                .map(move |line| format!("{}: {}", panel.title, line.plain_text().trim()))
        }))
        .collect()
}

fn notice_line(notice: &Notice, texts: &Texts) -> String {
    let level = match notice.level {
        NoticeLevel::Warning => keys::LEVEL_WARNING,
        NoticeLevel::Info => keys::LEVEL_INFO,
    };
    format!("{}: {} — {}", texts.get(level), notice.title, notice.body)
}

enum Incoming {
    Backend(BackendEvent),
    /// A line typed, or `None` at the end of input.
    Line(Option<String>),
}

pub fn run(
    app: &mut AppState,
    texts: &Texts,
    backend: &Backend,
    events: Receiver<BackendEvent>,
) -> io::Result<()> {
    let (tx, incoming) = channel();
    let from_backend = tx.clone();
    thread::Builder::new()
        .name("nrr-tui-events".into())
        .spawn(move || {
            while let Ok(event) = events.recv() {
                if from_backend.send(Incoming::Backend(event)).is_err() {
                    return;
                }
            }
        })?;
    thread::Builder::new()
        .name("nrr-tui-input".into())
        .spawn(move || {
            for line in io::stdin().lock().lines() {
                let Ok(line) = line else { break };
                if tx.send(Incoming::Line(Some(line))).is_err() {
                    return;
                }
            }
            let _ = tx.send(Incoming::Line(None));
        })?;

    let mut session = PlainSession::new(io::stdout());
    // Replaced when the user picks another language.
    let mut current = texts.clone();
    session.start(app, &current)?;
    while !app.quit {
        let texts = &current;
        match incoming.recv() {
            Ok(Incoming::Backend(event)) => {
                let shown = app.screen;
                for effect in app.apply(event, texts, Instant::now()) {
                    match effect {
                        Effect::Refresh => backend.send(Command::Refresh),
                        Effect::Bell => session.bell()?,
                    }
                }
                backend.send_outbox(&mut app.outbox);
                if app.screen == shown {
                    session.changed(app, texts)?;
                } else {
                    // The service opened another screen (the first-run setup):
                    // announce it whole, with its prompt.
                    session.input("", app, texts)?;
                }
            }
            Ok(Incoming::Line(Some(line))) => {
                session.input(&line, app, texts)?;
                backend.send_outbox(&mut app.outbox);
                if let Some(language) = app.language_change.take() {
                    current = Texts::load(Some(&language), &[]);
                    session.start(app, &current)?;
                }
            }
            Ok(Incoming::Line(None)) | Err(_) => app.quit = true,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
