//! The screens, in the order of the design's table. The map follows the GUI's
//! sections, so one piece of advice from the documentation works in both.

mod binding;
mod choice;
pub mod inspect;
pub mod interfaces;
pub mod overlaps;
mod placeholder;
pub mod rules;
mod status;
pub mod suggestions;
pub mod wizard;

use crate::i18n::{Key, Texts};
use crate::keys;
use crate::state::AppState;
use crate::view::ScreenView;

pub use status::connection_lines;
#[cfg(test)]
pub use status::state_word_keys;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScreenId {
    Status,
    Wizard,
    Interfaces,
    Rules,
    Overlaps,
    Suggestions,
    Trace,
    Cache,
    Diagnostics,
    Settings,
}

impl ScreenId {
    pub const ALL: [Self; 10] = [
        Self::Status,
        Self::Wizard,
        Self::Interfaces,
        Self::Rules,
        Self::Overlaps,
        Self::Suggestions,
        Self::Trace,
        Self::Cache,
        Self::Diagnostics,
        Self::Settings,
    ];

    pub fn title(self) -> Key {
        match self {
            Self::Status => keys::SCREEN_STATUS,
            Self::Wizard => keys::SCREEN_WIZARD,
            Self::Interfaces => keys::SCREEN_INTERFACES,
            Self::Rules => keys::SCREEN_RULES,
            Self::Overlaps => keys::SCREEN_OVERLAPS,
            Self::Suggestions => keys::SCREEN_SUGGESTIONS,
            Self::Trace => keys::SCREEN_TRACE,
            Self::Cache => keys::SCREEN_CACHE,
            Self::Diagnostics => keys::SCREEN_DIAGNOSTICS,
            Self::Settings => keys::SCREEN_SETTINGS,
        }
    }

    fn index(self) -> usize {
        Self::ALL.iter().position(|s| *s == self).unwrap_or(0)
    }

    /// The jump key shown beside the menu item: `1`–`9`, then `0`.
    pub fn hotkey(self) -> char {
        let n = (self.index() + 1) % 10;
        char::from_digit(n as u32, 10).unwrap_or('0')
    }

    pub fn from_hotkey(c: char) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.hotkey() == c)
    }

    pub fn next(self) -> Self {
        Self::ALL[(self.index() + 1) % Self::ALL.len()]
    }

    pub fn previous(self) -> Self {
        Self::ALL[(self.index() + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

/// What every screen provides: its picture, and the keys it adds to the
/// common ones in the help.
pub trait Screen {
    fn view(&self, app: &AppState, texts: &Texts) -> ScreenView;

    fn help(&self) -> &'static [Key] {
        &[]
    }

    /// Line mode's commands for this screen, printed under it and in its help.
    fn plain_help(&self) -> &'static [Key] {
        &[]
    }

    /// The screen came into view, or the service came back while it was:
    /// queue what it needs read.
    fn on_show(&self, _app: &mut AppState) {}

    /// Whether Tab can give this screen's content the focus.
    fn takes_focus(&self) -> bool {
        false
    }

    /// Whether the screen is taking typed text or waiting for an answer, so
    /// every key goes to it first.
    fn captures_keys(&self, _app: &AppState) -> bool {
        false
    }

    /// A key for the screen; `true` when it was used.
    fn on_key(&self, _app: &mut AppState, _key: crossterm::event::KeyEvent) -> bool {
        false
    }

    /// A line-mode answer the common commands did not take; `true` when used.
    fn on_line(&self, _app: &mut AppState, _line: &str) -> bool {
        false
    }

    /// Line mode's prompt while the screen waits for an answer of its own.
    fn plain_prompt(&self, _app: &AppState) -> Option<Key> {
        None
    }
}

pub fn screen(id: ScreenId) -> &'static dyn Screen {
    match id {
        ScreenId::Status => &status::StatusScreen,
        ScreenId::Wizard => &wizard::WizardScreen,
        ScreenId::Interfaces => &interfaces::InterfacesScreen,
        ScreenId::Rules => &rules::RulesScreen,
        ScreenId::Overlaps => &overlaps::OverlapsScreen,
        ScreenId::Suggestions => &suggestions::SuggestionsScreen,
        ScreenId::Trace => &inspect::trace::TraceScreen,
        ScreenId::Cache => &inspect::cache::CacheScreen,
        ScreenId::Diagnostics => &inspect::diagnostics::DiagnosticsScreen,
        _ => &placeholder::Placeholder,
    }
}

/// The keys every screen has, in the help's order.
pub const COMMON_HELP: &[Key] = &[
    keys::HELP_SCREENS,
    keys::HELP_MOVE,
    keys::HELP_OPEN,
    keys::HELP_PANELS,
    keys::HELP_HELP,
    keys::HELP_BACK,
    keys::HELP_QUIT,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hotkeys_run_one_to_nine_then_zero_and_back() {
        let keys: String = ScreenId::ALL.iter().map(|s| s.hotkey()).collect();
        assert_eq!(keys, "1234567890");
        for s in ScreenId::ALL {
            assert_eq!(ScreenId::from_hotkey(s.hotkey()), Some(s));
            assert_eq!(s.next().previous(), s);
        }
    }
}
