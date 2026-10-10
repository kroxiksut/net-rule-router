//! The screens, in the order of the design's table. The map follows the GUI's
//! sections, so one piece of advice from the documentation works in both.

mod binding;
mod choice;
pub mod inspect;
pub mod interfaces;
pub mod overlaps;
pub mod rules;
pub mod settings;
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
    /// What was blocked while the additional route was down; opens from the
    /// trace.
    OutageBlocks,
    Cache,
    Diagnostics,
    Settings,
}

impl ScreenId {
    /// Navigation order: the menu's, each sub-screen right after its parent.
    pub const ALL: [Self; 11] = [
        Self::Status,
        Self::Wizard,
        Self::Interfaces,
        Self::Rules,
        Self::Overlaps,
        Self::Suggestions,
        Self::Trace,
        Self::OutageBlocks,
        Self::Cache,
        Self::Diagnostics,
        Self::Settings,
    ];

    /// The screens with a digit key, in the menu's order.
    const KEYED: [Self; 10] = [
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
            Self::OutageBlocks => keys::SCREEN_OUTAGE_BLOCKS,
            Self::Cache => keys::SCREEN_CACHE,
            Self::Diagnostics => keys::SCREEN_DIAGNOSTICS,
            Self::Settings => keys::SCREEN_SETTINGS,
        }
    }

    /// The jump key shown beside the menu item: `1`–`9`, then `0`. A
    /// sub-screen has none: it opens from its parent.
    pub fn hotkey(self) -> Option<char> {
        let at = Self::KEYED.iter().position(|s| *s == self)?;
        char::from_digit(((at + 1) % 10) as u32, 10)
    }

    pub fn from_hotkey(c: char) -> Option<Self> {
        Self::KEYED.into_iter().find(|s| s.hotkey() == Some(c))
    }
}

/// One row of the menu: a screen, or a Settings section under Settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MenuItem {
    Screen(ScreenId),
    Section(settings::Category),
}

impl MenuItem {
    /// Every row Up and Down walk through: each sub-screen right after its
    /// parent, the Settings sections right after Settings.
    fn walk() -> impl Iterator<Item = Self> {
        ScreenId::ALL.into_iter().flat_map(|id| {
            let sections: &[settings::Category] = if id == ScreenId::Settings {
                &settings::Category::ALL
            } else {
                &[]
            };
            std::iter::once(Self::Screen(id)).chain(sections.iter().map(|c| Self::Section(*c)))
        })
    }

    /// The row the interface is on.
    pub fn current(app: &AppState) -> Self {
        match (app.screen, app.settings.open) {
            (ScreenId::Settings, Some(category)) => Self::Section(category),
            (screen, _) => Self::Screen(screen),
        }
    }

    /// The rows the menu shows: the screens with a key, an open sub-screen
    /// under its parent, and the Settings sections while Settings is open.
    pub fn shown(app: &AppState) -> Vec<Self> {
        Self::walk()
            .filter(|item| match item {
                Self::Screen(id) => id.hotkey().is_some() || *id == app.screen,
                Self::Section(_) => app.screen == ScreenId::Settings,
            })
            .collect()
    }
}

/// Up or Down in the menu: the next row of the walk, round at the ends.
pub fn menu_step(app: &mut AppState, forward: bool) {
    let walk: Vec<MenuItem> = MenuItem::walk().collect();
    let here = MenuItem::current(app);
    let at = walk.iter().position(|item| *item == here).unwrap_or(0);
    let next = if forward {
        (at + 1) % walk.len()
    } else {
        (at + walk.len() - 1) % walk.len()
    };
    match walk[next] {
        MenuItem::Screen(ScreenId::Settings) => {
            settings::show_sections(app);
            app.open(ScreenId::Settings);
        }
        MenuItem::Screen(id) => app.open(id),
        MenuItem::Section(category) => {
            settings::show_sections(app);
            app.open(ScreenId::Settings);
            settings::open_category(app, category);
        }
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
        ScreenId::OutageBlocks => &inspect::outage::OutageScreen,
        ScreenId::Cache => &inspect::cache::CacheScreen,
        ScreenId::Diagnostics => &inspect::diagnostics::DiagnosticsScreen,
        ScreenId::Settings => &settings::SettingsScreen,
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
        let keys: String = ScreenId::ALL.iter().filter_map(|s| s.hotkey()).collect();
        assert_eq!(keys, "1234567890");
        for s in ScreenId::ALL {
            if let Some(key) = s.hotkey() {
                assert_eq!(ScreenId::from_hotkey(key), Some(s));
            }
        }
        assert_eq!(ScreenId::OutageBlocks.hotkey(), None);
        let walk: Vec<MenuItem> = MenuItem::walk().collect();
        let trace = walk
            .iter()
            .position(|i| *i == MenuItem::Screen(ScreenId::Trace))
            .unwrap_or_default();
        assert_eq!(walk[trace + 1], MenuItem::Screen(ScreenId::OutageBlocks));
    }

    #[test]
    fn the_settings_sections_follow_settings_in_the_menu() {
        let mut app = AppState::new(ScreenId::Diagnostics, false);
        menu_step(&mut app, true);
        assert_eq!(
            MenuItem::current(&app),
            MenuItem::Screen(ScreenId::Settings)
        );
        let shown = MenuItem::shown(&app);
        assert_eq!(shown.len(), 10 + settings::Category::ALL.len());
        assert_eq!(
            shown[10],
            MenuItem::Section(settings::Category::Notifications)
        );

        for category in settings::Category::ALL {
            menu_step(&mut app, true);
            assert_eq!(app.screen, ScreenId::Settings);
            assert_eq!(MenuItem::current(&app), MenuItem::Section(category));
        }
        menu_step(&mut app, true);
        assert_eq!(app.screen, ScreenId::Status);
        assert_eq!(MenuItem::shown(&app).len(), 10, "folded away again");

        menu_step(&mut app, false);
        assert_eq!(
            MenuItem::current(&app),
            MenuItem::Section(settings::Category::Terminal)
        );
        for _ in settings::Category::ALL {
            menu_step(&mut app, false);
        }
        assert_eq!(
            MenuItem::current(&app),
            MenuItem::Screen(ScreenId::Settings)
        );
        assert_eq!(app.settings.open, None, "back on the list of sections");
    }
}
