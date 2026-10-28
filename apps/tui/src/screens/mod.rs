//! The screens, in the order of the design's table. The map follows the GUI's
//! sections, so one piece of advice from the documentation works in both.

pub mod app_groups;
pub(crate) mod binding;
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

#[cfg(test)]
pub use status::state_word_keys;
pub use status::{connection_lines, recovery_hints};
pub(crate) use status::{revision_rejected, track_policy_idle, vpn_split};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScreenId {
    Status,
    Wizard,
    Interfaces,
    Rules,
    /// Programs and virtual machines put on a route; opens from the rules.
    AppGroups,
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
    pub const ALL: [Self; 12] = [
        Self::Status,
        Self::Wizard,
        Self::Interfaces,
        Self::Rules,
        Self::AppGroups,
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
            Self::AppGroups => keys::SCREEN_APP_GROUPS,
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

    /// Whether a text field has the focus, so a paste can go into it.
    fn text_target(&self, _app: &AppState) -> crate::paste::TextTarget {
        crate::paste::TextTarget::None
    }

    /// A paste into a field that takes lines, taken whole; `true` when used.
    /// Otherwise the paste is typed key by key.
    fn on_paste(&self, _app: &mut AppState, _pasted: &str) -> bool {
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

    /// Line mode printed the screen: a number typed next means an item as
    /// printed now, whatever the list has become by then.
    fn on_printed(&self, _app: &mut AppState) {}
}

/// Where line mode's item `n` (from 1) stands now. `printed` is the list as
/// it was printed, `now` as it is, both by an identity of the item; nothing
/// printed yet means the list as it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Numbered {
    At(usize),
    /// The item printed under that number has left the list.
    Gone,
    /// No item was printed under that number.
    NoSuch,
}

/// A letter that changes something, pressed from the menu, only gives the list
/// the focus: the second press acts on a row the user has seen chosen.
/// `true` when this press was spent on the focus.
pub fn focus_list_first(app: &mut AppState) -> bool {
    if app.focus == crate::state::Focus::Feed {
        return false;
    }
    app.focus = crate::state::Focus::Feed;
    true
}

pub fn numbered_now(printed: &[String], now: &[String], n: usize) -> Numbered {
    let Some(at) = n.checked_sub(1) else {
        return Numbered::NoSuch;
    };
    if printed.is_empty() {
        return if at < now.len() {
            Numbered::At(at)
        } else {
            Numbered::NoSuch
        };
    }
    match printed.get(at) {
        None => Numbered::NoSuch,
        Some(item) => now
            .iter()
            .position(|x| x == item)
            .map_or(Numbered::Gone, Numbered::At),
    }
}

pub fn screen(id: ScreenId) -> &'static dyn Screen {
    match id {
        ScreenId::Status => &status::StatusScreen,
        ScreenId::Wizard => &wizard::WizardScreen,
        ScreenId::Interfaces => &interfaces::InterfacesScreen,
        ScreenId::Rules => &rules::RulesScreen,
        ScreenId::AppGroups => &app_groups::AppGroupsScreen,
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

    fn list(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    /// A number names what was printed under it, wherever that item went.
    #[test]
    fn a_typed_number_follows_the_printed_item() {
        let printed = list(&["a", "b", "c"]);
        let now = list(&["new", "a", "c", "b"]);
        assert_eq!(numbered_now(&printed, &now, 2), Numbered::At(3));
        assert_eq!(
            numbered_now(&printed, &list(&["a", "c"]), 2),
            Numbered::Gone
        );
        assert_eq!(numbered_now(&printed, &now, 4), Numbered::NoSuch);
        assert_eq!(numbered_now(&printed, &now, 0), Numbered::NoSuch);
        assert_eq!(numbered_now(&[], &now, 4), Numbered::At(3));
        assert_eq!(numbered_now(&[], &now, 5), Numbered::NoSuch);
    }

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
        assert_eq!(ScreenId::AppGroups.hotkey(), None);
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
