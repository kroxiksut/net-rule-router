//! A screen that is not built yet says so in words, under its own title.

use super::Screen;
use crate::i18n::Texts;
use crate::keys;
use crate::state::AppState;
use crate::view::{Panel, ScreenView, ViewLine};

pub struct Placeholder;

impl Screen for Placeholder {
    fn view(&self, app: &AppState, texts: &Texts) -> ScreenView {
        let title = texts.get(app.screen.title());
        ScreenView {
            title: title.clone(),
            panels: vec![Panel {
                title,
                lines: vec![ViewLine::text(texts.get(keys::PLACEHOLDER))],
                feed: false,
            }],
        }
    }
}
