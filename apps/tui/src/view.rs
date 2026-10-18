//! What a screen shows, independent of how it is drawn. Both renderers read
//! this model, so the full-screen picture and the line-mode transcript cannot
//! say different things.

use nrr_client_logic::Route;

/// How a piece of text is marked. A colour that means something is given
/// only with its words: a state colour by [`Segment::state`], a route colour by
/// [`Segment::route`]. The rest only set text apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Plain,
    /// Names and labels: bold, never coloured.
    Strong,
    /// Headings and table header rows.
    Accent,
    /// Hints and secondary text; plain without colour.
    Muted,
    /// The name of the main route.
    RoutePrimary,
    /// The name of the additional route.
    RouteSecondary,
    /// The row under the cursor, which also carries the `>` marker.
    Selected,
    Good,
    Caution,
    Bad,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub text: String,
    pub tone: Tone,
}

impl Segment {
    pub fn plain(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            tone: Tone::Plain,
        }
    }

    pub fn strong(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            tone: Tone::Strong,
        }
    }

    pub fn accent(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            tone: Tone::Accent,
        }
    }

    pub fn muted(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            tone: Tone::Muted,
        }
    }

    /// The row under the cursor; the caller puts the `>` marker in `text`.
    pub fn selected(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            tone: Tone::Selected,
        }
    }

    /// A route's name; the colour only repeats it.
    pub fn route(name: impl Into<String>, route: Route) -> Self {
        Self {
            text: name.into(),
            tone: match route {
                Route::Primary => Tone::RoutePrimary,
                Route::Secondary => Tone::RouteSecondary,
            },
        }
    }

    /// `name` marked as its route when `slug` is one of the two; plain
    /// otherwise (a block, no route, an unknown slug).
    pub fn route_slug(name: impl Into<String>, slug: &str) -> Self {
        match Route::from_slug(slug) {
            Some(route) => Self::route(name, route),
            None => Self::plain(name),
        }
    }

    /// A state word ("Available", "Rules not applied"); the colour only
    /// repeats what the word says.
    pub fn state(word: impl Into<String>, tone: StateTone) -> Self {
        Self {
            text: word.into(),
            tone: match tone {
                StateTone::Good => Tone::Good,
                StateTone::Caution => Tone::Caution,
                StateTone::Bad => Tone::Bad,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateTone {
    Good,
    Caution,
    Bad,
}

/// One line of text; a renderer wraps it, never cuts it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ViewLine {
    pub segments: Vec<Segment>,
}

impl ViewLine {
    pub fn new(segments: Vec<Segment>) -> Self {
        Self { segments }
    }

    pub fn text(text: impl Into<String>) -> Self {
        Self::new(vec![Segment::plain(text)])
    }

    /// The words of the line, without marking — what line mode prints.
    pub fn plain_text(&self) -> String {
        self.segments.iter().map(|s| s.text.as_str()).collect()
    }
}

/// A titled part of a screen. The title is text, so nothing depends on frame
/// lines to say where a panel starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Panel {
    pub title: String,
    pub lines: Vec<ViewLine>,
    /// A growing list (the notice feed): it scrolls and takes the focus on
    /// Tab, and line mode prints its new entries rather than re-reading it.
    pub feed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScreenView {
    pub title: String,
    pub panels: Vec<Panel>,
}
