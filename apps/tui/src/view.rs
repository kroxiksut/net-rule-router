//! What a screen shows, independent of how it is drawn. Both renderers read
//! this model, so the full-screen picture and the line-mode transcript cannot
//! say different things.

/// How a piece of text is marked. Colour is reserved for state words: the only
/// way to get a coloured tone is [`Segment::state`], which takes the word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Plain,
    /// Headings and names: bold, never coloured.
    Strong,
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
