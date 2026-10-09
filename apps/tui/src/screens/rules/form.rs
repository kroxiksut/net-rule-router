//! The add and edit form (the GUI's `RuleEditDialog` and `saveRule`).

use nrr_client_logic::rules_overlaps::overlaps_of_rule;
use nrr_client_logic::rules_table::{normalize_host_input, RuleRow, RuleType, TargetRoute};
use nrr_shared::platform_profile::PlatformProfile;
use nrr_shared::rules_json::FREE_MAX_RULES;
use nrr_shared::rules_overlap::{find_route_overlaps, OverlapRule, RouteOverlap};

use super::ace;
use super::apply::book_of;
use super::table::{Row, Table, Verdict, VerdictStatus};

/// The longest comment an import accepts (`MAX_INLINE_COMMENT_CHARS`).
const COMMENT_MAX: usize = 200;

/// The types the Add form offers, in the GUI's order; an application rule
/// only where this OS routes by application.
pub fn offered_types() -> Vec<RuleType> {
    let apps = PlatformProfile::current().supports.app_routing;
    [
        RuleType::Application,
        RuleType::Domain,
        RuleType::Zone,
        RuleType::ExactIp,
        RuleType::IpRange,
        RuleType::Subnet,
    ]
    .into_iter()
    .filter(|t| apps || *t != RuleType::Application)
    .collect()
}

/// The routes a rule can take.
pub fn route_options() -> [TargetRoute; 3] {
    [
        TargetRoute::Primary,
        TargetRoute::Secondary,
        TargetRoute::Block,
    ]
}

/// The length the GUI's field allows for a type (`matchValueMaxLength`).
fn max_len(rule_type: &RuleType) -> usize {
    match rule_type {
        RuleType::Zone | RuleType::Domain => 253,
        RuleType::ExactIp | RuleType::ExactIpv4 | RuleType::ExactIpv6 => 45,
        RuleType::Subnet => 51,
        RuleType::IpRange => 93,
        _ => 260,
    }
}

/// The characters the GUI's field lets through for a type (`matchValueRegex`).
fn accepts(rule_type: &RuleType, c: char) -> bool {
    let address = c.is_ascii_hexdigit() || c == '.' || c == ':';
    match rule_type {
        RuleType::ExactIp | RuleType::ExactIpv4 | RuleType::ExactIpv6 => address,
        RuleType::Subnet => address || c == '/' || c == ' ',
        RuleType::IpRange => address || c == ' ' || c == '-',
        _ => !c.is_control(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Type,
    Value,
    Route,
    /// "Unsure — check where it works": the rule's `?`.
    Verify,
    Comment,
    Enabled,
}

impl Field {
    pub const ALL: [Self; 6] = [
        Self::Type,
        Self::Value,
        Self::Route,
        Self::Verify,
        Self::Comment,
        Self::Enabled,
    ];

    fn step(self, by: isize) -> Self {
        let at = Self::ALL.iter().position(|f| *f == self).unwrap_or(0);
        let next = at.saturating_add_signed(by).min(Self::ALL.len() - 1);
        Self::ALL[next]
    }
}

/// A pair the rule in the form would take part in once saved, with each
/// side's route as the list names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Overlap {
    pub pair: RouteOverlap,
    pub winner_route: String,
    pub loser_route: String,
}

/// What decides the form's overlaps: its type, value, route and switch.
type OverlapInputs = (RuleType, String, TargetRoute, bool);

/// What a save did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Saved {
    Added {
        enabled: bool,
    },
    Updated,
    /// The value is refused; the form stays open on it.
    Refused,
    /// The same rule is already in the list, at this row.
    Duplicate(usize),
    Limit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Form {
    /// The row being edited; `None` adds one.
    pub editing: Option<usize>,
    pub rule_type: RuleType,
    pub value: String,
    pub route: TargetRoute,
    /// The `?` as ticked; [`Form::verify_offered`] says whether it applies.
    pub verify: bool,
    pub comment: String,
    pub enabled: bool,
    pub field: Field,
    /// Set by a save that found the same rule elsewhere.
    pub duplicate: Option<usize>,
    /// Rules of the other route the rule would overlap, and which one wins.
    pub overlaps: Vec<Overlap>,
    /// What `overlaps` was found for; found again only when it changes.
    overlaps_for: Option<OverlapInputs>,
}

impl Form {
    pub fn add() -> Self {
        Self {
            editing: None,
            rule_type: RuleType::Domain,
            value: String::new(),
            route: TargetRoute::Primary,
            verify: false,
            comment: String::new(),
            enabled: true,
            field: Field::Value,
            duplicate: None,
            overlaps: Vec::new(),
            overlaps_for: None,
        }
    }

    pub fn edit(table: &Table, master: usize) -> Option<Self> {
        let rule = &table.rows.get(master)?.rule;
        Some(Self {
            editing: Some(master),
            rule_type: rule.rule_type.clone(),
            value: rule.match_value.clone(),
            route: rule.target_route.clone(),
            verify: rule.verify,
            comment: rule.comment.clone(),
            enabled: rule.enabled,
            field: Field::Value,
            duplicate: None,
            overlaps: Vec::new(),
            overlaps_for: None,
        })
    }

    pub fn verdict(&self) -> Option<Verdict> {
        (!self.value.trim().is_empty()).then(|| Verdict::of(&self.rule_type, &self.value))
    }

    /// "Unsure" fits a domain or one address on a route, never a block.
    pub fn verify_offered(&self) -> bool {
        self.rule_type.allows_verify() && self.route != TargetRoute::Block
    }

    /// The `?` a save writes.
    fn saved_verify(&self) -> bool {
        self.verify && self.verify_offered()
    }

    /// The next field; "Unsure" is passed over while it does not apply.
    pub fn move_field(&mut self, by: isize) {
        self.field = self.field.step(by);
        if self.field == Field::Verify && !self.verify_offered() {
            self.field = self.field.step(by.signum());
        }
    }

    /// Left and Right on a choice; `by` is the direction.
    pub fn cycle(&mut self, by: isize) {
        match self.field {
            Field::Type => {
                let types = offered_types();
                let at = types.iter().position(|t| *t == self.rule_type);
                let next = match at {
                    Some(i) => (i as isize + by).rem_euclid(types.len() as isize) as usize,
                    None => 0,
                };
                if let Some(t) = types.get(next) {
                    self.set_type(t.clone());
                }
            }
            Field::Route => {
                let routes = route_options();
                let at = routes.iter().position(|r| *r == self.route);
                let next = match at {
                    Some(i) => (i as isize + by).rem_euclid(routes.len() as isize) as usize,
                    None => 0,
                };
                if let Some(r) = routes.get(next) {
                    self.route = r.clone();
                }
            }
            Field::Verify => self.verify = !self.verify,
            Field::Enabled => self.enabled = !self.enabled,
            Field::Value | Field::Comment => {}
        }
        self.duplicate = None;
    }

    /// A type that cannot carry `?` keeps it ticked but writes none.
    pub fn set_type(&mut self, rule_type: RuleType) {
        self.rule_type = rule_type;
    }

    pub fn type_char(&mut self, c: char) {
        match self.field {
            Field::Value => {
                if accepts(&self.rule_type, c)
                    && self.value.chars().count() < max_len(&self.rule_type)
                {
                    self.value.push(c);
                }
            }
            Field::Comment => {
                if !c.is_control() && self.comment.chars().count() < COMMENT_MAX {
                    self.comment.push(c);
                }
            }
            Field::Verify if c == ' ' => self.verify = !self.verify,
            Field::Enabled if c == ' ' => self.enabled = !self.enabled,
            _ => {}
        }
        self.duplicate = None;
    }

    pub fn backspace(&mut self) {
        match self.field {
            Field::Value => {
                self.value.pop();
            }
            Field::Comment => {
                self.comment.pop();
            }
            _ => {}
        }
        self.duplicate = None;
    }

    /// One line-mode answer for the current field; `true` once the last field
    /// was answered. An empty answer keeps what is shown; a number picks a
    /// choice.
    pub fn answer(&mut self, line: &str) -> bool {
        let line = line.trim();
        let pick = |count: usize| {
            line.parse::<usize>()
                .ok()
                .filter(|n| (1..=count).contains(n))
                .map(|n| n - 1)
        };
        match self.field {
            Field::Type => {
                let types = offered_types();
                if let Some(i) = pick(types.len()) {
                    self.set_type(types[i].clone());
                }
            }
            Field::Value if !line.is_empty() => {
                self.value = line.chars().take(max_len(&self.rule_type)).collect();
            }
            Field::Route => {
                let routes = route_options();
                if let Some(i) = pick(routes.len()) {
                    self.route = routes[i].clone();
                }
            }
            Field::Verify => match pick(2) {
                Some(0) => self.verify = true,
                Some(_) => self.verify = false,
                None => {}
            },
            Field::Comment if !line.is_empty() => {
                self.comment = line.chars().take(COMMENT_MAX).collect();
            }
            Field::Enabled => match pick(2) {
                Some(0) => self.enabled = true,
                Some(_) => self.enabled = false,
                None => {}
            },
            Field::Value | Field::Comment => {}
        }
        if self.field == Field::Enabled {
            return true;
        }
        self.move_field(1);
        false
    }

    /// Find the pairs the rule would take part in against the rest of the
    /// list; a keystroke that changes none of their inputs finds nothing new.
    pub fn refresh_overlaps(&mut self, table: &Table, include_subdomains: bool) {
        let inputs = (
            self.rule_type.clone(),
            self.value.clone(),
            self.route.clone(),
            self.enabled,
        );
        if self.overlaps_for.as_ref() == Some(&inputs) {
            return;
        }
        self.overlaps_for = Some(inputs);
        self.overlaps = match self.candidate(table) {
            Some(candidate) => overlaps_with(table, self.editing, candidate, include_subdomains),
            None => Vec::new(),
        };
    }

    /// The rule a save would write, under the id it would get; `None` while
    /// the value is refused.
    fn candidate(&self, table: &Table) -> Option<RuleRow> {
        let value = normalize_host_input(&self.rule_type, self.value.trim());
        let refused = Verdict::of(&self.rule_type, &value).status == VerdictStatus::Error;
        if value.is_empty() || refused {
            return None;
        }
        Some(RuleRow {
            id: self.saved_id(table),
            enabled: self.enabled,
            rule_type: self.rule_type.clone(),
            match_value: value,
            target_route: self.route.clone(),
            verify: self.saved_verify(),
            comment: String::new(),
            origin: None,
        })
    }

    /// An edited rule keeps its id; an added one takes the next free id.
    fn saved_id(&self, table: &Table) -> String {
        match self.editing.and_then(|i| table.rows.get(i)) {
            Some(row) => row.rule.id.clone(),
            None => table.next_free_id(),
        }
    }

    /// Write the form into the table (`saveRule`). A URL typed or pasted into
    /// a host value is cut to its host here, once the whole text is in: a
    /// terminal delivers a paste as keystrokes, and cutting on each one would
    /// stop at `https:`.
    pub fn save(&mut self, table: &mut Table) -> Saved {
        self.value = normalize_host_input(&self.rule_type, self.value.trim());
        if self
            .verdict()
            .is_none_or(|v| v.status == VerdictStatus::Error)
        {
            self.field = Field::Value;
            return Saved::Refused;
        }
        if self.editing.is_none() && table.user_rule_count() >= FREE_MAX_RULES {
            return Saved::Limit;
        }
        let mut comment = self.comment.clone();
        if comment.is_empty() && self.rule_type.is_hostlike() && !self.value.is_ascii() {
            let ace = ace::encode(&self.value);
            if ace != self.value {
                comment = format!("Punycode: {ace}");
            }
        }
        // Editing an app-authored rule makes it the user's own.
        let rule = RuleRow {
            id: self.saved_id(table),
            enabled: self.enabled,
            rule_type: self.rule_type.clone(),
            match_value: self.value.clone(),
            target_route: self.route.clone(),
            verify: self.saved_verify(),
            comment,
            origin: None,
        };
        if let Some(other) = table.duplicate_of(&rule, self.editing) {
            self.duplicate = Some(other);
            return Saved::Duplicate(other);
        }
        match self.editing {
            Some(i) if i < table.rows.len() => {
                let service_id = table.rows[i].service_id.take();
                table.rows[i] = Row {
                    service_id,
                    ..Row::new(rule)
                };
                table.select(i);
                Saved::Updated
            }
            _ => {
                table.rows.push(Row::new(rule));
                table.select(table.rows.len() - 1);
                Saved::Added {
                    enabled: self.enabled,
                }
            }
        }
    }
}

/// The pairs `candidate` takes part in once it stands in the list: in place of
/// the edited row, or after the last one.
fn overlaps_with(
    table: &Table,
    editing: Option<usize>,
    candidate: RuleRow,
    include_subdomains: bool,
) -> Vec<Overlap> {
    let id = candidate.id.clone();
    let mut rules: Vec<RuleRow> = table.rules().cloned().collect();
    match editing.filter(|&i| i < rules.len()) {
        Some(i) => rules[i] = candidate,
        None => rules.push(candidate),
    }
    let pairs = find_route_overlaps(&book_of(&rules), include_subdomains);
    // Ids are unique across both routes; a block rule rides in the secondary
    // bucket but is not a route.
    let route_of = |side: &OverlapRule| -> String {
        match rules.iter().find(|r| r.id == side.rule_id) {
            Some(rule) => rule.target_route.as_str().to_owned(),
            None => side.route.clone(),
        }
    };
    overlaps_of_rule(&pairs, &id)
        .map(|pair| Overlap {
            pair: pair.clone(),
            winner_route: route_of(&pair.winner),
            loser_route: route_of(&pair.loser),
        })
        .collect()
}
