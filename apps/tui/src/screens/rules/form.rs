//! The add and edit form (the GUI's `RuleEditDialog` and `saveRule`).

use nrr_client_logic::rules_table::{normalize_host_input, RuleRow, RuleType, TargetRoute};
use nrr_shared::platform_profile::PlatformProfile;
use nrr_shared::rules_json::FREE_MAX_RULES;

use super::ace;
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

/// Routes a rule of `rule_type` can take: "primary first" only for a name.
pub fn route_options(rule_type: &RuleType) -> Vec<TargetRoute> {
    let mut routes = vec![TargetRoute::Primary, TargetRoute::Secondary];
    if rule_type.allows_verify() {
        routes.push(TargetRoute::Verify);
    }
    routes.push(TargetRoute::Block);
    routes
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
    Comment,
    Enabled,
}

impl Field {
    pub const ALL: [Self; 5] = [
        Self::Type,
        Self::Value,
        Self::Route,
        Self::Comment,
        Self::Enabled,
    ];

    fn step(self, by: isize) -> Self {
        let at = Self::ALL.iter().position(|f| *f == self).unwrap_or(0);
        let next = at.saturating_add_signed(by).min(Self::ALL.len() - 1);
        Self::ALL[next]
    }
}

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
    pub comment: String,
    pub enabled: bool,
    pub field: Field,
    /// Set by a save that found the same rule elsewhere.
    pub duplicate: Option<usize>,
}

impl Form {
    pub fn add() -> Self {
        Self {
            editing: None,
            rule_type: RuleType::Domain,
            value: String::new(),
            route: TargetRoute::Primary,
            comment: String::new(),
            enabled: true,
            field: Field::Value,
            duplicate: None,
        }
    }

    pub fn edit(table: &Table, master: usize) -> Option<Self> {
        let rule = &table.rows.get(master)?.rule;
        Some(Self {
            editing: Some(master),
            rule_type: rule.rule_type.clone(),
            value: rule.match_value.clone(),
            route: rule.target_route.clone(),
            comment: rule.comment.clone(),
            enabled: rule.enabled,
            field: Field::Value,
            duplicate: None,
        })
    }

    pub fn verdict(&self) -> Option<Verdict> {
        (!self.value.trim().is_empty()).then(|| Verdict::of(&self.rule_type, &self.value))
    }

    pub fn move_field(&mut self, by: isize) {
        self.field = self.field.step(by);
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
                let routes = route_options(&self.rule_type);
                let at = routes.iter().position(|r| *r == self.route);
                let next = match at {
                    Some(i) => (i as isize + by).rem_euclid(routes.len() as isize) as usize,
                    None => 0,
                };
                if let Some(r) = routes.get(next) {
                    self.route = r.clone();
                }
            }
            Field::Enabled => self.enabled = !self.enabled,
            Field::Value | Field::Comment => {}
        }
        self.duplicate = None;
    }

    /// A type that cannot carry the route moves it to secondary
    /// (`routeForRuleType`).
    pub fn set_type(&mut self, rule_type: RuleType) {
        self.route = self.route.clone().for_rule_type(&rule_type);
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
                let routes = route_options(&self.rule_type);
                if let Some(i) = pick(routes.len()) {
                    self.route = routes[i].clone();
                }
            }
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
        let id = match self.editing.and_then(|i| table.rows.get(i)) {
            Some(row) => row.rule.id.clone(),
            None => table.next_free_id(),
        };
        // Editing an app-authored rule makes it the user's own.
        let rule = RuleRow {
            id,
            enabled: self.enabled,
            rule_type: self.rule_type.clone(),
            match_value: self.value.clone(),
            target_route: self.route.clone().for_rule_type(&self.rule_type),
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
