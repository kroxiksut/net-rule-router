//! The polkit action definitions the daemon's authorization checks name.
//!
//! ## Why this file has to exist
//!
//! `PolkitAuthority` asks `pkcheck` whether a caller may perform an action
//! named by [`IpcOperationClass::authorization_action`]. polkit answers about
//! actions it knows; an action nobody registered is not "allowed by default",
//! it is unknown — so without this file every privileged operation from an
//! ordinary desktop user is refused, with no way for an administrator to grant
//! it. The action ids come from the contracts crate, so the names polkit
//! registers and the names the service asks under cannot drift.
//!
//! ## Why four actions and not one
//!
//! An administrator writing a rule wants to distinguish "may edit the shared
//! baseline everyone falls back to" from "may take the network apart to
//! recover it" from "may switch protection off". One coarse action would force
//! them to grant all three together or none.
//!
//! ## Defaults
//!
//! `auth_admin_keep` for all four: an ordinary user is asked for an
//! administrator's password, and the grant is remembered for a short while so a
//! multi-step flow does not prompt at every step. `allow_inactive` is `no` —
//! a session that is not the one at the console does not get to reshape the
//! machine's network.
//!
//! `#[cfg(target_os = "linux")]`: a Linux-only install artefact, kept next to
//! `systemd`, which writes it as part of the install plan.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};

use nrr_shared::ipc_transport::{
    ACTION_CLEAR_SHARED_DATA, ACTION_DISABLE_PROTECTION, ACTION_EDIT_BASELINE,
    ACTION_RECOVER_NETWORK,
};

/// Where polkit reads action definitions from.
pub const POLKIT_ACTIONS_DIR: &str = "/usr/share/polkit-1/actions";

/// Our action file. Named for the product like the unit and the logrotate
/// drop-in, so an administrator finds every install artefact under one name.
pub const POLKIT_ACTIONS_NAME: &str = "netrulerouter.policy";

/// Absolute path of the installed action file.
pub fn actions_file() -> PathBuf {
    Path::new(POLKIT_ACTIONS_DIR).join(POLKIT_ACTIONS_NAME)
}

/// One action as polkit reads it: the id the service asks under, plus what the
/// prompt tells the person being asked.
struct ActionSpec {
    id: &'static str,
    /// Short label, shown in polkit's action lists.
    label_en: &'static str,
    label_ru: &'static str,
    /// The sentence in the password prompt. Says what is about to change, in
    /// the user's terms — never the mechanism.
    message_en: &'static str,
    message_ru: &'static str,
}

const ACTIONS: [ActionSpec; 4] = [
    ActionSpec {
        id: ACTION_EDIT_BASELINE,
        label_en: "Edit the shared routing rules",
        label_ru: "Изменение общих правил маршрутизации",
        message_en: "Authentication is required to change the routing rules every user on this computer falls back to.",
        message_ru: "Требуется подтверждение, чтобы изменить правила маршрутизации, общие для всех пользователей компьютера.",
    },
    ActionSpec {
        id: ACTION_RECOVER_NETWORK,
        label_ru: "Восстановление сетевых настроек",
        label_en: "Restore network settings",
        message_en: "Authentication is required to restore this computer's network settings.",
        message_ru: "Требуется подтверждение, чтобы восстановить сетевые настройки компьютера.",
    },
    ActionSpec {
        id: ACTION_DISABLE_PROTECTION,
        label_en: "Turn off leak protection",
        label_ru: "Отключение защиты от утечек",
        message_en: "Authentication is required to turn off leak protection.",
        message_ru: "Требуется подтверждение, чтобы отключить защиту от утечек.",
    },
    ActionSpec {
        id: ACTION_CLEAR_SHARED_DATA,
        label_en: "Erase shared history",
        label_ru: "Удаление общих данных",
        message_en: "Authentication is required to erase data shared by every user of this computer.",
        message_ru: "Требуется подтверждение, чтобы удалить данные, общие для всех пользователей компьютера.",
    },
];

/// Render the polkit action file.
pub fn render_actions_file() -> String {
    let mut s = String::with_capacity(2048);
    s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    s.push_str(
        "<!DOCTYPE policyconfig PUBLIC \"-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN\"\n",
    );
    s.push_str(" \"http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd\">\n");
    s.push_str("<policyconfig>\n");
    s.push_str(&format!(
        "  <vendor>{}</vendor>\n",
        nrr_shared::product_identity::PRODUCT_NAME
    ));
    for action in ACTIONS.iter() {
        s.push_str(&format!("  <action id=\"{}\">\n", action.id));
        s.push_str(&format!(
            "    <description>{}</description>\n",
            escape(action.label_en)
        ));
        s.push_str(&format!(
            "    <description xml:lang=\"ru\">{}</description>\n",
            escape(action.label_ru)
        ));
        s.push_str(&format!(
            "    <message>{}</message>\n",
            escape(action.message_en)
        ));
        s.push_str(&format!(
            "    <message xml:lang=\"ru\">{}</message>\n",
            escape(action.message_ru)
        ));
        s.push_str("    <defaults>\n");
        s.push_str("      <allow_any>auth_admin_keep</allow_any>\n");
        s.push_str("      <allow_inactive>no</allow_inactive>\n");
        s.push_str("      <allow_active>auth_admin_keep</allow_active>\n");
        s.push_str("    </defaults>\n");
        s.push_str("  </action>\n");
    }
    s.push_str("</policyconfig>\n");
    s
}

/// XML-escape the five characters that matter in element text and attributes.
/// The strings here are ours, not user input; escaping them anyway keeps the
/// file valid if a translation ever grows an ampersand.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_shared::ipc_transport::IpcOperationClass;

    /// Every action the service can ask about must be registered, or polkit
    /// answers "unknown action" and the operation is refused with no way for an
    /// administrator to allow it. This is the pair the review calls for: one
    /// side asks, the other declares, and the test reads both.
    #[test]
    fn every_action_the_service_asks_about_is_declared() {
        let rendered = render_actions_file();
        for class in IpcOperationClass::ALL {
            let Some(action) = class.authorization_action() else {
                continue;
            };
            assert!(
                rendered.contains(&format!("<action id=\"{action}\">")),
                "{action} is asked for by {} but not declared in the policy file",
                class.slug()
            );
        }
    }

    /// The reverse direction: an action nobody asks about is a prompt the user
    /// can never see, and a name an administrator would write rules against for
    /// nothing.
    #[test]
    fn every_declared_action_is_one_the_service_asks_about() {
        let asked: Vec<&str> = IpcOperationClass::ALL
            .iter()
            .filter_map(|c| c.authorization_action())
            .collect();
        for action in ACTIONS.iter() {
            assert!(
                asked.contains(&action.id),
                "{} is declared but no operation class asks for it",
                action.id
            );
        }
    }

    #[test]
    fn the_file_is_well_formed_enough_to_read() {
        let rendered = render_actions_file();
        assert!(rendered.starts_with("<?xml version=\"1.0\""));
        assert!(rendered.trim_end().ends_with("</policyconfig>"));
        assert_eq!(rendered.matches("<action id=").count(), ACTIONS.len());
        // Every action carries both languages; a missing translation would show
        // the English string to a Russian user with no way to tell why.
        assert_eq!(
            rendered.matches("xml:lang=\"ru\"").count(),
            ACTIONS.len() * 2
        );
    }

    #[test]
    fn the_actions_file_sits_where_polkit_reads_them() {
        assert_eq!(
            actions_file(),
            Path::new("/usr/share/polkit-1/actions/netrulerouter.policy")
        );
    }
}
