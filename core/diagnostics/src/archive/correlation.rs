//! Archive-local identities; the random key never leaves the builder.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{DiagnosticsError, DiagnosticsResult};
use crate::privacy::RedactionMode;
use nrr_shared::ipc_payloads::DiscoveryEpisodesSnapshotDto;

pub(super) struct ArchiveAliases {
    mac: Hmac<Sha256>,
}

impl ArchiveAliases {
    pub(super) fn new() -> DiagnosticsResult<Self> {
        let mut key = [0_u8; 32];
        getrandom::fill(&mut key).map_err(|error| DiagnosticsError::ExportFailed {
            reason: format!("cannot create private archive identities: {error}"),
        })?;
        let mac =
            Hmac::<Sha256>::new_from_slice(&key).map_err(|_| DiagnosticsError::ExportFailed {
                reason: "cannot initialise private archive identities".to_owned(),
            })?;
        Ok(Self { mac })
    }

    fn token(&self, kind: &str, value: &str) -> String {
        let mut mac = self.mac.clone();
        mac.update(kind.as_bytes());
        mac.update(&[0]);
        mac.update(value.as_bytes());
        let hash = mac.finalize().into_bytes();
        let mut token = format!("<{kind}:");
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in hash.iter().take(12) {
            token.push(char::from(HEX[(byte >> 4) as usize]));
            token.push(char::from(HEX[(byte & 15) as usize]));
        }
        token.push('>');
        token
    }

    pub(super) fn host(&self, value: &str) -> String {
        self.token(
            "host",
            &value.trim().trim_end_matches('.').to_ascii_lowercase(),
        )
    }

    pub(super) fn discovery(
        &self,
        snapshot: &mut DiscoveryEpisodesSnapshotDto,
        mode: RedactionMode,
    ) {
        for episode in snapshot.episodes.iter_mut().take(128) {
            episode.id = self.token("episode", &episode.id);
            if let Some(candidate) = episode.candidate_id.as_mut() {
                *candidate = self.token("candidate", candidate);
            }
            if !mode.shows_full_hostname() {
                if let Some(host) = episode.host.as_mut() {
                    *host = self.host(host);
                }
            }
            if !mode.shows_ip() {
                if let Some(destination) = episode.destination.as_mut() {
                    *destination = self.token("flow", destination);
                }
            }
        }
    }

    pub(super) fn log_line(&self, original: &str, capped: &str, mode: RedactionMode) -> String {
        const MAX_LINE: usize = 4 * 1024 * 1024;
        if original.len() > MAX_LINE {
            return capped.to_owned();
        }
        let Ok(source) = serde_json::from_str::<serde_json::Value>(original) else {
            return capped.to_owned();
        };
        let Ok(mut output) = serde_json::from_str::<serde_json::Value>(capped) else {
            return capped.to_owned();
        };
        let (Some(source), Some(output_payload)) =
            (source.get("payload"), output.get_mut("payload"))
        else {
            return capped.to_owned();
        };
        let changed = self.fields(source, output_payload, mode, 0);
        if changed {
            serde_json::to_string(&output).unwrap_or_else(|_| capped.to_owned())
        } else {
            capped.to_owned()
        }
    }

    fn fields(
        &self,
        source: &serde_json::Value,
        output: &mut serde_json::Value,
        mode: RedactionMode,
        depth: usize,
    ) -> bool {
        if depth > 16 {
            return false;
        }
        let (Some(source), Some(output)) = (source.as_object(), output.as_object_mut()) else {
            return false;
        };
        let mut changed = false;
        for (name, original) in source {
            let Some(value) = output.get_mut(name) else {
                continue;
            };
            let host = matches!(
                name.as_str(),
                "host"
                    | "hostname"
                    | "domain"
                    | "fqdn"
                    | "qname"
                    | "anchor"
                    | "rule_host"
                    | "target_host"
            );
            let endpoint = matches!(
                name.as_str(),
                "remote" | "local" | "destination" | "address" | "ip" | "addr"
            );
            if let Some(text) = original
                .as_str()
                .filter(|text| !text.is_empty() && !text.starts_with('<'))
            {
                if host && !mode.shows_full_hostname() {
                    *value = serde_json::Value::String(self.host(text));
                    changed = true;
                } else if endpoint && !mode.shows_ip() {
                    *value = serde_json::Value::String(self.token("endpoint", text));
                    changed = true;
                } else if name == "discovery_id" {
                    *value = serde_json::Value::String(self.token("episode", text));
                    changed = true;
                }
            } else if original.is_object() && value.is_object() {
                changed |= self.fields(original, value, mode, depth + 1);
            }
        }
        if let (Some(local), Some(remote)) = (
            source.get("local").and_then(serde_json::Value::as_str),
            source.get("remote").and_then(serde_json::Value::as_str),
        ) {
            if !local.starts_with('<')
                && !remote.starts_with('<')
                && local.len() <= 96
                && remote.len() <= 96
            {
                output.insert(
                    "discovery-flow-id".to_owned(),
                    serde_json::Value::String(self.token("flow", &format!("{local} -> {remote}"))),
                );
                changed = true;
            }
        }
        changed
    }
}
