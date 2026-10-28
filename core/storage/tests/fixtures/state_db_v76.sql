-- Sample of nrr_service_state.db at schema 76, as the build of 18.10 left
-- it: every table holds a row, each column at a value the defaults would not
-- give. Frozen; a later sample goes beside it.
INSERT INTO revisions (principal, revision_id, content_hash, rules_json, status, source, correlation_id, created_at, activated_at, superseded_at, superseded_by, rejected_reason, review_summary_json, risk_level, row_hmac) VALUES
  ('S-1-5-21-1000', 'rev-active', 'sha256:aa', '{"primary":["corp.example"],"secondary":["video.example"]}', 'active', 'gui-rules-edit', 'corr-1', 1700000001000, 1700000002000, NULL, NULL, NULL, '{"added":2}', 'medium', x'0102030405'),
  ('S-1-5-21-1000', 'rev-old', 'sha256:bb', '{"primary":["old.example"]}', 'superseded', 'preset-import', 'corr-0', 1690000001000, 1690000002000, 1700000002000, 'rev-active', NULL, NULL, 'low', x'0a0b0c'),
  ('S-1-5-21-1001', 'rev-rejected', 'sha256:cc', '{}', 'rejected', 'rollback', 'corr-2', 1700000003000, NULL, NULL, NULL, 'conflict', NULL, 'critical', x'ff');
INSERT INTO active_revision_pointer (principal, revision_id, activated_at, apply_attempt_id, row_hmac) VALUES
  ('S-1-5-21-1000', 'rev-active', 1700000002000, 'attempt-7', x'deadbeef');
INSERT INTO app_observed_destinations (sid, app_key, ip, learned_at) VALUES
  ('S-1-5-21-1000', 'C:/Apps/Mail/mail.exe', '198.51.100.7', 1700000010000);
INSERT INTO app_pattern_resolutions (pattern, resolved_path, resolved_at) VALUES
  ('C:/Apps/*/game.exe', 'C:/Apps/Arcade/game.exe', 1700000011000);
INSERT INTO apply_failure_policy_settings (id, policy, set_by_sid, set_at) VALUES
  (1, 'best-effort', 'S-1-5-21-500', 1700000012000);
INSERT INTO auto_rule_dismissals (sid, candidate_id, anchor, proposed_match, dismissed_at, dto_json) VALUES
  ('S-1-5-21-1000', 'cand-1', 'video.example', 'cdn.video.example', 1700000013000, '{"route":"secondary"}');
INSERT INTO auto_rule_evidence (sid, snapshot_json, updated_at) VALUES
  ('S-1-5-21-1000', '{"hosts":["cdn.video.example"]}', 1700000014000);
INSERT INTO auto_rule_pending_candidates (sid, candidate_id, route, match_kind, dto_json, parked_at) VALUES
  ('S-1-5-21-1000', 'cand-2', 'secondary', 'suffix', '{"value":"img.video.example"}', 1700000015000);
INSERT INTO autostart_state (id, enabled, last_known_state, updated_at) VALUES
  (1, 1, 'overridden-externally', 1700000016000);
INSERT INTO behavior_mode (sid, mode, updated_at) VALUES
  ('S-1-5-21-1000', 'prefer-secondary-when-available', 1700000017000);
INSERT INTO block_notice_journal (sid, raised_at, destination, app, reason, attempts, launched_by) VALUES
  ('S-1-5-21-1000', 1700000018000, 'blocked.example', 'C:/Apps/Mail/mail.exe', 'leak-protection', 3, 'C:/Windows/explorer.exe');
INSERT INTO block_notice_mutes (sid, scope_kind, scope_value, until_ms, updated_at) VALUES
  ('S-1-5-21-1000', 'host', 'blocked.example', 1800000000000, 1700000019000),
  ('S-1-5-21-1000', 'all', '', NULL, 1700000019500);
INSERT INTO conn_history_prefs (sid, enabled, retention_days, updated_at) VALUES
  ('S-1-5-21-1000', 0, 14, 1700000020000);
INSERT INTO doh_resolver_entries (target_kind, target, comment, enabled, updated_at) VALUES
  ('host', 'doh.resolver.example', 'my resolver', 0, 1700000021000);
INSERT INTO explain_snapshots (decision_id, created_at, redaction_level, payload_json, expires_at) VALUES
  ('decision-1', 1700000022000, 'diagnostics', '{"route":"primary"}', 1800000022000);
INSERT INTO fake_ip_heal_exclusions (hostname, learned_at) VALUES
  ('heal.example', 1700000023000);
INSERT INTO local_dns_suffixes (suffix, updated_at) VALUES
  ('corp.intra', 1700000025000);
INSERT INTO local_network_rules (sid, cidr, allow, origin, updated_at, adapter) VALUES
  ('S-1-5-21-1000', '192.168.56.0/24', 0, 'manual', 1700000026000, 'vbox-host-only');
INSERT INTO log_retention_config (id, log_max_age_days, log_max_size_bytes, audit_max_age_days, audit_max_size_bytes, updated_at) VALUES
  (1, 30, 1048576, 730, 2097152, 1700000027000);
INSERT INTO migration_state (sid, migration_id, completed_at, detail_json) VALUES
  ('S-1-5-21-1000', 'prefs-to-service', 1700000028000, '{"moved":4}');
INSERT INTO mutation_tokens (token, principal, mutation_payload_json, issued_at, expires_at, consumed) VALUES
  ('token-1', 'S-1-5-21-1000', '{"op":"rules.apply"}', 1700000029000, 1700000089000, 1);
INSERT INTO refusing_anchors (sid, hostname, marked_at) VALUES
  ('S-1-5-21-1000', 'refuses.example', 1700000032000);
INSERT INTO retention_settings (id, superseded_days, superseded_count_cap, rejected_days, rolledback_days, rolledback_count_cap, pin_lkg, last_cleanup_at, updated_at) VALUES
  (1, 60, 200, 14, 30, 40, 0, 1700000033000, 1700000033500);
INSERT INTO route_bindings (sid, role, stable_id, display_name, user_confirmed, updated_at, binding_source, known_stable_ids) VALUES
  ('S-1-5-21-1000', 'primary', 'win-adapter:ethernet', 'Ethernet', 1, 1700000034000, 'user-assigned', 'win-adapter:ethernet-old'),
  ('S-1-5-21-1000', 'secondary', 'win-adapter:vpn', 'Example VPN', 1, 1700000034500, 'migrated-from-preferences', '');
INSERT INTO route_link_provider_apps (sid, role, exe_path, display_name, source, updated_at) VALUES
  ('S-1-5-21-1000', 'secondary', 'C:/Program Files/Example VPN/vpn.exe', 'Example VPN', 'discovered', 1700000035000);
INSERT INTO security_alerts (alert_id, kind, state, raised_event_seq, raised_file, ack_event_seq, ack_file, resolved_event_seq, resolved_file, created_at, updated_at, reason_code) VALUES
  ('alert-1', 'audit-chain-break', 'acknowledged', 41, 'audit-2026-10-01.ndjson', 42, 'audit-2026-10-02.ndjson', 43, 'audit-2026-10-03.ndjson', 1700000038000, 1700000038500, 'hash-mismatch');
INSERT INTO service_stability_config (id, ipc_accept_kind, ipc_max_restarts, ipc_backoff_base_ms, ipc_backoff_cap_ms, set_by_sid, updated_at, conn_trace_gui, rule_scope_service_driven, routing_stop_policy, cache_refresh_interval_secs, enforcement_mode, secondary_liveness_window_secs, fake_ip_enabled, dns_via_secondary, dns_fast_answers, fake_ip_udp_relay, fake_ip_instant_rst, allow_user_rule_edits, verbose_until_ms, conn_trace_ndjson_until_ms) VALUES
  (1, 'recoverable', 7, 250, 20000, 'S-1-5-21-500', 1700000039000, 1, 0, 'persist', 900, 1, 120, 1, 1, 0, 1, 0, 0, 1800000039000, 1800000039500);
INSERT INTO traffic_stats_settings (id, enabled, count_loopback, count_virtual, retention_days, updated_at) VALUES
  (1, 0, 1, 1, 90, 1700000040000);
INSERT INTO vpn_client_apps (exe_path, learned_at) VALUES
  ('C:/Program Files/Example VPN/vpn.exe', 1700000042000);
INSERT INTO install_policy (id, secondary_unset, default_route_mode, updated_at) VALUES
  (1, 'block', 'prefer-secondary-when-available', 1700000024000);
INSERT INTO routing_pause_state (sid, paused, paused_at, pause_reason, updated_at) VALUES
  ('S-1-5-21-1000', 1, 1700000036000, 'user', 1700000036500);
INSERT INTO secondary_block_policy (sid, block_secondary_when_unavailable, updated_at, kill_switch_fail_closed, kill_switch_protocols, include_subdomains, shared_ip_policy, kill_switch_block_all, kill_switch_enabled, allow_dns_over_primary, mode_a_coverage_strategy, resolve_hosts_bypass, doh_lockdown_enabled, doh_lockdown_scope, browser_history_auto_seed, kill_switch_strict_shared_ips, auto_rules_mode, auto_rules_eager_delivery_names, primary_probe_auto, primary_probe_timeout_ms, primary_probe_max_targets, primary_probe_repeat_secs, block_ipv6_when_protected, local_networks_auto_accept, zone_priority_over_ip, short_name_completion, short_name_suffix, app_rules_take_all_addresses, doh_lockdown_auto, forwarded_outage) VALUES
  ('S-1-5-21-1000', 1, 1700000037000, 1, 3, 1, 2, 1, 1, 1, 2, 0, 1, 1, 1, 0, 'auto', 1, 1, 2500, 16, 600, 0, 1, 1, 1, 'corp.intra', 1, 0, 'unprotected');
INSERT INTO vpn_bootstrap_endpoints (ip, port, protocol, source, learned_at) VALUES
  ('203.0.113.9', 51820, 'udp', 'observed', 1700000041000),
  ('203.0.113.10', NULL, NULL, 'manual', 1700000041500);
