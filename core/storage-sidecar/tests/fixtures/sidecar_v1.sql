-- Sample of gui_metadata.db at schema 1: every table holds a row as the GUI
-- writes it. Frozen; a later sample goes beside it.
INSERT INTO rule_metadata (rule_signature, comment, created_at, updated_at) VALUES
  ('exact-fqdn|mail.example|primary', 'work mail, keep direct', 1700000001000, 1700000002000),
  ('zone|example|secondary', 'Комментарий пользователя', 1700000003000, 1700000004000);
INSERT INTO passthrough (route, section_name, raw_text, updated_at) VALUES
  ('primary', 'Linux', '--- Linux
/usr/bin/ssh', 1700000005000),
  ('secondary', 'Ports', '--- Ports
443/tcp', 1700000006000);
INSERT INTO pending_apply (id, rules_json, summary_json, content_hash, modified_at, expires_at) VALUES
  (1, '{"primary":["mail.example"]}', '{"added":1}', 'sha256:aa', 1700000007000, 1700604807000);
INSERT INTO db_state (id, last_vacuum_at_ms) VALUES
  (1, 1700000008000);
