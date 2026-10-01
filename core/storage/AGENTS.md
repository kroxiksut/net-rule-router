# nrr-storage

Synchronous SQLite persistence for two databases:

| File | Kind | On corruption |
|------|------|---------------|
| `nrr_fqdn_ip_cache.db` | Rebuildable | Delete + rebuild |
| `nrr_service_state.db` | Service-critical | Reported at boot, then rolled back to a trusted earlier revision |

Design invariants:
- **Sync-only** blocking `rusqlite`. No async primitives in the crate. Async callers wrap with `spawn_blocking`.
- **Single connection per database** (one `RefCell<Connection>` per store; no pool).
- **WAL mandatory**: verified on open, after `busy_timeout = 5000 ms`. Connection setup and the migration runner live in `nrr-sqlite-support`, shared with the GUI sidecar.
- **Checksum validation**: migration runner validates stored FNV-1a checksums against computed values on every startup — mismatch → `MigrationFailed`.
- **Privacy tiers**: `DiagnosticRedactionLevel` (Compact / Standard / Diagnostics) gates explain detail. Raw hostnames/IPs never appear in `Compact`.
