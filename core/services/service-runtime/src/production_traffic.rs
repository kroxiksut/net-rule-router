//! Block T (traffic counter) — production `TrafficStatsProvider` /
//! `TrafficStatsWriter` backed by the service [`TrafficSampler`] and the
//! service-critical `traffic_stats_settings` singleton.
//!
//! The settings live in the state DB (a different connection than the sampler's
//! traffic DB), so they are reached through the narrow [`TrafficSettingsAccess`]
//! seam; the concrete impl is assembled in the composition root (`runtime_deps`)
//! where the state connection is available. This keeps `ProductionTrafficStats`
//! testable with a fake settings store and a real sampler.

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use rusqlite::Connection;

use nrr_storage::{
    StorageResult, TrafficDayRow, TrafficStatsSettings, TrafficStatsSettingsRepository,
    TrafficTotalRow,
};

use crate::ipc_handlers::payloads::{
    TrafficRowDto, TrafficStatsGetRequest, TrafficStatsGetResponse, TrafficStatsSettingsDto,
};
use crate::ipc_handlers::providers::{TrafficStatsProvider, TrafficStatsWriter};
use crate::ipc_handlers::SettingsWriteError;
use crate::traffic_sampler::{TrafficSampler, TrafficSessionRow};

/// Narrow access to the service-critical `traffic_stats_settings` singleton.
pub trait TrafficSettingsAccess: Send + Sync {
    fn get(&self) -> StorageResult<TrafficStatsSettings>;
    fn set(&self, settings: &TrafficStatsSettings) -> StorageResult<()>;
}

/// Production [`TrafficSettingsAccess`] over the shared state-DB connection
/// (same `Arc<Mutex<Connection>>` the other settings providers hold, so their
/// writes serialise on one lock). Assembled in `runtime_deps`.
pub struct ProductionTrafficSettings {
    conn: Arc<Mutex<Connection>>,
}

impl ProductionTrafficSettings {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl TrafficSettingsAccess for ProductionTrafficSettings {
    fn get(&self) -> StorageResult<TrafficStatsSettings> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        TrafficStatsSettingsRepository::new(&conn).get_or_default()
    }

    fn set(&self, settings: &TrafficStatsSettings) -> StorageResult<()> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        TrafficStatsSettingsRepository::new(&conn).set(settings, now_ms())
    }
}

/// Production traffic-stats provider + writer.
pub struct ProductionTrafficStats {
    sampler: Arc<Mutex<TrafficSampler>>,
    settings: Arc<dyn TrafficSettingsAccess>,
}

impl ProductionTrafficStats {
    pub fn new(
        sampler: Arc<Mutex<TrafficSampler>>,
        settings: Arc<dyn TrafficSettingsAccess>,
    ) -> Self {
        Self { sampler, settings }
    }
}

fn settings_dto(s: &TrafficStatsSettings) -> TrafficStatsSettingsDto {
    TrafficStatsSettingsDto {
        enabled: s.enabled,
        count_loopback: s.count_loopback,
        count_virtual: s.count_virtual,
        retention_days: s.retention_days,
    }
}

/// Block T Feature 2 — the address fields shared by every `TrafficRowDto`
/// builder below, looked up once per response (see `addresses` in
/// [`ProductionTrafficStats::get`]) rather than re-querying the DB per row.
fn address_fields(
    addr: Option<&nrr_storage::AdapterAddressRow>,
) -> (Option<String>, Option<String>, Option<i64>) {
    match addr {
        Some(a) => (
            Some(a.local_ip.clone()),
            a.external_ip.clone(),
            Some(a.observed_at_ms),
        ),
        None => (None, None, None),
    }
}

fn day_row_dto(r: &TrafficDayRow, addr: Option<&nrr_storage::AdapterAddressRow>) -> TrafficRowDto {
    let (local_ip, external_ip, external_ip_observed_at_ms) = address_fields(addr);
    TrafficRowDto {
        adapter_key: r.adapter_key.clone(),
        display_name: r.display_name.clone(),
        role: r.role.clone(),
        in_bytes: r.in_bytes,
        out_bytes: r.out_bytes,
        local_ip,
        external_ip,
        external_ip_observed_at_ms,
    }
}

fn total_row_dto(
    r: &TrafficTotalRow,
    addr: Option<&nrr_storage::AdapterAddressRow>,
) -> TrafficRowDto {
    let (local_ip, external_ip, external_ip_observed_at_ms) = address_fields(addr);
    TrafficRowDto {
        adapter_key: r.adapter_key.clone(),
        display_name: r.display_name.clone(),
        role: r.role.clone(),
        in_bytes: r.in_bytes,
        out_bytes: r.out_bytes,
        local_ip,
        external_ip,
        external_ip_observed_at_ms,
    }
}

fn session_row_dto(
    r: &TrafficSessionRow,
    addr: Option<&nrr_storage::AdapterAddressRow>,
) -> TrafficRowDto {
    let (local_ip, external_ip, external_ip_observed_at_ms) = address_fields(addr);
    TrafficRowDto {
        adapter_key: r.adapter_key.clone(),
        display_name: r.display_name.clone(),
        role: r.role.clone(),
        in_bytes: r.in_bytes,
        out_bytes: r.out_bytes,
        local_ip,
        external_ip,
        external_ip_observed_at_ms,
    }
}

/// One CSV field, delimiter `;`; quoted (RFC-4180 style) when it contains the
/// delimiter, a quote, or a newline.
fn csv_field(s: &str) -> String {
    if s.contains(';') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Unit the exported byte columns are rendered in. Chosen by the user next to
/// the export button; the wire carries the lowercase slug.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CsvByteUnit {
    Bytes,
    Kilobytes,
    Megabytes,
    Gigabytes,
}

impl CsvByteUnit {
    /// Anything unrecognised (including an absent field) falls back to raw
    /// bytes, so an older or malformed client never mislabels its numbers.
    fn from_slug(slug: Option<&str>) -> Self {
        match slug {
            Some("kb") => Self::Kilobytes,
            Some("mb") => Self::Megabytes,
            Some("gb") => Self::Gigabytes,
            _ => Self::Bytes,
        }
    }

    /// Suffix of the two byte column headers (`received_…` / `sent_…`), so the
    /// unit is always readable from the exported file itself.
    fn header_suffix(self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::Kilobytes => "kb",
            Self::Megabytes => "mb",
            Self::Gigabytes => "gb",
        }
    }

    /// 1024-based divisor.
    fn divisor(self) -> u64 {
        match self {
            Self::Bytes => 1,
            Self::Kilobytes => 1024,
            Self::Megabytes => 1024 * 1024,
            Self::Gigabytes => 1024 * 1024 * 1024,
        }
    }

    /// Renders one byte count: an exact integer for `Bytes`, otherwise at most
    /// two decimals with trailing zeros trimmed. The decimal separator is a
    /// dot, which the `;` field delimiter keeps unambiguous.
    fn render(self, bytes: u64) -> String {
        if self == Self::Bytes {
            return bytes.to_string();
        }
        let scaled = format!("{:.2}", bytes as f64 / self.divisor() as f64);
        // `{:.2}` always emits a decimal point, so trimming zeros can never eat
        // a significant digit of the integer part.
        scaled
            .trim_end_matches('0')
            .trim_end_matches('.')
            .to_string()
    }
}

/// Builds the `;`-delimited CSV export from a day range. Stable English header
/// keys, with the byte columns named after the unit they are rendered in.
fn build_csv(rows: &[TrafficDayRow], unit: CsvByteUnit) -> String {
    let suffix = unit.header_suffix();
    let mut out = format!("day;adapter;role;received_{suffix};sent_{suffix}\r\n");
    for r in rows {
        out.push_str(&format!(
            "{};{};{};{};{}\r\n",
            r.day,
            csv_field(&r.display_name),
            r.role,
            unit.render(r.in_bytes),
            unit.render(r.out_bytes),
        ));
    }
    out
}

/// Recover the guard on a poisoned mutex rather than panicking — a poisoned
/// sampler lock still holds valid ledger data we can read.
fn lock_sampler(m: &Mutex<TrafficSampler>) -> std::sync::MutexGuard<'_, TrafficSampler> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl TrafficStatsProvider for ProductionTrafficStats {
    fn get(&self, request: &TrafficStatsGetRequest) -> TrafficStatsGetResponse {
        let settings = self
            .settings
            .get()
            .map(|s| settings_dto(&s))
            .unwrap_or_else(|_| settings_dto(&TrafficStatsSettings::DEFAULT));

        let sampler = lock_sampler(&self.sampler);
        // Block T Feature 2 — one bulk read of the observed-address table,
        // joined in-memory by `adapter_key` into each row below, rather than
        // a per-row DB query.
        let addresses: std::collections::HashMap<String, nrr_storage::AdapterAddressRow> = sampler
            .adapter_addresses()
            .unwrap_or_default()
            .into_iter()
            .map(|a| (a.adapter_key.clone(), a))
            .collect();
        let today = sampler
            .today_totals(request.day)
            .unwrap_or_default()
            .iter()
            .map(|r| day_row_dto(r, addresses.get(&r.adapter_key)))
            .collect();
        let session = sampler
            .session_totals()
            .iter()
            .map(|r| session_row_dto(r, addresses.get(&r.adapter_key)))
            .collect();
        let all_time = sampler
            .all_time_totals()
            .unwrap_or_default()
            .iter()
            .map(|r| total_row_dto(r, addresses.get(&r.adapter_key)))
            .collect();
        let csv = match (request.export_from_day, request.export_to_day) {
            (Some(from), Some(to)) => {
                let unit = CsvByteUnit::from_slug(request.export_unit.as_deref());
                sampler
                    .export_range(from, to)
                    .ok()
                    .map(|rows| build_csv(&rows, unit))
            }
            _ => None,
        };

        TrafficStatsGetResponse {
            today,
            session,
            all_time,
            session_active: sampler.session_active(),
            settings,
            csv,
        }
    }
}

impl TrafficStatsWriter for ProductionTrafficStats {
    fn set(
        &self,
        dto: &TrafficStatsSettingsDto,
    ) -> Result<TrafficStatsSettingsDto, SettingsWriteError> {
        let settings = TrafficStatsSettings {
            enabled: dto.enabled,
            count_loopback: dto.count_loopback,
            count_virtual: dto.count_virtual,
            retention_days: dto.retention_days,
            updated_at: 0,
        };
        settings
            .validate()
            .map_err(|e| SettingsWriteError::Invalid(e.to_string()))?;
        self.settings
            .set(&settings)
            .map_err(|e| SettingsWriteError::Storage(e.to_string()))?;
        Ok(settings_dto(&settings))
    }

    fn clear(&self) -> Result<TrafficStatsSettingsDto, SettingsWriteError> {
        {
            let mut sampler = lock_sampler(&self.sampler);
            sampler
                .clear()
                .map_err(|e| SettingsWriteError::Storage(e.to_string()))?;
        }
        let settings = self
            .settings
            .get()
            .map(|s| settings_dto(&s))
            .unwrap_or_else(|_| settings_dto(&TrafficStatsSettings::DEFAULT));
        Ok(settings)
    }
}

// ── SamplerAdapterAddressRecorder (Block T Feature 2) ───────────────────────

/// Wraps the sampler's `Arc<Mutex<TrafficSampler>>` as an
/// [`crate::production_handlers_misc::AdapterAddressRecorder`], so
/// `MonitoredAdaptersSnapshotProvider`'s user-requested external-IP probe
/// persists into the SAME connection the sampler already owns — never a
/// second connection to `nrr_traffic_stats.db`. A storage failure is logged
/// and swallowed: a failed address write must never fail the probe response
/// the GUI is waiting on.
pub struct SamplerAdapterAddressRecorder {
    sampler: Arc<Mutex<TrafficSampler>>,
}

impl SamplerAdapterAddressRecorder {
    pub fn new(sampler: Arc<Mutex<TrafficSampler>>) -> Self {
        Self { sampler }
    }
}

impl crate::production_handlers_misc::AdapterAddressRecorder for SamplerAdapterAddressRecorder {
    fn record(&self, adapter_key: &str, local_ip: &str, external_ip: &str, observed_at_ms: i64) {
        let sampler = lock_sampler(&self.sampler);
        if let Err(e) =
            sampler.record_adapter_address(adapter_key, local_ip, external_ip, observed_at_ms)
        {
            tracing::warn!(
                target: "nrr::traffic",
                error = %e,
                adapter_key,
                "failed to persist observed adapter address",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::{InterfaceCounters, InterfaceType, MockInterfaceCounterSource};
    use nrr_storage::repository::MigrationRunner;
    use nrr_storage::{open_connection, SqliteMigrationRunner, SqliteTrafficStore};
    use std::sync::Mutex as StdMutex;

    struct FakeSettings {
        row: StdMutex<TrafficStatsSettings>,
    }
    impl TrafficSettingsAccess for FakeSettings {
        fn get(&self) -> StorageResult<TrafficStatsSettings> {
            Ok(self.row.lock().expect("lock").clone())
        }
        fn set(&self, settings: &TrafficStatsSettings) -> StorageResult<()> {
            *self.row.lock().expect("lock") = settings.clone();
            Ok(())
        }
    }

    fn sampler_with(dir: &tempfile::TempDir) -> (Arc<MockInterfaceCounterSource>, TrafficSampler) {
        let src = Arc::new(MockInterfaceCounterSource::new());
        let path = dir.path().join("nrr_traffic_stats.db");
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_traffic_db(conn);
        runner.run_pending_migrations().expect("migrate");
        let store = SqliteTrafficStore::new(runner.into_connection());
        let sampler = TrafficSampler::new(
            Arc::clone(&src) as Arc<dyn nrr_platform_api::InterfaceCounterSource>,
            store,
        )
        .expect("sampler");
        (src, sampler)
    }

    fn counters(name: &str, in_o: u64, out_o: u64) -> InterfaceCounters {
        InterfaceCounters {
            stable_name: name.to_string(),
            display_name: name.to_string(),
            interface_type: InterfaceType::Ethernet,
            is_virtual: false,
            is_tunnel: false,
            is_up: true,
            in_octets: in_o,
            out_octets: out_o,
        }
    }

    fn toggles_on() -> nrr_domain::traffic_accountant::CountingToggles {
        nrr_domain::traffic_accountant::CountingToggles {
            count_loopback: true,
            count_virtual: true,
        }
    }

    #[test]
    fn get_returns_today_session_and_settings() {
        let dir = tempfile::tempdir().expect("dir");
        let (src, mut sampler) = sampler_with(&dir);
        // The additional adapter is up throughout, so a session is live and
        // both roles accumulate into it.
        src.set(vec![
            counters("Ethernet", 0, 0),
            counters("WireGuard", 0, 0),
        ]);
        sampler
            .tick(Some("Ethernet"), Some("WireGuard"), toggles_on(), 42, 1)
            .expect("t1");
        src.set(vec![
            counters("Ethernet", 300, 120),
            counters("WireGuard", 10, 5),
        ]);
        sampler
            .tick(Some("Ethernet"), Some("WireGuard"), toggles_on(), 42, 2)
            .expect("t2");

        let settings = Arc::new(FakeSettings {
            row: StdMutex::new(TrafficStatsSettings::DEFAULT),
        });
        let prod = ProductionTrafficStats::new(Arc::new(Mutex::new(sampler)), settings);

        let resp = prod.get(&TrafficStatsGetRequest {
            day: 42,
            export_from_day: None,
            export_to_day: None,
            export_unit: None,
        });
        let today_primary = resp
            .today
            .iter()
            .find(|r| r.role == "primary")
            .expect("primary today row");
        assert_eq!(
            (today_primary.in_bytes, today_primary.out_bytes),
            (300, 120)
        );
        assert!(resp.session_active, "additional adapter is up");
        assert_eq!(resp.session.len(), 2, "both roles counted in the session");
        let total_primary = resp
            .all_time
            .iter()
            .find(|r| r.role == "primary")
            .expect("primary all-time row");
        assert_eq!(
            (total_primary.in_bytes, total_primary.out_bytes),
            (300, 120),
            "all-time equals the single accounted day"
        );
        assert!(resp.settings.enabled);
        assert!(resp.csv.is_none());
    }

    #[test]
    fn get_joins_observed_addresses_by_adapter_key() {
        let dir = tempfile::tempdir().expect("dir");
        let (src, mut sampler) = sampler_with(&dir);
        src.set(vec![counters("Ethernet", 0, 0)]);
        sampler
            .tick(Some("Ethernet"), None, toggles_on(), 42, 1)
            .expect("t1");
        src.set(vec![counters("Ethernet", 100, 50)]);
        sampler
            .tick(Some("Ethernet"), None, toggles_on(), 42, 2)
            .expect("t2");
        sampler
            .record_adapter_address("Ethernet", "192.168.1.5", "203.0.113.7", 12345)
            .expect("record");

        let settings = Arc::new(FakeSettings {
            row: StdMutex::new(TrafficStatsSettings::DEFAULT),
        });
        let prod = ProductionTrafficStats::new(Arc::new(Mutex::new(sampler)), settings);
        let resp = prod.get(&TrafficStatsGetRequest {
            day: 42,
            export_from_day: None,
            export_to_day: None,
            export_unit: None,
        });
        let row = resp
            .today
            .iter()
            .find(|r| r.role == "primary")
            .expect("row");
        assert_eq!(row.local_ip.as_deref(), Some("192.168.1.5"));
        assert_eq!(row.external_ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(row.external_ip_observed_at_ms, Some(12345));
    }

    #[test]
    fn get_leaves_addresses_absent_when_never_probed() {
        let dir = tempfile::tempdir().expect("dir");
        let prod = provider_with_one_day(&dir);
        let resp = prod.get(&TrafficStatsGetRequest {
            day: 42,
            export_from_day: None,
            export_to_day: None,
            export_unit: None,
        });
        let row = resp
            .today
            .iter()
            .find(|r| r.role == "primary")
            .expect("row");
        assert_eq!(row.local_ip, None);
        assert_eq!(row.external_ip, None);
        assert_eq!(row.external_ip_observed_at_ms, None);
    }

    #[test]
    fn sampler_address_recorder_persists_through_the_shared_sampler() {
        use crate::production_handlers_misc::AdapterAddressRecorder;

        let dir = tempfile::tempdir().expect("dir");
        let (_src, sampler) = sampler_with(&dir);
        let sampler = Arc::new(Mutex::new(sampler));
        let recorder = SamplerAdapterAddressRecorder::new(Arc::clone(&sampler));

        recorder.record("Ethernet", "192.168.1.5", "203.0.113.7", 999);

        let stored = lock_sampler(&sampler)
            .adapter_addresses()
            .expect("read back");
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].adapter_key, "Ethernet");
        assert_eq!(stored[0].local_ip, "192.168.1.5");
        assert_eq!(stored[0].external_ip.as_deref(), Some("203.0.113.7"));
    }

    /// A provider whose ledger holds one `Ethernet` primary row of 100 received
    /// / 50 sent bytes on day 42.
    fn provider_with_one_day(dir: &tempfile::TempDir) -> ProductionTrafficStats {
        let (src, mut sampler) = sampler_with(dir);
        src.set(vec![counters("Ethernet", 0, 0)]);
        sampler
            .tick(Some("Ethernet"), None, toggles_on(), 42, 1)
            .expect("t1");
        src.set(vec![counters("Ethernet", 100, 50)]);
        sampler
            .tick(Some("Ethernet"), None, toggles_on(), 42, 2)
            .expect("t2");
        ProductionTrafficStats::new(
            Arc::new(Mutex::new(sampler)),
            Arc::new(FakeSettings {
                row: StdMutex::new(TrafficStatsSettings::DEFAULT),
            }),
        )
    }

    fn export_csv_in(prod: &ProductionTrafficStats, unit: Option<&str>) -> String {
        prod.get(&TrafficStatsGetRequest {
            day: 42,
            export_from_day: Some(0),
            export_to_day: Some(100),
            export_unit: unit.map(str::to_string),
        })
        .csv
        .expect("csv present")
    }

    #[test]
    fn get_with_export_range_returns_csv() {
        let dir = tempfile::tempdir().expect("dir");
        let csv = export_csv_in(&provider_with_one_day(&dir), None);
        assert!(csv.starts_with("day;adapter;role;received_bytes;sent_bytes"));
        assert!(csv.contains(";Ethernet;primary;100;50"));
    }

    #[test]
    fn export_unit_scales_values_and_headers() {
        let dir = tempfile::tempdir().expect("dir");
        let prod = provider_with_one_day(&dir);

        // Explicit `bytes` is identical to the default — no behaviour change.
        let bytes = export_csv_in(&prod, Some("bytes"));
        assert!(bytes.starts_with("day;adapter;role;received_bytes;sent_bytes"));
        assert!(bytes.contains(";Ethernet;primary;100;50"));

        // 100 / 1024 = 0.0976…, 50 / 1024 = 0.0488… — two decimals, zeros trimmed.
        let kb = export_csv_in(&prod, Some("kb"));
        assert!(kb.starts_with("day;adapter;role;received_kb;sent_kb"));
        assert!(kb.contains(";Ethernet;primary;0.1;0.05"), "{kb}");

        // Below the two-decimal resolution both columns round to a bare zero.
        let gb = export_csv_in(&prod, Some("gb"));
        assert!(gb.starts_with("day;adapter;role;received_gb;sent_gb"));
        assert!(gb.contains(";Ethernet;primary;0;0"), "{gb}");

        // An unrecognised slug must not mislabel the export.
        let unknown = export_csv_in(&prod, Some("furlongs"));
        assert!(unknown.starts_with("day;adapter;role;received_bytes;sent_bytes"));
        assert!(unknown.contains(";Ethernet;primary;100;50"));
    }

    #[test]
    fn csv_byte_unit_renders_at_most_two_decimals() {
        assert_eq!(CsvByteUnit::Bytes.render(1_048_576), "1048576");
        // Exact multiples come out as bare integers, not `1.00`.
        assert_eq!(CsvByteUnit::Kilobytes.render(1024), "1");
        assert_eq!(CsvByteUnit::Megabytes.render(1_048_576), "1");
        assert_eq!(CsvByteUnit::Megabytes.render(104_857_600), "100");
        assert_eq!(CsvByteUnit::Gigabytes.render(1_073_741_824), "1");
        // One trailing zero is trimmed, the significant decimal is kept.
        assert_eq!(CsvByteUnit::Kilobytes.render(1536), "1.5");
        assert_eq!(CsvByteUnit::Kilobytes.render(1546), "1.51");
        assert_eq!(CsvByteUnit::Bytes.render(0), "0");
        assert_eq!(CsvByteUnit::Gigabytes.render(0), "0");
    }

    #[test]
    fn set_persists_and_validates() {
        let dir = tempfile::tempdir().expect("dir");
        let (_src, sampler) = sampler_with(&dir);
        let settings = Arc::new(FakeSettings {
            row: StdMutex::new(TrafficStatsSettings::DEFAULT),
        });
        let prod = ProductionTrafficStats::new(Arc::new(Mutex::new(sampler)), settings.clone());

        let out = prod
            .set(&TrafficStatsSettingsDto {
                enabled: false,
                count_loopback: true,
                count_virtual: false,
                retention_days: 90,
            })
            .expect("set ok");
        assert!(!out.enabled);
        assert_eq!(out.retention_days, 90);
        assert_eq!(settings.row.lock().expect("lock").retention_days, 90);

        // Out-of-range retention is rejected before storage.
        let err = prod.set(&TrafficStatsSettingsDto {
            enabled: true,
            count_loopback: false,
            count_virtual: false,
            retention_days: 5,
        });
        assert!(matches!(err, Err(SettingsWriteError::Invalid(_))));
    }

    #[test]
    fn csv_field_quotes_delimiter() {
        assert_eq!(csv_field("Ethernet"), "Ethernet");
        assert_eq!(csv_field("a;b"), "\"a;b\"");
        assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
    }
}
