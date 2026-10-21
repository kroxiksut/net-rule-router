//! logind's sleep and user edges, read from the system bus: the Linux mechanism
//! behind the power-event and logon-session ports.
//!
//! One `AF_UNIX` connection to the system bus per subscription, speaking only
//! the frames the job needs (EXTERNAL auth, `Hello`, `AddMatch`,
//! `NameHasOwner`, then reading signals). `loginctl` answers questions but
//! streams nothing, and `busctl monitor` sees every peer's traffic; a D-Bus
//! library would bring an async runtime for two signals.
//!
//! ## Who may send what we act on
//!
//! The match names logind's bus name as the sender, so the bus drops a
//! broadcast from anyone else. A unicast signal addressed to us bypasses match
//! rules, so a message carrying a destination is never acted on. Frames are
//! bounded: an oversized one is read past without being kept, a malformed one
//! costs only itself, and a frame whose header cannot be read ends the stream
//! (framing is lost) without touching enforcement. A stream that ends for any
//! reason is resubscribed with a bounded backoff.

// The socket half has no caller off Linux; the parser below still compiles and
// is still tested there.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use nrr_platform_api::error::PlatformError;
use nrr_platform_api::logon_session::{
    LogonSessionCallback, LogonSessionEvent, LogonSessionObserver, LogonSessionSubscription,
};
use nrr_platform_api::power::{
    PowerEvent, PowerEventCallback, PowerEventObserver, PowerEventSubscription,
};

use crate::restart::{Backoff, Interrupt, StopSignal};

const LOGIND_NAME: &str = "org.freedesktop.login1";
const LOGIND_PATH: &str = "/org/freedesktop/login1";
const MANAGER_INTERFACE: &str = "org.freedesktop.login1.Manager";
const BUS_NAME: &str = "org.freedesktop.DBus";
const BUS_PATH: &str = "/org/freedesktop/DBus";

const PREPARE_FOR_SLEEP: &str = "PrepareForSleep";
const USER_NEW: &str = "UserNew";
const USER_REMOVED: &str = "UserRemoved";

/// Fixed part of every message: endianness, type, flags, version, body
/// length, serial, header-field array length.
const FIXED_HEADER_LEN: usize = 16;
/// Every signal we act on is a few dozen bytes; anything larger is read past.
pub const MAX_KEPT_MESSAGE: usize = 64 * 1024;
/// The protocol's own ceiling. A header declaring more is not a D-Bus stream.
const MAX_PROTOCOL_MESSAGE: u64 = 128 * 1024 * 1024;

const METHOD_CALL: u8 = 1;
const METHOD_RETURN: u8 = 2;
const ERROR: u8 = 3;
const SIGNAL: u8 = 4;

const FIELD_PATH: u8 = 1;
const FIELD_INTERFACE: u8 = 2;
const FIELD_MEMBER: u8 = 3;
const FIELD_ERROR_NAME: u8 = 4;
const FIELD_REPLY_SERIAL: u8 = 5;
const FIELD_DESTINATION: u8 = 6;
const FIELD_SENDER: u8 = 7;
const FIELD_SIGNATURE: u8 = 8;

/// A logind edge this crate reacts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogindSignal {
    /// `true` before the machine sleeps, `false` once it runs again.
    PrepareForSleep { starting: bool },
    /// A user gained a login (first session, or linger enabled).
    UserNew,
    /// A user's last login is gone.
    UserRemoved,
}

impl LogindSignal {
    fn member(self) -> &'static str {
        match self {
            Self::PrepareForSleep { .. } => PREPARE_FOR_SLEEP,
            Self::UserNew => USER_NEW,
            Self::UserRemoved => USER_REMOVED,
        }
    }
}

fn power_event(signal: LogindSignal) -> Option<PowerEvent> {
    match signal {
        LogindSignal::PrepareForSleep { starting: true } => Some(PowerEvent::Suspend),
        LogindSignal::PrepareForSleep { starting: false } => Some(PowerEvent::Resume),
        _ => None,
    }
}

/// Presence on Linux is per user, not per session: a second terminal of
/// someone already present changes nothing, so the user edges are the ones.
fn logon_event(signal: LogindSignal) -> Option<LogonSessionEvent> {
    match signal {
        LogindSignal::UserNew => Some(LogonSessionEvent::SignedIn),
        LogindSignal::UserRemoved => Some(LogonSessionEvent::SignedOut),
        LogindSignal::PrepareForSleep { .. } => None,
    }
}

// ── Message parsing (pure; tested on every host) ─────────────────────────────

/// The header fields of one message, borrowed from its frame.
#[derive(Debug, Default, PartialEq, Eq)]
struct MessageFields<'a> {
    kind: u8,
    big_endian: bool,
    reply_serial: Option<u32>,
    path: Option<&'a str>,
    interface: Option<&'a str>,
    member: Option<&'a str>,
    destination: Option<&'a str>,
    sender: Option<&'a str>,
    signature: &'a str,
    body: &'a [u8],
}

/// Why a frame header was refused: the stream can no longer be followed.
#[derive(Debug, PartialEq, Eq)]
struct BrokenFraming;

fn round_up(value: u64, align: u64) -> u64 {
    value.div_ceil(align) * align
}

fn u32_at(bytes: &[u8], at: usize, big_endian: bool) -> Option<u32> {
    let word: [u8; 4] = bytes.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(if big_endian {
        u32::from_be_bytes(word)
    } else {
        u32::from_le_bytes(word)
    })
}

/// Total length of the message this fixed header opens.
fn frame_len(header: &[u8; FIXED_HEADER_LEN]) -> Result<usize, BrokenFraming> {
    let big_endian = match header[0] {
        b'l' => false,
        b'B' => true,
        _ => return Err(BrokenFraming),
    };
    if header[3] != 1 {
        return Err(BrokenFraming);
    }
    let body = u64::from(u32_at(header, 4, big_endian).ok_or(BrokenFraming)?);
    let fields = u64::from(u32_at(header, 12, big_endian).ok_or(BrokenFraming)?);
    let total = round_up(FIXED_HEADER_LEN as u64 + fields, 8) + body;
    if total > MAX_PROTOCOL_MESSAGE {
        return Err(BrokenFraming);
    }
    usize::try_from(total).map_err(|_| BrokenFraming)
}

/// Reads the wire's basic types; offsets are from the message start, which is
/// what D-Bus alignment is relative to.
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
    big_endian: bool,
}

impl<'a> Cursor<'a> {
    fn align(&mut self, to: usize) -> Option<()> {
        let aligned = self.at.checked_next_multiple_of(to)?;
        if aligned > self.bytes.len() {
            return None;
        }
        self.at = aligned;
        Some(())
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(len)?;
        let out = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(out)
    }

    fn byte(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u32(&mut self) -> Option<u32> {
        self.align(4)?;
        let value = u32_at(self.bytes, self.at, self.big_endian)?;
        self.at += 4;
        Some(value)
    }

    fn text(&mut self, len: usize) -> Option<&'a str> {
        let raw = self.take(len.checked_add(1)?)?;
        let (nul, text) = raw.split_last()?;
        if *nul != 0 || text.contains(&0) {
            return None;
        }
        std::str::from_utf8(text).ok()
    }

    /// `s` and `o`.
    fn string(&mut self) -> Option<&'a str> {
        let len = usize::try_from(self.u32()?).ok()?;
        self.text(len)
    }

    /// `g`.
    fn signature(&mut self) -> Option<&'a str> {
        let len = usize::from(self.byte()?);
        self.text(len)
    }

    /// Steps over a value of a basic type a field we do not read carries.
    fn skip(&mut self, signature: &str) -> Option<()> {
        match signature {
            "y" => self.take(1).map(|_| ()),
            "n" | "q" => {
                self.align(2)?;
                self.take(2).map(|_| ())
            }
            "b" | "i" | "u" | "h" => self.u32().map(|_| ()),
            "x" | "t" | "d" => {
                self.align(8)?;
                self.take(8).map(|_| ())
            }
            "s" | "o" => self.string().map(|_| ()),
            "g" => self.signature().map(|_| ()),
            _ => None,
        }
    }
}

/// The header fields of one whole frame, or `None` for anything malformed.
fn parse_message(frame: &[u8]) -> Option<MessageFields<'_>> {
    let header = frame.get(..FIXED_HEADER_LEN)?;
    let big_endian = match header[0] {
        b'l' => false,
        b'B' => true,
        _ => return None,
    };
    let fields_len = usize::try_from(u32_at(header, 12, big_endian)?).ok()?;
    let fields_end = FIXED_HEADER_LEN.checked_add(fields_len)?;
    let mut cursor = Cursor {
        bytes: frame.get(..fields_end)?,
        at: FIXED_HEADER_LEN,
        big_endian,
    };
    let mut out = MessageFields {
        kind: header[1],
        big_endian,
        ..MessageFields::default()
    };
    // Every pass consumes at least the field code, so this ends.
    while cursor.at < fields_end {
        cursor.align(8)?;
        let code = cursor.byte()?;
        let signature = cursor.signature()?;
        match (code, signature) {
            (FIELD_PATH, "o") => out.path = Some(cursor.string()?),
            (FIELD_INTERFACE, "s") => out.interface = Some(cursor.string()?),
            (FIELD_MEMBER, "s") => out.member = Some(cursor.string()?),
            (FIELD_ERROR_NAME, "s") => {
                cursor.string()?;
            }
            (FIELD_REPLY_SERIAL, "u") => out.reply_serial = Some(cursor.u32()?),
            (FIELD_DESTINATION, "s") => out.destination = Some(cursor.string()?),
            (FIELD_SENDER, "s") => out.sender = Some(cursor.string()?),
            (FIELD_SIGNATURE, "g") => out.signature = cursor.signature()?,
            // A known field under the wrong type is a malformed message.
            (FIELD_PATH..=FIELD_SIGNATURE, _) => return None,
            (_, other) => cursor.skip(other)?,
        }
    }
    let body_start = fields_end.checked_next_multiple_of(8)?;
    out.body = frame.get(body_start..)?;
    Some(out)
}

/// A D-Bus boolean: a 32-bit word that may only be 0 or 1.
fn body_bool(fields: &MessageFields<'_>) -> Option<bool> {
    if fields.signature != "b" {
        return None;
    }
    match u32_at(fields.body, 0, fields.big_endian)? {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

/// The logind edge a message reports, or `None` for anything else.
fn decode_logind_signal(fields: &MessageFields<'_>) -> Option<LogindSignal> {
    if fields.kind != SIGNAL
        || fields.destination.is_some()
        || fields.path != Some(LOGIND_PATH)
        || fields.interface != Some(MANAGER_INTERFACE)
    {
        return None;
    }
    match fields.member? {
        PREPARE_FOR_SLEEP => Some(LogindSignal::PrepareForSleep {
            starting: body_bool(fields)?,
        }),
        USER_NEW if fields.signature == "uo" => Some(LogindSignal::UserNew),
        USER_REMOVED if fields.signature == "uo" => Some(LogindSignal::UserRemoved),
        _ => None,
    }
}

/// The bus driver's answer to call `serial`: `Some(Ok(fields))` for a return,
/// `Some(Err(()))` for an error, `None` when the message is about something
/// else.
fn reply_to(fields: MessageFields<'_>, serial: u32) -> Option<Result<MessageFields<'_>, ()>> {
    if fields.reply_serial != Some(serial) || fields.sender != Some(BUS_NAME) {
        return None;
    }
    match fields.kind {
        METHOD_RETURN => Some(Ok(fields)),
        ERROR => Some(Err(())),
        _ => None,
    }
}

/// The fuzz targets' entry: one frame through the length check, the field walk,
/// the reply match and the decoder, as the setup calls and the reader run them.
#[cfg(feature = "fuzzing")]
pub fn fuzz_frame(frame: &[u8]) -> Option<LogindSignal> {
    let header: &[u8; FIXED_HEADER_LEN] = frame.get(..FIXED_HEADER_LEN)?.try_into().ok()?;
    let total = frame_len(header).ok()?;
    if total > MAX_KEPT_MESSAGE {
        return None;
    }
    let frame = frame.get(..total)?;
    if let Some(Ok(reply)) = parse_message(frame).and_then(|fields| reply_to(fields, 1)) {
        let _ = body_bool(&reply);
    }
    decode_logind_signal(&parse_message(frame)?)
}

// ── Message writing ──────────────────────────────────────────────────────────

struct Writer {
    bytes: Vec<u8>,
    big_endian: bool,
}

impl Writer {
    fn pad(&mut self, to: usize) {
        let aligned = self.bytes.len().next_multiple_of(to);
        self.bytes.resize(aligned, 0);
    }

    fn u32(&mut self, value: u32) {
        self.pad(4);
        let word = if self.big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        self.bytes.extend_from_slice(&word);
    }

    fn string(&mut self, text: &str) {
        self.u32(u32::try_from(text.len()).unwrap_or(u32::MAX));
        self.bytes.extend_from_slice(text.as_bytes());
        self.bytes.push(0);
    }

    fn signature(&mut self, text: &str) {
        self.bytes.push(u8::try_from(text.len()).unwrap_or(u8::MAX));
        self.bytes.extend_from_slice(text.as_bytes());
        self.bytes.push(0);
    }

    fn put_u32_at(&mut self, at: usize, value: u32) {
        let word = if self.big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        self.bytes[at..at + 4].copy_from_slice(&word);
    }
}

/// A header field value: the type code it travels under and the value.
enum FieldValue<'a> {
    Path(&'a str),
    Text(&'a str),
    // Only test frames carry a reply serial; our own calls never do.
    #[cfg(test)]
    Serial(u32),
    Signature(&'a str),
}

/// One message frame. `body` is already marshalled, starting 8-aligned.
fn encode_message(
    kind: u8,
    serial: u32,
    fields: &[(u8, FieldValue<'_>)],
    body: &[u8],
    big_endian: bool,
) -> Vec<u8> {
    let mut w = Writer {
        bytes: vec![if big_endian { b'B' } else { b'l' }, kind, 0, 1],
        big_endian,
    };
    w.u32(0);
    w.u32(serial);
    w.u32(0);
    for (code, value) in fields {
        w.pad(8);
        w.bytes.push(*code);
        match value {
            FieldValue::Path(p) => {
                w.signature("o");
                w.string(p);
            }
            FieldValue::Text(t) => {
                w.signature("s");
                w.string(t);
            }
            #[cfg(test)]
            FieldValue::Serial(s) => {
                w.signature("u");
                w.u32(*s);
            }
            FieldValue::Signature(g) => {
                w.signature("g");
                w.signature(g);
            }
        }
    }
    let fields_len = w.bytes.len() - FIXED_HEADER_LEN;
    w.put_u32_at(12, u32::try_from(fields_len).unwrap_or(u32::MAX));
    w.pad(8);
    w.bytes.extend_from_slice(body);
    w.put_u32_at(4, u32::try_from(body.len()).unwrap_or(u32::MAX));
    w.bytes
}

/// A call to the bus driver with at most one string argument.
fn bus_call(serial: u32, member: &str, arg: Option<&str>) -> Vec<u8> {
    let mut fields = vec![
        (FIELD_PATH, FieldValue::Path(BUS_PATH)),
        (FIELD_DESTINATION, FieldValue::Text(BUS_NAME)),
        (FIELD_INTERFACE, FieldValue::Text(BUS_NAME)),
        (FIELD_MEMBER, FieldValue::Text(member)),
    ];
    let mut body = Writer {
        bytes: Vec::new(),
        big_endian: false,
    };
    if let Some(arg) = arg {
        fields.push((FIELD_SIGNATURE, FieldValue::Signature("s")));
        body.string(arg);
    }
    encode_message(METHOD_CALL, serial, &fields, &body.bytes, false)
}

/// The match rule for one logind manager signal, sent by logind and no one
/// else.
fn match_rule(member: &str) -> String {
    format!(
        "type='signal',sender='{LOGIND_NAME}',path='{LOGIND_PATH}',interface='{MANAGER_INTERFACE}',member='{member}'"
    )
}

/// The SASL EXTERNAL identity: the uid as decimal text, hex-encoded.
fn external_auth_line(uid: u32) -> String {
    let hex: String = uid
        .to_string()
        .bytes()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("AUTH EXTERNAL {hex}\r\n")
}

// ── Observers ────────────────────────────────────────────────────────────────

/// Suspend/resume from logind's `PrepareForSleep`.
#[derive(Debug, Default, Clone, Copy)]
pub struct LogindPowerEventObserver;

impl PowerEventObserver for LogindPowerEventObserver {
    fn subscribe(
        &self,
        on_event: PowerEventCallback,
    ) -> Result<PowerEventSubscription, PlatformError> {
        let watch = watch::SignalWatch::start(
            &[PREPARE_FOR_SLEEP],
            Box::new(move |signal| {
                if let Some(event) = power_event(signal) {
                    on_event(event);
                }
            }),
        )?;
        Ok(PowerEventSubscription::new(Box::new(watch)))
    }
}

/// Users arriving and leaving, from logind's `UserNew` / `UserRemoved`.
#[derive(Debug, Default, Clone, Copy)]
pub struct LogindLogonSessionObserver;

impl LogonSessionObserver for LogindLogonSessionObserver {
    fn subscribe(
        &self,
        on_event: LogonSessionCallback,
    ) -> Result<LogonSessionSubscription, PlatformError> {
        let watch = watch::SignalWatch::start(
            &[USER_NEW, USER_REMOVED],
            Box::new(move |signal| {
                if let Some(event) = logon_event(signal) {
                    on_event(event);
                }
            }),
        )?;
        Ok(LogonSessionSubscription::new(Box::new(watch)))
    }
}

type SignalCallback = Box<dyn Fn(LogindSignal) + Send>;

// ── Reconnecting reader (pure over an injected connection) ───────────────────

/// One live subscription: the frames it delivers and how to end a blocked read.
struct Connection {
    frames: Box<dyn std::io::Read + Send>,
    interrupt: Interrupt,
}

/// A bus restart takes seconds; the periodic presence checks cover the gap.
const RECONNECT_BACKOFF: Backoff = Backoff {
    first: std::time::Duration::from_secs(1),
    cap: std::time::Duration::from_secs(30),
};

/// Read one whole frame into `buf`. `Ok(false)` when it was too large to
/// keep and has been read past instead.
fn read_frame<R: std::io::Read + ?Sized>(
    stream: &mut R,
    buf: &mut Vec<u8>,
) -> std::io::Result<bool> {
    let mut header = [0u8; FIXED_HEADER_LEN];
    stream.read_exact(&mut header)?;
    let total = frame_len(&header).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "unreadable D-Bus frame")
    })?;
    let rest = (total - FIXED_HEADER_LEN) as u64;
    if total > MAX_KEPT_MESSAGE {
        let mut past = std::io::Read::take(&mut *stream, rest);
        let skipped = std::io::copy(&mut past, &mut std::io::sink())?;
        if skipped != rest {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        return Ok(false);
    }
    buf.clear();
    buf.extend_from_slice(&header);
    buf.resize(total, 0);
    stream.read_exact(&mut buf[FIXED_HEADER_LEN..])?;
    Ok(true)
}

/// Deliver logind's edges until the stream ends; the error says why.
fn read_signals(
    stream: &mut (dyn std::io::Read + Send),
    members: &[&'static str],
    on_signal: &SignalCallback,
) -> std::io::Error {
    let mut buf = Vec::new();
    loop {
        match read_frame(stream, &mut buf) {
            Ok(false) => continue,
            Ok(true) => {}
            Err(e) => return e,
        }
        let signal = parse_message(&buf).and_then(|fields| decode_logind_signal(&fields));
        if let Some(signal) = signal.filter(|s| members.contains(&s.member())) {
            on_signal(signal);
        }
    }
}

/// Follow the subscription across bus restarts until `stop`. Only signals
/// logind sent are delivered: a reconnect reports no edge of its own, so it
/// can neither fake a wake nor a sign-in; what happened while the bus was gone
/// is the periodic checks' to find.
fn run_reconnecting(
    mut connection: Option<Connection>,
    connect: &mut dyn FnMut() -> Result<Connection, PlatformError>,
    members: &[&'static str],
    on_signal: &SignalCallback,
    stop: &StopSignal,
    backoff: Backoff,
) {
    let mut delay = backoff.first;
    loop {
        if let Some(Connection {
            mut frames,
            interrupt,
        }) = connection.take()
        {
            if !stop.arm(interrupt) {
                return;
            }
            let ended = read_signals(frames.as_mut(), members, on_signal);
            stop.disarm();
            if stop.is_stopped() {
                return;
            }
            tracing::warn!(
                target: "nrr::logind",
                error = %ended,
                "logind signal stream ended; resubscribing, and the periodic checks cover sleep and sign-in edges meanwhile",
            );
            delay = backoff.first;
        }
        if stop.wait(delay) {
            return;
        }
        match connect() {
            Ok(next) => {
                tracing::info!(target: "nrr::logind", "logind signal stream resubscribed");
                connection = Some(next);
            }
            Err(e) => {
                tracing::debug!(
                    target: "nrr::logind",
                    error = %e,
                    retry_in_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                    "logind signal stream not back yet",
                );
                delay = backoff.after(delay);
            }
        }
    }
}

// ── Socket mechanism (Linux only) ────────────────────────────────────────────

#[cfg(not(target_os = "linux"))]
mod watch {
    use super::SignalCallback;
    use nrr_platform_api::error::PlatformError;

    pub(super) struct SignalWatch;

    impl SignalWatch {
        pub(super) fn start(
            _members: &[&'static str],
            _on_signal: SignalCallback,
        ) -> Result<Self, PlatformError> {
            Err(PlatformError::NotSupported {
                reason: "logind exists only on Linux",
            })
        }
    }
}

#[cfg(target_os = "linux")]
mod watch {
    use std::io::{Read, Write};
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    const SYSTEM_BUS_SOCKET: &str = "/run/dbus/system_bus_socket";
    /// The bus answers the setup calls at once; a silent one is not usable.
    const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
    /// Messages read while waiting for one reply before giving up on it.
    const SETUP_MAX_MESSAGES: usize = 64;
    const AUTH_LINE_MAX: usize = 512;

    /// Owns the reader thread; dropping it ends the current read or wait and
    /// joins the thread.
    pub(super) struct SignalWatch {
        stop: Arc<StopSignal>,
        reader: Option<std::thread::JoinHandle<()>>,
    }

    impl Drop for SignalWatch {
        fn drop(&mut self) {
            self.stop.stop();
            if let Some(reader) = self.reader.take() {
                let _ = reader.join();
            }
        }
    }

    fn transient(operation: &'static str, e: impl std::fmt::Display) -> PlatformError {
        PlatformError::Transient {
            operation,
            detail: e.to_string(),
        }
    }

    fn systemd_booted() -> bool {
        std::path::Path::new("/run/systemd/system").is_dir()
    }

    impl SignalWatch {
        /// Subscribe once now. A machine without a bus or logind is refused;
        /// a bus that is not answering yet (early boot) is retried in the
        /// background like a dropped one.
        pub(super) fn start(
            members: &[&'static str],
            on_signal: SignalCallback,
        ) -> Result<Self, PlatformError> {
            let members: Vec<&'static str> = members.to_vec();
            let first = match subscribe(&members) {
                Ok(connection) => Some(connection),
                Err(e @ (PlatformError::Transient { .. } | PlatformError::Errno { .. })) => {
                    tracing::warn!(
                        target: "nrr::logind",
                        error = %e,
                        "logind signal stream not available yet; retrying in the background",
                    );
                    None
                }
                Err(e) => return Err(e),
            };
            let stop = Arc::new(StopSignal::default());
            let thread_stop = Arc::clone(&stop);
            let reader = std::thread::Builder::new()
                .name("nrr-logind-watch".to_string())
                .spawn(move || {
                    let mut connect = || subscribe(&members);
                    run_reconnecting(
                        first,
                        &mut connect,
                        &members,
                        &on_signal,
                        &thread_stop,
                        RECONNECT_BACKOFF,
                    );
                })
                .map_err(|e| transient("spawn logind watch thread", e))?;
            Ok(Self {
                stop,
                reader: Some(reader),
            })
        }
    }

    /// Connect, authenticate and add the matches: one subscription.
    fn subscribe(members: &[&'static str]) -> Result<Connection, PlatformError> {
        let mut stream = UnixStream::connect(SYSTEM_BUS_SOCKET).map_err(|e| match e.kind() {
            // Mid-restart the socket is briefly gone; only without systemd
            // does that mean no bus at all.
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                if !systemd_booted() =>
            {
                PlatformError::NotSupported {
                    reason: "no system bus on this machine",
                }
            }
            _ => transient("connect to the system bus", e),
        })?;
        stream
            .set_read_timeout(Some(SETUP_TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(SETUP_TIMEOUT)))
            .map_err(|e| transient("set system bus timeouts", e))?;
        authenticate(&mut stream)?;

        let mut serial = 0u32;
        call(&mut stream, &mut serial, "Hello", None)?;
        for member in members {
            call(
                &mut stream,
                &mut serial,
                "AddMatch",
                Some(&match_rule(member)),
            )?;
        }
        // Asked after the matches, so an edge between the two is not lost.
        let logind_running = call(&mut stream, &mut serial, "NameHasOwner", Some(LOGIND_NAME))?;
        // A systemd boot gets logind even when it is not up yet: the match
        // follows the name to whoever takes it.
        if !logind_running && !systemd_booted() {
            return Err(PlatformError::NotSupported {
                reason: "logind is not running on this machine",
            });
        }
        stream
            .set_read_timeout(None)
            .map_err(|e| transient("clear system bus timeout", e))?;
        let socket = stream
            .try_clone()
            .map_err(|e| transient("clone system bus socket", e))?;
        Ok(Connection {
            frames: Box::new(stream),
            interrupt: Box::new(move || {
                let _ = socket.shutdown(std::net::Shutdown::Both);
            }),
        })
    }

    fn authenticate(stream: &mut UnixStream) -> Result<(), PlatformError> {
        // The owner of `/proc/self` is our effective uid, which is what the bus
        // compares against the socket's peer credentials.
        let uid = std::fs::metadata("/proc/self")
            .map_err(|e| transient("read own uid", e))?
            .uid();
        let mut hello = vec![0u8];
        hello.extend_from_slice(external_auth_line(uid).as_bytes());
        stream
            .write_all(&hello)
            .map_err(|e| transient("authenticate to the system bus", e))?;
        let mut line = Vec::new();
        while !line.ends_with(b"\r\n") {
            if line.len() >= AUTH_LINE_MAX {
                return Err(transient(
                    "authenticate to the system bus",
                    "overlong reply",
                ));
            }
            let mut byte = [0u8; 1];
            stream
                .read_exact(&mut byte)
                .map_err(|e| transient("authenticate to the system bus", e))?;
            line.push(byte[0]);
        }
        if !line.starts_with(b"OK ") {
            return Err(PlatformError::AccessDenied {
                operation: "authenticate to the system bus",
            });
        }
        stream
            .write_all(b"BEGIN\r\n")
            .map_err(|e| transient("authenticate to the system bus", e))
    }

    /// Send a bus-driver call and wait for its answer: `Hello` and `AddMatch`
    /// only need to succeed, `NameHasOwner` answers with a boolean.
    fn call(
        stream: &mut UnixStream,
        serial: &mut u32,
        member: &'static str,
        arg: Option<&str>,
    ) -> Result<bool, PlatformError> {
        *serial += 1;
        stream
            .write_all(&bus_call(*serial, member, arg))
            .map_err(|e| transient("call the system bus", e))?;
        let mut buf = Vec::new();
        for _ in 0..SETUP_MAX_MESSAGES {
            if !read_frame(stream, &mut buf).map_err(|e| transient("read the system bus", e))? {
                continue;
            }
            let Some(fields) = parse_message(&buf) else {
                continue;
            };
            match reply_to(fields, *serial) {
                None => continue,
                Some(Ok(reply)) => return Ok(body_bool(&reply).unwrap_or(true)),
                Some(Err(())) => {
                    return Err(PlatformError::Transient {
                        operation: "call the system bus",
                        detail: format!("{member} was refused"),
                    })
                }
            }
        }
        Err(transient("call the system bus", "no reply"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bool_body(value: u32, big_endian: bool) -> Vec<u8> {
        if big_endian {
            value.to_be_bytes().to_vec()
        } else {
            value.to_le_bytes().to_vec()
        }
    }

    fn logind_signal_frame(
        member: &str,
        signature: &str,
        body: &[u8],
        destination: Option<&str>,
        big_endian: bool,
    ) -> Vec<u8> {
        let mut fields = vec![
            (FIELD_PATH, FieldValue::Path(LOGIND_PATH)),
            (FIELD_INTERFACE, FieldValue::Text(MANAGER_INTERFACE)),
            (FIELD_MEMBER, FieldValue::Text(member)),
            (FIELD_SENDER, FieldValue::Text(":1.7")),
            (FIELD_SIGNATURE, FieldValue::Signature(signature)),
        ];
        if let Some(d) = destination {
            fields.push((FIELD_DESTINATION, FieldValue::Text(d)));
        }
        encode_message(SIGNAL, 9, &fields, body, big_endian)
    }

    fn decode(frame: &[u8]) -> Option<LogindSignal> {
        let header: &[u8; FIXED_HEADER_LEN] = frame[..FIXED_HEADER_LEN].try_into().ok()?;
        assert_eq!(
            frame_len(header),
            Ok(frame.len()),
            "the header frames the message"
        );
        decode_logind_signal(&parse_message(frame)?)
    }

    #[test]
    fn prepare_for_sleep_reports_both_edges_in_either_byte_order() {
        for big_endian in [false, true] {
            let sleep = logind_signal_frame(
                PREPARE_FOR_SLEEP,
                "b",
                &bool_body(1, big_endian),
                None,
                big_endian,
            );
            let wake = logind_signal_frame(
                PREPARE_FOR_SLEEP,
                "b",
                &bool_body(0, big_endian),
                None,
                big_endian,
            );
            assert_eq!(
                decode(&sleep),
                Some(LogindSignal::PrepareForSleep { starting: true })
            );
            assert_eq!(
                decode(&wake),
                Some(LogindSignal::PrepareForSleep { starting: false })
            );
        }
    }

    #[test]
    fn a_resume_is_a_resume_event_and_a_sleep_a_suspend() {
        assert_eq!(
            power_event(LogindSignal::PrepareForSleep { starting: false }),
            Some(PowerEvent::Resume)
        );
        assert_eq!(
            power_event(LogindSignal::PrepareForSleep { starting: true }),
            Some(PowerEvent::Suspend)
        );
        assert_eq!(power_event(LogindSignal::UserNew), None);
        assert_eq!(
            logon_event(LogindSignal::UserNew),
            Some(LogonSessionEvent::SignedIn)
        );
        assert_eq!(
            logon_event(LogindSignal::UserRemoved),
            Some(LogonSessionEvent::SignedOut)
        );
        assert_eq!(
            logon_event(LogindSignal::PrepareForSleep { starting: false }),
            None
        );
    }

    #[test]
    fn user_edges_decode_from_their_uid_and_path_arguments() {
        let mut body = Writer {
            bytes: Vec::new(),
            big_endian: false,
        };
        body.u32(1000);
        body.string("/org/freedesktop/login1/user/_1000");
        let new = logind_signal_frame(USER_NEW, "uo", &body.bytes, None, false);
        let gone = logind_signal_frame(USER_REMOVED, "uo", &body.bytes, None, false);
        assert_eq!(decode(&new), Some(LogindSignal::UserNew));
        assert_eq!(decode(&gone), Some(LogindSignal::UserRemoved));
    }

    #[test]
    fn a_signal_addressed_to_us_is_not_acted_on() {
        // Unicast skips the sender match, so anyone could send it.
        let frame = logind_signal_frame(
            PREPARE_FOR_SLEEP,
            "b",
            &bool_body(0, false),
            Some(":1.42"),
            false,
        );
        assert_eq!(decode(&frame), None);
    }

    #[test]
    fn a_boolean_that_is_neither_zero_nor_one_is_refused() {
        let frame = logind_signal_frame(PREPARE_FOR_SLEEP, "b", &bool_body(2, false), None, false);
        assert_eq!(decode(&frame), None);
        let wrong_type =
            logind_signal_frame(PREPARE_FOR_SLEEP, "s", &bool_body(0, false), None, false);
        assert_eq!(decode(&wrong_type), None);
        let empty = logind_signal_frame(PREPARE_FOR_SLEEP, "b", &[], None, false);
        assert_eq!(decode(&empty), None);
    }

    #[test]
    fn another_interface_path_or_member_is_ignored() {
        let mut frame = logind_signal_frame("SessionNew", "so", &[], None, false);
        assert_eq!(decode(&frame), None);
        frame = encode_message(
            SIGNAL,
            1,
            &[
                (FIELD_PATH, FieldValue::Path("/elsewhere")),
                (FIELD_INTERFACE, FieldValue::Text(MANAGER_INTERFACE)),
                (FIELD_MEMBER, FieldValue::Text(PREPARE_FOR_SLEEP)),
                (FIELD_SIGNATURE, FieldValue::Signature("b")),
            ],
            &bool_body(0, false),
            false,
        );
        assert_eq!(decode(&frame), None);
    }

    #[test]
    fn a_bus_reply_is_matched_by_serial_and_sender() {
        let reply = encode_message(
            METHOD_RETURN,
            3,
            &[
                (FIELD_REPLY_SERIAL, FieldValue::Serial(4)),
                (FIELD_SENDER, FieldValue::Text(BUS_NAME)),
                (FIELD_SIGNATURE, FieldValue::Signature("b")),
            ],
            &bool_body(1, false),
            false,
        );
        let fields = parse_message(&reply).expect("well formed");
        let answered = reply_to(fields, 4).expect("ours").expect("a return");
        assert_eq!(body_bool(&answered), Some(true));
        assert!(reply_to(parse_message(&reply).expect("well formed"), 5).is_none());

        let spoofed = encode_message(
            METHOD_RETURN,
            3,
            &[
                (FIELD_REPLY_SERIAL, FieldValue::Serial(4)),
                (FIELD_SENDER, FieldValue::Text(":1.99")),
            ],
            &[],
            false,
        );
        assert!(reply_to(parse_message(&spoofed).expect("well formed"), 4).is_none());
    }

    #[test]
    fn our_calls_parse_back_as_what_they_say() {
        let frame = bus_call(2, "AddMatch", Some(&match_rule(PREPARE_FOR_SLEEP)));
        let header: &[u8; FIXED_HEADER_LEN] = frame[..FIXED_HEADER_LEN].try_into().expect("16");
        assert_eq!(frame_len(header), Ok(frame.len()));
        let fields = parse_message(&frame).expect("well formed");
        assert_eq!(fields.kind, METHOD_CALL);
        assert_eq!(fields.member, Some("AddMatch"));
        assert_eq!(fields.destination, Some(BUS_NAME));
        assert_eq!(fields.signature, "s");
        let mut body = Cursor {
            bytes: fields.body,
            at: 0,
            big_endian: false,
        };
        assert_eq!(
            body.string(),
            Some("type='signal',sender='org.freedesktop.login1',path='/org/freedesktop/login1',interface='org.freedesktop.login1.Manager',member='PrepareForSleep'")
        );
    }

    #[test]
    fn the_external_identity_is_the_uid_text_in_hex() {
        assert_eq!(external_auth_line(0), "AUTH EXTERNAL 30\r\n");
        assert_eq!(external_auth_line(1000), "AUTH EXTERNAL 31303030\r\n");
    }

    #[test]
    fn a_header_that_cannot_frame_a_stream_is_refused() {
        let mut header = [0u8; FIXED_HEADER_LEN];
        header[0] = b'x';
        header[3] = 1;
        assert_eq!(frame_len(&header), Err(BrokenFraming));
        header[0] = b'l';
        header[3] = 2;
        assert_eq!(frame_len(&header), Err(BrokenFraming));
        // Over the protocol's ceiling.
        header[3] = 1;
        header[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        header[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(frame_len(&header), Err(BrokenFraming));
    }

    #[test]
    fn every_truncation_of_a_valid_frame_is_refused_without_panicking() {
        let frame = logind_signal_frame(PREPARE_FOR_SLEEP, "b", &bool_body(0, false), None, false);
        for cut in 0..frame.len() {
            let piece = &frame[..cut];
            let decoded = parse_message(piece).and_then(|f| decode_logind_signal(&f));
            assert_eq!(decoded, None, "cut at {cut}");
        }
    }

    #[test]
    fn a_field_length_past_the_frame_is_refused() {
        let mut frame =
            logind_signal_frame(PREPARE_FOR_SLEEP, "b", &bool_body(0, false), None, false);
        frame[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(parse_message(&frame), None);
    }

    #[test]
    fn a_known_field_under_the_wrong_type_is_refused() {
        let frame = encode_message(
            SIGNAL,
            1,
            &[(FIELD_MEMBER, FieldValue::Serial(7))],
            &[],
            false,
        );
        assert_eq!(parse_message(&frame), None);
    }

    // ── Reconnecting reader ──────────────────────────────────────────────────

    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// A stream fed frame by frame; it ends when its sender goes.
    struct ChannelReader {
        frames: mpsc::Receiver<Vec<u8>>,
        pending: std::collections::VecDeque<u8>,
    }

    impl std::io::Read for ChannelReader {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if self.pending.is_empty() {
                match self.frames.recv() {
                    Ok(frame) => self.pending.extend(frame),
                    Err(_) => return Ok(0),
                }
            }
            let n = out.len().min(self.pending.len());
            for (slot, byte) in out.iter_mut().zip(self.pending.drain(..n)) {
                *slot = byte;
            }
            Ok(n)
        }
    }

    /// A connection that delivers `frames` and then stays open until it is
    /// interrupted, or ends at once when `stays_open` is false.
    fn connection(frames: Vec<Vec<u8>>, stays_open: bool) -> Connection {
        let (tx, rx) = mpsc::channel();
        for frame in frames {
            tx.send(frame).expect("receiver alive");
        }
        let held = Mutex::new(stays_open.then_some(tx));
        Connection {
            frames: Box::new(ChannelReader {
                frames: rx,
                pending: std::collections::VecDeque::new(),
            }),
            interrupt: Box::new(move || {
                held.lock().expect("not poisoned").take();
            }),
        }
    }

    fn wake_frame() -> Vec<u8> {
        logind_signal_frame(PREPARE_FOR_SLEEP, "b", &bool_body(0, false), None, false)
    }

    fn user_new_frame() -> Vec<u8> {
        let mut body = Writer {
            bytes: Vec::new(),
            big_endian: false,
        };
        body.u32(1000);
        body.string("/org/freedesktop/login1/user/_1000");
        logind_signal_frame(USER_NEW, "uo", &body.bytes, None, false)
    }

    const FAST: Backoff = Backoff {
        first: Duration::from_millis(1),
        cap: Duration::from_millis(4),
    };

    /// The stream drops, the bus is briefly gone, then comes back: the watch
    /// resubscribes and delivers exactly what logind sent, inventing no edge
    /// for the reconnect itself.
    #[test]
    fn a_dropped_stream_is_resubscribed_without_inventing_an_edge() {
        let (seen_tx, seen_rx) = mpsc::channel();
        let on_signal: SignalCallback = Box::new(move |signal| {
            let _ = seen_tx.send(signal);
        });
        let stop = Arc::new(StopSignal::default());
        let attempts = Arc::new(Mutex::new(0u32));
        let thread_stop = Arc::clone(&stop);
        let counted = Arc::clone(&attempts);
        let reader = std::thread::spawn(move || {
            let mut connect = || {
                let mut attempt = counted.lock().expect("not poisoned");
                *attempt += 1;
                match *attempt {
                    1 | 2 => Err(PlatformError::Transient {
                        operation: "connect to the system bus",
                        detail: "restarting".into(),
                    }),
                    3 => Ok(connection(vec![user_new_frame()], true)),
                    _ => panic!("no attempt after the stream held"),
                }
            };
            run_reconnecting(
                Some(connection(vec![wake_frame()], false)),
                &mut connect,
                &[PREPARE_FOR_SLEEP, USER_NEW],
                &on_signal,
                &thread_stop,
                FAST,
            );
        });
        let first = seen_rx.recv_timeout(Duration::from_secs(5)).expect("wake");
        let second = seen_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("sign-in after the reconnect");
        assert_eq!(first, LogindSignal::PrepareForSleep { starting: false });
        assert_eq!(second, LogindSignal::UserNew);
        stop.stop();
        reader.join().expect("the reader ends on stop");
        assert_eq!(*attempts.lock().expect("not poisoned"), 3);
        assert!(
            seen_rx.try_recv().is_err(),
            "the reconnect reported nothing"
        );
    }

    #[test]
    fn a_stop_while_waiting_for_the_bus_ends_the_thread() {
        let stop = Arc::new(StopSignal::default());
        let thread_stop = Arc::clone(&stop);
        let reader = std::thread::spawn(move || {
            let mut connect = || -> Result<Connection, PlatformError> {
                Err(PlatformError::Transient {
                    operation: "connect to the system bus",
                    detail: "gone".into(),
                })
            };
            let ignore: SignalCallback = Box::new(|_| {});
            run_reconnecting(
                None,
                &mut connect,
                &[USER_NEW],
                &ignore,
                &thread_stop,
                Backoff {
                    first: Duration::from_secs(3600),
                    cap: Duration::from_secs(3600),
                },
            );
        });
        stop.stop();
        reader.join().expect("the wait ends on stop");
    }

    #[test]
    fn a_stopped_watch_never_reads_a_late_connection() {
        let stop = StopSignal::default();
        stop.stop();
        let mut connect = || -> Result<Connection, PlatformError> {
            panic!("no attempt after stop");
        };
        let (seen_tx, seen_rx) = mpsc::channel();
        let on_signal: SignalCallback = Box::new(move |signal| {
            let _ = seen_tx.send(signal);
        });
        run_reconnecting(
            Some(connection(vec![user_new_frame()], true)),
            &mut connect,
            &[USER_NEW],
            &on_signal,
            &stop,
            FAST,
        );
        assert!(seen_rx.try_recv().is_err());
    }

    #[test]
    fn an_oversized_frame_is_read_past_and_the_next_one_kept() {
        let mut big = logind_signal_frame(
            PREPARE_FOR_SLEEP,
            "b",
            &vec![0u8; MAX_KEPT_MESSAGE],
            None,
            false,
        );
        big.extend_from_slice(&wake_frame());
        let mut stream = std::io::Cursor::new(big);
        let mut buf = Vec::new();
        assert!(!read_frame(&mut stream, &mut buf).expect("read past"));
        assert!(read_frame(&mut stream, &mut buf).expect("kept"));
        assert_eq!(
            decode(&buf),
            Some(LogindSignal::PrepareForSleep { starting: false })
        );
    }
}
