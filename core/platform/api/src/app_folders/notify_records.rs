//! The records `ReadDirectoryChangesW` writes into its buffer
//! (`FILE_NOTIFY_INFORMATION`), walked without the OS.
//!
//! Kept beside the port rather than in the Windows backend so the walk is
//! tested on every host and fuzzed: the names inside are whatever any user who
//! can write into a watched folder chose to call a file, and the offsets are
//! read from the buffer itself.

/// `NextEntryOffset`, `Action`, `FileNameLength`: the fixed part of a record.
const RECORD_HEADER_LEN: usize = 12;

/// Records read from one buffer; the rest is ignored.
pub const MAX_NOTIFY_RECORDS: usize = 4096;

/// `FILE_ACTION_MODIFIED`: a file's data or attributes changed, its name did
/// not.
pub const ACTION_MODIFIED: u32 = 3;

/// One record: what happened, and to which name below the watched folder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotifyRecord {
    pub action: u32,
    /// Relative to the watched folder; `\` separates the levels below it.
    pub name: String,
}

impl NotifyRecord {
    /// Whether this record may change which programs the folder holds.
    #[must_use]
    pub fn may_change_programs(&self) -> bool {
        if super::name_is_windows_program(&self.name) {
            return true;
        }
        self.action != ACTION_MODIFIED && super::name_may_change_programs(&self.name)
    }
}

/// Walk a filled buffer. A record whose offsets or name run past the buffer
/// ends the walk instead of being read from the bytes after it.
#[must_use]
pub fn notify_records(buffer: &[u8]) -> Vec<NotifyRecord> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while out.len() < MAX_NOTIFY_RECORDS {
        let Some(name_start) = offset.checked_add(RECORD_HEADER_LEN) else {
            break;
        };
        let Some(header) = buffer.get(offset..name_start) else {
            break;
        };
        let next = u32_at(header, 0) as usize;
        let action = u32_at(header, 4);
        let name_len = u32_at(header, 8) as usize;
        let Some(raw) = name_start
            .checked_add(name_len)
            .and_then(|name_end| buffer.get(name_start..name_end))
        else {
            break;
        };
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        out.push(NotifyRecord {
            action,
            name: String::from_utf16_lossy(&units),
        });
        // Zero ends the chain; anything else moves forward, never back.
        if next == 0 {
            break;
        }
        match offset.checked_add(next) {
            Some(following) => offset = following,
            None => break,
        }
    }
    out
}

/// Whether a filled buffer may change which programs a folder holds. An empty
/// one is the OS saying it dropped records, and a malformed one says nothing
/// either: both count as a change, which the next listing then confirms or
/// not.
#[must_use]
pub fn notify_buffer_is_relevant(buffer: &[u8]) -> bool {
    if buffer.is_empty() {
        return true;
    }
    let records = notify_records(buffer);
    records.is_empty() || records.iter().any(NotifyRecord::may_change_programs)
}

fn u32_at(header: &[u8], at: usize) -> u32 {
    header
        .get(at..at + 4)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map_or(0, u32::from_le_bytes)
}
