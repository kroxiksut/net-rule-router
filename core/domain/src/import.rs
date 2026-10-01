//! The size ceiling a controlled import file must fit under.
//!
//! A preset reaches the service inside one IPC frame, so the file limit is
//! derived from the frame limit rather than set beside it.

/// Room reserved inside one IPC frame for everything that is not the file:
/// the envelope (operation, ids, class, token), the mutation payload's own
/// fields, and JSON punctuation. Generous on purpose — the cost of over-
/// reserving is a slightly smaller allowed file, the cost of under-reserving
/// is a refusal from the wrong layer.
const IMPORT_ENVELOPE_HEADROOM_BYTES: usize = 16 * 1024;

/// Maximum permitted raw rules file size for a controlled import, checked at
/// acquisition, before parsing.
///
/// A preset travels base64-wrapped inside a JSON envelope (4 wire bytes per 3
/// file bytes); a limit set beside the frame size rather than derived from it
/// lets a file pass here and then be refused by the transport as "frame too
/// large" — the wrong layer, in the wrong words.
pub const IMPORT_FILE_SIZE_LIMIT_BYTES: u64 =
    ((nrr_shared::ipc_transport::IPC_MAX_MESSAGE_BYTES - IMPORT_ENVELOPE_HEADROOM_BYTES) / 4 * 3)
        as u64;

#[cfg(test)]
mod tests {
    use super::*;

    /// The cap must be small enough that the file, base64-wrapped, still
    /// leaves room for the envelope inside ONE frame. Otherwise the domain says
    /// yes and the transport says "frame too large" — the exact split the
    /// derivation exists to close. The realistic envelope is measured in
    /// `nrr-service-runtime`, which is where a frame is actually built; this
    /// crate keeps no JSON or base64 dependency to do it here.
    #[test]
    fn the_largest_accepted_import_still_fits_one_frame() {
        const FRAME: usize = nrr_shared::ipc_transport::IPC_MAX_MESSAGE_BYTES;
        // base64 emits 4 characters per 3 input bytes, rounded up.
        let encoded = (IMPORT_FILE_SIZE_LIMIT_BYTES as usize).div_ceil(3) * 4;
        assert!(
            encoded + IMPORT_ENVELOPE_HEADROOM_BYTES <= FRAME,
            "a maximum-size import encodes to {encoded} bytes, which with the {IMPORT_ENVELOPE_HEADROOM_BYTES} byte envelope allowance exceeds the {FRAME} byte frame"
        );

        // Positive control: a flat one-frame cap does NOT fit, so the assertion
        // above tests the derivation rather than a roomy frame limit.
        assert!(FRAME.div_ceil(3) * 4 + IMPORT_ENVELOPE_HEADROOM_BYTES > FRAME);
    }
}
