#![no_main]
//! Bytes arriving on the service pipe: the length-prefixed frame codec and the
//! request envelope it decodes into, then the class the service derives from it.

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use nrr_service_runtime::ipc::{IpcRequestEnvelope, IpcResponseEnvelope};
use nrr_shared::ipc_transport::{canonical_operation_class, IPC_MAX_MESSAGE_BYTES};
use nrr_shared::ipc_wire::read_frame;

fuzz_target!(|data: &[u8]| {
    if data.len() > IPC_MAX_MESSAGE_BYTES + 4 {
        return;
    }
    let mut cursor = Cursor::new(data);
    if let Ok(request) = read_frame::<_, IpcRequestEnvelope>(&mut cursor) {
        let _ = canonical_operation_class(request.operation, &request.payload);
        let _ = request.operation.slug();
    }
    let mut cursor = Cursor::new(data);
    let _ = read_frame::<_, IpcResponseEnvelope>(&mut cursor);
    let mut cursor = Cursor::new(data);
    let _ = read_frame::<_, serde_json::Value>(&mut cursor);
});
