use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::time::Duration;

const MAX_FRAME: usize = 16 * 1024;
const MAX_MESSAGES: usize = 64;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    #[serde(rename = "type")]
    kind: String,
    protocol: u32,
    #[serde(rename = "requestId")]
    request_id: String,
}

#[derive(Serialize)]
struct Response<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    protocol: u32,
    #[serde(rename = "requestId")]
    request_id: &'a str,
    product: &'static str,
    service: &'static str,
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid browser message")
}

fn serve(input: &mut impl Read, output: &mut impl Write) -> io::Result<()> {
    for _ in 0..MAX_MESSAGES {
        let mut header = [0_u8; 4];
        match input.read_exact(&mut header[..1]) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        }
        input.read_exact(&mut header[1..])?;
        let length = u32::from_ne_bytes(header) as usize;
        if length == 0 || length > MAX_FRAME {
            return Err(invalid());
        }
        let mut payload = vec![0; length];
        input.read_exact(&mut payload)?;
        let request: Request = serde_json::from_slice(&payload).map_err(|_| invalid())?;
        if request.kind != "hello"
            || request.protocol != 1
            || request.request_id.is_empty()
            || request.request_id.len() > 64
            || !request
                .request_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(invalid());
        }
        let response = Response {
            kind: "hello",
            protocol: 1,
            request_id: &request.request_id,
            product: nrr_shared::product_identity::PRODUCT_NAME,
            service: "unknown",
        };
        let response = serde_json::to_vec(&response).map_err(|_| invalid())?;
        let length = u32::try_from(response.len()).map_err(|_| invalid())?;
        output.write_all(&length.to_ne_bytes())?;
        output.write_all(&response)?;
        output.flush()?;
    }
    Ok(())
}

fn with_deadline(
    work: impl FnOnce() -> io::Result<()> + Send + 'static,
    deadline: Duration,
) -> io::Result<()> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let _worker = std::thread::Builder::new()
        .name("browser-message".into())
        .spawn(move || {
            let _ = sender.send(work());
        })?;
    match receiver.recv_timeout(deadline) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "browser host expired",
        )),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err(io::Error::other("browser host stopped"))
        }
    }
}

pub fn run_stdio() -> io::Result<()> {
    with_deadline(
        || serve(&mut io::stdin().lock(), &mut io::stdout().lock()),
        Duration::from_secs(60),
    )
}

#[cfg(feature = "fuzzing")]
pub mod fuzz {
    pub const MAX_MESSAGE_SIZE: usize = super::MAX_FRAME;

    pub fn native_stream(bytes: &[u8]) {
        let mut output = Vec::new();
        let _ = super::serve(&mut std::io::Cursor::new(bytes), &mut output);
    }
}

#[cfg(test)]
mod tests;
