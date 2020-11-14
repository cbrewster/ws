#[macro_use]
extern crate bitflags;

use std::convert::Infallible;

use anyhow::Result;
use byteorder::ReadBytesExt;
use http::{header::CONNECTION, header::UPGRADE, Method, Request, Response, StatusCode};
use hyper::{upgrade::Upgraded, Body};
use sha1::Digest;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

#[derive(Error, Debug)]
pub enum WsError {
    #[error("Protocol Error: {0}")]
    ProtocolError(String),
    #[error("io error")]
    IoError(#[from] std::io::Error),
}

const WS_KEY_APPEND: &'static str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

bitflags! {
    struct Flags: u32 {
        const FIN  = 0b00000001;
        const RSV1 = 0b00000010;
        const RSV2 = 0b00000100;
        const RSV3 = 0b00001000;
    }
}

#[derive(Debug)]
enum Opcode {
    Continuation,
    Text,
    Binary,
    NonControl(u8),
    ConnectionClose,
    Ping,
    Pong,
    Control(u8),
}

impl From<u8> for Opcode {
    fn from(value: u8) -> Self {
        match value & 0xF {
            0x0 => Opcode::Continuation,
            0x1 => Opcode::Text,
            0x2 => Opcode::Binary,
            value @ 0x3..=0x7 => Opcode::NonControl(value),
            0x8 => Opcode::ConnectionClose,
            0x9 => Opcode::Ping,
            0xA => Opcode::Pong,
            value @ 0xB..=0xF => Opcode::Control(value),
            _ => unreachable!(),
        }
    }
}

#[derive(Debug)]
struct Frame {
    flags: Flags,
    opcode: Opcode,
    payload_length: u64,
    extension: Vec<u8>,
    application: Vec<u8>,
}

impl Frame {
    async fn read<R: AsyncRead + Unpin>(mut reader: R) -> Result<Frame, WsError> {
        let mut flags = Flags::empty();
        let mut header = [0; 2];
        reader.read_exact(&mut header).await?;
        let mut payload_length = (header[1] & 0x7F) as u64;

        // First Byte:
        // | FIN | RSV1 | RSV2 | RSV3 | OPCODE (4) |

        if header[0] & 0x80 == 0x80 {
            flags |= Flags::FIN;
        }

        if header[0] & 0x40 == 0x40 {
            flags |= Flags::RSV1;
        }

        if header[0] & 0x20 == 0x20 {
            flags |= Flags::RSV2;
        }

        if header[0] & 0x10 == 0x10 {
            flags |= Flags::RSV3;
        }

        let opcode = Opcode::from(header[0]);

        // Second Byte:
        // | MASK | Payload len (7) |

        let masked = header[1] & 0x80 == 0x80;

        if payload_length == 126 {
            payload_length = reader.read_u16().await? as u64;
            if payload_length < 126 {
                return Err(WsError::ProtocolError(
                    "Must use minimal bits for payload length".into(),
                ));
            }
        }
        if payload_length == 127 {
            payload_length = reader.read_u64().await? as u64;
            if payload_length < 127 {
                return Err(WsError::ProtocolError(
                    "Must use minimal bits for payload length".into(),
                ));
            }
        }

        let mask = if masked {
            let mut mask = [0; 4];
            reader.read_exact(&mut mask).await?;
            Some(mask)
        } else {
            None
        };

        // TODO: Handle extension data!

        let mut application = vec![0; payload_length as usize];
        reader.read_exact(&mut application).await?;
        // Unmask it
        if let Some(mask) = mask {
            for (i, byte) in application.iter_mut().enumerate() {
                *byte ^= mask[i % 4];
            }
        }

        Ok(Frame {
            opcode,
            flags: Flags::empty(),
            payload_length,
            extension: vec![],
            application,
        })
    }
}

fn bad_request() -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Body::empty())
        .unwrap()
}

async fn handle_upgraded(mut upgraded: Upgraded) -> Result<()> {
    println!("We're doing it!");
    loop {
        let frame = Frame::read(&mut upgraded).await?;
        // TODO: Check flags and return error if something is up!

        println!("Got frame {:?}", frame);
    }
}

pub async fn web_socket(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    if let Err(e) = handshake(&req) {
        eprintln!("Handshake error: {}", e);
        return Ok(bad_request());
    }

    let accept_key = match compute_accept_key(&req) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("Computing Sec-WebSocket-Accept: {}", e);
            return Ok(bad_request());
        }
    };

    println!("Lookin good!");

    tokio::spawn(async move {
        match req.into_body().on_upgrade().await {
            Ok(upgraded) => {
                if let Err(e) = handle_upgraded(upgraded).await {
                    eprintln!("WebSocket error: {}", e);
                }
            }
            Err(e) => eprintln!("Failed to upgrade: {}", e),
        }
    });

    let res = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(UPGRADE, "websocket")
        .header(CONNECTION, "Upgrade")
        .header("Sec-WebSocket-Accept", accept_key)
        .body(Body::empty())
        .expect("failed to build response");

    Ok(res)
}

fn compute_accept_key(req: &Request<Body>) -> Result<String> {
    let req_key = get_header_str(&req, "Sec-WebSocket-Key")?;

    let mut hasher = sha1::Sha1::new();
    hasher.update(format!("{}{}", req_key, WS_KEY_APPEND).as_bytes());

    let sha1 = hasher.finalize();
    Ok(base64::encode(sha1))
}

fn get_header_str<'a, 'b>(req: &'a Request<Body>, key: &'b str) -> Result<&'a str, WsError> {
    match req.headers().get(key).map(|v| v.to_str()) {
        Some(Ok(upgrade)) => Ok(upgrade),
        Some(Err(e)) => Err(WsError::ProtocolError(format!(
            "Reading {} header: {}",
            key, e
        ))),
        None => Err(WsError::ProtocolError(format!("Missing {} header", key))),
    }
}

fn handshake(req: &Request<Body>) -> Result<(), WsError> {
    // Spec Section 4.2.1

    // Step 1.
    if req.version() < http::Version::HTTP_11 {
        return Err(WsError::ProtocolError("Invalid HTTP Version".into()));
    }

    if req.method() != Method::GET {
        return Err(WsError::ProtocolError("Invalid Method".into()));
    }

    // TODO: Step 2.

    // Step 3.
    if !get_header_str(req, UPGRADE.as_str())?
        .to_ascii_lowercase()
        .contains("websocket")
    {
        return Err(WsError::ProtocolError(
            "Upgrade header does not contain websocket".into(),
        ));
    }

    // Step 4.
    if !get_header_str(req, CONNECTION.as_str())?
        .to_ascii_lowercase()
        .contains("upgrade")
    {
        return Err(WsError::ProtocolError(
            "Connection header does not contain upgrade".into(),
        ));
    }

    // Step 5.
    let ws_key_bytes = match base64::decode(get_header_str(req, "Sec-WebSocket-Key")?) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err(WsError::ProtocolError(
                "Failed to base64 decode websocket key".into(),
            ))
        }
    };

    if ws_key_bytes.len() != 16 {
        dbg!(&ws_key_bytes);
        return Err(WsError::ProtocolError(
            "Sec-WebSocket-Key decoded is not 16 bytes".into(),
        ));
    }

    // Step 6.
    if get_header_str(req, "Sec-WebSocket-Version")? != "13" {
        return Err(WsError::ProtocolError(
            "Sec-WebSocket-Version is not 13".into(),
        ));
    }

    // TODO: (Optional) Steps 7, 8, 9

    Ok(())
}
