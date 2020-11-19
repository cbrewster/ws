#[macro_use]
extern crate bitflags;

use std::{convert::Infallible, future::Future, pin::Pin, task::Poll};

use anyhow::Result;
use byteorder::ReadBytesExt;
use http::{header::CONNECTION, header::UPGRADE, Method, Request, Response, StatusCode};
use hyper::{service::Service, upgrade::Upgraded, Body};
use sha1::Digest;
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::mpsc::{error::SendError, Receiver, Sender},
};

#[derive(Debug)]
pub enum Message {
    Text(String),
    Binary(Vec<u8>),
    Close,
}

pub struct WebSocket {
    sender: Sender<Message>,
    receiver: Receiver<Message>,
}

impl WebSocket {
    pub async fn recv(&mut self) -> Option<Message> {
        self.receiver.recv().await
    }

    pub async fn send(&mut self, msg: Message) -> Result<(), SendError<Message>> {
        self.sender.send(msg).await
    }
}

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

#[derive(Debug, Copy, Clone)]
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

impl Into<u8> for Opcode {
    fn into(self) -> u8 {
        match self {
            Opcode::Continuation => 0x0,
            Opcode::Text => 0x1,
            Opcode::Binary => 0x2,
            Opcode::NonControl(v) => v,
            Opcode::ConnectionClose => 0x8,
            Opcode::Ping => 0x9,
            Opcode::Pong => 0xA,
            Opcode::Control(v) => v,
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
            flags,
            payload_length,
            extension: vec![],
            application,
        })
    }

    async fn write<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        let mut byte = 0u8;

        // First Byte:
        // | FIN | RSV1 | RSV2 | RSV3 | OPCODE (4) |

        if self.flags.contains(Flags::FIN) {
            byte |= 0x80;
        }

        if self.flags.contains(Flags::RSV1) {
            byte |= 0x40;
        }

        if self.flags.contains(Flags::RSV2) {
            byte |= 0x20;
        }

        if self.flags.contains(Flags::RSV3) {
            byte |= 0x10;
        }

        let opcode: u8 = self.opcode.into();
        // Mask it for sanity.
        byte |= opcode & 0x0F;

        writer.write(&[byte]).await?;

        // Always mask
        byte = 0x80;

        if self.payload_length < 126 {
            byte |= self.payload_length as u8;
        } else {
            todo!()
        }

        writer.write(&[byte]).await?;

        // TODO: lol rand gen
        let mask = [0xFF, 0x00, 0xFF, 0x00];

        writer.write(&mask).await?;

        // TODO: Maybe buffer this up into bigger chunks before writing?
        for (i, byte) in self.application.iter().enumerate() {
            writer.write(&[byte ^ mask[i % 4]]).await?;
        }

        Ok(())
    }
}

fn bad_request() -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Body::empty())
        .unwrap()
}

struct WebSocketWriter {
    writer: WriteHalf<Upgraded>,
}

impl WebSocketWriter {
    async fn write_message(&mut self, msg: Message) -> Result<(), WsError> {
        // For now lets deliver this is payload chunks of <= 125 bytes
        let (opcode, bytes) = match &msg {
            Message::Close => todo!(),
            Message::Binary(binary) => (Opcode::Binary, binary.as_slice()),
            Message::Text(text) => (Opcode::Text, text.as_bytes()),
        };

        let total_chunks = bytes.len() / 125;

        for (i, chunk) in bytes.chunks(125).enumerate() {
            let mut flags = Flags::empty();
            if i == total_chunks {
                flags |= Flags::FIN;
            }
            let frame = Frame {
                flags,
                opcode: if i == 0 { opcode } else { Opcode::Continuation },
                payload_length: chunk.len() as u64,
                extension: vec![],
                application: chunk.into(),
            };
            frame.write(&mut self.writer).await?;
        }

        Ok(())
    }
}

struct WebSocketReader {
    reader: ReadHalf<Upgraded>,
}

impl WebSocketReader {
    async fn read_message(&mut self) -> Result<Message, WsError> {
        let mut application_buffer = vec![];
        let mut current_op = None;

        loop {
            let mut frame = Frame::read(&mut self.reader).await?;

            // TODO: Handle these cases
            match frame.opcode {
                Opcode::NonControl(_)
                | Opcode::ConnectionClose
                | Opcode::Ping
                | Opcode::Pong
                | Opcode::Control(_) => todo!(),
                _ => {}
            };

            // We should either be starting a new message or get continuations.
            match (current_op, frame.opcode) {
                (None, op) => {
                    current_op = Some(op);
                }
                (Some(_), Opcode::Continuation) => {}
                _ => return Err(WsError::ProtocolError("Unexpected opcode".into())),
            }
            application_buffer.append(&mut frame.application);

            // If this was the last frame, gather the bits and deliver the message to the application.
            if frame.flags.contains(Flags::FIN) {
                let op = match current_op {
                    None => return Err(WsError::ProtocolError("Expected op".into())),
                    Some(op) => op,
                };

                match op {
                    Opcode::Binary => return Ok(Message::Binary(application_buffer)),
                    Opcode::Text => {
                        return Ok(Message::Text(
                            String::from_utf8(application_buffer).map_err(|_| {
                                WsError::ProtocolError("content not valid utf8".into())
                            })?,
                        ))
                    }
                    _ => return Err(WsError::ProtocolError("Unexpected opcode".into())),
                };
            }
        }
    }
}

async fn handle_upgraded(
    upgraded: Upgraded,
    mut receiver: Receiver<Message>,
    mut sender: Sender<Message>,
) -> Result<(), WsError> {
    let (reader, writer) = tokio::io::split(upgraded);

    tokio::task::spawn(async move {
        let mut writer = WebSocketWriter { writer };
        while let Some(msg) = receiver.recv().await {
            if let Err(err) = writer.write_message(msg).await {
                eprintln!("Write message error: {}", err);
            }
        }
    });

    tokio::task::spawn(async move {
        let mut reader = WebSocketReader { reader };
        loop {
            let msg = match reader.read_message().await {
                Ok(frame) => frame,
                Err(WsError::IoError(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // TODO: Send close or something
                    return;
                }
                Err(err) => {
                    eprintln!("WS Error: {}", err);
                    return;
                }
            };

            if let Err(err) = sender.send(msg).await {
                eprintln!("Error sending msg: {}", err);
            }
        }
    });

    Ok(())
}

pub struct WebSocketHandler<H> {
    handler: Option<H>,
}

impl<H, F> WebSocketHandler<H>
where
    H: FnMut(WebSocket) -> F + Send + 'static,
    F: Future + Send,
{
    pub fn new(handler: H) -> Self {
        Self {
            handler: Some(handler),
        }
    }
}

impl<H, F> Service<Request<Body>> for WebSocketHandler<H>
where
    H: FnMut(WebSocket) -> F + Send + 'static,
    F: Future + Send,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let handler = self.handler.take();

        let (client_sender, client_receiver) = tokio::sync::mpsc::channel(10);
        let (server_sender, server_receiver) = tokio::sync::mpsc::channel(10);

        let ws = WebSocket {
            sender: client_sender,
            receiver: server_receiver,
        };

        if let Some(mut handler) = handler {
            tokio::task::spawn(async move {
                (handler)(ws).await;
            });
        }

        let fut = async {
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
            tokio::task::spawn(async move {
                match req.into_body().on_upgrade().await {
                    Ok(upgraded) => {
                        if let Err(err) =
                            handle_upgraded(upgraded, client_receiver, server_sender).await
                        {
                            eprintln!("WebSocket Error: {}", err);
                        }
                    }
                    Err(err) => {
                        eprintln!("Failed to upgrade: {}", err);
                    }
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
        };

        Box::pin(fut)
    }
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
