use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::WsError;

bitflags! {
    pub struct Flags: u32 {
        const FIN  = 0b00000001;
        const RSV1 = 0b00000010;
        const RSV2 = 0b00000100;
        const RSV3 = 0b00001000;
    }
}

#[derive(Debug, Copy, Clone)]
pub enum Opcode {
    Continuation,
    Text,
    Binary,
    ConnectionClose,
    Ping,
    Pong,
}

impl From<u8> for Opcode {
    fn from(value: u8) -> Self {
        match value & 0xF {
            0x0 => Opcode::Continuation,
            0x1 => Opcode::Text,
            0x2 => Opcode::Binary,
            0x8 => Opcode::ConnectionClose,
            0x9 => Opcode::Ping,
            0xA => Opcode::Pong,
            _ => panic!("Unsupported Opcode"),
        }
    }
}

impl Into<u8> for Opcode {
    fn into(self) -> u8 {
        match self {
            Opcode::Continuation => 0x0,
            Opcode::Text => 0x1,
            Opcode::Binary => 0x2,
            Opcode::ConnectionClose => 0x8,
            Opcode::Ping => 0x9,
            Opcode::Pong => 0xA,
        }
    }
}

#[derive(Debug)]
pub struct Frame {
    pub flags: Flags,
    pub opcode: Opcode,
    pub payload_length: u64,
    pub extension: Vec<u8>,
    pub application: Vec<u8>,
}

impl Frame {
    pub async fn read<R: AsyncRead + Unpin>(mut reader: R) -> Result<Frame, WsError> {
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

    pub async fn write<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<(), std::io::Error> {
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
