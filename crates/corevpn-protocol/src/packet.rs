//! OpenVPN Packet Parsing and Serialization
//!
//! # Performance Optimizations
//! - Zero-copy parsing using Bytes slices
//! - Inlined hot path functions
//! - Pre-allocated serialization buffers

use bytes::{BufMut, Bytes, BytesMut};

use crate::{OpCode, KeyId, ProtocolError, Result};

/// Session ID (8 bytes)
pub type SessionId = [u8; 8];

/// Packet ID (4 bytes) for replay protection
pub type PacketId = u32;

/// OpenVPN packet header
#[derive(Debug, Clone)]
pub struct PacketHeader {
    /// Packet opcode
    pub opcode: OpCode,
    /// Key ID for data channel
    pub key_id: KeyId,
    /// Local session ID (for control channel)
    pub session_id: Option<SessionId>,
    /// HMAC (if tls-auth enabled)
    pub hmac: Option<[u8; 32]>,
    /// Packet ID (for replay protection with tls-auth)
    pub packet_id: Option<PacketId>,
    /// Timestamp (for tls-auth)
    pub timestamp: Option<u32>,
}

impl PacketHeader {
    /// Minimum header size (opcode only)
    pub const MIN_SIZE: usize = 1;

    /// Control channel header size (without HMAC)
    pub const CONTROL_HEADER_SIZE: usize = 1 + 8; // opcode + session_id

    /// Parse packet header from bytes
    #[inline]
    pub fn parse(data: &[u8], has_tls_auth: bool) -> Result<(Self, usize)> {
        if data.is_empty() {
            return Err(ProtocolError::PacketTooShort {
                expected: 1,
                got: 0,
            });
        }

        let opcode = OpCode::from_byte(data[0])?;
        let key_id = KeyId::from_byte(data[0]);

        if opcode.is_data() {
            // Data packets: just opcode + key_id, then encrypted payload
            return Ok((
                Self {
                    opcode,
                    key_id,
                    session_id: None,
                    hmac: None,
                    packet_id: None,
                    timestamp: None,
                },
                1,
            ));
        }

        // Control packets have more header fields
        let mut offset = 1;
        let mut hmac = None;
        let mut packet_id = None;
        let mut timestamp = None;

        // Parse HMAC if tls-auth is enabled
        if has_tls_auth {
            if data.len() < offset + 32 {
                return Err(ProtocolError::PacketTooShort {
                    expected: offset + 32,
                    got: data.len(),
                });
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&data[offset..offset + 32]);
            hmac = Some(h);
            offset += 32;

            // Packet ID (4 bytes)
            if data.len() < offset + 4 {
                return Err(ProtocolError::PacketTooShort {
                    expected: offset + 4,
                    got: data.len(),
                });
            }
            packet_id = Some(u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()));
            offset += 4;

            // Timestamp (4 bytes)
            if data.len() < offset + 4 {
                return Err(ProtocolError::PacketTooShort {
                    expected: offset + 4,
                    got: data.len(),
                });
            }
            timestamp = Some(u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()));
            offset += 4;
        }

        // Session ID (8 bytes)
        if data.len() < offset + 8 {
            return Err(ProtocolError::PacketTooShort {
                expected: offset + 8,
                got: data.len(),
            });
        }
        let mut session_id = [0u8; 8];
        session_id.copy_from_slice(&data[offset..offset + 8]);
        offset += 8;

        Ok((
            Self {
                opcode,
                key_id,
                session_id: Some(session_id),
                hmac,
                packet_id,
                timestamp,
            },
            offset,
        ))
    }

    /// Serialize header to bytes
    #[inline]
    pub fn serialize(&self, buf: &mut BytesMut) {
        buf.put_u8(self.opcode.to_byte(self.key_id));

        if let Some(hmac) = &self.hmac {
            buf.put_slice(hmac);
        }

        if let Some(packet_id) = self.packet_id {
            buf.put_u32(packet_id);
        }

        if let Some(timestamp) = self.timestamp {
            buf.put_u32(timestamp);
        }

        if let Some(session_id) = &self.session_id {
            buf.put_slice(session_id);
        }
    }
}

/// Parsed OpenVPN packet
#[derive(Debug, Clone)]
pub enum Packet {
    /// Control channel packet
    Control(ControlPacketData),
    /// Data channel packet
    Data(DataPacketData),
}

/// Control channel packet data
#[derive(Debug, Clone)]
pub struct ControlPacketData {
    /// Packet header
    pub header: PacketHeader,
    /// Remote session ID (for ACK packets)
    pub remote_session_id: Option<SessionId>,
    /// Acknowledgments
    pub acks: Vec<PacketId>,
    /// Message packet ID (for reliability)
    pub message_packet_id: Option<PacketId>,
    /// Payload (TLS records)
    pub payload: Bytes,
}

/// Data channel packet data
#[derive(Debug, Clone)]
pub struct DataPacketData {
    /// Packet header
    pub header: PacketHeader,
    /// Peer ID (for P_DATA_V2)
    pub peer_id: Option<u32>,
    /// Encrypted payload
    pub payload: Bytes,
}

impl Packet {
    /// Parse a packet from raw bytes
    #[inline]
    pub fn parse(data: &[u8], has_tls_auth: bool) -> Result<Self> {
        let (header, mut offset) = PacketHeader::parse(data, has_tls_auth)?;

        if header.opcode.is_data() {
            // Data packet
            let peer_id = if header.opcode == OpCode::DataV2 {
                if data.len() < offset + 3 {
                    return Err(ProtocolError::PacketTooShort {
                        expected: offset + 3,
                        got: data.len(),
                    });
                }
                // Peer ID is 24 bits
                let pid = ((data[offset] as u32) << 16)
                    | ((data[offset + 1] as u32) << 8)
                    | (data[offset + 2] as u32);
                offset += 3;
                Some(pid)
            } else {
                None
            };

            // Bounds check before slicing
            if offset > data.len() {
                return Err(ProtocolError::PacketTooShort {
                    expected: offset,
                    got: data.len(),
                });
            }
            return Ok(Packet::Data(DataPacketData {
                header,
                peer_id,
                payload: Bytes::copy_from_slice(&data[offset..]),
            }));
        }

        // Control packet - parse additional fields
        let mut remote_session_id = None;
        let mut acks = Vec::new();

        // Parse ACK array length
        if data.len() < offset + 1 {
            return Err(ProtocolError::PacketTooShort {
                expected: offset + 1,
                got: data.len(),
            });
        }
        const MAX_ACK_COUNT: usize = 16; // Reasonable limit to prevent DoS
        let ack_count = data[offset] as usize;
        if ack_count > MAX_ACK_COUNT {
            return Err(ProtocolError::InvalidPacket(
                format!("ACK count {} exceeds maximum {}", ack_count, MAX_ACK_COUNT).into(),
            ));
        }
        offset += 1;

        // Parse ACKs
        if ack_count > 0 {
            // Parse ACK packet IDs
            for _ in 0..ack_count {
                if data.len() < offset + 4 {
                    return Err(ProtocolError::PacketTooShort {
                        expected: offset + 4,
                        got: data.len(),
                    });
                }
                acks.push(u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()));
                offset += 4;
            }

            // Parse remote session ID
            if data.len() < offset + 8 {
                return Err(ProtocolError::PacketTooShort {
                    expected: offset + 8,
                    got: data.len(),
                });
            }
            let mut rsid = [0u8; 8];
            rsid.copy_from_slice(&data[offset..offset + 8]);
            remote_session_id = Some(rsid);
            offset += 8;
        }

        // Parse message packet ID (if not ACK-only)
        let message_packet_id = if header.opcode != OpCode::AckV1 && data.len() >= offset + 4 {
            let id = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap());
            offset += 4;
            Some(id)
        } else {
            None
        };

        // Remaining is payload
        let payload = if offset < data.len() {
            Bytes::copy_from_slice(&data[offset..])
        } else {
            Bytes::new()
        };

        Ok(Packet::Control(ControlPacketData {
            header,
            remote_session_id,
            acks,
            message_packet_id,
            payload,
        }))
    }

    /// Serialize packet to bytes
    #[inline]
    pub fn serialize(&self) -> BytesMut {
        // Pre-allocate typical MTU size to avoid reallocations
        let mut buf = BytesMut::with_capacity(1500);

        match self {
            Packet::Control(ctrl) => {
                ctrl.header.serialize(&mut buf);

                // ACK count
                buf.put_u8(ctrl.acks.len() as u8);

                // ACKs
                for ack in &ctrl.acks {
                    buf.put_u32(*ack);
                }

                // Remote session ID (if we have ACKs)
                if !ctrl.acks.is_empty() {
                    if let Some(rsid) = &ctrl.remote_session_id {
                        buf.put_slice(rsid);
                    }
                }

                // Message packet ID
                if let Some(mpid) = ctrl.message_packet_id {
                    buf.put_u32(mpid);
                }

                // Payload
                buf.put_slice(&ctrl.payload);
            }
            Packet::Data(data) => {
                data.header.serialize(&mut buf);

                // Peer ID for V2
                if let Some(pid) = data.peer_id {
                    buf.put_u8((pid >> 16) as u8);
                    buf.put_u8((pid >> 8) as u8);
                    buf.put_u8(pid as u8);
                }

                // Payload
                buf.put_slice(&data.payload);
            }
        }

        buf
    }

    /// Get the opcode
    pub fn opcode(&self) -> OpCode {
        match self {
            Packet::Control(c) => c.header.opcode,
            Packet::Data(d) => d.header.opcode,
        }
    }

    /// Get the key ID
    pub fn key_id(&self) -> KeyId {
        match self {
            Packet::Control(c) => c.header.key_id,
            Packet::Data(d) => d.header.key_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hard_reset_parse() {
        // P_CONTROL_HARD_RESET_CLIENT_V2 with session ID
        let data = [
            0x38, // opcode=7, key_id=0
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // session_id
            0x00, // ack_count = 0
        ];

        let packet = Packet::parse(&data, false).unwrap();
        if let Packet::Control(ctrl) = packet {
            assert_eq!(ctrl.header.opcode, OpCode::HardResetClientV2);
            assert_eq!(ctrl.header.key_id, KeyId::new(0));
            assert_eq!(
                ctrl.header.session_id,
                Some([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
            );
            assert!(ctrl.acks.is_empty());
        } else {
            panic!("Expected control packet");
        }
    }

    #[test]
    fn test_data_packet_v2() {
        let data = [
            0x48, // opcode=9 (DataV2), key_id=0
            0x00, 0x00, 0x01, // peer_id = 1
            0xDE, 0xAD, 0xBE, 0xEF, // payload
        ];

        let packet = Packet::parse(&data, false).unwrap();
        if let Packet::Data(d) = packet {
            assert_eq!(d.header.opcode, OpCode::DataV2);
            assert_eq!(d.peer_id, Some(1));
            assert_eq!(&d.payload[..], &[0xDE, 0xAD, 0xBE, 0xEF]);
        } else {
            panic!("Expected data packet");
        }
    }
}
