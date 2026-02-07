//! Data Channel Packet Handling

use bytes::{Bytes, BytesMut, BufMut};
use corevpn_crypto::{DataChannelKey, PacketCipher};

use crate::{KeyId, OpCode, ProtocolError, Result};

/// Data channel packet
#[derive(Debug, Clone)]
pub struct DataPacket {
    /// Key ID
    pub key_id: KeyId,
    /// Peer ID (for P_DATA_V2)
    pub peer_id: Option<u32>,
    /// Payload (IP packet)
    pub payload: Bytes,
}

impl DataPacket {
    /// Create a new data packet
    pub fn new(key_id: KeyId, payload: Bytes) -> Self {
        Self {
            key_id,
            peer_id: None,
            payload,
        }
    }

    /// Create a new data packet with peer ID (V2)
    pub fn new_v2(key_id: KeyId, peer_id: u32, payload: Bytes) -> Self {
        Self {
            key_id,
            peer_id: Some(peer_id),
            payload,
        }
    }

    /// Parse from raw encrypted packet
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(ProtocolError::PacketTooShort {
                expected: 1,
                got: 0,
            });
        }

        let opcode = OpCode::from_byte(data[0])?;
        let key_id = KeyId::from_byte(data[0]);

        let (peer_id, payload_start) = if opcode == OpCode::DataV2 {
            if data.len() < 4 {
                return Err(ProtocolError::PacketTooShort {
                    expected: 4,
                    got: data.len(),
                });
            }
            let pid = ((data[1] as u32) << 16) | ((data[2] as u32) << 8) | (data[3] as u32);
            (Some(pid), 4)
        } else {
            (None, 1)
        };

        Ok(Self {
            key_id,
            peer_id,
            payload: Bytes::copy_from_slice(&data[payload_start..]),
        })
    }

    /// Serialize to bytes (header + encrypted payload)
    pub fn serialize(&self) -> BytesMut {
        let opcode = if self.peer_id.is_some() {
            OpCode::DataV2
        } else {
            OpCode::DataV1
        };

        let mut buf = BytesMut::with_capacity(4 + self.payload.len());
        buf.put_u8(opcode.to_byte(self.key_id));

        if let Some(pid) = self.peer_id {
            buf.put_u8((pid >> 16) as u8);
            buf.put_u8((pid >> 8) as u8);
            buf.put_u8(pid as u8);
        }

        buf.put_slice(&self.payload);
        buf
    }
}

/// Data channel encryption/decryption handler
pub struct DataChannel {
    /// Key ID
    key_id: KeyId,
    /// Peer ID (for V2 protocol)
    peer_id: Option<u32>,
    /// Encrypt cipher (outgoing)
    encrypt_cipher: PacketCipher,
    /// Decrypt cipher (incoming)
    decrypt_cipher: PacketCipher,
    /// Whether to use V2 protocol
    use_v2: bool,
    /// Cached AAD prefix for encryption (opcode + peer_id header bytes)
    encrypt_ad_prefix: Vec<u8>,
}

impl DataChannel {
    /// Create a new data channel
    pub fn new(
        key_id: KeyId,
        encrypt_key: DataChannelKey,
        decrypt_key: DataChannelKey,
        use_v2: bool,
        peer_id: Option<u32>,
    ) -> Self {
        // Build the AAD prefix for encryption (header bytes that precede the packet ID).
        // OpenVPN's encrypt_sign() in forward.c:
        //   - P_DATA_V2: header (opcode+peer_id) is prepended to work buffer BEFORE
        //     openvpn_encrypt(), so AAD = [opcode(1)][peer_id(3)][packet_id(4)]
        //   - P_DATA_V1: opcode is prepended AFTER encryption (tls_prepend_opcode_v1),
        //     so AAD = [packet_id(4)] only (no opcode in AAD!)
        let encrypt_ad_prefix = if use_v2 {
            let opcode_byte = OpCode::DataV2.to_byte(key_id);
            let pid = peer_id.unwrap_or(0);
            vec![opcode_byte, (pid >> 16) as u8, (pid >> 8) as u8, pid as u8]
        } else {
            // V1: no header bytes in AAD, just the packet ID (added by PacketCipher)
            vec![]
        };

        Self {
            key_id,
            peer_id,
            encrypt_cipher: PacketCipher::new(encrypt_key),
            decrypt_cipher: PacketCipher::new(decrypt_key),
            use_v2,
            encrypt_ad_prefix,
        }
    }

    /// Get the key ID
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// Build AAD prefix from a received packet's header bytes.
    /// For V2: [opcode_byte(1)] [peer_id(3)]; for V1: empty (no header in AAD)
    fn decrypt_ad_prefix(&self, packet: &DataPacket) -> Vec<u8> {
        if let Some(pid) = packet.peer_id {
            let opcode_byte = OpCode::DataV2.to_byte(packet.key_id);
            vec![opcode_byte, (pid >> 16) as u8, (pid >> 8) as u8, pid as u8]
        } else {
            // V1: no header bytes in AAD (opcode is added after encryption by OpenVPN)
            vec![]
        }
    }

    /// Encrypt an IP packet for transmission
    pub fn encrypt(&mut self, ip_packet: &[u8]) -> Result<DataPacket> {
        let encrypted = self.encrypt_cipher.encrypt(ip_packet, &self.encrypt_ad_prefix)?;

        Ok(DataPacket {
            key_id: self.key_id,
            peer_id: if self.use_v2 { self.peer_id } else { None },
            payload: Bytes::from(encrypted),
        })
    }

    /// Decrypt a data packet
    pub fn decrypt(&mut self, packet: &DataPacket) -> Result<Bytes> {
        if packet.key_id != self.key_id {
            return Err(ProtocolError::KeyNotAvailable(packet.key_id.0));
        }

        let ad_prefix = self.decrypt_ad_prefix(packet);
        let decrypted = self.decrypt_cipher.decrypt(&packet.payload, &ad_prefix)?;
        Ok(Bytes::from(decrypted))
    }
}

/// Compression stub (compression is disabled for security)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// No compression
    None,
    /// LZO stub (accepts but doesn't decompress)
    LzoStub,
    /// LZ4 stub
    Lz4Stub,
}

impl Compression {
    /// Check if compression byte indicates compressed data
    pub fn is_compressed(byte: u8) -> bool {
        // OpenVPN compression prefixes
        // 0xFA = LZO compressed
        // 0xFB = LZ4 compressed
        byte == 0xFA || byte == 0xFB
    }

    /// Strip compression header if present (stub mode)
    pub fn strip_header(data: &[u8]) -> Result<&[u8]> {
        if data.is_empty() {
            return Ok(data);
        }

        match data[0] {
            0xFA | 0xFB => {
                // Compressed data - we don't support actual decompression
                // for security (VORACLE attacks)
                Err(ProtocolError::InvalidPacket(
                    "compressed data not supported".into(),
                ))
            }
            0x00 => {
                // Uncompressed with compression header
                Ok(&data[1..])
            }
            _ => {
                // No compression header
                Ok(data)
            }
        }
    }

    /// Add compression header (always uncompressed)
    pub fn add_header(data: &[u8], comp: Compression) -> Vec<u8> {
        match comp {
            Compression::None => data.to_vec(),
            Compression::LzoStub | Compression::Lz4Stub => {
                let mut out = Vec::with_capacity(1 + data.len());
                out.push(0x00); // Uncompressed marker
                out.extend_from_slice(data);
                out
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corevpn_crypto::CipherSuite;

    #[test]
    fn test_data_packet_v1() {
        let packet = DataPacket::new(KeyId::new(1), Bytes::from_static(&[1, 2, 3, 4]));
        let serialized = packet.serialize();

        let parsed = DataPacket::parse(&serialized).unwrap();
        assert_eq!(parsed.key_id, KeyId::new(1));
        assert!(parsed.peer_id.is_none());
        assert_eq!(&parsed.payload[..], &[1, 2, 3, 4]);
    }

    #[test]
    fn test_data_packet_v2() {
        let packet = DataPacket::new_v2(KeyId::new(2), 12345, Bytes::from_static(&[5, 6, 7, 8]));
        let serialized = packet.serialize();

        let parsed = DataPacket::parse(&serialized).unwrap();
        assert_eq!(parsed.key_id, KeyId::new(2));
        assert_eq!(parsed.peer_id, Some(12345));
        assert_eq!(&parsed.payload[..], &[5, 6, 7, 8]);
    }

    #[test]
    fn test_data_channel() {
        let key1 = DataChannelKey::new([0x42u8; 32], CipherSuite::ChaCha20Poly1305);
        let key2 = DataChannelKey::new([0x42u8; 32], CipherSuite::ChaCha20Poly1305);
        let key3 = DataChannelKey::new([0x42u8; 32], CipherSuite::ChaCha20Poly1305);
        let key4 = DataChannelKey::new([0x42u8; 32], CipherSuite::ChaCha20Poly1305);

        let mut client = DataChannel::new(KeyId::new(0), key1, key2, false, None);
        let mut server = DataChannel::new(KeyId::new(0), key3, key4, false, None);

        // Client encrypts
        let ip_packet = b"Hello, VPN!";
        let encrypted = client.encrypt(ip_packet).unwrap();

        // Server decrypts (note: in real use, server would use client's key for decrypt)
        // This test just verifies the packet format
        assert_eq!(encrypted.key_id, KeyId::new(0));
    }

    #[test]
    fn test_compression_strip() {
        // No compression
        let data = [1, 2, 3, 4];
        assert_eq!(Compression::strip_header(&data).unwrap(), &[1, 2, 3, 4]);

        // Uncompressed with header
        let data = [0x00, 1, 2, 3, 4];
        assert_eq!(Compression::strip_header(&data).unwrap(), &[1, 2, 3, 4]);

        // Compressed (should error)
        let data = [0xFA, 1, 2, 3, 4];
        assert!(Compression::strip_header(&data).is_err());
    }
}
