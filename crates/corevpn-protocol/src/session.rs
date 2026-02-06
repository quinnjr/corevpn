//! Protocol Session Management

use std::time::{Duration, Instant};

use bytes::Bytes;

use corevpn_crypto::{CipherSuite, KeyMaterial};

use crate::{
    KeyId, OpCode, Packet, DataPacket, DataChannel,
    ReliableTransport, ReliableConfig, TlsRecordReassembler,
    ProtocolError, Result,
};
use crate::packet::ControlPacketData;

/// Protocol session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolState {
    /// Initial state, waiting for client hello
    Initial,
    /// TLS handshake in progress
    TlsHandshake,
    /// Key exchange in progress
    KeyExchange,
    /// Authentication in progress
    Authenticating,
    /// Session fully established
    Established,
    /// Rekeying in progress
    Rekeying,
    /// Session terminated
    Terminated,
}

/// Session ID type (8 bytes)
pub type SessionIdBytes = [u8; 8];

/// Replay window for tls-auth packet IDs
/// Uses a 64-bit bitmap to track the last 64 packet IDs
struct ReplayWindow {
    /// Highest seen packet ID
    highest: u32,
    /// Bitmap of recently seen packets (relative to highest)
    /// Bit 0 = highest, bit N = highest - N
    bitmap: u64,
}

impl ReplayWindow {
    /// Window size in packets (64 bits = 64 packet tracking)
    const WINDOW_SIZE: u32 = 64;

    fn new() -> Self {
        Self {
            highest: 0,
            bitmap: 0,
        }
    }

    /// Check if packet ID is valid (not replayed) and update window
    ///
    /// Returns true if the packet should be processed, false if it's a replay
    /// or too old.
    fn check_and_update(&mut self, packet_id: u32) -> bool {
        // Packet ID 0 is invalid (counter starts at 1)
        if packet_id == 0 {
            return false;
        }

        if packet_id > self.highest {
            // New highest packet - advance window
            let shift = packet_id - self.highest;

            if shift >= Self::WINDOW_SIZE {
                // Packet is way ahead, clear entire window
                self.bitmap = 1; // Only mark current packet
            } else {
                // Shift window and mark current packet
                self.bitmap = (self.bitmap << shift) | 1;
            }
            self.highest = packet_id;
            true
        } else {
            // Packet is at or before highest
            let diff = self.highest - packet_id;

            // Check if packet is within window
            if diff >= Self::WINDOW_SIZE {
                return false; // Too old
            }

            // Check if already seen using bit test
            let mask = 1u64 << diff;
            if self.bitmap & mask != 0 {
                return false; // Replay detected
            }

            // Mark as seen
            self.bitmap |= mask;
            true
        }
    }

    /// Reset the replay window (e.g., for key renegotiation)
    fn reset(&mut self) {
        self.highest = 0;
        self.bitmap = 0;
    }
}

/// Protocol session
pub struct ProtocolSession {
    /// Local session ID
    local_session_id: SessionIdBytes,
    /// Remote session ID
    remote_session_id: Option<SessionIdBytes>,
    /// Current protocol state
    state: ProtocolState,
    /// Current key ID
    current_key_id: KeyId,
    /// Reliable transport for control channel
    reliable: ReliableTransport,
    /// TLS record reassembler
    tls_reassembler: TlsRecordReassembler,
    /// Data channels (one per key ID)
    data_channels: [Option<DataChannel>; 8],
    /// Peer ID (for P_DATA_V2)
    peer_id: Option<u32>,
    /// Use tls-auth
    use_tls_auth: bool,
    /// tls-auth key
    tls_auth_key: Option<corevpn_crypto::HmacAuth>,
    /// Replay window for tls-auth packet IDs
    replay_window: ReplayWindow,
    /// Session creation time
    created_at: Instant,
    /// Last activity time
    last_activity: Instant,
    /// Cipher suite to use
    cipher_suite: CipherSuite,
}

impl ProtocolSession {
    /// Create a new server-side session
    pub fn new_server(cipher_suite: CipherSuite) -> Self {
        Self {
            local_session_id: corevpn_crypto::generate_session_id(),
            remote_session_id: None,
            state: ProtocolState::Initial,
            current_key_id: KeyId::default(),
            reliable: ReliableTransport::new(ReliableConfig::default()),
            tls_reassembler: TlsRecordReassembler::new(65536),
            data_channels: Default::default(),
            peer_id: None,
            use_tls_auth: false,
            tls_auth_key: None,
            replay_window: ReplayWindow::new(),
            created_at: Instant::now(),
            last_activity: Instant::now(),
            cipher_suite,
        }
    }

    /// Create a new client-side session
    pub fn new_client(cipher_suite: CipherSuite) -> Self {
        let mut session = Self::new_server(cipher_suite);
        session.state = ProtocolState::Initial;
        session
    }

    /// Get local session ID
    pub fn local_session_id(&self) -> &SessionIdBytes {
        &self.local_session_id
    }

    /// Get remote session ID
    pub fn remote_session_id(&self) -> Option<&SessionIdBytes> {
        self.remote_session_id.as_ref()
    }

    /// Get current state
    pub fn state(&self) -> ProtocolState {
        self.state
    }

    /// Set state
    pub fn set_state(&mut self, state: ProtocolState) {
        self.state = state;
        self.last_activity = Instant::now();
    }

    /// Set remote session ID
    pub fn set_remote_session_id(&mut self, id: SessionIdBytes) {
        self.remote_session_id = Some(id);
    }

    /// Enable tls-auth
    pub fn set_tls_auth(&mut self, key: corevpn_crypto::HmacAuth) {
        self.use_tls_auth = true;
        self.tls_auth_key = Some(key);
    }

    /// Process incoming packet
    pub fn process_packet(&mut self, data: &[u8]) -> Result<ProcessedPacket> {
        self.last_activity = Instant::now();

        // Verify HMAC if tls-auth enabled
        let data = if self.use_tls_auth {
            if let Some(key) = &self.tls_auth_key {
                // First byte is opcode, check if control
                if !data.is_empty() && OpCode::from_byte(data[0])?.is_control() {
                    key.unwrap(data)?
                } else {
                    data.to_vec()
                }
            } else {
                data.to_vec()
            }
        } else {
            data.to_vec()
        };

        let packet = Packet::parse(&data, self.use_tls_auth)?;

        match packet {
            Packet::Control(ctrl) => self.process_control_packet(ctrl),
            Packet::Data(data_pkt) => self.process_data_packet(data_pkt),
        }
    }

    fn process_control_packet(&mut self, ctrl: ControlPacketData) -> Result<ProcessedPacket> {
        // Check replay protection for tls-auth packets
        if self.use_tls_auth {
            if let Some(packet_id) = ctrl.header.packet_id {
                if !self.replay_window.check_and_update(packet_id) {
                    return Err(ProtocolError::ReplayDetected);
                }
            }
        }

        // Process ACKs
        if !ctrl.acks.is_empty() {
            self.reliable.process_acks(&ctrl.acks);
        }

        // Handle different opcodes
        match ctrl.header.opcode {
            OpCode::HardResetClientV2 | OpCode::HardResetClientV3 => {
                // Client initiating connection
                // Security: Validate session ID - generate new one instead of accepting client's
                // This prevents session fixation attacks
                if let Some(remote_sid) = ctrl.header.session_id {
                    // Validate session ID is not all zeros or obviously malicious
                    if remote_sid == [0; 8] {
                        return Err(ProtocolError::InvalidSessionId);
                    }
                    // Accept the session ID but we'll use our own for the response
                    self.remote_session_id = Some(remote_sid);
                }

                // Queue ACK for the client's hard reset packet via the reliable
                // transport so it will be included in our response
                if let Some(packet_id) = ctrl.message_packet_id {
                    let _ = self.reliable.receive(packet_id, Bytes::new())?;
                }

                self.state = ProtocolState::TlsHandshake;

                Ok(ProcessedPacket::HardReset {
                    session_id: self.local_session_id,
                })
            }
            OpCode::HardResetServerV2 => {
                // Server response to hard reset
                if let Some(remote_sid) = ctrl.header.session_id {
                    self.remote_session_id = Some(remote_sid);
                }
                Ok(ProcessedPacket::HardResetAck)
            }
            OpCode::ControlV1 => {
                // TLS data
                if let Some(packet_id) = ctrl.message_packet_id {
                    if let Some(data) = self.reliable.receive(packet_id, ctrl.payload.clone())? {
                        self.tls_reassembler.add(&data)?;
                        let records = self.tls_reassembler.extract_records();
                        if !records.is_empty() {
                            return Ok(ProcessedPacket::TlsData(records));
                        }
                    }
                }
                Ok(ProcessedPacket::None)
            }
            OpCode::AckV1 => {
                // Pure ACK, already processed above
                Ok(ProcessedPacket::None)
            }
            OpCode::SoftResetV1 => {
                // Key renegotiation
                self.state = ProtocolState::Rekeying;
                Ok(ProcessedPacket::SoftReset)
            }
            _ => Err(ProtocolError::UnknownOpcode(ctrl.header.opcode as u8)),
        }
    }

    fn process_data_packet(&mut self, data_pkt: crate::packet::DataPacketData) -> Result<ProcessedPacket> {
        let packet = DataPacket {
            key_id: data_pkt.header.key_id,
            peer_id: data_pkt.peer_id,
            payload: data_pkt.payload,
        };

        let key_id = packet.key_id.0 as usize;
        if let Some(channel) = &mut self.data_channels[key_id] {
            let decrypted = channel.decrypt(&packet)?;
            Ok(ProcessedPacket::Data(decrypted))
        } else {
            Err(ProtocolError::KeyNotAvailable(packet.key_id.0))
        }
    }

    /// Create a hard reset response packet
    pub fn create_hard_reset_response(&mut self) -> Result<Bytes> {
        // Register with reliable transport to get a message_packet_id.
        // OpenVPN requires all control packets (including hard resets) to
        // carry a message_packet_id for the reliable transport layer.
        let (packet_id, _) = self.reliable.send(Bytes::new())?;

        let packet = crate::packet::ControlPacketData {
            header: crate::PacketHeader {
                opcode: OpCode::HardResetServerV2,
                key_id: KeyId::default(),
                session_id: Some(self.local_session_id),
                hmac: None,
                packet_id: None,
                timestamp: None,
            },
            remote_session_id: self.remote_session_id,
            acks: self.reliable.get_acks(),
            message_packet_id: Some(packet_id),
            payload: Bytes::new(),
        };

        let serialized = Packet::Control(packet).serialize();
        Ok(self.maybe_wrap_tls_auth(serialized.freeze()))
    }

    /// Create a control packet with TLS data
    pub fn create_control_packet(&mut self, tls_data: Bytes) -> Result<Bytes> {
        let (packet_id, _) = self.reliable.send(tls_data.clone())?;

        let packet = crate::packet::ControlPacketData {
            header: crate::PacketHeader {
                opcode: OpCode::ControlV1,
                key_id: self.current_key_id,
                session_id: Some(self.local_session_id),
                hmac: None,
                packet_id: None,
                timestamp: None,
            },
            remote_session_id: self.remote_session_id,
            acks: self.reliable.get_acks(),
            message_packet_id: Some(packet_id),
            payload: tls_data,
        };

        let serialized = Packet::Control(packet).serialize();
        Ok(self.maybe_wrap_tls_auth(serialized.freeze()))
    }

    /// Create an ACK packet
    pub fn create_ack_packet(&mut self) -> Option<Bytes> {
        let acks = self.reliable.get_acks();
        if acks.is_empty() {
            return None;
        }

        let packet = crate::packet::ControlPacketData {
            header: crate::PacketHeader {
                opcode: OpCode::AckV1,
                key_id: self.current_key_id,
                session_id: Some(self.local_session_id),
                hmac: None,
                packet_id: None,
                timestamp: None,
            },
            remote_session_id: self.remote_session_id,
            acks,
            message_packet_id: None,
            payload: Bytes::new(),
        };

        self.reliable.ack_sent();
        let serialized = Packet::Control(packet).serialize();
        Some(self.maybe_wrap_tls_auth(serialized.freeze()))
    }

    /// Install data channel keys
    pub fn install_keys(&mut self, key_material: &KeyMaterial, is_server: bool) {
        let key_id = self.current_key_id;
        let idx = key_id.0 as usize;

        let (encrypt_key, decrypt_key) = if is_server {
            (
                key_material.server_data_key(self.cipher_suite),
                key_material.client_data_key(self.cipher_suite),
            )
        } else {
            (
                key_material.client_data_key(self.cipher_suite),
                key_material.server_data_key(self.cipher_suite),
            )
        };

        self.data_channels[idx] = Some(DataChannel::new(
            key_id,
            encrypt_key,
            decrypt_key,
            true,
            self.peer_id,
        ));
    }

    /// Encrypt data for transmission
    pub fn encrypt_data(&mut self, data: &[u8]) -> Result<Bytes> {
        let idx = self.current_key_id.0 as usize;
        if let Some(channel) = &mut self.data_channels[idx] {
            let packet = channel.encrypt(data)?;
            Ok(packet.serialize().freeze())
        } else {
            Err(ProtocolError::KeyNotAvailable(self.current_key_id.0))
        }
    }

    /// Get packets needing retransmission
    pub fn get_retransmits(&mut self) -> Vec<Bytes> {
        self.reliable
            .get_retransmits()
            .into_iter()
            .map(|(id, data)| {
                // Rebuild packet with same ID
                let packet = crate::packet::ControlPacketData {
                    header: crate::PacketHeader {
                        opcode: OpCode::ControlV1,
                        key_id: self.current_key_id,
                        session_id: Some(self.local_session_id),
                        hmac: None,
                        packet_id: None,
                        timestamp: None,
                    },
                    remote_session_id: self.remote_session_id,
                    acks: vec![],
                    message_packet_id: Some(id),
                    payload: data,
                };
                let serialized = Packet::Control(packet).serialize();
                self.maybe_wrap_tls_auth(serialized.freeze())
            })
            .collect()
    }

    /// Check if we should send an ACK
    pub fn should_send_ack(&self) -> bool {
        self.reliable.should_send_ack()
    }

    /// Get next timeout
    pub fn next_timeout(&self) -> Option<Duration> {
        self.reliable.next_timeout()
    }

    /// Check if session is established
    pub fn is_established(&self) -> bool {
        self.state == ProtocolState::Established
    }

    /// Get session duration
    pub fn duration(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get idle time
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed()
    }

    fn maybe_wrap_tls_auth(&self, data: Bytes) -> Bytes {
        if self.use_tls_auth {
            if let Some(key) = &self.tls_auth_key {
                return Bytes::from(key.wrap(&data));
            }
        }
        data
    }

    /// Rotate to next key ID (for rekeying)
    pub fn rotate_key(&mut self) {
        self.current_key_id = self.current_key_id.next();
        // Reset replay window on key rotation
        self.replay_window.reset();
    }
}

/// Result of processing a packet
#[derive(Debug)]
pub enum ProcessedPacket {
    /// No action needed
    None,
    /// Hard reset from client
    HardReset {
        /// Session ID for the new connection
        session_id: SessionIdBytes,
    },
    /// Hard reset acknowledged
    HardResetAck,
    /// TLS records to process
    TlsData(Vec<Bytes>),
    /// Decrypted data packet
    Data(Bytes),
    /// Soft reset (rekey)
    SoftReset,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = ProtocolSession::new_server(CipherSuite::ChaCha20Poly1305);
        assert_eq!(session.state(), ProtocolState::Initial);
        assert!(session.remote_session_id().is_none());
    }

    #[test]
    fn test_hard_reset() {
        let mut session = ProtocolSession::new_server(CipherSuite::ChaCha20Poly1305);

        // Simulate receiving hard reset from client
        let hard_reset = [
            0x38, // opcode=7 (HardResetClientV2), key_id=0
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // session_id
            0x00, // ack_count = 0
            0x00, 0x00, 0x00, 0x00, // message_packet_id = 0
        ];

        let result = session.process_packet(&hard_reset).unwrap();
        matches!(result, ProcessedPacket::HardReset { .. });
        assert_eq!(session.state(), ProtocolState::TlsHandshake);
    }

    #[test]
    fn test_hard_reset_response_has_packet_id() {
        let mut session = ProtocolSession::new_server(CipherSuite::ChaCha20Poly1305);

        // Process client hard reset first
        let hard_reset = [
            0x38, // opcode=7 (HardResetClientV2), key_id=0
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // session_id
            0x00, // ack_count = 0
            0x00, 0x00, 0x00, 0x00, // message_packet_id = 0
        ];
        session.process_packet(&hard_reset).unwrap();

        // Create response and verify it contains message_packet_id
        let response = session.create_hard_reset_response().unwrap();

        // Response format (no tls-auth):
        // [0]    opcode + key_id (HardResetServerV2 = 0x40)
        // [1-8]  session_id (8 bytes)
        // [9]    ack_count (should be 1 - ACK of client's packet 0)
        // [10-13] ack_id[0] (4 bytes, value 0)
        // [14-21] remote_session_id (8 bytes)
        // [22-25] message_packet_id (4 bytes, value 0)
        assert!(response.len() >= 26, "Response too short: {} bytes", response.len());

        // Verify opcode is HardResetServerV2 (opcode=8, key_id=0 → 0x40)
        assert_eq!(response[0], 0x40);

        // Verify ack_count = 1 (ACK of client's hard reset)
        assert_eq!(response[9], 1);

        // Verify ACK'd packet_id = 0
        let ack_id = u32::from_be_bytes(response[10..14].try_into().unwrap());
        assert_eq!(ack_id, 0);

        // Verify message_packet_id = 0 (first outgoing packet)
        let msg_pid = u32::from_be_bytes(response[22..26].try_into().unwrap());
        assert_eq!(msg_pid, 0);
    }
}
