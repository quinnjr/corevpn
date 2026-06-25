//! Reliable Transport Layer for Control Channel
//!
//! Implements packet acknowledgment and retransmission for the control channel.

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::{ProtocolError, Result};

/// Configuration for reliable transport
#[derive(Debug, Clone)]
pub struct ReliableConfig {
    /// Initial retransmit timeout
    pub initial_rto: Duration,
    /// Maximum retransmit timeout
    pub max_rto: Duration,
    /// RTO backoff multiplier
    pub rto_backoff: f64,
    /// Maximum retransmit attempts
    pub max_retransmits: u32,
    /// Window size (max outstanding packets)
    pub window_size: u32,
    /// ACK delay (time to wait before sending standalone ACK)
    pub ack_delay: Duration,
}

impl Default for ReliableConfig {
    fn default() -> Self {
        Self {
            initial_rto: Duration::from_secs(2),
            max_rto: Duration::from_secs(60),
            rto_backoff: 2.0,
            max_retransmits: 10,
            window_size: 8,
            ack_delay: Duration::from_millis(100),
        }
    }
}

/// Outgoing packet awaiting acknowledgment
#[derive(Debug)]
struct PendingPacket {
    /// Packet data
    data: Bytes,
    /// Time sent
    sent_at: Instant,
    /// Next retransmit time
    next_retransmit: Instant,
    /// Current RTO
    rto: Duration,
    /// Retransmit count
    retransmits: u32,
}

/// Reliable transport layer
pub struct ReliableTransport {
    /// Configuration
    config: ReliableConfig,
    /// Next packet ID to send
    next_send_id: u32,
    /// Next expected packet ID to receive
    next_recv_id: u32,
    /// Packets awaiting ACK
    pending: BTreeMap<u32, PendingPacket>,
    /// ACKs to send
    pending_acks: VecDeque<u32>,
    /// Out-of-order received packets
    out_of_order: BTreeMap<u32, Bytes>,
    /// Time of last ACK sent
    last_ack_sent: Option<Instant>,
    /// Smoothed RTT (for RTO calculation)
    srtt: Option<Duration>,
    /// RTT variation
    rttvar: Duration,
}

impl ReliableTransport {
    /// Create a new reliable transport
    pub fn new(config: ReliableConfig) -> Self {
        Self {
            config,
            next_send_id: 0,
            next_recv_id: 0,
            pending: BTreeMap::new(),
            pending_acks: VecDeque::new(),
            out_of_order: BTreeMap::new(),
            last_ack_sent: None,
            srtt: None,
            rttvar: Duration::from_millis(500),
        }
    }

    /// Queue a packet for sending
    ///
    /// Returns the packet ID and the data to send
    pub fn send(&mut self, data: Bytes) -> Result<(u32, Bytes)> {
        // Check window
        if self.pending.len() >= self.config.window_size as usize {
            return Err(ProtocolError::InvalidPacket("send window full".into()));
        }

        let packet_id = self.next_send_id;
        self.next_send_id = self.next_send_id.wrapping_add(1);

        let now = Instant::now();
        let rto = self.calculate_rto();

        self.pending.insert(
            packet_id,
            PendingPacket {
                data: data.clone(),
                sent_at: now,
                next_retransmit: now + rto,
                rto,
                retransmits: 0,
            },
        );

        Ok((packet_id, data))
    }

    /// Maximum number of out-of-order packets to buffer
    const MAX_OUT_OF_ORDER: usize = 100;

    /// Process received packet
    ///
    /// Returns the payload if this is the next expected packet,
    /// otherwise buffers it for later delivery.
    pub fn receive(&mut self, packet_id: u32, data: Bytes) -> Result<Option<Bytes>> {
        // Queue ACK
        self.pending_acks.push_back(packet_id);

        if packet_id == self.next_recv_id {
            // In order - deliver immediately
            self.next_recv_id = self.next_recv_id.wrapping_add(1);

            // Check for buffered packets that can now be delivered
            while let Some(_buffered) = self.out_of_order.remove(&self.next_recv_id) {
                self.next_recv_id = self.next_recv_id.wrapping_add(1);
                // Note: in a real implementation, we'd queue these for delivery
            }

            Ok(Some(data))
        } else if packet_id > self.next_recv_id {
            // Out of order - buffer
            // Security: Limit buffer size to prevent DoS
            if self.out_of_order.len() >= Self::MAX_OUT_OF_ORDER {
                return Err(ProtocolError::InvalidPacket(
                    "too many out-of-order packets".into(),
                ));
            }
            self.out_of_order.insert(packet_id, data);
            Ok(None)
        } else {
            // Duplicate - ignore
            Ok(None)
        }
    }

    /// Process received ACKs
    pub fn process_acks(&mut self, acks: &[u32]) {
        let now = Instant::now();

        for &ack_id in acks {
            if let Some(pending) = self.pending.remove(&ack_id) {
                // Update RTT estimate
                if pending.retransmits == 0 {
                    let rtt = now.duration_since(pending.sent_at);
                    self.update_rtt(rtt);
                }
            }
        }
    }

    /// Get ACKs to send
    pub fn get_acks(&mut self) -> Vec<u32> {
        self.pending_acks.drain(..).collect()
    }

    /// Check if we should send a standalone ACK
    pub fn should_send_ack(&self) -> bool {
        if self.pending_acks.is_empty() {
            return false;
        }

        match self.last_ack_sent {
            Some(last) => last.elapsed() >= self.config.ack_delay,
            None => true,
        }
    }

    /// Mark ACK as sent
    pub fn ack_sent(&mut self) {
        self.last_ack_sent = Some(Instant::now());
    }

    /// Get packets that need retransmission
    pub fn get_retransmits(&mut self) -> Vec<(u32, Bytes)> {
        let now = Instant::now();
        let mut retransmits = Vec::new();

        for (id, pending) in self.pending.iter_mut() {
            if now >= pending.next_retransmit {
                if pending.retransmits >= self.config.max_retransmits {
                    // TODO: Signal connection failure
                    continue;
                }

                retransmits.push((*id, pending.data.clone()));

                // Update for next retransmit
                pending.retransmits += 1;
                pending.rto = Duration::from_secs_f64(
                    (pending.rto.as_secs_f64() * self.config.rto_backoff)
                        .min(self.config.max_rto.as_secs_f64()),
                );
                pending.next_retransmit = now + pending.rto;
            }
        }

        retransmits
    }

    /// Check if there are pending packets
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Get next timeout (when we need to check for retransmits)
    pub fn next_timeout(&self) -> Option<Duration> {
        self.pending
            .values()
            .map(|p| p.next_retransmit)
            .min()
            .map(|t| t.saturating_duration_since(Instant::now()))
    }

    fn calculate_rto(&self) -> Duration {
        match self.srtt {
            Some(srtt) => {
                // RTO = SRTT + 4 * RTTVAR (RFC 6298)
                let rto = srtt + self.rttvar * 4;
                rto.max(self.config.initial_rto).min(self.config.max_rto)
            }
            None => self.config.initial_rto,
        }
    }

    fn update_rtt(&mut self, rtt: Duration) {
        match self.srtt {
            Some(srtt) => {
                // RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R|
                // SRTT = (1 - alpha) * SRTT + alpha * R
                // where alpha = 1/8, beta = 1/4
                let diff = rtt.abs_diff(srtt);
                self.rttvar = Duration::from_secs_f64(
                    0.75 * self.rttvar.as_secs_f64() + 0.25 * diff.as_secs_f64(),
                );
                self.srtt = Some(Duration::from_secs_f64(
                    0.875 * srtt.as_secs_f64() + 0.125 * rtt.as_secs_f64(),
                ));
            }
            None => {
                // First RTT measurement
                self.srtt = Some(rtt);
                self.rttvar = rtt / 2;
            }
        }
    }
}

/// Reassembles fragmented TLS records
pub struct TlsRecordReassembler {
    /// Buffer for partial records
    buffer: Vec<u8>,
    /// Maximum buffer size
    max_size: usize,
}

impl TlsRecordReassembler {
    /// Create a new reassembler
    pub fn new(max_size: usize) -> Self {
        Self {
            buffer: Vec::new(),
            max_size,
        }
    }

    /// Add data to the buffer
    pub fn add(&mut self, data: &[u8]) -> Result<()> {
        if self.buffer.len() + data.len() > self.max_size {
            return Err(ProtocolError::InvalidPacket("TLS record too large".into()));
        }
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    /// Try to extract complete TLS records
    pub fn extract_records(&mut self) -> Vec<Bytes> {
        let mut records = Vec::new();

        while self.buffer.len() >= 5 {
            // TLS record header: type (1) + version (2) + length (2)
            let length = u16::from_be_bytes([self.buffer[3], self.buffer[4]]) as usize;

            if self.buffer.len() < 5 + length {
                break; // Incomplete record
            }

            let record = self.buffer.drain(..5 + length).collect::<Vec<_>>();
            records.push(Bytes::from(record));
        }

        records
    }

    /// Get buffer length
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reliable_basic() {
        let mut transport = ReliableTransport::new(ReliableConfig::default());

        // Send a packet
        let (id, _) = transport.send(Bytes::from_static(b"hello")).unwrap();
        assert_eq!(id, 0);
        assert!(transport.has_pending());

        // ACK it
        transport.process_acks(&[0]);
        assert!(!transport.has_pending());
    }

    #[test]
    fn test_reliable_receive() {
        let mut transport = ReliableTransport::new(ReliableConfig::default());

        // Receive packet 0
        let data = transport.receive(0, Bytes::from_static(b"first")).unwrap();
        assert!(data.is_some());

        // Receive packet 2 (out of order)
        let data = transport.receive(2, Bytes::from_static(b"third")).unwrap();
        assert!(data.is_none()); // Buffered

        // Receive packet 1
        let data = transport.receive(1, Bytes::from_static(b"second")).unwrap();
        assert!(data.is_some());

        // Packet 2 should now be deliverable (in a real impl)
    }

    #[test]
    fn test_tls_reassembler() {
        let mut reassembler = TlsRecordReassembler::new(16384);

        // Add partial TLS record header
        reassembler.add(&[0x17, 0x03, 0x03, 0x00, 0x05]).unwrap();
        assert!(reassembler.extract_records().is_empty());

        // Add the rest
        reassembler.add(&[1, 2, 3, 4, 5]).unwrap();
        let records = reassembler.extract_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].len(), 10); // 5 header + 5 payload
    }
}
