//! Symmetric cipher implementations for data channel encryption
//!
//! Supports ChaCha20-Poly1305 (preferred) and AES-256-GCM (fallback).
//! Both provide authenticated encryption with associated data (AEAD).
//!
//! # Performance Optimizations
//! - Cipher instances are cached in PacketCipher
//! - Counter-based nonces avoid RNG syscalls
//! - Pre-allocated output buffers reduce allocations
//! - Inlined hot paths for better performance

use aes_gcm::{Aes256Gcm, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, aead::AeadCore};
use zeroize::ZeroizeOnDrop;
use serde::{Serialize, Deserialize};

use crate::{CryptoError, Result};

/// Supported cipher suites
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CipherSuite {
    /// ChaCha20-Poly1305 - preferred for software implementations
    #[default]
    ChaCha20Poly1305,
    /// AES-256-GCM - hardware accelerated on modern CPUs
    Aes256Gcm,
}

impl CipherSuite {
    /// Key size in bytes (256 bits for both suites)
    pub const KEY_SIZE: usize = 32;
    /// Nonce size in bytes (96 bits for both suites)
    pub const NONCE_SIZE: usize = 12;
    /// Authentication tag size in bytes (128 bits for both suites)
    pub const TAG_SIZE: usize = 16;

    /// Get the key size for this cipher suite
    #[inline(always)]
    pub const fn key_size(&self) -> usize {
        Self::KEY_SIZE
    }

    /// Get the nonce size for this cipher suite
    #[inline(always)]
    pub const fn nonce_size(&self) -> usize {
        Self::NONCE_SIZE
    }

    /// Get the tag size for this cipher suite
    #[inline(always)]
    pub const fn tag_size(&self) -> usize {
        Self::TAG_SIZE
    }
}

/// Data channel encryption key with secure memory handling
pub struct DataChannelKey {
    key: [u8; 32],
    /// Implicit IV for AEAD nonce construction (XORed with packet counter)
    implicit_iv: [u8; 12],
    cipher_suite: CipherSuite,
}

impl DataChannelKey {
    /// Create a new data channel key (with zero implicit IV for non-AEAD or tests)
    pub fn new(key: [u8; 32], cipher_suite: CipherSuite) -> Self {
        Self { key, implicit_iv: [0u8; 12], cipher_suite }
    }

    /// Create a new data channel key with implicit IV (for OpenVPN AEAD)
    pub fn new_with_iv(key: [u8; 32], implicit_iv: [u8; 12], cipher_suite: CipherSuite) -> Self {
        Self { key, implicit_iv, cipher_suite }
    }

    /// Get the cipher suite
    pub fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }

    /// Get the implicit IV
    pub fn implicit_iv(&self) -> &[u8; 12] {
        &self.implicit_iv
    }

    /// Create a cipher instance
    pub fn cipher(&self) -> Cipher {
        Cipher::new(&self.key, self.cipher_suite)
    }
}

impl Drop for DataChannelKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
        self.implicit_iv.zeroize();
    }
}

impl ZeroizeOnDrop for DataChannelKey {}

/// AEAD cipher for encrypting/decrypting data channel packets
pub struct Cipher {
    inner: CipherInner,
    suite: CipherSuite,
}

enum CipherInner {
    ChaCha(ChaCha20Poly1305),
    Aes(Box<Aes256Gcm>),
}

impl Cipher {
    /// Create a new cipher instance
    #[inline]
    pub fn new(key: &[u8; 32], suite: CipherSuite) -> Self {
        let inner = match suite {
            CipherSuite::ChaCha20Poly1305 => {
                CipherInner::ChaCha(ChaCha20Poly1305::new(key.into()))
            }
            CipherSuite::Aes256Gcm => {
                CipherInner::Aes(Box::new(Aes256Gcm::new(key.into())))
            }
        };
        Self { inner, suite }
    }

    /// Encrypt plaintext with associated data
    ///
    /// Returns ciphertext with authentication tag appended.
    #[inline]
    pub fn encrypt(&self, nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        use chacha20poly1305::aead::Aead;
        use aes_gcm::aead::Payload;

        let payload = Payload { msg: plaintext, aad };

        match &self.inner {
            CipherInner::ChaCha(cipher) => {
                cipher.encrypt(nonce.into(), payload)
                    .map_err(|_| CryptoError::EncryptionFailed("ChaCha20-Poly1305 encryption failed"))
            }
            CipherInner::Aes(cipher) => {
                cipher.encrypt(nonce.into(), payload)
                    .map_err(|_| CryptoError::EncryptionFailed("AES-256-GCM encryption failed"))
            }
        }
    }

    /// Encrypt plaintext into pre-allocated buffer
    ///
    /// Returns the number of bytes written.
    /// Buffer must have capacity for plaintext + TAG_SIZE bytes.
    #[inline]
    pub fn encrypt_into(&self, nonce: &[u8; 12], plaintext: &[u8], aad: &[u8], out: &mut Vec<u8>) -> Result<usize> {
        use chacha20poly1305::aead::Aead;
        use aes_gcm::aead::Payload;

        let payload = Payload { msg: plaintext, aad };
        let start_len = out.len();

        let ciphertext = match &self.inner {
            CipherInner::ChaCha(cipher) => {
                cipher.encrypt(nonce.into(), payload)
                    .map_err(|_| CryptoError::EncryptionFailed("ChaCha20-Poly1305 encryption failed"))?
            }
            CipherInner::Aes(cipher) => {
                cipher.encrypt(nonce.into(), payload)
                    .map_err(|_| CryptoError::EncryptionFailed("AES-256-GCM encryption failed"))?
            }
        };

        out.extend_from_slice(&ciphertext);
        Ok(out.len() - start_len)
    }

    /// Decrypt ciphertext with associated data
    ///
    /// Verifies authentication tag and returns plaintext.
    #[inline]
    pub fn decrypt(&self, nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        use chacha20poly1305::aead::Aead;
        use aes_gcm::aead::Payload;

        let payload = Payload { msg: ciphertext, aad };

        match &self.inner {
            CipherInner::ChaCha(cipher) => {
                cipher.decrypt(nonce.into(), payload)
                    .map_err(|_| CryptoError::DecryptionFailed)
            }
            CipherInner::Aes(cipher) => {
                cipher.decrypt(nonce.into(), payload)
                    .map_err(|_| CryptoError::DecryptionFailed)
            }
        }
    }

    /// Generate a random nonce using OsRng
    ///
    /// Note: For high-throughput scenarios, consider using counter-based nonces
    /// via PacketCipher which avoids syscall overhead.
    #[inline]
    pub fn generate_nonce(&self) -> [u8; 12] {
        match &self.inner {
            CipherInner::ChaCha(_) => {
                ChaCha20Poly1305::generate_nonce(&mut rand::rngs::OsRng).into()
            }
            CipherInner::Aes(_) => {
                Aes256Gcm::generate_nonce(&mut rand::rngs::OsRng).into()
            }
        }
    }

    /// Get the cipher suite
    #[inline(always)]
    pub fn suite(&self) -> CipherSuite {
        self.suite
    }
}

/// Packet encryptor with automatic nonce management and replay protection.
///
/// Implements the OpenVPN AEAD data channel format:
/// - 4-byte packet ID (big-endian counter)
/// - Nonce = implicit_iv XOR padded(packet_id)
/// - On-wire: [packet_id(4)] [AEAD_tag(16)] [ciphertext]
/// - AAD = packet_id bytes (4 bytes)
///
/// # Performance
/// - Uses counter-based nonces (no RNG syscalls)
/// - Caches cipher instance for reuse
/// - Pre-allocates output buffers with known capacity
pub struct PacketCipher {
    cipher: Cipher,
    /// Implicit IV from key derivation, XORed with packet counter to form nonce
    implicit_iv: [u8; 12],
    /// Outgoing packet counter (32-bit, matching OpenVPN packet_id_type)
    tx_counter: u32,
    /// Replay protection window
    rx_window: ReplayWindow,
}

/// Packet ID header size (4-byte counter, matching OpenVPN)
const PACKET_ID_SIZE: usize = 4;

impl PacketCipher {
    /// Create a new packet cipher
    #[inline]
    pub fn new(key: DataChannelKey) -> Self {
        let implicit_iv = *key.implicit_iv();
        Self {
            cipher: key.cipher(),
            implicit_iv,
            tx_counter: 0,
            rx_window: ReplayWindow::new(),
        }
    }

    /// Build a 12-byte AEAD nonce from implicit IV and packet ID.
    ///
    /// nonce = implicit_iv XOR [packet_id_be(4) || 00000000(8)]
    #[inline(always)]
    fn build_nonce(&self, pid_bytes: &[u8; 4]) -> [u8; 12] {
        let mut nonce = self.implicit_iv;
        nonce[0] ^= pid_bytes[0];
        nonce[1] ^= pid_bytes[1];
        nonce[2] ^= pid_bytes[2];
        nonce[3] ^= pid_bytes[3];
        nonce
    }

    /// Encrypt a packet (OpenVPN AEAD tag-at-end format).
    ///
    /// `ad_prefix` is the header bytes (opcode + peer_id for V2) that precede
    /// the packet ID in the on-wire format. OpenVPN authenticates these as part
    /// of the AEAD AAD: AAD = [ad_prefix] [packet_id(4)].
    ///
    /// Returns: [packet_id(4)] [ciphertext] [AEAD_tag(16)]
    ///
    /// OpenVPN 2.6+ uses AEAD tag at the end by default for AEAD ciphers.
    /// The AEAD library naturally produces ciphertext||tag, so this is the
    /// standard format: [pid(4)] [ciphertext||tag].
    #[inline]
    pub fn encrypt(&mut self, plaintext: &[u8], ad_prefix: &[u8]) -> Result<Vec<u8>> {
        self.tx_counter = self.tx_counter.checked_add(1)
            .ok_or(CryptoError::EncryptionFailed("packet counter overflow"))?;

        let pid_bytes = self.tx_counter.to_be_bytes();
        let nonce = self.build_nonce(&pid_bytes);

        // Build full AAD: [ad_prefix] [pid(4)]
        let mut aad = Vec::with_capacity(ad_prefix.len() + PACKET_ID_SIZE);
        aad.extend_from_slice(ad_prefix);
        aad.extend_from_slice(&pid_bytes);

        // AEAD encrypt: produces ciphertext || tag (standard AEAD output)
        let ct_tag = self.cipher.encrypt(&nonce, plaintext, &aad)?;

        // Tag-at-end format: [pid(4)] [ciphertext||tag]
        let mut output = Vec::with_capacity(PACKET_ID_SIZE + ct_tag.len());
        output.extend_from_slice(&pid_bytes);
        output.extend_from_slice(&ct_tag);

        Ok(output)
    }

    /// Encrypt a packet into a pre-allocated buffer
    ///
    /// Returns the total bytes written.
    /// Buffer should be cleared before calling.
    #[inline]
    pub fn encrypt_into(&mut self, plaintext: &[u8], ad_prefix: &[u8], output: &mut Vec<u8>) -> Result<usize> {
        self.tx_counter = self.tx_counter.checked_add(1)
            .ok_or(CryptoError::EncryptionFailed("packet counter overflow"))?;

        let pid_bytes = self.tx_counter.to_be_bytes();
        let nonce = self.build_nonce(&pid_bytes);

        // Build full AAD: [ad_prefix] [pid(4)]
        let mut aad = Vec::with_capacity(ad_prefix.len() + PACKET_ID_SIZE);
        aad.extend_from_slice(ad_prefix);
        aad.extend_from_slice(&pid_bytes);

        let ct_tag = self.cipher.encrypt(&nonce, plaintext, &aad)?;

        let total = PACKET_ID_SIZE + ct_tag.len();
        output.extend_from_slice(&pid_bytes);
        output.extend_from_slice(&ct_tag);

        Ok(total)
    }

    /// Decrypt a packet with replay protection (OpenVPN AEAD format).
    ///
    /// `ad_prefix` is the header bytes (opcode + peer_id for V2) that precede
    /// the packet ID in the on-wire format. OpenVPN authenticates these as part
    /// of the AEAD AAD: AAD = [ad_prefix] [packet_id(4)].
    ///
    /// Supports both tag-at-end and tag-before-ciphertext formats:
    /// - Tag-at-end (OpenVPN 2.6+): [pid(4)] [ciphertext] [tag(16)]
    /// - Tag-before (legacy):       [pid(4)] [tag(16)] [ciphertext]
    ///
    /// Tries tag-at-end first, falls back to tag-before if decryption fails.
    #[inline]
    pub fn decrypt(&mut self, packet: &[u8], ad_prefix: &[u8]) -> Result<Vec<u8>> {
        const MIN_PACKET_SIZE: usize = PACKET_ID_SIZE + CipherSuite::TAG_SIZE;

        if packet.len() < MIN_PACKET_SIZE {
            return Err(CryptoError::DecryptionFailed);
        }

        // Extract 4-byte packet ID
        let pid_bytes: [u8; 4] = packet[..4].try_into().unwrap();
        let counter = u32::from_be_bytes(pid_bytes) as u64;

        // Check replay
        if !self.rx_window.check_and_update(counter) {
            return Err(CryptoError::ReplayDetected);
        }

        let nonce = self.build_nonce(&pid_bytes);

        // Build full AAD: [ad_prefix] [pid(4)]
        let mut aad = Vec::with_capacity(ad_prefix.len() + PACKET_ID_SIZE);
        aad.extend_from_slice(ad_prefix);
        aad.extend_from_slice(&pid_bytes);

        // Try tag-at-end first: [pid(4)] [ciphertext||tag]
        // The AEAD library expects ciphertext||tag, which is exactly packet[4..]
        let ct_tag = &packet[PACKET_ID_SIZE..];
        if let Ok(plaintext) = self.cipher.decrypt(&nonce, ct_tag, &aad) {
            return Ok(plaintext);
        }

        // Fall back to tag-before: [pid(4)] [tag(16)] [ciphertext]
        // Reassemble as ciphertext||tag for the AEAD library
        let tag = &packet[PACKET_ID_SIZE..PACKET_ID_SIZE + CipherSuite::TAG_SIZE];
        let ct = &packet[PACKET_ID_SIZE + CipherSuite::TAG_SIZE..];
        let mut ct_tag_reordered = Vec::with_capacity(ct.len() + CipherSuite::TAG_SIZE);
        ct_tag_reordered.extend_from_slice(ct);
        ct_tag_reordered.extend_from_slice(tag);

        self.cipher.decrypt(&nonce, &ct_tag_reordered, &aad)
    }

    /// Get current TX counter (for debugging/stats)
    #[inline(always)]
    pub fn tx_counter(&self) -> u64 {
        self.tx_counter as u64
    }
}

/// Sliding window for replay protection
///
/// Uses a 128-bit bitmap for efficient replay detection with O(1) operations.
/// The window tracks the last 128 packet IDs relative to the highest seen.
struct ReplayWindow {
    /// Highest seen packet ID
    highest: u64,
    /// Bitmap of recently seen packets (relative to highest)
    /// Bit 0 = highest, bit N = highest - N
    bitmap: u128,
}

impl ReplayWindow {
    /// Window size in packets (128 bits = 128 packet tracking)
    const WINDOW_SIZE: u64 = 128;

    #[inline]
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
    #[inline]
    fn check_and_update(&mut self, packet_id: u64) -> bool {
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
                // Use saturating shift to handle edge cases
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
            let mask = 1u128 << diff;
            if self.bitmap & mask != 0 {
                return false; // Replay detected
            }

            // Mark as seen
            self.bitmap |= mask;
            true
        }
    }

    /// Reset the replay window (e.g., for key renegotiation)
    #[allow(dead_code)]
    #[inline]
    pub fn reset(&mut self) {
        self.highest = 0;
        self.bitmap = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0x42u8; 32];

        for suite in [CipherSuite::ChaCha20Poly1305, CipherSuite::Aes256Gcm] {
            let cipher = Cipher::new(&key, suite);
            let nonce = cipher.generate_nonce();
            let plaintext = b"Hello, CoreVPN!";
            let aad = b"associated data";

            let ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();
            let decrypted = cipher.decrypt(&nonce, &ciphertext, aad).unwrap();

            assert_eq!(plaintext.as_slice(), decrypted.as_slice());
        }
    }

    #[test]
    fn test_authentication_failure() {
        let key = [0x42u8; 32];
        let cipher = Cipher::new(&key, CipherSuite::ChaCha20Poly1305);
        let nonce = cipher.generate_nonce();

        let ciphertext = cipher.encrypt(&nonce, b"test", b"aad").unwrap();

        // Tamper with ciphertext
        let mut tampered = ciphertext.clone();
        tampered[0] ^= 0xFF;

        assert!(cipher.decrypt(&nonce, &tampered, b"aad").is_err());
    }

    #[test]
    fn test_packet_cipher_replay_protection() {
        let iv = [0xABu8; 12];
        let key = DataChannelKey::new_with_iv([0x42u8; 32], iv, CipherSuite::ChaCha20Poly1305);
        let mut encryptor = PacketCipher::new(key);

        let key2 = DataChannelKey::new_with_iv([0x42u8; 32], iv, CipherSuite::ChaCha20Poly1305);
        let mut decryptor = PacketCipher::new(key2);

        let ad = &[0x48u8, 0x00, 0x00, 0x01]; // V2 header: opcode + peer_id

        // Encrypt some packets
        let p1 = encryptor.encrypt(b"packet 1", ad).unwrap();
        let p2 = encryptor.encrypt(b"packet 2", ad).unwrap();
        let p3 = encryptor.encrypt(b"packet 3", ad).unwrap();

        // Decrypt in order - should work
        assert!(decryptor.decrypt(&p1, ad).is_ok());
        assert!(decryptor.decrypt(&p2, ad).is_ok());

        // Replay p1 - should fail
        assert!(decryptor.decrypt(&p1, ad).is_err());

        // p3 out of order - should work
        assert!(decryptor.decrypt(&p3, ad).is_ok());

        // Replay p3 - should fail
        assert!(decryptor.decrypt(&p3, ad).is_err());
    }

    #[test]
    fn test_replay_window() {
        let mut window = ReplayWindow::new();

        assert!(window.check_and_update(1));
        assert!(window.check_and_update(2));
        assert!(!window.check_and_update(1)); // Replay
        assert!(window.check_and_update(100));
        assert!(!window.check_and_update(1)); // Too old
        assert!(window.check_and_update(99)); // In window
        assert!(!window.check_and_update(99)); // Replay
    }
}
