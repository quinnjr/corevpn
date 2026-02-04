//! HMAC Authentication for OpenVPN tls-auth / tls-crypt
//!
//! Provides pre-shared key authentication for the control channel,
//! protecting against DoS attacks and providing an additional layer of security.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;

use crate::{CryptoError, Result};

type HmacSha256 = Hmac<Sha256>;

/// HMAC authentication key for tls-auth
#[derive(ZeroizeOnDrop)]
pub struct HmacAuth {
    /// Key for outgoing packets
    tx_key: [u8; 32],
    /// Key for incoming packets
    rx_key: [u8; 32],
}

impl HmacAuth {
    /// Key size in bytes
    pub const KEY_SIZE: usize = 32;
    /// HMAC output size in bytes
    pub const HMAC_SIZE: usize = 32;

    /// Create from separate TX and RX keys
    pub fn new(tx_key: [u8; 32], rx_key: [u8; 32]) -> Self {
        Self { tx_key, rx_key }
    }

    /// Create from a single key (same key for both directions)
    pub fn from_single_key(key: [u8; 32]) -> Self {
        Self {
            tx_key: key,
            rx_key: key,
        }
    }

    /// Create from OpenVPN ta.key format (2048-bit / 256 bytes)
    ///
    /// OpenVPN ta.key contains 4 keys:
    /// - Bytes 0-63: Client HMAC key (encrypt direction)
    /// - Bytes 64-127: Server HMAC key (encrypt direction)
    /// - Bytes 128-191: Client HMAC key (decrypt direction)
    /// - Bytes 192-255: Server HMAC key (decrypt direction)
    pub fn from_ta_key(ta_key: &[u8; 256], is_server: bool, key_direction: Option<u8>) -> Result<Self> {
        let (tx_key, rx_key) = match (is_server, key_direction) {
            // Server with key-direction 0 (normal)
            (true, Some(0)) | (true, None) => {
                let mut tx = [0u8; 32];
                let mut rx = [0u8; 32];
                tx.copy_from_slice(&ta_key[64..96]);
                rx.copy_from_slice(&ta_key[0..32]);
                (tx, rx)
            }
            // Server with key-direction 1 (reversed)
            (true, Some(1)) => {
                let mut tx = [0u8; 32];
                let mut rx = [0u8; 32];
                tx.copy_from_slice(&ta_key[0..32]);
                rx.copy_from_slice(&ta_key[64..96]);
                (tx, rx)
            }
            // Client with key-direction 1 (normal for client)
            (false, Some(1)) | (false, None) => {
                let mut tx = [0u8; 32];
                let mut rx = [0u8; 32];
                tx.copy_from_slice(&ta_key[0..32]);
                rx.copy_from_slice(&ta_key[64..96]);
                (tx, rx)
            }
            // Client with key-direction 0 (reversed for client)
            (false, Some(0)) => {
                let mut tx = [0u8; 32];
                let mut rx = [0u8; 32];
                tx.copy_from_slice(&ta_key[64..96]);
                rx.copy_from_slice(&ta_key[0..32]);
                (tx, rx)
            }
            _ => {
                return Err(CryptoError::InvalidPem(
                    format!("Invalid key direction: is_server={}, key_direction={:?}", 
                            is_server, key_direction)
                ));
            }
        };

        Ok(Self { tx_key, rx_key })
    }

    /// Compute HMAC for an outgoing packet
    pub fn authenticate(&self, data: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.tx_key)
            .expect("HMAC key size is always valid");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }

    /// Verify HMAC for an incoming packet (constant-time)
    pub fn verify(&self, data: &[u8], expected_hmac: &[u8; 32]) -> Result<()> {
        let mut mac = HmacSha256::new_from_slice(&self.rx_key)
            .expect("HMAC key size is always valid");
        mac.update(data);
        let computed = mac.finalize().into_bytes();

        if computed.ct_eq(expected_hmac).into() {
            Ok(())
        } else {
            Err(CryptoError::HmacVerificationFailed)
        }
    }

    /// Wrap a packet with HMAC (prepends HMAC to data)
    pub fn wrap(&self, data: &[u8]) -> Vec<u8> {
        let hmac = self.authenticate(data);
        let mut output = Vec::with_capacity(Self::HMAC_SIZE + data.len());
        output.extend_from_slice(&hmac);
        output.extend_from_slice(data);
        output
    }

    /// Unwrap a packet and verify HMAC
    pub fn unwrap(&self, packet: &[u8]) -> Result<Vec<u8>> {
        if packet.len() < Self::HMAC_SIZE {
            return Err(CryptoError::HmacVerificationFailed);
        }

        let (hmac, data) = packet.split_at(Self::HMAC_SIZE);
        let hmac: [u8; 32] = hmac.try_into().unwrap();

        self.verify(data, &hmac)?;
        Ok(data.to_vec())
    }
}

/// tls-crypt key for both HMAC and encryption
#[derive(ZeroizeOnDrop)]
pub struct TlsCryptKey {
    /// Encryption key
    cipher_key: [u8; 32],
    /// HMAC authentication key
    hmac_key: [u8; 32],
}

impl TlsCryptKey {
    /// Create from raw keys
    pub fn new(cipher_key: [u8; 32], hmac_key: [u8; 32]) -> Self {
        Self { cipher_key, hmac_key }
    }

    /// Create from a 512-bit (64-byte) combined key
    pub fn from_combined(key: &[u8; 64]) -> Self {
        let mut cipher_key = [0u8; 32];
        let mut hmac_key = [0u8; 32];
        cipher_key.copy_from_slice(&key[0..32]);
        hmac_key.copy_from_slice(&key[32..64]);
        Self { cipher_key, hmac_key }
    }

    /// Get the cipher key
    pub fn cipher_key(&self) -> &[u8; 32] {
        &self.cipher_key
    }

    /// Get the HMAC key
    pub fn hmac_key(&self) -> &[u8; 32] {
        &self.hmac_key
    }

    /// Wrap control channel packet with tls-crypt (encrypt-then-MAC)
    ///
    /// Format: [HMAC-SHA256(ciphertext) | IV | ciphertext]
    pub fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        use crate::cipher::Cipher;
        use crate::CipherSuite;

        // Generate random IV
        let cipher = Cipher::new(&self.cipher_key, CipherSuite::ChaCha20Poly1305);
        let nonce = cipher.generate_nonce();

        // Encrypt
        let ciphertext = cipher.encrypt(&nonce, plaintext, &[])?;

        // Compute HMAC over IV + ciphertext
        let mut hmac_input = Vec::with_capacity(12 + ciphertext.len());
        hmac_input.extend_from_slice(&nonce);
        hmac_input.extend_from_slice(&ciphertext);

        let mut mac = HmacSha256::new_from_slice(&self.hmac_key)
            .expect("HMAC key size is always valid");
        mac.update(&hmac_input);
        let hmac = mac.finalize().into_bytes();

        // Build output: HMAC | IV | ciphertext
        let mut output = Vec::with_capacity(32 + 12 + ciphertext.len());
        output.extend_from_slice(&hmac);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);

        Ok(output)
    }

    /// Unwrap tls-crypt protected packet
    pub fn unwrap(&self, packet: &[u8]) -> Result<Vec<u8>> {
        use crate::cipher::Cipher;
        use crate::CipherSuite;

        if packet.len() < 32 + 12 + 16 {
            return Err(CryptoError::DecryptionFailed);
        }

        let (hmac, rest) = packet.split_at(32);
        let (nonce, ciphertext) = rest.split_at(12);

        // Verify HMAC first (constant-time)
        let mut mac = HmacSha256::new_from_slice(&self.hmac_key)
            .expect("HMAC key size is always valid");
        mac.update(nonce);
        mac.update(ciphertext);
        let computed = mac.finalize().into_bytes();

        if !bool::from(computed.ct_eq(hmac)) {
            return Err(CryptoError::HmacVerificationFailed);
        }

        // Decrypt
        let nonce: [u8; 12] = nonce.try_into().unwrap();
        let cipher = Cipher::new(&self.cipher_key, CipherSuite::ChaCha20Poly1305);
        cipher.decrypt(&nonce, ciphertext, &[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_auth_roundtrip() {
        let key = [0x42u8; 32];
        let auth = HmacAuth::from_single_key(key);

        let data = b"test packet data";
        let wrapped = auth.wrap(data);
        let unwrapped = auth.unwrap(&wrapped).unwrap();

        assert_eq!(data.as_slice(), unwrapped.as_slice());
    }

    #[test]
    fn test_hmac_auth_tamper_detection() {
        let key = [0x42u8; 32];
        let auth = HmacAuth::from_single_key(key);

        let mut wrapped = auth.wrap(b"test data");
        wrapped[0] ^= 0xFF; // Tamper with HMAC

        assert!(auth.unwrap(&wrapped).is_err());
    }

    #[test]
    fn test_tls_crypt_roundtrip() {
        let key = TlsCryptKey::new([0x42u8; 32], [0x43u8; 32]);

        let plaintext = b"secret control channel data";
        let wrapped = key.wrap(plaintext).unwrap();
        let unwrapped = key.unwrap(&wrapped).unwrap();

        assert_eq!(plaintext.as_slice(), unwrapped.as_slice());
    }

    #[test]
    fn test_tls_crypt_tamper_detection() {
        let key = TlsCryptKey::new([0x42u8; 32], [0x43u8; 32]);

        let mut wrapped = key.wrap(b"secret data").unwrap();
        wrapped[40] ^= 0xFF; // Tamper with ciphertext

        assert!(key.unwrap(&wrapped).is_err());
    }
}
