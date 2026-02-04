//! Key Derivation Functions
//!
//! Uses HKDF-SHA256 for deriving encryption keys from shared secrets.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CryptoError, Result, CipherSuite, DataChannelKey};

/// OpenVPN-style key material derived from TLS session
#[derive(ZeroizeOnDrop)]
pub struct KeyMaterial {
    /// Client -> Server encryption key
    pub client_write_key: [u8; 32],
    /// Server -> Client encryption key
    pub server_write_key: [u8; 32],
    /// Client -> Server HMAC key (for tls-auth)
    pub client_hmac_key: [u8; 32],
    /// Server -> Client HMAC key (for tls-auth)
    pub server_hmac_key: [u8; 32],
}

/// Derive key material from a shared secret
///
/// # Arguments
/// * `shared_secret` - The raw shared secret from DH exchange
/// * `client_random` - Client's random value (from TLS handshake)
/// * `server_random` - Server's random value (from TLS handshake)
/// * `info` - Optional context info (e.g., "OpenVPN data channel")
#[inline]
pub fn derive_keys(
    shared_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    info: &[u8],
) -> Result<KeyMaterial> {
    // Combine randoms as salt
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(client_random);
    salt[32..].copy_from_slice(server_random);

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret);

    // Derive 128 bytes (4 x 32-byte keys)
    let mut okm = [0u8; 128];
    hkdf.expand(info, &mut okm)
        .map_err(|_| CryptoError::KeyDerivationFailed("HKDF expansion failed"))?;

    let mut material = KeyMaterial {
        client_write_key: [0u8; 32],
        server_write_key: [0u8; 32],
        client_hmac_key: [0u8; 32],
        server_hmac_key: [0u8; 32],
    };

    material.client_write_key.copy_from_slice(&okm[0..32]);
    material.server_write_key.copy_from_slice(&okm[32..64]);
    material.client_hmac_key.copy_from_slice(&okm[64..96]);
    material.server_hmac_key.copy_from_slice(&okm[96..128]);

    // Zeroize intermediate values
    okm.zeroize();
    salt.zeroize();

    Ok(material)
}

impl KeyMaterial {
    /// Create data channel keys for the client side
    pub fn client_data_key(&self, suite: CipherSuite) -> DataChannelKey {
        DataChannelKey::new(self.client_write_key, suite)
    }

    /// Create data channel keys for the server side
    pub fn server_data_key(&self, suite: CipherSuite) -> DataChannelKey {
        DataChannelKey::new(self.server_write_key, suite)
    }
}

/// Derive a single key from input key material
pub fn derive_single_key(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = zeroize::Zeroizing::new([0u8; 32]);
    hkdf.expand(info, okm.as_mut())
        .map_err(|_| CryptoError::KeyDerivationFailed("HKDF expansion failed"))?;
    Ok(*okm)
}

/// PRF for OpenVPN TLS key expansion
///
/// Compatible with OpenVPN's PRF which uses:
/// P_SHA256(secret, seed) = HMAC_SHA256(secret, A(1) + seed) +
///                          HMAC_SHA256(secret, A(2) + seed) + ...
/// where A(0) = seed, A(i) = HMAC_SHA256(secret, A(i-1))
pub fn openvpn_prf(secret: &[u8], label: &[u8], seed: &[u8], output_len: usize) -> Result<Vec<u8>> {
    use hmac::{Hmac, Mac};

    type HmacSha256 = Hmac<Sha256>;

    // Combine label and seed
    let mut combined_seed = zeroize::Zeroizing::new(Vec::with_capacity(label.len() + seed.len()));
    combined_seed.extend_from_slice(label);
    combined_seed.extend_from_slice(seed);

    let mut output = Vec::with_capacity(output_len);
    let mut a = zeroize::Zeroizing::new(combined_seed.clone());

    while output.len() < output_len {
        // A(i) = HMAC(secret, A(i-1))
        let mut mac = HmacSha256::new_from_slice(secret)
            .map_err(|_| CryptoError::KeyDerivationFailed("Invalid HMAC key"))?;
        mac.update(&a);
        *a = zeroize::Zeroizing::new(mac.finalize().into_bytes().to_vec());

        // P_hash = HMAC(secret, A(i) + seed)
        let mut mac = HmacSha256::new_from_slice(secret)
            .map_err(|_| CryptoError::KeyDerivationFailed("Invalid HMAC key"))?;
        mac.update(&a);
        mac.update(&combined_seed);
        output.extend_from_slice(&mac.finalize().into_bytes());
    }

    output.truncate(output_len);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_keys() {
        let shared_secret = [0x42u8; 32];
        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];

        let keys = derive_keys(&shared_secret, &client_random, &server_random, b"test").unwrap();

        // Keys should be different from each other
        assert_ne!(keys.client_write_key, keys.server_write_key);
        assert_ne!(keys.client_hmac_key, keys.server_hmac_key);
        assert_ne!(keys.client_write_key, keys.client_hmac_key);
    }

    #[test]
    fn test_derive_keys_deterministic() {
        let shared_secret = [0x42u8; 32];
        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];

        let keys1 = derive_keys(&shared_secret, &client_random, &server_random, b"test").unwrap();
        let keys2 = derive_keys(&shared_secret, &client_random, &server_random, b"test").unwrap();

        assert_eq!(keys1.client_write_key, keys2.client_write_key);
    }

    #[test]
    fn test_openvpn_prf() {
        let secret = b"test secret";
        let label = b"test label";
        let seed = b"test seed";

        let output = openvpn_prf(secret, label, seed, 64).unwrap();
        assert_eq!(output.len(), 64);

        // Should be deterministic
        let output2 = openvpn_prf(secret, label, seed, 64).unwrap();
        assert_eq!(output, output2);
    }
}
