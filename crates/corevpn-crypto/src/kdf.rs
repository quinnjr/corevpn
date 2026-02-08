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
    /// Client -> Server HMAC key (for tls-auth / non-AEAD)
    pub client_hmac_key: [u8; 32],
    /// Server -> Client HMAC key (for tls-auth / non-AEAD)
    pub server_hmac_key: [u8; 32],
    /// Client -> Server implicit IV (for AEAD ciphers, 12 bytes)
    pub client_implicit_iv: [u8; 12],
    /// Server -> Client implicit IV (for AEAD ciphers, 12 bytes)
    pub server_implicit_iv: [u8; 12],
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
        client_implicit_iv: [0u8; 12],
        server_implicit_iv: [0u8; 12],
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
    /// Create key material from a raw key block (legacy layout, 128 bytes)
    ///
    /// Expected layout (128 bytes minimum):
    /// - bytes 0..32: client write key
    /// - bytes 32..64: server write key
    /// - bytes 64..96: client HMAC key
    /// - bytes 96..128: server HMAC key
    pub fn from_raw_block(block: &[u8]) -> Self {
        let mut material = Self {
            client_write_key: [0u8; 32],
            server_write_key: [0u8; 32],
            client_hmac_key: [0u8; 32],
            server_hmac_key: [0u8; 32],
            client_implicit_iv: [0u8; 12],
            server_implicit_iv: [0u8; 12],
        };
        material.client_write_key.copy_from_slice(&block[0..32]);
        material.server_write_key.copy_from_slice(&block[32..64]);
        material.client_hmac_key.copy_from_slice(&block[64..96]);
        material.server_hmac_key.copy_from_slice(&block[96..128]);
        material
    }

    /// Create key material from an OpenVPN PRF key block for AEAD ciphers (LEGACY - packed layout).
    ///
    /// **WARNING**: This uses a packed 88-byte layout which does NOT match the actual
    /// OpenVPN key2 struct layout. Use `from_openvpn_key2_block` instead.
    #[allow(dead_code)]
    pub fn from_openvpn_aead_key_block(block: &[u8]) -> Self {
        assert!(block.len() >= 88, "AEAD key block must be at least 88 bytes");
        let mut material = Self {
            client_write_key: [0u8; 32],
            server_write_key: [0u8; 32],
            client_hmac_key: [0u8; 32],
            server_hmac_key: [0u8; 32],
            client_implicit_iv: [0u8; 12],
            server_implicit_iv: [0u8; 12],
        };
        material.client_write_key.copy_from_slice(&block[0..32]);
        material.client_implicit_iv.copy_from_slice(&block[32..44]);
        material.server_write_key.copy_from_slice(&block[44..76]);
        material.server_implicit_iv.copy_from_slice(&block[76..88]);
        material
    }

    /// Create key material from an OpenVPN PRF key2 struct block for AEAD ciphers.
    ///
    /// OpenVPN's PRF outputs 256 bytes directly into the key2.keys struct:
    ///   struct key { uint8_t cipher[64]; uint8_t hmac[64]; };
    ///   struct key2 { int n; struct key keys[2]; };
    ///
    /// Layout (256 bytes):
    /// - bytes   0..64:   key[0].cipher (first 32 used as cipher key)
    /// - bytes  64..128:  key[0].hmac   (first 12 used as implicit IV for AEAD)
    /// - bytes 128..192:  key[1].cipher (first 32 used as cipher key)
    /// - bytes 192..256:  key[1].hmac   (first 12 used as implicit IV for AEAD)
    ///
    /// Key direction mapping (OpenVPN key_direction_state_init):
    ///   KEY_DIRECTION_NORMAL (client):  out_key=0, in_key=1
    ///   KEY_DIRECTION_INVERSE (server): out_key=1, in_key=0
    ///
    /// Therefore:
    /// - key[0] = client encrypt / server decrypt (client→server direction)
    /// - key[1] = server encrypt / client decrypt (server→client direction)
    ///
    /// OpenVPN AEAD implicit IV (from key_ctx_update_implicit_iv in crypto.c):
    ///   For non-epoch keys:
    ///     impl_iv_len = cipher_iv_length - sizeof(packet_id_type) = 12 - 4 = 8 bytes
    ///     impl_iv_offset = sizeof(packet_id_type) = 4
    ///     implicit_iv = [0, 0, 0, 0, hmac[0..8]]
    ///
    /// Nonce construction (openvpn_encrypt_aead in crypto.c):
    ///   iv[0..12] = [packet_id_be(4), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    ///   for i in 0..12: iv[i] ^= implicit_iv[i]
    ///   Result: [pid(4), hmac[0..8]] (concatenation, since XOR with 0 is identity)
    pub fn from_openvpn_key2_block(block: &[u8]) -> Self {
        assert!(block.len() >= 256, "key2 block must be at least 256 bytes");
        let mut material = Self {
            client_write_key: [0u8; 32],
            server_write_key: [0u8; 32],
            client_hmac_key: [0u8; 32],
            server_hmac_key: [0u8; 32],
            client_implicit_iv: [0u8; 12],
            server_implicit_iv: [0u8; 12],
        };
        // key[0] = client encrypt / server decrypt (client→server)
        material.client_write_key.copy_from_slice(&block[0..32]);
        // Implicit IV at offset 4: first 8 bytes of hmac key placed at nonce[4..12]
        // This matches OpenVPN's key_ctx_update_implicit_iv which uses:
        //   impl_iv_offset = sizeof(packet_id_type) = 4
        //   memcpy(implicit_iv + impl_iv_offset, key->hmac, impl_iv_len)
        // Result: implicit_iv = [0, 0, 0, 0, hmac[0], hmac[1], ..., hmac[7]]
        material.client_implicit_iv[4..12].copy_from_slice(&block[64..72]);
        // key[1] = server encrypt / client decrypt (server→client)
        material.server_write_key.copy_from_slice(&block[128..160]);
        material.server_implicit_iv[4..12].copy_from_slice(&block[192..200]);
        material
    }

    /// Create data channel keys for the client side (includes implicit IV for AEAD)
    pub fn client_data_key(&self, suite: CipherSuite) -> DataChannelKey {
        DataChannelKey::new_with_iv(self.client_write_key, self.client_implicit_iv, suite)
    }

    /// Create data channel keys for the server side (includes implicit IV for AEAD)
    pub fn server_data_key(&self, suite: CipherSuite) -> DataChannelKey {
        DataChannelKey::new_with_iv(self.server_write_key, self.server_implicit_iv, suite)
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

/// TLS 1.0 PRF for OpenVPN key expansion (ssl_tls1_PRF in crypto_openssl.c)
///
/// This is the standard TLS 1.0 PRF using P_MD5 XOR P_SHA-1:
///   PRF(secret, label, seed) = P_MD5(S1, label+seed) XOR P_SHA1(S2, label+seed)
/// where:
///   S1 = secret[0..ceil(len/2)]
///   S2 = secret[floor(len/2)..len]
///   (S1 and S2 overlap by 1 byte if secret length is odd)
///
/// P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
///                         HMAC_hash(secret, A(2) + seed) + ...
/// where A(0) = seed, A(i) = HMAC_hash(secret, A(i-1))
pub fn openvpn_prf(secret: &[u8], label: &[u8], seed: &[u8], output_len: usize) -> Result<Vec<u8>> {
    use hmac::Hmac;

    // Combine label and seed (OpenVPN's openvpn_PRF concatenates label + client_seed + server_seed + sids,
    // but our caller already provides label and seed separately)
    let mut combined_seed = Vec::with_capacity(label.len() + seed.len());
    combined_seed.extend_from_slice(label);
    combined_seed.extend_from_slice(seed);

    // Split the secret into two halves (overlapping by 1 if odd length)
    let half = (secret.len() + 1) / 2; // ceil(len/2)
    let s1 = &secret[..half];
    let s2 = &secret[secret.len() / 2..]; // floor(len/2)..end

    // P_MD5(S1, combined_seed)
    let p_md5 = p_hash::<Hmac<md5::Md5>>(s1, &combined_seed, output_len)?;

    // P_SHA1(S2, combined_seed)
    let p_sha1 = p_hash::<Hmac<sha1::Sha1>>(s2, &combined_seed, output_len)?;

    // XOR the two results
    let mut output = Vec::with_capacity(output_len);
    for i in 0..output_len {
        output.push(p_md5[i] ^ p_sha1[i]);
    }

    Ok(output)
}

/// Generic P_hash function for TLS PRF
///
/// P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
///                         HMAC_hash(secret, A(2) + seed) + ...
/// where A(0) = seed, A(i) = HMAC_hash(secret, A(i-1))
fn p_hash<M>(secret: &[u8], seed: &[u8], output_len: usize) -> Result<Vec<u8>>
where
    M: hmac::Mac + hmac::digest::KeyInit,
{
    let mut output = Vec::with_capacity(output_len + 64); // extra capacity for last block
    let mut a = seed.to_vec(); // A(0) = seed

    while output.len() < output_len {
        // A(i) = HMAC(secret, A(i-1))
        let mut mac = <M as hmac::digest::KeyInit>::new_from_slice(secret)
            .map_err(|_| CryptoError::KeyDerivationFailed("Invalid HMAC key"))?;
        hmac::Mac::update(&mut mac, &a);
        a = mac.finalize().into_bytes().to_vec();

        // HMAC(secret, A(i) + seed)
        let mut mac = <M as hmac::digest::KeyInit>::new_from_slice(secret)
            .map_err(|_| CryptoError::KeyDerivationFailed("Invalid HMAC key"))?;
        hmac::Mac::update(&mut mac, &a);
        hmac::Mac::update(&mut mac, seed);
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
