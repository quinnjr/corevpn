//! CoreVPN Cryptographic Primitives
//!
//! This crate provides the cryptographic foundation for CoreVPN, using only
//! audited, pure-Rust implementations. No OpenSSL dependency.
//!
//! # Security Principles
//! - All key material implements `Zeroize` for secure memory clearing
//! - Constant-time comparisons for all authentication operations
//! - No custom cryptography - only well-audited implementations
//! - Perfect Forward Secrecy through ephemeral key exchange

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod cert;
pub mod cipher;
pub mod error;
pub mod hmac_auth;
pub mod kdf;
pub mod keys;

pub use cert::{Certificate, CertificateAuthority, CertificateRequest, parse_static_key};
pub use cipher::{Cipher, CipherSuite, DataChannelKey, PacketCipher};
pub use error::{CryptoError, Result};
pub use hmac_auth::HmacAuth;
pub use kdf::{KeyMaterial, derive_keys, openvpn_prf};
pub use keys::{
    KeyPair, PublicKey, SharedSecret, Signature, SigningKey, StaticSecret, VerifyingKey,
};

/// Securely generate random bytes
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf);
    buf
}

/// Generate a cryptographically secure session ID
pub fn generate_session_id() -> [u8; 8] {
    random_bytes()
}

/// Generate a cryptographically secure packet ID
pub fn generate_packet_id() -> u32 {
    u32::from_be_bytes(random_bytes())
}
