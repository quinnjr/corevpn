//! Cryptographic key types with secure memory handling
//!
//! All secret key material implements `Zeroize` to ensure keys are
//! securely cleared from memory when dropped.

use ed25519_dalek::{
    SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey,
    Signature as Ed25519Signature,
    Signer, Verifier,
};
use x25519_dalek::{
    StaticSecret as X25519StaticSecret,
    PublicKey as X25519PublicKey,
    SharedSecret as X25519SharedSecret,
};
use zeroize::ZeroizeOnDrop;
use serde::{Serialize, Deserialize};

use crate::{CryptoError, Result};

/// X25519 static secret key for key exchange
///
/// This key should be generated once and stored securely.
/// For Perfect Forward Secrecy, use ephemeral keys for each session.
#[derive(ZeroizeOnDrop)]
pub struct StaticSecret {
    inner: X25519StaticSecret,
}

impl StaticSecret {
    /// Generate a new random static secret
    pub fn generate() -> Self {
        Self {
            inner: X25519StaticSecret::random_from_rng(rand::rngs::OsRng),
        }
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            inner: X25519StaticSecret::from(bytes),
        }
    }

    /// Get the corresponding public key
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            inner: X25519PublicKey::from(&self.inner),
        }
    }

    /// Perform Diffie-Hellman key exchange
    pub fn diffie_hellman(&self, their_public: &PublicKey) -> SharedSecret {
        SharedSecret {
            inner: self.inner.diffie_hellman(&their_public.inner),
        }
    }

    /// Export as bytes (use with caution - prefer keeping in memory)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }
}

/// X25519 public key for key exchange
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    #[serde(with = "serde_bytes_array")]
    inner: X25519PublicKey,
}

mod serde_bytes_array {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use x25519_dalek::PublicKey;

    pub fn serialize<S>(key: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        key.as_bytes().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        Ok(PublicKey::from(bytes))
    }
}

impl PublicKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            inner: X25519PublicKey::from(bytes),
        }
    }

    /// Export as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.inner.as_bytes()
    }

    /// Export as bytes (owned)
    pub fn to_bytes(&self) -> [u8; 32] {
        *self.inner.as_bytes()
    }
}

/// Shared secret from Diffie-Hellman exchange
#[derive(ZeroizeOnDrop)]
pub struct SharedSecret {
    inner: X25519SharedSecret,
}

impl SharedSecret {
    /// Get the raw shared secret bytes
    ///
    /// Note: You should typically derive keys from this using HKDF,
    /// not use it directly.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.inner.as_bytes()
    }
}

/// Ed25519 signing key
#[derive(ZeroizeOnDrop)]
pub struct SigningKey {
    inner: Ed25519SigningKey,
}

impl SigningKey {
    /// Generate a new random signing key
    pub fn generate() -> Self {
        Self {
            inner: Ed25519SigningKey::generate(&mut rand::rngs::OsRng),
        }
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            inner: Ed25519SigningKey::from_bytes(bytes),
        }
    }

    /// Get the corresponding verifying key
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            inner: self.inner.verifying_key(),
        }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature {
            inner: self.inner.sign(message),
        }
    }

    /// Export as bytes (use with caution)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// Get the inner key for certificate signing
    #[allow(dead_code)]
    pub(crate) fn inner(&self) -> &Ed25519SigningKey {
        &self.inner
    }
}

/// Ed25519 verifying (public) key
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey {
    inner: Ed25519VerifyingKey,
}

impl VerifyingKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let inner = Ed25519VerifyingKey::from_bytes(bytes)
            .map_err(|_| CryptoError::InvalidKeyLength { expected: 32, got: bytes.len() })?;
        Ok(Self { inner })
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        self.inner
            .verify(message, &signature.inner)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    /// Export as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.inner.as_bytes()
    }

    /// Export as bytes (owned)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }
}

/// Ed25519 signature
#[derive(Clone, Debug)]
pub struct Signature {
    inner: Ed25519Signature,
}

impl Signature {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        Self {
            inner: Ed25519Signature::from_bytes(bytes),
        }
    }

    /// Export as bytes
    pub fn to_bytes(&self) -> [u8; 64] {
        self.inner.to_bytes()
    }
}

/// Combined key pair for both encryption and signing
#[derive(ZeroizeOnDrop)]
pub struct KeyPair {
    /// Key exchange secret
    pub exchange: StaticSecret,
    /// Signing key
    pub signing: SigningKey,
}

impl KeyPair {
    /// Generate a new key pair
    pub fn generate() -> Self {
        Self {
            exchange: StaticSecret::generate(),
            signing: SigningKey::generate(),
        }
    }
}

/// Ephemeral key pair for Perfect Forward Secrecy
///
/// This should be generated fresh for each session and discarded after use.
pub struct EphemeralKeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl Drop for EphemeralKeyPair {
    fn drop(&mut self) {
        // StaticSecret already implements ZeroizeOnDrop, so it will be zeroized automatically.
        // PublicKey doesn't need zeroization as it's public information.
        // This explicit Drop ensures the secret is cleared when the struct is dropped.
    }
}

impl EphemeralKeyPair {
    /// Generate a new ephemeral key pair
    pub fn generate() -> Self {
        let secret = StaticSecret::generate();
        let public = secret.public_key();
        Self { secret, public }
    }

    /// Get the public key to send to the peer
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Perform key exchange and consume this ephemeral key
    pub fn diffie_hellman(self, their_public: &PublicKey) -> SharedSecret {
        self.secret.diffie_hellman(their_public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange() {
        let alice = StaticSecret::generate();
        let bob = StaticSecret::generate();

        let alice_public = alice.public_key();
        let bob_public = bob.public_key();

        let alice_shared = alice.diffie_hellman(&bob_public);
        let bob_shared = bob.diffie_hellman(&alice_public);

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_signing() {
        let signing_key = SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let message = b"test message";
        let signature = signing_key.sign(message);

        assert!(verifying_key.verify(message, &signature).is_ok());
        assert!(verifying_key.verify(b"wrong message", &signature).is_err());
    }

    #[test]
    fn test_ephemeral_pfs() {
        let server_static = StaticSecret::generate();
        let client_ephemeral = EphemeralKeyPair::generate();

        let client_public = client_ephemeral.public_key().clone();
        let shared1 = client_ephemeral.diffie_hellman(&server_static.public_key());
        let shared2 = server_static.diffie_hellman(&client_public);

        assert_eq!(shared1.as_bytes(), shared2.as_bytes());
    }
}
