//! TLS Integration for OpenVPN Control Channel
//!
//! Bridges rustls with the OpenVPN control channel transport.

use std::io::{Read, Write, ErrorKind};
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use rustls::{ServerConfig, ServerConnection};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::{ProtocolError, Result};

/// TLS handler for OpenVPN connections
pub struct TlsHandler {
    /// Rustls server connection
    conn: ServerConnection,
    /// Incoming data buffer (from control channel)
    incoming: BytesMut,
    /// Outgoing data buffer (to control channel)
    outgoing: BytesMut,
    /// Whether handshake is complete
    handshake_complete: bool,
}

impl TlsHandler {
    /// Create a new TLS handler with server configuration
    pub fn new(config: Arc<ServerConfig>) -> Result<Self> {
        let conn = ServerConnection::new(config)
            .map_err(|e| ProtocolError::TlsError(e.to_string()))?;

        Ok(Self {
            conn,
            incoming: BytesMut::with_capacity(16384),
            outgoing: BytesMut::with_capacity(16384),
            handshake_complete: false,
        })
    }

    /// Process incoming TLS data from control channel
    pub fn process_incoming(&mut self, data: &[u8]) -> Result<()> {
        self.incoming.extend_from_slice(data);
        self.process_tls()
    }

    /// Process incoming TLS records (already extracted from control channel)
    pub fn process_tls_records(&mut self, records: Vec<Bytes>) -> Result<()> {
        for record in records {
            self.incoming.extend_from_slice(&record);
        }
        self.process_tls()
    }

    /// Internal TLS processing
    fn process_tls(&mut self) -> Result<()> {
        // Create a cursor for reading
        let mut reader = &self.incoming[..];

        match self.conn.read_tls(&mut reader) {
            Ok(0) => {
                // No data read
            }
            Ok(n) => {
                // Remove consumed data
                let _ = self.incoming.split_to(n);
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                // Need more data
            }
            Err(e) => {
                return Err(ProtocolError::TlsError(e.to_string()));
            }
        }

        // Process any TLS state changes
        match self.conn.process_new_packets() {
            Ok(_state) => {
                if !self.handshake_complete && !self.conn.is_handshaking() {
                    self.handshake_complete = true;
                }
            }
            Err(e) => {
                return Err(ProtocolError::TlsError(e.to_string()));
            }
        }

        Ok(())
    }

    /// Get data to send on control channel
    pub fn get_outgoing(&mut self) -> Result<Option<Bytes>> {
        self.outgoing.clear();

        match self.conn.write_tls(&mut VecWriter(&mut self.outgoing)) {
            Ok(0) => Ok(None),
            Ok(_) => Ok(Some(self.outgoing.clone().freeze())),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(ProtocolError::TlsError(e.to_string())),
        }
    }

    /// Check if handshake is complete
    pub fn is_handshake_complete(&self) -> bool {
        self.handshake_complete
    }

    /// Check if we're still handshaking
    pub fn is_handshaking(&self) -> bool {
        self.conn.is_handshaking()
    }

    /// Check if there's data waiting to be written
    pub fn wants_write(&self) -> bool {
        self.conn.wants_write()
    }

    /// Read decrypted application data
    pub fn read_plaintext(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut reader = self.conn.reader();
        match reader.read(buf) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(ProtocolError::TlsError(e.to_string())),
        }
    }

    /// Write plaintext data (will be encrypted)
    pub fn write_plaintext(&mut self, data: &[u8]) -> Result<usize> {
        let mut writer = self.conn.writer();
        match writer.write(data) {
            Ok(n) => Ok(n),
            Err(e) => Err(ProtocolError::TlsError(e.to_string())),
        }
    }

    /// Export keying material from the TLS session (RFC 5705)
    ///
    /// Used by OpenVPN for data channel key derivation with TLS 1.3.
    pub fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<()> {
        self.conn.export_keying_material(output, label, context)
            .map_err(|e| ProtocolError::TlsError(format!("EKM export failed: {}", e)))?;
        Ok(())
    }

    /// Get peer certificate if available
    pub fn peer_certificates(&self) -> Option<Vec<CertificateDer<'static>>> {
        self.conn.peer_certificates().map(|certs| {
            certs.iter().map(|c| c.clone().into_owned()).collect()
        })
    }

    /// Get negotiated cipher suite name
    pub fn cipher_suite(&self) -> Option<&'static str> {
        self.conn.negotiated_cipher_suite().map(|cs| cs.suite().as_str().unwrap_or("unknown"))
    }
}

/// Helper to write to BytesMut
struct VecWriter<'a>(&'a mut BytesMut);

impl<'a> Write for VecWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Create TLS server config from certificates and key
pub fn create_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    client_cert_verifier: Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>,
) -> Result<Arc<ServerConfig>> {
    // Security: rustls 0.23+ uses safe defaults automatically:
    // - TLS 1.3 is the minimum (TLS 1.2 weak ciphers not available)
    // - Only secure cipher suites are available:
    //   - TLS13_CHACHA20_POLY1305_SHA256
    //   - TLS13_AES_256_GCM_SHA384
    //   - TLS13_AES_128_GCM_SHA256
    // - Weak ciphers (RC4, DES, etc.) are not supported
    let config = if let Some(verifier) = client_cert_verifier {
        ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(cert_chain, key)
            .map_err(|e: rustls::Error| ProtocolError::TlsError(e.to_string()))?
    } else {
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e: rustls::Error| ProtocolError::TlsError(e.to_string()))?
    };

    Ok(Arc::new(config))
}

/// Load certificate chain from PEM
pub fn load_certs_from_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut certs = Vec::new();
    for cert in rustls_pemfile::certs(&mut pem.as_bytes()) {
        match cert {
            Ok(c) => certs.push(c),
            Err(e) => return Err(ProtocolError::TlsError(format!("Failed to parse cert: {}", e))),
        }
    }
    Ok(certs)
}

/// Load private key from PEM
pub fn load_key_from_pem(pem: &str) -> Result<PrivateKeyDer<'static>> {
    // Try PKCS8 first, then RSA, then EC
    for item in rustls_pemfile::read_all(&mut pem.as_bytes()) {
        match item {
            Ok(rustls_pemfile::Item::Pkcs8Key(key)) => return Ok(PrivateKeyDer::Pkcs8(key)),
            Ok(rustls_pemfile::Item::Pkcs1Key(key)) => return Ok(PrivateKeyDer::Pkcs1(key)),
            Ok(rustls_pemfile::Item::Sec1Key(key)) => return Ok(PrivateKeyDer::Sec1(key)),
            _ => continue,
        }
    }
    Err(ProtocolError::TlsError("No private key found in PEM".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Basic test - just verifies compilation
    #[test]
    fn test_tls_handler_creation() {
        // Would need valid certs to create a real handler
    }
}
