//! OpenVPN configuration file (.ovpn) parser
//!
//! Parses .ovpn files including inline certificate blocks for use
//! with the CoreVPN client.

use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context, Result, bail};

/// Parsed OpenVPN client configuration
#[derive(Debug)]
pub struct OvpnConfig {
    /// Remote server address and port
    pub remote: SocketAddr,
    /// Protocol (udp or tcp)
    pub protocol: String,
    /// Cipher name (e.g., CHACHA20-POLY1305)
    pub cipher: String,
    /// Data ciphers for NCP negotiation
    pub data_ciphers: Vec<String>,
    /// Auth digest (e.g., SHA256)
    pub auth: String,
    /// Verbosity level
    pub verb: u8,
    /// CA certificate (PEM)
    pub ca_pem: String,
    /// Client certificate (PEM)
    pub cert_pem: String,
    /// Client private key (PEM)
    pub key_pem: String,
    /// TLS-auth static key (hex-encoded lines)
    pub tls_auth_key: Option<Vec<u8>>,
    /// Key direction for tls-auth (0 or 1)
    pub key_direction: Option<u8>,
    /// Whether remote-cert-tls server is enabled
    pub remote_cert_tls: bool,
    /// Device type (tun or tap)
    pub dev: String,
}

impl OvpnConfig {
    /// Parse an .ovpn configuration file
    pub fn parse_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read .ovpn file: {}", path.display()))?;
        Self::parse(&content)
    }

    /// Parse .ovpn configuration from string content
    pub fn parse(content: &str) -> Result<Self> {
        let mut remote_host = String::new();
        let mut remote_port: u16 = 1194;
        let mut protocol = "udp".to_string();
        let mut cipher = "AES-256-GCM".to_string();
        let mut data_ciphers = Vec::new();
        let mut auth = "SHA256".to_string();
        let mut verb: u8 = 3;
        let mut remote_cert_tls = false;
        let mut key_direction: Option<u8> = None;
        let mut dev = "tun".to_string();

        // Extract inline blocks
        let ca_pem = extract_inline_block(content, "ca")
            .context("Missing <ca> block in .ovpn file")?;
        let cert_pem = extract_inline_block(content, "cert")
            .context("Missing <cert> block in .ovpn file")?;
        let key_pem = extract_inline_block(content, "key")
            .context("Missing <key> block in .ovpn file")?;
        let tls_auth_raw = extract_inline_block(content, "tls-auth");

        // Parse tls-auth key from hex
        let tls_auth_key = if let Some(ref raw) = tls_auth_raw {
            Some(parse_static_key(raw)?)
        } else {
            None
        };

        // Parse directives
        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines, comments, and inline block content
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            let mut parts = line.split_whitespace();
            match parts.next() {
                Some("remote") => {
                    if let Some(host) = parts.next() {
                        remote_host = host.to_string();
                    }
                    if let Some(port) = parts.next() {
                        remote_port = port.parse().unwrap_or(1194);
                    }
                }
                Some("proto") => {
                    if let Some(p) = parts.next() {
                        protocol = p.to_string();
                    }
                }
                Some("cipher") => {
                    if let Some(c) = parts.next() {
                        cipher = c.to_string();
                    }
                }
                Some("data-ciphers") => {
                    if let Some(ciphers) = parts.next() {
                        data_ciphers = ciphers.split(':').map(|s| s.to_string()).collect();
                    }
                }
                Some("auth") => {
                    if let Some(a) = parts.next() {
                        auth = a.to_string();
                    }
                }
                Some("verb") => {
                    if let Some(v) = parts.next() {
                        verb = v.parse().unwrap_or(3);
                    }
                }
                Some("remote-cert-tls") => {
                    remote_cert_tls = true;
                }
                Some("key-direction") => {
                    if let Some(d) = parts.next() {
                        key_direction = Some(d.parse().unwrap_or(1));
                    }
                }
                Some("dev") => {
                    if let Some(d) = parts.next() {
                        dev = d.to_string();
                    }
                }
                _ => {} // Ignore unknown directives
            }
        }

        if remote_host.is_empty() {
            bail!("Missing 'remote' directive in .ovpn file");
        }

        // Resolve remote address
        let remote: SocketAddr = format!("{}:{}", remote_host, remote_port)
            .parse()
            .with_context(|| format!("Invalid remote address: {}:{}", remote_host, remote_port))?;

        Ok(Self {
            remote,
            protocol,
            cipher,
            data_ciphers,
            auth,
            verb,
            ca_pem,
            cert_pem,
            key_pem,
            tls_auth_key,
            key_direction,
            remote_cert_tls,
            dev,
        })
    }
}

/// Extract an inline block like <ca>...</ca> from .ovpn content
fn extract_inline_block(content: &str, tag: &str) -> Option<String> {
    let start_tag = format!("<{}>", tag);
    let end_tag = format!("</{}>", tag);

    let start_idx = content.find(&start_tag)?;
    let end_idx = content.find(&end_tag)?;

    if start_idx >= end_idx {
        return None;
    }

    let block_start = start_idx + start_tag.len();
    let block = &content[block_start..end_idx];
    Some(block.trim().to_string())
}

/// Parse OpenVPN static key V1 format (hex lines) into 256-byte key
fn parse_static_key(pem_block: &str) -> Result<Vec<u8>> {
    let mut hex_data = String::new();

    for line in pem_block.lines() {
        let line = line.trim();
        // Skip comments and markers
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with('-')
            || line.contains("OpenVPN Static key")
        {
            continue;
        }
        hex_data.push_str(line);
    }

    // Decode hex to bytes
    let bytes = hex_decode(&hex_data)
        .context("Failed to decode tls-auth key hex data")?;

    if bytes.len() != 256 {
        bail!(
            "tls-auth key has wrong length: expected 256 bytes, got {}",
            bytes.len()
        );
    }

    Ok(bytes)
}

/// Simple hex decoder
fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        bail!("Hex string has odd length");
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16)
            .with_context(|| format!("Invalid hex at position {}", i))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_inline_block() {
        let content = "<ca>\n-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n</ca>";
        let block = extract_inline_block(content, "ca").unwrap();
        assert!(block.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_hex_decode() {
        let bytes = hex_decode("deadbeef").unwrap();
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }
}
