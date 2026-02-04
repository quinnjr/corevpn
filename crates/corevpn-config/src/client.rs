//! Client Configuration

use serde::{Deserialize, Serialize};

/// Client configuration for .ovpn file generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Client name/identifier
    pub name: String,
    /// Server hostname/IP
    pub remote_host: String,
    /// Server port
    pub remote_port: u16,
    /// Protocol (udp or tcp)
    pub protocol: String,
    /// CA certificate (PEM)
    pub ca_cert: String,
    /// Client certificate (PEM)
    pub client_cert: String,
    /// Client private key (PEM)
    pub client_key: String,
    /// TLS auth key (if enabled)
    pub tls_auth_key: Option<String>,
    /// TLS crypt key (if enabled)
    pub tls_crypt_key: Option<String>,
    /// Cipher
    pub cipher: String,
    /// Auth digest
    pub auth: String,
    /// Key direction for tls-auth
    pub key_direction: Option<u8>,
    /// Additional options
    pub extra_options: Vec<String>,
}

impl ClientConfig {
    /// Validate PEM format
    fn validate_pem(content: &str, expected_type: &str) -> Result<(), crate::ConfigError> {
        let content = content.trim();
        
        // Check for proper PEM headers/footers
        let header = format!("-----BEGIN {}", expected_type);
        let footer = format!("-----END {}", expected_type);
        
        if !content.starts_with(&header) {
            return Err(crate::ConfigError::ValidationError(format!(
                "Invalid PEM format: missing BEGIN {} header",
                expected_type
            )));
        }
        
        if !content.ends_with(&footer) {
            return Err(crate::ConfigError::ValidationError(format!(
                "Invalid PEM format: missing END {} footer",
                expected_type
            )));
        }
        
        // Basic validation: ensure there's content between headers
        // Find the end of the header line
        let header_line_end = content.find('\n').or_else(|| content.find('\r'));
        if let Some(header_end) = header_line_end {
            // Find where the footer starts
            if let Some(footer_start) = content.rfind(&footer) {
                if footer_start <= header_end {
                    return Err(crate::ConfigError::ValidationError(format!(
                        "Invalid PEM format: empty or malformed {} content",
                        expected_type
                    )));
                }
                // Check that there's actual base64-like content (at least some non-whitespace)
                let body = &content[header_end + 1..footer_start];
                if body.trim().is_empty() {
                    return Err(crate::ConfigError::ValidationError(format!(
                        "Invalid PEM format: empty {} content",
                        expected_type
                    )));
                }
            }
        }
        
        Ok(())
    }

    /// Validate all certificates and keys before generating .ovpn
    pub fn validate(&self) -> Result<(), crate::ConfigError> {
        // Validate CA certificate
        Self::validate_pem(&self.ca_cert, "CERTIFICATE")
            .map_err(|e| crate::ConfigError::ValidationError(format!("CA certificate: {}", e)))?;
        
        // Validate client certificate
        Self::validate_pem(&self.client_cert, "CERTIFICATE")
            .map_err(|e| crate::ConfigError::ValidationError(format!("Client certificate: {}", e)))?;
        
        // Validate client key (can be PRIVATE KEY or RSA PRIVATE KEY)
        let key_valid = Self::validate_pem(&self.client_key, "PRIVATE KEY").is_ok()
            || Self::validate_pem(&self.client_key, "RSA PRIVATE KEY").is_ok()
            || Self::validate_pem(&self.client_key, "EC PRIVATE KEY").is_ok();
        
        if !key_valid {
            return Err(crate::ConfigError::ValidationError(
                "Client key: Invalid PEM format - must be PRIVATE KEY, RSA PRIVATE KEY, or EC PRIVATE KEY".into(),
            ));
        }
        
        // Validate tls-auth key if present
        if let Some(ta_key) = &self.tls_auth_key {
            if ta_key.trim().is_empty() {
                return Err(crate::ConfigError::ValidationError(
                    "tls-auth key cannot be empty".into(),
                ));
            }
            // tls-auth keys are typically base64 encoded, not PEM
            // Just check they're not empty and have reasonable length
            if ta_key.trim().len() < 32 {
                return Err(crate::ConfigError::ValidationError(
                    "tls-auth key appears to be too short".into(),
                ));
            }
        }
        
        // Validate tls-crypt key if present
        if let Some(tc_key) = &self.tls_crypt_key {
            if tc_key.trim().is_empty() {
                return Err(crate::ConfigError::ValidationError(
                    "tls-crypt key cannot be empty".into(),
                ));
            }
            if tc_key.trim().len() < 32 {
                return Err(crate::ConfigError::ValidationError(
                    "tls-crypt key appears to be too short".into(),
                ));
            }
        }
        
        Ok(())
    }

    /// Generate .ovpn file contents
    /// 
    /// # Panics
    /// Panics if the configuration is invalid. Use `validate()` before calling this method
    /// to check for errors without panicking.
    pub fn to_ovpn(&self) -> String {
        // Validate before generating
        // We panic here because malformed configs should never be written
        // Callers should validate first if they want to handle errors gracefully
        self.validate().expect("Invalid client configuration");
        let mut lines = vec![
            "# CoreVPN Client Configuration".to_string(),
            "# Generated automatically - do not edit".to_string(),
            "".to_string(),
            "client".to_string(),
            "dev tun".to_string(),
            format!("proto {}", self.protocol),
            format!("remote {} {}", self.remote_host, self.remote_port),
            "resolv-retry infinite".to_string(),
            "nobind".to_string(),
            "persist-key".to_string(),
            "persist-tun".to_string(),
            "remote-cert-tls server".to_string(),
            format!("cipher {}", self.cipher),
            format!("auth {}", self.auth),
            "verb 3".to_string(),
            "".to_string(),
            "# Security settings".to_string(),
            "tls-client".to_string(),
            "tls-version-min 1.3".to_string(),
            "".to_string(),
        ];

        // Add extra options
        for opt in &self.extra_options {
            lines.push(opt.clone());
        }
        lines.push("".to_string());

        // Add inline certificates
        lines.push("<ca>".to_string());
        lines.push(self.ca_cert.trim().to_string());
        lines.push("</ca>".to_string());
        lines.push("".to_string());

        lines.push("<cert>".to_string());
        lines.push(self.client_cert.trim().to_string());
        lines.push("</cert>".to_string());
        lines.push("".to_string());

        lines.push("<key>".to_string());
        lines.push(self.client_key.trim().to_string());
        lines.push("</key>".to_string());
        lines.push("".to_string());

        // Add tls-auth or tls-crypt
        if let Some(key) = &self.tls_crypt_key {
            lines.push("<tls-crypt>".to_string());
            lines.push(key.trim().to_string());
            lines.push("</tls-crypt>".to_string());
        } else if let Some(key) = &self.tls_auth_key {
            if let Some(dir) = self.key_direction {
                lines.push(format!("key-direction {}", dir));
            }
            lines.push("<tls-auth>".to_string());
            lines.push(key.trim().to_string());
            lines.push("</tls-auth>".to_string());
        }

        lines.join("\n")
    }

    /// Generate a minimal .ovpn for mobile devices
    pub fn to_ovpn_mobile(&self) -> String {
        // Same as regular but with mobile-optimized settings
        let mut config = self.clone();
        config.extra_options.push("# Mobile optimizations".to_string());
        config.extra_options.push("connect-retry 2".to_string());
        config.extra_options.push("connect-retry-max 5".to_string());
        config.extra_options.push("auth-retry interact".to_string());
        config.to_ovpn()
    }
}

/// Builder for client configuration
pub struct ClientConfigBuilder {
    name: String,
    remote_host: String,
    remote_port: u16,
    protocol: String,
    ca_cert: String,
    client_cert: String,
    client_key: String,
    tls_auth_key: Option<String>,
    tls_crypt_key: Option<String>,
    cipher: String,
    auth: String,
    key_direction: Option<u8>,
    extra_options: Vec<String>,
}

impl ClientConfigBuilder {
    /// Create a new builder
    pub fn new(name: &str, remote_host: &str) -> Self {
        Self {
            name: name.to_string(),
            remote_host: remote_host.to_string(),
            remote_port: 1194,
            protocol: "udp".to_string(),
            ca_cert: String::new(),
            client_cert: String::new(),
            client_key: String::new(),
            tls_auth_key: None,
            tls_crypt_key: None,
            cipher: "AES-256-GCM".to_string(),
            auth: "SHA256".to_string(),
            key_direction: Some(1),
            extra_options: vec![],
        }
    }

    /// Set remote port
    pub fn port(mut self, port: u16) -> Self {
        self.remote_port = port;
        self
    }

    /// Set protocol
    pub fn protocol(mut self, proto: &str) -> Self {
        self.protocol = proto.to_string();
        self
    }

    /// Set CA certificate
    pub fn ca_cert(mut self, cert: &str) -> Self {
        self.ca_cert = cert.to_string();
        self
    }

    /// Set client certificate
    pub fn client_cert(mut self, cert: &str) -> Self {
        self.client_cert = cert.to_string();
        self
    }

    /// Set client private key
    pub fn client_key(mut self, key: &str) -> Self {
        self.client_key = key.to_string();
        self
    }

    /// Set tls-auth key
    pub fn tls_auth(mut self, key: &str, direction: u8) -> Self {
        self.tls_auth_key = Some(key.to_string());
        self.key_direction = Some(direction);
        self
    }

    /// Set tls-crypt key
    pub fn tls_crypt(mut self, key: &str) -> Self {
        self.tls_crypt_key = Some(key.to_string());
        self.tls_auth_key = None;
        self
    }

    /// Set cipher
    pub fn cipher(mut self, cipher: &str) -> Self {
        self.cipher = cipher.to_string();
        self
    }

    /// Add extra option
    pub fn extra_option(mut self, opt: &str) -> Self {
        self.extra_options.push(opt.to_string());
        self
    }

    /// Build the configuration
    pub fn build(self) -> ClientConfig {
        ClientConfig {
            name: self.name,
            remote_host: self.remote_host,
            remote_port: self.remote_port,
            protocol: self.protocol,
            ca_cert: self.ca_cert,
            client_cert: self.client_cert,
            client_key: self.client_key,
            tls_auth_key: self.tls_auth_key,
            tls_crypt_key: self.tls_crypt_key,
            cipher: self.cipher,
            auth: self.auth,
            key_direction: self.key_direction,
            extra_options: self.extra_options,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_config_builder() {
        let config = ClientConfigBuilder::new("testuser", "vpn.example.com")
            .port(443)
            .protocol("tcp")
            .ca_cert("CA CERT")
            .client_cert("CLIENT CERT")
            .client_key("CLIENT KEY")
            .tls_auth("TA KEY", 1)
            .build();

        assert_eq!(config.name, "testuser");
        assert_eq!(config.remote_port, 443);
        assert_eq!(config.protocol, "tcp");
    }

    #[test]
    fn test_ovpn_generation() {
        let config = ClientConfigBuilder::new("test", "vpn.example.com")
            .ca_cert("-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----")
            .client_cert("-----BEGIN CERTIFICATE-----\nCLIENT\n-----END CERTIFICATE-----")
            .client_key("-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----")
            .build();

        let ovpn = config.to_ovpn();

        assert!(ovpn.contains("client"));
        assert!(ovpn.contains("remote vpn.example.com 1194"));
        assert!(ovpn.contains("<ca>"));
        assert!(ovpn.contains("<cert>"));
        assert!(ovpn.contains("<key>"));
    }
}
