//! Client Configuration Generator

use std::path::Path;

use corevpn_crypto::{CertificateAuthority, Certificate};

use crate::{ClientConfigBuilder, ConfigError, Result, ServerConfig};

/// Client configuration generator
pub struct ConfigGenerator {
    /// Server configuration
    server_config: ServerConfig,
    /// Certificate Authority
    ca: CertificateAuthority,
    /// CA certificate PEM
    ca_cert_pem: String,
    /// tls-auth key (if enabled)
    ta_key: Option<String>,
}

impl ConfigGenerator {
    /// Create a new config generator
    pub fn new(
        server_config: ServerConfig,
        ca: CertificateAuthority,
        ta_key: Option<String>,
    ) -> Self {
        let ca_cert_pem = ca.certificate_pem().to_string();
        Self {
            server_config,
            ca,
            ca_cert_pem,
            ta_key,
        }
    }

    /// Generate client configuration
    pub fn generate_client_config(
        &self,
        username: &str,
        email: Option<&str>,
    ) -> Result<GeneratedConfig> {
        // Issue client certificate
        let cert = self.ca.issue_client_certificate(
            username,
            email,
            self.server_config.security.client_cert_lifetime_days,
        ).map_err(|e| ConfigError::ValidationError(e.to_string()))?;

        // Build client config
        let mut builder = ClientConfigBuilder::new(
            username,
            &self.server_config.server.public_host,
        )
        .port(self.server_config.server.listen_addr.port())
        .protocol(&self.server_config.server.protocol)
        .ca_cert(&self.ca_cert_pem)
        .client_cert(&cert.cert_pem)
        .client_key(&cert.key_pem)
        .cipher(&self.map_cipher(&self.server_config.security.cipher))
        .reneg_sec(self.server_config.security.reneg_sec);

        // Add tls-auth if enabled
        if let Some(ta_key) = &self.ta_key {
            builder = builder.tls_auth(ta_key, 1);
        }

        // Add compression stub (disabled for security)
        builder = builder.extra_option("compress stub-v2");

        let config = builder.build();
        // Validate configuration before generating .ovpn content
        config.validate()
            .map_err(|e| ConfigError::ValidationError(format!("Invalid client config: {}", e)))?;
        let ovpn_content = config.to_ovpn();

        Ok(GeneratedConfig {
            username: username.to_string(),
            ovpn_content,
            certificate: cert,
        })
    }

    /// Generate mobile-optimized client configuration
    pub fn generate_mobile_config(
        &self,
        username: &str,
        email: Option<&str>,
    ) -> Result<GeneratedConfig> {
        let mut generated = self.generate_client_config(username, email)?;

        // Build with mobile optimizations
        let mut builder = ClientConfigBuilder::new(
            username,
            &self.server_config.server.public_host,
        )
        .port(self.server_config.server.listen_addr.port())
        .protocol(&self.server_config.server.protocol)
        .ca_cert(&self.ca_cert_pem)
        .client_cert(&generated.certificate.cert_pem)
        .client_key(&generated.certificate.key_pem)
        .cipher(&self.map_cipher(&self.server_config.security.cipher))
        .reneg_sec(self.server_config.security.reneg_sec)
        .extra_option("connect-retry 2")
        .extra_option("connect-retry-max 5")
        .extra_option("auth-retry interact")
        .extra_option("compress stub-v2");

        if let Some(ta_key) = &self.ta_key {
            builder = builder.tls_auth(ta_key, 1);
        }

        let config = builder.build();
        // Validate configuration before generating .ovpn content
        config.validate()
            .map_err(|e| ConfigError::ValidationError(format!("Invalid mobile config: {}", e)))?;
        generated.ovpn_content = config.to_ovpn();

        Ok(generated)
    }

    fn map_cipher(&self, cipher: &str) -> String {
        match cipher.to_lowercase().as_str() {
            "chacha20-poly1305" => "CHACHA20-POLY1305".to_string(),
            "aes-256-gcm" => "AES-256-GCM".to_string(),
            _ => "AES-256-GCM".to_string(),
        }
    }
}

/// Generated client configuration
#[derive(Debug, Clone)]
pub struct GeneratedConfig {
    /// Username
    pub username: String,
    /// .ovpn file contents
    pub ovpn_content: String,
    /// Certificate and keys
    pub certificate: Certificate,
}

impl GeneratedConfig {
    /// Get filename for the .ovpn file
    pub fn filename(&self) -> String {
        format!("{}.ovpn", self.username.replace(['@', '.', ' '], "_"))
    }

    /// Save to file
    pub fn save(&self, dir: &Path) -> Result<std::path::PathBuf> {
        // Sanitize filename - reject any path separators or parent directory references
        let filename = self.filename();
        if filename.contains(std::path::MAIN_SEPARATOR) || filename.contains("..") {
            return Err(crate::ConfigError::ValidationError(
                "Invalid filename: contains path separators or parent directory references".into(),
            ));
        }

        // Ensure directory exists and is actually a directory
        if !dir.exists() {
            std::fs::create_dir_all(dir)?;
        }
        if !dir.is_dir() {
            return Err(crate::ConfigError::ValidationError(
                "Target path is not a directory".into(),
            ));
        }

        // Canonicalize the directory to resolve symlinks
        let canonical_dir = dir.canonicalize()
            .map_err(|e| crate::ConfigError::IoError(e))?;

        // Build the final path - using join() ensures we can't escape the directory
        // as long as filename doesn't contain path separators (which we already checked)
        let path = canonical_dir.join(&filename);

        // Verify the path is still within the canonical directory
        // This prevents path traversal attacks even if join() somehow allows it
        // Since the file doesn't exist yet, we check that the path's parent is within canonical_dir
        if let Some(parent) = path.parent() {
            // Canonicalize the parent to resolve any symlinks
            let canonical_parent = parent.canonicalize()
                .map_err(|e| crate::ConfigError::IoError(e))?;
            
            // Ensure the canonical parent is within the canonical directory
            if !canonical_parent.starts_with(&canonical_dir) {
                return Err(crate::ConfigError::ValidationError(
                    "Path traversal detected: final path outside target directory".into(),
                ));
            }
        } else {
            // This shouldn't happen, but be defensive
            return Err(crate::ConfigError::ValidationError(
                "Invalid path: no parent directory".into(),
            ));
        }

        // Additional check: ensure the filename itself doesn't contain any path components
        // This is redundant but provides defense in depth
        if path != canonical_dir.join(&filename) {
            return Err(crate::ConfigError::ValidationError(
                "Path traversal detected: invalid path construction".into(),
            ));
        }

        std::fs::write(&path, &self.ovpn_content)?;
        Ok(path)
    }
}

/// Initialize server PKI (CA, server cert, ta.key)
pub fn initialize_pki(
    data_dir: &Path,
    server_cn: &str,
    organization: &str,
) -> Result<(CertificateAuthority, String)> {
    use std::fs;

    // Create data directory
    fs::create_dir_all(data_dir)?;

    // Generate CA
    let ca = CertificateAuthority::new(
        &format!("{} CA", organization),
        organization,
        3650, // 10 years
    ).map_err(|e| ConfigError::ValidationError(e.to_string()))?;

    // Save CA cert and key
    fs::write(data_dir.join("ca.crt"), ca.certificate_pem())?;
    fs::write(data_dir.join("ca.key"), ca.private_key_pem())?;

    // Generate server certificate
    let server_cert = ca.issue_server_certificate(
        server_cn,
        &[server_cn.to_string()],
        &[],
        365, // 1 year
    ).map_err(|e| ConfigError::ValidationError(e.to_string()))?;

    // Save server cert and key
    fs::write(data_dir.join("server.crt"), &server_cert.cert_pem)?;
    fs::write(data_dir.join("server.key"), &server_cert.key_pem)?;

    // Generate tls-auth key
    let ta_key_bytes = corevpn_crypto::cert::generate_static_key();
    let ta_key = corevpn_crypto::cert::format_static_key(&ta_key_bytes);
    fs::write(data_dir.join("ta.key"), &ta_key)?;

    Ok((ca, ta_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_initialize_pki() {
        let dir = tempdir().unwrap();
        let (ca, ta_key) = initialize_pki(
            dir.path(),
            "vpn.example.com",
            "Test Org",
        ).unwrap();

        assert!(dir.path().join("ca.crt").exists());
        assert!(dir.path().join("ca.key").exists());
        assert!(dir.path().join("server.crt").exists());
        assert!(dir.path().join("server.key").exists());
        assert!(dir.path().join("ta.key").exists());
        assert!(!ta_key.is_empty());
    }
}
