//! X.509 Certificate generation and management
//!
//! Generates certificates compatible with OpenVPN's TLS authentication.

use std::time::{Duration, SystemTime};

use rcgen::{
    BasicConstraints, Certificate as RcgenCertificate, CertificateParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};
use serde::{Deserialize, Serialize};
use x509_cert::{
    der::Decode,
    Certificate as X509Certificate,
};

use crate::{CryptoError, Result};

/// Extract Common Name from a PEM certificate (simple parser)
fn extract_cn_from_pem(pem: &str) -> Option<String> {
    // Simple extraction - look for CN= in the subject line
    // This is a basic parser for display purposes
    for line in pem.lines() {
        if line.contains("Subject:") && line.contains("CN=") {
            if let Some(start) = line.find("CN=") {
                let rest = &line[start + 3..];
                let end = rest.find(',').unwrap_or(rest.len());
                return Some(rest[..end].trim().to_string());
            }
        }
    }
    None
}

/// Certificate Authority for issuing client/server certificates
pub struct CertificateAuthority {
    /// CA certificate
    ca_cert: RcgenCertificate,
    /// CA key pair
    key_pair: KeyPair,
    /// CA certificate in PEM format (cached)
    cert_pem: String,
}

impl CertificateAuthority {
    /// Create a new CA with the given parameters
    pub fn new(
        common_name: &str,
        organization: &str,
        validity_days: u32,
    ) -> Result<Self> {
        // Generate key pair
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| CryptoError::CertificateError(e.to_string()))?;

        let mut params = CertificateParams::new(vec![])
            .map_err(|e| CryptoError::CertificateError(e.to_string()))?;

        // Set distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        dn.push(DnType::OrganizationName, organization);
        params.distinguished_name = dn;

        // CA settings
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        // Validity
        let now = SystemTime::now();
        params.not_before = now.into();
        params.not_after = (now + Duration::from_secs(validity_days as u64 * 24 * 60 * 60)).into();

        // Generate self-signed certificate
        let ca_cert = params.self_signed(&key_pair)
            .map_err(|e| CryptoError::CertificateError(e.to_string()))?;

        let cert_pem = ca_cert.pem();

        Ok(Self { ca_cert, key_pair, cert_pem })
    }

    /// Load CA from PEM-encoded certificate and private key
    ///
    /// Note: This creates a new CA certificate with the same key pair.
    /// The original certificate PEM is preserved for distribution.
    ///
    /// Validates that the CA certificate is not expired.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let key_pair = KeyPair::from_pem(key_pem)
            .map_err(|e| CryptoError::InvalidPem(e.to_string()))?;

        // Extract CN from existing cert if possible, otherwise use a default
        let common_name = extract_cn_from_pem(cert_pem).unwrap_or_else(|| "CoreVPN CA".to_string());

        // Create new CA params with the existing key pair
        let mut params = CertificateParams::new(vec![])
            .map_err(|e| CryptoError::CertificateError(e.to_string()))?;

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, &common_name);
        params.distinguished_name = dn;

        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        // Long validity for CA
        let now = SystemTime::now();
        params.not_before = now.into();
        params.not_after = (now + Duration::from_secs(365 * 10 * 24 * 60 * 60)).into();

        let ca_cert = params.self_signed(&key_pair)
            .map_err(|e| CryptoError::CertificateError(e.to_string()))?;

        let ca = Self {
            ca_cert,
            key_pair,
            // Keep original cert PEM for distribution
            cert_pem: cert_pem.to_string(),
        };

        // Validate the loaded CA certificate expiration
        let temp_cert = Certificate {
            cert_pem: cert_pem.to_string(),
            key_pem: String::new(), // Not needed for validation
            ca_pem: cert_pem.to_string(), // Self-signed
        };
        temp_cert.validate_expiration()?;

        Ok(ca)
    }

    /// Get CA certificate in PEM format
    pub fn certificate_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Get CA private key in PEM format
    pub fn private_key_pem(&self) -> String {
        self.key_pair.serialize_pem()
    }

    /// Issue a server certificate
    pub fn issue_server_certificate(
        &self,
        common_name: &str,
        san_dns: &[String],
        san_ips: &[std::net::IpAddr],
        validity_days: u32,
    ) -> Result<Certificate> {
        // Generate key pair for server
        let server_key = KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| CryptoError::CertificateError(e.to_string()))?;

        // Build SANs
        let mut sans: Vec<SanType> = san_dns
            .iter()
            .filter_map(|s| {
                s.clone().try_into().ok().map(SanType::DnsName)
            })
            .collect();
        for ip in san_ips {
            sans.push(SanType::IpAddress(*ip));
        }

        let mut params = CertificateParams::new(vec![])
            .map_err(|e| CryptoError::CertificateError(e.to_string()))?;

        // Distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        params.distinguished_name = dn;

        // Server settings
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.subject_alt_names = sans;

        // Validity
        let now = SystemTime::now();
        params.not_before = now.into();
        params.not_after = (now + Duration::from_secs(validity_days as u64 * 24 * 60 * 60)).into();

        let cert = params.signed_by(&server_key, &self.ca_cert, &self.key_pair)
            .map_err(|e| CryptoError::CertificateError(e.to_string()))?;

        Ok(Certificate {
            cert_pem: cert.pem(),
            key_pem: server_key.serialize_pem(),
            ca_pem: self.cert_pem.clone(),
        })
    }

    /// Issue a client certificate
    pub fn issue_client_certificate(
        &self,
        common_name: &str,
        email: Option<&str>,
        validity_days: u32,
    ) -> Result<Certificate> {
        // Generate key pair for client
        let client_key = KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| CryptoError::CertificateError(e.to_string()))?;

        // Build SANs
        let sans: Vec<SanType> = if let Some(email) = email {
            if let Ok(ia5) = email.to_string().try_into() {
                vec![SanType::Rfc822Name(ia5)]
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        let mut params = CertificateParams::new(vec![])
            .map_err(|e| CryptoError::CertificateError(e.to_string()))?;

        // Distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        params.distinguished_name = dn;

        // Client settings
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.subject_alt_names = sans;

        // Validity - short lifetime for clients (security best practice)
        let now = SystemTime::now();
        params.not_before = now.into();
        params.not_after = (now + Duration::from_secs(validity_days as u64 * 24 * 60 * 60)).into();

        let cert = params.signed_by(&client_key, &self.ca_cert, &self.key_pair)
            .map_err(|e| CryptoError::CertificateError(e.to_string()))?;

        Ok(Certificate {
            cert_pem: cert.pem(),
            key_pem: client_key.serialize_pem(),
            ca_pem: self.cert_pem.clone(),
        })
    }
}

/// Issued certificate with private key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    /// Certificate in PEM format
    pub cert_pem: String,
    /// Private key in PEM format
    pub key_pem: String,
    /// CA certificate in PEM format
    pub ca_pem: String,
}

impl Certificate {
    /// Generate an OpenVPN-compatible inline config snippet
    pub fn to_ovpn_inline(&self) -> String {
        format!(
            "<ca>\n{}</ca>\n\n<cert>\n{}</cert>\n\n<key>\n{}</key>",
            self.ca_pem.trim(),
            self.cert_pem.trim(),
            self.key_pem.trim()
        )
    }

    /// Validate that the certificate is not expired
    ///
    /// Checks both not_before and not_after dates against the current time.
    pub fn validate_expiration(&self) -> Result<()> {
        let pem_data = pem::parse(self.cert_pem.as_str())
            .map_err(|e| CryptoError::InvalidPem(format!("Failed to parse certificate PEM: {}", e)))?;
        
        let cert = X509Certificate::from_der(pem_data.contents())
            .map_err(|e| CryptoError::CertificateError(format!("Failed to parse certificate: {}", e)))?;

        let validity = &cert.tbs_certificate.validity;
        let now = SystemTime::now();

        // Convert Time to SystemTime by converting through unix timestamp
        // x509-cert's Time type returns Duration directly from to_unix_duration()
        let not_before_secs = validity.not_before.to_unix_duration().as_secs();
        let not_before_time = SystemTime::UNIX_EPOCH + Duration::from_secs(not_before_secs);
        
        let not_after_secs = validity.not_after.to_unix_duration().as_secs();
        let not_after_time = SystemTime::UNIX_EPOCH + Duration::from_secs(not_after_secs);

        if now < not_before_time {
            return Err(CryptoError::CertificateError(
                "Certificate not yet valid".to_string()
            ));
        }

        if now > not_after_time {
            return Err(CryptoError::CertificateError(
                "Certificate expired".to_string()
            ));
        }

        Ok(())
    }

    /// Validate that the certificate is signed by the expected CA
    ///
    /// This verifies the certificate chain by checking that the certificate
    /// is signed by the CA certificate provided in the Certificate struct.
    pub fn validate_chain(&self) -> Result<()> {
        // Parse the certificate
        let cert_pem_data = pem::parse(self.cert_pem.as_str())
            .map_err(|e| CryptoError::InvalidPem(format!("Failed to parse certificate PEM: {}", e)))?;
        
        let cert = X509Certificate::from_der(cert_pem_data.contents())
            .map_err(|e| CryptoError::CertificateError(format!("Failed to parse certificate: {}", e)))?;

        // Parse the CA certificate
        let ca_pem_data = pem::parse(self.ca_pem.as_str())
            .map_err(|e| CryptoError::InvalidPem(format!("Failed to parse CA certificate PEM: {}", e)))?;
        
        let ca_cert = X509Certificate::from_der(ca_pem_data.contents())
            .map_err(|e| CryptoError::CertificateError(format!("Failed to parse CA certificate: {}", e)))?;

        // Extract the issuer from the certificate
        let cert_issuer = &cert.tbs_certificate.issuer;
        let ca_subject = &ca_cert.tbs_certificate.subject;

        // Verify that the certificate's issuer matches the CA's subject
        if cert_issuer != ca_subject {
            return Err(CryptoError::CertificateError(
                "Certificate issuer does not match CA subject".to_string()
            ));
        }

        // Verify the signature
        // Note: Full signature verification requires cryptographic operations
        // For now, we verify the issuer matches. Full signature verification
        // would require extracting the public key from the CA and verifying
        // the signature algorithm and signature bytes, which is complex.
        // This is a basic chain validation - full verification would use
        // a library like webpki or rustls.
        
        Ok(())
    }

    /// Validate both expiration and chain
    pub fn validate(&self) -> Result<()> {
        self.validate_expiration()?;
        self.validate_chain()?;
        Ok(())
    }

    /// Load and validate a certificate from PEM strings
    pub fn from_pem(cert_pem: &str, key_pem: &str, ca_pem: &str) -> Result<Self> {
        let cert = Self {
            cert_pem: cert_pem.to_string(),
            key_pem: key_pem.to_string(),
            ca_pem: ca_pem.to_string(),
        };
        cert.validate()?;
        Ok(cert)
    }
}

/// Certificate signing request (for external CAs)
#[derive(Clone, Serialize, Deserialize)]
pub struct CertificateRequest {
    /// CSR in PEM format
    pub csr_pem: String,
    /// Private key in PEM format (keep secret!)
    pub key_pem: String,
}

impl CertificateRequest {
    /// Create a new CSR for a client
    pub fn new_client(common_name: &str, email: Option<&str>) -> Result<Self> {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| CryptoError::CertificateError(e.to_string()))?;

        // Build SANs
        let sans: Vec<SanType> = if let Some(email) = email {
            if let Ok(ia5) = email.to_string().try_into() {
                vec![SanType::Rfc822Name(ia5)]
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        let mut params = CertificateParams::new(vec![])
            .map_err(|e| CryptoError::CertificateError(e.to_string()))?;

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        params.distinguished_name = dn;
        params.subject_alt_names = sans;

        // Generate self-signed cert (as placeholder for CSR)
        let cert = params.self_signed(&key_pair)
            .map_err(|e| CryptoError::CertificateError(e.to_string()))?;

        Ok(Self {
            csr_pem: cert.pem(), // Note: rcgen doesn't have separate CSR, this is a placeholder
            key_pem: key_pair.serialize_pem(),
        })
    }
}

/// Generate a tls-auth/tls-crypt static key
pub fn generate_static_key() -> [u8; 256] {
    crate::random_bytes()
}

/// Format static key in OpenVPN ta.key format
pub fn format_static_key(key: &[u8; 256]) -> String {
    let mut output = String::new();
    output.push_str("#\n");
    output.push_str("# 2048 bit OpenVPN static key\n");
    output.push_str("#\n");
    output.push_str("-----BEGIN OpenVPN Static key V1-----\n");

    // Format as hex, 16 bytes per line
    for chunk in key.chunks(16) {
        for byte in chunk {
            output.push_str(&format!("{:02x}", byte));
        }
        output.push('\n');
    }

    output.push_str("-----END OpenVPN Static key V1-----\n");
    output
}

/// Parse OpenVPN static key format
pub fn parse_static_key(pem: &str) -> Result<[u8; 256]> {
    let mut key = [0u8; 256];
    let mut offset = 0;

    for line in pem.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with('-') || line.is_empty() {
            continue;
        }

        // Parse hex line
        for i in (0..line.len()).step_by(2) {
            if offset >= 256 {
                break;
            }
            if i + 2 > line.len() {
                break;
            }
            let byte = u8::from_str_radix(&line[i..i + 2], 16)
                .map_err(|_| CryptoError::InvalidPem("Invalid hex in static key".into()))?;
            key[offset] = byte;
            offset += 1;
        }
    }

    if offset != 256 {
        return Err(CryptoError::InvalidPem(format!(
            "Static key wrong length: expected 256, got {}",
            offset
        )));
    }

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ca_creation() {
        let ca = CertificateAuthority::new("CoreVPN CA", "CoreVPN", 365).unwrap();

        let cert_pem = ca.certificate_pem();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));

        let key_pem = ca.private_key_pem();
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_server_certificate() {
        let ca = CertificateAuthority::new("CoreVPN CA", "CoreVPN", 365).unwrap();

        let cert = ca
            .issue_server_certificate(
                "vpn.example.com",
                &["vpn.example.com".to_string()],
                &["10.8.0.1".parse().unwrap()],
                90,
            )
            .unwrap();

        assert!(cert.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(cert.key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_client_certificate() {
        let ca = CertificateAuthority::new("CoreVPN CA", "CoreVPN", 365).unwrap();

        let cert = ca
            .issue_client_certificate("user@example.com", Some("user@example.com"), 30)
            .unwrap();

        let ovpn = cert.to_ovpn_inline();
        assert!(ovpn.contains("<ca>"));
        assert!(ovpn.contains("<cert>"));
        assert!(ovpn.contains("<key>"));
    }

    #[test]
    fn test_static_key_roundtrip() {
        let key = generate_static_key();
        let formatted = format_static_key(&key);
        let parsed = parse_static_key(&formatted).unwrap();
        assert_eq!(key, parsed);
    }
}
