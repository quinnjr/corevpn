//! OAuth2/OIDC Provider Configuration

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use secrecy::{ExposeSecret, Secret, SecretString};
use tracing::{debug, warn};
use url::Url;

use crate::{AuthError, Result};

/// OAuth2 provider type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderType {
    /// Google Workspace
    Google,
    /// Microsoft Entra ID
    Microsoft,
    /// Okta
    Okta,
    /// Generic OIDC
    Generic,
}

impl std::fmt::Display for ProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderType::Google => write!(f, "google"),
            ProviderType::Microsoft => write!(f, "microsoft"),
            ProviderType::Okta => write!(f, "okta"),
            ProviderType::Generic => write!(f, "generic"),
        }
    }
}

/// Provider configuration
#[derive(Clone)]
pub struct ProviderConfig {
    /// Provider type
    pub provider_type: ProviderType,
    /// OAuth2 Client ID
    pub client_id: String,
    /// OAuth2 Client Secret (encrypted at rest)
    pub client_secret: SecretString,
    /// Issuer URL (for OIDC discovery)
    pub issuer_url: String,
    /// Authorization endpoint (optional, discovered via OIDC)
    pub authorization_endpoint: Option<String>,
    /// Token endpoint (optional, discovered via OIDC)
    pub token_endpoint: Option<String>,
    /// UserInfo endpoint (optional)
    pub userinfo_endpoint: Option<String>,
    /// Device authorization endpoint (for device flow)
    pub device_authorization_endpoint: Option<String>,
    /// JWKS URI for token validation
    pub jwks_uri: Option<String>,
    /// Scopes to request
    pub scopes: Vec<String>,
    /// Allowed domains (empty = all allowed)
    pub allowed_domains: Vec<String>,
    /// Required groups (user must be in at least one)
    pub required_groups: Vec<String>,
    /// Group claim name in ID token
    pub group_claim: String,
    /// Email claim name in ID token
    pub email_claim: String,
    /// Name claim name in ID token
    pub name_claim: String,
    /// Additional parameters for authorization URL
    pub additional_params: HashMap<String, String>,
}

impl ProviderConfig {
    /// Create a Google provider configuration
    pub fn google(client_id: &str, client_secret: &str, allowed_domain: Option<&str>) -> Self {
        let mut config = Self {
            provider_type: ProviderType::Google,
            client_id: client_id.to_string(),
            client_secret: SecretString::new(client_secret.to_string()),
            issuer_url: "https://accounts.google.com".to_string(),
            authorization_endpoint: Some("https://accounts.google.com/o/oauth2/v2/auth".to_string()),
            token_endpoint: Some("https://oauth2.googleapis.com/token".to_string()),
            userinfo_endpoint: Some("https://openidconnect.googleapis.com/v1/userinfo".to_string()),
            device_authorization_endpoint: Some("https://oauth2.googleapis.com/device/code".to_string()),
            jwks_uri: Some("https://www.googleapis.com/oauth2/v3/certs".to_string()),
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            allowed_domains: vec![],
            required_groups: vec![],
            group_claim: "groups".to_string(),
            email_claim: "email".to_string(),
            name_claim: "name".to_string(),
            additional_params: HashMap::new(),
        };

        if let Some(domain) = allowed_domain {
            config.allowed_domains.push(domain.to_string());
            // Add hd parameter to restrict to domain
            config.additional_params.insert("hd".to_string(), domain.to_string());
        }

        config
    }

    /// Create a Microsoft provider configuration
    pub fn microsoft(client_id: &str, client_secret: &str, tenant_id: &str) -> Self {
        let base_url = format!("https://login.microsoftonline.com/{}", tenant_id);

        Self {
            provider_type: ProviderType::Microsoft,
            client_id: client_id.to_string(),
            client_secret: SecretString::new(client_secret.to_string()),
            issuer_url: format!("{}/v2.0", base_url),
            authorization_endpoint: Some(format!("{}/oauth2/v2.0/authorize", base_url)),
            token_endpoint: Some(format!("{}/oauth2/v2.0/token", base_url)),
            userinfo_endpoint: Some("https://graph.microsoft.com/oidc/userinfo".to_string()),
            device_authorization_endpoint: Some(format!("{}/oauth2/v2.0/devicecode", base_url)),
            jwks_uri: Some(format!("{}/discovery/v2.0/keys", base_url)),
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
                "offline_access".to_string(),
            ],
            allowed_domains: vec![],
            required_groups: vec![],
            group_claim: "groups".to_string(),
            email_claim: "email".to_string(),
            name_claim: "name".to_string(),
            additional_params: HashMap::new(),
        }
    }

    /// Create an Okta provider configuration
    pub fn okta(client_id: &str, client_secret: &str, domain: &str, auth_server_id: Option<&str>) -> Self {
        let auth_server = auth_server_id.unwrap_or("default");
        let base_url = format!("https://{}/oauth2/{}", domain, auth_server);

        Self {
            provider_type: ProviderType::Okta,
            client_id: client_id.to_string(),
            client_secret: SecretString::new(client_secret.to_string()),
            issuer_url: base_url.clone(),
            authorization_endpoint: Some(format!("{}/v1/authorize", base_url)),
            token_endpoint: Some(format!("{}/v1/token", base_url)),
            userinfo_endpoint: Some(format!("{}/v1/userinfo", base_url)),
            device_authorization_endpoint: Some(format!("{}/v1/device/authorize", base_url)),
            jwks_uri: Some(format!("{}/v1/keys", base_url)),
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
                "groups".to_string(),
                "offline_access".to_string(),
            ],
            allowed_domains: vec![],
            required_groups: vec![],
            group_claim: "groups".to_string(),
            email_claim: "email".to_string(),
            name_claim: "name".to_string(),
            additional_params: HashMap::new(),
        }
    }

    /// Create a generic OIDC provider configuration
    pub fn generic(client_id: &str, client_secret: &str, issuer_url: &str) -> Self {
        Self {
            provider_type: ProviderType::Generic,
            client_id: client_id.to_string(),
            client_secret: SecretString::new(client_secret.to_string()),
            issuer_url: issuer_url.to_string(),
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            device_authorization_endpoint: None,
            jwks_uri: None,
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            allowed_domains: vec![],
            required_groups: vec![],
            group_claim: "groups".to_string(),
            email_claim: "email".to_string(),
            name_claim: "name".to_string(),
            additional_params: HashMap::new(),
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        if self.client_id.is_empty() {
            return Err(AuthError::ConfigError("client_id is required".into()));
        }
        if self.client_secret.expose_secret().is_empty() {
            return Err(AuthError::ConfigError("client_secret is required".into()));
        }
        if self.issuer_url.is_empty() {
            return Err(AuthError::ConfigError("issuer_url is required".into()));
        }
        Ok(())
    }
}

/// OAuth2 Provider with runtime state
pub struct OAuthProvider {
    /// Configuration
    config: ProviderConfig,
    /// HTTP client
    http_client: reqwest::Client,
    /// Discovered metadata (if using OIDC discovery)
    metadata: Option<OidcMetadata>,
}

/// OIDC Discovery metadata
#[derive(Debug, Clone, Deserialize)]
pub struct OidcMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    #[serde(default)]
    pub device_authorization_endpoint: Option<String>,
    pub jwks_uri: String,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    #[serde(default)]
    pub response_types_supported: Vec<String>,
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
}

/// Check if an IP address is in a private range
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // 10.0.0.0/8
            (octets[0] == 10) ||
            // 172.16.0.0/12
            (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) ||
            // 192.168.0.0/16
            (octets[0] == 192 && octets[1] == 168) ||
            // 127.0.0.0/8 (loopback)
            (octets[0] == 127) ||
            // 169.254.0.0/16 (link-local)
            (octets[0] == 169 && octets[1] == 254) ||
            // 0.0.0.0/8
            (octets[0] == 0)
        }
        IpAddr::V6(ipv6) => {
            // ::1 (loopback)
            ipv6.is_loopback() ||
            // fe80::/10 (link-local)
            ipv6.is_unicast_link_local() ||
            // fc00::/7 (unique local)
            (ipv6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

/// Validate URL for SSRF protection
fn validate_url_for_ssrf(url_str: &str) -> Result<()> {
    let url = Url::parse(url_str)
        .map_err(|e| AuthError::ConfigError(format!("Invalid URL: {}", e)))?;

    // Only allow HTTPS
    if url.scheme() != "https" {
        return Err(AuthError::ConfigError(
            "Only HTTPS URLs are allowed for security".into()
        ));
    }

    // Resolve hostname and check for private IPs
    if let Some(host) = url.host() {
        match host {
            url::Host::Domain(domain) => {
                // Block localhost variants
                if domain == "localhost" || domain.ends_with(".localhost") {
                    return Err(AuthError::ConfigError(
                        "localhost URLs are not allowed".into()
                    ));
                }
                // Block .local domains (mDNS)
                if domain.ends_with(".local") {
                    return Err(AuthError::ConfigError(
                        ".local domains are not allowed".into()
                    ));
                }
            }
            url::Host::Ipv4(ip) => {
                if is_private_ip(IpAddr::V4(ip)) {
                    return Err(AuthError::ConfigError(
                        "Private IP addresses are not allowed".into()
                    ));
                }
            }
            url::Host::Ipv6(ip) => {
                if is_private_ip(IpAddr::V6(ip)) {
                    return Err(AuthError::ConfigError(
                        "Private IP addresses are not allowed".into()
                    ));
                }
            }
        }
    }

    Ok(())
}

impl OAuthProvider {
    /// Create a new provider
    pub fn new(config: ProviderConfig) -> Self {
        Self {
            config,
            http_client: reqwest::Client::new(),
            metadata: None,
        }
    }

    /// Get the configuration
    pub fn config(&self) -> &ProviderConfig {
        &self.config
    }

    /// Perform OIDC discovery
    pub async fn discover(&mut self) -> Result<()> {
        let discovery_url = format!("{}/.well-known/openid-configuration", self.config.issuer_url);

        // Validate URL for SSRF protection
        validate_url_for_ssrf(&discovery_url)?;

        debug!("Performing OIDC discovery for {}", self.config.issuer_url);

        let response = self.http_client
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| {
                warn!("OIDC discovery failed: {}", e);
                AuthError::DiscoveryFailed("Failed to connect to provider".into())
            })?;

        if !response.status().is_success() {
            let status = response.status();
            warn!("OIDC discovery returned status {}", status);
            return Err(AuthError::DiscoveryFailed(
                "Provider discovery failed".into()
            ));
        }

        let metadata: OidcMetadata = response.json().await
            .map_err(|e| {
                warn!("Failed to parse OIDC metadata: {}", e);
                AuthError::DiscoveryFailed("Invalid provider response".into())
            })?;

        // Validate discovered endpoints for SSRF
        validate_url_for_ssrf(&metadata.authorization_endpoint)?;
        validate_url_for_ssrf(&metadata.token_endpoint)?;
        validate_url_for_ssrf(&metadata.jwks_uri)?;
        if let Some(ref uri) = metadata.userinfo_endpoint {
            validate_url_for_ssrf(uri)?;
        }

        // Update config with discovered endpoints
        self.config.authorization_endpoint = Some(metadata.authorization_endpoint.clone());
        self.config.token_endpoint = Some(metadata.token_endpoint.clone());
        self.config.userinfo_endpoint = metadata.userinfo_endpoint.clone();
        self.config.device_authorization_endpoint = metadata.device_authorization_endpoint.clone();
        self.config.jwks_uri = Some(metadata.jwks_uri.clone());

        self.metadata = Some(metadata);

        Ok(())
    }

    /// Get authorization endpoint
    pub fn authorization_endpoint(&self) -> Result<&str> {
        self.config.authorization_endpoint
            .as_deref()
            .ok_or_else(|| AuthError::ConfigError("authorization_endpoint not configured".into()))
    }

    /// Get token endpoint
    pub fn token_endpoint(&self) -> Result<&str> {
        self.config.token_endpoint
            .as_deref()
            .ok_or_else(|| AuthError::ConfigError("token_endpoint not configured".into()))
    }

    /// Get device authorization endpoint
    pub fn device_authorization_endpoint(&self) -> Result<&str> {
        self.config.device_authorization_endpoint
            .as_deref()
            .ok_or_else(|| AuthError::ConfigError("device_authorization_endpoint not configured".into()))
    }

    /// Check if email domain is allowed
    pub fn is_domain_allowed(&self, email: &str) -> bool {
        if self.config.allowed_domains.is_empty() {
            return true;
        }

        // Parse email properly using addr crate for validation
        if addr::parse_email_address(email).is_err() {
            debug!("Invalid email format: {}", email);
            return false;
        }

        // Extract domain part after @ (already validated by addr crate)
        let email_domain = match email.rsplit_once('@') {
            Some((_, domain)) => domain.to_lowercase(),
            None => return false,
        };

        self.config.allowed_domains.iter().any(|d| {
            d.to_lowercase() == email_domain
        })
    }

    /// Check if user is in required groups
    pub fn is_in_required_group(&self, groups: &[String]) -> bool {
        if self.config.required_groups.is_empty() {
            return true;
        }

        self.config.required_groups.iter().any(|g| groups.contains(g))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_google_config() {
        let config = ProviderConfig::google("client-id", "client-secret", Some("example.com"));

        assert_eq!(config.provider_type, ProviderType::Google);
        assert_eq!(config.allowed_domains, vec!["example.com"]);
        assert!(config.additional_params.contains_key("hd"));
    }

    #[test]
    fn test_microsoft_config() {
        let config = ProviderConfig::microsoft("client-id", "client-secret", "tenant-id");

        assert_eq!(config.provider_type, ProviderType::Microsoft);
        assert!(config.issuer_url.contains("tenant-id"));
    }

    #[test]
    fn test_domain_check() {
        let config = ProviderConfig::google("id", "secret", Some("example.com"));
        let provider = OAuthProvider::new(config);

        assert!(provider.is_domain_allowed("user@example.com"));
        assert!(!provider.is_domain_allowed("user@other.com"));
    }
}
