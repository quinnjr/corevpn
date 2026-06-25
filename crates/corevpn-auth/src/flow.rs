//! OAuth2 Authentication Flows

use std::collections::HashMap;
use std::time::Duration;

use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use tracing::warn;
use uuid::Uuid;

use crate::session::RateLimiter;
use crate::{AuthError, OAuthProvider, Result, TokenSet};
use parking_lot::RwLock;
use std::sync::Arc;

/// Authentication state (for CSRF protection)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthState {
    /// Random state value
    pub state: String,
    /// Nonce for ID token validation
    pub nonce: String,
    /// PKCE code verifier
    pub code_verifier: String,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Expiration timestamp
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl AuthState {
    /// Create a new auth state
    pub fn new(lifetime: Duration) -> Self {
        let now = chrono::Utc::now();
        Self {
            state: Uuid::new_v4().to_string(),
            nonce: Uuid::new_v4().to_string(),
            code_verifier: Self::generate_code_verifier(),
            created_at: now,
            expires_at: now
                + chrono::Duration::from_std(lifetime)
                    .unwrap_or_else(|_| chrono::Duration::seconds(600)), // Fallback to 10 minutes
            metadata: HashMap::new(),
        }
    }

    /// Check if state is expired
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now() > self.expires_at
    }

    /// Get PKCE code challenge
    pub fn code_challenge(&self) -> String {
        use base64::Engine;
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(self.code_verifier.as_bytes());
        let hash = hasher.finalize();

        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
    }

    fn generate_code_verifier() -> String {
        use base64::Engine;

        let random_bytes: [u8; 32] = corevpn_crypto::random_bytes();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes)
    }
}

/// OAuth2 Authorization Code Flow
pub struct AuthFlow {
    /// Provider
    provider: OAuthProvider,
    /// Redirect URI
    redirect_uri: String,
    /// Rate limiter for authentication attempts
    // Retained for future per-flow rate limiting; not yet consulted on this struct.
    #[allow(dead_code)]
    rate_limiter: Arc<RwLock<RateLimiter>>,
}

impl AuthFlow {
    /// Create a new auth flow
    pub fn new(provider: OAuthProvider, redirect_uri: &str) -> Self {
        Self {
            provider,
            redirect_uri: redirect_uri.to_string(),
            rate_limiter: Arc::new(RwLock::new(RateLimiter::new(
                5,                                   // 5 attempts
                std::time::Duration::from_secs(300), // per 5 minutes
            ))),
        }
    }

    /// Create a new auth flow with custom rate limiter
    pub fn with_rate_limiter(
        provider: OAuthProvider,
        redirect_uri: &str,
        rate_limiter: RateLimiter,
    ) -> Self {
        Self {
            provider,
            redirect_uri: redirect_uri.to_string(),
            rate_limiter: Arc::new(RwLock::new(rate_limiter)),
        }
    }

    /// Generate authorization URL
    pub fn authorization_url(&self, state: &AuthState) -> Result<String> {
        let endpoint = self.provider.authorization_endpoint()?;
        let config = self.provider.config();

        let code_challenge = state.code_challenge();
        let mut params = vec![
            ("client_id", config.client_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", &self.redirect_uri),
            ("state", &state.state),
            ("nonce", &state.nonce),
            ("code_challenge", code_challenge.as_str()),
            ("code_challenge_method", "S256"),
        ];

        // Add scopes
        let scopes = config.scopes.join(" ");
        params.push(("scope", &scopes));

        // Build URL
        let mut url = endpoint.to_string();
        url.push('?');

        for (i, (key, value)) in params.iter().enumerate() {
            if i > 0 {
                url.push('&');
            }
            url.push_str(key);
            url.push('=');
            url.push_str(&urlencoding::encode(value));
        }

        // Add any additional parameters
        for (key, value) in &config.additional_params {
            url.push('&');
            url.push_str(key);
            url.push('=');
            url.push_str(&urlencoding::encode(value));
        }

        Ok(url)
    }

    /// Exchange authorization code for tokens
    pub async fn exchange_code(&self, code: &str, state: &AuthState) -> Result<TokenSet> {
        let endpoint = self.provider.token_endpoint()?;
        let config = self.provider.config();

        let client_secret = config.client_secret.expose_secret();
        let params = [
            ("grant_type", "authorization_code"),
            ("client_id", config.client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("code", code),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("code_verifier", state.code_verifier.as_str()),
        ];

        let client = reqwest::Client::new();
        let response = client
            .post(endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| {
                warn!("Token exchange request failed: {}", e);
                AuthError::OAuth2Error("Authentication failed".into())
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            warn!(
                "Token exchange failed with status {}: {}",
                status, error_text
            );
            return Err(AuthError::OAuth2Error("Authentication failed".into()));
        }

        let token_response: TokenResponse = response.json().await?;

        Ok(TokenSet {
            access_token: token_response.access_token,
            refresh_token: token_response.refresh_token,
            id_token: token_response.id_token,
            expires_at: chrono::Utc::now()
                + chrono::Duration::seconds(token_response.expires_in.unwrap_or(3600) as i64),
            token_type: token_response.token_type,
            scopes: token_response
                .scope
                .map(|s| s.split(' ').map(String::from).collect())
                .unwrap_or_default(),
        })
    }

    /// Refresh access token
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<TokenSet> {
        let endpoint = self.provider.token_endpoint()?;
        let config = self.provider.config();

        let client_secret = config.client_secret.expose_secret();
        let params = [
            ("grant_type", "refresh_token"),
            ("client_id", config.client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("refresh_token", refresh_token),
        ];

        let client = reqwest::Client::new();
        let response = client
            .post(endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| {
                warn!("Token refresh request failed: {}", e);
                AuthError::TokenRefreshFailed("Token refresh failed".into())
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            warn!(
                "Token refresh failed with status {}: {}",
                status, error_text
            );
            return Err(AuthError::TokenRefreshFailed("Token refresh failed".into()));
        }

        let token_response: TokenResponse = response.json().await?;

        Ok(TokenSet {
            access_token: token_response.access_token,
            refresh_token: token_response.refresh_token,
            id_token: token_response.id_token,
            expires_at: chrono::Utc::now()
                + chrono::Duration::seconds(token_response.expires_in.unwrap_or(3600) as i64),
            token_type: token_response.token_type,
            scopes: token_response
                .scope
                .map(|s| s.split(' ').map(String::from).collect())
                .unwrap_or_default(),
        })
    }
}

/// OAuth2 Device Authorization Flow (for CLI/headless)
pub struct DeviceAuthFlow {
    /// Provider
    provider: OAuthProvider,
    /// Rate limiter for device auth attempts
    rate_limiter: Arc<RwLock<RateLimiter>>,
}

impl DeviceAuthFlow {
    /// Create a new device auth flow
    pub fn new(provider: OAuthProvider) -> Self {
        Self {
            provider,
            rate_limiter: Arc::new(RwLock::new(RateLimiter::new(
                10,                                  // 10 attempts
                std::time::Duration::from_secs(600), // per 10 minutes
            ))),
        }
    }

    /// Start device authorization
    pub async fn start(&self, client_ip: Option<&str>) -> Result<DeviceAuthResponse> {
        // Rate limit device auth attempts
        let rate_limit_key = client_ip.unwrap_or("unknown");
        if !self.rate_limiter.read().check(rate_limit_key) {
            return Err(AuthError::OAuth2Error(
                "Too many device authorization attempts".into(),
            ));
        }

        let endpoint = self.provider.device_authorization_endpoint()?;
        let config = self.provider.config();

        let scopes = config.scopes.join(" ");
        let params = [("client_id", config.client_id.as_str()), ("scope", &scopes)];

        let client = reqwest::Client::new();
        let response = client.post(endpoint).form(&params).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            warn!(
                "Device authorization failed with status {}: {}",
                status, error_text
            );
            return Err(AuthError::OAuth2Error("Device authorization failed".into()));
        }

        let device_response: DeviceAuthResponse = response.json().await?;
        Ok(device_response)
    }

    /// Poll for token (call repeatedly until success or error)
    pub async fn poll(&self, device_code: &str, client_ip: Option<&str>) -> Result<TokenSet> {
        // Rate limit polling attempts
        let rate_limit_key = client_ip.unwrap_or(device_code);
        if !self.rate_limiter.read().check(rate_limit_key) {
            return Err(AuthError::OAuth2Error("Too many polling attempts".into()));
        }

        let endpoint = self.provider.token_endpoint()?;
        let config = self.provider.config();

        let client_secret = config.client_secret.expose_secret();
        let params = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("client_id", config.client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("device_code", device_code),
        ];

        let client = reqwest::Client::new();
        let response = client.post(endpoint).form(&params).send().await?;

        if !response.status().is_success() {
            let error_response: ErrorResponse = response.json().await.map_err(|e| {
                warn!("Failed to parse error response: {}", e);
                AuthError::OAuth2Error("Device authorization failed".into())
            })?;

            return match error_response.error.as_str() {
                "authorization_pending" => Err(AuthError::AuthorizationPending),
                "slow_down" => Err(AuthError::AuthorizationPending),
                "expired_token" => Err(AuthError::DeviceAuthExpired),
                _ => {
                    warn!("Device auth error: {}", error_response.error);
                    Err(AuthError::OAuth2Error("Device authorization failed".into()))
                }
            };
        }

        let token_response: TokenResponse = response.json().await?;

        Ok(TokenSet {
            access_token: token_response.access_token,
            refresh_token: token_response.refresh_token,
            id_token: token_response.id_token,
            expires_at: chrono::Utc::now()
                + chrono::Duration::seconds(token_response.expires_in.unwrap_or(3600) as i64),
            token_type: token_response.token_type,
            scopes: token_response
                .scope
                .map(|s| s.split(' ').map(String::from).collect())
                .unwrap_or_default(),
        })
    }
}

/// OAuth2 token response
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    token_type: String,
    #[serde(default)]
    scope: Option<String>,
}

/// Device authorization response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthResponse {
    /// Device code (for polling)
    pub device_code: String,
    /// User code (to enter on verification page)
    pub user_code: String,
    /// Verification URI
    pub verification_uri: String,
    /// Verification URI with code pre-filled (optional)
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    /// Expiration in seconds
    pub expires_in: u64,
    /// Polling interval in seconds
    #[serde(default = "default_interval")]
    pub interval: u64,
}

fn default_interval() -> u64 {
    5
}

/// Error response
#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
    // Deserialized from OAuth2 error responses for completeness; not surfaced yet.
    #[allow(dead_code)]
    #[serde(default)]
    error_description: Option<String>,
}

/// Generate authentication challenge for OpenVPN auth-user-pass
pub fn generate_vpn_auth_challenge(device_response: &DeviceAuthResponse) -> String {
    format!(
        "CRV1:R,E:{}:Please visit {} and enter code: {}",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            device_response.device_code.as_bytes()
        ),
        device_response.verification_uri,
        device_response.user_code
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_state() {
        let state = AuthState::new(Duration::from_secs(300));

        assert!(!state.is_expired());
        assert!(!state.state.is_empty());
        assert!(!state.nonce.is_empty());
        assert!(!state.code_verifier.is_empty());
    }

    #[test]
    fn test_code_challenge() {
        let state = AuthState::new(Duration::from_secs(300));
        let challenge = state.code_challenge();

        // Should be base64url encoded SHA256 hash
        assert!(!challenge.is_empty());
        assert!(!challenge.contains('+'));
        assert!(!challenge.contains('/'));
    }
}
