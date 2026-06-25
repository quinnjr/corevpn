//! CoreVPN Authentication System
//!
//! Provides OAuth2/OIDC authentication with support for:
//! - Google Workspace
//! - Microsoft Entra ID (Azure AD)
//! - Okta
//! - Generic OIDC providers

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod error;
pub mod flow;
pub mod provider;
pub mod session;
pub mod token;

pub use error::{AuthError, Result};
pub use flow::{AuthFlow, AuthState, DeviceAuthFlow};
pub use provider::{OAuthProvider, ProviderConfig, ProviderType};
pub use session::{AuthSession, AuthSessionManager};
pub use token::{TokenSet, TokenValidator, UserInfo};

use secrecy::SecretString;

/// Supported OAuth2 providers with pre-configured settings
#[derive(Clone)]
pub enum KnownProvider {
    /// Google Workspace
    Google {
        /// OAuth2 Client ID
        client_id: String,
        /// OAuth2 Client Secret
        client_secret: SecretString,
        /// Allowed domain (e.g., "company.com")
        allowed_domain: Option<String>,
    },
    /// Microsoft Entra ID (Azure AD)
    Microsoft {
        /// OAuth2 Client ID
        client_id: String,
        /// OAuth2 Client Secret
        client_secret: SecretString,
        /// Tenant ID (or "common" for multi-tenant)
        tenant_id: String,
    },
    /// Okta
    Okta {
        /// OAuth2 Client ID
        client_id: String,
        /// OAuth2 Client Secret
        client_secret: SecretString,
        /// Okta domain (e.g., "company.okta.com")
        domain: String,
        /// Authorization server ID (or "default")
        auth_server_id: Option<String>,
    },
    /// Generic OIDC provider
    Generic {
        /// Display name
        name: String,
        /// OAuth2 Client ID
        client_id: String,
        /// OAuth2 Client Secret
        client_secret: SecretString,
        /// Issuer URL (for OIDC discovery)
        issuer_url: String,
    },
}

impl KnownProvider {
    /// Get the issuer URL for this provider
    pub fn issuer_url(&self) -> String {
        match self {
            KnownProvider::Google { .. } => "https://accounts.google.com".to_string(),
            KnownProvider::Microsoft { tenant_id, .. } => {
                format!("https://login.microsoftonline.com/{}/v2.0", tenant_id)
            }
            KnownProvider::Okta {
                domain,
                auth_server_id,
                ..
            } => match auth_server_id {
                Some(id) => format!("https://{}/oauth2/{}", domain, id),
                None => format!("https://{}/oauth2/default", domain),
            },
            KnownProvider::Generic { issuer_url, .. } => issuer_url.clone(),
        }
    }

    /// Get the client ID
    pub fn client_id(&self) -> &str {
        match self {
            KnownProvider::Google { client_id, .. } => client_id,
            KnownProvider::Microsoft { client_id, .. } => client_id,
            KnownProvider::Okta { client_id, .. } => client_id,
            KnownProvider::Generic { client_id, .. } => client_id,
        }
    }

    /// Get the client secret
    pub fn client_secret(&self) -> &SecretString {
        match self {
            KnownProvider::Google { client_secret, .. } => client_secret,
            KnownProvider::Microsoft { client_secret, .. } => client_secret,
            KnownProvider::Okta { client_secret, .. } => client_secret,
            KnownProvider::Generic { client_secret, .. } => client_secret,
        }
    }

    /// Get provider type name
    pub fn provider_type(&self) -> &'static str {
        match self {
            KnownProvider::Google { .. } => "google",
            KnownProvider::Microsoft { .. } => "microsoft",
            KnownProvider::Okta { .. } => "okta",
            KnownProvider::Generic { .. } => "generic",
        }
    }
}
