//! UI Configuration
//!
//! Configuration settings for the CoreVPN UI.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// UI configuration settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    /// Window settings
    pub window: WindowConfig,
    /// Theme settings
    pub theme: ThemeConfig,
    /// Connection settings
    pub connection: ConnectionConfig,
    /// Authentication settings
    pub auth: AuthConfig,
    /// Notification settings
    pub notifications: NotificationConfig,
}

/// Window configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowConfig {
    /// Window width
    pub width: f64,
    /// Window height
    pub height: f64,
    /// Start minimized to tray
    pub start_minimized: bool,
    /// Minimize to tray on close
    pub minimize_to_tray: bool,
    /// Remember window position
    pub remember_position: bool,
    /// Window X position (if remembered)
    pub x: Option<i32>,
    /// Window Y position (if remembered)
    pub y: Option<i32>,
}

/// Theme configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThemeConfig {
    /// Theme mode: "light", "dark", or "system"
    pub mode: String,
    /// Accent color (hex)
    pub accent_color: Option<String>,
}

/// Connection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionConfig {
    /// Auto-connect on startup
    pub auto_connect: bool,
    /// Reconnect on disconnect
    pub auto_reconnect: bool,
    /// Maximum reconnection attempts
    pub max_reconnect_attempts: u32,
    /// Reconnection delay (seconds)
    pub reconnect_delay_secs: u32,
    /// Kill switch (block traffic when VPN disconnects)
    pub kill_switch: bool,
    /// Allow LAN access when connected
    pub allow_lan: bool,
    /// DNS leak protection
    pub dns_leak_protection: bool,
}

/// Authentication configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Default authentication method
    pub default_method: String,
    /// Remember credentials
    pub remember_credentials: bool,
    /// OAuth2 callback port (for localhost redirect)
    pub oauth_callback_port: u16,
    /// SSO providers configuration
    pub sso_providers: Vec<SsoProviderConfig>,
}

/// SSO provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoProviderConfig {
    /// Provider type
    pub provider_type: String,
    /// Display name
    pub name: String,
    /// Enabled
    pub enabled: bool,
    /// Client ID (if needed for public clients)
    pub client_id: Option<String>,
    /// Issuer URL
    pub issuer_url: Option<String>,
}

/// Notification configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    /// Show connection notifications
    pub connection_status: bool,
    /// Show error notifications
    pub errors: bool,
    /// Show update notifications
    pub updates: bool,
    /// Notification sound
    pub sound: bool,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            window: WindowConfig::default(),
            theme: ThemeConfig::default(),
            connection: ConnectionConfig::default(),
            auth: AuthConfig::default(),
            notifications: NotificationConfig::default(),
        }
    }
}

impl Default for WindowConfig {
    fn default() -> Self {
        Self {
            width: 420.0,
            height: 680.0,
            start_minimized: false,
            minimize_to_tray: true,
            remember_position: true,
            x: None,
            y: None,
        }
    }
}

impl Default for ThemeConfig {
    fn default() -> Self {
        Self {
            mode: "system".to_string(),
            accent_color: None,
        }
    }
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            auto_connect: false,
            auto_reconnect: true,
            max_reconnect_attempts: 3,
            reconnect_delay_secs: 5,
            kill_switch: false,
            allow_lan: true,
            dns_leak_protection: true,
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            default_method: "oauth2".to_string(),
            remember_credentials: false,
            oauth_callback_port: 8400,
            sso_providers: vec![
                SsoProviderConfig {
                    provider_type: "google".to_string(),
                    name: "Google Workspace".to_string(),
                    enabled: true,
                    client_id: None,
                    issuer_url: Some("https://accounts.google.com".to_string()),
                },
                SsoProviderConfig {
                    provider_type: "microsoft".to_string(),
                    name: "Microsoft Entra ID".to_string(),
                    enabled: true,
                    client_id: None,
                    issuer_url: None,
                },
                SsoProviderConfig {
                    provider_type: "okta".to_string(),
                    name: "Okta".to_string(),
                    enabled: true,
                    client_id: None,
                    issuer_url: None,
                },
            ],
        }
    }
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            connection_status: true,
            errors: true,
            updates: true,
            sound: false,
        }
    }
}

impl UiConfig {
    /// Load configuration from file.
    pub fn load(path: &PathBuf) -> Result<Self, ConfigError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| ConfigError::IoError(e.to_string()))?;
        toml::from_str(&content).map_err(|e| ConfigError::ParseError(e.to_string()))
    }

    /// Save configuration to file.
    pub fn save(&self, path: &PathBuf) -> Result<(), ConfigError> {
        let content =
            toml::to_string_pretty(self).map_err(|e| ConfigError::SerializeError(e.to_string()))?;
        std::fs::write(path, content).map_err(|e| ConfigError::IoError(e.to_string()))
    }

    /// Get the default configuration path.
    pub fn default_path() -> PathBuf {
        if let Some(config_dir) = dirs_config_path() {
            config_dir.join("corevpn").join("ui.toml")
        } else {
            PathBuf::from("corevpn-ui.toml")
        }
    }

    /// Merge with command line overrides.
    pub fn merge_cli(&mut self, cli: &CliOverrides) {
        if let Some(theme) = &cli.theme {
            self.theme.mode = theme.clone();
        }
        if cli.auto_connect {
            self.connection.auto_connect = true;
        }
        if cli.minimized {
            self.window.start_minimized = true;
        }
    }
}

/// CLI overrides for configuration.
#[derive(Debug, Default)]
pub struct CliOverrides {
    /// Theme override
    pub theme: Option<String>,
    /// Auto-connect override
    pub auto_connect: bool,
    /// Start minimized
    pub minimized: bool,
}

/// Configuration error.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// IO error
    #[error("IO error: {0}")]
    IoError(String),
    /// Parse error
    #[error("Parse error: {0}")]
    ParseError(String),
    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializeError(String),
}

/// Get platform-specific config directory.
fn dirs_config_path() -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        std::env::var("XDG_CONFIG_HOME")
            .ok()
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var("HOME")
                    .ok()
                    .map(|h| PathBuf::from(h).join(".config"))
            })
    }

    #[cfg(target_os = "macos")]
    {
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join("Library").join("Application Support"))
    }

    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA").ok().map(PathBuf::from)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}
