//! Application State Management
//!
//! Manages the global application state for the VPN client.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use zeroize::Zeroizing;

use crate::types::{AuthMethod, ConnectionStats, VpnConnectionStatus};

/// Authentication state.
#[derive(Clone)]
pub enum AuthState {
    /// Not authenticated
    NotAuthenticated,
    /// Authenticating via OAuth2/SAML (browser opened)
    AwaitingSso {
        /// Auth URL to open in browser
        url: Option<String>,
    },
    /// Authenticated with credentials
    Authenticated {
        /// User email
        email: String,
        /// User display name
        name: Option<String>,
        /// Token expiration
        expires_at: Option<DateTime<Utc>>,
    },
    /// Authentication failed
    Failed {
        /// Error message
        error: String,
    },
}

impl std::fmt::Debug for AuthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAuthenticated => f.debug_tuple("NotAuthenticated").finish(),
            Self::AwaitingSso { url } => f.debug_struct("AwaitingSso").field("url", url).finish(),
            Self::Authenticated {
                email,
                name,
                expires_at,
            } => f
                .debug_struct("Authenticated")
                .field("email", email)
                .field("name", name)
                .field("expires_at", expires_at)
                .finish(),
            Self::Failed { error } => f.debug_struct("Failed").field("error", error).finish(),
        }
    }
}

impl Default for AuthState {
    fn default() -> Self {
        Self::NotAuthenticated
    }
}

/// VPN Connection state.
#[derive(Debug, Clone)]
pub struct ConnectionState {
    /// Current status
    pub status: VpnConnectionStatus,
    /// Connected server address
    pub server_addr: Option<String>,
    /// Connection statistics
    pub stats: ConnectionStats,
    /// Connection start time
    pub connected_at: Option<DateTime<Utc>>,
    /// Last error message
    pub last_error: Option<String>,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self {
            status: VpnConnectionStatus::Disconnected,
            server_addr: None,
            stats: ConnectionStats::default(),
            connected_at: None,
            last_error: None,
        }
    }
}

impl ConnectionState {
    /// Update connection duration.
    pub fn update_duration(&mut self) {
        if let Some(connected_at) = self.connected_at {
            let duration = Utc::now() - connected_at;
            self.stats.duration_secs = duration.num_seconds().max(0) as u64;
        }
    }
}

/// VPN Profile (saved connection configuration loaded from .ovpn).
#[derive(Debug, Clone)]
pub struct VpnProfile {
    /// Profile display name (derived from filename)
    pub name: String,
    /// Path to the .ovpn config file
    pub config_path: Option<PathBuf>,
    /// Remote server address:port
    pub server_addr: String,
    /// Protocol (udp/tcp)
    pub protocol: String,
    /// Cipher name
    pub cipher: String,
    /// Whether tls-auth is configured
    pub has_tls_auth: bool,
    /// Auto-connect this profile
    pub auto_connect: bool,
}

/// Main application state.
#[derive(Clone)]
pub struct AppState {
    /// Current view
    pub current_view: AppView,
    /// Authentication state
    pub auth: AuthState,
    /// Connection state
    pub connection: ConnectionState,
    /// Saved profiles (from imported .ovpn files)
    pub profiles: Vec<VpnProfile>,
    /// Active profile name
    pub active_profile: Option<String>,
    /// Authentication method for current profile
    pub auth_method: AuthMethod,
    /// Username (for username/password auth)
    pub username: String,
    /// Password (for username/password auth) - not persisted, zeroized on drop
    pub password: Zeroizing<String>,
    /// Remember credentials
    pub remember_credentials: bool,
    /// Auto-connect on startup
    pub auto_connect: bool,
    /// Show notifications
    pub show_notifications: bool,
    /// Log entries
    pub logs: Vec<LogEntry>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("current_view", &self.current_view)
            .field("auth", &self.auth)
            .field("connection", &self.connection)
            .field("profiles", &self.profiles)
            .field("active_profile", &self.active_profile)
            .field("auth_method", &self.auth_method)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("remember_credentials", &self.remember_credentials)
            .field("auto_connect", &self.auto_connect)
            .field("show_notifications", &self.show_notifications)
            .field("logs", &self.logs)
            .finish()
    }
}

/// Log entry for connection logs.
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// Log level
    pub level: LogLevel,
    /// Log message
    pub message: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Log level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// Debug level
    Debug,
    /// Info level
    Info,
    /// Warning level
    Warn,
    /// Error level
    Error,
}

impl LogLevel {
    /// Get the display string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }

    /// Get the color for UI display.
    pub fn color(&self) -> egui::Color32 {
        match self {
            Self::Debug => egui::Color32::GRAY,
            Self::Info => egui::Color32::from_rgb(100, 180, 255),
            Self::Warn => egui::Color32::YELLOW,
            Self::Error => egui::Color32::RED,
        }
    }
}

/// Application views.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AppView {
    /// Main connection view
    #[default]
    Connection,
    /// Server selection list (unused for now, profiles replace this)
    ServerList,
    /// Profile management
    Profiles,
    /// Settings
    Settings,
    /// Connection logs
    Logs,
    /// About/Help
    About,
}

impl Default for AppState {
    fn default() -> Self {
        let initial_logs = vec![LogEntry {
            level: LogLevel::Info,
            message: "Ready. Import an .ovpn profile to get started.".to_string(),
            timestamp: Utc::now(),
        }];

        Self {
            current_view: AppView::default(),
            auth: AuthState::default(),
            connection: ConnectionState::default(),
            profiles: Vec::new(),
            active_profile: None,
            auth_method: AuthMethod::Certificate,
            username: String::new(),
            password: Zeroizing::new(String::new()),
            remember_credentials: false,
            auto_connect: false,
            show_notifications: true,
            logs: initial_logs,
        }
    }
}

impl AppState {
    /// Create new application state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the active profile.
    pub fn active_profile_ref(&self) -> Option<&VpnProfile> {
        self.active_profile
            .as_ref()
            .and_then(|name| self.profiles.iter().find(|p| &p.name == name))
    }

    /// Check if we need to show password input.
    pub fn requires_password(&self) -> bool {
        self.auth_method.requires_password()
    }

    /// Check if using SSO authentication.
    pub fn is_sso(&self) -> bool {
        self.auth_method.is_sso()
    }

    /// Start connection process.
    pub fn start_connecting(&mut self) {
        self.connection.status = VpnConnectionStatus::Connecting;
        self.connection.last_error = None;
        self.add_log(LogLevel::Info, "Initiating VPN connection...");
    }

    /// Set connection as authenticating.
    pub fn set_authenticating(&mut self) {
        self.connection.status = VpnConnectionStatus::Authenticating;
        self.add_log(LogLevel::Info, "Authenticating...");
    }

    /// Set connection as connected.
    pub fn set_connected(&mut self) {
        self.connection.status = VpnConnectionStatus::Connected;
        self.connection.connected_at = Some(Utc::now());
        if let Some(profile) = self.active_profile_ref() {
            self.add_log(
                LogLevel::Info,
                &format!("Connected to {}", profile.server_addr),
            );
        }
    }

    /// Start disconnection process.
    pub fn start_disconnecting(&mut self) {
        self.connection.status = VpnConnectionStatus::Disconnecting;
        self.add_log(LogLevel::Info, "Disconnecting...");
    }

    /// Set connection as disconnected.
    pub fn set_disconnected(&mut self) {
        self.connection.status = VpnConnectionStatus::Disconnected;
        self.connection.server_addr = None;
        self.connection.connected_at = None;
        self.connection.stats = ConnectionStats::default();
        self.add_log(LogLevel::Info, "Disconnected");
    }

    /// Set connection error.
    pub fn set_error(&mut self, error: impl Into<String>) {
        let error = error.into();
        self.connection.status = VpnConnectionStatus::Error;
        self.connection.last_error = Some(error.clone());
        self.add_log(LogLevel::Error, &error);
    }

    /// Add a log entry.
    pub fn add_log(&mut self, level: LogLevel, message: &str) {
        self.logs.push(LogEntry {
            level,
            message: message.to_string(),
            timestamp: Utc::now(),
        });
        // Cap logs at 500 entries
        if self.logs.len() > 500 {
            self.logs.drain(0..100);
        }
    }

    /// Clear all logs.
    pub fn clear_logs(&mut self) {
        self.logs.clear();
    }

    /// Get password as a mutable reference for UI input.
    pub fn password_mut(&mut self) -> &mut String {
        &mut self.password
    }

    /// Get password for authentication.
    pub fn password(&self) -> &str {
        &self.password
    }
}

/// Validate username input.
pub fn validate_username(username: &str) -> Option<&'static str> {
    if username.is_empty() {
        return Some("Username cannot be empty");
    }
    if username.len() > 256 {
        return Some("Username is too long (max 256 characters)");
    }
    if username.chars().any(|c| c.is_control()) {
        return Some("Username contains invalid characters");
    }
    None
}

/// Validate password input.
pub fn validate_password(password: &str) -> Option<&'static str> {
    if password.is_empty() {
        return Some("Password cannot be empty");
    }
    if password.len() > 1024 {
        return Some("Password is too long (max 1024 characters)");
    }
    None
}
