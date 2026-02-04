//! Application State Management
//!
//! Manages the global application state for the VPN client.

use chrono::{DateTime, Utc};
use zeroize::Zeroizing;

use corevpn_auth::ProviderType;
use crate::types::{AuthMethod, ConnectionStats, VpnConnectionStatus, VpnServer};

/// Authentication state.
#[derive(Clone)]
pub enum AuthState {
    /// Not authenticated
    NotAuthenticated,
    /// Authenticating via OAuth2/SAML (browser opened)
    AwaitingSso {
        /// Provider type
        provider: ProviderType,
        /// State for CSRF protection (sensitive - use Zeroizing to clear on drop)
        state: Zeroizing<String>,
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
            Self::AwaitingSso { provider, state: _ } => {
                f.debug_struct("AwaitingSso")
                    .field("provider", provider)
                    .field("state", &"<redacted>")
                    .finish()
            }
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
    /// Connected server (if any)
    pub server: Option<VpnServer>,
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
            server: None,
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

/// Main application state.
#[derive(Clone)]
pub struct AppState {
    /// Current view
    pub current_view: AppView,
    /// Authentication state
    pub auth: AuthState,
    /// Connection state
    pub connection: ConnectionState,
    /// Available servers
    pub servers: Vec<VpnServer>,
    /// Selected server ID
    pub selected_server_id: Option<String>,
    /// Saved profiles
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
    /// Search query for server list
    pub server_search: String,
    /// Log entries
    pub logs: Vec<LogEntry>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("current_view", &self.current_view)
            .field("auth", &self.auth)
            .field("connection", &self.connection)
            .field("servers", &self.servers)
            .field("selected_server_id", &self.selected_server_id)
            .field("profiles", &self.profiles)
            .field("active_profile", &self.active_profile)
            .field("auth_method", &self.auth_method)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("remember_credentials", &self.remember_credentials)
            .field("auto_connect", &self.auto_connect)
            .field("show_notifications", &self.show_notifications)
            .field("server_search", &self.server_search)
            .field("logs", &self.logs)
            .finish()
    }
}

/// VPN Profile (saved connection configuration).
#[derive(Debug, Clone)]
pub struct VpnProfile {
    /// Profile name
    pub name: String,
    /// Server configuration
    pub server: VpnServer,
    /// Authentication method
    pub auth_method: AuthMethod,
    /// Saved username (if any)
    pub username: Option<String>,
    /// OAuth2 provider type (if SSO)
    pub oauth_provider: Option<ProviderType>,
    /// Auto-connect this profile
    pub auto_connect: bool,
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
    /// Server selection list
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
        // Default demo servers for development
        let demo_servers = vec![
            VpnServer::new("us-east-1", "US East", "vpn-us-east.corevpn.io")
                .country("US")
                .city("New York")
                .port(1194)
                .load(35)
                .latency(25)
                .sso_enabled(true),
            VpnServer::new("us-west-1", "US West", "vpn-us-west.corevpn.io")
                .country("US")
                .city("San Francisco")
                .port(1194)
                .load(62)
                .latency(45)
                .sso_enabled(true),
            VpnServer::new("eu-west-1", "Europe West", "vpn-eu-west.corevpn.io")
                .country("DE")
                .city("Frankfurt")
                .port(1194)
                .load(48)
                .latency(120)
                .sso_enabled(true),
            VpnServer::new("eu-north-1", "Europe North", "vpn-eu-north.corevpn.io")
                .country("SE")
                .city("Stockholm")
                .port(1194)
                .load(22)
                .latency(135)
                .sso_enabled(true),
            VpnServer::new("ap-east-1", "Asia Pacific", "vpn-ap-east.corevpn.io")
                .country("JP")
                .city("Tokyo")
                .port(1194)
                .load(55)
                .latency(180)
                .sso_enabled(false),
            VpnServer::new("ap-south-1", "Asia South", "vpn-ap-south.corevpn.io")
                .country("SG")
                .city("Singapore")
                .port(1194)
                .load(41)
                .latency(200),
        ];

        let initial_logs = vec![
            LogEntry {
                level: LogLevel::Info,
                message: "Application started".to_string(),
                timestamp: Utc::now(),
            },
            LogEntry {
                level: LogLevel::Info,
                message: "Loading configuration...".to_string(),
                timestamp: Utc::now(),
            },
            LogEntry {
                level: LogLevel::Info,
                message: "Configuration loaded successfully".to_string(),
                timestamp: Utc::now(),
            },
            LogEntry {
                level: LogLevel::Info,
                message: "Ready to connect".to_string(),
                timestamp: Utc::now(),
            },
        ];

        Self {
            current_view: AppView::default(),
            auth: AuthState::default(),
            connection: ConnectionState::default(),
            servers: demo_servers,
            selected_server_id: Some("us-east-1".to_string()),
            profiles: Vec::new(),
            active_profile: None,
            auth_method: AuthMethod::OAuth2, // Default to SSO
            username: String::new(),
            password: Zeroizing::new(String::new()),
            remember_credentials: false,
            auto_connect: false,
            show_notifications: true,
            server_search: String::new(),
            logs: initial_logs,
        }
    }
}

impl AppState {
    /// Create new application state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the currently selected server.
    pub fn selected_server(&self) -> Option<&VpnServer> {
        self.selected_server_id
            .as_ref()
            .and_then(|id| self.servers.iter().find(|s| &s.id == id))
    }

    /// Check if we need to show password input.
    pub fn requires_password(&self) -> bool {
        self.auth_method.requires_password()
    }

    /// Check if using SSO authentication.
    pub fn is_sso(&self) -> bool {
        self.auth_method.is_sso()
    }

    /// Select a server by ID.
    pub fn select_server(&mut self, id: &str) {
        if self.servers.iter().any(|s| s.id == id) {
            self.selected_server_id = Some(id.to_string());

            // Update auth method based on server SSO support
            if let Some(server) = self.servers.iter().find(|s| s.id == id) {
                if server.sso_enabled {
                    self.auth_method = AuthMethod::OAuth2;
                }
            }
        }
    }

    /// Start connection process.
    pub fn start_connecting(&mut self) {
        self.connection.status = VpnConnectionStatus::Connecting;
        self.connection.last_error = None;
        self.add_log(LogLevel::Info, "Connecting to VPN server...");
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
        if let Some(server) = self.selected_server().cloned() {
            self.add_log(LogLevel::Info, &format!("Connected to {}", server.name));
            self.connection.server = Some(server);
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
        self.connection.server = None;
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

    /// Update connection statistics.
    pub fn update_stats(&mut self, bytes_rx: u64, bytes_tx: u64, speed_rx: u64, speed_tx: u64) {
        self.connection.stats.bytes_rx = bytes_rx;
        self.connection.stats.bytes_tx = bytes_tx;
        self.connection.stats.speed_rx = speed_rx;
        self.connection.stats.speed_tx = speed_tx;
        self.connection.update_duration();
    }

    /// Add a log entry.
    pub fn add_log(&mut self, level: LogLevel, message: &str) {
        self.logs.push(LogEntry {
            level,
            message: message.to_string(),
            timestamp: Utc::now(),
        });
    }

    /// Clear all logs.
    pub fn clear_logs(&mut self) {
        self.logs.clear();
    }

    /// Get filtered servers based on search query.
    pub fn filtered_servers(&self) -> Vec<&VpnServer> {
        if self.server_search.is_empty() {
            self.servers.iter().collect()
        } else {
            // Sanitize search query to prevent injection
            let sanitized_query = sanitize_search_input(&self.server_search);
            let query = sanitized_query.to_lowercase();
            self.servers
                .iter()
                .filter(|s| {
                    s.name.to_lowercase().contains(&query)
                        || s.location().to_lowercase().contains(&query)
                        || s.host.to_lowercase().contains(&query)
                })
                .collect()
        }
    }

    /// Get password as a mutable reference for UI input.
    /// This is needed for egui TextEdit which requires &mut String.
    /// The Zeroizing wrapper ensures the password is cleared from memory on drop.
    pub fn password_mut(&mut self) -> &mut String {
        &mut self.password
    }

    /// Set password from a string.
    pub fn set_password(&mut self, password: String) {
        self.password = Zeroizing::new(password);
    }

    /// Get password for authentication.
    pub fn password(&self) -> &str {
        &self.password
    }
}

/// Validate username input.
/// Returns an error message if validation fails, None if valid.
pub fn validate_username(username: &str) -> Option<&'static str> {
    if username.is_empty() {
        return Some("Username cannot be empty");
    }

    // Check length (reasonable limit)
    if username.len() > 256 {
        return Some("Username is too long (max 256 characters)");
    }

    // Check for control characters
    if username.chars().any(|c| c.is_control()) {
        return Some("Username contains invalid characters");
    }

    None
}

/// Validate password input.
/// Returns an error message if validation fails, None if valid.
pub fn validate_password(password: &str) -> Option<&'static str> {
    if password.is_empty() {
        return Some("Password cannot be empty");
    }

    // Check length (reasonable limit)
    if password.len() > 1024 {
        return Some("Password is too long (max 1024 characters)");
    }

    // Check for control characters (except common ones like tab/newline which might be valid)
    // Allow printable ASCII and common unicode, but reject control chars
    if password.chars().any(|c| {
        c.is_control() && c != '\t' && c != '\n' && c != '\r'
    }) {
        return Some("Password contains invalid control characters");
    }

    None
}

/// Validate server hostname.
/// Returns an error message if validation fails, None if valid.
pub fn validate_hostname(hostname: &str) -> Option<&'static str> {
    if hostname.is_empty() {
        return Some("Hostname cannot be empty");
    }

    // Check length
    if hostname.len() > 253 {
        return Some("Hostname is too long (max 253 characters)");
    }

    // Check for injection characters
    if hostname.chars().any(|c| {
        matches!(c, '\0' | '\n' | '\r' | '\t' | ' ' | '/' | '\\' | ':' | ';' | '|' | '&' | '$' | '`' | '\'' | '"' | '<' | '>' | '(' | ')' | '{' | '}' | '[' | ']')
    }) {
        return Some("Hostname contains invalid characters");
    }

    None
}

/// Validate port number.
/// Returns an error message if validation fails, None if valid.
pub fn validate_port(port: u16) -> Option<&'static str> {
    if port == 0 {
        return Some("Port cannot be 0");
    }
    // u16 already enforces max 65535, so we just check for 0
    None
}

/// Sanitize search input to prevent injection.
/// Removes or escapes potentially dangerous characters.
pub fn sanitize_search_input(input: &str) -> String {
    input
        .chars()
        .filter(|c| {
            // Allow alphanumeric, spaces, common punctuation, and unicode letters
            c.is_alphanumeric()
                || c.is_whitespace()
                || matches!(c, '-' | '_' | '.' | ',' | ':' | ';' | '(' | ')' | '[' | ']' | '{' | '}' | '!' | '?' | '@' | '#' | '$' | '%' | '&' | '*' | '+' | '=' | '|' | '\\' | '/' | '<' | '>')
        })
        .take(256) // Limit length
        .collect()
}
