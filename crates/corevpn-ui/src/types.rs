//! VPN UI Types
//!
//! Core types for the VPN client interface.

use serde::{Deserialize, Serialize};

/// VPN connection status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum VpnConnectionStatus {
    /// Not connected
    #[default]
    Disconnected,
    /// Establishing connection
    Connecting,
    /// Authenticating with server
    Authenticating,
    /// Successfully connected
    Connected,
    /// Disconnecting from server
    Disconnecting,
    /// Attempting to reconnect
    Reconnecting,
    /// Connection error
    Error,
}

impl VpnConnectionStatus {
    /// Get a human-readable status string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Disconnected => "Disconnected",
            Self::Connecting => "Connecting...",
            Self::Authenticating => "Authenticating...",
            Self::Connected => "Connected",
            Self::Disconnecting => "Disconnecting...",
            Self::Reconnecting => "Reconnecting...",
            Self::Error => "Error",
        }
    }

    /// Check if currently connected.
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected)
    }

    /// Check if in a transitional state.
    pub fn is_transitioning(&self) -> bool {
        matches!(
            self,
            Self::Connecting | Self::Authenticating | Self::Disconnecting | Self::Reconnecting
        )
    }

    /// Get the status color for UI display.
    pub fn color(&self) -> egui::Color32 {
        match self {
            Self::Disconnected => egui::Color32::GRAY,
            Self::Connecting | Self::Authenticating => egui::Color32::YELLOW,
            Self::Connected => egui::Color32::from_rgb(80, 200, 120),
            Self::Disconnecting | Self::Reconnecting => egui::Color32::from_rgb(255, 165, 0),
            Self::Error => egui::Color32::from_rgb(220, 80, 80),
        }
    }
}

/// Authentication method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum AuthMethod {
    /// Username and password
    UsernamePassword,
    /// Certificate-based authentication
    #[default]
    Certificate,
    /// OAuth2/OIDC authentication
    OAuth2,
    /// SAML authentication
    Saml,
}

impl AuthMethod {
    /// Check if this method requires a password input.
    pub fn requires_password(&self) -> bool {
        matches!(self, Self::UsernamePassword)
    }

    /// Check if this is an SSO method.
    pub fn is_sso(&self) -> bool {
        matches!(self, Self::OAuth2 | Self::Saml)
    }

    /// Get a human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::UsernamePassword => "Username/Password",
            Self::Certificate => "Certificate",
            Self::OAuth2 => "OAuth2/SSO",
            Self::Saml => "SAML/SSO",
        }
    }
}

/// Connection statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectionStats {
    /// Bytes received
    pub bytes_rx: u64,
    /// Bytes transmitted
    pub bytes_tx: u64,
    /// Current download speed (bytes/sec)
    pub speed_rx: u64,
    /// Current upload speed (bytes/sec)
    pub speed_tx: u64,
    /// Connection duration in seconds
    pub duration_secs: u64,
}

impl ConnectionStats {
    /// Format bytes for display.
    pub fn format_bytes(bytes: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;

        if bytes >= GB {
            format!("{:.2} GB", bytes as f64 / GB as f64)
        } else if bytes >= MB {
            format!("{:.2} MB", bytes as f64 / MB as f64)
        } else if bytes >= KB {
            format!("{:.1} KB", bytes as f64 / KB as f64)
        } else {
            format!("{} B", bytes)
        }
    }

    /// Format speed for display.
    pub fn format_speed(bytes_per_sec: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;

        if bytes_per_sec >= MB {
            format!("{:.1} MB/s", bytes_per_sec as f64 / MB as f64)
        } else if bytes_per_sec >= KB {
            format!("{:.1} KB/s", bytes_per_sec as f64 / KB as f64)
        } else {
            format!("{} B/s", bytes_per_sec)
        }
    }

    /// Format duration for display.
    pub fn format_duration(secs: u64) -> String {
        let hours = secs / 3600;
        let minutes = (secs % 3600) / 60;
        let seconds = secs % 60;

        if hours > 0 {
            format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
        } else {
            format!("{:02}:{:02}", minutes, seconds)
        }
    }
}
