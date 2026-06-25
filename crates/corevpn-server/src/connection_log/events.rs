//! Connection Event Types
//!
//! Defines all trackable connection events for the logging system.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a connection session
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConnectionId(pub Uuid);

impl ConnectionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ConnectionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Authentication method used
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// Certificate-based authentication
    Certificate,
    /// Username/password
    UsernamePassword,
    /// OAuth2/OIDC
    OAuth2,
    /// SAML
    Saml,
    /// Pre-shared key
    Psk,
    /// Unknown/not yet determined
    #[default]
    Unknown,
}

/// Reason for disconnection
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DisconnectReason {
    /// Client initiated clean disconnect
    ClientDisconnect,
    /// Server initiated disconnect
    ServerDisconnect,
    /// Idle timeout
    IdleTimeout,
    /// Session timeout (max duration)
    SessionTimeout,
    /// Authentication failure
    AuthFailure,
    /// Protocol error
    ProtocolError,
    /// Connection reset
    ConnectionReset,
    /// Server shutdown
    ServerShutdown,
    /// Admin terminated
    AdminTerminated,
    /// Key renegotiation failure
    RenegotiationFailure,
    /// Unknown reason
    #[default]
    Unknown,
}

/// Authentication result
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthResult {
    /// Authentication succeeded
    Success,
    /// Invalid credentials
    InvalidCredentials,
    /// Expired credentials/certificate
    Expired,
    /// User not authorized (valid creds but not permitted)
    NotAuthorized,
    /// Rate limited
    RateLimited,
    /// Provider error (OAuth2/SAML)
    ProviderError,
    /// Timeout during authentication
    Timeout,
    /// Unknown failure
    Unknown,
}

/// Data transfer statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransferStats {
    /// Bytes received from client
    pub bytes_rx: u64,
    /// Bytes sent to client
    pub bytes_tx: u64,
    /// Packets received from client
    pub packets_rx: u64,
    /// Packets sent to client
    pub packets_tx: u64,
}

#[allow(dead_code)] // Convenience accessors retained for future reporting use.
impl TransferStats {
    pub fn total_bytes(&self) -> u64 {
        self.bytes_rx + self.bytes_tx
    }

    pub fn total_packets(&self) -> u64 {
        self.packets_rx + self.packets_tx
    }
}

/// A connection event that can be logged
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum ConnectionEvent {
    /// Initial connection attempt (before authentication)
    ConnectionAttempt {
        /// Connection identifier
        connection_id: ConnectionId,
        /// Timestamp of the event
        timestamp: DateTime<Utc>,
        /// Client's source address
        client_addr: SocketAddr,
        /// Protocol version detected
        protocol_version: Option<String>,
    },

    /// Authentication event
    Authentication {
        /// Connection identifier
        connection_id: ConnectionId,
        /// Timestamp of the event
        timestamp: DateTime<Utc>,
        /// Client's source address
        client_addr: SocketAddr,
        /// Username or identifier (may be hashed)
        username: Option<String>,
        /// Authentication method used
        auth_method: AuthMethod,
        /// Result of authentication
        result: AuthResult,
        /// Additional details (error message, provider, etc.)
        details: Option<String>,
    },

    /// Successful connection established
    Connected {
        /// Connection identifier
        connection_id: ConnectionId,
        /// Timestamp of the event
        timestamp: DateTime<Utc>,
        /// Client's source address
        client_addr: SocketAddr,
        /// Username or identifier (may be hashed)
        username: Option<String>,
        /// Assigned VPN IP address
        vpn_ip: IpAddr,
        /// Authentication method used
        auth_method: AuthMethod,
        /// Client software/version if available
        client_info: Option<String>,
    },

    /// Client disconnected
    Disconnected {
        /// Connection identifier
        connection_id: ConnectionId,
        /// Timestamp of the event
        timestamp: DateTime<Utc>,
        /// Client's source address
        client_addr: SocketAddr,
        /// Username or identifier (may be hashed)
        username: Option<String>,
        /// Reason for disconnection
        reason: DisconnectReason,
        /// Connection duration
        duration: Duration,
        /// Transfer statistics
        stats: Option<TransferStats>,
    },

    /// Client IP address changed (reconnected from different IP)
    IpChange {
        /// Connection identifier
        connection_id: ConnectionId,
        /// Timestamp of the event
        timestamp: DateTime<Utc>,
        /// Previous client address
        old_addr: SocketAddr,
        /// New client address
        new_addr: SocketAddr,
        /// Username or identifier (may be hashed)
        username: Option<String>,
    },

    /// Key renegotiation event
    Renegotiation {
        /// Connection identifier
        connection_id: ConnectionId,
        /// Timestamp of the event
        timestamp: DateTime<Utc>,
        /// Client's source address
        client_addr: SocketAddr,
        /// Whether renegotiation succeeded
        success: bool,
    },
}

impl ConnectionEvent {
    /// Get the connection ID for this event
    #[allow(dead_code)] // Accessor retained for future query/reporting use.
    pub fn connection_id(&self) -> ConnectionId {
        match self {
            Self::ConnectionAttempt { connection_id, .. } => *connection_id,
            Self::Authentication { connection_id, .. } => *connection_id,
            Self::Connected { connection_id, .. } => *connection_id,
            Self::Disconnected { connection_id, .. } => *connection_id,
            Self::IpChange { connection_id, .. } => *connection_id,
            Self::Renegotiation { connection_id, .. } => *connection_id,
        }
    }

    /// Get the timestamp for this event
    pub fn timestamp(&self) -> DateTime<Utc> {
        match self {
            Self::ConnectionAttempt { timestamp, .. } => *timestamp,
            Self::Authentication { timestamp, .. } => *timestamp,
            Self::Connected { timestamp, .. } => *timestamp,
            Self::Disconnected { timestamp, .. } => *timestamp,
            Self::IpChange { timestamp, .. } => *timestamp,
            Self::Renegotiation { timestamp, .. } => *timestamp,
        }
    }

    /// Get the event type as a string
    #[allow(dead_code)] // Accessor retained for future query/reporting use.
    pub fn event_type(&self) -> &'static str {
        match self {
            Self::ConnectionAttempt { .. } => "connection_attempt",
            Self::Authentication { .. } => "authentication",
            Self::Connected { .. } => "connected",
            Self::Disconnected { .. } => "disconnected",
            Self::IpChange { .. } => "ip_change",
            Self::Renegotiation { .. } => "renegotiation",
        }
    }

    /// Get the client address for this event (if available)
    #[allow(dead_code)] // Accessor retained for future query/reporting use.
    pub fn client_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::ConnectionAttempt { client_addr, .. } => Some(*client_addr),
            Self::Authentication { client_addr, .. } => Some(*client_addr),
            Self::Connected { client_addr, .. } => Some(*client_addr),
            Self::Disconnected { client_addr, .. } => Some(*client_addr),
            Self::IpChange { new_addr, .. } => Some(*new_addr),
            Self::Renegotiation { client_addr, .. } => Some(*client_addr),
        }
    }
}

/// Builder for creating connection events
pub struct ConnectionEventBuilder {
    connection_id: ConnectionId,
}

impl ConnectionEventBuilder {
    pub fn new() -> Self {
        Self {
            connection_id: ConnectionId::new(),
        }
    }

    pub fn with_id(connection_id: ConnectionId) -> Self {
        Self { connection_id }
    }

    pub fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    pub fn attempt(self, client_addr: SocketAddr) -> ConnectionEvent {
        ConnectionEvent::ConnectionAttempt {
            connection_id: self.connection_id,
            timestamp: Utc::now(),
            client_addr,
            protocol_version: None,
        }
    }

    pub fn authentication(
        self,
        client_addr: SocketAddr,
        username: Option<String>,
        auth_method: AuthMethod,
        result: AuthResult,
    ) -> ConnectionEvent {
        ConnectionEvent::Authentication {
            connection_id: self.connection_id,
            timestamp: Utc::now(),
            client_addr,
            username,
            auth_method,
            result,
            details: None,
        }
    }

    #[allow(dead_code)] // Builder variant retained for future event emission.
    pub fn connected(
        self,
        client_addr: SocketAddr,
        vpn_ip: IpAddr,
        username: Option<String>,
        auth_method: AuthMethod,
    ) -> ConnectionEvent {
        ConnectionEvent::Connected {
            connection_id: self.connection_id,
            timestamp: Utc::now(),
            client_addr,
            username,
            vpn_ip,
            auth_method,
            client_info: None,
        }
    }

    pub fn disconnected(
        self,
        client_addr: SocketAddr,
        username: Option<String>,
        reason: DisconnectReason,
        duration: Duration,
        stats: Option<TransferStats>,
    ) -> ConnectionEvent {
        ConnectionEvent::Disconnected {
            connection_id: self.connection_id,
            timestamp: Utc::now(),
            client_addr,
            username,
            reason,
            duration,
            stats,
        }
    }

    #[allow(dead_code)] // Builder variant retained for future event emission.
    pub fn ip_change(
        self,
        old_addr: SocketAddr,
        new_addr: SocketAddr,
        username: Option<String>,
    ) -> ConnectionEvent {
        ConnectionEvent::IpChange {
            connection_id: self.connection_id,
            timestamp: Utc::now(),
            old_addr,
            new_addr,
            username,
        }
    }

    pub fn renegotiation(self, client_addr: SocketAddr, success: bool) -> ConnectionEvent {
        ConnectionEvent::Renegotiation {
            connection_id: self.connection_id,
            timestamp: Utc::now(),
            client_addr,
            success,
        }
    }
}

impl Default for ConnectionEventBuilder {
    fn default() -> Self {
        Self::new()
    }
}
