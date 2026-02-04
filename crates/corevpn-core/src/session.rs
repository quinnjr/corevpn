//! VPN Session management

use chrono::{DateTime, Duration, Utc};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{CoreError, Result, UserId, VpnAddress};

/// Unique session identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(Uuid);

impl SessionId {
    /// Generate a new random session ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Uuid::from_bytes(bytes))
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// Initial connection, awaiting authentication
    Connecting,
    /// TLS handshake in progress
    Handshaking,
    /// Authenticating (OAuth2 flow or certificate)
    Authenticating,
    /// Fully established and active
    Active,
    /// Graceful disconnection in progress
    Disconnecting,
    /// Session terminated
    Terminated,
}

/// VPN Session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session ID
    pub id: SessionId,
    /// Associated user (if authenticated)
    pub user_id: Option<UserId>,
    /// Session state
    pub state: SessionState,
    /// Assigned VPN IP address
    pub vpn_address: Option<VpnAddress>,
    /// Client's real IP address
    pub client_ip: std::net::IpAddr,
    /// Client's port
    pub client_port: u16,
    /// Session creation time
    pub created_at: DateTime<Utc>,
    /// Last activity time
    pub last_activity: DateTime<Utc>,
    /// Session expiration time
    pub expires_at: DateTime<Utc>,
    /// Bytes received from client
    pub bytes_rx: u64,
    /// Bytes sent to client
    pub bytes_tx: u64,
    /// Packets received from client
    pub packets_rx: u64,
    /// Packets sent to client
    pub packets_tx: u64,
    /// Client user agent / version
    pub client_version: Option<String>,
    /// OAuth2 access token (if using OAuth2 auth)
    #[serde(skip)]
    pub oauth_token: Option<SecretString>,
}

impl Session {
    /// Create a new session
    pub fn new(client_ip: std::net::IpAddr, client_port: u16, lifetime: Duration) -> Self {
        let now = Utc::now();
        Self {
            id: SessionId::new(),
            user_id: None,
            state: SessionState::Connecting,
            vpn_address: None,
            client_ip,
            client_port,
            created_at: now,
            last_activity: now,
            expires_at: now + lifetime,
            bytes_rx: 0,
            bytes_tx: 0,
            packets_rx: 0,
            packets_tx: 0,
            client_version: None,
            oauth_token: None,
        }
    }

    /// Check if session is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if session is active
    pub fn is_active(&self) -> bool {
        self.state == SessionState::Active && !self.is_expired()
    }

    /// Update last activity timestamp
    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
    }

    /// Record received data
    pub fn record_rx(&mut self, bytes: u64) {
        self.bytes_rx += bytes;
        self.packets_rx += 1;
        self.touch();
    }

    /// Record sent data
    pub fn record_tx(&mut self, bytes: u64) {
        self.bytes_tx += bytes;
        self.packets_tx += 1;
        self.touch();
    }

    /// Transition to a new state
    pub fn transition(&mut self, new_state: SessionState) -> Result<()> {
        use SessionState::*;

        // Validate state transitions
        let valid = match (self.state, new_state) {
            (Connecting, Handshaking) => true,
            (Handshaking, Authenticating) => true,
            (Authenticating, Active) => true,
            (Active, Disconnecting) => true,
            (_, Terminated) => true, // Can always terminate
            _ => false,
        };

        if valid {
            self.state = new_state;
            Ok(())
        } else {
            Err(CoreError::Internal(format!(
                "Invalid state transition: {:?} -> {:?}",
                self.state, new_state
            )))
        }
    }

    /// Get session duration
    pub fn duration(&self) -> Duration {
        Utc::now() - self.created_at
    }

    /// Get idle time since last activity
    pub fn idle_time(&self) -> Duration {
        Utc::now() - self.last_activity
    }

    /// Extend session expiration
    pub fn extend(&mut self, duration: Duration) {
        self.expires_at = Utc::now() + duration;
    }
}

/// Session manager for tracking active sessions
pub struct SessionManager {
    sessions: parking_lot::RwLock<std::collections::HashMap<SessionId, Session>>,
    max_sessions: usize,
    default_lifetime: Duration,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(max_sessions: usize, default_lifetime: Duration) -> Self {
        Self {
            sessions: parking_lot::RwLock::new(std::collections::HashMap::new()),
            max_sessions,
            default_lifetime,
        }
    }

    /// Create a new session
    pub fn create_session(
        &self,
        client_ip: std::net::IpAddr,
        client_port: u16,
    ) -> Result<Session> {
        let mut sessions = self.sessions.write();

        // Check capacity
        if sessions.len() >= self.max_sessions {
            // Try to clean up expired sessions
            sessions.retain(|_, s| !s.is_expired());

            if sessions.len() >= self.max_sessions {
                return Err(CoreError::Internal("Maximum sessions reached".into()));
            }
        }

        let session = Session::new(client_ip, client_port, self.default_lifetime);
        sessions.insert(session.id, session.clone());

        Ok(session)
    }

    /// Get a session by ID
    pub fn get_session(&self, id: &SessionId) -> Option<Session> {
        self.sessions.read().get(id).cloned()
    }

    /// Update a session
    pub fn update_session(&self, session: Session) -> Result<()> {
        use std::collections::hash_map::Entry;
        let mut sessions = self.sessions.write();
        match sessions.entry(session.id) {
            Entry::Occupied(mut e) => {
                e.insert(session);
                Ok(())
            }
            Entry::Vacant(_) => Err(CoreError::SessionNotFound(session.id.to_string())),
        }
    }

    /// Remove a session
    pub fn remove_session(&self, id: &SessionId) -> Option<Session> {
        self.sessions.write().remove(id)
    }

    /// Get all active sessions
    pub fn active_sessions(&self) -> Vec<Session> {
        self.sessions
            .read()
            .values()
            .filter(|s| s.is_active())
            .cloned()
            .collect()
    }

    /// Get session count
    pub fn session_count(&self) -> usize {
        self.sessions.read().len()
    }

    /// Clean up expired sessions
    pub fn cleanup_expired(&self) -> usize {
        let mut sessions = self.sessions.write();
        let before = sessions.len();
        sessions.retain(|_, s| !s.is_expired());
        before - sessions.len()
    }

    /// Get sessions by user ID
    pub fn get_user_sessions(&self, user_id: &UserId) -> Vec<Session> {
        self.sessions
            .read()
            .values()
            .filter(|s| s.user_id.as_ref() == Some(user_id))
            .cloned()
            .collect()
    }

    /// Terminate all sessions for a user
    pub fn terminate_user_sessions(&self, user_id: &UserId) -> usize {
        let mut sessions = self.sessions.write();
        let mut count = 0;

        for session in sessions.values_mut() {
            if session.user_id.as_ref() == Some(user_id) {
                session.state = SessionState::Terminated;
                count += 1;
            }
        }

        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_lifecycle() {
        let mut session = Session::new(
            "192.168.1.1".parse().unwrap(),
            12345,
            Duration::hours(1),
        );

        assert_eq!(session.state, SessionState::Connecting);
        assert!(!session.is_expired());

        session.transition(SessionState::Handshaking).unwrap();
        session.transition(SessionState::Authenticating).unwrap();
        session.transition(SessionState::Active).unwrap();

        assert!(session.is_active());

        session.record_rx(1000);
        session.record_tx(500);

        assert_eq!(session.bytes_rx, 1000);
        assert_eq!(session.bytes_tx, 500);
    }

    #[test]
    fn test_session_manager() {
        let manager = SessionManager::new(100, Duration::hours(1));

        let session = manager
            .create_session("192.168.1.1".parse().unwrap(), 12345)
            .unwrap();

        assert!(manager.get_session(&session.id).is_some());
        assert_eq!(manager.session_count(), 1);

        manager.remove_session(&session.id);
        assert!(manager.get_session(&session.id).is_none());
    }
}
