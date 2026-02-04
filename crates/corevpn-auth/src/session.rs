//! Authentication Session Management

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use tracing::{debug, warn};

use crate::{AuthError, AuthState, Result, TokenSet, UserInfo};

/// Rate limiter entry
#[derive(Clone)]
struct RateLimitEntry {
    count: u32,
    reset_at: SystemTime,
}

/// In-memory rate limiter for brute force protection
pub struct RateLimiter {
    /// Attempts per window
    max_attempts: u32,
    /// Window duration
    window: Duration,
    /// Entries by key (IP address, email, etc.)
    entries: RwLock<HashMap<String, RateLimitEntry>>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(max_attempts: u32, window: Duration) -> Self {
        Self {
            max_attempts,
            window,
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Check if key is rate limited
    pub fn check(&self, key: &str) -> bool {
        let mut entries = self.entries.write();
        let now = SystemTime::now();

        // Clean up expired entries
        entries.retain(|_, entry| entry.reset_at > now);

        let entry = entries.entry(key.to_string()).or_insert_with(|| {
            RateLimitEntry {
                count: 0,
                reset_at: now + self.window,
            }
        });

        // Check if reset time has passed
        if now >= entry.reset_at {
            entry.count = 0;
            entry.reset_at = now + self.window;
        }

        entry.count += 1;
        let allowed = entry.count <= self.max_attempts;

        if !allowed {
            warn!("Rate limit exceeded for key: {}", key);
        }

        allowed
    }

    /// Reset rate limit for a key
    pub fn reset(&self, key: &str) {
        self.entries.write().remove(key);
    }

    /// Clean up expired entries
    pub fn cleanup(&self) {
        let now = SystemTime::now();
        self.entries.write().retain(|_, entry| entry.reset_at > now);
    }
}

/// Authentication session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    /// Session ID
    pub id: String,
    /// Authentication state (for OAuth2 flow)
    pub auth_state: Option<AuthState>,
    /// Token set (after successful authentication)
    pub tokens: Option<TokenSet>,
    /// User information
    pub user_info: Option<UserInfo>,
    /// Provider name
    pub provider: String,
    /// Session creation time
    pub created_at: DateTime<Utc>,
    /// Session expiration time
    pub expires_at: DateTime<Utc>,
    /// Last activity time
    pub last_activity: DateTime<Utc>,
    /// Associated VPN session ID (if connected)
    pub vpn_session_id: Option<String>,
    /// IP address of the client
    pub client_ip: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl AuthSession {
    /// Create a new auth session
    pub fn new(provider: &str, lifetime: Duration) -> Self {
        let now = Utc::now();
        let auth_state = AuthState::new(Duration::from_secs(600)); // 10 min for OAuth flow

        Self {
            id: Uuid::new_v4().to_string(),
            auth_state: Some(auth_state),
            tokens: None,
            user_info: None,
            provider: provider.to_string(),
            created_at: now,
            expires_at: now + chrono::Duration::from_std(lifetime)
                .unwrap_or_else(|_| chrono::Duration::seconds(86400)), // Fallback to 24 hours
            last_activity: now,
            vpn_session_id: None,
            client_ip: None,
            metadata: HashMap::new(),
        }
    }

    /// Check if session is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if session is authenticated
    pub fn is_authenticated(&self) -> bool {
        self.tokens.is_some() && self.user_info.is_some()
    }

    /// Check if tokens need refresh
    pub fn needs_token_refresh(&self) -> bool {
        if let Some(tokens) = &self.tokens {
            tokens.expires_within(chrono::Duration::minutes(5))
        } else {
            false
        }
    }

    /// Update tokens
    pub fn update_tokens(&mut self, tokens: TokenSet) {
        self.tokens = Some(tokens);
        self.last_activity = Utc::now();
    }

    /// Update user info
    pub fn update_user_info(&mut self, user_info: UserInfo) {
        self.user_info = Some(user_info);
        self.last_activity = Utc::now();
    }

    /// Mark authentication complete
    pub fn complete_auth(&mut self, tokens: TokenSet, user_info: UserInfo) {
        self.tokens = Some(tokens);
        self.user_info = Some(user_info);
        self.auth_state = None; // Clear auth state after successful auth
        self.last_activity = Utc::now();
    }

    /// Associate with VPN session
    pub fn associate_vpn_session(&mut self, vpn_session_id: &str) {
        self.vpn_session_id = Some(vpn_session_id.to_string());
        self.last_activity = Utc::now();
    }

    /// Extend session lifetime
    pub fn extend(&mut self, duration: Duration) {
        self.expires_at = Utc::now() + chrono::Duration::from_std(duration).unwrap();
    }

    /// Touch session (update last activity)
    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
    }

    /// Get session duration
    pub fn duration(&self) -> chrono::Duration {
        Utc::now() - self.created_at
    }

    /// Get idle time
    pub fn idle_time(&self) -> chrono::Duration {
        Utc::now() - self.last_activity
    }

    /// Get the OAuth2 state value
    pub fn state(&self) -> Option<&str> {
        self.auth_state.as_ref().map(|s| s.state.as_str())
    }

    /// Get user email
    pub fn email(&self) -> Option<&str> {
        self.user_info.as_ref().and_then(|u| u.email.as_deref())
    }

    /// Get user display name
    pub fn display_name(&self) -> Option<&str> {
        self.user_info.as_ref().and_then(|u| u.name.as_deref())
    }
}

/// Authentication session manager
pub struct AuthSessionManager {
    /// Sessions by ID
    sessions: RwLock<HashMap<String, AuthSession>>,
    /// Sessions by OAuth2 state
    sessions_by_state: RwLock<HashMap<String, String>>,
    /// Default session lifetime
    default_lifetime: Duration,
    /// Maximum sessions per user
    max_sessions_per_user: usize,
    /// Rate limiter for session lookups
    lookup_rate_limiter: RateLimiter,
}

impl AuthSessionManager {
    /// Create a new session manager
    pub fn new(default_lifetime: Duration, max_sessions_per_user: usize) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            sessions_by_state: RwLock::new(HashMap::new()),
            default_lifetime,
            max_sessions_per_user,
            lookup_rate_limiter: RateLimiter::new(100, Duration::from_secs(60)), // 100 lookups per minute
        }
    }

    /// Create a new session
    pub fn create_session(&self, provider: &str) -> AuthSession {
        let session = AuthSession::new(provider, self.default_lifetime);

        // Store session
        let mut sessions = self.sessions.write();
        let mut by_state = self.sessions_by_state.write();

        if let Some(state) = session.state() {
            by_state.insert(state.to_string(), session.id.clone());
        }
        sessions.insert(session.id.clone(), session.clone());

        session
    }

    /// Get session by ID (with rate limiting)
    pub fn get_session(&self, id: &str, client_ip: Option<&str>) -> Option<AuthSession> {
        // Rate limit lookups by IP or session ID
        let rate_limit_key = client_ip.unwrap_or(id);
        if !self.lookup_rate_limiter.check(rate_limit_key) {
            warn!("Rate limit exceeded for session lookup: {}", rate_limit_key);
            return None;
        }

        // Verify session ID is a valid UUID v4
        if Uuid::parse_str(id).map(|u| u.get_version() != Some(uuid::Version::Random))
            .unwrap_or(true) {
            warn!("Invalid session ID format: {}", id);
            return None;
        }

        self.sessions.read().get(id).cloned()
    }

    /// Get session by OAuth2 state (with rate limiting)
    pub fn get_session_by_state(&self, state: &str, client_ip: Option<&str>) -> Option<AuthSession> {
        // Rate limit lookups
        let rate_limit_key = client_ip.unwrap_or(state);
        if !self.lookup_rate_limiter.check(rate_limit_key) {
            warn!("Rate limit exceeded for state lookup: {}", rate_limit_key);
            return None;
        }

        let session_id = self.sessions_by_state.read().get(state)?.clone();
        self.get_session(&session_id, client_ip)
    }

    /// Update session
    pub fn update_session(&self, session: &AuthSession) -> Result<()> {
        let mut sessions = self.sessions.write();
        if sessions.contains_key(&session.id) {
            sessions.insert(session.id.clone(), session.clone());
            Ok(())
        } else {
            Err(AuthError::SessionNotFound)
        }
    }

    /// Remove session
    pub fn remove_session(&self, id: &str) -> Option<AuthSession> {
        let mut sessions = self.sessions.write();
        let mut by_state = self.sessions_by_state.write();

        if let Some(session) = sessions.remove(id) {
            if let Some(state) = session.state() {
                by_state.remove(state);
            }
            Some(session)
        } else {
            None
        }
    }

    /// Get all sessions for a user (by email) - with rate limiting
    pub fn get_user_sessions(&self, email: &str, client_ip: Option<&str>) -> Vec<AuthSession> {
        // Rate limit user session lookups
        let rate_limit_key = client_ip.unwrap_or(email);
        if !self.lookup_rate_limiter.check(rate_limit_key) {
            warn!("Rate limit exceeded for user session lookup: {}", rate_limit_key);
            return Vec::new();
        }

        self.sessions
            .read()
            .values()
            .filter(|s| s.email() == Some(email))
            .cloned()
            .collect()
    }

    /// Remove all sessions for a user
    pub fn remove_user_sessions(&self, email: &str) -> usize {
        let mut sessions = self.sessions.write();
        let mut by_state = self.sessions_by_state.write();

        let to_remove: Vec<_> = sessions
            .iter()
            .filter(|(_, s)| s.email() == Some(email))
            .map(|(id, s)| (id.clone(), s.state().map(String::from)))
            .collect();

        for (id, state) in &to_remove {
            sessions.remove(id);
            if let Some(s) = state {
                by_state.remove(s);
            }
        }

        to_remove.len()
    }

    /// Cleanup expired sessions
    pub fn cleanup_expired(&self) -> usize {
        let mut sessions = self.sessions.write();
        let mut by_state = self.sessions_by_state.write();

        let before = sessions.len();

        let expired: Vec<_> = sessions
            .iter()
            .filter(|(_, s)| s.is_expired())
            .map(|(id, s)| (id.clone(), s.state().map(String::from)))
            .collect();

        for (id, state) in &expired {
            sessions.remove(id);
            if let Some(s) = state {
                by_state.remove(s);
            }
        }

        before - sessions.len()
    }

    /// Get session count
    pub fn session_count(&self) -> usize {
        self.sessions.read().len()
    }

    /// Get all active sessions
    pub fn active_sessions(&self) -> Vec<AuthSession> {
        self.sessions
            .read()
            .values()
            .filter(|s| !s.is_expired() && s.is_authenticated())
            .cloned()
            .collect()
    }
}

impl Default for AuthSessionManager {
    fn default() -> Self {
        Self::new(Duration::from_secs(86400), 5) // 24 hours, 5 sessions per user
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_session() {
        let mut session = AuthSession::new("google", Duration::from_secs(3600));

        assert!(!session.is_expired());
        assert!(!session.is_authenticated());
        assert!(session.state().is_some());
    }

    #[test]
    fn test_session_manager() {
        let manager = AuthSessionManager::default();

        let session = manager.create_session("google");
        let state = session.state().unwrap().to_string();

        // Get by ID
        let found = manager.get_session(&session.id, None);
        assert!(found.is_some());

        // Get by state
        let found = manager.get_session_by_state(&state, None);
        assert!(found.is_some());

        // Remove
        manager.remove_session(&session.id);
        assert!(manager.get_session(&session.id, None).is_none());
    }

    #[test]
    fn test_session_lifecycle() {
        let manager = AuthSessionManager::default();

        let mut session = manager.create_session("google");

        // Simulate successful auth
        let tokens = TokenSet {
            access_token: "test-token".to_string(),
            refresh_token: Some("refresh-token".to_string()),
            id_token: None,
            expires_at: Utc::now() + chrono::Duration::hours(1),
            token_type: "Bearer".to_string(),
            scopes: vec![],
        };

        let user_info = UserInfo {
            sub: "user123".to_string(),
            email: Some("user@example.com".to_string()),
            email_verified: true,
            name: Some("Test User".to_string()),
            given_name: None,
            family_name: None,
            picture: None,
            groups: vec![],
            provider: "google".to_string(),
        };

        session.complete_auth(tokens, user_info);

        assert!(session.is_authenticated());
        assert!(session.auth_state.is_none()); // Cleared after auth
        assert_eq!(session.email(), Some("user@example.com"));
    }
}
