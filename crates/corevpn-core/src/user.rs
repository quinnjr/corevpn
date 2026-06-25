//! User management types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique user identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(String);

impl UserId {
    /// Create a new user ID from string
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Create from email (common for OAuth2)
    pub fn from_email(email: &str) -> Self {
        Self(email.to_lowercase())
    }

    /// Create a random user ID
    pub fn random() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Get the ID as a string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for UserId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for UserId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// User role for access control
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum UserRole {
    /// Full access to all networks
    Admin,
    /// Standard VPN access
    #[default]
    User,
    /// Limited access (specific routes only)
    Limited,
    /// Read-only (monitoring only, no VPN access)
    ReadOnly,
    /// Custom role with specific permissions
    Custom(String),
}

/// VPN User
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Unique user ID
    pub id: UserId,
    /// Email address
    pub email: Option<String>,
    /// Display name
    pub name: Option<String>,
    /// User role
    pub role: UserRole,
    /// Whether user is enabled
    pub enabled: bool,
    /// OAuth2 provider (if using OAuth2)
    pub oauth_provider: Option<String>,
    /// OAuth2 subject claim
    pub oauth_subject: Option<String>,
    /// Groups the user belongs to
    pub groups: Vec<String>,
    /// Static VPN IP (if configured)
    pub static_ip: Option<crate::VpnAddress>,
    /// Custom routes for this user
    pub custom_routes: Vec<crate::Route>,
    /// Maximum concurrent sessions
    pub max_sessions: u32,
    /// User creation time
    pub created_at: DateTime<Utc>,
    /// Last login time
    pub last_login: Option<DateTime<Utc>>,
    /// Account expiration (if set)
    pub expires_at: Option<DateTime<Utc>>,
    /// Additional metadata
    pub metadata: std::collections::HashMap<String, String>,
}

impl User {
    /// Create a new user
    pub fn new(id: UserId) -> Self {
        Self {
            id,
            email: None,
            name: None,
            role: UserRole::default(),
            enabled: true,
            oauth_provider: None,
            oauth_subject: None,
            groups: vec![],
            static_ip: None,
            custom_routes: vec![],
            max_sessions: 3,
            created_at: Utc::now(),
            last_login: None,
            expires_at: None,
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Create from OAuth2 claims
    pub fn from_oauth(
        provider: &str,
        subject: &str,
        email: Option<&str>,
        name: Option<&str>,
        groups: Vec<String>,
    ) -> Self {
        let id = email
            .map(UserId::from_email)
            .unwrap_or_else(|| UserId::new(format!("{}:{}", provider, subject)));

        Self {
            id,
            email: email.map(String::from),
            name: name.map(String::from),
            role: UserRole::User,
            enabled: true,
            oauth_provider: Some(provider.to_string()),
            oauth_subject: Some(subject.to_string()),
            groups,
            static_ip: None,
            custom_routes: vec![],
            max_sessions: 3,
            created_at: Utc::now(),
            last_login: Some(Utc::now()),
            expires_at: None,
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Check if user is expired
    pub fn is_expired(&self) -> bool {
        self.expires_at.map(|exp| Utc::now() > exp).unwrap_or(false)
    }

    /// Check if user can connect
    pub fn can_connect(&self) -> bool {
        self.enabled && !self.is_expired()
    }

    /// Check if user is in a specific group
    pub fn in_group(&self, group: &str) -> bool {
        self.groups.iter().any(|g| g == group)
    }

    /// Check if user has admin role
    pub fn is_admin(&self) -> bool {
        matches!(self.role, UserRole::Admin)
    }

    /// Record login
    pub fn record_login(&mut self) {
        self.last_login = Some(Utc::now());
    }

    /// Set email
    pub fn with_email(mut self, email: &str) -> Self {
        self.email = Some(email.to_string());
        self
    }

    /// Set name
    pub fn with_name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }

    /// Set role
    pub fn with_role(mut self, role: UserRole) -> Self {
        self.role = role;
        self
    }

    /// Add to group
    pub fn add_group(&mut self, group: &str) {
        if !self.in_group(group) {
            self.groups.push(group.to_string());
        }
    }

    /// Remove from group
    pub fn remove_group(&mut self, group: &str) {
        self.groups.retain(|g| g != group);
    }
}

/// User store trait for different backends
#[async_trait::async_trait]
pub trait UserStore: Send + Sync {
    /// Get user by ID
    async fn get_user(&self, id: &UserId) -> Option<User>;

    /// Get user by email
    async fn get_user_by_email(&self, email: &str) -> Option<User>;

    /// Get user by OAuth2 subject
    async fn get_user_by_oauth(&self, provider: &str, subject: &str) -> Option<User>;

    /// Create or update user
    async fn upsert_user(&self, user: &User) -> crate::Result<()>;

    /// Delete user
    async fn delete_user(&self, id: &UserId) -> crate::Result<()>;

    /// List all users
    async fn list_users(&self) -> Vec<User>;

    /// Get users in a group
    async fn get_users_in_group(&self, group: &str) -> Vec<User>;
}

/// In-memory user store (for testing/simple deployments)
pub struct MemoryUserStore {
    users: parking_lot::RwLock<std::collections::HashMap<UserId, User>>,
}

impl MemoryUserStore {
    /// Create a new in-memory user store
    pub fn new() -> Self {
        Self {
            users: parking_lot::RwLock::new(std::collections::HashMap::new()),
        }
    }
}

impl Default for MemoryUserStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl UserStore for MemoryUserStore {
    async fn get_user(&self, id: &UserId) -> Option<User> {
        self.users.read().get(id).cloned()
    }

    async fn get_user_by_email(&self, email: &str) -> Option<User> {
        let email_lower = email.to_lowercase();
        self.users
            .read()
            .values()
            .find(|u| u.email.as_ref().map(|e| e.to_lowercase()) == Some(email_lower.clone()))
            .cloned()
    }

    async fn get_user_by_oauth(&self, provider: &str, subject: &str) -> Option<User> {
        self.users
            .read()
            .values()
            .find(|u| {
                u.oauth_provider.as_deref() == Some(provider)
                    && u.oauth_subject.as_deref() == Some(subject)
            })
            .cloned()
    }

    async fn upsert_user(&self, user: &User) -> crate::Result<()> {
        self.users.write().insert(user.id.clone(), user.clone());
        Ok(())
    }

    async fn delete_user(&self, id: &UserId) -> crate::Result<()> {
        self.users.write().remove(id);
        Ok(())
    }

    async fn list_users(&self) -> Vec<User> {
        self.users.read().values().cloned().collect()
    }

    async fn get_users_in_group(&self, group: &str) -> Vec<User> {
        self.users
            .read()
            .values()
            .filter(|u| u.in_group(group))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_creation() {
        let user = User::new(UserId::from_email("test@example.com"))
            .with_email("test@example.com")
            .with_name("Test User")
            .with_role(UserRole::Admin);

        assert!(user.is_admin());
        assert!(user.can_connect());
        assert_eq!(user.email, Some("test@example.com".to_string()));
    }

    #[test]
    fn test_user_groups() {
        let mut user = User::new(UserId::new("test"));

        user.add_group("developers");
        user.add_group("vpn-users");

        assert!(user.in_group("developers"));
        assert!(user.in_group("vpn-users"));
        assert!(!user.in_group("admins"));

        user.remove_group("developers");
        assert!(!user.in_group("developers"));
    }

    #[tokio::test]
    async fn test_memory_user_store() {
        let store = MemoryUserStore::new();

        let user = User::new(UserId::from_email("test@example.com")).with_email("test@example.com");

        store.upsert_user(&user).await.unwrap();

        let found = store.get_user_by_email("test@example.com").await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, user.id);
    }
}
