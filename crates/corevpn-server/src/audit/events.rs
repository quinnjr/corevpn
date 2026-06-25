//! Audit Event Types and Builders

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Audit event severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditSeverity {
    /// Informational event
    Info,
    /// Low severity - notable but not concerning
    Low,
    /// Medium severity - requires attention
    Medium,
    /// High severity - potential security issue
    High,
    /// Critical severity - immediate action required
    Critical,
}

impl AuditSeverity {
    /// Convert to syslog severity level
    pub fn to_syslog_severity(&self) -> u8 {
        match self {
            AuditSeverity::Info => 6,     // Informational
            AuditSeverity::Low => 5,      // Notice
            AuditSeverity::Medium => 4,   // Warning
            AuditSeverity::High => 3,     // Error
            AuditSeverity::Critical => 2, // Critical
        }
    }

    /// Convert to CEF severity (0-10)
    pub fn to_cef_severity(&self) -> u8 {
        match self {
            AuditSeverity::Info => 1,
            AuditSeverity::Low => 3,
            AuditSeverity::Medium => 5,
            AuditSeverity::High => 7,
            AuditSeverity::Critical => 10,
        }
    }
}

/// Audit event categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditCategory {
    /// Authentication events (login, logout, MFA)
    Authentication,
    /// Authorization events (access granted/denied)
    Authorization,
    /// Connection events (connect, disconnect, reconnect)
    Connection,
    /// Configuration changes
    Configuration,
    /// Security events (attacks, anomalies)
    Security,
    /// Administrative actions
    Administrative,
    /// Certificate operations
    Certificate,
    /// Network events
    Network,
    /// System events
    System,
}

impl AuditCategory {
    /// Get the category name for logging
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditCategory::Authentication => "authentication",
            AuditCategory::Authorization => "authorization",
            AuditCategory::Connection => "connection",
            AuditCategory::Configuration => "configuration",
            AuditCategory::Security => "security",
            AuditCategory::Administrative => "administrative",
            AuditCategory::Certificate => "certificate",
            AuditCategory::Network => "network",
            AuditCategory::System => "system",
        }
    }
}

/// Outcome of an audited action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditOutcome {
    Success,
    Failure,
    Unknown,
}

/// Actor who performed the action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditActor {
    /// Actor type (user, system, service)
    #[serde(rename = "type")]
    pub actor_type: String,

    /// Actor identifier
    pub id: Option<String>,

    /// Actor name/username
    pub name: Option<String>,

    /// Actor email
    pub email: Option<String>,

    /// Source IP address
    pub source_ip: Option<String>,

    /// User agent or client info
    pub user_agent: Option<String>,

    /// Session ID
    pub session_id: Option<String>,

    /// Authentication method used
    pub auth_method: Option<String>,
}

/// Target of the audited action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTarget {
    /// Target type (resource, user, configuration)
    #[serde(rename = "type")]
    pub target_type: String,

    /// Target identifier
    pub id: Option<String>,

    /// Target name
    pub name: Option<String>,

    /// Additional target attributes
    #[serde(flatten)]
    pub attributes: HashMap<String, serde_json::Value>,
}

/// A complete audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event ID
    pub id: String,

    /// Event timestamp
    pub timestamp: DateTime<Utc>,

    /// Event version for schema compatibility
    pub version: String,

    /// Event category
    pub category: AuditCategory,

    /// Event type/action
    pub action: String,

    /// Event severity
    pub severity: AuditSeverity,

    /// Event outcome
    pub outcome: AuditOutcome,

    /// Human-readable message
    pub message: String,

    /// Actor who performed the action
    pub actor: Option<AuditActor>,

    /// Target of the action
    pub target: Option<AuditTarget>,

    /// Service/application name
    pub service: String,

    /// Server hostname
    pub host: String,

    /// Additional event data
    #[serde(default)]
    pub data: HashMap<String, serde_json::Value>,

    /// Tags for filtering
    #[serde(default)]
    pub tags: Vec<String>,

    /// Error details if outcome is failure
    pub error: Option<AuditError>,

    /// Duration of the action in milliseconds
    pub duration_ms: Option<u64>,

    /// Request ID for correlation
    pub request_id: Option<String>,

    /// Trace ID for distributed tracing
    pub trace_id: Option<String>,
}

/// Error details for failed actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditError {
    /// Error code
    pub code: String,

    /// Error message
    pub message: String,

    /// Additional error details
    #[serde(default)]
    pub details: HashMap<String, serde_json::Value>,
}

/// Builder for creating audit events
pub struct AuditEventBuilder {
    category: AuditCategory,
    action: Option<String>,
    severity: AuditSeverity,
    outcome: AuditOutcome,
    message: Option<String>,
    actor: Option<AuditActor>,
    target: Option<AuditTarget>,
    data: HashMap<String, serde_json::Value>,
    tags: Vec<String>,
    error: Option<AuditError>,
    duration_ms: Option<u64>,
    request_id: Option<String>,
    trace_id: Option<String>,
}

impl AuditEventBuilder {
    /// Create a new audit event builder
    pub fn new(category: AuditCategory) -> Self {
        Self {
            category,
            action: None,
            severity: AuditSeverity::Info,
            outcome: AuditOutcome::Success,
            message: None,
            actor: None,
            target: None,
            data: HashMap::new(),
            tags: Vec::new(),
            error: None,
            duration_ms: None,
            request_id: None,
            trace_id: None,
        }
    }

    /// Set the action type
    pub fn action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    /// Set the severity
    pub fn severity(mut self, severity: AuditSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Set the outcome
    pub fn outcome(mut self, outcome: AuditOutcome) -> Self {
        self.outcome = outcome;
        self
    }

    /// Mark as success
    pub fn success(mut self) -> Self {
        self.outcome = AuditOutcome::Success;
        self
    }

    /// Mark as failure with error details
    pub fn failure(mut self, code: impl Into<String>, message: impl Into<String>) -> Self {
        self.outcome = AuditOutcome::Failure;
        self.error = Some(AuditError {
            code: code.into(),
            message: message.into(),
            details: HashMap::new(),
        });
        self
    }

    /// Set the message
    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// Set the actor
    pub fn actor(mut self, actor: AuditActor) -> Self {
        self.actor = Some(actor);
        self
    }

    /// Set actor from username and IP
    pub fn actor_user(mut self, username: impl Into<String>, source_ip: Option<String>) -> Self {
        self.actor = Some(AuditActor {
            actor_type: "user".to_string(),
            id: None,
            name: Some(username.into()),
            email: None,
            source_ip,
            user_agent: None,
            session_id: None,
            auth_method: None,
        });
        self
    }

    /// Set actor as system
    pub fn actor_system(mut self) -> Self {
        self.actor = Some(AuditActor {
            actor_type: "system".to_string(),
            id: None,
            name: Some("corevpn-server".to_string()),
            email: None,
            source_ip: None,
            user_agent: None,
            session_id: None,
            auth_method: None,
        });
        self
    }

    /// Set the target
    pub fn target(mut self, target: AuditTarget) -> Self {
        self.target = Some(target);
        self
    }

    /// Set target with type and ID
    pub fn target_resource(
        mut self,
        target_type: impl Into<String>,
        id: impl Into<String>,
    ) -> Self {
        self.target = Some(AuditTarget {
            target_type: target_type.into(),
            id: Some(id.into()),
            name: None,
            attributes: HashMap::new(),
        });
        self
    }

    /// Add custom data field
    pub fn data(mut self, key: impl Into<String>, value: impl Serialize) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            self.data.insert(key.into(), v);
        }
        self
    }

    /// Add a tag
    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Add multiple tags
    pub fn tags(mut self, tags: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.tags.extend(tags.into_iter().map(Into::into));
        self
    }

    /// Set the duration
    pub fn duration_ms(mut self, duration: u64) -> Self {
        self.duration_ms = Some(duration);
        self
    }

    /// Set the request ID
    pub fn request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    /// Set the trace ID
    pub fn trace_id(mut self, id: impl Into<String>) -> Self {
        self.trace_id = Some(id.into());
        self
    }

    /// Build the audit event
    pub fn build(self) -> AuditEvent {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        AuditEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            version: "1.0".to_string(),
            category: self.category,
            action: self.action.unwrap_or_else(|| "unknown".to_string()),
            severity: self.severity,
            outcome: self.outcome,
            message: self.message.unwrap_or_default(),
            actor: self.actor,
            target: self.target,
            service: "corevpn".to_string(),
            host: hostname,
            data: self.data,
            tags: self.tags,
            error: self.error,
            duration_ms: self.duration_ms,
            request_id: self.request_id,
            trace_id: self.trace_id,
        }
    }
}

// Predefined event builders for common scenarios
impl AuditEventBuilder {
    /// Authentication attempt event
    pub fn auth_attempt(username: &str, source_ip: Option<String>) -> Self {
        Self::new(AuditCategory::Authentication)
            .action("auth.attempt")
            .actor_user(username, source_ip)
            .message(format!("Authentication attempt for user: {}", username))
    }

    /// Authentication success event
    pub fn auth_success(username: &str, source_ip: Option<String>, method: &str) -> Self {
        Self::new(AuditCategory::Authentication)
            .action("auth.success")
            .actor_user(username, source_ip.clone())
            .message(format!(
                "User {} authenticated successfully via {}",
                username, method
            ))
            .data("auth_method", method)
    }

    /// Authentication failure event
    pub fn auth_failure(username: &str, source_ip: Option<String>, reason: &str) -> Self {
        Self::new(AuditCategory::Authentication)
            .action("auth.failure")
            .severity(AuditSeverity::Medium)
            .actor_user(username, source_ip)
            .failure("AUTH_FAILED", reason)
            .message(format!(
                "Authentication failed for user {}: {}",
                username, reason
            ))
    }

    /// VPN connection established
    pub fn vpn_connect(username: &str, source_ip: &str, assigned_ip: &str) -> Self {
        Self::new(AuditCategory::Connection)
            .action("vpn.connect")
            .actor_user(username, Some(source_ip.to_string()))
            .message(format!("VPN connection established for {}", username))
            .data("assigned_ip", assigned_ip)
            .data("source_ip", source_ip)
    }

    /// VPN connection terminated
    pub fn vpn_disconnect(
        username: &str,
        source_ip: &str,
        reason: &str,
        duration_secs: u64,
    ) -> Self {
        Self::new(AuditCategory::Connection)
            .action("vpn.disconnect")
            .actor_user(username, Some(source_ip.to_string()))
            .message(format!(
                "VPN connection terminated for {}: {}",
                username, reason
            ))
            .data("disconnect_reason", reason)
            .data("session_duration_secs", duration_secs)
    }

    /// Configuration change
    pub fn config_change(admin: &str, setting: &str, old_value: &str, new_value: &str) -> Self {
        Self::new(AuditCategory::Configuration)
            .action("config.change")
            .severity(AuditSeverity::Medium)
            .actor_user(admin, None)
            .target_resource("configuration", setting)
            .message(format!("Configuration changed: {} by {}", setting, admin))
            .data("old_value", old_value)
            .data("new_value", new_value)
    }

    /// Security alert
    pub fn security_alert(alert_type: &str, description: &str, source_ip: Option<String>) -> Self {
        Self::new(AuditCategory::Security)
            .action(format!("security.{}", alert_type))
            .severity(AuditSeverity::High)
            .message(description.to_string())
            .data("alert_type", alert_type)
            .data("source_ip", source_ip.unwrap_or_default())
    }

    /// Client certificate issued
    pub fn cert_issued(admin: &str, client_name: &str, expires_at: &str) -> Self {
        Self::new(AuditCategory::Certificate)
            .action("cert.issued")
            .actor_user(admin, None)
            .target_resource("certificate", client_name)
            .message(format!("Certificate issued for client: {}", client_name))
            .data("expires_at", expires_at)
    }

    /// Client certificate revoked
    pub fn cert_revoked(admin: &str, client_name: &str, reason: &str) -> Self {
        Self::new(AuditCategory::Certificate)
            .action("cert.revoked")
            .severity(AuditSeverity::Medium)
            .actor_user(admin, None)
            .target_resource("certificate", client_name)
            .message(format!("Certificate revoked for client: {}", client_name))
            .data("revocation_reason", reason)
    }
}
