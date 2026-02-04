//! Server Configuration

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use ipnet::{Ipv4Net, Ipv6Net};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{ConfigError, Result};

/// Main server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server settings
    pub server: ServerSettings,
    /// Network settings
    pub network: NetworkSettings,
    /// Security settings
    pub security: SecuritySettings,
    /// OAuth2 settings
    #[serde(default)]
    pub oauth: Option<OAuthSettings>,
    /// Logging settings
    #[serde(default)]
    pub logging: LoggingSettings,
    /// Admin API settings
    #[serde(default)]
    pub admin: AdminSettings,
    /// Audit logging settings (SIEM/cloud integration)
    #[serde(default)]
    pub audit: AuditSettings,
}

/// Server network settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    /// Listen address for VPN (UDP)
    #[serde(default = "default_listen_addr")]
    pub listen_addr: SocketAddr,
    /// Listen address for TCP (optional fallback)
    #[serde(default)]
    pub tcp_listen_addr: Option<SocketAddr>,
    /// Public hostname/IP for client configs
    pub public_host: String,
    /// Protocol (udp, tcp, or both)
    #[serde(default = "default_protocol")]
    pub protocol: String,
    /// Maximum concurrent clients
    #[serde(default = "default_max_clients")]
    pub max_clients: u32,
    /// Data directory
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
}

fn default_listen_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1194)
}

fn default_protocol() -> String {
    "udp".to_string()
}

fn default_max_clients() -> u32 {
    1000
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/corevpn")
}

/// Network settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSettings {
    /// VPN subnet (e.g., "10.8.0.0/24")
    #[serde(default = "default_subnet")]
    pub subnet: String,
    /// IPv6 subnet (optional)
    #[serde(default)]
    pub subnet_v6: Option<String>,
    /// DNS servers to push to clients
    #[serde(default = "default_dns")]
    pub dns: Vec<String>,
    /// Search domains
    #[serde(default)]
    pub dns_search: Vec<String>,
    /// Routes to push to clients
    #[serde(default)]
    pub push_routes: Vec<String>,
    /// Enable redirect-gateway (full tunnel)
    #[serde(default = "default_redirect_gateway")]
    pub redirect_gateway: bool,
    /// MTU setting
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

fn default_subnet() -> String {
    "10.8.0.0/24".to_string()
}

fn default_dns() -> Vec<String> {
    vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()]
}

fn default_redirect_gateway() -> bool {
    true
}

fn default_mtu() -> u16 {
    1420
}

/// Security settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySettings {
    /// Cipher suite (chacha20-poly1305 or aes-256-gcm)
    #[serde(default = "default_cipher")]
    pub cipher: String,
    /// TLS minimum version (1.3)
    #[serde(default = "default_tls_version")]
    pub tls_min_version: String,
    /// Enable tls-auth
    #[serde(default = "default_true")]
    pub tls_auth: bool,
    /// Enable tls-crypt (stronger than tls-auth)
    #[serde(default)]
    pub tls_crypt: bool,
    /// Certificate lifetime in days
    #[serde(default = "default_cert_lifetime")]
    pub cert_lifetime_days: u32,
    /// Client certificate lifetime in days
    #[serde(default = "default_client_cert_lifetime")]
    pub client_cert_lifetime_days: u32,
    /// Renegotiation interval in seconds
    #[serde(default = "default_reneg_sec")]
    pub reneg_sec: u32,
    /// Enable perfect forward secrecy
    #[serde(default = "default_true")]
    pub pfs: bool,
}

fn default_cipher() -> String {
    "chacha20-poly1305".to_string()
}

fn default_tls_version() -> String {
    "1.3".to_string()
}

fn default_true() -> bool {
    true
}

fn default_cert_lifetime() -> u32 {
    3650 // 10 years for CA
}

fn default_client_cert_lifetime() -> u32 {
    90 // 90 days for clients
}

fn default_reneg_sec() -> u32 {
    3600 // 1 hour
}

/// OAuth2 settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthSettings {
    /// Enable OAuth2 authentication
    #[serde(default)]
    pub enabled: bool,
    /// Provider type (google, microsoft, okta, generic)
    pub provider: String,
    /// Client ID
    pub client_id: String,
    /// Client secret (will be encrypted at rest)
    #[serde(skip_serializing, deserialize_with = "deserialize_secret_string")]
    pub client_secret: SecretString,
    /// Issuer URL (for generic OIDC)
    #[serde(default)]
    pub issuer_url: Option<String>,
    /// Tenant ID (for Microsoft)
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Domain (for Okta)
    #[serde(default)]
    pub domain: Option<String>,
    /// Allowed email domains
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// Required groups (user must be in at least one)
    #[serde(default)]
    pub required_groups: Vec<String>,
}

/// Connection logging mode
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionLogMode {
    /// No connection logging at all - ghost mode, leaves no trace
    /// This disables ALL connection tracking including memory-only tracking
    None,
    /// Memory only - connections tracked but never persisted to disk/db
    /// Useful for real-time monitoring without evidence
    #[default]
    Memory,
    /// Log connections to a file (append mode)
    File,
    /// Log connections to SQLite database
    Database,
    /// Log to both file and database
    Both,
}

/// What connection events to log
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConnectionLogEvents {
    /// Log connection attempts (before authentication)
    #[serde(default)]
    pub attempts: bool,
    /// Log successful connections
    #[serde(default = "default_true")]
    pub connects: bool,
    /// Log disconnections
    #[serde(default = "default_true")]
    pub disconnects: bool,
    /// Log authentication events (success/failure)
    #[serde(default)]
    pub auth_events: bool,
    /// Log data transfer statistics on disconnect
    #[serde(default)]
    pub transfer_stats: bool,
    /// Log IP address changes (reconnects from different IP)
    #[serde(default)]
    pub ip_changes: bool,
    /// Log key renegotiations
    #[serde(default)]
    pub renegotiations: bool,
}

/// Connection log anonymization settings
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConnectionLogAnonymization {
    /// Hash client IP addresses instead of storing them plain
    /// Uses HMAC-SHA256 with a daily rotating salt for unlinkability
    #[serde(default)]
    pub hash_client_ips: bool,
    /// Truncate client IPs to /24 (IPv4) or /48 (IPv6) for reduced precision
    #[serde(default)]
    pub truncate_client_ips: bool,
    /// Don't log usernames, only hashed identifiers
    #[serde(default)]
    pub hash_usernames: bool,
    /// Round timestamps to nearest hour to reduce precision
    #[serde(default)]
    pub round_timestamps: bool,
    /// Aggregate transfer stats into buckets instead of exact bytes
    #[serde(default)]
    pub aggregate_transfer_stats: bool,
}

/// Connection log retention settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionLogRetention {
    /// Days to retain connection logs (0 = forever, but not recommended)
    #[serde(default = "default_retention_days")]
    pub days: u32,
    /// Maximum log file size in MB before rotation (file mode only)
    #[serde(default = "default_max_log_size_mb")]
    pub max_file_size_mb: u32,
    /// Number of rotated log files to keep
    #[serde(default = "default_max_log_files")]
    pub max_files: u32,
    /// Automatically purge logs older than retention period
    #[serde(default = "default_true")]
    pub auto_purge: bool,
    /// Secure deletion (overwrite before delete) - slower but more secure
    #[serde(default)]
    pub secure_delete: bool,
}

fn default_retention_days() -> u32 {
    7 // 1 week default
}

fn default_max_log_size_mb() -> u32 {
    100 // 100MB
}

fn default_max_log_files() -> u32 {
    5
}

impl Default for ConnectionLogRetention {
    fn default() -> Self {
        Self {
            days: default_retention_days(),
            max_file_size_mb: default_max_log_size_mb(),
            max_files: default_max_log_files(),
            auto_purge: true,
            secure_delete: false,
        }
    }
}

/// Logging settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingSettings {
    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Log format (json or pretty)
    #[serde(default = "default_log_format")]
    pub format: String,
    /// Log file path for application logs (none for stdout)
    #[serde(default)]
    pub file: Option<PathBuf>,

    // === Connection Logging Settings ===

    /// Connection logging mode
    /// Set to "none" for complete ghost mode - no connection logging at all
    #[serde(default)]
    pub connection_mode: ConnectionLogMode,
    /// Path for connection log file (when mode is "file" or "both")
    #[serde(default)]
    pub connection_log_file: Option<PathBuf>,
    /// Path for connection log database (when mode is "database" or "both")
    #[serde(default)]
    pub connection_log_db: Option<PathBuf>,
    /// Which events to log
    #[serde(default)]
    pub connection_events: ConnectionLogEvents,
    /// Anonymization settings for logged data
    #[serde(default)]
    pub anonymization: ConnectionLogAnonymization,
    /// Retention settings
    #[serde(default)]
    pub retention: ConnectionLogRetention,

    // Legacy field for backwards compatibility
    /// Enable connection logging (DEPRECATED: use connection_mode instead)
    #[serde(default = "default_true")]
    #[deprecated(note = "Use connection_mode instead")]
    pub log_connections: bool,
}

impl Default for LoggingSettings {
    fn default() -> Self {
        #[allow(deprecated)]
        Self {
            level: default_log_level(),
            format: default_log_format(),
            file: None,
            connection_mode: ConnectionLogMode::default(),
            connection_log_file: None,
            connection_log_db: None,
            connection_events: ConnectionLogEvents::default(),
            anonymization: ConnectionLogAnonymization::default(),
            retention: ConnectionLogRetention::default(),
            log_connections: true,
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "pretty".to_string()
}

/// Admin API settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminSettings {
    /// Enable admin API
    #[serde(default)]
    pub enabled: bool,
    /// Listen address for admin API
    #[serde(default = "default_admin_addr")]
    pub listen_addr: SocketAddr,
    /// API key (auto-generated if not set)
    #[serde(skip_serializing, deserialize_with = "deserialize_optional_secret_string")]
    pub api_key: Option<SecretString>,
    /// Allowed IP addresses
    #[serde(default)]
    pub allowed_ips: Vec<String>,
}

fn default_admin_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8443)
}

impl Default for AdminSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: default_admin_addr(),
            api_key: None,
            allowed_ips: vec!["127.0.0.1".to_string()],
        }
    }
}

/// Audit logging settings for SIEM and cloud services
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSettings {
    /// Enable audit logging
    #[serde(default)]
    pub enabled: bool,

    /// Event buffer size
    #[serde(default = "default_audit_buffer")]
    pub buffer_size: usize,

    /// Include source IP in audit events
    #[serde(default = "default_true")]
    pub include_source_ip: bool,

    /// Include user identity in audit events
    #[serde(default = "default_true")]
    pub include_user_identity: bool,

    /// Hash sensitive fields for privacy
    #[serde(default)]
    pub hash_sensitive_fields: bool,

    /// Audit sinks configuration (inline TOML)
    #[serde(default)]
    pub sinks: Vec<AuditSinkConfig>,
}

fn default_audit_buffer() -> usize { 10000 }

impl Default for AuditSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            buffer_size: 10000,
            include_source_ip: true,
            include_user_identity: true,
            hash_sensitive_fields: false,
            sinks: Vec::new(),
        }
    }
}

/// Configuration for a single audit sink
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditSinkConfig {
    /// AWS CloudWatch Logs
    AwsCloudwatch {
        region: String,
        log_group: String,
        #[serde(default = "default_cloudwatch_stream")]
        log_stream: String,
        #[serde(default)]
        profile: Option<String>,
        #[serde(default)]
        role_arn: Option<String>,
    },

    /// AWS S3 bucket
    AwsS3 {
        region: String,
        bucket: String,
        #[serde(default = "default_s3_prefix")]
        prefix: String,
        #[serde(default)]
        profile: Option<String>,
    },

    /// AWS Security Hub
    AwsSecurityHub {
        region: String,
        account_id: String,
        #[serde(default)]
        profile: Option<String>,
    },

    /// AWS EventBridge
    AwsEventBridge {
        region: String,
        #[serde(default = "default_event_bus")]
        event_bus: String,
        #[serde(default)]
        profile: Option<String>,
    },

    /// Azure Monitor / Log Analytics
    AzureMonitor {
        workspace_id: String,
        shared_key: String,
        #[serde(default = "default_azure_log_type")]
        log_type: String,
    },

    /// Azure Event Hub
    AzureEventHub {
        namespace: String,
        event_hub: String,
        policy_name: String,
        policy_key: String,
    },

    /// Azure Sentinel (via Log Analytics)
    AzureSentinel {
        workspace_id: String,
        shared_key: String,
        #[serde(default = "default_sentinel_log_type")]
        log_type: String,
    },

    /// Oracle Cloud Logging
    OracleLogging {
        region: String,
        log_id: String,
        tenancy_id: String,
        user_id: String,
        fingerprint: String,
        private_key: String,
    },

    /// Oracle Cloud Streaming
    OracleStreaming {
        region: String,
        stream_id: String,
        tenancy_id: String,
        user_id: String,
        fingerprint: String,
        private_key: String,
    },

    /// Elasticsearch
    Elasticsearch {
        urls: Vec<String>,
        #[serde(default = "default_es_index")]
        index: String,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
        #[serde(default)]
        api_key: Option<String>,
    },

    /// Splunk HEC
    Splunk {
        url: String,
        token: String,
        #[serde(default = "default_splunk_sourcetype")]
        sourcetype: String,
        #[serde(default)]
        index: Option<String>,
    },

    /// Kafka
    Kafka {
        brokers: Vec<String>,
        topic: String,
        #[serde(default)]
        sasl_username: Option<String>,
        #[serde(default)]
        sasl_password: Option<String>,
    },

    /// Syslog (TCP/UDP/TLS)
    Syslog {
        address: String,
        #[serde(default = "default_syslog_port")]
        port: u16,
        #[serde(default = "default_syslog_protocol")]
        protocol: String,
        #[serde(default)]
        use_cef: bool,
        #[serde(default)]
        use_leef: bool,
    },

    /// HTTP Webhook
    Webhook {
        url: String,
        #[serde(default)]
        headers: std::collections::HashMap<String, String>,
        #[serde(default)]
        bearer_token: Option<String>,
        #[serde(default)]
        api_key_header: Option<String>,
        #[serde(default)]
        api_key_value: Option<String>,
    },

    /// Local file
    File {
        path: String,
        #[serde(default = "default_audit_format")]
        format: String,
        #[serde(default = "default_max_size")]
        max_size_mb: u64,
        #[serde(default = "default_max_files")]
        max_files: u32,
    },
}

fn default_cloudwatch_stream() -> String { "corevpn-audit-{date}".to_string() }
fn default_s3_prefix() -> String { "audit-logs/{date}/{hour}/".to_string() }
fn default_event_bus() -> String { "default".to_string() }
fn default_azure_log_type() -> String { "CoreVPNAudit".to_string() }
fn default_sentinel_log_type() -> String { "CoreVPNSecurity".to_string() }
fn default_es_index() -> String { "corevpn-audit-{date}".to_string() }
fn default_splunk_sourcetype() -> String { "corevpn:audit".to_string() }
fn default_syslog_port() -> u16 { 514 }
fn default_syslog_protocol() -> String { "udp".to_string() }
fn default_audit_format() -> String { "json".to_string() }
fn default_max_size() -> u64 { 100 }
fn default_max_files() -> u32 { 10 }

impl ServerConfig {
    /// Create a default configuration
    pub fn default_config(public_host: &str) -> Self {
        Self {
            server: ServerSettings {
                listen_addr: default_listen_addr(),
                tcp_listen_addr: None,
                public_host: public_host.to_string(),
                protocol: default_protocol(),
                max_clients: default_max_clients(),
                data_dir: default_data_dir(),
            },
            network: NetworkSettings {
                subnet: default_subnet(),
                subnet_v6: None,
                dns: default_dns(),
                dns_search: vec![],
                push_routes: vec![],
                redirect_gateway: default_redirect_gateway(),
                mtu: default_mtu(),
            },
            security: SecuritySettings {
                cipher: default_cipher(),
                tls_min_version: default_tls_version(),
                tls_auth: true,
                tls_crypt: false,
                cert_lifetime_days: default_cert_lifetime(),
                client_cert_lifetime_days: default_client_cert_lifetime(),
                reneg_sec: default_reneg_sec(),
                pfs: true,
            },
            oauth: None,
            logging: LoggingSettings::default(),
            admin: AdminSettings::default(),
            audit: AuditSettings::default(),
        }
    }

    /// Load from TOML file
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Save to TOML file
    pub fn save(&self, path: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Validate hostname or IP address
    fn validate_hostname_or_ip(host: &str) -> Result<()> {
        // Try parsing as IP address first
        if host.parse::<IpAddr>().is_ok() {
            return Ok(());
        }

        // Validate as hostname
        // Basic hostname validation: must not be empty, reasonable length, valid characters
        if host.is_empty() {
            return Err(ConfigError::ValidationError("Hostname cannot be empty".into()));
        }

        if host.len() > 253 {
            return Err(ConfigError::ValidationError(
                "Hostname exceeds maximum length (253 characters)".into(),
            ));
        }

        // Check for valid hostname characters (letters, digits, hyphens, dots)
        // Must start and end with alphanumeric
        if !host.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '.') {
            return Err(ConfigError::ValidationError(
                "Hostname contains invalid characters".into(),
            ));
        }

        if host.starts_with('.') || host.ends_with('.') {
            return Err(ConfigError::ValidationError(
                "Hostname cannot start or end with a dot".into(),
            ));
        }

        if host.starts_with('-') || host.ends_with('-') {
            return Err(ConfigError::ValidationError(
                "Hostname cannot start or end with a hyphen".into(),
            ));
        }

        // Check for consecutive dots
        if host.contains("..") {
            return Err(ConfigError::ValidationError(
                "Hostname cannot contain consecutive dots".into(),
            ));
        }

        // Each label (between dots) must be 1-63 characters
        for label in host.split('.') {
            if label.is_empty() {
                return Err(ConfigError::ValidationError(
                    "Hostname labels cannot be empty".into(),
                ));
            }
            if label.len() > 63 {
                return Err(ConfigError::ValidationError(format!(
                    "Hostname label '{}' exceeds maximum length (63 characters)",
                    label
                )));
            }
        }

        Ok(())
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        if self.server.public_host.is_empty() {
            return Err(ConfigError::MissingField("server.public_host".into()));
        }

        // Validate hostname or IP address
        Self::validate_hostname_or_ip(&self.server.public_host)?;

        // Validate subnet
        self.network.subnet.parse::<Ipv4Net>()
            .map_err(|e| ConfigError::ValidationError(format!("invalid subnet: {}", e)))?;

        // Validate IPv6 subnet if provided
        if let Some(ref subnet_v6) = self.network.subnet_v6 {
            subnet_v6.parse::<ipnet::Ipv6Net>()
                .map_err(|e| ConfigError::ValidationError(format!("invalid IPv6 subnet: {}", e)))?;
        }

        // Validate DNS servers
        for (idx, dns) in self.network.dns.iter().enumerate() {
            dns.parse::<IpAddr>()
                .map_err(|e| ConfigError::ValidationError(format!(
                    "invalid DNS server #{} '{}': {}",
                    idx + 1, dns, e
                )))?;
        }

        // Validate DNS search domains
        for (idx, domain) in self.network.dns_search.iter().enumerate() {
            if domain.is_empty() {
                return Err(ConfigError::ValidationError(format!(
                    "DNS search domain #{} cannot be empty",
                    idx + 1
                )));
            }
            // Basic domain validation
            if domain.len() > 253 {
                return Err(ConfigError::ValidationError(format!(
                    "DNS search domain #{} exceeds maximum length (253 characters)",
                    idx + 1
                )));
            }
        }

        // Validate push routes
        for (idx, route) in self.network.push_routes.iter().enumerate() {
            let is_valid_ipv4 = route.parse::<Ipv4Net>().is_ok();
            let is_valid_ipv6 = route.parse::<Ipv6Net>().is_ok();
            if !is_valid_ipv4 && !is_valid_ipv6 {
                return Err(ConfigError::ValidationError(format!(
                    "invalid push route #{} '{}': must be valid IPv4 or IPv6 network",
                    idx + 1, route
                )));
            }
        }

        // Validate OAuth if enabled
        if let Some(oauth) = &self.oauth {
            if oauth.enabled {
                if oauth.client_id.is_empty() {
                    return Err(ConfigError::MissingField("oauth.client_id".into()));
                }
                if oauth.client_secret.expose_secret().is_empty() {
                    return Err(ConfigError::MissingField("oauth.client_secret".into()));
                }
            }
        }

        // Validate port ranges
        if self.server.listen_addr.port() == 0 {
            return Err(ConfigError::ValidationError(
                "Server listen port cannot be 0".into(),
            ));
        }
        if let Some(tcp_addr) = &self.server.tcp_listen_addr {
            if tcp_addr.port() == 0 {
                return Err(ConfigError::ValidationError(
                    "TCP listen port cannot be 0".into(),
                ));
            }
        }
        if self.admin.listen_addr.port() == 0 {
            return Err(ConfigError::ValidationError(
                "Admin API listen port cannot be 0".into(),
            ));
        }

        // Validate max_clients is reasonable
        if self.server.max_clients == 0 {
            return Err(ConfigError::ValidationError(
                "max_clients must be greater than 0".into(),
            ));
        }
        if self.server.max_clients > 100000 {
            return Err(ConfigError::ValidationError(
                "max_clients exceeds maximum allowed value (100000)".into(),
            ));
        }

        // Validate certificate lifetimes
        if self.security.cert_lifetime_days == 0 {
            return Err(ConfigError::ValidationError(
                "cert_lifetime_days must be greater than 0".into(),
            ));
        }
        if self.security.client_cert_lifetime_days == 0 {
            return Err(ConfigError::ValidationError(
                "client_cert_lifetime_days must be greater than 0".into(),
            ));
        }
        if self.security.client_cert_lifetime_days > self.security.cert_lifetime_days {
            return Err(ConfigError::ValidationError(
                "client_cert_lifetime_days cannot exceed cert_lifetime_days".into(),
            ));
        }

        // Validate renegotiation interval
        if self.security.reneg_sec == 0 {
            return Err(ConfigError::ValidationError(
                "reneg_sec must be greater than 0".into(),
            ));
        }

        // Validate MTU
        if self.network.mtu < 68 || self.network.mtu > 1500 {
            return Err(ConfigError::ValidationError(
                "MTU must be between 68 and 1500".into(),
            ));
        }

        Ok(())
    }

    /// Get the data directory path
    pub fn data_dir(&self) -> &Path {
        &self.server.data_dir
    }

    /// Get CA certificate path
    pub fn ca_cert_path(&self) -> PathBuf {
        self.server.data_dir.join("ca.crt")
    }

    /// Get CA key path
    pub fn ca_key_path(&self) -> PathBuf {
        self.server.data_dir.join("ca.key")
    }

    /// Get server certificate path
    pub fn server_cert_path(&self) -> PathBuf {
        self.server.data_dir.join("server.crt")
    }

    /// Get server key path
    pub fn server_key_path(&self) -> PathBuf {
        self.server.data_dir.join("server.key")
    }

    /// Get tls-auth key path
    pub fn ta_key_path(&self) -> PathBuf {
        self.server.data_dir.join("ta.key")
    }

    /// Get DH parameters path (for compatibility)
    pub fn dh_path(&self) -> PathBuf {
        self.server.data_dir.join("dh.pem")
    }
}

/// Deserialize a SecretString from a regular string
fn deserialize_secret_string<'de, D>(deserializer: D) -> std::result::Result<SecretString, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(SecretString::new(s))
}

/// Deserialize an Option<SecretString> from an Option<String>
fn deserialize_optional_secret_string<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<SecretString>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    Ok(opt.map(SecretString::new))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default_config("vpn.example.com");

        assert_eq!(config.server.public_host, "vpn.example.com");
        assert_eq!(config.network.subnet, "10.8.0.0/24");
        assert!(config.security.tls_auth);
    }

    #[test]
    fn test_config_validation() {
        let mut config = ServerConfig::default_config("vpn.example.com");
        assert!(config.validate().is_ok());

        config.server.public_host = String::new();
        assert!(config.validate().is_err());
    }
}
