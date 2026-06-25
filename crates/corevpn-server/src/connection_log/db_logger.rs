//! Database-Based Connection Logger
//!
//! Logs connection events to SQLite with full query support.
//! Supports automatic purging of old records.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use sqlx::Row;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use tracing::info;

use super::events::{
    AuthMethod, AuthResult, ConnectionEvent, ConnectionId, DisconnectReason, TransferStats,
};
use super::logger::{ConnectionLogger, LoggerStats};

/// SQLite-based connection logger
pub struct DatabaseConnectionLogger {
    /// Database connection pool
    pool: SqlitePool,
    /// Retention period in days
    retention_days: u32,
    /// Auto-purge enabled
    auto_purge: bool,
    /// Total events logged
    total_logged: AtomicU64,
    /// First event timestamp
    first_event: RwLock<Option<DateTime<Utc>>>,
    /// Last event timestamp
    last_event: RwLock<Option<DateTime<Utc>>>,
}

impl DatabaseConnectionLogger {
    pub async fn new(path: PathBuf, retention_days: u32, auto_purge: bool) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .context("Failed to create database directory")?;
        }

        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .context("Failed to connect to database")?;

        let logger = Self {
            pool,
            retention_days,
            auto_purge,
            total_logged: AtomicU64::new(0),
            first_event: RwLock::new(None),
            last_event: RwLock::new(None),
        };

        // Initialize schema
        logger.init_schema().await?;

        // Load stats
        logger.load_stats().await?;

        Ok(logger)
    }

    async fn init_schema(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS connection_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                connection_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                client_addr TEXT,
                username TEXT,
                vpn_ip TEXT,
                auth_method TEXT,
                auth_result TEXT,
                disconnect_reason TEXT,
                duration_secs INTEGER,
                bytes_rx INTEGER,
                bytes_tx INTEGER,
                packets_rx INTEGER,
                packets_tx INTEGER,
                old_addr TEXT,
                new_addr TEXT,
                success INTEGER,
                protocol_version TEXT,
                client_info TEXT,
                details TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_connection_id ON connection_events(connection_id);
            CREATE INDEX IF NOT EXISTS idx_timestamp ON connection_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_event_type ON connection_events(event_type);
            CREATE INDEX IF NOT EXISTS idx_username ON connection_events(username);
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create schema")?;

        Ok(())
    }

    async fn load_stats(&self) -> Result<()> {
        // Get count
        let row = sqlx::query("SELECT COUNT(*) as count FROM connection_events")
            .fetch_one(&self.pool)
            .await?;
        let count: i64 = row.get("count");
        self.total_logged.store(count as u64, Ordering::Relaxed);

        // Get first event
        let row = sqlx::query("SELECT MIN(timestamp) as ts FROM connection_events")
            .fetch_optional(&self.pool)
            .await?;
        if let Some(row) = row {
            if let Ok(ts) = row.try_get::<String, _>("ts") {
                if let Ok(dt) = DateTime::parse_from_rfc3339(&ts) {
                    *self.first_event.write() = Some(dt.with_timezone(&Utc));
                }
            }
        }

        // Get last event
        let row = sqlx::query("SELECT MAX(timestamp) as ts FROM connection_events")
            .fetch_optional(&self.pool)
            .await?;
        if let Some(row) = row {
            if let Ok(ts) = row.try_get::<String, _>("ts") {
                if let Ok(dt) = DateTime::parse_from_rfc3339(&ts) {
                    *self.last_event.write() = Some(dt.with_timezone(&Utc));
                }
            }
        }

        Ok(())
    }

    async fn insert_event(&self, event: &ConnectionEvent) -> Result<()> {
        match event {
            ConnectionEvent::ConnectionAttempt {
                connection_id,
                timestamp,
                client_addr,
                protocol_version,
            } => {
                sqlx::query(
                    r#"
                    INSERT INTO connection_events
                    (connection_id, event_type, timestamp, client_addr, protocol_version)
                    VALUES (?, 'connection_attempt', ?, ?, ?)
                    "#,
                )
                .bind(connection_id.to_string())
                .bind(timestamp.to_rfc3339())
                .bind(client_addr.to_string())
                .bind(protocol_version.as_deref())
                .execute(&self.pool)
                .await?;
            }
            ConnectionEvent::Authentication {
                connection_id,
                timestamp,
                client_addr,
                username,
                auth_method,
                result,
                details,
            } => {
                sqlx::query(
                    r#"
                    INSERT INTO connection_events
                    (connection_id, event_type, timestamp, client_addr, username, auth_method, auth_result, details)
                    VALUES (?, 'authentication', ?, ?, ?, ?, ?, ?)
                    "#,
                )
                .bind(connection_id.to_string())
                .bind(timestamp.to_rfc3339())
                .bind(client_addr.to_string())
                .bind(username.as_deref())
                .bind(format!("{:?}", auth_method))
                .bind(format!("{:?}", result))
                .bind(details.as_deref())
                .execute(&self.pool)
                .await?;
            }
            ConnectionEvent::Connected {
                connection_id,
                timestamp,
                client_addr,
                username,
                vpn_ip,
                auth_method,
                client_info,
            } => {
                sqlx::query(
                    r#"
                    INSERT INTO connection_events
                    (connection_id, event_type, timestamp, client_addr, username, vpn_ip, auth_method, client_info)
                    VALUES (?, 'connected', ?, ?, ?, ?, ?, ?)
                    "#,
                )
                .bind(connection_id.to_string())
                .bind(timestamp.to_rfc3339())
                .bind(client_addr.to_string())
                .bind(username.as_deref())
                .bind(vpn_ip.to_string())
                .bind(format!("{:?}", auth_method))
                .bind(client_info.as_deref())
                .execute(&self.pool)
                .await?;
            }
            ConnectionEvent::Disconnected {
                connection_id,
                timestamp,
                client_addr,
                username,
                reason,
                duration,
                stats,
            } => {
                let (bytes_rx, bytes_tx, packets_rx, packets_tx) = stats
                    .as_ref()
                    .map(|s| {
                        (
                            Some(s.bytes_rx as i64),
                            Some(s.bytes_tx as i64),
                            Some(s.packets_rx as i64),
                            Some(s.packets_tx as i64),
                        )
                    })
                    .unwrap_or((None, None, None, None));

                sqlx::query(
                    r#"
                    INSERT INTO connection_events
                    (connection_id, event_type, timestamp, client_addr, username, disconnect_reason,
                     duration_secs, bytes_rx, bytes_tx, packets_rx, packets_tx)
                    VALUES (?, 'disconnected', ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                )
                .bind(connection_id.to_string())
                .bind(timestamp.to_rfc3339())
                .bind(client_addr.to_string())
                .bind(username.as_deref())
                .bind(format!("{:?}", reason))
                .bind(duration.as_secs() as i64)
                .bind(bytes_rx)
                .bind(bytes_tx)
                .bind(packets_rx)
                .bind(packets_tx)
                .execute(&self.pool)
                .await?;
            }
            ConnectionEvent::IpChange {
                connection_id,
                timestamp,
                old_addr,
                new_addr,
                username,
            } => {
                sqlx::query(
                    r#"
                    INSERT INTO connection_events
                    (connection_id, event_type, timestamp, old_addr, new_addr, username)
                    VALUES (?, 'ip_change', ?, ?, ?, ?)
                    "#,
                )
                .bind(connection_id.to_string())
                .bind(timestamp.to_rfc3339())
                .bind(old_addr.to_string())
                .bind(new_addr.to_string())
                .bind(username.as_deref())
                .execute(&self.pool)
                .await?;
            }
            ConnectionEvent::Renegotiation {
                connection_id,
                timestamp,
                client_addr,
                success,
            } => {
                sqlx::query(
                    r#"
                    INSERT INTO connection_events
                    (connection_id, event_type, timestamp, client_addr, success)
                    VALUES (?, 'renegotiation', ?, ?, ?)
                    "#,
                )
                .bind(connection_id.to_string())
                .bind(timestamp.to_rfc3339())
                .bind(client_addr.to_string())
                .bind(*success as i32)
                .execute(&self.pool)
                .await?;
            }
        }

        Ok(())
    }

    async fn purge_old_events(&self) -> Result<usize> {
        if self.retention_days == 0 {
            return Ok(0);
        }

        let cutoff = Utc::now() - chrono::Duration::days(self.retention_days as i64);

        let result = sqlx::query("DELETE FROM connection_events WHERE timestamp < ?")
            .bind(cutoff.to_rfc3339())
            .execute(&self.pool)
            .await?;

        let deleted = result.rows_affected() as usize;
        if deleted > 0 {
            info!("Purged {} old connection events", deleted);
        }

        Ok(deleted)
    }

    #[allow(dead_code)] // Used by query_recent/query_connection, which are not yet wired up.
    fn parse_event_row(row: &sqlx::sqlite::SqliteRow) -> Option<ConnectionEvent> {
        let event_type: String = row.try_get("event_type").ok()?;
        let connection_id_str: String = row.try_get("connection_id").ok()?;
        let connection_id = ConnectionId(uuid::Uuid::parse_str(&connection_id_str).ok()?);
        let timestamp_str: String = row.try_get("timestamp").ok()?;
        let timestamp = DateTime::parse_from_rfc3339(&timestamp_str)
            .ok()?
            .with_timezone(&Utc);

        match event_type.as_str() {
            "connection_attempt" => {
                let client_addr_str: String = row.try_get("client_addr").ok()?;
                let client_addr = client_addr_str.parse().ok()?;
                let protocol_version: Option<String> = row.try_get("protocol_version").ok();

                Some(ConnectionEvent::ConnectionAttempt {
                    connection_id,
                    timestamp,
                    client_addr,
                    protocol_version,
                })
            }
            "authentication" => {
                let client_addr_str: String = row.try_get("client_addr").ok()?;
                let client_addr = client_addr_str.parse().ok()?;
                let username: Option<String> = row.try_get("username").ok();
                let auth_method_str: String = row.try_get("auth_method").unwrap_or_default();
                let auth_result_str: String = row.try_get("auth_result").unwrap_or_default();
                let details: Option<String> = row.try_get("details").ok();

                Some(ConnectionEvent::Authentication {
                    connection_id,
                    timestamp,
                    client_addr,
                    username,
                    auth_method: parse_auth_method(&auth_method_str),
                    result: parse_auth_result(&auth_result_str),
                    details,
                })
            }
            "connected" => {
                let client_addr_str: String = row.try_get("client_addr").ok()?;
                let client_addr = client_addr_str.parse().ok()?;
                let username: Option<String> = row.try_get("username").ok();
                let vpn_ip_str: String = row.try_get("vpn_ip").ok()?;
                let vpn_ip = vpn_ip_str.parse().ok()?;
                let auth_method_str: String = row.try_get("auth_method").unwrap_or_default();
                let client_info: Option<String> = row.try_get("client_info").ok();

                Some(ConnectionEvent::Connected {
                    connection_id,
                    timestamp,
                    client_addr,
                    username,
                    vpn_ip,
                    auth_method: parse_auth_method(&auth_method_str),
                    client_info,
                })
            }
            "disconnected" => {
                let client_addr_str: String = row.try_get("client_addr").ok()?;
                let client_addr = client_addr_str.parse().ok()?;
                let username: Option<String> = row.try_get("username").ok();
                let reason_str: String = row.try_get("disconnect_reason").unwrap_or_default();
                let duration_secs: i64 = row.try_get("duration_secs").unwrap_or(0);
                let bytes_rx: Option<i64> = row.try_get("bytes_rx").ok();
                let bytes_tx: Option<i64> = row.try_get("bytes_tx").ok();
                let packets_rx: Option<i64> = row.try_get("packets_rx").ok();
                let packets_tx: Option<i64> = row.try_get("packets_tx").ok();

                let stats = if bytes_rx.is_some() || bytes_tx.is_some() {
                    Some(TransferStats {
                        bytes_rx: bytes_rx.unwrap_or(0) as u64,
                        bytes_tx: bytes_tx.unwrap_or(0) as u64,
                        packets_rx: packets_rx.unwrap_or(0) as u64,
                        packets_tx: packets_tx.unwrap_or(0) as u64,
                    })
                } else {
                    None
                };

                Some(ConnectionEvent::Disconnected {
                    connection_id,
                    timestamp,
                    client_addr,
                    username,
                    reason: parse_disconnect_reason(&reason_str),
                    duration: std::time::Duration::from_secs(duration_secs as u64),
                    stats,
                })
            }
            "ip_change" => {
                let old_addr_str: String = row.try_get("old_addr").ok()?;
                let new_addr_str: String = row.try_get("new_addr").ok()?;
                let old_addr = old_addr_str.parse().ok()?;
                let new_addr = new_addr_str.parse().ok()?;
                let username: Option<String> = row.try_get("username").ok();

                Some(ConnectionEvent::IpChange {
                    connection_id,
                    timestamp,
                    old_addr,
                    new_addr,
                    username,
                })
            }
            "renegotiation" => {
                let client_addr_str: String = row.try_get("client_addr").ok()?;
                let client_addr = client_addr_str.parse().ok()?;
                let success: i32 = row.try_get("success").unwrap_or(0);

                Some(ConnectionEvent::Renegotiation {
                    connection_id,
                    timestamp,
                    client_addr,
                    success: success != 0,
                })
            }
            _ => None,
        }
    }
}

#[allow(dead_code)] // Parsing helper retained for the not-yet-wired query path.
fn parse_auth_method(s: &str) -> AuthMethod {
    match s.to_lowercase().as_str() {
        "certificate" => AuthMethod::Certificate,
        "usernamepassword" => AuthMethod::UsernamePassword,
        "oauth2" => AuthMethod::OAuth2,
        "saml" => AuthMethod::Saml,
        "psk" => AuthMethod::Psk,
        _ => AuthMethod::Unknown,
    }
}

#[allow(dead_code)] // Parsing helper retained for the not-yet-wired query path.
fn parse_auth_result(s: &str) -> AuthResult {
    match s.to_lowercase().as_str() {
        "success" => AuthResult::Success,
        "invalidcredentials" => AuthResult::InvalidCredentials,
        "expired" => AuthResult::Expired,
        "notauthorized" => AuthResult::NotAuthorized,
        "ratelimited" => AuthResult::RateLimited,
        "providererror" => AuthResult::ProviderError,
        "timeout" => AuthResult::Timeout,
        _ => AuthResult::Unknown,
    }
}

#[allow(dead_code)] // Parsing helper retained for the not-yet-wired query path.
fn parse_disconnect_reason(s: &str) -> DisconnectReason {
    match s.to_lowercase().as_str() {
        "clientdisconnect" => DisconnectReason::ClientDisconnect,
        "serverdisconnect" => DisconnectReason::ServerDisconnect,
        "idletimeout" => DisconnectReason::IdleTimeout,
        "sessiontimeout" => DisconnectReason::SessionTimeout,
        "authfailure" => DisconnectReason::AuthFailure,
        "protocolerror" => DisconnectReason::ProtocolError,
        "connectionreset" => DisconnectReason::ConnectionReset,
        "servershutdown" => DisconnectReason::ServerShutdown,
        "adminterminated" => DisconnectReason::AdminTerminated,
        "renegotiationfailure" => DisconnectReason::RenegotiationFailure,
        _ => DisconnectReason::Unknown,
    }
}

#[async_trait]
impl ConnectionLogger for DatabaseConnectionLogger {
    async fn log(&self, event: ConnectionEvent) -> Result<()> {
        let timestamp = event.timestamp();

        // Update timestamps
        {
            let mut first = self.first_event.write();
            if first.is_none() {
                *first = Some(timestamp);
            }
        }
        {
            let mut last = self.last_event.write();
            *last = Some(timestamp);
        }

        // Insert event
        self.insert_event(&event).await?;

        self.total_logged.fetch_add(1, Ordering::Relaxed);

        // Auto-purge occasionally
        if self.auto_purge && self.total_logged.load(Ordering::Relaxed) % 1000 == 0 {
            self.purge_old_events().await?;
        }

        Ok(())
    }

    async fn query_recent(&self, limit: usize) -> Result<Option<Vec<ConnectionEvent>>> {
        let rows = sqlx::query("SELECT * FROM connection_events ORDER BY timestamp DESC LIMIT ?")
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await?;

        let events: Vec<ConnectionEvent> = rows.iter().filter_map(Self::parse_event_row).collect();

        Ok(Some(events))
    }

    async fn query_connection(&self, id: ConnectionId) -> Result<Option<Vec<ConnectionEvent>>> {
        let rows = sqlx::query(
            "SELECT * FROM connection_events WHERE connection_id = ? ORDER BY timestamp",
        )
        .bind(id.to_string())
        .fetch_all(&self.pool)
        .await?;

        let events: Vec<ConnectionEvent> = rows.iter().filter_map(Self::parse_event_row).collect();

        Ok(Some(events))
    }

    async fn flush(&self) -> Result<()> {
        // SQLite with WAL mode handles this automatically
        Ok(())
    }

    async fn cleanup(&self) -> Result<()> {
        self.purge_old_events().await?;

        // Vacuum to reclaim space
        sqlx::query("VACUUM").execute(&self.pool).await.ok(); // Don't fail on vacuum errors

        Ok(())
    }

    fn stats(&self) -> LoggerStats {
        LoggerStats {
            events_logged: self.total_logged.load(Ordering::Relaxed),
            pending_events: 0,   // Database has no pending events
            storage_bytes: None, // Would need to query file size
            oldest_event: *self.first_event.read(),
            newest_event: *self.last_event.read(),
        }
    }

    fn logger_type(&self) -> &'static str {
        "database"
    }
}
