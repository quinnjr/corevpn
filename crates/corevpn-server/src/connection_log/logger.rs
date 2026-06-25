//! Connection Logger Trait and Factory
//!
//! Defines the interface for connection logging backends.

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

use corevpn_config::{ConnectionLogMode, LoggingSettings};

use super::events::{ConnectionEvent, ConnectionId};
use super::{
    DatabaseConnectionLogger, FileConnectionLogger, MemoryConnectionLogger, NullConnectionLogger,
};

/// Trait for connection logging backends
#[async_trait]
pub trait ConnectionLogger: Send + Sync {
    /// Log a connection event
    async fn log(&self, event: ConnectionEvent) -> Result<()>;

    /// Query recent events (for monitoring)
    /// Returns None if querying is not supported (null logger)
    #[allow(dead_code)] // Query API retained for future monitoring endpoints.
    async fn query_recent(&self, limit: usize) -> Result<Option<Vec<ConnectionEvent>>>;

    /// Query events for a specific connection
    #[allow(dead_code)] // Query API retained for future monitoring endpoints.
    async fn query_connection(&self, id: ConnectionId) -> Result<Option<Vec<ConnectionEvent>>>;

    /// Flush any buffered events to storage
    async fn flush(&self) -> Result<()>;

    /// Perform cleanup (log rotation, purging old entries)
    async fn cleanup(&self) -> Result<()>;

    /// Get statistics about the logger
    #[allow(dead_code)] // Stats API retained for future monitoring endpoints.
    fn stats(&self) -> LoggerStats;

    /// Check if this logger is a null/ghost logger
    #[allow(dead_code)] // Retained for future introspection.
    fn is_null(&self) -> bool {
        false
    }

    /// Get the logger type name
    #[allow(dead_code)] // Retained for future introspection.
    fn logger_type(&self) -> &'static str;
}

/// Statistics about the logger
#[allow(dead_code)] // Constructed once query/stats endpoints are wired up.
#[derive(Debug, Clone, Default)]
pub struct LoggerStats {
    /// Total events logged
    pub events_logged: u64,
    /// Events logged since last flush
    pub pending_events: u64,
    /// Storage size in bytes (if applicable)
    pub storage_bytes: Option<u64>,
    /// Oldest event timestamp (if known)
    pub oldest_event: Option<chrono::DateTime<chrono::Utc>>,
    /// Most recent event timestamp
    pub newest_event: Option<chrono::DateTime<chrono::Utc>>,
}

/// Create a connection logger based on configuration
pub async fn create_logger(settings: &LoggingSettings) -> Result<Arc<dyn ConnectionLogger>> {
    match settings.connection_mode {
        ConnectionLogMode::None => {
            // Ghost mode - no logging at all
            Ok(Arc::new(NullConnectionLogger::new()))
        }
        ConnectionLogMode::Memory => {
            // In-memory only - no persistence
            Ok(Arc::new(MemoryConnectionLogger::new(
                settings.retention.days as usize * 24 * 60, // Rough estimate of max events
            )))
        }
        ConnectionLogMode::File => {
            // File-based logging
            let path = settings
                .connection_log_file
                .clone()
                .unwrap_or_else(|| std::path::PathBuf::from("/var/log/corevpn/connections.log"));

            let logger = FileConnectionLogger::new(
                path,
                settings.retention.max_file_size_mb as u64 * 1024 * 1024,
                settings.retention.max_files as usize,
                settings.retention.secure_delete,
            )
            .await?;

            Ok(Arc::new(logger))
        }
        ConnectionLogMode::Database => {
            // Database logging
            let path = settings
                .connection_log_db
                .clone()
                .unwrap_or_else(|| std::path::PathBuf::from("/var/lib/corevpn/connections.db"));

            let logger = DatabaseConnectionLogger::new(
                path,
                settings.retention.days,
                settings.retention.auto_purge,
            )
            .await?;

            Ok(Arc::new(logger))
        }
        ConnectionLogMode::Both => {
            // Both file and database - use a composite logger
            let file_path = settings
                .connection_log_file
                .clone()
                .unwrap_or_else(|| std::path::PathBuf::from("/var/log/corevpn/connections.log"));
            let db_path = settings
                .connection_log_db
                .clone()
                .unwrap_or_else(|| std::path::PathBuf::from("/var/lib/corevpn/connections.db"));

            let file_logger = FileConnectionLogger::new(
                file_path,
                settings.retention.max_file_size_mb as u64 * 1024 * 1024,
                settings.retention.max_files as usize,
                settings.retention.secure_delete,
            )
            .await?;

            let db_logger = DatabaseConnectionLogger::new(
                db_path,
                settings.retention.days,
                settings.retention.auto_purge,
            )
            .await?;

            Ok(Arc::new(CompositeLogger::new(
                Arc::new(file_logger),
                Arc::new(db_logger),
            )))
        }
    }
}

/// Composite logger that writes to multiple backends
pub struct CompositeLogger {
    file_logger: Arc<FileConnectionLogger>,
    db_logger: Arc<DatabaseConnectionLogger>,
}

impl CompositeLogger {
    pub fn new(
        file_logger: Arc<FileConnectionLogger>,
        db_logger: Arc<DatabaseConnectionLogger>,
    ) -> Self {
        Self {
            file_logger,
            db_logger,
        }
    }
}

#[async_trait]
impl ConnectionLogger for CompositeLogger {
    async fn log(&self, event: ConnectionEvent) -> Result<()> {
        // Log to both - don't fail if one fails
        let file_result = self.file_logger.log(event.clone()).await;
        let db_result = self.db_logger.log(event).await;

        // Return error only if both fail
        if file_result.is_err() && db_result.is_err() {
            file_result?;
        }

        Ok(())
    }

    async fn query_recent(&self, limit: usize) -> Result<Option<Vec<ConnectionEvent>>> {
        // Prefer database for queries
        self.db_logger.query_recent(limit).await
    }

    async fn query_connection(&self, id: ConnectionId) -> Result<Option<Vec<ConnectionEvent>>> {
        self.db_logger.query_connection(id).await
    }

    async fn flush(&self) -> Result<()> {
        self.file_logger.flush().await?;
        self.db_logger.flush().await?;
        Ok(())
    }

    async fn cleanup(&self) -> Result<()> {
        self.file_logger.cleanup().await?;
        self.db_logger.cleanup().await?;
        Ok(())
    }

    fn stats(&self) -> LoggerStats {
        // Combine stats from both
        let file_stats = self.file_logger.stats();
        let db_stats = self.db_logger.stats();

        LoggerStats {
            events_logged: file_stats.events_logged.max(db_stats.events_logged),
            pending_events: file_stats.pending_events + db_stats.pending_events,
            storage_bytes: match (file_stats.storage_bytes, db_stats.storage_bytes) {
                (Some(a), Some(b)) => Some(a + b),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            },
            oldest_event: match (file_stats.oldest_event, db_stats.oldest_event) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            },
            newest_event: match (file_stats.newest_event, db_stats.newest_event) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            },
        }
    }

    fn logger_type(&self) -> &'static str {
        "composite"
    }
}
