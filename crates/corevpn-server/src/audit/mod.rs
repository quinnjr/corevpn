//! Audit Logging Module
//!
//! Provides comprehensive audit logging support for SIEM and cloud services including:
//! - AWS (CloudWatch Logs, S3, Security Hub, EventBridge)
//! - Microsoft Azure (Sentinel, Monitor, Event Hub)
//! - Oracle Cloud (OCI Logging, Audit, Streaming)
//! - Generic SIEM formats (Syslog, CEF, LEEF, JSON)
//! - Splunk HEC
//! - Elasticsearch
//! - Kafka
//! - Webhook

pub mod events;
pub mod formats;
pub mod sinks;

use std::sync::Arc;
use tokio::sync::mpsc;

pub use events::{AuditCategory, AuditEvent, AuditEventBuilder, AuditSeverity};
pub use formats::{AuditFormat, FormatConfig};
pub use sinks::{AuditSink, SinkConfig};

/// Audit logger that routes events to configured sinks
pub struct AuditLogger {
    sinks: Vec<Arc<dyn AuditSink>>,
    tx: mpsc::Sender<AuditEvent>,
    enabled: bool,
}

impl AuditLogger {
    /// Create a new audit logger with the given configuration
    pub async fn new(config: AuditConfig) -> Result<Self, AuditError> {
        let (tx, rx) = mpsc::channel(config.buffer_size);
        let sinks = Self::create_sinks(&config).await?;

        let sinks_clone: Vec<Arc<dyn AuditSink>> = sinks.iter().map(Arc::clone).collect();

        // Spawn background task to process events
        tokio::spawn(async move {
            Self::process_events(rx, sinks_clone).await;
        });

        Ok(Self {
            sinks,
            tx,
            enabled: config.enabled,
        })
    }

    /// Create a no-op audit logger (for ghost mode)
    pub fn null() -> Self {
        let (tx, _rx) = mpsc::channel(1);
        Self {
            sinks: Vec::new(),
            tx,
            enabled: false,
        }
    }

    /// Log an audit event
    pub async fn log(&self, event: AuditEvent) {
        if !self.enabled {
            return;
        }

        if let Err(e) = self.tx.send(event).await {
            log::error!("Failed to queue audit event: {}", e);
        }
    }

    /// Create a builder for a new audit event
    pub fn event(&self, category: AuditCategory) -> AuditEventBuilder {
        AuditEventBuilder::new(category)
    }

    async fn create_sinks(config: &AuditConfig) -> Result<Vec<Arc<dyn AuditSink>>, AuditError> {
        let mut sinks: Vec<Arc<dyn AuditSink>> = Vec::new();

        for sink_config in &config.sinks {
            let sink = sinks::create_sink(sink_config).await?;
            sinks.push(sink);
        }

        Ok(sinks)
    }

    async fn process_events(mut rx: mpsc::Receiver<AuditEvent>, sinks: Vec<Arc<dyn AuditSink>>) {
        while let Some(event) = rx.recv().await {
            for sink in &sinks {
                if let Err(e) = sink.send(&event).await {
                    log::error!("Failed to send audit event to sink: {}", e);
                }
            }
        }
    }

    /// Flush all pending events
    pub async fn flush(&self) -> Result<(), AuditError> {
        for sink in &self.sinks {
            sink.flush().await?;
        }
        Ok(())
    }

    /// Close all sinks gracefully
    pub async fn close(&self) -> Result<(), AuditError> {
        for sink in &self.sinks {
            sink.close().await?;
        }
        Ok(())
    }
}

/// Audit logging configuration
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct AuditConfig {
    /// Enable audit logging
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Event buffer size
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,

    /// Configured sinks
    #[serde(default)]
    pub sinks: Vec<SinkConfig>,

    /// Default format for sinks that don't specify one
    #[serde(default)]
    pub default_format: FormatConfig,

    /// Include source IP in events
    #[serde(default = "default_false")]
    pub include_source_ip: bool,

    /// Include user identity in events
    #[serde(default = "default_false")]
    pub include_user_identity: bool,

    /// Hash sensitive fields for privacy
    #[serde(default)]
    pub hash_sensitive_fields: bool,

    /// Categories to log
    #[serde(default = "default_categories")]
    pub categories: Vec<AuditCategory>,
}

fn default_enabled() -> bool {
    true
}
fn default_buffer_size() -> usize {
    10000
}
// Retained as a serde default helper for config fields not yet wired up.
#[allow(dead_code)]
fn default_true() -> bool {
    true
}
fn default_false() -> bool {
    false
}
fn default_categories() -> Vec<AuditCategory> {
    vec![
        AuditCategory::Authentication,
        AuditCategory::Authorization,
        AuditCategory::Connection,
        AuditCategory::Configuration,
        AuditCategory::Security,
    ]
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            buffer_size: 10000,
            sinks: Vec::new(),
            default_format: FormatConfig::default(),
            include_source_ip: false,
            include_user_identity: false,
            hash_sensitive_fields: false,
            categories: default_categories(),
        }
    }
}

/// Audit logging errors
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Authentication error: {0}")]
    Authentication(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("Cloud provider error: {0}")]
    CloudProvider(String),

    #[error("Sink error: {0}")]
    Sink(String),
}
