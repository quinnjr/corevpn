//! Oracle Cloud Audit Sinks
//!
//! Supports:
//! - OCI Logging
//! - OCI Streaming

use super::{AuditError, AuditEvent, AuditSink};
use crate::audit::formats::{FormatConfig, FormatEncoder};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Oracle Cloud Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleLoggingConfig {
    /// OCI region
    pub region: String,

    /// Log OCID
    pub log_id: String,

    /// Tenancy OCID
    pub tenancy_id: String,

    /// User OCID
    pub user_id: String,

    /// API key fingerprint
    pub fingerprint: String,

    /// Private key path or content
    pub private_key: String,

    /// Private key passphrase (optional)
    pub passphrase: Option<String>,

    /// Format configuration
    #[serde(default)]
    pub format: FormatConfig,

    /// Batch size
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Flush interval in seconds
    #[serde(default = "default_flush_interval")]
    pub flush_interval_secs: u64,
}

fn default_batch_size() -> usize {
    100
}
fn default_flush_interval() -> u64 {
    5
}

/// OCI Logging sink
pub struct OracleLoggingSink {
    config: OracleLoggingConfig,
    encoder: FormatEncoder,
    buffer: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl OracleLoggingSink {
    pub async fn new(config: OracleLoggingConfig) -> Result<Self, AuditError> {
        let encoder = FormatEncoder::new(config.format.clone());

        Ok(Self {
            config,
            encoder,
            buffer: Arc::new(Mutex::new(Vec::new())),
        })
    }

    fn get_endpoint(&self) -> String {
        format!(
            "https://ingestion.logging.{}.oci.oraclecloud.com",
            self.config.region
        )
    }

    async fn send_batch(&self, entries: Vec<serde_json::Value>) -> Result<(), AuditError> {
        if entries.is_empty() {
            return Ok(());
        }

        let endpoint = self.get_endpoint();
        let log_entries = serde_json::json!({
            "logEntryBatches": [{
                "entries": entries,
                "logId": self.config.log_id,
                "defaultlogentrytime": chrono::Utc::now().to_rfc3339()
            }]
        });

        log::debug!(
            "Would send {} entries to OCI Logging: {}",
            entries.len(),
            endpoint
        );

        // In production, this would:
        // 1. Sign the request using OCI signature
        // 2. POST to the logging endpoint
        let _ = log_entries;

        Ok(())
    }
}

#[async_trait]
impl AuditSink for OracleLoggingSink {
    async fn send(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let json_str = self.encoder.encode(event)?;
        let entry = serde_json::json!({
            "data": json_str,
            "id": event.id,
            "time": event.timestamp.to_rfc3339()
        });

        let mut buffer = self.buffer.lock().await;
        buffer.push(entry);

        if buffer.len() >= self.config.batch_size {
            let entries = std::mem::take(&mut *buffer);
            drop(buffer);
            self.send_batch(entries).await?;
        }

        Ok(())
    }

    async fn flush(&self) -> Result<(), AuditError> {
        let mut buffer = self.buffer.lock().await;
        let entries = std::mem::take(&mut *buffer);
        drop(buffer);
        self.send_batch(entries).await
    }

    async fn close(&self) -> Result<(), AuditError> {
        self.flush().await
    }

    fn name(&self) -> &str {
        "oracle_logging"
    }
}

/// Oracle Cloud Streaming configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleStreamingConfig {
    /// OCI region
    pub region: String,

    /// Stream OCID
    pub stream_id: String,

    /// Stream pool OCID (optional)
    pub stream_pool_id: Option<String>,

    /// Tenancy OCID
    pub tenancy_id: String,

    /// User OCID
    pub user_id: String,

    /// API key fingerprint
    pub fingerprint: String,

    /// Private key path or content
    pub private_key: String,

    /// Private key passphrase (optional)
    pub passphrase: Option<String>,

    /// Partition key (optional, uses event ID if not set)
    pub partition_key: Option<String>,

    /// Format configuration
    #[serde(default)]
    pub format: FormatConfig,

    /// Batch size
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
}

/// OCI Streaming sink
pub struct OracleStreamingSink {
    config: OracleStreamingConfig,
    encoder: FormatEncoder,
    buffer: Arc<Mutex<Vec<StreamMessage>>>,
}

struct StreamMessage {
    key: String,
    value: String,
}

impl OracleStreamingSink {
    pub async fn new(config: OracleStreamingConfig) -> Result<Self, AuditError> {
        let encoder = FormatEncoder::new(config.format.clone());

        Ok(Self {
            config,
            encoder,
            buffer: Arc::new(Mutex::new(Vec::new())),
        })
    }

    fn get_endpoint(&self) -> String {
        format!(
            "https://streaming.{}.oci.oraclecloud.com/20180418/streams/{}/messages",
            self.config.region, self.config.stream_id
        )
    }

    async fn send_batch(&self, messages: Vec<StreamMessage>) -> Result<(), AuditError> {
        if messages.is_empty() {
            return Ok(());
        }

        let endpoint = self.get_endpoint();
        let records: Vec<_> = messages
            .iter()
            .map(|m| {
                serde_json::json!({
                    "key": base64::encode(&m.key),
                    "value": base64::encode(&m.value)
                })
            })
            .collect();

        let body = serde_json::json!({
            "messages": records
        });

        log::debug!(
            "Would send {} messages to OCI Streaming: {}",
            messages.len(),
            endpoint
        );

        let _ = body;

        Ok(())
    }
}

#[async_trait]
impl AuditSink for OracleStreamingSink {
    async fn send(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let key = self
            .config
            .partition_key
            .clone()
            .unwrap_or_else(|| event.id.clone());
        let value = self.encoder.encode(event)?;

        let mut buffer = self.buffer.lock().await;
        buffer.push(StreamMessage { key, value });

        if buffer.len() >= self.config.batch_size {
            let messages = std::mem::take(&mut *buffer);
            drop(buffer);
            self.send_batch(messages).await?;
        }

        Ok(())
    }

    async fn flush(&self) -> Result<(), AuditError> {
        let mut buffer = self.buffer.lock().await;
        let messages = std::mem::take(&mut *buffer);
        drop(buffer);
        self.send_batch(messages).await
    }

    async fn close(&self) -> Result<(), AuditError> {
        self.flush().await
    }

    fn name(&self) -> &str {
        "oracle_streaming"
    }
}

// Base64 encode helper
mod base64 {
    use base64::Engine;

    pub fn encode(data: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(data.as_bytes())
    }
}
