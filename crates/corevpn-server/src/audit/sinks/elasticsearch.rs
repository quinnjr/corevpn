//! Elasticsearch Audit Sink

use super::{AuditError, AuditEvent, AuditSink};
use crate::audit::formats::{FormatConfig, FormatEncoder};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Elasticsearch configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElasticsearchConfig {
    /// Elasticsearch URLs (comma-separated for cluster)
    pub urls: Vec<String>,

    /// Index name pattern (supports {date} placeholder)
    #[serde(default = "default_index")]
    pub index: String,

    /// Username for authentication
    pub username: Option<String>,

    /// Password for authentication
    pub password: Option<String>,

    /// API key for authentication
    pub api_key: Option<String>,

    /// Cloud ID for Elastic Cloud
    pub cloud_id: Option<String>,

    /// Enable TLS verification
    #[serde(default = "default_true")]
    pub tls_verify: bool,

    /// CA certificate path
    pub ca_cert: Option<String>,

    /// Format configuration
    #[serde(default)]
    pub format: FormatConfig,

    /// Batch size for bulk API
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Flush interval in seconds
    #[serde(default = "default_flush_interval")]
    pub flush_interval_secs: u64,

    /// Number of replicas for index
    #[serde(default)]
    pub replicas: u32,

    /// Number of shards for index
    #[serde(default = "default_shards")]
    pub shards: u32,

    /// Pipeline for ingest (optional)
    pub pipeline: Option<String>,
}

fn default_index() -> String {
    "corevpn-audit-{date}".to_string()
}
fn default_true() -> bool {
    true
}
fn default_batch_size() -> usize {
    100
}
fn default_flush_interval() -> u64 {
    5
}
fn default_shards() -> u32 {
    1
}

/// Elasticsearch sink
pub struct ElasticsearchSink {
    config: ElasticsearchConfig,
    encoder: FormatEncoder,
    buffer: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl ElasticsearchSink {
    pub async fn new(config: ElasticsearchConfig) -> Result<Self, AuditError> {
        let encoder = FormatEncoder::new(config.format.clone());

        Ok(Self {
            config,
            encoder,
            buffer: Arc::new(Mutex::new(Vec::new())),
        })
    }

    fn get_index_name(&self) -> String {
        let date = chrono::Utc::now().format("%Y.%m.%d").to_string();
        self.config.index.replace("{date}", &date)
    }

    async fn send_batch(&self, documents: Vec<serde_json::Value>) -> Result<(), AuditError> {
        if documents.is_empty() {
            return Ok(());
        }

        let index = self.get_index_name();
        let mut bulk_body = String::new();

        for doc in &documents {
            // Add action line
            let action = serde_json::json!({
                "index": {
                    "_index": index
                }
            });
            bulk_body.push_str(&serde_json::to_string(&action)?);
            bulk_body.push('\n');

            // Add document
            bulk_body.push_str(&serde_json::to_string(doc)?);
            bulk_body.push('\n');
        }

        log::debug!(
            "Would send {} documents to Elasticsearch: {}/_bulk",
            documents.len(),
            self.config.urls.first().unwrap_or(&String::new())
        );

        Ok(())
    }
}

#[async_trait]
impl AuditSink for ElasticsearchSink {
    async fn send(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let json_str = self.encoder.encode(event)?;
        let doc: serde_json::Value = serde_json::from_str(&json_str)?;

        let mut buffer = self.buffer.lock().await;
        buffer.push(doc);

        if buffer.len() >= self.config.batch_size {
            let documents = std::mem::take(&mut *buffer);
            drop(buffer);
            self.send_batch(documents).await?;
        }

        Ok(())
    }

    async fn flush(&self) -> Result<(), AuditError> {
        let mut buffer = self.buffer.lock().await;
        let documents = std::mem::take(&mut *buffer);
        drop(buffer);
        self.send_batch(documents).await
    }

    async fn close(&self) -> Result<(), AuditError> {
        self.flush().await
    }

    fn name(&self) -> &str {
        "elasticsearch"
    }
}
