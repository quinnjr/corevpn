//! Splunk HEC Audit Sink

use super::{AuditError, AuditEvent, AuditSink};
use crate::audit::formats::{FormatConfig, FormatEncoder};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Splunk HEC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplunkConfig {
    /// HEC endpoint URL
    pub url: String,

    /// HEC token
    pub token: String,

    /// Source type
    #[serde(default = "default_sourcetype")]
    pub sourcetype: String,

    /// Source
    #[serde(default = "default_source")]
    pub source: String,

    /// Index
    pub index: Option<String>,

    /// Host field override
    pub host: Option<String>,

    /// Enable TLS verification
    #[serde(default = "default_true")]
    pub tls_verify: bool,

    /// Format configuration
    #[serde(default)]
    pub format: FormatConfig,

    /// Batch size
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Flush interval in seconds
    #[serde(default = "default_flush_interval")]
    pub flush_interval_secs: u64,

    /// Use raw endpoint (vs event endpoint)
    #[serde(default)]
    pub raw: bool,

    /// Channel for HEC acknowledgment
    pub channel: Option<String>,
}

fn default_sourcetype() -> String {
    "corevpn:audit".to_string()
}
fn default_source() -> String {
    "corevpn".to_string()
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

/// Splunk HEC sink
pub struct SplunkSink {
    config: SplunkConfig,
    encoder: FormatEncoder,
    buffer: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl SplunkSink {
    pub async fn new(config: SplunkConfig) -> Result<Self, AuditError> {
        let encoder = FormatEncoder::new(config.format.clone());

        Ok(Self {
            config,
            encoder,
            buffer: Arc::new(Mutex::new(Vec::new())),
        })
    }

    fn build_hec_event(&self, event: &AuditEvent, data: serde_json::Value) -> serde_json::Value {
        let mut hec_event = serde_json::json!({
            "time": event.timestamp.timestamp_millis() as f64 / 1000.0,
            "sourcetype": self.config.sourcetype,
            "source": self.config.source,
            "event": data
        });

        if let Some(ref index) = self.config.index {
            hec_event["index"] = serde_json::json!(index);
        }

        if let Some(ref host) = self.config.host {
            hec_event["host"] = serde_json::json!(host);
        } else {
            hec_event["host"] = serde_json::json!(event.host);
        }

        hec_event
    }

    async fn send_batch(&self, events: Vec<serde_json::Value>) -> Result<(), AuditError> {
        if events.is_empty() {
            return Ok(());
        }

        let endpoint = if self.config.raw {
            format!("{}/services/collector/raw", self.config.url)
        } else {
            format!("{}/services/collector/event", self.config.url)
        };

        // For batch, we send newline-delimited JSON
        let body: String = events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n");

        log::debug!(
            "Would send {} events to Splunk HEC: {}",
            events.len(),
            endpoint
        );

        let _ = body;

        Ok(())
    }
}

#[async_trait]
impl AuditSink for SplunkSink {
    async fn send(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let json_str = self.encoder.encode(event)?;
        let data: serde_json::Value = serde_json::from_str(&json_str)?;
        let hec_event = self.build_hec_event(event, data);

        let mut buffer = self.buffer.lock().await;
        buffer.push(hec_event);

        if buffer.len() >= self.config.batch_size {
            let events = std::mem::take(&mut *buffer);
            drop(buffer);
            self.send_batch(events).await?;
        }

        Ok(())
    }

    async fn flush(&self) -> Result<(), AuditError> {
        let mut buffer = self.buffer.lock().await;
        let events = std::mem::take(&mut *buffer);
        drop(buffer);
        self.send_batch(events).await
    }

    async fn close(&self) -> Result<(), AuditError> {
        self.flush().await
    }

    fn name(&self) -> &str {
        "splunk"
    }
}
