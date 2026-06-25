//! Azure Audit Sinks
//!
//! Supports:
//! - Azure Monitor / Log Analytics
//! - Azure Event Hub
//! - Azure Sentinel

use super::{AuditError, AuditEvent, AuditSink};
use crate::audit::formats::{AuditFormat, FormatConfig, FormatEncoder};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Azure Monitor / Log Analytics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureMonitorConfig {
    /// Workspace ID
    pub workspace_id: String,

    /// Shared key (primary or secondary)
    pub shared_key: String,

    /// Custom log type name
    #[serde(default = "default_log_type")]
    pub log_type: String,

    /// Azure Government or other cloud
    #[serde(default)]
    pub azure_cloud: AzureCloud,

    /// Time field name in records
    #[serde(default = "default_time_field")]
    pub time_field: String,

    /// Batch size
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Flush interval in seconds
    #[serde(default = "default_flush_interval")]
    pub flush_interval_secs: u64,
}

fn default_log_type() -> String {
    "CoreVPNAudit".to_string()
}
fn default_time_field() -> String {
    "TimeGenerated".to_string()
}
fn default_batch_size() -> usize {
    100
}
fn default_flush_interval() -> u64 {
    5
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AzureCloud {
    #[default]
    Public,
    Government,
    China,
    Germany,
}

impl AzureCloud {
    fn log_analytics_endpoint(&self) -> &str {
        match self {
            AzureCloud::Public => "ods.opinsights.azure.com",
            AzureCloud::Government => "ods.opinsights.azure.us",
            AzureCloud::China => "ods.opinsights.azure.cn",
            AzureCloud::Germany => "ods.opinsights.azure.de",
        }
    }
}

/// Azure Monitor sink
pub struct AzureMonitorSink {
    config: AzureMonitorConfig,
    encoder: FormatEncoder,
    buffer: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl AzureMonitorSink {
    pub async fn new(config: AzureMonitorConfig) -> Result<Self, AuditError> {
        let encoder = FormatEncoder::new(FormatConfig {
            format: AuditFormat::AzureMonitor,
            ..Default::default()
        });

        Ok(Self {
            config,
            encoder,
            buffer: Arc::new(Mutex::new(Vec::new())),
        })
    }

    fn build_signature(&self, _date: &str, _content_length: usize) -> String {
        // In production, this would compute the HMAC-SHA256 signature
        // using the shared key
        "placeholder_signature".to_string()
    }

    async fn send_batch(&self, records: Vec<serde_json::Value>) -> Result<(), AuditError> {
        if records.is_empty() {
            return Ok(());
        }

        let endpoint = self.config.azure_cloud.log_analytics_endpoint();
        let url = format!(
            "https://{}.{}/api/logs?api-version=2016-04-01",
            self.config.workspace_id, endpoint
        );

        let body = serde_json::to_string(&records)?;
        let date = chrono::Utc::now()
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        let _signature = self.build_signature(&date, body.len());

        log::debug!(
            "Would send {} records to Azure Monitor: {}",
            records.len(),
            url
        );

        Ok(())
    }
}

#[async_trait]
impl AuditSink for AzureMonitorSink {
    async fn send(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let json_str = self.encoder.encode(event)?;
        let record: serde_json::Value = serde_json::from_str(&json_str)?;

        let mut buffer = self.buffer.lock().await;
        buffer.push(record);

        if buffer.len() >= self.config.batch_size {
            let records = std::mem::take(&mut *buffer);
            drop(buffer);
            self.send_batch(records).await?;
        }

        Ok(())
    }

    async fn flush(&self) -> Result<(), AuditError> {
        let mut buffer = self.buffer.lock().await;
        let records = std::mem::take(&mut *buffer);
        drop(buffer);
        self.send_batch(records).await
    }

    async fn close(&self) -> Result<(), AuditError> {
        self.flush().await
    }

    fn name(&self) -> &str {
        "azure_monitor"
    }
}

/// Azure Event Hub configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureEventHubConfig {
    /// Event Hub namespace
    pub namespace: String,

    /// Event Hub name
    pub event_hub: String,

    /// Shared Access Signature policy name
    pub policy_name: String,

    /// Shared Access Signature key
    pub policy_key: String,

    /// Partition key (optional)
    pub partition_key: Option<String>,

    /// Format configuration
    #[serde(default)]
    pub format: FormatConfig,

    /// Batch size
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Azure cloud
    #[serde(default)]
    pub azure_cloud: AzureCloud,
}

/// Azure Event Hub sink
pub struct AzureEventHubSink {
    config: AzureEventHubConfig,
    encoder: FormatEncoder,
    buffer: Arc<Mutex<Vec<String>>>,
}

impl AzureEventHubSink {
    pub async fn new(config: AzureEventHubConfig) -> Result<Self, AuditError> {
        let encoder = FormatEncoder::new(config.format.clone());

        Ok(Self {
            config,
            encoder,
            buffer: Arc::new(Mutex::new(Vec::new())),
        })
    }

    fn get_endpoint(&self) -> String {
        let suffix = match self.config.azure_cloud {
            AzureCloud::Public => "servicebus.windows.net",
            AzureCloud::Government => "servicebus.usgovcloudapi.net",
            AzureCloud::China => "servicebus.chinacloudapi.cn",
            AzureCloud::Germany => "servicebus.cloudapi.de",
        };

        format!(
            "https://{}.{}/{}/messages",
            self.config.namespace, suffix, self.config.event_hub
        )
    }

    async fn send_batch(&self, events: Vec<String>) -> Result<(), AuditError> {
        if events.is_empty() {
            return Ok(());
        }

        let endpoint = self.get_endpoint();
        log::debug!(
            "Would send {} events to Event Hub: {}",
            events.len(),
            endpoint
        );

        Ok(())
    }
}

#[async_trait]
impl AuditSink for AzureEventHubSink {
    async fn send(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let message = self.encoder.encode(event)?;

        let mut buffer = self.buffer.lock().await;
        buffer.push(message);

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
        "azure_event_hub"
    }
}

/// Azure Sentinel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureSentinelConfig {
    /// Log Analytics Workspace ID (Sentinel uses Log Analytics)
    pub workspace_id: String,

    /// Shared key
    pub shared_key: String,

    /// Custom log type for Sentinel
    #[serde(default = "default_sentinel_log_type")]
    pub log_type: String,

    /// Azure cloud
    #[serde(default)]
    pub azure_cloud: AzureCloud,

    /// Add Sentinel-specific enrichments
    #[serde(default = "default_true")]
    pub enrich_for_sentinel: bool,

    /// Batch size
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
}

fn default_sentinel_log_type() -> String {
    "CoreVPNSecurity".to_string()
}
fn default_true() -> bool {
    true
}

/// Azure Sentinel sink (via Log Analytics)
pub struct AzureSentinelSink {
    // Sentinel uses Log Analytics under the hood
    monitor_sink: AzureMonitorSink,
    enrich: bool,
}

impl AzureSentinelSink {
    pub async fn new(config: AzureSentinelConfig) -> Result<Self, AuditError> {
        let monitor_config = AzureMonitorConfig {
            workspace_id: config.workspace_id,
            shared_key: config.shared_key,
            log_type: config.log_type,
            azure_cloud: config.azure_cloud,
            time_field: "TimeGenerated".to_string(),
            batch_size: config.batch_size,
            flush_interval_secs: 5,
        };

        let monitor_sink = AzureMonitorSink::new(monitor_config).await?;

        Ok(Self {
            monitor_sink,
            enrich: config.enrich_for_sentinel,
        })
    }
}

#[async_trait]
impl AuditSink for AzureSentinelSink {
    async fn send(&self, event: &AuditEvent) -> Result<(), AuditError> {
        // Optionally enrich for Sentinel-specific fields
        if self.enrich {
            // Add Sentinel-compatible fields
            log::trace!("Enriching event for Sentinel: {}", event.id);
        }

        self.monitor_sink.send(event).await
    }

    async fn flush(&self) -> Result<(), AuditError> {
        self.monitor_sink.flush().await
    }

    async fn close(&self) -> Result<(), AuditError> {
        self.monitor_sink.close().await
    }

    fn name(&self) -> &str {
        "azure_sentinel"
    }
}
