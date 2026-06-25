//! Audit Log Sinks
//!
//! Destinations for audit events including cloud providers and SIEM systems.

mod aws;
mod azure;
mod elasticsearch;
mod file;
mod kafka;
mod oracle;
mod splunk;
mod syslog;
mod webhook;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::{AuditError, AuditEvent};

pub use aws::*;
pub use azure::*;
pub use elasticsearch::*;
pub use file::*;
pub use kafka::*;
pub use oracle::*;
pub use splunk::*;
pub use syslog::*;
pub use webhook::*;

/// Trait for audit log destinations
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Send an audit event to the sink
    async fn send(&self, event: &AuditEvent) -> Result<(), AuditError>;

    /// Flush any buffered events
    async fn flush(&self) -> Result<(), AuditError>;

    /// Close the sink gracefully
    async fn close(&self) -> Result<(), AuditError>;

    /// Get the sink name for logging
    fn name(&self) -> &str;
}

/// Configuration for a single sink
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SinkConfig {
    /// AWS CloudWatch Logs
    AwsCloudwatch(AwsCloudwatchConfig),

    /// AWS S3 bucket
    AwsS3(AwsS3Config),

    /// AWS Security Hub
    AwsSecurityHub(AwsSecurityHubConfig),

    /// AWS EventBridge
    AwsEventBridge(AwsEventBridgeConfig),

    /// Azure Monitor / Log Analytics
    AzureMonitor(AzureMonitorConfig),

    /// Azure Event Hub
    AzureEventHub(AzureEventHubConfig),

    /// Azure Sentinel
    AzureSentinel(AzureSentinelConfig),

    /// Oracle Cloud Logging
    OracleLogging(OracleLoggingConfig),

    /// Oracle Cloud Streaming
    OracleStreaming(OracleStreamingConfig),

    /// Elasticsearch
    Elasticsearch(ElasticsearchConfig),

    /// Splunk HEC
    Splunk(SplunkConfig),

    /// Kafka
    Kafka(KafkaConfig),

    /// Syslog (TCP/UDP/TLS)
    Syslog(SyslogConfig),

    /// HTTP Webhook
    Webhook(WebhookConfig),

    /// Local file
    File(FileConfig),
}

/// Create a sink from configuration
pub async fn create_sink(config: &SinkConfig) -> Result<Arc<dyn AuditSink>, AuditError> {
    match config {
        SinkConfig::AwsCloudwatch(c) => Ok(Arc::new(AwsCloudwatchSink::new(c.clone()).await?)),
        SinkConfig::AwsS3(c) => Ok(Arc::new(AwsS3Sink::new(c.clone()).await?)),
        SinkConfig::AwsSecurityHub(c) => Ok(Arc::new(AwsSecurityHubSink::new(c.clone()).await?)),
        SinkConfig::AwsEventBridge(c) => Ok(Arc::new(AwsEventBridgeSink::new(c.clone()).await?)),
        SinkConfig::AzureMonitor(c) => Ok(Arc::new(AzureMonitorSink::new(c.clone()).await?)),
        SinkConfig::AzureEventHub(c) => Ok(Arc::new(AzureEventHubSink::new(c.clone()).await?)),
        SinkConfig::AzureSentinel(c) => Ok(Arc::new(AzureSentinelSink::new(c.clone()).await?)),
        SinkConfig::OracleLogging(c) => Ok(Arc::new(OracleLoggingSink::new(c.clone()).await?)),
        SinkConfig::OracleStreaming(c) => Ok(Arc::new(OracleStreamingSink::new(c.clone()).await?)),
        SinkConfig::Elasticsearch(c) => Ok(Arc::new(ElasticsearchSink::new(c.clone()).await?)),
        SinkConfig::Splunk(c) => Ok(Arc::new(SplunkSink::new(c.clone()).await?)),
        SinkConfig::Kafka(c) => Ok(Arc::new(KafkaSink::new(c.clone()).await?)),
        SinkConfig::Syslog(c) => Ok(Arc::new(SyslogSink::new(c.clone()).await?)),
        SinkConfig::Webhook(c) => Ok(Arc::new(WebhookSink::new(c.clone()).await?)),
        SinkConfig::File(c) => Ok(Arc::new(FileSink::new(c.clone()).await?)),
    }
}
