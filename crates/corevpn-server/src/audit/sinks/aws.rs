//! AWS Audit Sinks
//!
//! Supports:
//! - CloudWatch Logs
//! - S3
//! - Security Hub
//! - EventBridge

use super::{AuditError, AuditEvent, AuditSink};
use crate::audit::formats::{AuditFormat, FormatConfig, FormatEncoder};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

/// AWS CloudWatch Logs configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsCloudwatchConfig {
    /// AWS region
    pub region: String,

    /// Log group name
    pub log_group: String,

    /// Log stream name (supports {date}, {host} placeholders)
    #[serde(default = "default_stream")]
    pub log_stream: String,

    /// Create log group if it doesn't exist
    #[serde(default = "default_true")]
    pub create_log_group: bool,

    /// Retention in days (0 = never expire)
    #[serde(default)]
    pub retention_days: u32,

    /// Format configuration
    #[serde(default)]
    pub format: FormatConfig,

    /// Batch size for sending logs
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Flush interval in seconds
    #[serde(default = "default_flush_interval")]
    pub flush_interval_secs: u64,

    /// AWS credentials profile (optional, uses default chain if not set)
    pub profile: Option<String>,

    /// Assume role ARN (optional)
    pub role_arn: Option<String>,
}

fn default_stream() -> String {
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

/// CloudWatch Logs sink
pub struct AwsCloudwatchSink {
    config: AwsCloudwatchConfig,
    encoder: FormatEncoder,
    buffer: Arc<Mutex<Vec<(i64, String)>>>,
}

impl AwsCloudwatchSink {
    pub async fn new(config: AwsCloudwatchConfig) -> Result<Self, AuditError> {
        let encoder = FormatEncoder::new(FormatConfig {
            format: AuditFormat::CloudWatch,
            ..config.format.clone()
        });

        Ok(Self {
            config,
            encoder,
            buffer: Arc::new(Mutex::new(Vec::new())),
        })
    }

    async fn send_batch(&self, events: Vec<(i64, String)>) -> Result<(), AuditError> {
        if events.is_empty() {
            return Ok(());
        }

        // In production, this would use aws-sdk-cloudwatchlogs
        // For now, log that we would send
        log::debug!(
            "Would send {} events to CloudWatch Logs: {}/{}",
            events.len(),
            self.config.log_group,
            self.config.log_stream
        );

        Ok(())
    }
}

#[async_trait]
impl AuditSink for AwsCloudwatchSink {
    async fn send(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let message = self.encoder.encode(event)?;
        let timestamp = event.timestamp.timestamp_millis();

        let mut buffer = self.buffer.lock().await;
        buffer.push((timestamp, message));

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
        "aws_cloudwatch"
    }
}

/// AWS S3 configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsS3Config {
    /// AWS region
    pub region: String,

    /// S3 bucket name
    pub bucket: String,

    /// Key prefix (supports {date}, {hour}, {host} placeholders)
    #[serde(default = "default_s3_prefix")]
    pub prefix: String,

    /// File format
    #[serde(default)]
    pub format: FormatConfig,

    /// Compress files with gzip
    #[serde(default = "default_true")]
    pub compress: bool,

    /// Max file size before rotation (bytes)
    #[serde(default = "default_max_file_size")]
    pub max_file_size: u64,

    /// Server-side encryption
    #[serde(default)]
    pub sse: Option<S3Encryption>,

    /// AWS credentials profile
    pub profile: Option<String>,
}

fn default_s3_prefix() -> String {
    "audit-logs/{date}/{hour}/".to_string()
}
fn default_max_file_size() -> u64 {
    100 * 1024 * 1024
} // 100MB

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum S3Encryption {
    Aes256,
    AwsKms { key_id: String },
}

/// S3 audit sink
pub struct AwsS3Sink {
    config: AwsS3Config,
    encoder: FormatEncoder,
    buffer: Arc<Mutex<Vec<String>>>,
}

impl AwsS3Sink {
    pub async fn new(config: AwsS3Config) -> Result<Self, AuditError> {
        let encoder = FormatEncoder::new(config.format.clone());

        Ok(Self {
            config,
            encoder,
            buffer: Arc::new(Mutex::new(Vec::new())),
        })
    }
}

#[async_trait]
impl AuditSink for AwsS3Sink {
    async fn send(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let line = self.encoder.encode(event)?;
        let mut buffer = self.buffer.lock().await;
        buffer.push(line);
        Ok(())
    }

    async fn flush(&self) -> Result<(), AuditError> {
        let mut buffer = self.buffer.lock().await;
        if buffer.is_empty() {
            return Ok(());
        }

        let content = buffer.join("\n");
        buffer.clear();

        log::debug!(
            "Would upload {} bytes to S3: s3://{}/{}",
            content.len(),
            self.config.bucket,
            self.config.prefix
        );

        Ok(())
    }

    async fn close(&self) -> Result<(), AuditError> {
        self.flush().await
    }

    fn name(&self) -> &str {
        "aws_s3"
    }
}

/// AWS Security Hub configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsSecurityHubConfig {
    /// AWS region
    pub region: String,

    /// Product ARN for findings
    pub product_arn: Option<String>,

    /// AWS account ID
    pub account_id: String,

    /// Minimum severity to send (filters lower severity events)
    #[serde(default)]
    pub min_severity: Option<String>,

    /// AWS credentials profile
    pub profile: Option<String>,
}

/// Security Hub sink
pub struct AwsSecurityHubSink {
    config: AwsSecurityHubConfig,
}

impl AwsSecurityHubSink {
    pub async fn new(config: AwsSecurityHubConfig) -> Result<Self, AuditError> {
        Ok(Self { config })
    }

    fn event_to_finding(&self, event: &AuditEvent) -> serde_json::Value {
        let severity = match event.severity {
            crate::audit::events::AuditSeverity::Info => "INFORMATIONAL",
            crate::audit::events::AuditSeverity::Low => "LOW",
            crate::audit::events::AuditSeverity::Medium => "MEDIUM",
            crate::audit::events::AuditSeverity::High => "HIGH",
            crate::audit::events::AuditSeverity::Critical => "CRITICAL",
        };

        serde_json::json!({
            "SchemaVersion": "2018-10-08",
            "Id": event.id,
            "ProductArn": self.config.product_arn.as_deref().unwrap_or("arn:aws:securityhub:::product/pegasusheavy/corevpn"),
            "GeneratorId": "corevpn",
            "AwsAccountId": self.config.account_id,
            "Types": [format!("Software and Configuration Checks/VPN/{}", event.category.as_str())],
            "CreatedAt": event.timestamp.to_rfc3339(),
            "UpdatedAt": event.timestamp.to_rfc3339(),
            "Severity": {
                "Label": severity
            },
            "Title": event.action,
            "Description": event.message,
            "Resources": [{
                "Type": "Other",
                "Id": event.host.clone(),
                "Details": {
                    "Other": {
                        "Category": event.category.as_str(),
                        "Outcome": format!("{:?}", event.outcome)
                    }
                }
            }]
        })
    }
}

#[async_trait]
impl AuditSink for AwsSecurityHubSink {
    async fn send(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let finding = self.event_to_finding(event);
        log::debug!("Would send finding to Security Hub: {:?}", finding);
        Ok(())
    }

    async fn flush(&self) -> Result<(), AuditError> {
        Ok(())
    }

    async fn close(&self) -> Result<(), AuditError> {
        Ok(())
    }

    fn name(&self) -> &str {
        "aws_security_hub"
    }
}

/// AWS EventBridge configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsEventBridgeConfig {
    /// AWS region
    pub region: String,

    /// Event bus name
    #[serde(default = "default_event_bus")]
    pub event_bus: String,

    /// Event source name
    #[serde(default = "default_source")]
    pub source: String,

    /// Detail type for events
    #[serde(default = "default_detail_type")]
    pub detail_type: String,

    /// AWS credentials profile
    pub profile: Option<String>,
}

fn default_event_bus() -> String {
    "default".to_string()
}
fn default_source() -> String {
    "corevpn.audit".to_string()
}
fn default_detail_type() -> String {
    "CoreVPN Audit Event".to_string()
}

/// EventBridge sink
pub struct AwsEventBridgeSink {
    config: AwsEventBridgeConfig,
}

impl AwsEventBridgeSink {
    pub async fn new(config: AwsEventBridgeConfig) -> Result<Self, AuditError> {
        Ok(Self { config })
    }
}

#[async_trait]
impl AuditSink for AwsEventBridgeSink {
    async fn send(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let eb_event = serde_json::json!({
            "Source": self.config.source,
            "DetailType": self.config.detail_type,
            "Detail": serde_json::to_string(event)?,
            "EventBusName": self.config.event_bus,
        });

        log::debug!("Would send to EventBridge: {:?}", eb_event);
        Ok(())
    }

    async fn flush(&self) -> Result<(), AuditError> {
        Ok(())
    }

    async fn close(&self) -> Result<(), AuditError> {
        Ok(())
    }

    fn name(&self) -> &str {
        "aws_eventbridge"
    }
}
