//! Kafka Audit Sink

use super::{AuditError, AuditEvent, AuditSink};
use crate::audit::formats::{FormatConfig, FormatEncoder};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Kafka configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KafkaConfig {
    /// Kafka bootstrap servers
    pub brokers: Vec<String>,

    /// Topic name
    pub topic: String,

    /// Partition key field from event (e.g., "actor.source_ip")
    pub partition_key: Option<String>,

    /// SASL mechanism (PLAIN, SCRAM-SHA-256, SCRAM-SHA-512)
    pub sasl_mechanism: Option<String>,

    /// SASL username
    pub sasl_username: Option<String>,

    /// SASL password
    pub sasl_password: Option<String>,

    /// Enable TLS
    #[serde(default)]
    pub tls_enabled: bool,

    /// TLS CA certificate path
    pub tls_ca_cert: Option<String>,

    /// TLS client certificate path
    pub tls_client_cert: Option<String>,

    /// TLS client key path
    pub tls_client_key: Option<String>,

    /// Format configuration
    #[serde(default)]
    pub format: FormatConfig,

    /// Batch size
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Compression (none, gzip, snappy, lz4, zstd)
    #[serde(default)]
    pub compression: Option<String>,

    /// Required acknowledgments (0, 1, all)
    #[serde(default = "default_acks")]
    pub acks: String,

    /// Linger time in ms
    #[serde(default = "default_linger")]
    pub linger_ms: u32,
}

fn default_batch_size() -> usize {
    100
}
fn default_acks() -> String {
    "all".to_string()
}
fn default_linger() -> u32 {
    5
}

// Fields retained for future Kafka message keying/payload wiring.
#[allow(dead_code)]
struct KafkaMessage {
    key: Option<String>,
    value: String,
}

/// Kafka sink
pub struct KafkaSink {
    config: KafkaConfig,
    encoder: FormatEncoder,
    buffer: Arc<Mutex<Vec<KafkaMessage>>>,
}

impl KafkaSink {
    pub async fn new(config: KafkaConfig) -> Result<Self, AuditError> {
        let encoder = FormatEncoder::new(config.format.clone());

        // In production, this would initialize the Kafka producer
        log::info!(
            "Kafka sink configured for topic: {} on brokers: {:?}",
            config.topic,
            config.brokers
        );

        Ok(Self {
            config,
            encoder,
            buffer: Arc::new(Mutex::new(Vec::new())),
        })
    }

    fn extract_partition_key(&self, event: &AuditEvent) -> Option<String> {
        self.config.partition_key.as_ref().and_then(|key_path| {
            // Simple path extraction (production would use a proper JSON path library)
            match key_path.as_str() {
                "id" => Some(event.id.clone()),
                "category" => Some(event.category.as_str().to_string()),
                "actor.source_ip" => event.actor.as_ref()?.source_ip.clone(),
                "actor.name" => event.actor.as_ref()?.name.clone(),
                _ => None,
            }
        })
    }

    async fn send_batch(&self, messages: Vec<KafkaMessage>) -> Result<(), AuditError> {
        if messages.is_empty() {
            return Ok(());
        }

        log::debug!(
            "Would send {} messages to Kafka topic: {}",
            messages.len(),
            self.config.topic
        );

        // In production, this would use rdkafka or similar
        // to actually produce messages

        Ok(())
    }
}

#[async_trait]
impl AuditSink for KafkaSink {
    async fn send(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let key = self.extract_partition_key(event);
        let value = self.encoder.encode(event)?;

        let mut buffer = self.buffer.lock().await;
        buffer.push(KafkaMessage { key, value });

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
        "kafka"
    }
}
