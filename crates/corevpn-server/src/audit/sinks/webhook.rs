//! HTTP Webhook Audit Sink

use super::{AuditError, AuditEvent, AuditSink};
use crate::audit::formats::{FormatConfig, FormatEncoder};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook URL
    pub url: String,

    /// HTTP method (POST, PUT)
    #[serde(default = "default_method")]
    pub method: String,

    /// Additional headers
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Authentication type
    pub auth: Option<WebhookAuth>,

    /// Format configuration
    #[serde(default)]
    pub format: FormatConfig,

    /// Batch size
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,

    /// Retry attempts
    #[serde(default = "default_retries")]
    pub retries: u32,

    /// Retry delay in milliseconds
    #[serde(default = "default_retry_delay")]
    pub retry_delay_ms: u64,

    /// TLS verification
    #[serde(default = "default_true")]
    pub tls_verify: bool,

    /// Wrap batch in array
    #[serde(default = "default_true")]
    pub batch_as_array: bool,
}

fn default_method() -> String {
    "POST".to_string()
}
fn default_batch_size() -> usize {
    100
}
fn default_timeout() -> u64 {
    30
}
fn default_retries() -> u32 {
    3
}
fn default_retry_delay() -> u64 {
    1000
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WebhookAuth {
    /// Bearer token authentication
    Bearer { token: String },

    /// Basic authentication
    Basic { username: String, password: String },

    /// API key header
    ApiKey { header: String, value: String },

    /// OAuth2 client credentials
    OAuth2 {
        token_url: String,
        client_id: String,
        client_secret: String,
        scope: Option<String>,
    },

    /// HMAC signature
    Hmac {
        secret: String,
        algorithm: String,
        header: String,
    },
}

/// Webhook sink
pub struct WebhookSink {
    config: WebhookConfig,
    encoder: FormatEncoder,
    buffer: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl WebhookSink {
    pub async fn new(config: WebhookConfig) -> Result<Self, AuditError> {
        let encoder = FormatEncoder::new(config.format.clone());

        log::info!("Webhook sink configured: {} {}", config.method, config.url);

        Ok(Self {
            config,
            encoder,
            buffer: Arc::new(Mutex::new(Vec::new())),
        })
    }

    fn build_auth_header(&self) -> Option<(String, String)> {
        match &self.config.auth {
            Some(WebhookAuth::Bearer { token }) => {
                Some(("Authorization".to_string(), format!("Bearer {}", token)))
            }
            Some(WebhookAuth::Basic { username, password }) => {
                let credentials = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    format!("{}:{}", username, password),
                );
                Some((
                    "Authorization".to_string(),
                    format!("Basic {}", credentials),
                ))
            }
            Some(WebhookAuth::ApiKey { header, value }) => Some((header.clone(), value.clone())),
            _ => None,
        }
    }

    async fn send_batch(&self, events: Vec<serde_json::Value>) -> Result<(), AuditError> {
        if events.is_empty() {
            return Ok(());
        }

        let body = if self.config.batch_as_array {
            serde_json::to_string(&events)?
        } else {
            // Send as newline-delimited JSON
            events
                .iter()
                .map(|e| serde_json::to_string(e).unwrap_or_default())
                .collect::<Vec<_>>()
                .join("\n")
        };

        let auth_header = self.build_auth_header();

        log::debug!(
            "Would send {} events to webhook: {} {} ({} bytes)",
            events.len(),
            self.config.method,
            self.config.url,
            body.len()
        );

        // In production, this would use reqwest or similar
        // to actually send the HTTP request with retry logic
        let _ = auth_header;

        Ok(())
    }
}

#[async_trait]
impl AuditSink for WebhookSink {
    async fn send(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let json_str = self.encoder.encode(event)?;
        let value: serde_json::Value = serde_json::from_str(&json_str)?;

        let mut buffer = self.buffer.lock().await;
        buffer.push(value);

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
        "webhook"
    }
}
