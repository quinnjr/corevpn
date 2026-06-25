//! Syslog Audit Sink

use super::{AuditError, AuditEvent, AuditSink};
use crate::audit::formats::{AuditFormat, FormatConfig, FormatEncoder};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Syslog configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogConfig {
    /// Syslog server address
    pub address: String,

    /// Port
    #[serde(default = "default_port")]
    pub port: u16,

    /// Protocol (udp, tcp, tls)
    #[serde(default)]
    pub protocol: SyslogProtocol,

    /// Facility (0-23)
    #[serde(default = "default_facility")]
    pub facility: u8,

    /// App name
    #[serde(default = "default_app_name")]
    pub app_name: String,

    /// TLS CA certificate path (for TLS protocol)
    pub tls_ca_cert: Option<String>,

    /// TLS client certificate path
    pub tls_client_cert: Option<String>,

    /// TLS client key path
    pub tls_client_key: Option<String>,

    /// Skip TLS verification
    #[serde(default)]
    pub tls_insecure: bool,

    /// Use CEF format
    #[serde(default)]
    pub use_cef: bool,

    /// Use LEEF format
    #[serde(default)]
    pub use_leef: bool,

    /// Frame messages with octet counting (RFC 5425)
    #[serde(default)]
    pub octet_counting: bool,

    /// Reconnect on failure
    #[serde(default = "default_true")]
    pub reconnect: bool,

    /// Reconnect interval in seconds
    #[serde(default = "default_reconnect_interval")]
    pub reconnect_interval_secs: u64,
}

fn default_port() -> u16 {
    514
}
fn default_facility() -> u8 {
    4
} // security/auth
fn default_app_name() -> String {
    "corevpn".to_string()
}
fn default_true() -> bool {
    true
}
fn default_reconnect_interval() -> u64 {
    5
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyslogProtocol {
    #[default]
    Udp,
    Tcp,
    Tls,
}

/// Syslog sink
pub struct SyslogSink {
    config: SyslogConfig,
    encoder: FormatEncoder,
    buffer: Arc<Mutex<Vec<String>>>,
}

impl SyslogSink {
    pub async fn new(config: SyslogConfig) -> Result<Self, AuditError> {
        // Determine format based on config
        let format = if config.use_cef {
            AuditFormat::Cef
        } else if config.use_leef {
            AuditFormat::Leef
        } else {
            AuditFormat::Syslog
        };

        let encoder = FormatEncoder::new(FormatConfig {
            format,
            syslog_facility: config.facility,
            syslog_app_name: config.app_name.clone(),
            ..Default::default()
        });

        log::info!(
            "Syslog sink configured: {:?}://{}:{}",
            config.protocol,
            config.address,
            config.port
        );

        Ok(Self {
            config,
            encoder,
            buffer: Arc::new(Mutex::new(Vec::new())),
        })
    }

    fn frame_message(&self, message: &str) -> String {
        if self.config.octet_counting {
            format!("{} {}", message.len(), message)
        } else {
            format!("{}\n", message)
        }
    }

    async fn send_messages(&self, messages: Vec<String>) -> Result<(), AuditError> {
        if messages.is_empty() {
            return Ok(());
        }

        let address = format!("{}:{}", self.config.address, self.config.port);

        for message in &messages {
            let framed = self.frame_message(message);
            log::debug!(
                "Would send syslog message to {}: {} bytes",
                address,
                framed.len()
            );
        }

        // In production, this would:
        // - For UDP: send datagrams
        // - For TCP: maintain a connection and send
        // - For TLS: establish TLS connection and send

        Ok(())
    }
}

#[async_trait]
impl AuditSink for SyslogSink {
    async fn send(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let message = self.encoder.encode(event)?;

        // For UDP, send immediately; for TCP/TLS, buffer
        match self.config.protocol {
            SyslogProtocol::Udp => {
                self.send_messages(vec![message]).await?;
            }
            SyslogProtocol::Tcp | SyslogProtocol::Tls => {
                let mut buffer = self.buffer.lock().await;
                buffer.push(message);

                if buffer.len() >= 10 {
                    let messages = std::mem::take(&mut *buffer);
                    drop(buffer);
                    self.send_messages(messages).await?;
                }
            }
        }

        Ok(())
    }

    async fn flush(&self) -> Result<(), AuditError> {
        let mut buffer = self.buffer.lock().await;
        let messages = std::mem::take(&mut *buffer);
        drop(buffer);
        self.send_messages(messages).await
    }

    async fn close(&self) -> Result<(), AuditError> {
        self.flush().await
    }

    fn name(&self) -> &str {
        "syslog"
    }
}
