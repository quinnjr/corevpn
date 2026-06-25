//! Audit Event Format Encoders
//!
//! Supports multiple formats for SIEM compatibility:
//! - JSON (default)
//! - CEF (Common Event Format) - ArcSight, many SIEMs
//! - LEEF (Log Event Extended Format) - IBM QRadar
//! - Syslog (RFC 5424)
//! - AWS CloudWatch Logs format
//! - Azure Monitor format
//! - OCSF (Open Cybersecurity Schema Framework)

use super::events::{AuditEvent, AuditSeverity};
use chrono::SecondsFormat;
use serde::{Deserialize, Serialize};

/// Supported audit log formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AuditFormat {
    /// JSON format (default)
    #[default]
    Json,
    /// JSON Lines format (one JSON object per line)
    JsonLines,
    /// Common Event Format (CEF)
    Cef,
    /// Log Event Extended Format (LEEF)
    Leef,
    /// Syslog RFC 5424
    Syslog,
    /// AWS CloudWatch Logs
    CloudWatch,
    /// Azure Monitor
    AzureMonitor,
    /// Open Cybersecurity Schema Framework
    Ocsf,
}

/// Format configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatConfig {
    /// Output format
    #[serde(default)]
    pub format: AuditFormat,

    /// Pretty print JSON (for debugging)
    #[serde(default)]
    pub pretty: bool,

    /// Include null fields
    #[serde(default)]
    pub include_nulls: bool,

    /// CEF device vendor
    #[serde(default = "default_vendor")]
    pub cef_vendor: String,

    /// CEF device product
    #[serde(default = "default_product")]
    pub cef_product: String,

    /// CEF device version
    #[serde(default = "default_version")]
    pub cef_version: String,

    /// Syslog facility (0-23)
    #[serde(default = "default_facility")]
    pub syslog_facility: u8,

    /// Syslog app name
    #[serde(default = "default_app_name")]
    pub syslog_app_name: String,
}

fn default_vendor() -> String {
    "PegasusHeavy".to_string()
}
fn default_product() -> String {
    "CoreVPN".to_string()
}
fn default_version() -> String {
    "1.0".to_string()
}
fn default_facility() -> u8 {
    4
} // security/auth
fn default_app_name() -> String {
    "corevpn".to_string()
}

impl Default for FormatConfig {
    fn default() -> Self {
        Self {
            format: AuditFormat::Json,
            pretty: false,
            include_nulls: false,
            cef_vendor: default_vendor(),
            cef_product: default_product(),
            cef_version: default_version(),
            syslog_facility: default_facility(),
            syslog_app_name: default_app_name(),
        }
    }
}

/// Format encoder
pub struct FormatEncoder {
    config: FormatConfig,
}

impl FormatEncoder {
    pub fn new(config: FormatConfig) -> Self {
        Self { config }
    }

    /// Encode an event to the configured format
    pub fn encode(&self, event: &AuditEvent) -> Result<String, super::AuditError> {
        match self.config.format {
            AuditFormat::Json => self.encode_json(event),
            AuditFormat::JsonLines => self.encode_json_lines(event),
            AuditFormat::Cef => self.encode_cef(event),
            AuditFormat::Leef => self.encode_leef(event),
            AuditFormat::Syslog => self.encode_syslog(event),
            AuditFormat::CloudWatch => self.encode_cloudwatch(event),
            AuditFormat::AzureMonitor => self.encode_azure_monitor(event),
            AuditFormat::Ocsf => self.encode_ocsf(event),
        }
    }

    fn encode_json(&self, event: &AuditEvent) -> Result<String, super::AuditError> {
        if self.config.pretty {
            serde_json::to_string_pretty(event).map_err(Into::into)
        } else {
            serde_json::to_string(event).map_err(Into::into)
        }
    }

    fn encode_json_lines(&self, event: &AuditEvent) -> Result<String, super::AuditError> {
        let json = serde_json::to_string(event)?;
        Ok(format!("{}\n", json))
    }

    /// Encode to Common Event Format (CEF)
    /// Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    fn encode_cef(&self, event: &AuditEvent) -> Result<String, super::AuditError> {
        let severity = event.severity.to_cef_severity();
        let signature_id = format!("{}.{}", event.category.as_str(), event.action);

        // Build extension fields
        let mut extensions = Vec::new();

        extensions.push(format!("rt={}", event.timestamp.timestamp_millis()));
        extensions.push(format!("msg={}", escape_cef(&event.message)));
        extensions.push(format!("outcome={:?}", event.outcome));
        extensions.push(format!("cat={}", event.category.as_str()));

        if let Some(ref actor) = event.actor {
            if let Some(ref name) = actor.name {
                extensions.push(format!("suser={}", escape_cef(name)));
            }
            if let Some(ref ip) = actor.source_ip {
                extensions.push(format!("src={}", ip));
            }
            if let Some(ref session) = actor.session_id {
                extensions.push(format!("sproc={}", escape_cef(session)));
            }
        }

        if let Some(ref target) = event.target {
            if let Some(ref id) = target.id {
                extensions.push(format!("duid={}", escape_cef(id)));
            }
            if let Some(ref name) = target.name {
                extensions.push(format!("duser={}", escape_cef(name)));
            }
        }

        extensions.push(format!("dvchost={}", escape_cef(&event.host)));
        extensions.push(format!("externalId={}", &event.id));

        let extension_str = extensions.join(" ");

        Ok(format!(
            "CEF:0|{}|{}|{}|{}|{}|{}|{}",
            escape_cef(&self.config.cef_vendor),
            escape_cef(&self.config.cef_product),
            escape_cef(&self.config.cef_version),
            escape_cef(&signature_id),
            escape_cef(&event.action),
            severity,
            extension_str
        ))
    }

    /// Encode to Log Event Extended Format (LEEF) for IBM QRadar
    /// Format: LEEF:Version|Vendor|Product|Version|EventID|Extension
    fn encode_leef(&self, event: &AuditEvent) -> Result<String, super::AuditError> {
        let event_id = format!("{}.{}", event.category.as_str(), event.action);

        let mut extensions = Vec::new();

        extensions.push(format!(
            "devTime={}",
            event.timestamp.to_rfc3339_opts(SecondsFormat::Millis, true)
        ));
        extensions.push(format!("cat={}", event.category.as_str()));
        extensions.push(format!("sev={}", event.severity.to_cef_severity()));
        extensions.push(format!("msg={}", escape_leef(&event.message)));

        if let Some(ref actor) = event.actor {
            if let Some(ref name) = actor.name {
                extensions.push(format!("usrName={}", escape_leef(name)));
            }
            if let Some(ref ip) = actor.source_ip {
                extensions.push(format!("src={}", ip));
            }
        }

        extensions.push(format!("identHostName={}", escape_leef(&event.host)));

        let extension_str = extensions.join("\t");

        Ok(format!(
            "LEEF:2.0|{}|{}|{}|{}|{}",
            escape_leef(&self.config.cef_vendor),
            escape_leef(&self.config.cef_product),
            escape_leef(&self.config.cef_version),
            escape_leef(&event_id),
            extension_str
        ))
    }

    /// Encode to Syslog RFC 5424 format
    fn encode_syslog(&self, event: &AuditEvent) -> Result<String, super::AuditError> {
        let facility = self.config.syslog_facility;
        let severity = event.severity.to_syslog_severity();
        let priority = (facility * 8) + severity;

        let timestamp = event.timestamp.to_rfc3339_opts(SecondsFormat::Micros, true);
        let msg_id = format!("{}.{}", event.category.as_str(), event.action);

        // Build structured data
        let mut sd = String::new();
        sd.push_str(&format!(
            "[corevpn@32473 eventId=\"{}\" outcome=\"{:?}\" category=\"{}\"]",
            event.id,
            event.outcome,
            event.category.as_str()
        ));

        if let Some(ref actor) = event.actor {
            sd.push_str(&format!("[actor@32473 type=\"{}\"", actor.actor_type));
            if let Some(ref name) = actor.name {
                sd.push_str(&format!(" name=\"{}\"", escape_syslog_sd(name)));
            }
            if let Some(ref ip) = actor.source_ip {
                sd.push_str(&format!(" sourceIp=\"{}\"", ip));
            }
            sd.push(']');
        }

        Ok(format!(
            "<{}>1 {} {} {} - {} {} {}",
            priority, timestamp, event.host, self.config.syslog_app_name, msg_id, sd, event.message
        ))
    }

    /// Encode for AWS CloudWatch Logs
    fn encode_cloudwatch(&self, event: &AuditEvent) -> Result<String, super::AuditError> {
        #[derive(Serialize)]
        struct CloudWatchEvent<'a> {
            timestamp: i64,
            message: &'a str,
            #[serde(flatten)]
            event: &'a AuditEvent,
        }

        let cw_event = CloudWatchEvent {
            timestamp: event.timestamp.timestamp_millis(),
            message: &event.message,
            event,
        };

        serde_json::to_string(&cw_event).map_err(Into::into)
    }

    /// Encode for Azure Monitor / Log Analytics
    fn encode_azure_monitor(&self, event: &AuditEvent) -> Result<String, super::AuditError> {
        #[derive(Serialize)]
        #[serde(rename_all = "PascalCase")]
        struct AzureMonitorEvent<'a> {
            time_generated: String,
            source_system: &'static str,
            category: &'a str,
            operation_name: &'a str,
            result_type: &'a str,
            caller_ip_address: Option<&'a str>,
            caller_identity: Option<&'a str>,
            resource_id: Option<&'a str>,
            #[serde(flatten)]
            properties: &'a AuditEvent,
        }

        let result_type = match event.outcome {
            super::events::AuditOutcome::Success => "Success",
            super::events::AuditOutcome::Failure => "Failure",
            super::events::AuditOutcome::Unknown => "Unknown",
        };

        let caller_ip = event.actor.as_ref().and_then(|a| a.source_ip.as_deref());
        let caller_id = event.actor.as_ref().and_then(|a| a.name.as_deref());
        let resource_id = event.target.as_ref().and_then(|t| t.id.as_deref());

        let az_event = AzureMonitorEvent {
            time_generated: event.timestamp.to_rfc3339_opts(SecondsFormat::Millis, true),
            source_system: "CoreVPN",
            category: event.category.as_str(),
            operation_name: &event.action,
            result_type,
            caller_ip_address: caller_ip,
            caller_identity: caller_id,
            resource_id,
            properties: event,
        };

        serde_json::to_string(&az_event).map_err(Into::into)
    }

    /// Encode to OCSF (Open Cybersecurity Schema Framework)
    fn encode_ocsf(&self, event: &AuditEvent) -> Result<String, super::AuditError> {
        #[derive(Serialize)]
        struct OcsfEvent<'a> {
            class_uid: u32,
            class_name: &'static str,
            category_uid: u32,
            category_name: &'a str,
            severity_id: u8,
            activity_id: u8,
            activity_name: &'a str,
            status_id: u8,
            message: &'a str,
            time: i64,
            timezone_offset: i32,
            metadata: OcsfMetadata<'a>,
            actor: Option<OcsfActor<'a>>,
            #[serde(flatten)]
            raw_data: &'a AuditEvent,
        }

        #[derive(Serialize)]
        struct OcsfMetadata<'a> {
            version: &'static str,
            product: OcsfProduct,
            uid: &'a str,
        }

        #[derive(Serialize)]
        struct OcsfProduct {
            name: &'static str,
            vendor_name: &'static str,
            version: &'static str,
        }

        #[derive(Serialize)]
        struct OcsfActor<'a> {
            user: Option<OcsfUser<'a>>,
        }

        #[derive(Serialize)]
        struct OcsfUser<'a> {
            name: Option<&'a str>,
            uid: Option<&'a str>,
        }

        let (class_uid, class_name) = match event.category {
            super::events::AuditCategory::Authentication => (3002, "Authentication"),
            super::events::AuditCategory::Authorization => (3003, "Authorization"),
            super::events::AuditCategory::Network | super::events::AuditCategory::Connection => {
                (4001, "Network Activity")
            }
            super::events::AuditCategory::Configuration => (5001, "Configuration"),
            _ => (1001, "Security Finding"),
        };

        let severity_id = match event.severity {
            AuditSeverity::Info => 1,
            AuditSeverity::Low => 2,
            AuditSeverity::Medium => 3,
            AuditSeverity::High => 4,
            AuditSeverity::Critical => 5,
        };

        let status_id = match event.outcome {
            super::events::AuditOutcome::Success => 1,
            super::events::AuditOutcome::Failure => 2,
            super::events::AuditOutcome::Unknown => 0,
        };

        let actor = event.actor.as_ref().map(|a| OcsfActor {
            user: Some(OcsfUser {
                name: a.name.as_deref(),
                uid: a.id.as_deref(),
            }),
        });

        let ocsf = OcsfEvent {
            class_uid,
            class_name,
            category_uid: class_uid / 1000,
            category_name: event.category.as_str(),
            severity_id,
            activity_id: 1,
            activity_name: &event.action,
            status_id,
            message: &event.message,
            time: event.timestamp.timestamp_millis(),
            timezone_offset: 0,
            metadata: OcsfMetadata {
                version: "1.0.0",
                product: OcsfProduct {
                    name: "CoreVPN",
                    vendor_name: "Pegasus Heavy Industries",
                    version: "0.1.0",
                },
                uid: &event.id,
            },
            actor,
            raw_data: event,
        };

        serde_json::to_string(&ocsf).map_err(Into::into)
    }
}

// Escape special characters for CEF format
fn escape_cef(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('=', "\\=")
}

// Escape special characters for LEEF format
fn escape_leef(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

// Escape special characters for syslog structured data
fn escape_syslog_sd(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(']', "\\]")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::events::AuditEventBuilder;

    #[test]
    fn test_json_encoding() {
        let event =
            AuditEventBuilder::auth_success("testuser", Some("192.168.1.1".into()), "password")
                .build();

        let encoder = FormatEncoder::new(FormatConfig::default());
        let json = encoder.encode(&event).unwrap();

        assert!(json.contains("testuser"));
        assert!(json.contains("auth.success"));
    }

    #[test]
    fn test_cef_encoding() {
        let event =
            AuditEventBuilder::auth_success("testuser", Some("192.168.1.1".into()), "password")
                .build();

        let encoder = FormatEncoder::new(FormatConfig {
            format: AuditFormat::Cef,
            ..Default::default()
        });
        let cef = encoder.encode(&event).unwrap();

        assert!(cef.starts_with("CEF:0|"));
        assert!(cef.contains("suser=testuser"));
        assert!(cef.contains("src=192.168.1.1"));
    }

    #[test]
    fn test_syslog_encoding() {
        let event =
            AuditEventBuilder::auth_failure("baduser", Some("10.0.0.1".into()), "invalid password")
                .build();

        let encoder = FormatEncoder::new(FormatConfig {
            format: AuditFormat::Syslog,
            ..Default::default()
        });
        let syslog = encoder.encode(&event).unwrap();

        assert!(syslog.starts_with("<"));
        assert!(syslog.contains("[corevpn@32473"));
    }
}
