//! CoreVPN Configuration Management
//!
//! Handles server configuration, client config generation, and persistence.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod client;
pub mod generator;
pub mod server;

pub use client::{ClientConfig, ClientConfigBuilder};
pub use generator::ConfigGenerator;
pub use server::{
    AuditSettings, AuditSinkConfig, ConnectionLogAnonymization, ConnectionLogEvents,
    ConnectionLogMode, ConnectionLogRetention, LoggingSettings, ServerConfig,
};

use thiserror::Error;

/// Configuration error
#[derive(Debug, Error)]
pub enum ConfigError {
    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Serialization error
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Validation error
    #[error("validation error: {0}")]
    ValidationError(String),

    /// Missing required field
    #[error("missing required field: {0}")]
    MissingField(String),
}

/// Result type for config operations
pub type Result<T> = std::result::Result<T, ConfigError>;

impl From<toml::de::Error> for ConfigError {
    fn from(err: toml::de::Error) -> Self {
        ConfigError::SerializationError(err.to_string())
    }
}

impl From<toml::ser::Error> for ConfigError {
    fn from(err: toml::ser::Error) -> Self {
        ConfigError::SerializationError(err.to_string())
    }
}
