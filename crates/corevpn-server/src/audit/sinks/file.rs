//! File Audit Sink

use super::{AuditError, AuditEvent, AuditSink};
use crate::audit::formats::{AuditFormat, FormatConfig, FormatEncoder};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

/// File sink configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileConfig {
    /// File path (supports placeholders: {date}, {hour}, {host})
    pub path: String,

    /// Format configuration
    #[serde(default)]
    pub format: FormatConfig,

    /// Rotation strategy
    #[serde(default)]
    pub rotation: RotationStrategy,

    /// Maximum file size in bytes (for size-based rotation)
    #[serde(default = "default_max_size")]
    pub max_size: u64,

    /// Maximum number of backup files to keep
    #[serde(default = "default_max_files")]
    pub max_files: u32,

    /// Compress rotated files
    #[serde(default)]
    pub compress: bool,

    /// File permissions (octal, e.g., 0o600)
    #[serde(default = "default_permissions")]
    pub permissions: u32,

    /// Sync after each write
    #[serde(default)]
    pub sync_writes: bool,

    /// Buffer size
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
}

fn default_max_size() -> u64 {
    100 * 1024 * 1024
} // 100MB
fn default_max_files() -> u32 {
    10
}
fn default_permissions() -> u32 {
    0o600
}
fn default_buffer_size() -> usize {
    100
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RotationStrategy {
    /// No rotation
    #[default]
    None,
    /// Rotate based on size
    Size,
    /// Rotate daily
    Daily,
    /// Rotate hourly
    Hourly,
    /// Rotate on both size and time
    SizeAndDaily,
}

/// File audit sink
pub struct FileSink {
    config: FileConfig,
    encoder: FormatEncoder,
    buffer: Arc<Mutex<Vec<String>>>,
    current_file: Arc<Mutex<Option<File>>>,
    current_path: Arc<Mutex<PathBuf>>,
    current_size: Arc<Mutex<u64>>,
}

impl FileSink {
    pub async fn new(config: FileConfig) -> Result<Self, AuditError> {
        let format = match config.format.format {
            AuditFormat::Json => AuditFormat::JsonLines,
            other => other,
        };

        let encoder = FormatEncoder::new(FormatConfig {
            format,
            ..config.format.clone()
        });

        let path = Self::resolve_path(&config.path);

        // Create directory if it doesn't exist
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        log::info!("File sink configured: {}", path.display());

        Ok(Self {
            config,
            encoder,
            buffer: Arc::new(Mutex::new(Vec::new())),
            current_file: Arc::new(Mutex::new(None)),
            current_path: Arc::new(Mutex::new(path)),
            current_size: Arc::new(Mutex::new(0)),
        })
    }

    fn resolve_path(template: &str) -> PathBuf {
        let now = chrono::Utc::now();
        let path = template
            .replace("{date}", &now.format("%Y-%m-%d").to_string())
            .replace("{hour}", &now.format("%H").to_string())
            .replace(
                "{host}",
                &hostname::get()
                    .map(|h| h.to_string_lossy().to_string())
                    .unwrap_or_else(|_| "unknown".to_string()),
            );
        PathBuf::from(path)
    }

    async fn get_or_open_file(&self) -> Result<(), AuditError> {
        let mut file_guard = self.current_file.lock().await;
        let mut path_guard = self.current_path.lock().await;

        // Check if we need to rotate based on time
        let new_path = Self::resolve_path(&self.config.path);
        if *path_guard != new_path {
            // Close current file and open new one
            if let Some(ref mut f) = *file_guard {
                f.flush().await?;
            }
            *file_guard = None;
            *path_guard = new_path;
            *self.current_size.lock().await = 0;
        }

        // Open file if not already open
        if file_guard.is_none() {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&*path_guard)
                .await?;

            let metadata = file.metadata().await?;
            *self.current_size.lock().await = metadata.len();
            *file_guard = Some(file);
        }

        Ok(())
    }

    async fn check_rotation(&self) -> Result<bool, AuditError> {
        match self.config.rotation {
            RotationStrategy::Size | RotationStrategy::SizeAndDaily => {
                let size = *self.current_size.lock().await;
                Ok(size >= self.config.max_size)
            }
            _ => Ok(false),
        }
    }

    async fn rotate(&self) -> Result<(), AuditError> {
        let mut file_guard = self.current_file.lock().await;
        let path_guard = self.current_path.lock().await;

        // Close current file
        if let Some(ref mut f) = *file_guard {
            f.flush().await?;
        }
        *file_guard = None;

        // Rotate existing backup files
        for i in (1..self.config.max_files).rev() {
            let old_path = format!("{}.{}", path_guard.display(), i);
            let new_path = format!("{}.{}", path_guard.display(), i + 1);

            if tokio::fs::metadata(&old_path).await.is_ok() {
                let _ = tokio::fs::rename(&old_path, &new_path).await;
            }
        }

        // Rename current file to .1
        let backup_path = format!("{}.1", path_guard.display());
        let _ = tokio::fs::rename(&*path_guard, &backup_path).await;

        // Reset size counter
        *self.current_size.lock().await = 0;

        log::debug!("Rotated log file: {}", path_guard.display());

        Ok(())
    }

    async fn write_lines(&self, lines: Vec<String>) -> Result<(), AuditError> {
        if lines.is_empty() {
            return Ok(());
        }

        // Check if rotation is needed
        if self.check_rotation().await? {
            self.rotate().await?;
        }

        // Ensure file is open
        self.get_or_open_file().await?;

        let mut file_guard = self.current_file.lock().await;
        let mut size_guard = self.current_size.lock().await;

        if let Some(ref mut file) = *file_guard {
            for line in lines {
                let bytes = line.as_bytes();
                file.write_all(bytes).await?;
                *size_guard += bytes.len() as u64;
            }

            if self.config.sync_writes {
                file.flush().await?;
            }
        }

        Ok(())
    }
}

#[async_trait]
impl AuditSink for FileSink {
    async fn send(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let line = self.encoder.encode(event)?;

        let mut buffer = self.buffer.lock().await;
        buffer.push(line);

        if buffer.len() >= self.config.buffer_size {
            let lines = std::mem::take(&mut *buffer);
            drop(buffer);
            self.write_lines(lines).await?;
        }

        Ok(())
    }

    async fn flush(&self) -> Result<(), AuditError> {
        // Flush buffer
        let mut buffer = self.buffer.lock().await;
        let lines = std::mem::take(&mut *buffer);
        drop(buffer);
        self.write_lines(lines).await?;

        // Flush file
        let mut file_guard = self.current_file.lock().await;
        if let Some(ref mut file) = *file_guard {
            file.flush().await?;
        }

        Ok(())
    }

    async fn close(&self) -> Result<(), AuditError> {
        self.flush().await?;

        let mut file_guard = self.current_file.lock().await;
        *file_guard = None;

        Ok(())
    }

    fn name(&self) -> &str {
        "file"
    }
}
