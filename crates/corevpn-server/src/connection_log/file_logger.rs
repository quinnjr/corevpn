//! File-Based Connection Logger
//!
//! Logs connection events to append-only files with rotation support.
//! Supports secure deletion for paranoid mode.

use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use tokio::fs;
use tracing::{debug, warn};

use super::events::{ConnectionEvent, ConnectionId};
use super::logger::{ConnectionLogger, LoggerStats};

/// File-based connection logger with rotation
pub struct FileConnectionLogger {
    /// Path to the log file
    path: PathBuf,
    /// Maximum file size before rotation (bytes)
    max_size: u64,
    /// Number of rotated files to keep
    max_files: usize,
    /// Use secure deletion
    secure_delete: bool,
    /// Current log file writer
    writer: Arc<Mutex<Option<BufWriter<std::fs::File>>>>,
    /// Total events logged
    total_logged: AtomicU64,
    /// Pending events (since last flush)
    pending: AtomicU64,
    /// First event timestamp
    first_event: parking_lot::RwLock<Option<DateTime<Utc>>>,
    /// Last event timestamp
    last_event: parking_lot::RwLock<Option<DateTime<Utc>>>,
}

impl FileConnectionLogger {
    pub async fn new(
        path: PathBuf,
        max_size: u64,
        max_files: usize,
        secure_delete: bool,
    ) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .context("Failed to create log directory")?;
        }

        let logger = Self {
            path,
            max_size: max_size.max(1024 * 1024), // Minimum 1MB
            max_files: max_files.max(1),
            secure_delete,
            writer: Arc::new(Mutex::new(None)),
            total_logged: AtomicU64::new(0),
            pending: AtomicU64::new(0),
            first_event: parking_lot::RwLock::new(None),
            last_event: parking_lot::RwLock::new(None),
        };

        // Open or create the log file
        logger.open_file().await?;

        Ok(logger)
    }

    async fn open_file(&self) -> Result<()> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .context("Failed to open log file")?;

        let writer = BufWriter::with_capacity(8192, file);
        *self.writer.lock() = Some(writer);

        Ok(())
    }

    async fn rotate_if_needed(&self) -> Result<()> {
        let file_size = match fs::metadata(&self.path).await {
            Ok(meta) => meta.len(),
            Err(_) => return Ok(()), // File doesn't exist yet
        };

        if file_size < self.max_size {
            return Ok(());
        }

        debug!("Rotating log file (size: {} bytes)", file_size);

        // Close current file
        {
            let mut writer = self.writer.lock();
            if let Some(ref mut w) = *writer {
                w.flush()?;
            }
            *writer = None;
        }

        // Rotate files: .log -> .log.1 -> .log.2 -> ...
        for i in (1..self.max_files).rev() {
            let from = if i == 1 {
                self.path.clone()
            } else {
                self.path.with_extension(format!("log.{}", i - 1))
            };
            let to = self.path.with_extension(format!("log.{}", i));

            if from.exists() {
                if to.exists() && self.secure_delete {
                    self.secure_delete_file(&to).await?;
                }
                fs::rename(&from, &to).await.ok();
            }
        }

        // Delete oldest if we have too many
        let oldest = self.path.with_extension(format!("log.{}", self.max_files));
        if oldest.exists() {
            if self.secure_delete {
                self.secure_delete_file(&oldest).await?;
            } else {
                fs::remove_file(&oldest).await.ok();
            }
        }

        // Open new file
        self.open_file().await?;

        Ok(())
    }

    /// Securely delete a file by overwriting with random data before deletion
    async fn secure_delete_file(&self, path: &PathBuf) -> Result<()> {
        use std::io::{Seek, SeekFrom};

        let file_size = match fs::metadata(path).await {
            Ok(meta) => meta.len(),
            Err(_) => return Ok(()),
        };

        if file_size == 0 {
            fs::remove_file(path).await.ok();
            return Ok(());
        }

        // Overwrite with zeros (3 passes for paranoid mode)
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .context("Failed to open file for secure delete")?;

        let zeros = vec![0u8; 4096];
        for pass in 0..3 {
            file.seek(SeekFrom::Start(0))?;
            let mut remaining = file_size;

            while remaining > 0 {
                let to_write = remaining.min(4096) as usize;
                file.write_all(&zeros[..to_write])?;
                remaining -= to_write as u64;
            }

            file.sync_all()?;

            if pass < 2 {
                // On passes 0 and 1, also write random-ish data (XOR pattern)
                file.seek(SeekFrom::Start(0))?;
                let pattern: Vec<u8> = (0..4096)
                    .map(|i| ((i * 0x5A + pass) & 0xFF) as u8)
                    .collect();
                let mut remaining = file_size;

                while remaining > 0 {
                    let to_write = remaining.min(4096) as usize;
                    file.write_all(&pattern[..to_write])?;
                    remaining -= to_write as u64;
                }

                file.sync_all()?;
            }
        }

        drop(file);
        fs::remove_file(path).await?;

        Ok(())
    }

    fn write_event(&self, event: &ConnectionEvent) -> Result<()> {
        let mut writer_guard = self.writer.lock();
        if let Some(ref mut writer) = *writer_guard {
            // Serialize to JSON - serde_json automatically escapes special characters
            // This prevents log injection attacks
            let json = serde_json::to_string(event)?;
            writeln!(writer, "{}", json)?;
            self.pending.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Log file not open"))
        }
    }
}

#[async_trait]
impl ConnectionLogger for FileConnectionLogger {
    async fn log(&self, event: ConnectionEvent) -> Result<()> {
        let timestamp = event.timestamp();

        // Update timestamps
        {
            let mut first = self.first_event.write();
            if first.is_none() {
                *first = Some(timestamp);
            }
        }
        {
            let mut last = self.last_event.write();
            *last = Some(timestamp);
        }

        // Check rotation
        self.rotate_if_needed().await?;

        // Write event
        self.write_event(&event)?;

        self.total_logged.fetch_add(1, Ordering::Relaxed);

        // Auto-flush every 100 events
        if self.pending.load(Ordering::Relaxed) >= 100 {
            self.flush().await?;
        }

        Ok(())
    }

    async fn query_recent(&self, limit: usize) -> Result<Option<Vec<ConnectionEvent>>> {
        // For file logger, we need to read from the file
        // This is expensive, so we only support it for small queries
        if limit > 1000 {
            warn!("Large query on file logger, consider using database mode");
        }

        // Flush first to ensure all events are written
        self.flush().await?;

        let content = fs::read_to_string(&self.path).await?;
        let events: Vec<ConnectionEvent> = content
            .lines()
            .rev()
            .take(limit)
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();

        Ok(Some(events))
    }

    async fn query_connection(&self, id: ConnectionId) -> Result<Option<Vec<ConnectionEvent>>> {
        // Flush first
        self.flush().await?;

        let content = fs::read_to_string(&self.path).await?;
        let events: Vec<ConnectionEvent> = content
            .lines()
            .filter_map(|line| serde_json::from_str::<ConnectionEvent>(line).ok())
            .filter(|e| e.connection_id() == id)
            .collect();

        Ok(Some(events))
    }

    async fn flush(&self) -> Result<()> {
        let mut writer_guard = self.writer.lock();
        if let Some(ref mut writer) = *writer_guard {
            writer.flush()?;
            self.pending.store(0, Ordering::Relaxed);
        }
        Ok(())
    }

    async fn cleanup(&self) -> Result<()> {
        // Rotation handles cleanup
        self.rotate_if_needed().await
    }

    fn stats(&self) -> LoggerStats {
        let storage = std::fs::metadata(&self.path).map(|m| m.len()).ok();

        LoggerStats {
            events_logged: self.total_logged.load(Ordering::Relaxed),
            pending_events: self.pending.load(Ordering::Relaxed),
            storage_bytes: storage,
            oldest_event: *self.first_event.read(),
            newest_event: *self.last_event.read(),
        }
    }

    fn logger_type(&self) -> &'static str {
        "file"
    }
}

impl Drop for FileConnectionLogger {
    fn drop(&mut self) {
        // Flush on drop
        if let Some(ref mut writer) = *self.writer.lock() {
            writer.flush().ok();
        }
    }
}
