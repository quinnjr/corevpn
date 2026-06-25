//! Connection Logging System
//!
//! Provides flexible connection logging with multiple backends:
//! - **None/Ghost Mode**: No logging at all - leaves no trace
//! - **Memory**: Real-time tracking without persistence
//! - **File**: Append-only log files with rotation
//! - **Database**: SQLite-based structured logging
//!
//! Supports anonymization options for privacy-conscious deployments.

mod anonymizer;
mod db_logger;
mod events;
mod file_logger;
mod logger;
mod memory_logger;
mod null_logger;

pub use anonymizer::Anonymizer;
pub use db_logger::DatabaseConnectionLogger;
pub use events::*;
pub use file_logger::FileConnectionLogger;
pub use logger::{ConnectionLogger, create_logger};
pub use memory_logger::MemoryConnectionLogger;
pub use null_logger::NullConnectionLogger;
