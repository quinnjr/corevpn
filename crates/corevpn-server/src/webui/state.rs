//! Web UI shared state

use corevpn_config::ServerConfig;
use corevpn_core::SessionManager;
use parking_lot::RwLock;
use std::sync::Arc;

/// Shared state for web UI handlers
#[derive(Clone)]
pub struct WebUiState {
    /// Server configuration
    pub config: Arc<ServerConfig>,
    /// Session manager reference
    pub session_manager: Arc<RwLock<SessionManager>>,
    /// Server start time
    pub start_time: std::time::Instant,
}

impl WebUiState {
    pub fn new(config: ServerConfig, session_manager: SessionManager) -> Self {
        Self {
            config: Arc::new(config),
            session_manager: Arc::new(RwLock::new(session_manager)),
            start_time: std::time::Instant::now(),
        }
    }

    /// Get uptime as human readable string
    pub fn uptime(&self) -> String {
        let elapsed = self.start_time.elapsed();
        let secs = elapsed.as_secs();

        if secs < 60 {
            format!("{}s", secs)
        } else if secs < 3600 {
            format!("{}m {}s", secs / 60, secs % 60)
        } else if secs < 86400 {
            format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
        } else {
            format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
        }
    }
}
