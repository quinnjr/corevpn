//! VPN Backend
//!
//! Manages the async VPN connection in a background tokio task,
//! communicating with the GUI via channels.

use std::path::PathBuf;
use std::sync::mpsc;

use corevpn_cli::client::VpnClient;
use corevpn_cli::ovpn::OvpnConfig;

/// Commands sent from the GUI to the VPN backend.
#[derive(Debug)]
pub enum VpnCommand {
    /// Connect using the given .ovpn config path
    Connect(PathBuf),
    /// Disconnect the active connection
    Disconnect,
}

/// Events sent from the VPN backend to the GUI.
#[derive(Debug, Clone)]
pub enum VpnEvent {
    /// Connection state changed
    Connecting,
    /// TLS handshake started
    Handshaking,
    /// Authenticating (e.g., waiting for OAuth)
    Authenticating {
        /// OAuth URL to open, if any
        url: Option<String>,
    },
    /// Successfully connected
    Connected {
        /// Assigned VPN IP address
        vpn_ip: Option<String>,
        /// Server name/address
        server: String,
    },
    /// Disconnected cleanly
    Disconnected,
    /// An error occurred
    Error(String),
    /// Log message from the backend
    Log {
        /// Log level
        level: LogLevel,
        /// Message text
        message: String,
    },
}

/// Log level for backend messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// Debug
    Debug,
    /// Info
    Info,
    /// Warning
    Warn,
    /// Error
    Error,
}

/// Handle to communicate with the VPN backend.
pub struct VpnBackend {
    /// Send commands to the backend worker
    cmd_tx: mpsc::Sender<VpnCommand>,
    /// Receive events from the backend worker
    event_rx: mpsc::Receiver<VpnEvent>,
    /// Tokio runtime for spawning async tasks (held to keep tasks alive)
    #[allow(dead_code)]
    runtime: tokio::runtime::Runtime,
    /// Whether a connection task is currently running
    active: bool,
    /// Shutdown signal sender (drop to signal shutdown)
    _shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
}

impl VpnBackend {
    /// Create a new VPN backend with its own tokio runtime.
    pub fn new() -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime");

        let (cmd_tx, cmd_rx) = mpsc::channel::<VpnCommand>();
        let (event_tx, event_rx) = mpsc::channel::<VpnEvent>();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        // Spawn the command processing loop
        let event_tx_clone = event_tx.clone();
        runtime.spawn(async move {
            command_loop(cmd_rx, event_tx_clone, shutdown_rx).await;
        });

        Self {
            cmd_tx,
            event_rx,
            runtime,
            active: false,
            _shutdown_tx: Some(shutdown_tx),
        }
    }

    /// Send a connect command.
    pub fn connect(&mut self, config_path: PathBuf) {
        self.active = true;
        let _ = self.cmd_tx.send(VpnCommand::Connect(config_path));
    }

    /// Send a disconnect command.
    pub fn disconnect(&mut self) {
        let _ = self.cmd_tx.send(VpnCommand::Disconnect);
    }

    /// Poll for pending events (non-blocking). Returns all available events.
    pub fn poll_events(&mut self) -> Vec<VpnEvent> {
        let mut events = Vec::new();
        while let Ok(event) = self.event_rx.try_recv() {
            match &event {
                VpnEvent::Disconnected | VpnEvent::Error(_) => {
                    self.active = false;
                }
                _ => {}
            }
            events.push(event);
        }
        events
    }

    /// Whether a connection task is active.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

/// Background command processing loop.
async fn command_loop(
    cmd_rx: mpsc::Receiver<VpnCommand>,
    event_tx: mpsc::Sender<VpnEvent>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        // Check for shutdown
        if *shutdown_rx.borrow() {
            break;
        }

        // Non-blocking check for commands
        match cmd_rx.try_recv() {
            Ok(VpnCommand::Connect(config_path)) => {
                let tx = event_tx.clone();
                let mut shutdown = shutdown_rx.clone();

                tokio::spawn(async move {
                    run_connection(config_path, tx, &mut shutdown).await;
                });
            }
            Ok(VpnCommand::Disconnect) => {
                // Signal disconnect by sending the event; the connection task
                // will be cancelled on next iteration or via shutdown
                let _ = event_tx.send(VpnEvent::Disconnected);
            }
            Err(mpsc::TryRecvError::Empty) => {
                // No commands, sleep briefly
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                break;
            }
        }
    }
}

/// Run a VPN connection from start to finish.
async fn run_connection(
    config_path: PathBuf,
    event_tx: mpsc::Sender<VpnEvent>,
    _shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
) {
    // Parse the config
    let _ = event_tx.send(VpnEvent::Log {
        level: LogLevel::Info,
        message: format!("Loading config: {}", config_path.display()),
    });

    let config = match OvpnConfig::parse_file(&config_path) {
        Ok(c) => c,
        Err(e) => {
            let _ = event_tx.send(VpnEvent::Error(format!("Failed to parse .ovpn: {}", e)));
            return;
        }
    };

    let server_addr = config.remote.to_string();
    let _ = event_tx.send(VpnEvent::Log {
        level: LogLevel::Info,
        message: format!(
            "Loaded config: remote={}, cipher={}, proto={}",
            config.remote, config.cipher, config.protocol
        ),
    });
    let _ = event_tx.send(VpnEvent::Connecting);

    // Create and run the VPN client
    let client = VpnClient::new(config);
    match client.connect().await {
        Ok(()) => {
            let _ = event_tx.send(VpnEvent::Connected {
                vpn_ip: None,
                server: server_addr,
            });
        }
        Err(e) => {
            let err_msg = format!("{:#}", e);
            // Check if it's an auth-pending situation
            if err_msg.contains("AUTH_PENDING") || err_msg.contains("auth") {
                let _ = event_tx.send(VpnEvent::Authenticating { url: None });
            }
            let _ = event_tx.send(VpnEvent::Error(err_msg));
        }
    }

    let _ = event_tx.send(VpnEvent::Disconnected);
}

/// Load and validate an .ovpn file, returning a summary for display.
pub fn validate_ovpn(path: &std::path::Path) -> Result<OvpnSummary, String> {
    let config = OvpnConfig::parse_file(path).map_err(|e| format!("{:#}", e))?;
    Ok(OvpnSummary {
        remote: config.remote.to_string(),
        protocol: config.protocol.clone(),
        cipher: config.cipher.clone(),
        has_tls_auth: config.tls_auth_key.is_some(),
        dev: config.dev.clone(),
    })
}

/// Summary of a parsed .ovpn config for display in the UI.
#[derive(Debug, Clone)]
pub struct OvpnSummary {
    /// Remote server address:port
    pub remote: String,
    /// Protocol (udp/tcp)
    pub protocol: String,
    /// Cipher name
    pub cipher: String,
    /// Whether tls-auth is configured
    pub has_tls_auth: bool,
    /// Device type
    pub dev: String,
}
