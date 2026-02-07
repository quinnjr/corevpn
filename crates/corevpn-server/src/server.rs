//! VPN Server Implementation
//!
//! Handles OpenVPN-compatible connections with TLS and OAuth2 authentication.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;
use parking_lot::RwLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tracing::{info, warn, error, debug, trace};
use tun::Device as TunDevice;

/// OpenVPN keepalive ping magic payload
const OPENVPN_PING_PAYLOAD: [u8; 16] = [
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
    0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
];

use corevpn_config::{ConnectionLogMode, ServerConfig};
use corevpn_core::{SessionManager, AddressPool};
use corevpn_crypto::{CipherSuite, HmacAuth, parse_static_key};
use corevpn_protocol::{
    OpCode, ProtocolSession, ProtocolState, ProcessedPacket,
    TlsHandler, create_server_config, load_certs_from_pem, load_key_from_pem,
};

use crate::connection_log::{
    ConnectionLogger, ConnectionEvent, ConnectionEventBuilder, ConnectionId,
    AuthMethod, DisconnectReason, TransferStats, Anonymizer, create_logger,
};

/// Active connection state
struct Connection {
    /// Protocol session
    protocol: ProtocolSession,
    /// TLS handler
    tls: Option<TlsHandler>,
    /// Last activity time
    last_activity: Instant,
    /// Connection start time
    connected_at: Instant,
    /// Peer address
    peer_addr: SocketAddr,
    /// Assigned VPN IP (if authenticated)
    vpn_ip: Option<std::net::Ipv4Addr>,
    /// Connection ID for logging
    connection_id: ConnectionId,
    /// Username (if authenticated)
    username: Option<String>,
    /// Authentication method used
    auth_method: AuthMethod,
    /// Transfer statistics
    stats: TransferStats,
    /// Cached hard reset response for retransmission on UDP retries
    hard_reset_response: Option<Bytes>,
    /// Pending PUSH_REPLY string (waiting for OAuth authentication)
    pending_push_reply: Option<String>,
    /// OAuth state token for this connection
    oauth_state: Option<String>,
    /// Negotiated cipher name (stored for deferred PUSH_REPLY)
    negotiated_cipher: Option<String>,
}

impl Connection {
    fn new(peer_addr: SocketAddr, cipher_suite: CipherSuite, connection_id: ConnectionId) -> Self {
        Self {
            protocol: ProtocolSession::new_server(cipher_suite),
            tls: None,
            last_activity: Instant::now(),
            connected_at: Instant::now(),
            peer_addr,
            vpn_ip: None,
            connection_id,
            username: None,
            auth_method: AuthMethod::Unknown,
            stats: TransferStats::default(),
            hard_reset_response: None,
            pending_push_reply: None,
            oauth_state: None,
            negotiated_cipher: None,
        }
    }

    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    fn is_stale(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

    fn duration(&self) -> Duration {
        self.connected_at.elapsed()
    }

    fn add_bytes_rx(&mut self, bytes: u64) {
        self.stats.bytes_rx += bytes;
        self.stats.packets_rx += 1;
    }

    fn add_bytes_tx(&mut self, bytes: u64) {
        self.stats.bytes_tx += bytes;
        self.stats.packets_tx += 1;
    }
}

/// Connection map type
type ConnectionMap = Arc<RwLock<HashMap<SocketAddr, Connection>>>;

/// OAuth authentication completion message
pub struct AuthCompleted {
    /// OAuth state token
    pub state: String,
    /// Authenticated user email
    pub email: String,
}

/// Pending OAuth auth info (shared between HTTP server and VPN)
pub struct PendingOAuth {
    pub peer_addr: SocketAddr,
    pub created_at: Instant,
}

/// Shared OAuth state between HTTP handler and VPN server
pub type PendingOAuthMap = Arc<RwLock<HashMap<String, PendingOAuth>>>;

/// Server state
pub struct VpnServer {
    config: ServerConfig,
    session_manager: SessionManager,
    address_pool: AddressPool,
    connections: ConnectionMap,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    /// tls-auth HMAC key (loaded from ta.key)
    tls_auth_key: Option<Arc<[u8; 256]>>,
    /// Connection logger
    connection_logger: Arc<dyn ConnectionLogger>,
    /// Event anonymizer (if configured)
    anonymizer: Option<parking_lot::Mutex<Anonymizer>>,
    /// Pending OAuth authentications (state_token → peer info)
    pending_oauths: PendingOAuthMap,
}

impl VpnServer {
    /// Create a new VPN server
    pub async fn new(config: ServerConfig) -> Result<Self> {
        let session_manager = SessionManager::new(
            config.server.max_clients as usize,
            chrono::Duration::hours(24),
        );

        let subnet = config.network.subnet.parse()
            .map_err(|e| anyhow::anyhow!("Invalid subnet: {}", e))?;

        let address_pool = AddressPool::new(Some(subnet), None)
            .map_err(|e| anyhow::anyhow!("Invalid address pool configuration: {}", e))?;

        // Load TLS configuration
        let tls_config = Self::load_tls_config(&config)?;

        // Load tls-auth key if enabled
        let tls_auth_key = Self::load_tls_auth_key(&config);

        // Initialize connection logger
        let connection_logger = create_logger(&config.logging).await?;

        // Log the logging mode for transparency
        match config.logging.connection_mode {
            ConnectionLogMode::None => {
                info!("Connection logging: DISABLED (ghost mode)");
            }
            ConnectionLogMode::Memory => {
                info!("Connection logging: memory only (not persisted)");
            }
            ConnectionLogMode::File => {
                info!("Connection logging: file-based");
            }
            ConnectionLogMode::Database => {
                info!("Connection logging: database-based");
            }
            ConnectionLogMode::Both => {
                info!("Connection logging: file + database");
            }
        }

        // Initialize anonymizer if any anonymization is configured
        let anonymizer = if config.logging.anonymization.hash_client_ips
            || config.logging.anonymization.truncate_client_ips
            || config.logging.anonymization.hash_usernames
            || config.logging.anonymization.round_timestamps
            || config.logging.anonymization.aggregate_transfer_stats
        {
            info!("Connection log anonymization: enabled");
            Some(parking_lot::Mutex::new(Anonymizer::new(
                config.logging.anonymization.clone(),
            )))
        } else {
            None
        };

        Ok(Self {
            config,
            session_manager,
            address_pool,
            connections: Arc::new(RwLock::new(HashMap::new())),
            tls_config,
            tls_auth_key,
            connection_logger,
            anonymizer,
            pending_oauths: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Log a connection event, applying anonymization if configured
    async fn log_event(&self, event: ConnectionEvent) {
        let event = if let Some(ref anonymizer) = self.anonymizer {
            anonymizer.lock().anonymize(event)
        } else {
            event
        };

        if let Err(e) = self.connection_logger.log(event).await {
            warn!("Failed to log connection event: {}", e);
        }
    }

    fn load_tls_config(config: &ServerConfig) -> Result<Option<Arc<rustls::ServerConfig>>> {
        // Check if certificates exist
        let cert_path = config.server_cert_path();
        let key_path = config.server_key_path();

        if !cert_path.exists() || !key_path.exists() {
            warn!("Server certificates not found, TLS disabled");
            return Ok(None);
        }

        let cert_pem = std::fs::read_to_string(&cert_path)
            .map_err(|e| anyhow::anyhow!("Failed to read server cert: {}", e))?;
        let key_pem = std::fs::read_to_string(&key_path)
            .map_err(|e| anyhow::anyhow!("Failed to read server key: {}", e))?;

        let certs = load_certs_from_pem(&cert_pem)
            .map_err(|e| anyhow::anyhow!("Failed to parse server cert: {}", e))?;
        let key = load_key_from_pem(&key_pem)
            .map_err(|e| anyhow::anyhow!("Failed to parse server key: {}", e))?;

        let tls_config = create_server_config(certs, key, None)
            .map_err(|e| anyhow::anyhow!("Failed to create TLS config: {}", e))?;

        Ok(Some(tls_config))
    }

    /// Load tls-auth key from ta.key file if tls_auth is enabled in config
    fn load_tls_auth_key(config: &ServerConfig) -> Option<Arc<[u8; 256]>> {
        if !config.security.tls_auth {
            return None;
        }

        let ta_path = config.ta_key_path();
        if !ta_path.exists() {
            warn!("tls-auth enabled but ta.key not found at {:?}", ta_path);
            return None;
        }

        match std::fs::read_to_string(&ta_path) {
            Ok(pem) => match parse_static_key(&pem) {
                Ok(key) => {
                    info!("tls-auth key loaded from {:?}", ta_path);
                    Some(Arc::new(key))
                }
                Err(e) => {
                    warn!("Failed to parse tls-auth key: {}", e);
                    None
                }
            },
            Err(e) => {
                warn!("Failed to read tls-auth key file: {}", e);
                None
            }
        }
    }

    /// Get cipher suite from config
    fn get_cipher_suite(&self) -> CipherSuite {
        if self.config.security.cipher.contains("chacha") {
            CipherSuite::ChaCha20Poly1305
        } else {
            CipherSuite::Aes256Gcm
        }
    }
}

/// Run the VPN server
pub async fn run_server(config: ServerConfig) -> Result<()> {
    info!("CoreVPN Server starting...");
    info!("Listening on: {}", config.server.listen_addr);
    info!("Public host: {}", config.server.public_host);
    info!("VPN subnet: {}", config.network.subnet);

    // Set resource limits before binding
    set_resource_limits()?;

    let server = Arc::new(VpnServer::new(config.clone()).await?);

    // Bind UDP socket
    let socket = UdpSocket::bind(&config.server.listen_addr).await?;
    let socket = Arc::new(socket);

    // Create TUN device for data plane
    let subnet_net: ipnet::Ipv4Net = config.network.subnet.parse()
        .map_err(|e| anyhow::anyhow!("Invalid subnet for TUN: {}", e))?;
    let gateway_ip = server.address_pool.gateway_v4()
        .unwrap_or(Ipv4Addr::new(10, 8, 0, 1));

    let mut tun_config = tun::Configuration::default();
    tun_config.name("tun0");
    tun_config.address(gateway_ip);
    tun_config.netmask(subnet_net.netmask());
    tun_config.mtu(1500);
    tun_config.up();

    #[cfg(target_os = "linux")]
    tun_config.platform(|p| {
        p.packet_information(false); // No IFF_PI header
    });

    let tun_device = tun::create(&tun_config)
        .map_err(|e| anyhow::anyhow!("Failed to create TUN device: {}", e))?;
    let tun_name = tun_device.name()
        .map_err(|e| anyhow::anyhow!("Failed to get TUN device name: {}", e))?;
    info!("TUN device created: {} (IP: {}/{})", tun_name, gateway_ip, subnet_net.prefix_len());

    let tun_device = tun::AsyncDevice::new(tun_device)
        .map_err(|e| anyhow::anyhow!("Failed to create async TUN device: {}", e))?;

    // Enable IP forwarding
    if let Err(e) = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1") {
        warn!("Failed to enable IP forwarding (may already be enabled): {}", e);
    } else {
        info!("IP forwarding enabled");
    }

    // Set up NAT/masquerading
    let default_iface = get_default_interface().unwrap_or_else(|| "eth0".to_string());
    info!("Setting up NAT on interface: {}", default_iface);

    let _ = std::process::Command::new("iptables")
        .args(["-t", "nat", "-A", "POSTROUTING", "-s", &config.network.subnet, "-o", &default_iface, "-j", "MASQUERADE"])
        .status();
    let _ = std::process::Command::new("iptables")
        .args(["-A", "FORWARD", "-i", &tun_name, "-o", &default_iface, "-j", "ACCEPT"])
        .status();
    let _ = std::process::Command::new("iptables")
        .args(["-A", "FORWARD", "-i", &default_iface, "-o", &tun_name, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
        .status();
    info!("NAT/masquerading configured");

    // Split TUN device into reader and writer halves
    let (mut tun_reader, tun_writer) = tokio::io::split(tun_device);

    // Channel for sending data to TUN device (avoids holding connection locks across await points)
    let (tun_write_tx, mut tun_write_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);

    // Spawn TUN writer task
    tokio::spawn(async move {
        let mut writer = tun_writer;
        while let Some(data) = tun_write_rx.recv().await {
            if let Err(e) = writer.write_all(&data).await {
                warn!("TUN write error: {}", e);
            }
        }
    });

    // Drop privileges after binding and TUN creation (if running as root)
    drop_privileges()?;

    info!("Server ready, waiting for connections...");

    // Spawn cleanup task
    let server_cleanup = server.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            cleanup_stale_connections(&server_cleanup, Duration::from_secs(300)).await;
        }
    });

    // Spawn log cleanup task
    let logger = server.connection_logger.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Hourly
        loop {
            interval.tick().await;
            if let Err(e) = logger.cleanup().await {
                warn!("Log cleanup failed: {}", e);
            }
        }
    });

    // Channel for OAuth auth completion notifications
    let (auth_completed_tx, mut auth_completed_rx) = tokio::sync::mpsc::channel::<AuthCompleted>(32);

    // Start OAuth HTTP server if OAuth is enabled
    let oauth_enabled = config.oauth.as_ref().map(|o| o.enabled).unwrap_or(false);
    if oauth_enabled {
        let oauth_config = config.oauth.clone().unwrap();
        let pending_oauths = server.pending_oauths.clone();
        let auth_tx = auth_completed_tx.clone();
        let public_host = config.server.public_host.clone();

        tokio::spawn(async move {
            if let Err(e) = run_oauth_server(oauth_config, pending_oauths, auth_tx, public_host).await {
                error!("OAuth HTTP server error: {}", e);
            }
        });
        info!("OAuth HTTP server started on port 9000");
    }

    // Main event loop: multiplex UDP recv, TUN read, and keepalive timer
    let mut udp_buf = vec![0u8; 65535];
    let mut tun_buf = vec![0u8; 65535];
    let mut ping_interval = tokio::time::interval(Duration::from_secs(10));

    loop {
        tokio::select! {
            // Receive UDP packet from client
            result = socket.recv_from(&mut udp_buf) => {
                match result {
                    Ok((len, peer_addr)) => {
                        let packet_data = Bytes::copy_from_slice(&udp_buf[..len]);
                        if let Err(e) = handle_packet(&server, &socket, peer_addr, packet_data, &tun_write_tx).await {
                            debug!("Packet handling error from {}: {}", peer_addr, e);
                        }
                    }
                    Err(e) => {
                        error!("UDP receive error: {}", e);
                    }
                }
            }
            // Read IP packet from TUN (outbound to client)
            result = tun_reader.read(&mut tun_buf) => {
                match result {
                    Ok(0) => {
                        warn!("TUN device closed");
                        break;
                    }
                    Ok(n) => {
                        let ip_packet = &tun_buf[..n];
                        if let Err(e) = handle_tun_packet(&server, &socket, ip_packet).await {
                            debug!("TUN packet handling error: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("TUN read error: {}", e);
                    }
                }
            }
            // Send keepalive pings to established connections
            _ = ping_interval.tick() => {
                send_keepalive_pings(&server, &socket).await;
            }
            // Handle OAuth authentication completions
            Some(auth) = auth_completed_rx.recv() => {
                if let Err(e) = handle_auth_completed(&server, &socket, auth).await {
                    warn!("Failed to handle OAuth completion: {}", e);
                }
            }
        }
    }

    Ok(())
}

/// Cleanup stale connections
async fn cleanup_stale_connections(server: &VpnServer, timeout: Duration) {
    let stale_connections: Vec<_> = {
        let map = server.connections.read();
        map.iter()
            .filter(|(_, conn)| conn.is_stale(timeout))
            .map(|(addr, conn)| (*addr, conn.connection_id, conn.username.clone(), conn.duration(), conn.stats.clone()))
            .collect()
    };

    if stale_connections.is_empty() {
        return;
    }

    // Log disconnections for stale connections
    for (addr, connection_id, username, duration, stats) in &stale_connections {
        let event = ConnectionEventBuilder::with_id(*connection_id).disconnected(
            *addr,
            username.clone(),
            DisconnectReason::IdleTimeout,
            *duration,
            Some(stats.clone()),
        );
        server.log_event(event).await;
    }

    // Remove stale connections
    let mut map = server.connections.write();
    for (addr, _, _, _, _) in &stale_connections {
        map.remove(addr);
    }

    info!("Cleaned up {} stale connections", stale_connections.len());
}

async fn handle_packet(
    server: &VpnServer,
    socket: &UdpSocket,
    peer_addr: SocketAddr,
    data: Bytes,
    tun_write_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }

    // Parse packet opcode
    let opcode = OpCode::from_byte(data[0])?;
    trace!("Received {} from {}", opcode, peer_addr);

    match opcode {
        OpCode::HardResetClientV2 | OpCode::HardResetClientV3 => {
            handle_hard_reset(server, socket, peer_addr, &data).await?;
        }
        OpCode::ControlV1 | OpCode::AckV1 | OpCode::SoftResetV1 => {
            handle_control_packet(server, socket, peer_addr, &data).await?;
        }
        OpCode::DataV1 | OpCode::DataV2 => {
            handle_data_packet(server, socket, peer_addr, &data, tun_write_tx).await?;
        }
        _ => {
            debug!("Unhandled opcode: {}", opcode);
        }
    }

    Ok(())
}

async fn handle_hard_reset(
    server: &VpnServer,
    socket: &UdpSocket,
    peer_addr: SocketAddr,
    data: &[u8],
) -> Result<()> {
    // Check if we already have a non-stale connection from this peer.
    // If so, this is a UDP retransmit — resend the cached response
    // instead of creating a new session (which would change the session ID
    // and confuse the client).
    {
        let connections = server.connections.read();
        if let Some(existing) = connections.get(&peer_addr) {
            if !existing.is_stale(Duration::from_secs(30)) {
                if let Some(ref cached_response) = existing.hard_reset_response {
                    debug!("Retransmitting cached hard reset response to {} (UDP retry)", peer_addr);
                    socket.send_to(cached_response, peer_addr).await?;
                    return Ok(());
                }
            }
        }
    }

    info!("New connection from {}", peer_addr);

    // Create connection ID for logging
    let event_builder = ConnectionEventBuilder::new();
    let connection_id = event_builder.connection_id();

    // Log connection attempt if configured
    if server.config.logging.connection_events.attempts {
        let event = event_builder.attempt(peer_addr);
        server.log_event(event).await;
    }

    let cipher_suite = server.get_cipher_suite();
    let mut conn = Connection::new(peer_addr, cipher_suite, connection_id);

    // Enable tls-auth if key is loaded
    if let Some(ref ta_key) = server.tls_auth_key {
        match HmacAuth::from_ta_key(ta_key, true, None) {
            Ok(hmac_auth) => {
                conn.protocol.set_tls_auth(hmac_auth);
            }
            Err(e) => {
                warn!("Failed to create HMAC auth for {}: {}", peer_addr, e);
            }
        }
    }

    // Process hard reset
    let _result = conn.protocol.process_packet(data)?;

    // Initialize TLS handler if we have TLS config
    if let Some(ref tls_config) = server.tls_config {
        let tls = TlsHandler::new(tls_config.clone())
            .map_err(|e| anyhow::anyhow!("TLS init failed: {}", e))?;
        conn.tls = Some(tls);
    }

    // Send hard reset response and cache it for retransmission
    let response = conn.protocol.create_hard_reset_response()?;
    socket.send_to(&response, peer_addr).await?;
    conn.hard_reset_response = Some(response.clone());

    debug!("Sent hard reset response to {}", peer_addr);

    // Store connection
    server.connections.write().insert(peer_addr, conn);

    Ok(())
}

async fn handle_control_packet(
    server: &VpnServer,
    socket: &UdpSocket,
    peer_addr: SocketAddr,
    data: &[u8],
) -> Result<()> {
    // Collect data we need to send while holding the lock
    let packets_to_send: Vec<Bytes>;
    let mut log_events: Vec<ConnectionEvent> = Vec::new();

    {
        // Scope for the write lock - release before any awaits
        let mut connections = server.connections.write();
        let conn = match connections.get_mut(&peer_addr) {
            Some(c) => c,
            None => {
                debug!("No session for {}", peer_addr);
                return Ok(());
            }
        };

        conn.touch();

        // Process control packet
        let result = conn.protocol.process_packet(data)?;

        let mut pending_packets = Vec::new();

        match result {
            ProcessedPacket::TlsData(records) => {
                info!("Received {} TLS record(s) from {} (total {} bytes)", records.len(), peer_addr, records.iter().map(|r| r.len()).sum::<usize>());

                // Pass TLS records to TLS handler
                if let Some(ref mut tls) = conn.tls {
                    tls.process_tls_records(records)
                        .map_err(|e| {
                            warn!("TLS processing failed for {}: {}", peer_addr, e);
                            anyhow::anyhow!("TLS processing failed: {}", e)
                        })?;

                    // If TLS handler wants to write, get the data and split
                    // into MTU-safe control channel packets
                    while tls.wants_write() {
                        if let Some(tls_out) = tls.get_outgoing()
                            .map_err(|e| anyhow::anyhow!("TLS outgoing failed: {}", e))?
                        {
                            debug!("Sending {} bytes of TLS data to {} (splitting if needed)", tls_out.len(), peer_addr);
                            // Wrap TLS data in control packets, splitting large
                            // payloads to avoid IP fragmentation
                            let ctrl_packets = conn.protocol.create_control_packets(tls_out)?;
                            debug!("Split into {} control packet(s) for {}", ctrl_packets.len(), peer_addr);
                            pending_packets.extend(ctrl_packets);
                        } else {
                            break;
                        }
                    }

                    // Check if handshake is complete
                    if tls.is_handshake_complete() && conn.protocol.state() == ProtocolState::TlsHandshake {
                        info!("TLS handshake complete with {}", peer_addr);
                        conn.protocol.set_state(ProtocolState::KeyExchange);
                        conn.auth_method = AuthMethod::Certificate;

                        // Read client's key_method_v2 from TLS plaintext
                        let mut buf = vec![0u8; 4096];
                        if let Ok(n) = tls.read_plaintext(&mut buf) {
                            if n > 0 {
                                debug!("Received {} bytes of key_method_v2 from {}", n, peer_addr);

                                // Parse client's key_method_v2
                                match corevpn_protocol::KeyMethodV2::parse(&buf[..n]) {
                                    Ok(client_km) => {
                                        debug!("Client options: {}", client_km.options);
                                        if let Some(ref pi) = client_km.peer_info {
                                            debug!("Client peer_info: {}", pi);
                                        }
                                        if let Some(ref user) = client_km.username {
                                            conn.username = Some(user.clone());
                                        }

                                        // Negotiate cipher via NCP (Negotiable Crypto Parameters)
                                        // Parse client's IV_CIPHERS from peer_info
                                        let negotiated_cipher = if let Some(ref pi) = client_km.peer_info {
                                            // Extract IV_CIPHERS line
                                            let client_ciphers: Vec<&str> = pi.lines()
                                                .find(|l| l.starts_with("IV_CIPHERS="))
                                                .map(|l| l.trim_start_matches("IV_CIPHERS="))
                                                .unwrap_or("")
                                                .split(':')
                                                .filter(|s| !s.is_empty())
                                                .collect();
                                            // Pick first cipher from client list that we support
                                            let server_cipher = server.config.security.cipher.to_uppercase();
                                            // Server supports AES-256-GCM, AES-128-GCM, CHACHA20-POLY1305
                                            let supported = ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"];
                                            client_ciphers.iter()
                                                .find(|c| supported.contains(&c.to_uppercase().as_str()))
                                                .map(|c| c.to_string())
                                                .unwrap_or_else(|| server_cipher.clone())
                                        } else {
                                            server.config.security.cipher.to_uppercase()
                                        };
                                        debug!("Negotiated cipher: {} for {}", negotiated_cipher, peer_addr);

                                        // Update the session's cipher suite to match the negotiated cipher
                                        let negotiated_suite = if negotiated_cipher.contains("CHACHA") {
                                            CipherSuite::ChaCha20Poly1305
                                        } else {
                                            CipherSuite::Aes256Gcm
                                        };
                                        conn.protocol.set_cipher_suite(negotiated_suite);

                                        // Generate server's key_method_v2
                                        // Note: server does NOT send pre_master (encode(true) skips it).
                                        // Only random1 and random2 are sent and used.
                                        let server_random1: [u8; 32] = corevpn_crypto::random_bytes();
                                        let server_random2: [u8; 32] = corevpn_crypto::random_bytes();

                                        let server_km = corevpn_protocol::KeyMethodV2 {
                                            pre_master: [0u8; 48], // not sent on wire (is_server=true)
                                            random1: server_random1,
                                            random2: server_random2,
                                            options: format!(
                                                "V4,dev-type tun,link-mtu 1560,tun-mtu 1500,proto UDPv4,cipher {},auth [null-digest],keysize 256,key-method 2,tls-server",
                                                negotiated_cipher
                                            ),
                                            username: None,
                                            password: None,
                                            peer_info: None,
                                        };

                                        // Send server's key_method_v2 via TLS
                                        // is_server=true: omit pre_master from key source
                                        let km_bytes = server_km.encode(true);
                                        debug!("Sending {} bytes of key_method_v2 to {}", km_bytes.len(), peer_addr);
                                        if let Err(e) = tls.write_plaintext(&km_bytes) {
                                            warn!("Failed to send key_method_v2 to {}: {}", peer_addr, e);
                                        }

                                        // Flush TLS outgoing data
                                        while tls.wants_write() {
                                            if let Some(tls_out) = tls.get_outgoing()
                                                .map_err(|e| anyhow::anyhow!("TLS outgoing failed: {}", e))?
                                            {
                                                debug!("Sending {} bytes of key exchange TLS data to {}", tls_out.len(), peer_addr);
                                                let ctrl_packets = conn.protocol.create_control_packets(tls_out)?;
                                                pending_packets.extend(ctrl_packets);
                                            } else {
                                                break;
                                            }
                                        }

                                        // Derive data channel keys
                                        //
                                        // With TLS 1.3 (used by rustls), OpenVPN 2.6+ uses TLS Exported
                                        // Keying Material (EKM, RFC 5705) instead of the legacy OpenVPN PRF.
                                        // The EKM approach directly exports 256 bytes from the TLS session
                                        // into the key2 block.
                                        //
                                        // Label: "EXPORTER-OpenVPN-datakeys"
                                        // Context: NONE (OpenVPN calls SSL_export_keying_material
                                        //          with use_context=0, i.e. no context at all)
                                        // Output: 256 bytes → key2 struct layout
                                        {
                                            let mut key_block = vec![0u8; 256];
                                            match tls.export_keying_material(
                                                &mut key_block,
                                                b"EXPORTER-OpenVPN-datakeys",
                                                None,
                                            ) {
                                                Ok(()) => {
                                                    // OpenVPN key2 struct layout (256 bytes):
                                                    //   key[0].cipher[64] | key[0].hmac[64] | key[1].cipher[64] | key[1].hmac[64]
                                                    // For AES-256-GCM AEAD:
                                                    //   key[0].cipher[0..32] = cipher key, key[0].hmac[0..12] = implicit IV
                                                    // Direction (with client keydir=1, server keydir=0):
                                                    //   key[0] = server encrypt / client decrypt (server→client)
                                                    //   key[1] = client encrypt / server decrypt (client→server)
                                                    let key_material = corevpn_crypto::KeyMaterial::from_openvpn_key2_block(&key_block);
                                                    info!("EKM key block (256 bytes): key[0].cipher[..8]={:02x?}, key[0].hmac[..12]={:02x?}, key[1].cipher[..8]={:02x?}, key[1].hmac[..12]={:02x?}",
                                                        &key_block[0..8], &key_block[64..76], &key_block[128..136], &key_block[192..204]);
                                                    info!("Server encrypt key (key[0]): {:02x?}", &key_material.server_write_key[..8]);
                                                    info!("Server encrypt IV (key[0]): {:02x?}", &key_material.server_implicit_iv);
                                                    info!("Client encrypt key (key[1]): {:02x?}", &key_material.client_write_key[..8]);
                                                    info!("Client encrypt IV (key[1]): {:02x?}", &key_material.client_implicit_iv);
                                                    conn.protocol.install_keys(&key_material, true);
                                                    info!("Derived data channel keys via EKM for {} (TLS 1.3)", peer_addr);
                                                }
                                                Err(e) => {
                                                    // EKM failed, fall back to legacy OpenVPN PRF
                                                    warn!("EKM export failed for {}: {}, falling back to PRF", peer_addr, e);

                                                    let mut master_seed = Vec::with_capacity(64);
                                                    master_seed.extend_from_slice(&client_km.random1);
                                                    master_seed.extend_from_slice(&server_random1);

                                                    if let Ok(master) = corevpn_crypto::openvpn_prf(
                                                        &client_km.pre_master,
                                                        b"OpenVPN master secret",
                                                        &master_seed,
                                                        48,
                                                    ) {
                                                        let mut expansion_seed = Vec::with_capacity(80);
                                                        expansion_seed.extend_from_slice(&client_km.random2);
                                                        expansion_seed.extend_from_slice(&server_random2);
                                                        if let Some(remote_sid) = conn.protocol.remote_session_id() {
                                                            expansion_seed.extend_from_slice(remote_sid);
                                                        }
                                                        expansion_seed.extend_from_slice(conn.protocol.local_session_id());

                                                        if let Ok(key_block_prf) = corevpn_crypto::openvpn_prf(
                                                            &master,
                                                            b"OpenVPN key expansion",
                                                            &expansion_seed,
                                                            256,
                                                        ) {
                                                            let key_material = corevpn_crypto::KeyMaterial::from_openvpn_key2_block(&key_block_prf);
                                                            conn.protocol.install_keys(&key_material, true);
                                                            debug!("Derived data channel keys via PRF fallback for {}", peer_addr);
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        // Allocate VPN IP and build push reply
                                        match server.address_pool.allocate() {
                                            Ok(vpn_addr) => {
                                                let client_ip = vpn_addr.ipv4.map(|ip| ip.to_string()).unwrap_or_default();
                                                let gateway_ip = server.address_pool.gateway_v4()
                                                    .map(|ip| ip.to_string())
                                                    .unwrap_or_else(|| "10.8.0.1".to_string());

                                                // Compute subnet mask from config subnet (e.g., "10.8.0.0/24" -> "255.255.255.0")
                                                let subnet_mask = server.config.network.subnet.parse::<ipnet::Ipv4Net>()
                                                    .map(|net| net.netmask().to_string())
                                                    .unwrap_or_else(|_| "255.255.255.0".to_string());

                                                info!("Assigned VPN IP {} to {} (gateway: {}, mask: {})", client_ip, peer_addr, gateway_ip, subnet_mask);

                                                conn.vpn_ip = vpn_addr.ipv4;

                                                let mut push_reply = corevpn_protocol::PushReply::default();
                                                // For topology subnet, ifconfig needs (client_ip, subnet_mask) not (client_ip, gateway_ip)
                                                push_reply.ifconfig = Some((client_ip.clone(), subnet_mask));
                                                push_reply.topology = corevpn_protocol::Topology::Subnet;

                                                // Add DNS from config
                                                for dns in &server.config.network.dns {
                                                    push_reply.dns.push(dns.clone());
                                                }

                                                // Add redirect gateway if configured
                                                push_reply.redirect_gateway = server.config.network.redirect_gateway;
                                                if server.config.network.redirect_gateway {
                                                    push_reply.route_gateway = Some(gateway_ip.clone());
                                                }

                                                // Add push_routes from config
                                                for route_cidr in &server.config.network.push_routes {
                                                    if let Some((network, netmask)) = cidr_to_netmask(route_cidr) {
                                                        push_reply.routes.push(corevpn_protocol::PushRoute::new(&network, &netmask));
                                                    } else {
                                                        warn!("Invalid push_route CIDR: {}", route_cidr);
                                                    }
                                                }

                                                push_reply.ping = 10;
                                                push_reply.ping_restart = 60;

                                                // Push negotiated cipher for NCP
                                                push_reply.options.push(format!("cipher {}", negotiated_cipher));

                                                let reply_str = push_reply.encode();

                                                // Check if OAuth is enabled - defer PUSH_REPLY until auth completes
                                                let oauth_enabled = server.config.oauth.as_ref()
                                                    .map(|o| o.enabled).unwrap_or(false);

                                                if oauth_enabled {
                                                    // Generate OAuth state token
                                                    let state_token = format!("{:x}", rand::random::<u64>());

                                                    // Store pending push reply and state
                                                    conn.pending_push_reply = Some(reply_str.clone());
                                                    conn.oauth_state = Some(state_token.clone());
                                                    conn.negotiated_cipher = Some(negotiated_cipher.clone());

                                                    // Register in shared pending_oauths map
                                                    {
                                                        let mut pending = server.pending_oauths.write();
                                                        pending.insert(state_token.clone(), PendingOAuth {
                                                            peer_addr,
                                                            created_at: Instant::now(),
                                                        });
                                                    }

                                                    // Build OAuth URL
                                                    let public_host = &server.config.server.public_host;
                                                    let oauth_port = 9000; // OAuth HTTP server port
                                                    let auth_url = format!("http://{}:{}/auth/start?state={}", public_host, oauth_port, state_token);

                                                    // Send AUTH_PENDING with OPEN_URL
                                                    let auth_pending = format!("AUTH_PENDING,timeout 120,OPEN_URL:{}\0", auth_url);
                                                    debug!("Sending AUTH_PENDING to {}: {}", peer_addr, auth_pending.trim_end_matches('\0'));
                                                    if let Err(e) = tls.write_plaintext(auth_pending.as_bytes()) {
                                                        warn!("Failed to send AUTH_PENDING to {}: {}", peer_addr, e);
                                                    }

                                                    // Flush TLS outgoing data for AUTH_PENDING
                                                    while tls.wants_write() {
                                                        if let Some(tls_out) = tls.get_outgoing()
                                                            .map_err(|e| anyhow::anyhow!("TLS outgoing failed: {}", e))?
                                                        {
                                                            let ctrl_packets = conn.protocol.create_control_packets(tls_out)?;
                                                            pending_packets.extend(ctrl_packets);
                                                        } else {
                                                            break;
                                                        }
                                                    }

                                                    info!("Waiting for OAuth authentication from {} (state: {})", peer_addr, state_token);
                                                } else {
                                                    // No OAuth - send PUSH_REPLY immediately
                                                    debug!("Sending PUSH_REPLY to {}: {}", peer_addr, reply_str);
                                                    let reply_bytes = format!("{}\0", reply_str);
                                                    if let Err(e) = tls.write_plaintext(reply_bytes.as_bytes()) {
                                                        warn!("Failed to send PUSH_REPLY to {}: {}", peer_addr, e);
                                                    }

                                                    // Flush TLS outgoing data for push reply
                                                    while tls.wants_write() {
                                                        if let Some(tls_out) = tls.get_outgoing()
                                                            .map_err(|e| anyhow::anyhow!("TLS outgoing failed: {}", e))?
                                                        {
                                                            debug!("Sending {} bytes of push reply TLS data to {}", tls_out.len(), peer_addr);
                                                            let ctrl_packets = conn.protocol.create_control_packets(tls_out)?;
                                                            pending_packets.extend(ctrl_packets);
                                                        } else {
                                                            break;
                                                        }
                                                    }

                                                    conn.protocol.set_state(ProtocolState::Established);
                                                    info!("VPN session established with {} (IP: {})", peer_addr, client_ip);
                                                }
                                            }
                                            Err(e) => {
                                                warn!("Failed to allocate VPN IP for {}: {}", peer_addr, e);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Failed to parse key_method_v2 from {}: {}", peer_addr, e);
                                    }
                                }
                            }
                        }

                        // Log successful authentication if configured
                        if server.config.logging.connection_events.auth_events {
                            log_events.push(ConnectionEventBuilder::with_id(conn.connection_id)
                                .authentication(
                                    peer_addr,
                                    conn.username.clone(),
                                    conn.auth_method.clone(),
                                    crate::connection_log::AuthResult::Success,
                                ));
                        }
                    }

                    // Handle post-handshake TLS data (PUSH_REQUEST, etc.)
                    if tls.is_handshake_complete() && conn.protocol.state() == ProtocolState::Established {
                        let mut buf = vec![0u8; 4096];
                        while let Ok(n) = tls.read_plaintext(&mut buf) {
                            if n == 0 { break; }
                            let msg = String::from_utf8_lossy(&buf[..n]);
                            debug!("Post-handshake plaintext from {}: {:?}", peer_addr, msg.trim_end_matches('\0'));
                            // Client may send additional requests here
                            break;
                        }
                    }
                } else {
                    warn!("Received TLS data from {} but no TLS handler configured", peer_addr);
                }
            }
            ProcessedPacket::HardReset { session_id: _ } => {
                debug!("Late hard reset from {}", peer_addr);
            }
            ProcessedPacket::SoftReset => {
                info!("Key renegotiation from {}", peer_addr);

                // Log renegotiation if configured
                if server.config.logging.connection_events.renegotiations {
                    log_events.push(ConnectionEventBuilder::with_id(conn.connection_id)
                        .renegotiation(peer_addr, true));
                }
            }
            ProcessedPacket::None => {
                // ACK or no action needed
            }
            _ => {}
        }

        // Collect ACKs
        if conn.protocol.should_send_ack() {
            if let Some(ack) = conn.protocol.create_ack_packet() {
                pending_packets.push(ack);
            }
        }

        // Collect retransmits
        for retransmit in conn.protocol.get_retransmits() {
            pending_packets.push(retransmit);
        }

        packets_to_send = pending_packets;
    } // Lock released here

    // Log any events
    for event in log_events {
        server.log_event(event).await;
    }

    // Now send all collected packets without holding the lock
    for packet in packets_to_send {
        socket.send_to(&packet, peer_addr).await?;
    }

    Ok(())
}

async fn handle_data_packet(
    server: &VpnServer,
    socket: &UdpSocket,
    peer_addr: SocketAddr,
    data: &[u8],
    tun_write_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    // Process data inside lock scope, collect results for async operations outside
    let (tun_data, response_packets) = {
        let mut connections = server.connections.write();
        let conn = match connections.get_mut(&peer_addr) {
            Some(c) => c,
            None => {
                debug!("No session for data packet from {}", peer_addr);
                return Ok(());
            }
        };

        conn.touch();

        // Only process data if established
        if conn.protocol.state() != ProtocolState::Established {
            debug!("Data packet before established from {}", peer_addr);
            return Ok(());
        }

        // Track incoming bytes
        conn.add_bytes_rx(data.len() as u64);

        // Debug: hex dump first data packets
        if conn.stats.packets_rx <= 5 {
            let hex: String = data.iter().take(64).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
            info!("Data packet #{} from {} ({} bytes): {}{}", conn.stats.packets_rx, peer_addr, data.len(), hex, if data.len() > 64 { "..." } else { "" });
            // Log opcode parsing
            if !data.is_empty() {
                let opcode_byte = data[0];
                info!("  opcode_byte=0x{:02x} (opcode={}, key_id={})", opcode_byte, opcode_byte >> 3, opcode_byte & 0x07);
            }
        }

        // Process data packet (decrypt)
        let result = conn.protocol.process_packet(data)?;

        let mut tun_data: Option<Vec<u8>> = None;
        let mut response_packets: Vec<Bytes> = Vec::new();

        if let ProcessedPacket::Data(ip_packet) = result {
            if ip_packet.len() == OPENVPN_PING_PAYLOAD.len() && ip_packet.as_ref() == OPENVPN_PING_PAYLOAD {
                // OpenVPN keepalive ping - respond with ping back
                trace!("Received keepalive ping from {}, responding", peer_addr);
                match conn.protocol.encrypt_data(&OPENVPN_PING_PAYLOAD) {
                    Ok(encrypted) => {
                        conn.add_bytes_tx(encrypted.len() as u64);
                        response_packets.push(encrypted);
                    }
                    Err(e) => {
                        warn!("Failed to encrypt ping response for {}: {}", peer_addr, e);
                    }
                }
            } else if ip_packet.len() >= 20 {
                // Real IP packet - forward to TUN device
                trace!("Received {} bytes of tunnel data from {}", ip_packet.len(), peer_addr);
                tun_data = Some(ip_packet.to_vec());
            } else {
                debug!("Short data packet ({} bytes) from {}, ignoring", ip_packet.len(), peer_addr);
            }
        }

        (tun_data, response_packets)
    }; // Connection lock released here

    // Send response packets (ping responses) via UDP - no lock held
    for packet in response_packets {
        if let Err(e) = socket.send_to(&packet, peer_addr).await {
            warn!("Failed to send data packet to {}: {}", peer_addr, e);
        }
    }

    // Write decrypted IP data to TUN device - no lock held
    if let Some(ip_data) = tun_data {
        if let Err(e) = tun_write_tx.try_send(ip_data) {
            warn!("Failed to send to TUN (channel full or closed): {}", e);
        }
    }

    Ok(())
}

/// Handle an IP packet read from the TUN device (route to appropriate client)
async fn handle_tun_packet(
    server: &VpnServer,
    socket: &UdpSocket,
    ip_packet: &[u8],
) -> Result<()> {
    // Extract destination IPv4 address from IP header (bytes 16..20)
    if ip_packet.len() < 20 {
        return Ok(());
    }

    // Check IP version (first nibble)
    let version = ip_packet[0] >> 4;
    if version != 4 {
        trace!("Non-IPv4 packet from TUN (version={}), ignoring", version);
        return Ok(());
    }

    let dest_ip = Ipv4Addr::new(ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]);

    // Find the connection with this VPN IP and encrypt the packet
    let (peer_addr, encrypted) = {
        let mut connections = server.connections.write();
        let conn = connections.values_mut()
            .find(|c| c.vpn_ip == Some(dest_ip) && c.protocol.state() == ProtocolState::Established);

        match conn {
            Some(conn) => {
                match conn.protocol.encrypt_data(ip_packet) {
                    Ok(encrypted) => {
                        conn.add_bytes_tx(encrypted.len() as u64);
                        (conn.peer_addr, encrypted)
                    }
                    Err(e) => {
                        debug!("Failed to encrypt packet for {}: {}", dest_ip, e);
                        return Ok(());
                    }
                }
            }
            None => {
                trace!("No client with VPN IP {}, dropping TUN packet", dest_ip);
                return Ok(());
            }
        }
    }; // Lock released

    // Send encrypted packet to client via UDP
    if let Err(e) = socket.send_to(&encrypted, peer_addr).await {
        warn!("Failed to send encrypted data to {}: {}", peer_addr, e);
    }

    Ok(())
}

/// Send keepalive pings to all established connections
async fn send_keepalive_pings(
    server: &VpnServer,
    socket: &UdpSocket,
) {
    // Collect ping packets while holding lock (sync encrypt operation)
    let ping_packets: Vec<(SocketAddr, Bytes)> = {
        let mut connections = server.connections.write();
        connections.values_mut()
            .filter(|c| c.protocol.state() == ProtocolState::Established)
            .filter_map(|conn| {
                match conn.protocol.encrypt_data(&OPENVPN_PING_PAYLOAD) {
                    Ok(encrypted) => {
                        conn.add_bytes_tx(encrypted.len() as u64);
                        Some((conn.peer_addr, encrypted))
                    }
                    Err(e) => {
                        debug!("Failed to encrypt keepalive for {}: {}", conn.peer_addr, e);
                        None
                    }
                }
            })
            .collect()
    }; // Lock released

    // Send all pings without holding lock
    for (addr, packet) in ping_packets {
        if let Err(e) = socket.send_to(&packet, addr).await {
            debug!("Failed to send keepalive to {}: {}", addr, e);
        }
    }
}

/// Detect the default network interface from the routing table
/// Convert a CIDR notation (e.g., "10.2.0.0/16") to (network, netmask) pair
fn cidr_to_netmask(cidr: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let network = parts[0];
    let prefix_len: u32 = parts[1].parse().ok()?;
    if prefix_len > 32 {
        return None;
    }
    let mask = if prefix_len == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix_len)
    };
    let netmask = format!(
        "{}.{}.{}.{}",
        (mask >> 24) & 0xFF,
        (mask >> 16) & 0xFF,
        (mask >> 8) & 0xFF,
        mask & 0xFF
    );
    Some((network.to_string(), netmask))
}

fn get_default_interface() -> Option<String> {
    if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // Default route has destination 00000000
            if fields.len() >= 2 && fields[1] == "00000000" {
                return Some(fields[0].to_string());
            }
        }
    }
    None
}

/// Statistics for the server
#[derive(Debug, Clone, Default)]
pub struct ServerStats {
    /// Total connections received
    pub connections: u64,
    /// Active sessions
    pub active_sessions: u64,
    /// Bytes received
    pub bytes_rx: u64,
    /// Bytes sent
    pub bytes_tx: u64,
    /// Packets received
    pub packets_rx: u64,
    /// Packets sent
    pub packets_tx: u64,
}

impl ServerStats {
    /// Get current stats from server
    pub fn from_server(server: &VpnServer) -> Self {
        let connections = server.connections.read();
        let active = connections.values()
            .filter(|c| c.protocol.is_established())
            .count();

        Self {
            connections: connections.len() as u64,
            active_sessions: active as u64,
            ..Default::default()
        }
    }
}

/// Set resource limits for the server process
fn set_resource_limits() -> Result<()> {
    use nix::sys::resource::{getrlimit, setrlimit, Resource};

    // Set RLIMIT_NOFILE (file descriptors) - available on all Unix platforms
    let (_, hard_limit) = getrlimit(Resource::RLIMIT_NOFILE)?;
    let soft_limit = (hard_limit.min(65536)).max(1024); // At least 1024, max 65536
    setrlimit(Resource::RLIMIT_NOFILE, soft_limit, hard_limit)?;
    info!("Set RLIMIT_NOFILE to {}", soft_limit);

    // Set RLIMIT_NPROC (processes) - prevent fork bombs (Linux only)
    #[cfg(target_os = "linux")]
    {
        let (_, hard_limit_proc) = getrlimit(Resource::RLIMIT_NPROC)?;
        let soft_limit_proc = (hard_limit_proc.min(4096)).max(256);
        setrlimit(Resource::RLIMIT_NPROC, soft_limit_proc, hard_limit_proc)?;
        info!("Set RLIMIT_NPROC to {}", soft_limit_proc);
    }

    Ok(())
}

/// Drop privileges after binding privileged ports
fn drop_privileges() -> Result<()> {
    use nix::unistd::{getuid, getgid, setuid, setgid, Uid, Gid};

    // Only drop if running as root
    if !getuid().is_root() {
        return Ok(());
    }

    // Try to get target user/group from environment or config
    // Default to "nobody" user/group if available
    let target_uid = std::env::var("COREVPN_USER")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .map(Uid::from_raw)
        .or_else(|| {
            // Try to resolve "nobody" user
            nix::unistd::User::from_name("nobody")
                .ok()
                .flatten()
                .map(|u| u.uid)
        });

    let target_gid = std::env::var("COREVPN_GROUP")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .map(Gid::from_raw)
        .or_else(|| {
            // Try to resolve "nobody" group
            nix::unistd::Group::from_name("nobody")
                .ok()
                .flatten()
                .map(|g| g.gid)
        });

    if let (Some(uid), Some(gid)) = (target_uid, target_gid) {
        // Set group first, then user
        setgid(gid)?;
        setuid(uid)?;
        info!("Dropped privileges to UID {} GID {}", uid, gid);
    } else {
        warn!("Could not drop privileges: target user/group not found");
    }

    Ok(())
}

// ============================================================================
// OAuth HTTP Server
// ============================================================================

/// State shared between OAuth HTTP routes
#[derive(Clone)]
struct OAuthState {
    config: corevpn_config::server::OAuthSettings,
    pending_oauths: PendingOAuthMap,
    auth_completed_tx: tokio::sync::mpsc::Sender<AuthCompleted>,
    public_host: String,
}

/// Handle OAuth authentication completion - send deferred PUSH_REPLY
async fn handle_auth_completed(
    server: &VpnServer,
    socket: &UdpSocket,
    auth: AuthCompleted,
) -> Result<()> {
    let mut connections = server.connections.write();

    // Find connection by OAuth state token
    let peer_addr = {
        let pending = server.pending_oauths.read();
        pending.get(&auth.state).map(|p| p.peer_addr)
    };

    let peer_addr = match peer_addr {
        Some(addr) => addr,
        None => {
            warn!("OAuth completed but no pending auth found for state: {}", auth.state);
            return Ok(());
        }
    };

    // Remove from pending
    {
        let mut pending = server.pending_oauths.write();
        pending.remove(&auth.state);
    }

    let conn = match connections.get_mut(&peer_addr) {
        Some(c) => c,
        None => {
            warn!("OAuth completed but connection gone for {}", peer_addr);
            return Ok(());
        }
    };

    let push_reply_str = match conn.pending_push_reply.take() {
        Some(s) => s,
        None => {
            warn!("OAuth completed but no pending push reply for {}", peer_addr);
            return Ok(());
        }
    };

    // Set authenticated user
    conn.username = Some(auth.email.clone());
    conn.auth_method = AuthMethod::OAuth2;

    // Send PUSH_REPLY through TLS
    let tls = match conn.tls.as_mut() {
        Some(t) => t,
        None => {
            warn!("OAuth completed but no TLS handler for {}", peer_addr);
            return Ok(());
        }
    };

    debug!("Sending deferred PUSH_REPLY to {} (user: {}): {}", peer_addr, auth.email, push_reply_str);
    let reply_bytes = format!("{}\0", push_reply_str);
    if let Err(e) = tls.write_plaintext(reply_bytes.as_bytes()) {
        warn!("Failed to send PUSH_REPLY to {}: {}", peer_addr, e);
        return Ok(());
    }

    // Flush TLS outgoing data
    let mut packets = Vec::new();
    while tls.wants_write() {
        if let Some(tls_out) = tls.get_outgoing()
            .map_err(|e| anyhow::anyhow!("TLS outgoing failed: {}", e))?
        {
            let ctrl_packets = conn.protocol.create_control_packets(tls_out)?;
            packets.extend(ctrl_packets);
        } else {
            break;
        }
    }

    conn.protocol.set_state(ProtocolState::Established);
    let client_ip = conn.vpn_ip.map(|ip| ip.to_string()).unwrap_or_default();
    info!("VPN session established with {} (user: {}, IP: {})", peer_addr, auth.email, client_ip);

    // Release lock before sending UDP
    drop(connections);

    // Send all control packets
    for packet in packets {
        socket.send_to(&packet, peer_addr).await?;
    }

    Ok(())
}

/// Run the OAuth HTTP server for handling SSO callbacks
async fn run_oauth_server(
    oauth_config: corevpn_config::server::OAuthSettings,
    pending_oauths: PendingOAuthMap,
    auth_completed_tx: tokio::sync::mpsc::Sender<AuthCompleted>,
    public_host: String,
) -> Result<()> {
    use axum::{Router, routing::get};

    let state = OAuthState {
        config: oauth_config,
        pending_oauths,
        auth_completed_tx,
        public_host,
    };

    let app = Router::new()
        .route("/auth/start", get(oauth_start))
        .route("/auth/complete", axum::routing::post(oauth_complete))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:9000").await?;
    info!("OAuth HTTP server listening on 0.0.0.0:9000");

    axum::serve(listener, app).await?;

    Ok(())
}

#[derive(serde::Deserialize)]
struct OAuthStartQuery {
    state: String,
}

/// The localhost port that the VPN client's SSO service listens on for OAuth callbacks.
const CLIENT_OAUTH_CALLBACK_PORT: u16 = 19823;

/// OAuth start handler - redirect to Google OAuth
///
/// The redirect_uri points to localhost on the client machine. Google allows
/// `http://localhost` redirect URIs (unlike non-localhost HTTP which is blocked).
/// After Google authenticates the user, it redirects to the client's local server,
/// which then POSTs the auth code to the VPN server's /auth/complete endpoint.
async fn oauth_start(
    axum::extract::State(state): axum::extract::State<OAuthState>,
    axum::extract::Query(query): axum::extract::Query<OAuthStartQuery>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    use axum::http::StatusCode;

    info!("OAuth /auth/start request received with state: {}", query.state);

    // Verify state token exists in pending auths
    {
        let pending = state.pending_oauths.read();
        if !pending.contains_key(&query.state) {
            warn!("OAuth start: invalid state token: {}", query.state);
            return (StatusCode::BAD_REQUEST, "Invalid or expired authentication state").into_response();
        }
    }

    // The redirect goes to localhost on the client. The client's SSO service
    // runs a temporary HTTP server on this port to catch the callback.
    let redirect_uri = format!("http://localhost:{}/oauth/callback", CLIENT_OAUTH_CALLBACK_PORT);

    let auth_url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?\
         client_id={}&\
         redirect_uri={}&\
         response_type=code&\
         scope=openid%20email%20profile&\
         state={}&\
         access_type=online&\
         prompt=consent",
        urlencoding::encode(&state.config.client_id),
        urlencoding::encode(&redirect_uri),
        urlencoding::encode(&query.state),
    );

    info!("OAuth start: redirecting to Google for state: {} (redirect to localhost:{})", query.state, CLIENT_OAUTH_CALLBACK_PORT);
    axum::response::Redirect::temporary(&auth_url).into_response()
}

/// Request body for the /auth/complete endpoint (POST from client's SSO service)
#[derive(serde::Deserialize)]
struct OAuthCompleteRequest {
    code: String,
    state: String,
}

/// OAuth complete handler - receives the auth code from the VPN client's SSO service.
///
/// Flow: Google redirected to localhost on the client -> the client's SSO service
/// caught the callback and POSTs the code + state here -> we exchange code for token,
/// verify the user, and complete the VPN authentication.
async fn oauth_complete(
    axum::extract::State(state): axum::extract::State<OAuthState>,
    axum::extract::Json(body): axum::extract::Json<OAuthCompleteRequest>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    use axum::http::StatusCode;
    use secrecy::ExposeSecret;

    info!("OAuth /auth/complete received for state: {}", body.state);

    // Verify state token
    {
        let pending = state.pending_oauths.read();
        if !pending.contains_key(&body.state) {
            warn!("OAuth complete: invalid state token: {}", body.state);
            return (StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({
                "error": "Invalid or expired authentication state"
            }))).into_response();
        }
    }

    // The redirect_uri must match exactly what was sent to Google in /auth/start
    let redirect_uri = format!("http://localhost:{}/oauth/callback", CLIENT_OAUTH_CALLBACK_PORT);

    // Exchange authorization code for tokens
    let client = reqwest::Client::new();
    let token_response = client.post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", body.code.as_str()),
            ("client_id", state.config.client_id.as_str()),
            ("client_secret", state.config.client_secret.expose_secret()),
            ("redirect_uri", redirect_uri.as_str()),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await;

    let token_response = match token_response {
        Ok(r) => r,
        Err(e) => {
            error!("OAuth token exchange failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({
                "error": "Token exchange failed"
            }))).into_response();
        }
    };

    if !token_response.status().is_success() {
        let body_text = token_response.text().await.unwrap_or_default();
        error!("OAuth token exchange returned error: {}", body_text);
        return (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({
            "error": "Token exchange failed"
        }))).into_response();
    }

    let token_data: serde_json::Value = match token_response.json().await {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to parse OAuth token response: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({
                "error": "Token parse failed"
            }))).into_response();
        }
    };

    // Get user info from the access token
    let access_token = match token_data["access_token"].as_str() {
        Some(t) => t,
        None => {
            error!("No access_token in OAuth response");
            return (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({
                "error": "No access token"
            }))).into_response();
        }
    };

    let userinfo_response = client.get("https://www.googleapis.com/oauth2/v3/userinfo")
        .bearer_auth(access_token)
        .send()
        .await;

    let userinfo: serde_json::Value = match userinfo_response {
        Ok(r) if r.status().is_success() => {
            match r.json().await {
                Ok(v) => v,
                Err(e) => {
                    error!("Failed to parse userinfo: {}", e);
                    return (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({
                        "error": "Userinfo parse failed"
                    }))).into_response();
                }
            }
        }
        Ok(r) => {
            error!("Userinfo request failed with status: {}", r.status());
            return (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({
                "error": "Userinfo request failed"
            }))).into_response();
        }
        Err(e) => {
            error!("Userinfo request failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({
                "error": "Userinfo request failed"
            }))).into_response();
        }
    };

    let email = match userinfo["email"].as_str() {
        Some(e) => e.to_string(),
        None => {
            error!("No email in userinfo response");
            return (StatusCode::FORBIDDEN, axum::Json(serde_json::json!({
                "error": "No email in profile"
            }))).into_response();
        }
    };

    // Check allowed domains
    if !state.config.allowed_domains.is_empty() {
        let email_domain = email.split('@').last().unwrap_or("");
        if !state.config.allowed_domains.iter().any(|d| d == email_domain) {
            warn!("OAuth: email {} not in allowed domains {:?}", email, state.config.allowed_domains);
            return (StatusCode::FORBIDDEN, axum::Json(serde_json::json!({
                "error": "Your email domain is not authorized for VPN access"
            }))).into_response();
        }
    }

    info!("OAuth authentication successful for: {}", email);

    // Notify VPN server of auth completion
    if let Err(e) = state.auth_completed_tx.send(AuthCompleted {
        state: body.state,
        email: email.clone(),
    }).await {
        error!("Failed to send auth completion: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({
            "error": "Internal error"
        }))).into_response();
    }

    // Return success to the client's SSO service
    axum::Json(serde_json::json!({
        "status": "ok",
        "email": email,
    })).into_response()
}
