//! VPN Server Implementation
//!
//! Handles OpenVPN-compatible connections with TLS and OAuth2 authentication.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;
use parking_lot::RwLock;
use tokio::net::UdpSocket;
use tracing::{info, warn, error, debug, trace};

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

    // Drop privileges after binding (if running as root)
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

    // Main receive loop
    let mut buf = vec![0u8; 65535];

    loop {
        let (len, peer_addr) = match socket.recv_from(&mut buf).await {
            Ok(result) => result,
            Err(e) => {
                error!("Receive error: {}", e);
                continue;
            }
        };

        let packet_data = Bytes::copy_from_slice(&buf[..len]);
        let socket_clone = socket.clone();
        let server_clone = server.clone();

        // Handle packet - directly without spawning to avoid Send issues
        // In production, you'd use a message passing channel instead
        if let Err(e) = handle_packet(&server_clone, &socket_clone, peer_addr, packet_data).await {
            debug!("Packet handling error from {}: {}", peer_addr, e);
        }
    }
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
            handle_data_packet(server, socket, peer_addr, &data).await?;
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
                debug!("Received {} TLS record(s) from {}", records.len(), peer_addr);

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

                                        // Generate server's key_method_v2
                                        let server_pre_master: [u8; 48] = corevpn_crypto::random_bytes();
                                        let server_random1: [u8; 32] = corevpn_crypto::random_bytes();
                                        let server_random2: [u8; 32] = corevpn_crypto::random_bytes();

                                        let server_km = corevpn_protocol::KeyMethodV2 {
                                            pre_master: server_pre_master,
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

                                        // Derive data channel keys using TLS EKM
                                        // EKM context uses random1 from both sides
                                        let ekm_label = b"EXPORTER-OpenVPN-datakeys".to_vec();
                                        let mut ekm_context = Vec::new();
                                        ekm_context.extend_from_slice(&client_km.random1);
                                        ekm_context.extend_from_slice(&server_random1);
                                        let mut key_block = vec![0u8; 256];

                                        match tls.export_keying_material(&mut key_block, &ekm_label, Some(&ekm_context)) {
                                            Ok(()) => {
                                                debug!("Derived data channel keys via TLS EKM for {}", peer_addr);
                                                // Key block layout: client_cipher_key(32) + server_cipher_key(32) + client_hmac_key(32) + server_hmac_key(32)
                                                let key_material = corevpn_crypto::KeyMaterial::from_raw_block(&key_block[..128]);
                                                conn.protocol.install_keys(&key_material, true);
                                            }
                                            Err(e) => {
                                                debug!("EKM not available ({}), falling back to PRF key derivation for {}", e, peer_addr);
                                                // Fallback: use OpenVPN PRF with pre-master secrets
                                                let mut combined_pre_master = [0u8; 48];
                                                for i in 0..48 {
                                                    combined_pre_master[i] = client_km.pre_master[i] ^ server_pre_master[i];
                                                }
                                                // PRF seed: client.random1 + server.random1 + client.random2 + server.random2
                                                let mut seed = Vec::new();
                                                seed.extend_from_slice(&client_km.random1);
                                                seed.extend_from_slice(&server_random1);
                                                seed.extend_from_slice(&client_km.random2);
                                                seed.extend_from_slice(&server_random2);

                                                match corevpn_crypto::openvpn_prf(
                                                    &combined_pre_master,
                                                    b"OpenVPN master secret",
                                                    &seed,
                                                    128,
                                                ) {
                                                    Ok(master) => {
                                                        // Expand master secret to key block
                                                        match corevpn_crypto::openvpn_prf(
                                                            &master,
                                                            b"OpenVPN key expansion",
                                                            &seed,
                                                            256,
                                                        ) {
                                                            Ok(key_block) => {
                                                                let key_material = corevpn_crypto::KeyMaterial::from_raw_block(&key_block[..128]);
                                                                conn.protocol.install_keys(&key_material, true);
                                                                debug!("Derived data channel keys via PRF for {}", peer_addr);
                                                            }
                                                            Err(e) => {
                                                                warn!("Key expansion failed for {}: {}", peer_addr, e);
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        warn!("PRF key derivation failed for {}: {}", peer_addr, e);
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

                                                info!("Assigned VPN IP {} to {}", client_ip, peer_addr);

                                                conn.vpn_ip = vpn_addr.ipv4;

                                                let mut push_reply = corevpn_protocol::PushReply::default();
                                                push_reply.ifconfig = Some((client_ip.clone(), gateway_ip.clone()));
                                                push_reply.topology = corevpn_protocol::Topology::Subnet;

                                                // Add DNS from config
                                                for dns in &server.config.network.dns {
                                                    push_reply.dns.push(dns.clone());
                                                }

                                                // Add redirect gateway if configured
                                                push_reply.redirect_gateway = server.config.network.redirect_gateway;

                                                push_reply.ping = 10;
                                                push_reply.ping_restart = 60;

                                                // Push negotiated cipher for NCP
                                                push_reply.options.push(format!("cipher {}", negotiated_cipher));

                                                // Send PUSH_REPLY through TLS
                                                let reply_str = push_reply.encode();
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
    _socket: &UdpSocket,
    peer_addr: SocketAddr,
    data: &[u8],
) -> Result<()> {
    // Get existing connection
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

    // Process data packet
    let result = conn.protocol.process_packet(data)?;

    if let ProcessedPacket::Data(ip_packet) = result {
        trace!("Received {} bytes of tunnel data from {}", ip_packet.len(), peer_addr);
    }

    Ok(())
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
