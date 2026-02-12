//! VPN Client Connection Logic
//!
//! Implements the full OpenVPN-compatible client handshake and data channel,
//! including tls-auth, TLS 1.3, KeyMethodV2 exchange, and TUN forwarding.

use std::process::Command;

use anyhow::{Context, Result, bail};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn, error};

use corevpn_crypto::{CipherSuite, HmacAuth, KeyMaterial};
use corevpn_protocol::{
    KeyMethodV2, ProcessedPacket, ProtocolSession, ProtocolState,
    PushReply, TlsClientHandler, create_client_config, load_certs_from_pem, load_key_from_pem,
};

use crate::ovpn::OvpnConfig;

/// Events emitted during a VPN connection lifecycle.
///
/// Consumers (like the NetworkManager plugin) can receive these events
/// to learn about push reply data (IP, routes, DNS) before the data plane starts.
#[derive(Debug, Clone)]
pub enum ConnectionEvent {
    /// The server sent a PUSH_REPLY with network configuration.
    PushReply {
        /// Assigned IP address and netmask
        ifconfig: Option<(String, String)>,
        /// Routes pushed by the server (network, netmask)
        routes: Vec<(String, String)>,
        /// DNS servers pushed by the server
        dns: Vec<String>,
        /// Gateway address
        gateway: Option<String>,
        /// Whether server wants redirect-gateway (full tunnel)
        redirect_gateway: bool,
    },
    /// TUN device was created and data plane is starting.
    Connected {
        /// Name of the TUN device
        tun_name: String,
    },
    /// An error occurred during connection.
    Error(String),
}

/// VPN client that manages the connection lifecycle
pub struct VpnClient {
    config: OvpnConfig,
}

impl VpnClient {
    /// Create a new VPN client from parsed .ovpn config
    pub fn new(config: OvpnConfig) -> Self {
        Self { config }
    }

    /// Connect to the VPN server and run the tunnel.
    pub async fn connect(&self) -> Result<()> {
        self.connect_with_info(None).await
    }

    /// Connect to the VPN server, sending lifecycle events through the optional channel.
    ///
    /// This is used by the NetworkManager plugin to receive push reply data
    /// (IP, routes, DNS) before the data plane starts, so it can report
    /// the configuration back to NetworkManager.
    pub async fn connect_with_info(
        &self,
        event_tx: Option<tokio::sync::mpsc::UnboundedSender<ConnectionEvent>>,
    ) -> Result<()> {
        info!("Connecting to {} via {}...", self.config.remote, self.config.protocol);

        // Determine cipher suite
        let cipher_suite = match self.config.cipher.to_uppercase().as_str() {
            "CHACHA20-POLY1305" => CipherSuite::ChaCha20Poly1305,
            "AES-256-GCM" => CipherSuite::Aes256Gcm,
            other => bail!("Unsupported cipher: {}", other),
        };

        // Bind UDP socket
        let socket = UdpSocket::bind("0.0.0.0:0").await
            .context("Failed to bind UDP socket")?;
        socket.connect(self.config.remote).await
            .context("Failed to connect UDP socket")?;
        info!("Bound local socket to {}", socket.local_addr()?);

        // Create protocol session (client side)
        let mut session = ProtocolSession::new_client(cipher_suite);

        // Set up tls-auth if configured
        if let Some(ref ta_key_bytes) = self.config.tls_auth_key {
            let ta_key: [u8; 256] = ta_key_bytes[..256].try_into()
                .context("tls-auth key must be 256 bytes")?;
            let key_dir = self.config.key_direction;
            let hmac_auth = HmacAuth::from_ta_key(&ta_key, false, key_dir)
                .map_err(|e| anyhow::anyhow!("Failed to create HMAC auth: {}", e))?;
            session.set_tls_auth(hmac_auth);
            info!("tls-auth enabled (key-direction: {:?})", key_dir);
        }

        // Phase 1: Send hard reset to server
        info!("Sending HARD_RESET_CLIENT_V2...");
        let hard_reset = session.create_hard_reset_client()
            .map_err(|e| anyhow::anyhow!("Failed to create hard reset: {}", e))?;
        socket.send(&hard_reset).await?;

        // Phase 2: Wait for server's hard reset response
        let mut buf = vec![0u8; 4096];
        let _server_response = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            self.receive_until(&socket, &mut session, &mut buf, |pkt| {
                matches!(pkt, ProcessedPacket::HardResetAck)
            }),
        )
        .await
        .context("Timeout waiting for server hard reset response")??;
        info!("Received server hard reset response");

        // Send ACK for server's hard reset
        if let Some(ack) = session.create_ack_packet() {
            socket.send(&ack).await?;
            debug!("Sent ACK for server hard reset");
        }

        // Phase 3: TLS handshake
        info!("Starting TLS handshake...");
        let tls = self.setup_tls_client()?;
        let mut tls = tls;

        // Get initial TLS ClientHello
        let client_hello = tls.get_outgoing()
            .map_err(|e| anyhow::anyhow!("Failed to get ClientHello: {}", e))?
            .context("No ClientHello data")?;

        // Send ClientHello via control channel
        let ctrl_packets = session.create_control_packets(client_hello)
            .map_err(|e| anyhow::anyhow!("Failed to create control packets: {}", e))?;
        for pkt in &ctrl_packets {
            socket.send(pkt).await?;
        }
        debug!("Sent ClientHello ({} control packets)", ctrl_packets.len());

        // Phase 4: Prepare KeyMethodV2 (generated before handshake loop so it
        // can be sent together with the TLS Finished message)
        let pre_master: [u8; 48] = corevpn_crypto::random_bytes();
        let client_random1: [u8; 32] = corevpn_crypto::random_bytes();
        let client_random2: [u8; 32] = corevpn_crypto::random_bytes();

        let client_km = KeyMethodV2 {
            pre_master,
            random1: client_random1,
            random2: client_random2,
            options: format!(
                "V4,dev-type tun,link-mtu 1560,tun-mtu 1500,proto UDPv4,cipher {},auth [null-digest],keysize 256,key-method 2,tls-client",
                self.config.cipher
            ),
            username: None,
            password: None,
            peer_info: Some(format!(
                "IV_VER=corevpn-0.4.0\nIV_PLAT=linux\nIV_NCP=2\nIV_TCPNL=1\nIV_PROTO=30\nIV_CIPHERS=CHACHA20-POLY1305:AES-256-GCM:AES-128-GCM\n"
            )),
        };

        let km_bytes = client_km.encode(false); // false = client

        // TLS handshake loop - exchange TLS records until handshake completes
        let mut handshake_complete = false;
        let mut handshake_attempts = 0;
        const MAX_HANDSHAKE_ATTEMPTS: usize = 50;

        while !handshake_complete {
            handshake_attempts += 1;
            if handshake_attempts > MAX_HANDSHAKE_ATTEMPTS {
                bail!("TLS handshake failed: too many iterations");
            }

            // Receive data from server
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                socket.recv(&mut buf),
            )
            .await
            .context("Timeout during TLS handshake")?
            .context("Failed to receive during TLS handshake")?;

            let result = session.process_packet(&buf[..n])
                .map_err(|e| anyhow::anyhow!("Failed to process packet during handshake: {}", e))?;

            match result {
                ProcessedPacket::TlsData(records) => {
                    // Feed TLS records to the TLS handler
                    tls.process_tls_records(records)
                        .map_err(|e| anyhow::anyhow!("TLS processing failed: {}", e))?;

                    // Send any pending ACKs
                    if session.should_send_ack() {
                        if let Some(ack) = session.create_ack_packet() {
                            socket.send(&ack).await?;
                        }
                    }

                    if tls.is_handshake_complete() {
                        // Handshake just completed. Write the KM2 plaintext
                        // BEFORE flushing TLS so the Finished message and KM2
                        // application data are sent together in the same batch.
                        // This is critical: the corevpn server reads plaintext
                        // immediately when the handshake completes, so the KM2
                        // must be available in the same TLS processing round.
                        info!("Performing key exchange...");
                        session.set_state(ProtocolState::KeyExchange);
                        debug!("Writing {} bytes of key_method_v2 to TLS", km_bytes.len());
                        tls.write_plaintext(&km_bytes)
                            .map_err(|e| anyhow::anyhow!("Failed to write key_method_v2: {}", e))?;

                        // Now flush everything: TLS Finished + KM2 together
                        self.flush_tls_to_socket(&mut tls, &mut session, &socket).await?;
                        handshake_complete = true;
                    } else {
                        // Normal handshake: flush TLS response data
                        while tls.wants_write() {
                            if let Some(tls_out) = tls.get_outgoing()
                                .map_err(|e| anyhow::anyhow!("TLS outgoing failed: {}", e))?
                            {
                                let ctrl_packets = session.create_control_packets(tls_out)
                                    .map_err(|e| anyhow::anyhow!("Failed to create control packets: {}", e))?;
                                for pkt in &ctrl_packets {
                                    socket.send(pkt).await?;
                                }
                            } else {
                                break;
                            }
                        }
                    }
                }
                ProcessedPacket::None => {
                    // ACK or other non-data packet, continue
                }
                other => {
                    debug!("Unexpected packet during handshake: {:?}", other);
                }
            }

            // Check retransmits
            let retransmits = session.get_retransmits();
            for pkt in retransmits {
                socket.send(&pkt).await?;
            }
        }

        info!(
            "TLS handshake complete (cipher: {:?}, version: {:?})",
            tls.cipher_suite(),
            tls.protocol_version()
        );

        // Receive server's key_method_v2 and PUSH_REPLY from TLS stream
        let mut plaintext_buf = vec![0u8; 8192];
        let mut total_plaintext = Vec::new();
        let mut server_km: Option<KeyMethodV2> = None;
        let mut push_reply: Option<PushReply> = None;
        let mut km_attempts = 0;
        const MAX_KM_ATTEMPTS: usize = 100;

        while push_reply.is_none() {
            km_attempts += 1;
            if km_attempts > MAX_KM_ATTEMPTS {
                bail!("Timeout waiting for server key exchange and push reply");
            }

            // Try to read plaintext first (data may already be buffered)
            let n = tls.read_plaintext(&mut plaintext_buf)
                .map_err(|e| anyhow::anyhow!("TLS read failed: {}", e))?;
            if n > 0 {
                total_plaintext.extend_from_slice(&plaintext_buf[..n]);
                debug!("Read {} bytes of TLS plaintext (total: {})", n, total_plaintext.len());

                // Try to parse messages from plaintext
                self.try_parse_server_messages(&mut total_plaintext, &mut server_km, &mut push_reply)?;

                if push_reply.is_some() {
                    break;
                }
                continue;
            }

            // Need more data from network (longer timeout to allow OAuth auth)
            let recv_result = tokio::time::timeout(
                std::time::Duration::from_secs(120),
                socket.recv(&mut buf),
            )
            .await
            .context("Timeout waiting for server key exchange (if OAuth, did you complete auth?)")?
            .context("Failed to receive during key exchange")?;

            debug!("Received {} bytes from server during KM exchange", recv_result);

            let result = session.process_packet(&buf[..recv_result])
                .map_err(|e| anyhow::anyhow!("Failed to process packet during key exchange: {}", e))?;

            match result {
                ProcessedPacket::TlsData(records) => {
                    debug!("Got {} TLS records during KM exchange", records.len());
                    tls.process_tls_records(records)
                        .map_err(|e| anyhow::anyhow!("TLS processing failed: {}", e))?;

                    // Send ACKs
                    if session.should_send_ack() {
                        if let Some(ack) = session.create_ack_packet() {
                            socket.send(&ack).await?;
                            debug!("Sent ACK during KM exchange");
                        }
                    }

                    // Flush any TLS responses
                    self.flush_tls_to_socket(&mut tls, &mut session, &socket).await?;
                }
                ProcessedPacket::None => {
                    debug!("Got None (ACK) during KM exchange");
                    // May need to send ACKs back
                    if session.should_send_ack() {
                        if let Some(ack) = session.create_ack_packet() {
                            socket.send(&ack).await?;
                        }
                    }
                }
                other => {
                    debug!("Unexpected packet during key exchange: {:?}", other);
                }
            }

            // Check for retransmissions
            let retransmits = session.get_retransmits();
            for pkt in retransmits {
                socket.send(&pkt).await?;
                debug!("Retransmitted control packet during KM exchange");
            }
        }

        let server_km = server_km.context("Never received server KeyMethodV2")?;
        let push_reply = push_reply.unwrap();

        // Notify listeners of push reply data (for NM plugin integration)
        if let Some(ref tx) = event_tx {
            let _ = tx.send(ConnectionEvent::PushReply {
                ifconfig: push_reply.ifconfig.clone(),
                routes: push_reply.routes.iter()
                    .map(|r| (r.network.clone(), r.netmask.clone()))
                    .collect(),
                dns: push_reply.dns.clone(),
                gateway: push_reply.route_gateway.clone(),
                redirect_gateway: push_reply.redirect_gateway,
            });
        }

        // Phase 5: Key derivation via OpenVPN PRF
        info!("Deriving data channel keys...");
        let client_sid = *session.local_session_id();
        let server_sid = session.remote_session_id()
            .copied()
            .context("Missing remote session ID")?;

        // Step 1: master_secret = PRF(pre_master, "OpenVPN master secret", client_r1 || server_r1, 48)
        let mut seed1 = Vec::with_capacity(64);
        seed1.extend_from_slice(&client_random1);
        seed1.extend_from_slice(&server_km.random1);
        let master_secret = corevpn_crypto::openvpn_prf(
            &pre_master,
            b"OpenVPN master secret",
            &seed1,
            48,
        ).map_err(|e| anyhow::anyhow!("PRF master secret failed: {}", e))?;

        debug!("PRF master_secret[..8]={:02x?}", &master_secret[..8]);

        // Step 2: key_block = PRF(master_secret, "OpenVPN key expansion",
        //                         client_r2 || server_r2 || client_sid || server_sid, 256)
        let mut seed2 = Vec::with_capacity(64 + 16);
        seed2.extend_from_slice(&client_random2);
        seed2.extend_from_slice(&server_km.random2);
        seed2.extend_from_slice(&client_sid);
        seed2.extend_from_slice(&server_sid);
        let key_block = corevpn_crypto::openvpn_prf(
            &master_secret,
            b"OpenVPN key expansion",
            &seed2,
            256,
        ).map_err(|e| anyhow::anyhow!("PRF key expansion failed: {}", e))?;

        let km = KeyMaterial::from_openvpn_key2_block(&key_block);

        // Install keys (false = client side: encrypt with client key, decrypt with server key)
        session.install_keys(&km, false);
        info!("Installed data channel keys");

        // Phase 6: Configure TUN device
        let (ifconfig_ip, ifconfig_mask) = push_reply.ifconfig.as_ref()
            .context("PUSH_REPLY missing ifconfig")?
            .clone();

        info!("VPN IP: {} / {}", ifconfig_ip, ifconfig_mask);
        if let Some(ref gw) = push_reply.route_gateway {
            info!("Gateway: {}", gw);
        }
        for dns in &push_reply.dns {
            info!("DNS: {}", dns);
        }

        // Set state to established
        session.set_state(ProtocolState::Established);
        info!("VPN session established!");

        // Create TUN device
        let tun_dev = self.create_tun_device(&ifconfig_ip, &ifconfig_mask, &push_reply)?;

        // Notify listeners that the TUN device is up
        if let Some(ref tx) = event_tx {
            let _ = tx.send(ConnectionEvent::Connected {
                tun_name: "tun0".to_string(), // TUN crate doesn't expose the name easily
            });
        }

        // Phase 7: Data plane - forward packets between TUN and UDP
        info!("Starting data plane forwarding...");
        self.run_data_plane(socket, session, tun_dev, &push_reply).await
    }

    /// Set up TLS client handler
    fn setup_tls_client(&self) -> Result<TlsClientHandler> {
        // Install ring as the crypto provider for rustls
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Parse CA certificate
        let ca_certs = load_certs_from_pem(&self.config.ca_pem)
            .map_err(|e| anyhow::anyhow!("Failed to load CA cert: {}", e))?;

        // Parse client certificate and key for mTLS
        let client_certs = load_certs_from_pem(&self.config.cert_pem)
            .map_err(|e| anyhow::anyhow!("Failed to load client cert: {}", e))?;
        let client_key = load_key_from_pem(&self.config.key_pem)
            .map_err(|e| anyhow::anyhow!("Failed to load client key: {}", e))?;

        // Create TLS config
        let tls_config = create_client_config(
            ca_certs,
            Some((client_certs, client_key)),
        ).map_err(|e| anyhow::anyhow!("Failed to create TLS config: {}", e))?;

        // Create TLS handler - use "corevpn" as server name (will be validated by our custom verifier)
        let server_name = rustls::pki_types::ServerName::try_from("corevpn")
            .map_err(|e| anyhow::anyhow!("Invalid server name: {}", e))?
            .to_owned();

        TlsClientHandler::new(tls_config, server_name)
            .map_err(|e| anyhow::anyhow!("Failed to create TLS handler: {}", e))
    }

    /// Create and configure the TUN device
    fn create_tun_device(
        &self,
        ip: &str,
        mask: &str,
        push_reply: &PushReply,
    ) -> Result<tun::AsyncDevice> {
        let mut config = tun::Configuration::default();
        config.address(ip.parse::<std::net::Ipv4Addr>()?)
            .netmask(mask.parse::<std::net::Ipv4Addr>()?)
            .mtu(1500)
            .up();

        let dev = tun::create_as_async(&config)
            .context("Failed to create TUN device. Are you running as root/with CAP_NET_ADMIN?")?;

        info!("TUN device created");

        // Configure routes
        if push_reply.redirect_gateway {
            if let Some(ref gw) = push_reply.route_gateway {
                info!("Setting up full tunnel (redirect-gateway) via {}", gw);
                // Note: Full gateway redirect requires careful route manipulation
                // to avoid routing loops. For now, just add the VPN subnet route.
            }
        }

        for route in &push_reply.routes {
            info!("Adding route: {} {} via VPN", route.network, route.netmask);
            // Routes will be configured via the OS
            if let Err(e) = add_route(&route.network, &route.netmask, ip) {
                warn!("Failed to add route {} {}: {}", route.network, route.netmask, e);
            }
        }

        Ok(dev)
    }

    /// Flush TLS outgoing data to the UDP socket via control packets.
    ///
    /// Collects ALL pending TLS output into a single buffer before wrapping
    /// in control packets. This is critical: the TLS Finished message and
    /// any immediately-following application data (like KeyMethodV2) must
    /// arrive in the same control packet batch so the server can process
    /// them together in a single round.
    async fn flush_tls_to_socket(
        &self,
        tls: &mut TlsClientHandler,
        session: &mut ProtocolSession,
        socket: &UdpSocket,
    ) -> Result<()> {
        // Collect all pending TLS output first
        let mut all_tls_data = Vec::new();
        while tls.wants_write() {
            if let Some(tls_out) = tls.get_outgoing()
                .map_err(|e| anyhow::anyhow!("TLS outgoing failed: {}", e))?
            {
                all_tls_data.extend_from_slice(&tls_out);
            } else {
                break;
            }
        }
        if !all_tls_data.is_empty() {
            debug!("Flushing {} bytes of TLS data to control channel", all_tls_data.len());
            let tls_data = bytes::Bytes::from(all_tls_data);
            let ctrl_packets = session.create_control_packets(tls_data)
                .map_err(|e| anyhow::anyhow!("Failed to create control packets: {}", e))?;
            for pkt in &ctrl_packets {
                socket.send(pkt).await?;
            }
        }
        Ok(())
    }

    /// Try to parse server KeyMethodV2 and PUSH_REPLY from accumulated plaintext
    fn try_parse_server_messages(
        &self,
        total_plaintext: &mut Vec<u8>,
        server_km: &mut Option<KeyMethodV2>,
        push_reply: &mut Option<PushReply>,
    ) -> Result<()> {
        // Try to parse server's KeyMethodV2 if we haven't yet
        if server_km.is_none() && total_plaintext.len() >= 71 {
            match KeyMethodV2::parse_from_server(total_plaintext) {
                Ok(km) => {
                    debug!("Parsed server KeyMethodV2 (options: {})", km.options);

                    // Determine how many bytes the KM consumed
                    let km_size = calculate_km_size(total_plaintext)?;
                    let remaining = total_plaintext.split_off(km_size);
                    *total_plaintext = remaining;

                    *server_km = Some(km);
                    debug!("Remaining plaintext after KM: {} bytes", total_plaintext.len());
                }
                Err(e) => {
                    debug!("Not enough data for KeyMethodV2 yet: {}", e);
                }
            }
        }

        // Try to parse control messages if we have server_km
        if server_km.is_some() && !total_plaintext.is_empty() {
            // Strip leading null bytes (separators between messages)
            while total_plaintext.first() == Some(&0) {
                total_plaintext.remove(0);
            }
            if total_plaintext.is_empty() {
                return Ok(());
            }

            let msg = String::from_utf8_lossy(total_plaintext);
            let msg_str = msg.trim_end_matches('\0');
            debug!("Checking plaintext for control message: {:?}", msg_str);

            if msg_str.starts_with("PUSH_REPLY") {
                *push_reply = Some(PushReply::parse(msg_str)
                    .map_err(|e| anyhow::anyhow!("Failed to parse PUSH_REPLY: {}", e))?);
                info!("Received PUSH_REPLY");
            } else if msg_str.contains("AUTH_PENDING") {
                info!("Server requires authentication (pending)");
                total_plaintext.clear();
            } else if msg_str.starts_with("INFO_PRE,WEB_AUTH:") {
                // WEB_AUTH format: INFO_PRE,WEB_AUTH:flags:url
                // flags may be empty, so the URL follows the second ':'
                if let Some(rest) = msg_str.strip_prefix("INFO_PRE,WEB_AUTH:") {
                    // Skip flags (everything up to the next ':')
                    let url = rest.split_once(':').map(|(_, u)| u).unwrap_or(rest).trim();
                    info!("Server requires OAuth authentication.");
                    info!("Please open this URL in your browser: {}", url);
                    eprintln!("\n  Open this URL to authenticate:\n  {}\n", url);
                }
                total_plaintext.clear();
            } else if msg_str.starts_with("INFO_PRE,OPEN_URL:") {
                // Deprecated OPEN_URL format
                let url = msg_str.strip_prefix("INFO_PRE,OPEN_URL:").unwrap_or("").trim();
                info!("Server requires OAuth authentication.");
                info!("Please open this URL in your browser: {}", url);
                eprintln!("\n  Open this URL to authenticate:\n  {}\n", url);
                total_plaintext.clear();
            }
        }

        Ok(())
    }

    /// Receive packets until a condition is met
    async fn receive_until(
        &self,
        socket: &UdpSocket,
        session: &mut ProtocolSession,
        buf: &mut [u8],
        condition: impl Fn(&ProcessedPacket) -> bool,
    ) -> Result<ProcessedPacket> {
        loop {
            let n = socket.recv(buf).await
                .context("Failed to receive packet")?;

            let result = session.process_packet(&buf[..n])
                .map_err(|e| anyhow::anyhow!("Failed to process packet: {}", e))?;

            if condition(&result) {
                return Ok(result);
            }
        }
    }

    /// Main data plane forwarding loop
    async fn run_data_plane(
        &self,
        socket: UdpSocket,
        mut session: ProtocolSession,
        tun_dev: tun::AsyncDevice,
        push_reply: &PushReply,
    ) -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut tun_reader, mut tun_writer) = tokio::io::split(tun_dev);

        let mut udp_buf = vec![0u8; 4096];
        let mut tun_buf = vec![0u8; 2048];

        // Ping timer
        let ping_interval = std::time::Duration::from_secs(push_reply.ping as u64);
        let ping_restart = std::time::Duration::from_secs(push_reply.ping_restart as u64);
        let mut last_recv = tokio::time::Instant::now();
        let mut ping_timer = tokio::time::interval(ping_interval);
        ping_timer.tick().await; // First tick is immediate

        info!("Data plane active (ping: {}s, restart: {}s)", push_reply.ping, push_reply.ping_restart);

        loop {
            tokio::select! {
                // Read from TUN -> encrypt -> send to server
                result = tun_reader.read(&mut tun_buf) => {
                    match result {
                        Ok(0) => {
                            info!("TUN device closed");
                            break;
                        }
                        Ok(n) => {
                            match session.encrypt_data(&tun_buf[..n]) {
                                Ok(encrypted) => {
                                    if let Err(e) = socket.send(&encrypted).await {
                                        warn!("Failed to send encrypted data: {}", e);
                                    }
                                }
                                Err(e) => {
                                    warn!("Failed to encrypt data: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("TUN read error: {}", e);
                            break;
                        }
                    }
                }

                // Read from server -> decrypt -> write to TUN
                result = socket.recv(&mut udp_buf) => {
                    match result {
                        Ok(n) => {
                            last_recv = tokio::time::Instant::now();

                            match session.process_packet(&udp_buf[..n]) {
                                Ok(ProcessedPacket::Data(decrypted)) => {
                                    if let Err(e) = tun_writer.write_all(&decrypted).await {
                                        warn!("Failed to write to TUN: {}", e);
                                    }
                                }
                                Ok(ProcessedPacket::None) => {
                                    // ACK or keepalive - send ACK if needed
                                    if session.should_send_ack() {
                                        if let Some(ack) = session.create_ack_packet() {
                                            let _ = socket.send(&ack).await;
                                        }
                                    }
                                }
                                Ok(ProcessedPacket::TlsData(_)) => {
                                    debug!("Received post-handshake TLS data (ignored)");
                                    if session.should_send_ack() {
                                        if let Some(ack) = session.create_ack_packet() {
                                            let _ = socket.send(&ack).await;
                                        }
                                    }
                                }
                                Ok(other) => {
                                    debug!("Unexpected packet in data plane: {:?}", other);
                                }
                                Err(e) => {
                                    debug!("Failed to process packet: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("UDP recv error: {}", e);
                            break;
                        }
                    }
                }

                // Send OpenVPN ping (keepalive)
                _ = ping_timer.tick() => {
                    // Check if we've timed out
                    if last_recv.elapsed() > ping_restart {
                        error!("Connection timed out (no data for {}s)", ping_restart.as_secs());
                        break;
                    }

                    // Send OpenVPN ping packet (0x2a 0x18 0x7b 0xf3 0x64 0x1e 0xb4 0xcb 0x07 0xed 0x2d 0x0a 0x98 0x1f 0xc7 0x48)
                    // This is the well-known OpenVPN ping payload
                    let ping_payload: [u8; 16] = [
                        0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
                        0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
                    ];
                    match session.encrypt_data(&ping_payload) {
                        Ok(encrypted) => {
                            if let Err(e) = socket.send(&encrypted).await {
                                warn!("Failed to send ping: {}", e);
                            }
                        }
                        Err(e) => {
                            debug!("Failed to encrypt ping: {}", e);
                        }
                    }
                }
            }
        }

        info!("VPN connection closed");
        Ok(())
    }
}

/// Calculate the byte size of a server KeyMethodV2 message
fn calculate_km_size(data: &[u8]) -> Result<usize> {
    // Server KM2 format (no pre_master):
    // 4 (literal zero) + 1 (key method) + 32 (random1) + 32 (random2) = 69
    // Then length-prefixed strings: options, username, password
    if data.len() < 71 {
        bail!("KeyMethodV2 data too short");
    }

    let mut offset = 69; // After fixed header

    // Skip length-prefixed strings (options, then optional username, password)
    // The server may send empty username/password as length-prefixed empty strings
    for _ in 0..3 {
        if offset + 2 > data.len() {
            break;
        }
        let str_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        if offset + 2 + str_len > data.len() {
            break;
        }
        offset += 2 + str_len;
    }

    Ok(offset)
}

/// Add a route via the OS
fn add_route(network: &str, netmask: &str, gateway: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // Convert netmask to prefix length
        let mask: std::net::Ipv4Addr = netmask.parse()?;
        let mask_bits: u32 = u32::from(mask);
        let prefix_len = mask_bits.count_ones();

        let output = Command::new("ip")
            .args(["route", "add", &format!("{}/{}", network, prefix_len), "via", gateway])
            .output()
            .context("Failed to execute ip route add")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore "File exists" errors (route already exists)
            if !stderr.contains("File exists") {
                warn!("ip route add failed: {}", stderr.trim());
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        warn!("Route configuration not implemented for this platform");
    }

    Ok(())
}
