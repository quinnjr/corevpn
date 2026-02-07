//! Control Channel Message Types

use std::net::Ipv4Addr;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::{ProtocolError, Result};

/// Validate that a string is a valid IPv4 address
fn validate_ipv4(s: &str) -> Result<()> {
    s.parse::<Ipv4Addr>()
        .map_err(|_| ProtocolError::InvalidPacket(format!("invalid IPv4 address: {}", s)))?;
    Ok(())
}

/// Control channel message types
#[derive(Debug, Clone)]
pub enum ControlMessage {
    /// TLS data (wrapped in control channel)
    TlsData(Bytes),
    /// Push request from client
    PushRequest,
    /// Push reply from server
    PushReply(PushReply),
    /// Authentication data
    Auth(AuthMessage),
    /// Info message (version, etc.)
    Info(String),
    /// Exit/shutdown
    Exit,
}

/// Control packet for the reliable transport layer
#[derive(Debug, Clone)]
pub struct ControlPacket {
    /// Packet ID for reliability
    pub packet_id: u32,
    /// Message content
    pub message: ControlMessage,
}

impl ControlPacket {
    /// Create a new control packet
    pub fn new(packet_id: u32, message: ControlMessage) -> Self {
        Self { packet_id, message }
    }
}

/// Push reply containing VPN configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushReply {
    /// Routes to push
    pub routes: Vec<PushRoute>,
    /// IPv4 address and netmask
    pub ifconfig: Option<(String, String)>,
    /// IPv6 address
    pub ifconfig_ipv6: Option<String>,
    /// DNS servers
    pub dns: Vec<String>,
    /// Search domains
    pub dns_search: Vec<String>,
    /// Redirect gateway (full tunnel)
    pub redirect_gateway: bool,
    /// Route gateway (VPN gateway IP for redirect-gateway)
    pub route_gateway: Option<String>,
    /// Topology type
    pub topology: Topology,
    /// Ping interval
    pub ping: u32,
    /// Ping restart timeout
    pub ping_restart: u32,
    /// Additional options
    pub options: Vec<String>,
}

impl Default for PushReply {
    fn default() -> Self {
        Self {
            routes: vec![],
            ifconfig: None,
            ifconfig_ipv6: None,
            dns: vec![],
            dns_search: vec![],
            redirect_gateway: false,
            route_gateway: None,
            topology: Topology::Subnet,
            ping: 10,
            ping_restart: 60,
            options: vec![],
        }
    }
}

impl PushReply {
    /// Encode as OpenVPN push reply string
    pub fn encode(&self) -> String {
        let mut parts = vec!["PUSH_REPLY".to_string()];

        // Topology
        parts.push(format!("topology {}", self.topology.as_str()));

        // ifconfig
        if let Some((ip, mask)) = &self.ifconfig {
            parts.push(format!("ifconfig {} {}", ip, mask));
        }

        // ifconfig-ipv6
        if let Some(ipv6) = &self.ifconfig_ipv6 {
            parts.push(format!("ifconfig-ipv6 {}", ipv6));
        }

        // Routes
        for route in &self.routes {
            parts.push(route.encode());
        }

        // Route gateway (must come before redirect-gateway)
        if let Some(gw) = &self.route_gateway {
            parts.push(format!("route-gateway {}", gw));
        }

        // Redirect gateway
        if self.redirect_gateway {
            parts.push("redirect-gateway def1".to_string());
        }

        // DNS
        for dns in &self.dns {
            parts.push(format!("dhcp-option DNS {}", dns));
        }

        // DNS search domains
        for domain in &self.dns_search {
            parts.push(format!("dhcp-option DOMAIN {}", domain));
        }

        // Ping settings
        parts.push(format!("ping {}", self.ping));
        parts.push(format!("ping-restart {}", self.ping_restart));

        // Additional options
        for opt in &self.options {
            parts.push(opt.clone());
        }

        parts.join(",")
    }

    /// Parse from OpenVPN push reply string
    pub fn parse(s: &str) -> Result<Self> {
        let mut reply = Self::default();

        // Remove PUSH_REPLY prefix if present
        let s = s.strip_prefix("PUSH_REPLY,").unwrap_or(s);

        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let mut tokens = part.split_whitespace();
            match tokens.next() {
                Some("topology") => {
                    if let Some(topo) = tokens.next() {
                        reply.topology = Topology::parse(topo);
                    }
                }
                Some("ifconfig") => {
                    let ip = tokens.next().unwrap_or("").to_string();
                    let mask = tokens.next().unwrap_or("").to_string();
                    reply.ifconfig = Some((ip, mask));
                }
                Some("ifconfig-ipv6") => {
                    if let Some(ipv6) = tokens.next() {
                        reply.ifconfig_ipv6 = Some(ipv6.to_string());
                    }
                }
                Some("route") => {
                    if let Ok(route) = PushRoute::parse(part) {
                        reply.routes.push(route);
                    }
                }
                Some("route-gateway") => {
                    if let Some(gw) = tokens.next() {
                        reply.route_gateway = Some(gw.to_string());
                    }
                }
                Some("redirect-gateway") => {
                    reply.redirect_gateway = true;
                }
                Some("dhcp-option") => {
                    match tokens.next() {
                        Some("DNS") => {
                            if let Some(dns) = tokens.next() {
                                reply.dns.push(dns.to_string());
                            }
                        }
                        Some("DOMAIN") => {
                            if let Some(domain) = tokens.next() {
                                reply.dns_search.push(domain.to_string());
                            }
                        }
                        _ => {}
                    }
                }
                Some("ping") => {
                    if let Some(Ok(p)) = tokens.next().map(|s| s.parse()) {
                        reply.ping = p;
                    }
                }
                Some("ping-restart") => {
                    if let Some(Ok(p)) = tokens.next().map(|s| s.parse()) {
                        reply.ping_restart = p;
                    }
                }
                _ => {
                    reply.options.push(part.to_string());
                }
            }
        }

        Ok(reply)
    }
}

/// Route to push to client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushRoute {
    /// Network address
    pub network: String,
    /// Netmask
    pub netmask: String,
    /// Gateway (optional, vpn_gateway used if not set)
    pub gateway: Option<String>,
    /// Metric
    pub metric: Option<u32>,
}

impl PushRoute {
    /// Create a new route
    pub fn new(network: &str, netmask: &str) -> Self {
        Self {
            network: network.to_string(),
            netmask: netmask.to_string(),
            gateway: None,
            metric: None,
        }
    }

    /// Encode as OpenVPN route directive
    pub fn encode(&self) -> String {
        let mut s = format!("route {} {}", self.network, self.netmask);
        if let Some(gw) = &self.gateway {
            s.push_str(&format!(" {}", gw));
        } else {
            s.push_str(" vpn_gateway");
        }
        if let Some(metric) = self.metric {
            s.push_str(&format!(" {}", metric));
        }
        s
    }

    /// Parse from OpenVPN route directive
    pub fn parse(s: &str) -> Result<Self> {
        let mut tokens = s.split_whitespace();
        tokens.next(); // skip "route"

        let network_str = tokens
            .next()
            .ok_or_else(|| ProtocolError::InvalidPacket("missing network in route".into()))?;
        
        // Validate network address
        validate_ipv4(network_str)?;
        let network = network_str.to_string();

        let netmask_str = tokens
            .next()
            .ok_or_else(|| ProtocolError::InvalidPacket("missing netmask in route".into()))?;
        
        // Validate netmask
        validate_ipv4(netmask_str)?;
        let netmask = netmask_str.to_string();

        let gateway = tokens.next().and_then(|g| {
            if g == "vpn_gateway" {
                None
            } else {
                // Validate gateway IP address
                validate_ipv4(g).ok().map(|_| g.to_string())
            }
        });

        let metric = tokens.next().and_then(|m| {
            m.parse::<u32>().ok().filter(|&m| m <= 9999) // Reasonable metric limit
        });

        Ok(Self {
            network,
            netmask,
            gateway,
            metric,
        })
    }
}

/// Network topology type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Topology {
    /// Point-to-point (net30)
    Net30,
    /// Point-to-point (p2p)
    P2P,
    /// Subnet mode (recommended)
    #[default]
    Subnet,
}

impl Topology {
    /// Parse from string
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "net30" => Topology::Net30,
            "p2p" => Topology::P2P,
            "subnet" => Topology::Subnet,
            _ => Topology::Subnet,
        }
    }

    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            Topology::Net30 => "net30",
            Topology::P2P => "p2p",
            Topology::Subnet => "subnet",
        }
    }
}

/// Authentication message from client
#[derive(Debug, Clone)]
pub struct AuthMessage {
    /// Username
    pub username: String,
    /// Password
    pub password: String,
}

impl AuthMessage {
    /// Maximum username length
    const MAX_USERNAME_LEN: usize = 256;
    /// Maximum password length
    const MAX_PASSWORD_LEN: usize = 1024;

    /// Parse from OpenVPN auth data
    pub fn parse(data: &[u8]) -> Result<Self> {
        // Format: username\0password\0
        // Security: Limit total input size to prevent DoS
        if data.len() > Self::MAX_USERNAME_LEN + Self::MAX_PASSWORD_LEN + 2 {
            return Err(ProtocolError::InvalidPacket("auth data too long".into()));
        }

        let s = std::str::from_utf8(data)
            .map_err(|_| ProtocolError::InvalidPacket("invalid UTF-8 in auth".into()))?;

        let parts: Vec<&str> = s.split('\0').collect();
        if parts.len() < 2 {
            return Err(ProtocolError::InvalidPacket("missing auth fields".into()));
        }

        let username = parts[0];
        let password = parts[1];

        // Validate lengths
        if username.len() > Self::MAX_USERNAME_LEN {
            return Err(ProtocolError::InvalidPacket(
                format!("username too long (max {} bytes)", Self::MAX_USERNAME_LEN).into(),
            ));
        }
        if password.len() > Self::MAX_PASSWORD_LEN {
            return Err(ProtocolError::InvalidPacket(
                format!("password too long (max {} bytes)", Self::MAX_PASSWORD_LEN).into(),
            ));
        }

        Ok(Self {
            username: username.to_string(),
            password: password.to_string(),
        })
    }

    /// Encode to OpenVPN auth format
    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.username.as_bytes());
        data.push(0);
        data.extend_from_slice(self.password.as_bytes());
        data.push(0);
        data
    }
}

/// Key method v2 data (exchanged during TLS handshake)
#[derive(Debug, Clone)]
pub struct KeyMethodV2 {
    /// Pre-master secret (48 bytes)
    pub pre_master: [u8; 48],
    /// Random data 1 (32 bytes) - used as EKM context and PRF seed
    pub random1: [u8; 32],
    /// Random data 2 (32 bytes) - used as additional PRF seed
    pub random2: [u8; 32],
    /// Options string
    pub options: String,
    /// Username (if using auth)
    pub username: Option<String>,
    /// Password (if using auth)
    pub password: Option<String>,
    /// Peer info
    pub peer_info: Option<String>,
}

impl KeyMethodV2 {
    /// Parse key method v2 data from bytes (received from TLS plaintext)
    ///
    /// Format (OpenVPN key_source + metadata):
    /// - 4 bytes: literal 0
    /// - 1 byte: key method (must be 2)
    /// - 48 bytes: pre-master secret
    /// - 32 bytes: random1
    /// - 32 bytes: random2
    /// - 2 bytes + N bytes: options string (length-prefixed, null-terminated)
    /// - 2 bytes + N bytes: username (length-prefixed, optional)
    /// - 2 bytes + N bytes: password (length-prefixed, optional)
    /// - 2 bytes + N bytes: peer_info (length-prefixed, optional)
    pub fn parse(data: &[u8]) -> Result<Self> {
        // Minimum: 4 + 1 + 48 + 32 + 32 + 2 = 119 bytes
        if data.len() < 119 {
            return Err(ProtocolError::PacketTooShort {
                expected: 119,
                got: data.len(),
            });
        }

        let mut offset = 0;

        // Skip 4 bytes literal zero
        offset += 4;

        // Key method byte (must be 2)
        let key_method = data[offset];
        offset += 1;
        if key_method != 2 {
            return Err(ProtocolError::InvalidPacket(
                format!("unsupported key method: {}", key_method),
            ));
        }

        // Pre-master secret (48 bytes)
        let mut pre_master = [0u8; 48];
        pre_master.copy_from_slice(&data[offset..offset + 48]);
        offset += 48;

        // Random1 (32 bytes)
        let mut random1 = [0u8; 32];
        random1.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        // Random2 (32 bytes)
        let mut random2 = [0u8; 32];
        random2.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        // Options string (length-prefixed)
        let options = Self::read_length_prefixed_string(data, &mut offset)?;

        // Username (optional, length-prefixed)
        let username = if offset + 2 <= data.len() {
            let s = Self::read_length_prefixed_string(data, &mut offset)?;
            if s.is_empty() { None } else { Some(s) }
        } else {
            None
        };

        // Password (optional, length-prefixed)
        let password = if offset + 2 <= data.len() {
            let s = Self::read_length_prefixed_string(data, &mut offset)?;
            if s.is_empty() { None } else { Some(s) }
        } else {
            None
        };

        // Peer info (optional, length-prefixed)
        let peer_info = if offset + 2 <= data.len() {
            let s = Self::read_length_prefixed_string(data, &mut offset)?;
            if s.is_empty() { None } else { Some(s) }
        } else {
            None
        };

        Ok(Self {
            pre_master,
            random1,
            random2,
            options,
            username,
            password,
            peer_info,
        })
    }

    /// Read a length-prefixed string from the buffer
    fn read_length_prefixed_string(data: &[u8], offset: &mut usize) -> Result<String> {
        if *offset + 2 > data.len() {
            return Err(ProtocolError::PacketTooShort {
                expected: *offset + 2,
                got: data.len(),
            });
        }
        let len = u16::from_be_bytes([data[*offset], data[*offset + 1]]) as usize;
        *offset += 2;
        if *offset + len > data.len() {
            return Err(ProtocolError::PacketTooShort {
                expected: *offset + len,
                got: data.len(),
            });
        }
        let s = std::str::from_utf8(&data[*offset..*offset + len])
            .map_err(|_| ProtocolError::InvalidPacket("invalid UTF-8 in key method v2".into()))?;
        *offset += len;
        // Trim trailing null bytes (OpenVPN often null-terminates strings)
        Ok(s.trim_end_matches('\0').to_string())
    }

    /// Write a null-terminated string in OpenVPN's wire format:
    /// u16 length (including null terminator) + string bytes + null byte
    fn write_string(buf: &mut Vec<u8>, s: &str) {
        let len = s.len() + 1; // include null terminator
        buf.extend_from_slice(&(len as u16).to_be_bytes());
        buf.extend_from_slice(s.as_bytes());
        buf.push(0); // null terminator
    }

    /// Encode to bytes (OpenVPN key_method_v2 wire format)
    ///
    /// When `is_server` is true (server writing its response), pre_master is
    /// NOT included in the key source material -- only random1 and random2.
    /// When `is_server` is false (client writing), pre_master IS included.
    /// This matches the OpenVPN key_source2_randomize_write asymmetry.
    pub fn encode(&self, is_server: bool) -> Vec<u8> {
        let mut buf = Vec::new();

        // Literal 0
        buf.extend_from_slice(&[0u8; 4]);

        // Key method (2)
        buf.push(2);

        // Key source material:
        // Client writes: pre_master(48) + random1(32) + random2(32) = 112 bytes
        // Server writes: random1(32) + random2(32) = 64 bytes
        if !is_server {
            buf.extend_from_slice(&self.pre_master);
        }

        // Random1 (32 bytes)
        buf.extend_from_slice(&self.random1);

        // Random2 (32 bytes)
        buf.extend_from_slice(&self.random2);

        // Options string (null-terminated, length includes null)
        Self::write_string(&mut buf, &self.options);

        // Username (optional, null-terminated)
        if let Some(username) = &self.username {
            Self::write_string(&mut buf, username);
        } else {
            Self::write_string(&mut buf, "");
        }

        // Password (optional, null-terminated)
        if let Some(password) = &self.password {
            Self::write_string(&mut buf, password);
        } else {
            Self::write_string(&mut buf, "");
        }

        // Peer info (optional, null-terminated)
        if let Some(peer_info) = &self.peer_info {
            Self::write_string(&mut buf, peer_info);
        }

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_reply_roundtrip() {
        let mut reply = PushReply::default();
        reply.ifconfig = Some(("10.8.0.2".to_string(), "255.255.255.0".to_string()));
        reply.dns.push("1.1.1.1".to_string());
        reply.routes.push(PushRoute::new("192.168.1.0", "255.255.255.0"));
        reply.redirect_gateway = true;

        let encoded = reply.encode();
        let parsed = PushReply::parse(&encoded).unwrap();

        assert_eq!(parsed.ifconfig, reply.ifconfig);
        assert_eq!(parsed.dns, reply.dns);
        assert!(parsed.redirect_gateway);
    }

    #[test]
    fn test_auth_message() {
        let auth = AuthMessage {
            username: "user".to_string(),
            password: "pass".to_string(),
        };

        let encoded = auth.encode();
        let parsed = AuthMessage::parse(&encoded).unwrap();

        assert_eq!(parsed.username, "user");
        assert_eq!(parsed.password, "pass");
    }
}
