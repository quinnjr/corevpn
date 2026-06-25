//! NetworkManager VPN Plugin D-Bus interface implementation.
//!
//! Implements `org.freedesktop.NetworkManager.VPN.Plugin` using `zbus`,
//! bridging NM's D-Bus calls to the CoreVPN client library.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use zbus::object_server::SignalEmitter;
use zbus::zvariant::OwnedValue;

use corevpn_cli::client::{ConnectionEvent, VpnClient};
use corevpn_cli::ovpn::OvpnConfig;

use crate::config::parse_nm_settings;

// ---------------------------------------------------------------------------
// NM VPN state constants
// ---------------------------------------------------------------------------

pub const NM_VPN_STATE_INIT: u32 = 1;
#[allow(dead_code)]
pub const NM_VPN_STATE_SHUTDOWN: u32 = 2;
pub const NM_VPN_STATE_STARTING: u32 = 3;
pub const NM_VPN_STATE_STARTED: u32 = 4;
pub const NM_VPN_STATE_STOPPING: u32 = 5;
pub const NM_VPN_STATE_STOPPED: u32 = 6;

pub const NM_VPN_FAILURE_CONNECT_FAILED: u32 = 1;

/// D-Bus object path for the VPN plugin.
pub const OBJECT_PATH: &str = "/org/freedesktop/NetworkManager/VPN/Plugin";

// ---------------------------------------------------------------------------
// Plugin internals
// ---------------------------------------------------------------------------

pub(crate) struct PluginInner {
    pub state: u32,
    pub connection_task: Option<tokio::task::JoinHandle<()>>,
}

/// The VPN plugin D-Bus object.
pub struct VpnPlugin {
    pub(crate) inner: Arc<Mutex<PluginInner>>,
}

impl VpnPlugin {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(PluginInner {
                state: NM_VPN_STATE_INIT,
                connection_task: None,
            })),
        }
    }
}

// ---------------------------------------------------------------------------
// D-Bus interface
// ---------------------------------------------------------------------------

#[zbus::interface(name = "org.freedesktop.NetworkManager.VPN.Plugin")]
impl VpnPlugin {
    // -- Methods ----------------------------------------------------------

    /// Start a VPN connection with the given NM connection settings.
    async fn connect(
        &self,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        connection_settings: HashMap<String, HashMap<String, OwnedValue>>,
    ) -> zbus::fdo::Result<()> {
        info!("Connect called by NetworkManager");

        let nm_settings = parse_nm_settings(&connection_settings).map_err(|e| {
            error!("Failed to parse NM settings: {}", e);
            zbus::fdo::Error::InvalidArgs(e.to_string())
        })?;

        info!("Config file: {}", nm_settings.config_path.display());

        let ovpn_content = std::fs::read_to_string(&nm_settings.config_path).map_err(|e| {
            zbus::fdo::Error::InvalidArgs(format!(
                "Cannot read {}: {}",
                nm_settings.config_path.display(),
                e
            ))
        })?;

        let config = OvpnConfig::parse(&ovpn_content)
            .map_err(|e| zbus::fdo::Error::InvalidArgs(format!("Invalid .ovpn: {}", e)))?;

        // Cancel any existing connection
        {
            let mut inner = self.inner.lock().await;
            if let Some(task) = inner.connection_task.take() {
                task.abort();
            }
            inner.state = NM_VPN_STATE_STARTING;
        }

        let _ = Self::state_changed(&emitter, NM_VPN_STATE_STARTING).await;

        let server_addr = config.remote.to_string();
        let conn = conn.clone();
        let inner = self.inner.clone();

        let task = tokio::spawn(async move {
            if let Err(e) =
                run_vpn_connection(config, server_addr, conn.clone(), inner.clone()).await
            {
                error!("VPN connection failed: {}", e);
                emit_failure_signals(&conn, &inner).await;
            }
        });

        self.inner.lock().await.connection_task = Some(task);
        Ok(())
    }

    /// Interactive connect — delegates to Connect.
    async fn connect_interactive(
        &self,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        connection_settings: HashMap<String, HashMap<String, OwnedValue>>,
        _details: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<()> {
        self.connect(conn, emitter, connection_settings).await
    }

    /// Check whether additional secrets are needed.
    async fn need_secrets(
        &self,
        _connection_settings: HashMap<String, HashMap<String, OwnedValue>>,
    ) -> zbus::fdo::Result<String> {
        Ok(String::new())
    }

    /// Disconnect the active VPN connection.
    async fn disconnect(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<()> {
        info!("Disconnect called by NetworkManager");

        {
            let mut inner = self.inner.lock().await;
            inner.state = NM_VPN_STATE_STOPPING;
        }
        let _ = Self::state_changed(&emitter, NM_VPN_STATE_STOPPING).await;

        {
            let mut inner = self.inner.lock().await;
            if let Some(task) = inner.connection_task.take() {
                task.abort();
                debug!("Connection task aborted");
            }
            inner.state = NM_VPN_STATE_STOPPED;
        }
        let _ = Self::state_changed(&emitter, NM_VPN_STATE_STOPPED).await;

        Ok(())
    }

    /// Set generic VPN config — emits Config signal.
    async fn set_config(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        config: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<()> {
        Self::config(&emitter, config)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }

    /// Set IPv4 config — emits Ip4Config signal.
    async fn set_ip4_config(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        config: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<()> {
        Self::ip4_config(&emitter, config)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }

    /// Set IPv6 config — emits Ip6Config signal.
    async fn set_ip6_config(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        config: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<()> {
        Self::ip6_config(&emitter, config)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }

    /// Report a failure reason.
    async fn set_failure(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        reason: &str,
    ) -> zbus::fdo::Result<()> {
        error!("SetFailure: {}", reason);
        let _ = Self::failure(&emitter, NM_VPN_FAILURE_CONNECT_FAILED).await;
        Ok(())
    }

    /// Provide new secrets.
    async fn new_secrets(
        &self,
        _connection_settings: HashMap<String, HashMap<String, OwnedValue>>,
    ) -> zbus::fdo::Result<()> {
        debug!("NewSecrets — not currently used");
        Ok(())
    }

    // -- Properties -------------------------------------------------------

    /// Current VPN service state (suppresses auto property-change signal
    /// since we have an explicit StateChanged signal).
    #[zbus(property(emits_changed_signal = "false"))]
    async fn state(&self) -> u32 {
        self.inner.lock().await.state
    }

    // -- Signals ----------------------------------------------------------

    #[zbus(signal)]
    async fn state_changed(emitter: &SignalEmitter<'_>, state: u32) -> zbus::Result<()>;

    #[zbus(signal)]
    #[allow(dead_code)]
    async fn secrets_required(
        emitter: &SignalEmitter<'_>,
        connection: HashMap<String, HashMap<String, OwnedValue>>,
        setting_name: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn config(
        emitter: &SignalEmitter<'_>,
        config: HashMap<String, OwnedValue>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn ip4_config(
        emitter: &SignalEmitter<'_>,
        config: HashMap<String, OwnedValue>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn ip6_config(
        emitter: &SignalEmitter<'_>,
        config: HashMap<String, OwnedValue>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    #[allow(dead_code)]
    async fn login_banner(emitter: &SignalEmitter<'_>, banner: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn failure(emitter: &SignalEmitter<'_>, reason: u32) -> zbus::Result<()>;
}

// ---------------------------------------------------------------------------
// Helper: emit failure + stopped signals from a background task
// ---------------------------------------------------------------------------

async fn emit_failure_signals(conn: &zbus::Connection, inner: &Arc<Mutex<PluginInner>>) {
    if let Ok(iface_ref) = conn
        .object_server()
        .interface::<_, VpnPlugin>(OBJECT_PATH)
        .await
    {
        // Use the generated VpnPluginSignals trait on InterfaceRef
        use VpnPluginSignals as _;
        let _ = iface_ref.failure(NM_VPN_FAILURE_CONNECT_FAILED).await;
        let _ = iface_ref.state_changed(NM_VPN_STATE_STOPPED).await;
    }

    let mut guard = inner.lock().await;
    guard.state = NM_VPN_STATE_STOPPED;
    guard.connection_task = None;
}

// ---------------------------------------------------------------------------
// Background VPN connection
// ---------------------------------------------------------------------------

async fn run_vpn_connection(
    config: OvpnConfig,
    server_addr: String,
    conn: zbus::Connection,
    inner: Arc<Mutex<PluginInner>>,
) -> anyhow::Result<()> {
    let client = VpnClient::new(config);

    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<ConnectionEvent>();

    let vpn_handle = tokio::spawn(async move { client.connect_with_info(Some(event_tx)).await });

    while let Some(event) = event_rx.recv().await {
        let iface_ref = conn
            .object_server()
            .interface::<_, VpnPlugin>(OBJECT_PATH)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get interface ref: {}", e))?;

        // Use the generated signal trait on InterfaceRef<VpnPlugin>
        use VpnPluginSignals as _;

        match event {
            ConnectionEvent::PushReply {
                ifconfig,
                routes,
                dns,
                gateway,
                redirect_gateway,
            } => {
                info!("Received push reply, reporting IP config to NetworkManager");

                // Emit Config signal
                let mut config_dict = HashMap::<String, OwnedValue>::new();
                if let Some(gw_ip) = extract_ip_from_remote(&server_addr) {
                    config_dict.insert("gateway".into(), OwnedValue::from(ipv4_to_nm(&gw_ip)));
                }
                config_dict.insert("has-ip4".into(), OwnedValue::from(ifconfig.is_some()));
                config_dict.insert("has-ip6".into(), OwnedValue::from(false));

                iface_ref
                    .config(config_dict)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to emit Config: {}", e))?;

                // Emit Ip4Config signal
                if let Some((ip, mask)) = ifconfig {
                    let mut ip4 = HashMap::<String, OwnedValue>::new();
                    ip4.insert("address".into(), OwnedValue::from(ipv4_to_nm(&ip)));
                    ip4.insert("prefix".into(), OwnedValue::from(netmask_to_prefix(&mask)));

                    if let Some(ref gw) = gateway {
                        ip4.insert("gateway".into(), OwnedValue::from(ipv4_to_nm(gw)));
                    }

                    if !dns.is_empty() {
                        let dns_addrs: Vec<u32> = dns.iter().map(|d| ipv4_to_nm(d)).collect();
                        ip4.insert(
                            "dns".into(),
                            zbus::zvariant::Value::from(dns_addrs)
                                .try_into()
                                .expect("dns array should be ownable"),
                        );
                    }

                    if !routes.is_empty() {
                        let route_arrays: Vec<Vec<u32>> = routes
                            .iter()
                            .map(|(net, nmask)| {
                                vec![
                                    ipv4_to_nm(net),
                                    netmask_to_prefix(nmask),
                                    gateway.as_deref().map(ipv4_to_nm).unwrap_or(0),
                                    0u32,
                                ]
                            })
                            .collect();
                        ip4.insert(
                            "routes".into(),
                            zbus::zvariant::Value::from(route_arrays)
                                .try_into()
                                .expect("routes array should be ownable"),
                        );
                    }

                    ip4.insert("never-default".into(), OwnedValue::from(!redirect_gateway));

                    iface_ref
                        .ip4_config(ip4)
                        .await
                        .map_err(|e| anyhow::anyhow!("Failed to emit Ip4Config: {}", e))?;
                }
            }

            ConnectionEvent::Connected { tun_name } => {
                info!("VPN connected on {}, emitting STARTED", tun_name);
                iface_ref
                    .state_changed(NM_VPN_STATE_STARTED)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to emit StateChanged: {}", e))?;
                inner.lock().await.state = NM_VPN_STATE_STARTED;
            }

            ConnectionEvent::Error(msg) => {
                error!("VPN client error: {}", msg);
            }
        }
    }

    // Event channel closed — VPN task is finishing
    let result = vpn_handle.await;

    info!("VPN data plane ended, transitioning to STOPPED");
    {
        let mut guard = inner.lock().await;
        guard.state = NM_VPN_STATE_STOPPED;
        guard.connection_task = None;
    }

    if let Ok(iface_ref) = conn
        .object_server()
        .interface::<_, VpnPlugin>(OBJECT_PATH)
        .await
    {
        use VpnPluginSignals as _;
        let _ = iface_ref.state_changed(NM_VPN_STATE_STOPPED).await;
    }

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(e) if e.is_cancelled() => {
            info!("VPN connection was cancelled");
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("VPN task panicked: {}", e)),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert an IPv4 string to NM's u32 format (network byte order in native u32).
fn ipv4_to_nm(ip: &str) -> u32 {
    ip.parse::<Ipv4Addr>()
        .map(|addr| u32::from_ne_bytes(addr.octets()))
        .unwrap_or(0)
}

/// Convert a netmask string to a prefix length.
fn netmask_to_prefix(mask: &str) -> u32 {
    if let Ok(addr) = mask.parse::<Ipv4Addr>() {
        let bits = u32::from(addr);
        let inv = !bits;
        if inv == 0 || (inv & (inv + 1)) == 0 {
            return bits.count_ones();
        }
        warn!("'{}' doesn't look like a netmask, using /24", mask);
    }
    24
}

/// Extract the IP from a "host:port" remote string.
fn extract_ip_from_remote(remote: &str) -> Option<String> {
    let host = if let Some(idx) = remote.rfind(':') {
        if remote[idx + 1..].parse::<u16>().is_ok() {
            &remote[..idx]
        } else {
            remote
        }
    } else {
        remote
    };

    if host.parse::<Ipv4Addr>().is_ok() {
        return Some(host.to_string());
    }

    use std::net::ToSocketAddrs;
    if let Ok(mut addrs) = format!("{}:0", host).to_socket_addrs() {
        for addr in &mut addrs {
            if let std::net::SocketAddr::V4(v4) = addr {
                return Some(v4.ip().to_string());
            }
        }
    }
    None
}
